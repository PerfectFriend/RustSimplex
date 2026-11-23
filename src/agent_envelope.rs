//! Official agent message envelope — G13 piece 1.
//!
//! decryptedSMPClientMessage = agentConfirmation / agentMsgEnvelope /
//!                             agentInvitation / agentRatchetKey
//!   agentConfirmation = agentVersion %s"C" ("0" / "1" sndE2EEncryptionParams) encConnInfo
//!   agentMsgEnvelope  = agentVersion %s"M" encAgentMessage
//!   agentInvitation   = agentVersion %s"I" connReqLength connReq connInfo
//!   agentRatchetKey   = agentVersion %s"R" rcvE2EEncryptionParams ratchetKeyInfo
//!   agentVersion = 2*2 OCTET        (Word16, big-endian)
//!
//! Reference: simplexmq 7.0.1.0, Agent/Protocol.hs:833-861, currentSMPAgentVersion = 7 (:325).
//! NOTE: in the official stack the C/M payloads are double-ratchet CIPHERTEXT
//! (encConnInfo / encAgentMessage). This codec is format-complete but smp-rs still
//! sends the inner payloads as plaintext — that ratchet layer is the remaining G13 gap.

use crate::encoding::Reader;

/// currentSMPAgentVersion = VersionSMPA 7 (simplexmq 7.0.1.0).
pub const AGENT_VERSION: u16 = 7;
/// duplexHandshakeSMPAgentVersion = VersionSMPA 2 — oldest envelope we accept.
pub const MIN_AGENT_VERSION: u16 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Envelope {
    /// "C": pq flag + optional snd e2e params + encrypted connInfo
    Confirmation { pq: bool, e2e_params: Vec<u8>, enc_conn_info: Vec<u8> },
    /// "M": encrypted agentMessage
    Msg { enc_agent_msg: Vec<u8> },
    /// "I": connReqLength connReq connInfo (plaintext, sent to a contact address)
    Invitation { conn_req: Vec<u8>, conn_info: Vec<u8> },
    /// "R": rcv e2e params + ratchet key info
    RatchetKey { rcv_e2e_params: Vec<u8>, ratchet_key_info: Vec<u8> },
}

pub fn encode(env: &Envelope) -> Vec<u8> {
    encode_versioned(AGENT_VERSION, env)
}

pub fn encode_versioned(version: u16, env: &Envelope) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(&version.to_be_bytes());
    match env {
        Envelope::Confirmation { pq, e2e_params, enc_conn_info } => {
            o.push(b'C');
            if *pq {
                o.push(b'1');
                o.extend_from_slice(e2e_params);
            } else {
                o.push(b'0');
            }
            o.extend_from_slice(enc_conn_info);
        }
        Envelope::Msg { enc_agent_msg } => {
            o.push(b'M');
            o.extend_from_slice(enc_agent_msg);
        }
        Envelope::Invitation { conn_req, conn_info } => {
            o.push(b'I');
            o.extend_from_slice(&(conn_req.len() as u16).to_be_bytes());
            o.extend_from_slice(conn_req);
            o.extend_from_slice(conn_info);
        }
        Envelope::RatchetKey { rcv_e2e_params, ratchet_key_info } => {
            o.push(b'R');
            o.extend_from_slice(rcv_e2e_params);
            o.extend_from_slice(ratchet_key_info);
        }
    }
    o
}

/// Split a byte string at the end of an encoded e2eRatchetParams structure.
/// Returns (params_bytes, tail).
pub fn split_e2e_params(buf: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut r = Reader::new(buf);
    crate::pq::decode_e2e_ratchet_params(&mut r).map_err(|e| format!("e2e params: {e}"))?;
    let n = r.pos;
    Ok((buf[..n].to_vec(), buf[n..].to_vec()))
}

pub fn decode(buf: &[u8]) -> Result<(u16, Envelope), String> {
    if buf.len() < 3 {
        return Err("envelope too short".into());
    }
    let version = u16::from_be_bytes([buf[0], buf[1]]);
    if version > AGENT_VERSION {
        return Err(format!("agent version {version} newer than supported {AGENT_VERSION}"));
    }
    if version < MIN_AGENT_VERSION {
        return Err(format!("agent version {version} too old (min {MIN_AGENT_VERSION})"));
    }
    let rest = &buf[2..];
    let env = match rest[0] {
        b'C' => {
            let tail = &rest[1..];
            if tail.is_empty() {
                return Err("C envelope missing pq flag".into());
            }
            match tail[0] {
                b'0' => Envelope::Confirmation { pq: false, e2e_params: vec![], enc_conn_info: tail[1..].to_vec() },
                b'1' => {
                    let (p, ci) = split_e2e_params(&tail[1..])?;
                    Envelope::Confirmation { pq: true, e2e_params: p, enc_conn_info: ci }
                }
                c => return Err(format!("bad pq flag {c:#x}")),
            }
        }
        b'M' => Envelope::Msg { enc_agent_msg: rest[1..].to_vec() },
        b'I' => {
            let tail = &rest[1..];
            if tail.len() < 2 {
                return Err("I envelope missing connReqLength".into());
            }
            let n = u16::from_be_bytes([tail[0], tail[1]]) as usize;
            if tail.len() < 2 + n {
                return Err("I envelope connReq overruns buffer".into());
            }
            Envelope::Invitation { conn_req: tail[2..2 + n].to_vec(), conn_info: tail[2 + n..].to_vec() }
        }
        b'R' => {
            let (p, info) = split_e2e_params(&rest[1..])?;
            Envelope::RatchetKey { rcv_e2e_params: p, ratchet_key_info: info }
        }
        c => return Err(format!("unknown envelope type {c:#x} ({})", c as char)),
    };
    Ok((version, env))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq::{encode_e2e_ratchet_params, E2eRatchetParams, KemParams};

    fn sample_params() -> Vec<u8> {
        let p = E2eRatchetParams {
            v_min: 1,
            v_max: 1,
            snd_dh_spki: vec![0xAA; 44],
            rcv_dh_spki: vec![0xBB; 44],
            kem: KemParams::Pk(vec![0xCC; 32]),
        };
        let mut o = Vec::new();
        encode_e2e_ratchet_params(&mut o, &p).unwrap();
        o
    }

    #[test]
    fn golden_msg_envelope() {
        let v = encode(&Envelope::Msg { enc_agent_msg: vec![0xDE, 0xAD] });
        assert_eq!(v, vec![0u8, AGENT_VERSION as u8, b'M', 0xDE, 0xAD]);
    }

    #[test]
    fn roundtrip_all_variants() {
        let p = sample_params();
        let cases = vec![
            Envelope::Confirmation { pq: false, e2e_params: vec![], enc_conn_info: vec![1, 2, 3] },
            Envelope::Confirmation { pq: true, e2e_params: p.clone(), enc_conn_info: vec![9; 100] },
            Envelope::Msg { enc_agent_msg: vec![7; 50] },
            Envelope::Invitation { conn_req: b"simplex:/contact#/?v=2-7".to_vec(), conn_info: b"profile".to_vec() },
            Envelope::RatchetKey { rcv_e2e_params: p.clone(), ratchet_key_info: vec![5, 6] },
        ];
        for c in cases {
            let enc = encode(&c);
            let (v, back) = decode(&enc).expect("decode");
            assert_eq!(v, AGENT_VERSION);
            assert_eq!(back, c);
        }
    }

    #[test]
    fn invitation_length_prefix_is_exact() {
        let req = b"smp://x".to_vec();
        let enc = encode(&Envelope::Invitation { conn_req: req.clone(), conn_info: vec![0xFF] });
        // [0,7]['I'][0,len][req...][0xFF]
        assert_eq!(&enc[3..5], &(req.len() as u16).to_be_bytes());
        assert_eq!(enc[5..5 + req.len()], req[..]);
        assert_eq!(enc[5 + req.len()..], vec![0xFF]);
    }

    #[test]
    fn rejects_malformed() {
        assert!(decode(&[]).is_err());
        assert!(decode(&[0, 7]).is_err());
        assert!(decode(&[0, 7, b'X', 1]).is_err()); // unknown type
        assert!(decode(&[0, 8, b'M', 1]).is_err()); // version too new
        assert!(decode(&[0, 1, b'M', 1]).is_err()); // version too old
        assert!(decode(&[0, 7, b'I', 0]).is_err()); // truncated length
        assert!(decode(&[0, 7, b'I', 0, 9, 1]).is_err()); // connReq overruns
        assert!(decode(&[0, 7, b'C']).is_err()); // missing pq flag
    }

    #[test]
    fn composes_with_inner_agent_message() {
        // G13 composition proof: inner decryptedAgentMessage ("M" agentMsgHeader aMessage)
        // wrapped in the official agentMsgEnvelope.
        let inner = crate::agent::encode_agent(
            &crate::agent::AgentMsg::Hello { msg_id: 42, prev_hash: vec![0x11; 32] },
            42,
            &[0x11; 32],
        );
        let wire = encode(&Envelope::Msg { enc_agent_msg: inner.clone() });
        let (_v, env) = decode(&wire).unwrap();
        match env {
            Envelope::Msg { enc_agent_msg } => {
                assert_eq!(enc_agent_msg, inner);
                let am = crate::agent::parse_agent(&enc_agent_msg).unwrap();
                assert!(matches!(am, crate::agent::AgentMsg::Hello { msg_id: 42, .. }));
            }
            _ => panic!("expected Msg envelope"),
        }
    }
}
