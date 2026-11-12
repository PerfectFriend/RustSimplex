//! SMP client over plain TCP or TLS 1.3 (rustls), pinning the router by keyHash.

use std::net::SocketAddr;

use crate::crypto::*;
use crate::encoding::{pad, unpad};
use crate::protocol::*;
use crate::transport::*;

pub type ClResult<T> = Result<T, String>;

/// Channel binding (spec appendix A): client asserts sessionIdentifier == tls-unique.
/// TLS 1.3 has empty tls-unique (RFC 5929) and plain TCP uses "" — so sessionId must be empty.
pub fn check_session_binding(sid: &[u8]) -> ClResult<()> {
    if sid.is_empty() {
        Ok(())
    } else {
        Err("SESSION: unexpected non-empty sessionId in server hello".into())
    }
}

fn map_e<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

pub struct Client {
    stream: BoxStream,
    session_id: Vec<u8>,
    pub server_key_hash: Vec<u8>,
    /// per-connection ephemeral X25519 pub from server hello (authPubKey), used for box auth
    pub server_eph_pub: Option<[u8; 32]>,
}

impl Client {
    fn handshake(stream: &mut BoxStream, key_hash: &[u8]) -> ClResult<(Vec<u8>, Option<[u8; 32]>)> {
        let sh = read_block(stream).map_err(map_e)?;
        let (_min, _max, sid, auth_spki) = parse_server_hello_key(&sh).map_err(map_e)?;
        // channel binding (spec appendix A): client MUST assert sessionIdentifier == tls-unique.
        check_session_binding(&sid)?;
        let ch = client_hello_block(SMP_VERSION, key_hash, false).map_err(map_e)?;
        write_block(stream, &ch).map_err(map_e)?;
        let eph = auth_spki.and_then(|der| parse_spki(&der).ok()).map(|(_a, raw)| raw);
        Ok((sid, eph))
    }

    pub fn connect_plain(addr: SocketAddr, key_hash: &[u8]) -> ClResult<Client> {
        let mut s = connect_plain(addr).map_err(map_e)?;
        let (sid, eph) = Self::handshake(&mut s, key_hash)?;
        Ok(Client { stream: s, session_id: sid, server_key_hash: key_hash.to_vec(), server_eph_pub: eph })
    }

    pub fn connect_tls(addr: SocketAddr, host: &str, key_hash: [u8; 32]) -> ClResult<Client> {
        let mut s = connect_tls(addr, host, key_hash).map_err(map_e)?;
        let (sid, eph) = Self::handshake(&mut s, &key_hash)?;
        Ok(Client { stream: s, session_id: sid, server_key_hash: key_hash.to_vec(), server_eph_pub: eph })
    }

    /// X25519 box-auth shared secret for a queue whose auth key is `qauth_kp`:
    /// dhSecret = DH(queue auth priv, server per-connection eph pub) — C.cbAuthenticate k pk.
    pub fn box_secret(&self, qauth_kp: &X25519Keypair) -> Option<[u8; 32]> {
        let srv = self.server_eph_pub?;
        Some(x25519_dh(&qauth_kp.secret, &x25519_public(srv)))
    }

    /// Send one command transmission (signed if `auth` given) and read one response block.
    pub fn request(&mut self, cmd: Command, entity_id: Vec<u8>, auth: Option<&Ed25519Keypair>) -> ClResult<Vec<BrokerMsg>> {
        let mut t = Transmission {
            authenticator: Vec::new(),
            corr_id: random_bytes(24),
            entity_id,
            command: encode_command(&cmd).map_err(map_e)?,
        };
        if let Some(kp) = auth {
            auth_sign(&self.session_id, &mut t, kp).map_err(map_e)?;
        }
        let wire = encode_transmission(&t).map_err(map_e)?;
        let blk = encode_block(&[wire]).map_err(map_e)?;
        write_block(&mut self.stream, &blk).map_err(map_e)?;
        self.recv_block()
    }

    /// Send one command authorized with the X25519 crypto_box authenticator
    /// (secretbox(dhSecret, cbNonce(corrId), sha512(authorized)) = 80 bytes) and read one response block.
    pub fn request_box(&mut self, cmd: Command, entity_id: Vec<u8>, dh_secret: &[u8; 32]) -> ClResult<Vec<BrokerMsg>> {
        let mut t = Transmission {
            authenticator: Vec::new(),
            corr_id: random_bytes(24),
            entity_id,
            command: encode_command(&cmd).map_err(map_e)?,
        };
        auth_box(&self.session_id, &mut t, dh_secret).map_err(map_e)?;
        let wire = encode_transmission(&t).map_err(map_e)?;
        let blk = encode_block(&[wire]).map_err(map_e)?;
        write_block(&mut self.stream, &blk).map_err(map_e)?;
        self.recv_block()
    }

    /// Read one block and parse all broker messages in it (responses + pushed MSG).
    pub fn recv_block(&mut self) -> ClResult<Vec<BrokerMsg>> {
        let rb = read_block(&mut self.stream).map_err(map_e)?;
        if let Ok(path) = std::env::var("SMP_DUMP_RAW") {
            use std::io::Write;
            let p = if path.is_empty() || path == "1" {
                std::env::temp_dir().join("raw_blocks.hex") // TMPDIR points at the hermes scratch dir
            } else {
                std::path::PathBuf::from(path)
            };
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
                let _ = writeln!(f, "{}", rb.iter().map(|b| format!("{b:02x}")).collect::<String>());
            }
        }
        let wires = decode_block(&rb).map_err(map_e)?;
        let mut out = Vec::new();
        for w in wires {
            let t = decode_transmission(&w).map_err(map_e)?;
            out.push(parse_broker(&t.command).map_err(map_e)?);
        }
        Ok(out)
    }

    /// PRXY: ask this router to open a proxied session to dest. Returns the PKEY.
    pub fn proxy_open(&mut self, dest_host: &str, dest_port: u16) -> ClResult<BrokerMsg> {
        let r = self
            .request(
                Command::Proxy { host: dest_host.as_bytes().to_vec(), port: dest_port.to_string().into_bytes(), auth: None },
                vec![],
                None,
            )
            .map_err(map_e)?;
        r.into_iter().next().ok_or_else(|| "empty PRXY response".into())
    }

    /// PFWD: send a command via the proxy session to the destination router.
    /// `pkey` = the PKEY response; returns decrypted broker messages from PRES.
    pub fn pfwd(&mut self, pkey: &BrokerMsg, cmd: Command, entity_id: Vec<u8>, auth: Option<&Ed25519Keypair>) -> ClResult<Vec<BrokerMsg>> {
        let BrokerMsg::Pkey { session_id, cert_key, .. } = pkey else {
            return Err("expected PKEY".into());
        };
        let (_a, dest_pub_raw) = parse_spki(cert_key).map_err(map_e)?;
        let dest_pub = x25519_public(dest_pub_raw);
        // per-command ephemeral key
        let eph = x25519_keypair();
        let client_sess = x25519_dh(&eph.secret, &dest_pub);
        // inner transmission (signed with OUR session id on the proxy connection, as usual)
        let mut t = Transmission {
            authenticator: Vec::new(),
            corr_id: random_bytes(24),
            entity_id,
            command: encode_command(&cmd).map_err(map_e)?,
        };
        if let Some(kp) = auth {
            auth_sign(&self.session_id, &mut t, kp).map_err(map_e)?;
        }
        let wire = encode_transmission(&t).map_err(map_e)?;
        let padded = pad(&wire, crate::proxy::PROXIED_T_LEN).map_err(map_e)?;
        let nonce = cb_nonce(&t.corr_id);
        let enc = secretbox_encrypt(&client_sess, &nonce, &padded);
        // PFWD transmission: entity = proxy session id, unsigned
        let pfwd_cmd = Command::Pfwd { version: SMP_VERSION, command_key: spki_x25519(&eph.public.to_bytes()), enc };
        let pt = Transmission {
            authenticator: Vec::new(),
            corr_id: t.corr_id.clone(),
            entity_id: session_id.clone(),
            command: encode_command(&pfwd_cmd).map_err(map_e)?,
        };
        let pwire = encode_transmission(&pt).map_err(map_e)?;
        let blk = encode_block(&[pwire]).map_err(map_e)?;
        write_block(&mut self.stream, &blk).map_err(map_e)?;
        let msgs = self.recv_block()?;
        for m in &msgs {
            if let BrokerMsg::Pres { enc } = m {
                let rn = crate::proxy::reverse_nonce(&nonce);
                let plain = secretbox_decrypt(&client_sess, &rn, enc).ok_or("PRES decrypt failed")?;
                let inner = unpad(&plain).map_err(map_e)?;
                let it = decode_transmission(&inner).map_err(map_e)?;
                return Ok(vec![parse_broker(&it.command).map_err(map_e)?]);
            }
        }
        Ok(msgs)
    }
}
