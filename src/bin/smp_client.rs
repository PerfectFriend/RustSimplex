//! smp-client: demo client against the Rust SMP engine (plain or TLS).
//!   smp-client <host:port>                 -- plain, full round-trip demo
//!   smp-client --tls <host> <keyHashB64> <host:port>  -- TLS 1.3 pinned by keyHash, full demo
//! Demo: PING -> NEW (create queue) -> SUB -> SEND -> recv MSG -> decrypt -> ACK -> DEL.

use std::net::SocketAddr;
use std::process::exit;

use smp_rs::client::Client;
use smp_rs::crypto::*;
use smp_rs::protocol::*;
use smp_rs::server::decrypt_for_recipient;

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

fn b64url_dec(s: &str) -> Result<Vec<u8>, String> {
    let mut tbl = [0xffu8; 256];
    for (i, c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".iter().enumerate() {
        tbl[*c as usize] = i as u8;
    }
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut nbits = 0;
    for c in s.bytes() {
        let v = tbl[c as usize];
        if v == 0xff {
            return Err(format!("bad b64 char {c}"));
        }
        acc = (acc << 6) | v as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Ok(out)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mut client, key_hash) = if args.first().map(|a| a == "--tls").unwrap_or(false) {
        let host = args[1].clone();
        let kh = b64url_dec(&args[2]).expect("keyHash b64");
        let kh32: [u8; 32] = kh.try_into().expect("keyHash 32 bytes");
        let addr: SocketAddr = args[3].parse().expect("host:port");
        (Client::connect_tls(addr, &host, kh32).expect("connect_tls"), kh32)
    } else {
        let addr: SocketAddr = args[0].parse().expect("host:port");
        let kh = [0xABu8; 32];
        (Client::connect_plain(addr, &kh).expect("connect_plain"), kh)
    };
    println!("connected. keyHash = {}", base64url_nopad(&key_hash));

    println!("PING -> {:?}", client.request(Command::Ping, vec![], None).expect("PING"));

    // recipient side: create queue
    let rcv_auth = ed25519_keypair();
    let rcv_dh = x25519_keypair();
    // APublicAuthKey/PublicKeyX25519 on the wire = SPKI DER (X.509 SubjectPublicKeyInfo) as shortString
    let auth_der = spki_ed25519(&rcv_auth.verifying.to_bytes());
    let dh_der = spki_x25519(&rcv_dh.public.to_bytes());
    let resp = client
        .request(
            Command::New { rcv_auth_key: auth_der, rcv_dh_key: dh_der, basic_auth: None, sub_mode: b'S', queue_req_data: None, ntf_creds: None },
            vec![],
            Some(&rcv_auth),
        )
        .expect("NEW");
    let (rcv_id, snd_id, srv_dh_der) = match &resp[0] {
        BrokerMsg::Ids { rcv_id, snd_id, rcv_dh_key, .. } => (rcv_id.clone(), snd_id.clone(), rcv_dh_key.clone()),
        other => {
            println!("unexpected: {other:?}");
            exit(1);
        }
    };
    println!("queue: rcv_id={} snd_id={}", base64url_nopad(&rcv_id), base64url_nopad(&snd_id));
    println!("link: smp://{}@.../{}#{}", base64url_nopad(&key_hash), base64url_nopad(&rcv_id), base64url_nopad(&snd_id));

    // recipient subscribes (on the same connection for the demo)
    let sub = client.request(Command::Sub, rcv_id.clone(), Some(&rcv_auth)).expect("SUB");
    println!("SUB -> {:?}", sub);

    // sender side: SEND a message
    let body = b"hello over rust smp engine".to_vec();
    let send = client.request(Command::Send { flags: true, body: body.clone() }, snd_id.clone(), None).expect("SEND");
    println!("SEND -> {:?}", send.iter().map(|m| match m { BrokerMsg::Msg{..} => "Msg(..)".into(), other => format!("{other:?}") }).collect::<Vec<_>>());

    // recipient receives the pushed MSG (may already be inside the SEND response block)
    let dh_secret = x25519_dh(&rcv_dh.secret, &x25519_public(parse_spki(&srv_dh_der).unwrap().1));
    let mut got = None;
    'outer: for m in &send {
        if let BrokerMsg::Msg { msg_id, body: enc } = m {
            if let Some(pt) = decrypt_for_recipient(&dh_secret, msg_id, enc) {
                got = Some((msg_id.clone(), pt));
            }
            break 'outer;
        }
    }
    for _ in 0..50 {
        if got.is_some() { break; }
        let blk = client.recv_block().expect("recv");
        for m in &blk {
            if let BrokerMsg::Msg { msg_id, body: enc } = m {
                let pt = decrypt_for_recipient(&dh_secret, msg_id, enc).expect("decrypt");
                got = Some((msg_id.clone(), pt));
            }
        }
    }
    let (msg_id, pt) = got.expect("no MSG received");
    println!("MSG received: msg_id={} plaintext={:?}", base64url_nopad(&msg_id), String::from_utf8_lossy(&pt));
    // RcvMsgBody layout (Protocol.hs v6.5.0): rcvMeta = smpEncode(msgTs :: Int64 BE, msgFlags, ' ') <> msgBody
    let msg_ts = i64::from_be_bytes(pt[0..8].try_into().unwrap());
    let msg_flags = pt[8];
    assert_eq!(pt[9], b' ', "rcvMeta separator");
    let rcv_body = &pt[10..];
    println!("MSG meta: msgTs={} ({}s epoch) flags={} body={:?}", msg_ts, msg_ts, msg_flags as char, String::from_utf8_lossy(rcv_body));
    assert_eq!(rcv_body, body.as_slice(), "decrypted rcv body mismatch");

    println!("ACK -> {:?}", client.request(Command::Ack(msg_id), rcv_id.clone(), Some(&rcv_auth)).expect("ACK"));
    println!("DEL -> {:?}", client.request(Command::Del, rcv_id.clone(), Some(&rcv_auth)).expect("DEL"));
    println!("OK: full round-trip over the Rust engine succeeded");
}
