//! Live NTF probe (feature v71-probes): PING -> NKEY -> NID -> NSUB against a public NTF server.
//! NoVerify pin probe — diagnostics only, never for production traffic.
use smp_rs::client::Client;
use smp_rs::crypto::*;
use smp_rs::protocol::*;
use std::net::ToSocketAddrs;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let host = args.first().cloned().unwrap_or_else(|| "ntf1.simplex.im".into());
    let port: u16 = args.get(1).and_then(|p| p.parse().ok()).unwrap_or(443);
    let addr: std::net::SocketAddr = format!("{host}:{port}")
        .to_socket_addrs()
        .expect("dns")
        .next()
        .expect("at least one addr");
    let kh = [0u8; 32]; // NoVerify probe
    // 443 = web/NTF vhost (no ALPN, SNI); 5223 = NTF vhost with ALPN smp/1
    let mut c = if port == 443 {
        let s = smp_rs::transport::connect_tls_sni_alpn_noverify(addr, &host, true, None).expect("connect_tls 443");
        Client::from_stream(s, kh)
    } else {
        let s = smp_rs::transport::connect_tls_sni_alpn_noverify(addr, &host, true, Some(b"smp/1")).expect("connect_tls 5223");
        Client::from_stream(s, kh)
    };
    println!("connected {host}:{port}");
    let pong = c.request(Command::Ping, vec![], None).expect("PING");
    println!("PING -> {:?}", pong.first().map(|m| match m { BrokerMsg::Pong => "PONG".to_string(), o => format!("{o:?}") }));

    // NKEY with a fresh notifier Ed25519 key + recipient NTF DH key (public NTF issues NID)
    let ntf_auth = ed25519_keypair();
    let rcv_ntf_dh = x25519_keypair();
    let resp = c.request(
        Command::Nkey {
            ntf_key: spki_ed25519(&ntf_auth.verifying.to_bytes()),
            rcv_ntf_dh_key: spki_x25519(&rcv_ntf_dh.public.to_bytes()),
        },
        vec![],
        Some(&ntf_auth),
    );
    match resp {
        Ok(msgs) => match &msgs[0] {
            BrokerMsg::Nid { ntf_id, srv_ntf_dh } => {
                println!("NKEY -> NID ntf_id_len={} srv_ntf_dh_len={}", ntf_id.len(), srv_ntf_dh.len());
                let sub = c.request(Command::Nsub, ntf_id.clone(), Some(&ntf_auth)).expect("NSUB");
                println!("NSUB -> {:?}", sub.first().map(|m| format!("{:?}", m).chars().take(60).collect::<String>()));
            }
            other => println!("NKEY -> {other:?}"),
        },
        Err(e) => println!("NKEY -> ERR {e}"),
    }
}
