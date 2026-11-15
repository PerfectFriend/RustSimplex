//! Proxy e2e: client -> proxy engine -> destination engine via PRXY/PKEY/PFWD/RFWD/PRES/RRES.

use smp_rs::client::Client;
use smp_rs::crypto::*;
use smp_rs::protocol::*;
use smp_rs::server::{spawn_engine, Engine};

#[test]
fn proxy_pfwd_roundtrip() {
    std::env::set_var("SMP_ALLOW_LOCAL_PROXY", "1");
    // destination router
    let dest = Engine::bind_plain("127.0.0.1:0").unwrap();
    let (dest_addr, _st1, _sd1, _h1) = spawn_engine(dest);
    let dest_port = dest_addr.port();
    // proxy router
    let proxy = Engine::bind_plain("127.0.0.1:0").unwrap();
    let (proxy_addr, _st2, _sd2, _h2) = spawn_engine(proxy);

    let kh = [0xCDu8; 32];
    eprintln!("[t] connect proxy");
    let mut c = Client::connect_plain(proxy_addr, &kh).unwrap();
    eprintln!("[t] ping");
    assert!(matches!(c.request(Command::Ping, vec![], None).unwrap()[0], BrokerMsg::Pong));

    // PRXY to dest
    eprintln!("[t] proxy_open");
    let pkey = c.proxy_open("127.0.0.1", dest_port).expect("PRXY");
    let BrokerMsg::Pkey { session_id, .. } = &pkey else { panic!("expected PKEY, got {pkey:?}") };
    assert_eq!(session_id.len(), 24);

    // NEW a queue on the DESTINATION router via the proxy
    eprintln!("[t] pfwd NEW");
    let rcv_auth = ed25519_keypair();
    let rcv_dh = x25519_keypair();
    let new_resp = c
        .pfwd(
            &pkey,
            Command::New {
                rcv_auth_key: spki_ed25519(&rcv_auth.verifying.to_bytes()),
                rcv_dh_key: spki_x25519(&rcv_dh.public.to_bytes()),
                basic_auth: None,
                sub_mode: b'S',
                queue_req_data: None,
                ntf_creds: None,
            },
            vec![],
            Some(&rcv_auth),
        )
        .expect("PFWD NEW");
    let (rcv_id, snd_id, srv_dh) = match &new_resp[0] {
        BrokerMsg::Ids { rcv_id, snd_id, rcv_dh_key, .. } => (rcv_id.clone(), snd_id.clone(), rcv_dh_key.clone()),
        other => panic!("expected IDS via proxy, got {other:?}"),
    };

    // SEND via proxy (subscriber already attached on DEST, so MSG is pushed live)
    eprintln!("[t] direct SUB on dest");
    let mut sub = Client::connect_plain(dest_addr, &kh).unwrap();
    let sk = sub.request(Command::Sub, rcv_id.clone(), Some(&rcv_auth)).expect("SUB");
    assert!(matches!(sk[0], BrokerMsg::Sok(_)), "got {sk:?}");
    eprintln!("[t] pfwd SEND");
    let body = b"via proxy".to_vec();
    let s = c.pfwd(&pkey, Command::Send { flags: false, body: body.clone() }, snd_id.clone(), None).expect("PFWD SEND");
    assert!(matches!(s[0], BrokerMsg::Ok), "got {s:?}");

    // subscriber on DEST picks up the message
    eprintln!("[t] recv MSG");
    let msgs = sub.recv_block().expect("recv MSG");
    let (msg_id, enc) = match &msgs[0] {
        BrokerMsg::Msg { msg_id, body } => (msg_id.clone(), body.clone()),
        other => panic!("expected MSG, got {other:?}"),
    };
    let secret = x25519_dh(&rcv_dh.secret, &x25519_public(parse_spki(&srv_dh).unwrap().1));
    let plain = smp_rs::server::decrypt_for_recipient(&secret, &msg_id, &enc).expect("decrypt");
    assert_eq!(plain, body);
}
