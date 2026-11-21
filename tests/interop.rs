//! End-to-end: Rust SMP client <-> Rust SMP engine over plain TCP and over TLS 1.3.
//! Flow: NEW -> IDS, SUB -> SOK, SEND -> OK, pushed MSG -> decrypt -> ACK -> OK, DEL.

use std::net::SocketAddr;

use smp_rs::client::Client;
use smp_rs::crypto::*;
use smp_rs::protocol::*;
use smp_rs::server::{decrypt_for_recipient, spawn_engine, Engine};

fn start_plain() -> SocketAddr {
    let e = Engine::bind_plain("127.0.0.1:0").unwrap();
    spawn_engine(e).0
}

fn start_tls() -> (SocketAddr, [u8; 32]) {
    let e = Engine::bind_tls("127.0.0.1:0", "127.0.0.1").unwrap();
    let kh = e.key_hash().unwrap();
    let (addr, _st, _sd, _h) = spawn_engine(e);
    (addr, kh)
}

fn new_queue(c: &mut Client, rcv_auth: &Ed25519Keypair, rcv_dh: &X25519Keypair) -> (Vec<u8>, Vec<u8>, [u8; 32], Vec<u8>) {
    let resp = c
        .request(
            Command::New {
                rcv_auth_key: spki_ed25519(&rcv_auth.verifying.to_bytes()),
                rcv_dh_key: spki_x25519(&rcv_dh.public.to_bytes()),
                basic_auth: None,
                sub_mode: b'S',
                queue_req_data: None,
                ntf_creds: None,
            },
            vec![],
            Some(rcv_auth),
        )
        .expect("NEW");
    match &resp[0] {
        BrokerMsg::Ids { rcv_id, snd_id, rcv_dh_key, .. } => {
            let (_a, srv_raw) = parse_spki(rcv_dh_key).unwrap();
            let secret = x25519_dh(&rcv_dh.secret, &x25519_public(srv_raw));
            (rcv_id.clone(), snd_id.clone(), secret, rcv_dh_key.clone())
        }
        other => panic!("expected IDS, got {other:?}"),
    }
}

fn roundtrip(mut rcv: Client, mut snd: Client) {
    let rcv_auth = ed25519_keypair();
    let rcv_dh = x25519_keypair();
    let (rcv_id, snd_id, secret, _srv_dh) = new_queue(&mut rcv, &rcv_auth, &rcv_dh);
    assert_eq!(rcv_id.len(), 16);
    assert_eq!(snd_id.len(), 24);

    let p = rcv.request(Command::Ping, vec![], None).expect("PING");
    assert!(matches!(p[0], BrokerMsg::Pong));

    let s = rcv.request(Command::Sub, rcv_id.clone(), Some(&rcv_auth)).expect("SUB");
    assert!(matches!(s[0], BrokerMsg::Sok(_)), "got {s:?}");

    let body = b"hello over SMP e2e".to_vec();
    let r = snd.request(Command::Send { flags: false, body: body.clone() }, snd_id.clone(), None).expect("SEND");
    assert!(matches!(r[0], BrokerMsg::Ok), "got {r:?}");

    let msgs = rcv.recv_block().expect("recv MSG");
    let (msg_id, enc_body) = match &msgs[0] {
        BrokerMsg::Msg { msg_id, body } => (msg_id.clone(), body.clone()),
        other => panic!("expected MSG, got {other:?}"),
    };
    let plain = decrypt_for_recipient(&secret, &msg_id, &enc_body).expect("decrypt MSG");
    assert_eq!(plain, body);

    let a = rcv.request(Command::Ack(msg_id), rcv_id.clone(), Some(&rcv_auth)).expect("ACK");
    assert!(matches!(a[0], BrokerMsg::Ok));
    let d = rcv.request(Command::Del, rcv_id.clone(), Some(&rcv_auth)).expect("DEL");
    assert!(matches!(d[0], BrokerMsg::Deld));
}

#[test]
fn plain_roundtrip() {
    let addr = start_plain();
    let kh = [0xCDu8; 32];
    let rcv = Client::connect_plain(addr, &kh).unwrap();
    let snd = Client::connect_plain(addr, &kh).unwrap();
    roundtrip(rcv, snd);
}

#[test]
fn tls_roundtrip() {
    let (addr, kh) = start_tls();
    let rcv = Client::connect_tls(addr, "127.0.0.1", kh).unwrap();
    let snd = Client::connect_tls(addr, "127.0.0.1", kh).unwrap();
    roundtrip(rcv, snd);
}

#[test]
fn tls_wrong_keyhash_rejected() {
    let (addr, _kh) = start_tls();
    let wrong = [0x11u8; 32];
    let r = Client::connect_tls(addr, "127.0.0.1", wrong);
    assert!(r.is_err(), "client must reject a router whose keyHash does not match");
}

/// SEC-01 negative MITM test: attacker presents [leaf signed by EVIL CA, real pinned CA].
/// The pin check passes (last cert in chain == pinned CA), so only the webpki
/// leaf-signature verification against the pinned anchor can reject this.
#[test]
fn tls_mitm_evil_leaf_with_pinned_ca_rejected() {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
        ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PKCS_ED25519,
    };
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use smp_rs::crypto::sha256;
    use smp_rs::identity::RouterIdentity;

    // real router identity (what the client pins)
    let real = RouterIdentity::generate("127.0.0.1").unwrap();
    let pinned_hash = real.key_hash;

    // evil CA + leaf signed by the evil CA (SAN = 127.0.0.1, ServerAuth)
    let evil_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut evil_ca_params = CertificateParams::new(vec!["evil-ca".to_string()]).unwrap();
    evil_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    evil_ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
    let evil_ca = CertifiedIssuer::self_signed(evil_ca_params, evil_kp).unwrap();
    let evil_leaf_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut leaf_params = CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "127.0.0.1");
    leaf_params.distinguished_name = dn;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let evil_leaf = leaf_params.signed_by(&evil_leaf_kp, &evil_ca).unwrap();

    // attacker chain: evil leaf + the REAL pinned CA cert appended
    let chain: Vec<CertificateDer<'static>> = vec![
        CertificateDer::from(evil_leaf.der().to_vec()),
        CertificateDer::from(real.offline_der.clone()),
    ];
    let key = PrivatePkcs8KeyDer::from(evil_leaf_kp.serialize_der());
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key.into())
        .unwrap();
    let cfg = std::sync::Arc::new(cfg);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in listener.incoming().flatten() {
            let conn = rustls::ServerConnection::new(cfg.clone()).unwrap();
            let mut st = rustls::StreamOwned::new(conn, s);
            let mut buf = [0u8; 4096];
            let _ = std::io::Read::read(&mut st, &mut buf); // handshake happens here; client aborts
        }
    });

    let r = Client::connect_tls(addr, "127.0.0.1", pinned_hash);
    assert!(
        r.is_err(),
        "MITM with [evil_leaf, pinned_CA] must be rejected by leaf signature verification"
    );
    // sanity: the pinned hash is really the offline CA (sha256 of SPKI DER is what PinVerifier compares)
    assert_eq!(pinned_hash, sha256(&real.offline_der));
}


#[test]
fn auth_rejected_for_wrong_key() {
    let addr = start_plain();
    let kh = [0xEFu8; 32];
    let mut rcv = Client::connect_plain(addr, &kh).unwrap();
    let rcv_auth = ed25519_keypair();
    let other = ed25519_keypair();
    let dh = x25519_keypair();
    let (rcv_id, _snd, _sec, _dh) = new_queue(&mut rcv, &rcv_auth, &dh);
    let s = rcv.request(Command::Sub, rcv_id, Some(&other)).unwrap();
    assert!(matches!(&s[0], BrokerMsg::Err(e) if e.contains("AUTH")), "got {s:?}");
}

#[test]
fn tls_x25519_box_auth_roundtrip() {
    // v0.16: queue created with X25519 auth key, all commands authorized with the
    // crypto_box authenticator (secretbox(dhSecret, cbNonce(corrId), sha512(authorized))).
    let (addr, kh) = start_tls();
    let mut rcv = Client::connect_tls(addr, "127.0.0.1", kh).unwrap();
    assert!(rcv.server_eph_pub.is_some(), "server hello must carry ephemeral X25519 authPubKey");
    let qauth = x25519_keypair();
    let secret = rcv.box_secret(&qauth).expect("box secret from server eph pub");
    let dh = x25519_keypair();
    let resp = rcv
        .request_box(
            Command::New {
                rcv_auth_key: spki_x25519(&qauth.public.to_bytes()),
                rcv_dh_key: spki_x25519(&dh.public.to_bytes()),
                basic_auth: None,
                sub_mode: b'S',
                queue_req_data: None,
                ntf_creds: None,
            },
            vec![],
            &secret,
        )
        .expect("NEW box");
    let (rcv_id, snd_id, srv_dh) = match &resp[0] {
        BrokerMsg::Ids { rcv_id, snd_id, rcv_dh_key, .. } => {
            let (_a, raw) = parse_spki(rcv_dh_key).unwrap();
            (rcv_id.clone(), snd_id.clone(), raw)
        }
        other => panic!("expected IDS, got {other:?}"),
    };
    let shared = x25519_dh(&dh.secret, &x25519_public(srv_dh));
    // SUB with box auth
    let s = rcv.request_box(Command::Sub, rcv_id.clone(), &secret).unwrap();
    assert!(matches!(&s[0], BrokerMsg::Sok(_)), "SUB -> {s:?}");
    // sender sends (sender side has no auth by default)
    let mut snd = Client::connect_tls(addr, "127.0.0.1", kh).unwrap();
    let body = b"box-auth body".to_vec();
    let ok = snd
        .request(Command::Send { flags: false, body: body.clone() }, snd_id.clone(), None)
        .unwrap();
    assert!(matches!(&ok[0], BrokerMsg::Ok), "SEND -> {ok:?}");
    let pushed = rcv.recv_block().unwrap();
    let (msg_id, enc_body) = match &pushed[0] {
        BrokerMsg::Msg { msg_id, body } => (msg_id.clone(), body.clone()),
        other => panic!("expected MSG, got {other:?}"),
    };
    let plain = decrypt_for_recipient(&shared, &msg_id, &enc_body).expect("decrypt MSG");
    assert_eq!(plain, body);
    let ack = rcv.request_box(Command::Ack(msg_id), rcv_id.clone(), &secret).unwrap();
    assert!(matches!(&ack[0], BrokerMsg::Ok), "ACK -> {ack:?}");
    // negative: wrong dhSecret must be rejected
    let bad = [0xABu8; 32];
    let r = rcv.request_box(Command::Sub, rcv_id.clone(), &bad).unwrap();
    assert!(matches!(&r[0], BrokerMsg::Err(e) if e.contains("AUTH")), "got {r:?}");
}

#[test]
fn session_binding_rejects_nonempty_sid() {
    use smp_rs::client::check_session_binding;
    // v0.26: non-empty sessionId (TLS 1.3 Finished) is valid; assertion vs tls-unique happens in handshake
    assert!(check_session_binding(b"").is_ok());
    assert!(check_session_binding(&[7u8; 32]).is_ok());
}

#[test]
fn v0_18_garbage_block_does_not_kill_connection() {
    // raw-socket robustness: malformed transmissions get no crash; a valid PING
    // in the same batch still gets PONG.
    use smp_rs::protocol::{decode_block, encode_block, encode_command, encode_transmission, Command, Transmission, SMP_VERSION};
    use smp_rs::transport::{client_hello_block, connect_plain, read_block, write_block};
    let addr = start_plain();
    let mut s = connect_plain(addr).unwrap();
    let sh = read_block(&mut s).unwrap();
    let _ = smp_rs::transport::parse_server_hello_key(&sh).unwrap();
    let kh = [0xEFu8; 32];
    write_block(&mut s, &client_hello_block(SMP_VERSION, &kh, false).unwrap()).unwrap();

    let ping = Transmission {
        authenticator: vec![],
        corr_id: smp_rs::crypto::random_bytes(24),
        entity_id: vec![],
        command: encode_command(&Command::Ping).unwrap(),
    };
    let garbage = vec![0xff, 0x00, 0x13, 0x37]; // undecodable transmission
    let blk = encode_block(&[garbage, encode_transmission(&ping).unwrap()]).unwrap();
    write_block(&mut s, &blk).unwrap();
    let resp = read_block(&mut s).unwrap();
    let msgs = decode_block(&resp).unwrap();
    let mut saw_pong = false;
    for w in &msgs {
        if let Ok(t) = smp_rs::protocol::decode_transmission(w) {
            if t.command.starts_with(b"PONG") {
                saw_pong = true;
            }
        }
    }
    assert!(saw_pong, "PING must be answered even after garbage in the same block");
    // connection still alive: one more PING
    let ping2 = Transmission {
        authenticator: vec![],
        corr_id: smp_rs::crypto::random_bytes(24),
        entity_id: vec![],
        command: encode_command(&Command::Ping).unwrap(),
    };
    write_block(&mut s, &encode_block(&[encode_transmission(&ping2).unwrap()]).unwrap()).unwrap();
    let resp2 = read_block(&mut s).unwrap();
    let msgs2 = decode_block(&resp2).unwrap();
    assert!(msgs2.iter().any(|w| smp_rs::protocol::decode_transmission(w).map(|t| t.command.starts_with(b"PONG")).unwrap_or(false)));
}

#[test]
fn channel_binding_rejects_rewritten_sid() {
    use smp_rs::client::{check_session_binding, verify_channel_binding};
    let real = [9u8; 32];
    assert!(check_session_binding(&real).is_ok());
    assert!(check_session_binding(b"").is_ok());
    assert!(check_session_binding(b"short").is_err());
    assert!(verify_channel_binding(&real, &real).is_ok());
    assert!(verify_channel_binding(&[8u8; 32], &real).is_err());
    assert!(verify_channel_binding(b"", b"").is_err());
}

/// Task 3.3 (G4) — the TLS channel binding used for the SMP session id must be
/// explicit: either the RFC 8446 exporter output (rustls) or the raw TLS 1.3
/// Finished verify_data (upstream-compatible).
///
/// The invariants matter more than the choice: a `Finished` binding must never
/// silently fall back to the exporter when the Finished value is missing or the
/// wrong length, because that would break the upstream contract without any
/// visible symptom.
#[test]
fn session_id_binding_derive_invariants() {
    use smp_rs::transport::{derive_session_id, SessionIdBinding};

    let exporter = [7u8; 32];
    assert_eq!(
        derive_session_id(SessionIdBinding::Exporter, &exporter, None).unwrap(),
        exporter.to_vec()
    );

    let finished = [9u8; 32];
    assert_eq!(
        derive_session_id(SessionIdBinding::Finished, &exporter, Some(&finished)).unwrap(),
        finished.to_vec()
    );

    // No silent fallback: a missing or malformed Finished is an error.
    assert!(derive_session_id(SessionIdBinding::Finished, &exporter, None).is_err());
    assert!(derive_session_id(SessionIdBinding::Finished, &exporter, Some(&[1u8; 16])).is_err());
    assert!(derive_session_id(SessionIdBinding::Finished, &exporter, Some(&[])).is_err());
}

/// Task 3.3 (G4) — in TLS mode the server hands out a 32-byte channel-bound
/// session id, and the client accepts it only because it matches its own
/// derivation over the same TLS session.
#[test]
fn tls_session_id_is_32_byte_channel_binding() {
    let (addr, kh) = start_tls();
    let c = Client::connect_tls(addr, "127.0.0.1", kh).unwrap();
    assert_eq!(c.session_id().len(), 32);
    assert_ne!(c.session_id(), &[0u8; 32][..]);
}

