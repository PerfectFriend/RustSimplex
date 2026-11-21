//! Task 3.3 (G4) — the upstream-compatible TLS 1.3 Finished channel binding.
//!
//! Upstream (simplexmq on hs-tls) binds the SMP session id to the TLS 1.3
//! Finished verify_data: the server sets `sessionId = getPeerFinished` (the
//! CLIENT's Finished) and the client aborts unless the server's session id
//! equals its own `getFinished`.
//!
//! rustls 0.23 does not expose the Finished verify_data — the value only lives
//! inside the handshake state machine, and RFC 8446's exporter has no label
//! that reproduces it. The rustls path therefore binds the session id to the
//! exporter output instead: the same 32-byte, symmetric, transcript-bound
//! property, but NOT byte-equal to upstream's `tlsUnique`.
//!
//! These tests pin both facts:
//!
//!   1. the Finished binding is implementable and symmetric — with openssl on
//!      both ends the client's own Finished equals the server's view of it;
//!   2. the rustls exporter output is NOT the TLS Finished, so a rustls server's
//!      session id is not byte-compatible with upstream.

#![cfg(feature = "v71-probes")]

use std::net::{TcpListener, TcpStream};

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{
    Ssl, SslAcceptor, SslConnector, SslMethod, SslVerifyMode, SslVersion,
};
use openssl::x509::{X509NameBuilder, X509};

use smp_rs::server::{spawn_engine, Engine};
use smp_rs::transport::{derive_session_id, parse_server_hello_key, read_block_tol, SessionIdBinding};

fn self_signed() -> (X509, PKey<Private>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(key).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "localhost").unwrap();
    let name = name.build();

    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&pkey).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
    let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
    b.set_serial_number(&serial).unwrap();
    b.sign(&pkey, MessageDigest::sha256()).unwrap();
    (b.build(), pkey)
}

fn openssl_client(addr: std::net::SocketAddr) -> openssl::ssl::SslStream<TcpStream> {
    let tcp = TcpStream::connect(addr).unwrap();
    let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
    connector.set_verify(SslVerifyMode::NONE);
    // ALPN wire format: one length-prefixed protocol name.
    connector.set_alpn_protos(b"\x05smp/1").unwrap();
    // Pin a SHA-256 suite so the Finished verify_data is 32 bytes — otherwise the
    // comparison against the rustls session id (also 32 bytes) would be trivially
    // decided by the length alone.
    connector.set_ciphersuites("TLS_AES_128_GCM_SHA256").unwrap();
    let mut ssl = Ssl::new(connector.build().context()).unwrap();
    ssl.set_min_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    let mut stream = openssl::ssl::SslStream::new(ssl, tcp).unwrap();
    stream.connect().unwrap();
    stream
}

/// The Finished verify_data is the upstream `tlsUnique`: the client's own
/// Finished must equal the server's view of it, and it must be 32 bytes.
#[test]
fn openssl_finished_is_the_upstream_channel_binding() {
    let (cert, pkey) = self_signed();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor.set_certificate(&cert).unwrap();
    acceptor.set_private_key(&pkey).unwrap();
    acceptor.set_min_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    let acceptor = acceptor.build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let stream = acceptor.accept(tcp).unwrap();
        let mut buf = [0u8; 64];
        let n = stream.ssl().peer_finished(&mut buf);
        buf[..n].to_vec()
    });

    let client = openssl_client(addr);
    let mut buf = [0u8; 64];
    let n = client.ssl().finished(&mut buf);
    let own = buf[..n].to_vec();
    // close the connection before joining: the server thread must not wait for a peer
    drop(client);
    let peer = server.join().unwrap();

    assert_eq!(own.len(), 32, "the TLS 1.3 Finished verify_data must be 32 bytes with a SHA-256 suite");
    assert_eq!(
        own, peer,
        "the server's view of the client's Finished must equal the client's own Finished"
    );
    // and the Finished binding derives exactly those bytes
    assert_eq!(
        derive_session_id(SessionIdBinding::Finished, &[0u8; 32], Some(&own)).unwrap(),
        own
    );
}

/// The rustls path binds the session id to the RFC 8446 exporter output, which
/// is NOT the TLS Finished — so a rustls server's session id is not
/// byte-compatible with upstream's `tlsUnique`.
#[test]
fn rustls_exporter_is_not_the_tls_finished() {
    let e = Engine::bind_tls("127.0.0.1:0", "127.0.0.1").unwrap();
    let (addr, _st, _sd, _h) = spawn_engine(e);

    let mut client = openssl_client(addr);
    let mut buf = [0u8; 64];
    let n = client.ssl().finished(&mut buf);
    let finished = buf[..n].to_vec();

    // the SMP server hello carries the server's session id
    let block = read_block_tol(&mut client).unwrap();
    let (_min, _max, sid, _auth) = parse_server_hello_key(&block).unwrap();

    assert_eq!(finished.len(), 32);
    assert_eq!(sid.len(), 32);
    assert_ne!(
        sid, finished,
        "the rustls session id is the exporter output, not the TLS Finished"
    );
}
