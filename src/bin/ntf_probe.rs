//! Live NTF probe (feature v71-probes): NTF handshake + PING against a public notifications server.
//!
//! NTF is a separate protocol from SMP (learned from simplexmq Notifications/Transport.hs):
//! - TLS 1.3, ALPN `ntf/1` (port 443); rustls fails the handshake, openssl works;
//! - block size **512** bytes: `u16 BE len + payload + '#' padding`;
//! - server hello: `u16 minVer + u16 maxVer + sessionId(short 32) [+ authPubKey Large(DER)]`;
//! - client hello: `u16 ntfVersion + keyHash` (keyHash = ByteString encoding: len byte + 32B);
//! - keyHash = SHA-256 over the DER of the **CA certificate** in the served chain.
//!
//! Two paths:
//! - positive: the **library** `NtfClient` performs the handshake and the `PING → PONG` round-trip
//!   (this is what proves the public API works against the real server);
//! - negative control (`NTF_BAD_HASH=1`): a hand-rolled client hello with a corrupted keyHash —
//!   the server must close the connection.
//!
//! The CA fingerprint pin is mandatory in both paths: the probe refuses to send anything when the
//! served CA does not match the expected fingerprint (exit code 3).
use openssl::ssl::{Ssl, SslConnector, SslMethod, SslVerifyMode, SslVersion};
use smp_rs::ntf::*;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

type S = openssl::ssl::SslStream<TcpStream>;

/// base64url decoder (no padding), tolerant of a trailing '='.
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
            if c == b'=' {
                break;
            }
            return Err(format!("bad b64 char {c}"));
        }
        acc = (acc << 6) | v as u64 as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Ok(out)
}

fn tls_connect(host: &str, port: u16) -> S {
    let addr: std::net::SocketAddr = format!("{host}:{port}").to_socket_addrs().expect("dns").next().expect("addr");
    let mut b = SslConnector::builder(SslMethod::tls()).expect("connector");
    b.set_verify(SslVerifyMode::NONE);
    b.set_min_proto_version(Some(SslVersion::TLS1_3)).expect("tls13");
    let connector = b.build();
    let tcp = TcpStream::connect(addr).expect("tcp");
    tcp.set_read_timeout(Some(Duration::from_secs(15))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(15))).ok();
    let mut ssl = Ssl::new(connector.context()).expect("ssl");
    ssl.set_alpn_protos(b"\x05ntf/1").expect("alpn");
    ssl.set_hostname(host).expect("sni");
    let stream = ssl.connect(tcp).expect("tls handshake");
    println!("tls ok {host}:{port} alpn={:?}", stream.ssl().selected_alpn_protocol());
    stream
}

/// CA certificate DER of the served chain (the fingerprint source for keyHash).
fn ca_cert_der(s: &S) -> Vec<u8> {
    let chain = s.ssl().peer_cert_chain().expect("chain");
    let mut certs = Vec::new();
    for i in 0..chain.len() {
        if let Some(c) = chain.get(i) {
            certs.push(c.to_der().expect("der"));
        }
    }
    certs.last().cloned().expect("ca cert")
}

fn read_ntf_block(s: &mut S) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; NTF_BLOCK_SIZE];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_ntf_block(s: &mut S, payload: &[u8]) -> std::io::Result<()> {
    let block = pad_ntf_block(payload).expect("pad");
    s.write_all(&block)?;
    s.flush()
}

/// Negative control: a hand-rolled client hello with a corrupted keyHash. The server must close
/// the connection instead of accepting the session.
fn negative_control(s: &mut S, kh: [u8; 32]) {
    let sh_block = read_ntf_block(s).expect("server hello block");
    let sh_payload = unpad_ntf_block(&sh_block).expect("unpad server hello");
    let sh = parse_ntf_server_handshake(&sh_payload).expect("parse server hello");
    println!(
        "server hello: minVer={} maxVer={} sessionId={}B authPubKey={}",
        sh.min_version,
        sh.max_version,
        sh.session_id.len(),
        sh.auth_pub_key.as_ref().map(|k| format!("{}B", k.len())).unwrap_or_else(|| "none".into())
    );
    let ver = negotiate_ntf_version(&sh).expect("negotiate");
    let mut bad = kh;
    bad[0] ^= 0xFF;
    println!("(negative control: sending a corrupted keyHash)");
    let ch = encode_ntf_client_handshake(&NtfClientHandshake { ntf_version: ver, key_hash: bad });
    write_ntf_block(s, &ch).expect("client hello");
    match read_ntf_block(s) {
        Ok(block) => {
            let payload = unpad_ntf_block(&block).expect("unpad reply");
            println!("server replied instead of closing: {}B payload", payload.len());
            eprintln!("NEGATIVE CONTROL FAILED: the server accepted a corrupted keyHash");
            std::process::exit(5);
        }
        Err(e) => {
            println!("server closed the connection after the corrupted keyHash (expected): {e}");
            println!("LIVE NTF OK (negative control): corrupted keyHash rejected");
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let host = args.first().cloned().unwrap_or_else(|| "ntf2.simplex.im".into());
    let port: u16 = args.get(1).and_then(|p| p.parse().ok()).unwrap_or(443);
    // Expected CA fingerprint (base64url, no padding). Pinning is mandatory: an NTF client that
    // trusts whatever CA the peer presents can be MITM'd by anyone who serves their own chain.
    let expected_fp = args
        .get(2)
        .cloned()
        .or_else(|| std::env::var("NTF_EXPECTED_FP").ok())
        .unwrap_or_else(|| {
            eprintln!("usage: ntf-probe <host> <port> <expected-ca-fingerprint-b64url>");
            eprintln!("       (or set NTF_EXPECTED_FP)");
            std::process::exit(2);
        });
    let expected = {
        let raw = b64url_dec(expected_fp.trim_end_matches('=')).unwrap_or_else(|e| {
            eprintln!("bad expected fingerprint: {e}");
            std::process::exit(2);
        });
        let arr: [u8; 32] = raw.try_into().unwrap_or_else(|_| {
            eprintln!("expected fingerprint must be 32 bytes");
            std::process::exit(2);
        });
        arr
    };
    let mut s = tls_connect(&host, port);

    let ca_der = ca_cert_der(&s);
    let kh = key_hash_from_ca_der(&ca_der);
    println!("keyHash(sha256 CA DER) = {}", hex::encode(kh));
    // PIN: the served CA fingerprint MUST equal the expected one — otherwise refuse to proceed.
    if kh != expected {
        eprintln!("PIN FAILURE: served CA fingerprint {} != expected {}", hex::encode(kh), hex::encode(expected));
        std::process::exit(3);
    }
    println!("pin ok: CA fingerprint matches the expected value");

    if std::env::var("NTF_BAD_HASH").is_ok() {
        negative_control(&mut s, kh);
        return;
    }

    // Positive path: the **library** NtfClient performs the handshake and the PING -> PONG
    // round-trip. This proves the public API works against the real server.
    let mut client = NtfClient::connect(&mut s, &ca_der, kh).expect("NtfClient::connect");
    println!(
        "library client connected: NTF v{}, sessionId={}B",
        client.version(),
        client.session_id().len()
    );
    match client.ping() {
        Ok(resp) => {
            println!(
                "response: tag={} corrMatch={} entityId={}B",
                String::from_utf8_lossy(resp.tag.tag_bytes()),
                resp.corr_id == (0u8..24).collect::<Vec<u8>>(),
                resp.entity_id.len()
            );
            if resp.tag == NtfResponseTag::Pong {
                println!("LIVE NTF OK: PING -> PONG (via library NtfClient)");
            } else {
                eprintln!("unexpected response tag");
                std::process::exit(4);
            }
        }
        Err(e) => {
            eprintln!("no PONG: {e}");
            std::process::exit(4);
        }
    }
}
