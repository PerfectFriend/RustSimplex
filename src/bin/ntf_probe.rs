//! Live NTF probe (feature v71-probes): NTF handshake against a public notifications server.
//!
//! NTF is a separate protocol from SMP (learned from simplexmq Notifications/Transport.hs):
//! - TLS 1.3, ALPN `ntf/1` (port 443); rustls fails the handshake, openssl works;
//! - block size **512** bytes: `u16 BE len + payload + '#' padding`;
//! - server hello: `u16 minVer + u16 maxVer + sessionId(short 32) [+ authPubKey Large(DER)]`;
//! - client hello: `u16 ntfVersion + keyHash` (keyHash = ByteString encoding: len byte + 32B);
//! - keyHash = SHA-256 over the DER of the **CA certificate** in the served chain.
//!
//! NoVerify pin probe — diagnostics only, never for production traffic.
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
        acc = (acc << 6) | v as u32;
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

    let kh = key_hash_from_ca_der(&ca_cert_der(&s));
    println!("keyHash(sha256 CA DER) = {}", hex::encode(kh));
    // PIN: the served CA fingerprint MUST equal the expected one — otherwise refuse to proceed.
    if kh != expected {
        eprintln!("PIN FAILURE: served CA fingerprint {} != expected {}", hex::encode(kh), hex::encode(expected));
        std::process::exit(3);
    }
    println!("pin ok: CA fingerprint matches the expected value");
    // negative control: NTF_BAD_HASH=1 sends a wrong fingerprint — the server must close the conn
    let kh = if std::env::var("NTF_BAD_HASH").is_ok() {
        let mut bad = kh;
        bad[0] ^= 0xFF;
        println!("(negative control: using corrupted keyHash)");
        bad
    } else {
        kh
    };

    let sh_block = read_ntf_block(&mut s).expect("server hello block");
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
    let ch = encode_ntf_client_handshake(&NtfClientHandshake { ntf_version: ver, key_hash: kh });
    write_ntf_block(&mut s, &ch).expect("client hello");
    println!("client hello sent (v{ver}, {} bytes)", ch.len());

    // The server may answer with a handshake error block; read one if present.
    let mut peek = [0u8; 1];
    match s.read(&mut peek) {
        Ok(1) => {
            println!("server replied after client hello (first byte 0x{:02x})", peek[0]);
            let mut rest = vec![0u8; NTF_BLOCK_SIZE - 1];
            s.read_exact(&mut rest).expect("rest of block");
            let mut block = vec![peek[0]];
            block.extend_from_slice(&rest);
            let payload = unpad_ntf_block(&block).expect("unpad reply");
            println!("reply payload ({}B): {}", payload.len(), hex::encode(&payload[..payload.len().min(64)]));
        }
        Ok(_) => {
            println!("server closed connection after client hello");
            return;
        }
        Err(e) => println!("no reply yet (expected on a healthy handshake): {e}"),
    }

    // NTF command round-trip: PING -> PONG
    // NTF v>=2 implies the sessionId (no sessionId on the wire) and uses batch framing:
    // block payload = u8 count + count * Large(transmission).
    let corr_id: Vec<u8> = (0u8..24).collect();
    let ping = NtfTransmission {
        authenticator: Vec::new(),
        corr_id: corr_id.clone(),
        entity_id: Vec::new(),
        command: NtfCommand::new(NtfCommandTag::Ping).encode(),
    };
    let batch = encode_ntf_batch(std::slice::from_ref(&ping));
    write_ntf_block(&mut s, &batch).expect("send PING");
    println!("PING sent (batch {}B, corrId {})", batch.len(), hex::encode(&corr_id));

    match read_ntf_block(&mut s) {
        Ok(block) => {
            let payload = unpad_ntf_block(&block).expect("unpad PONG block");
            println!("response block payload ({}B): {}", payload.len(), hex::encode(&payload[..payload.len().min(64)]));
            let ts = parse_ntf_batch(&payload).expect("parse NTF batch");
            for t in &ts {
                let (tag, rest) = split_ntf_response(&t.command).unwrap_or((NtfResponseTag::Ok, &[]));
                println!(
                    "response: tag={} corrMatch={} entityId={}B rest={}",
                    String::from_utf8_lossy(tag.tag_bytes()),
                    t.corr_id == corr_id,
                    t.entity_id.len(),
                    hex::encode(rest)
                );
                if tag == NtfResponseTag::Pong {
                    println!("LIVE NTF OK: PING -> PONG");
                }
            }
        }
        Err(e) => println!("no PONG: {e}"),
    }
}
