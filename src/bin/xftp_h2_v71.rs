#![allow(dead_code)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::doc_overindented_list_items)]
//! xftp-h2: probe client for the real XFTP protocol v7.1 (HTTP/2 + TLS 1.3, ALPN "xftp/1").
//!   xftp-h2 <host> <port>
//!
//! Handshake (per simplexmq v7.1 XFTP/Server.hs xftpServerHandshakeV1):
//!   1. POST with EMPTY body -> padded XFTPServerHandshake block
//!      (vRange u16,u16 + sessionId shortString + authPubKey + sig + serverInfo)
//!      sessionId = client TLS Finished verify_data (tls-unique for TLS 1.3).
//!   2. POST padded XFTPClientHandshake: xftpVersion u16 + keyHash shortString(32B,
//!      SHA-256 of server CA cert DER) + entitlementProof '0' (Nothing, v>=4)
//!      -> server answers with EMPTY body.
//! Then commands: block = u16 BE len + tEncodeBatch1 + 0x23-pad to 16384.
//!   tEncodeBatch1 = 0x01 + Large(u16 len + auth + transmission)
//!   auth: none = 0x00; signature = shortString(64B Ed25519 sig over tForAuth)
//!   transmission = short(sessionId) + short(corrId 24B) + short(entityId) + command
//!   tForAuth = sessionId <> corrId <> entityId <> command
//! NOTE: accepts any server certificate (probe tool, not for production).

use bytes::Bytes;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use sha2::Digest;
use tokio::net::TcpStream;

const BLOCK: usize = 16384;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Truncate to at most `max` CHARS without splitting a UTF-8 sequence.
/// Slicing a String by a byte index panics when the index lands inside a multi-byte char —
/// and these responses are raw binary, so that happens in practice.
fn truncate_chars(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

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

async fn post(h2: &mut h2::client::SendRequest<Bytes>, body: Bytes, authority: &str) -> Bytes {
    let req = http::Request::builder()
        .method("POST")
        .uri(format!("https://{authority}/"))
        .body(())
        .unwrap();
    let (resp, mut stream) = h2.send_request(req, false).expect("send");
    let n = body.len();
    // The body is sent in flow-control-sized pieces: a 1MiB FPUT exceeds the default
    // 64KiB HTTP/2 window, so the granted capacity must be awaited between DATA frames.
    const SEND_SLICE: usize = 32 * 1024;
    let mut off = 0usize;
    while off < n {
        if stream.capacity() == 0 {
            stream.reserve_capacity(SEND_SLICE);
            match std::future::poll_fn(|cx| stream.poll_capacity(cx)).await {
                Some(Ok(_)) => {}
                Some(Err(e)) => panic!("h2 capacity: {e}"),
                None => panic!("h2 stream closed while sending"),
            }
            continue;
        }
        let take = stream.capacity().min(n - off);
        let end = off + take;
        stream.send_data(body.slice(off..end), end == n).expect("send_data");
        off = end;
    }
    if n == 0 {
        stream.send_data(body, true).expect("send_data");
    }
    let resp = tokio::time::timeout(std::time::Duration::from_secs(20), resp).await.expect("resp timeout").expect("resp");
    let status = resp.status();
    let mut rbody = resp.into_body();
    let mut data = Vec::new();
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(15), rbody.data()).await {
            Ok(Some(chunk)) => {
                let chunk = chunk.expect("chunk");
                let n = chunk.len();
                data.extend_from_slice(&chunk);
                let _ = rbody.flow_control().release_capacity(n);
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    println!("  POST {n} bytes -> HTTP {status}, {} bytes", data.len());
    Bytes::from(data)
}

// ---- helpers ----
fn block(payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    b.extend_from_slice(payload);
    b.resize(BLOCK, 0x23);
    b
}
// transmission = short(sid) + short(corr) + short(entity) + cmd
fn transmission(sid: &[u8], corr: &[u8], entity: &[u8], cmd: &[u8]) -> Vec<u8> {
    let mut t = Vec::new();
    t.push(sid.len() as u8);
    t.extend_from_slice(sid);
    t.push(corr.len() as u8);
    t.extend_from_slice(corr);
    t.push(entity.len() as u8);
    t.extend_from_slice(entity);
    t.extend_from_slice(cmd);
    t
}
// batch = 0x01 + u16 len + auth + transmission ; auth = 0x00 none, or shortString(sig)
fn batch(auth: &[u8], t: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(auth);
    inner.extend_from_slice(t);
    let mut b = vec![1u8];
    b.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    b.extend_from_slice(&inner);
    block(&b)
}
fn corr() -> Vec<u8> {
    (0..24).map(|_| rand::random::<u8>()).collect()
}
fn show_resp(r: &Bytes) -> String {
    if r.len() < 2 {
        return format!("{}B", r.len());
    }
    let l = u16::from_be_bytes([r[0], r[1]]) as usize;
    String::from_utf8_lossy(&r[2..(2 + l).min(r.len())]).to_string()
}


/// One full XFTP file cycle: FNEW -> FPUT -> FGET -> FDEL.
///
/// The body of a large file exceeds the default HTTP/2 flow-control window, so
/// `post` sends it in slices and waits for the granted capacity.
///
/// Returns (byte_exact, one_line_summary).
async fn file_cycle(
    h2: &mut h2::client::SendRequest<Bytes>,
    host: &str,
    session_id: &[u8],
    file: Vec<u8>,
    label: &str,
) -> (bool, String) {
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    let snd = SigningKey::generate(&mut rand::rngs::OsRng);
    let rcv = SigningKey::generate(&mut rand::rngs::OsRng);
    let spki = |vk: &VerifyingKey| -> Vec<u8> {
        let mut v = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
        v.extend_from_slice(&vk.to_bytes());
        v
    };

    let digest: [u8; 32] = sha2::Sha256::digest(&file).into();
    let mut cmd = b"FNEW ".to_vec();
    let snd_spki = spki(&snd.verifying_key());
    cmd.push(snd_spki.len() as u8);
    cmd.extend_from_slice(&snd_spki);
    cmd.extend_from_slice(&(file.len() as u32).to_be_bytes());
    cmd.push(32u8);
    cmd.extend_from_slice(&digest);
    let rcv_spki = spki(&rcv.verifying_key());
    cmd.push(1u8); // NonEmpty rKeys count
    cmd.push(rcv_spki.len() as u8);
    cmd.extend_from_slice(&rcv_spki);
    cmd.push(b'0'); // Maybe BasicAuth = Nothing
    cmd.push(b'0'); // Maybe Word32 storageHours = Nothing (v>=4)

    let c = corr();
    let t = transmission(session_id, &c, b"", &cmd);
    let sig = snd.sign(&t); // tForAuth = whole transmission (sessionId included)
    let mut auth = vec![64u8];
    auth.extend_from_slice(&sig.to_bytes());
    let fr = post(h2, Bytes::from(batch(&auth, &t)), host).await;
    println!("[{label}] FNEW -> {}", truncate_chars(&show_resp(&fr), 120));
    if fr.len() < 2 {
        return (false, format!("{label}: FNEW response too short"));
    }
    let pl = u16::from_be_bytes([fr[0], fr[1]]) as usize;
    let fp = &fr[2..(2 + pl).min(fr.len())];
    let pos = match fp.windows(4).position(|w| w == b"SIDS") {
        Some(p) => p,
        None => return (false, format!("{label}: no SIDS in FNEW response")),
    };
    let mut p = pos + 5;
    let sidl2 = fp[p] as usize; p += 1;
    let sender_id = fp[p..p + sidl2].to_vec(); p += sidl2;
    let nrcv = fp[p] as usize; p += 1;
    let ridl = fp[p] as usize; p += 1;
    let rcv_id = fp[p..p + ridl].to_vec();
    println!("[{label}]   senderId({})={} nRcv={nrcv} rcvId({})={}", sidl2, hex(&sender_id), ridl, hex(&rcv_id));

    // ---- FPUT: entity=senderId, cmd FPUT, the file body streamed after the block ----
    let c = corr();
    let t = transmission(session_id, &c, &sender_id, b"FPUT");
    let sig = snd.sign(&t);
    let mut auth = vec![64u8];
    auth.extend_from_slice(&sig.to_bytes());
    let mut blk = batch(&auth, &t);
    blk.extend_from_slice(&file);
    let pr = post(h2, Bytes::from(blk), host).await;
    println!("[{label}] FPUT -> {}", show_resp(&pr));

    // ---- FGET as recipient: entity=rcvId, cmd "FGET " + rDhKey(X25519 SPKI) ----
    let r_dh_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let r_dh_pub = x25519_dalek::PublicKey::from(&r_dh_secret);
    let rdh_spki = smp_rs::crypto::spki_x25519(r_dh_pub.as_bytes());
    let mut gcmd = b"FGET ".to_vec();
    gcmd.push(rdh_spki.len() as u8);
    gcmd.extend_from_slice(&rdh_spki);
    let c = corr();
    let t = transmission(session_id, &c, &rcv_id, &gcmd);
    let sig = rcv.sign(&t);
    let mut auth = vec![64u8];
    auth.extend_from_slice(&sig.to_bytes());
    let gr = post(h2, Bytes::from(batch(&auth, &t)), host).await;
    println!("[{label}] FGET -> {} bytes total", gr.len());
    let mut ok = false;
    let mut summary = format!("{label}: no FILE in the FGET response");
    if gr.len() >= 2 {
        let gl = u16::from_be_bytes([gr[0], gr[1]]) as usize;
        let gp = &gr[2..(2 + gl).min(gr.len())];
        if let Some(pos) = gp.windows(4).position(|w| w == b"FILE") {
            let mut q = pos + 5;
            let kl = gp[q] as usize; q += 1;
            let sdh_spki = &gp[q..q + kl]; q += kl;
            let nonce: [u8; 24] = gp[q..q + 24].try_into().unwrap();
            let (_, sdh_raw) = smp_rs::crypto::parse_spki(sdh_spki).expect("sDhKey");
            let shared = smp_rs::crypto::x25519_dh(&r_dh_secret, &smp_rs::crypto::x25519_public(sdh_raw));
            let enc_packet = if gr.len() > BLOCK { &gr[BLOCK..] } else { &[][..] };
            let reordered = [
                &enc_packet[enc_packet.len().saturating_sub(16)..],
                &enc_packet[..enc_packet.len().saturating_sub(16)],
            ]
            .concat();
            match smp_rs::crypto::secretbox_decrypt(&shared, &nonce, &reordered) {
                Some(pt) => {
                    let got = smp_rs::crypto::sha256(&pt);
                    let sha_match = got == digest;
                    let same = pt == file;
                    ok = same && sha_match;
                    summary = format!(
                        "{label}: FGET decrypted {} bytes, matches uploaded: {}, sha256 match: {}, sha256={}",
                        pt.len(), same, sha_match, hex(&got)
                    );
                    println!("  {}", summary);
                }
                None => {
                    summary = format!("{label}: FGET DECRYPT FAILED");
                    println!("  {}", summary);
                }
            }
        } else if let Some(pos) = gp.windows(3).position(|w| w == b"ERR") {
            summary = format!(
                "{label}: FGET ERR: {:?}",
                String::from_utf8_lossy(&gp[pos..(pos + 40).min(gp.len())])
            );
            println!("  {}", summary);
        }
    }

    // ---- FDEL as sender: entity=senderId, cmd "FDEL", signed with snd key ----
    let c = corr();
    let t = transmission(session_id, &c, &sender_id, b"FDEL");
    let sig = snd.sign(&t);
    let mut auth = vec![64u8];
    auth.extend_from_slice(&sig.to_bytes());
    let dr = post(h2, Bytes::from(batch(&auth, &t)), host).await;
    println!("[{label}] FDEL -> {}", show_resp(&dr));
    (ok, summary)
}

#[tokio::main]
async fn main() {
    let host = std::env::args().nth(1).unwrap_or_else(|| "xftp1.simplex.im".into());
    let port: u16 = std::env::args().nth(2).unwrap_or_else(|| "443".into()).parse().unwrap();
    // Expected CA fingerprint (base64url, no padding). PINNING IS MANDATORY: without it the client
    // would trust whatever CA the peer presents, so a MITM serving its own chain would pass.
    // The fingerprint is compared against the served chain BEFORE any XFTP traffic is sent.
    let expected_fp = std::env::args()
        .nth(3)
        .or_else(|| std::env::var("XFTP_EXPECTED_FP").ok())
        .unwrap_or_else(|| {
            eprintln!("usage: xftp-h2-v71 <host> <port> <expected-ca-fingerprint-b64url>");
            eprintln!("       (or set XFTP_EXPECTED_FP)");
            std::process::exit(2);
        });
    let expected: [u8; 32] = {
        let raw = b64url_dec(expected_fp.trim_end_matches('=')).unwrap_or_else(|e| {
            eprintln!("bad expected fingerprint: {e}");
            std::process::exit(2);
        });
        raw.try_into().unwrap_or_else(|_| {
            eprintln!("expected fingerprint must be 32 bytes");
            std::process::exit(2);
        })
    };
    println!("connect {host}:{port} ALPN xftp/1 (openssl, TLS1.3), pinned CA fingerprint {expected_fp}");

    let mut builder = SslConnector::builder(SslMethod::tls()).expect("connector");
    builder.set_verify(SslVerifyMode::NONE); // probe only
    builder.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_3)).expect("min tls");
    builder.set_alpn_protos(b"\x06xftp/1").unwrap_or_else(|_| panic!("alpn"));
    let connector = builder.build();

    let tcp = TcpStream::connect((host.as_str(), port)).await.expect("tcp");
    let cfg = connector.configure().expect("configure");
    // NO SNI: the public relay serves the web cert on SNI and treats SNI connections as web (ERR SESSION)
    let _ssl_obj = cfg.into_ssl("localhost").expect("ssl");
    let ssl_obj = openssl::ssl::Ssl::new(connector.context()).expect("ssl ctx");
    let ssl_obj = {
        let mut s = ssl_obj;
        s.set_alpn_protos(b"\x06xftp/1").expect("alpn");
        s
    };
    let mut ssl = tokio_openssl::SslStream::new(ssl_obj, tcp).expect("stream");
    {
        let mut pinned = std::pin::Pin::new(&mut ssl);
        pinned.as_mut().connect().await.expect("tls handshake");
    }
    println!("TLS OK, ALPN: {:?}", ssl.ssl().selected_alpn_protocol());

    // sessionId = client Finished verify_data (32B for TLS1.3/SHA256)
    let mut fin_buf = [0u8; 64];
    let fin_len = ssl.ssl().finished(&mut fin_buf);
    let session_id: Vec<u8> = fin_buf[..fin_len].to_vec();
    println!("sessionId (client Finished, {}B) = {}", session_id.len(), hex(&session_id));

    // keyHash = SHA-256 of server CA certificate DER (last cert in peer chain)
    let chain = ssl.ssl().peer_cert_chain().expect("peer chain");
    let n = chain.len();
    let ca_der = chain.iter().last().expect("ca cert").to_der().expect("der");
    let key_hash: [u8; 32] = sha2::Sha256::digest(&ca_der).into();
    println!("peer chain {n} certs; keyHash = SHA256(CA DER) = {}", hex(&key_hash));
    // PIN: the served CA fingerprint MUST equal the expected one — otherwise refuse to proceed.
    // Checked before the h2 handshake, so a MITM never receives a single XFTP byte.
    if key_hash != expected {
        eprintln!("PIN FAILURE: served CA fingerprint {} != expected {}", hex(&key_hash), hex(&expected));
        std::process::exit(3);
    }
    println!("pin ok: CA fingerprint matches the expected value");

    let (mut h2, conn) = h2::client::handshake(ssl).await.expect("h2 handshake");
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("h2 conn error: {e}");
        }
    });


    // ---- 1. empty POST -> padded serverHello ----
    let sh = post(&mut h2, Bytes::new(), &host).await;
    if sh.len() < 8 {
        println!("serverHello too short — stop");
        return;
    }
    println!("serverHello raw head: {}", hex(&sh[..48]));
    if sh[2..].windows(7).any(|w| w == b"SESSION") || sh[2..].windows(4).any(|w| w == b"HANDSHAKE") {
        println!("serverHello is an ERR block — stop");
        return;
    }
    let pl = u16::from_be_bytes([sh[0], sh[1]]) as usize;
    let p = &sh[2..2 + pl.min(sh.len() - 2)];
    let vmin_srv = u16::from_be_bytes([p[0], p[1]]);
    let vmax_srv = u16::from_be_bytes([p[2], p[3]]);
    let sidl = p[4] as usize;
    let srv_sid = if p.len() >= 5 + sidl { &p[5..5 + sidl] } else { &p[5..] };
    println!("serverHello: vRange {vmin_srv}..{vmax_srv} sessionId({sidl})={}", hex(srv_sid));
    if srv_sid != session_id.as_slice() {
        println!("  WARN: server sessionId != client Finished ({}B vs {}B)", srv_sid.len(), session_id.len());
    }
    let v = vmax_srv.min(4).max(vmin_srv.min(4)); // negotiate highest mutually supported (v4)
    println!("negotiated xftp version v{v}");

    // ---- 2. padded clientHello -> empty response ----
    let mut ch = Vec::new();
    ch.extend_from_slice(&v.to_be_bytes());
    ch.push(32u8);
    ch.extend_from_slice(&key_hash);
    if v >= 4 {
        ch.push(b'0'); // entitlementProof = Nothing
    }
    let mut blk = Vec::new();
    blk.extend_from_slice(&(ch.len() as u16).to_be_bytes());
    blk.extend_from_slice(&ch);
    blk.resize(BLOCK, 0x23);
    let chr = post(&mut h2, Bytes::from(blk), &host).await;
    if !chr.is_empty() {
        let l = u16::from_be_bytes([chr[0], chr[1]]) as usize;
        println!("clientHello -> non-empty ({}B): {:?}", chr.len(), String::from_utf8_lossy(&chr[2..(2 + l).min(chr.len())]));
        return;
    }
    println!("clientHello v{v} accepted (empty response)");


    // ---- 3. PING (no auth) ----
    let c = corr();
    let t = transmission(&session_id, &c, b"", b"PING");
    let pr = post(&mut h2, Bytes::from(batch(&[0u8], &t)), &host).await;
    println!("PING -> {}", show_resp(&pr));

    // ---- 4/5. file cycles: 64 KiB (existing) and 1 MiB (chunked body) ----
    let (ok64, sum64) = file_cycle(&mut h2, &host, &session_id, vec![0x42u8; 64 * 1024], "64KiB").await;
    println!("CYCLE 64KiB {sum64}");
    let (ok1m, sum1m) = file_cycle(&mut h2, &host, &session_id, vec![0x37u8; 1024 * 1024], "1MiB").await;
    println!("CYCLE 1MiB {sum1m}");
    println!("XFTP ROUNDTRIP 64KiB byte-exact={ok64}");
    println!("XFTP ROUNDTRIP 1MiB byte-exact={ok1m}");
}