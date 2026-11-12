//! xftp-h2: probe client for the real XFTP protocol (HTTP/2 + TLS, ALPN "xftp/1") — v6.5.0 interop.
//!   xftp-h2 <host> <port>
//! Handshake: POST empty -> paddedRouterHello block; POST paddedClientHello -> empty response.
//! Then PING -> expect PONG. Dumps hex of hello/response blocks for wire analysis.
//! NOTE: accepts any server certificate (probe tool, not for production).

use std::sync::Arc;

use bytes::Bytes;
use futures::stream::StreamExt;
use tokio::net::TcpStream;
use tokio_rustls::rustls::{self, pki_types::ServerName};

const BLOCK: usize = 16384;

#[tokio::main]
async fn main() {
    let host = std::env::args().nth(1).unwrap_or_else(|| "xftp1.simplex.im".into());
    let port: u16 = std::env::args().nth(2).unwrap_or_else(|| "443".into()).parse().unwrap();
    println!("connect {host}:{port} ALPN xftp/1");

    let mut roots = rustls::RootCertStore::empty();
    // permissive: probe only
    let verifier = Arc::new(NoVerify);
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls13")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"xftp/1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));

    let tcp = TcpStream::connect((host.as_str(), port)).await.expect("tcp");
    let server_name = ServerName::try_from(host.clone()).expect("server name").to_owned();
    let tls = connector.connect(server_name, tcp).await.expect("tls");
    println!("TLS OK, ALPN: {:?}", tls.get_ref().1.alpn_protocol());

    let (mut h2, conn) = h2::client::handshake(tls).await.expect("h2 handshake");
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("h2 conn error: {e}");
        }
    });

    async fn post(h2: &mut h2::client::SendRequest<Bytes>, body: Bytes, authority: &str) -> Bytes {
        let req = http::Request::builder()
            .method("POST")
            .uri(format!("https://{authority}/"))
            .body(())
            .unwrap();
        let (resp, mut stream) = h2.send_request(req, false).expect("send");
        stream.send_data(body.clone(), true).expect("send_data");
        let resp = resp.await.expect("resp");
        let status = resp.status();
        let mut rbody = resp.into_body();
        let mut data = Vec::new();
        while let Some(chunk) = rbody.data().await {
            data.extend_from_slice(&chunk.expect("chunk"));
        }
        let data = Bytes::from(data);
        println!("  POST {} bytes -> HTTP {status}, {} bytes", body.len(), data.len());
        data
    }

    // 1. empty POST -> paddedRouterHello
    // wire block = u16 BE unpadded-length + payload + 0x23 padding to 16384
    // payload (stable v6.5): versionRange(min u16, max u16) + sessionId(shortString) + authPubKey + ...
    let hello = post(&mut h2, Bytes::new(), &host).await;
    println!("routerHello ({} bytes): {}...", hello.len(), hex(&hello[..hello.len().min(96)]));
    let hlen = u16::from_be_bytes([hello[0], hello[1]]) as usize;
    let hp = &hello[2..2 + hlen];
    let vmin = u16::from_be_bytes([hp[0], hp[1]]);
    let vmax = u16::from_be_bytes([hp[2], hp[3]]);
    let sidl = hp[4] as usize;
    let sid = hp[5..5 + sidl].to_vec();
    println!("server xftp version range {vmin}..{vmax} sessionId({sidl})={}", hex(&sid));
    let v = vmax.min(3); // stable supports up to 3

    // keyHash = SHA-256 of CA certificate DER (arg 3 = path to ca.crt PEM, optional)
    let key_hash: [u8; 32] = match std::env::args().nth(3) {
        Some(p) => {
            use sha2::Digest;
            let pem = std::fs::read_to_string(&p).expect("ca cert");
            let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
            let der = base64_decode(&b64);
            let mut h = sha2::Sha256::new();
            h.update(&der);
            h.finalize().into()
        }
        None => [0u8; 32], // live probe: echo not possible, use zeros only if server accepts (it won't) — pass ca path
    };

    // 2. paddedClientHello = u16 len + xftpVersion(2B) + keyHash(shortString 32B), padded with 0x23
    let mut payload = Vec::new();
    payload.extend_from_slice(&v.to_be_bytes());
    payload.push(32u8);
    payload.extend_from_slice(&key_hash);
    let mut ch = Vec::new();
    ch.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    ch.extend_from_slice(&payload);
    ch.resize(BLOCK, 0x23);
    let r = post(&mut h2, Bytes::from(ch), &host).await;
    println!("clientHello v{v} -> response {} bytes (expect 0)", r.len());
    if !r.is_empty() {
        let rl = u16::from_be_bytes([r[0], r[1]]) as usize;
        println!("  handshake NOT finalized: {}", String::from_utf8_lossy(&r[2..2 + rl.min(64)]));
        return;
    }

    // 3. PING: block = u16 len + tEncodeBatch1 = 01 + Large(u16 + auth(0x00) + transmission)
    //    transmission = short(sessionId 32B) + short(corrId 24B) + short(entityId "") + "PING"
    let corr: Vec<u8> = (0..24).map(|_| rand::random::<u8>()).collect();
    let mut t = Vec::new();
    t.push(sid.len() as u8);
    t.extend_from_slice(&sid);
    t.push(corr.len() as u8);
    t.extend_from_slice(&corr);
    t.push(0u8); // empty entity
    t.extend_from_slice(b"PING");
    let mut inner = vec![0u8]; // no auth
    inner.extend_from_slice(&t);
    let mut batch = vec![1u8]; // transmission count = 1
    batch.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    batch.extend_from_slice(&inner);
    let mut blk = Vec::new();
    blk.extend_from_slice(&(batch.len() as u16).to_be_bytes());
    blk.extend_from_slice(&batch);
    blk.resize(BLOCK, 0x23);
    let pr = post(&mut h2, Bytes::from(blk), &host).await;
    let pl = u16::from_be_bytes([pr[0], pr[1]]) as usize;
    println!("PING -> {} bytes payload: {:?}", pr.len(), String::from_utf8_lossy(&pr[2..(2 + pl).min(pr.len())]));

    // 4. FNEW: create a file packet. Signed with sender Ed25519 key.
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
    use sha2::Digest;
    let snd = SigningKey::generate(&mut rand::rngs::OsRng);
    let rcv = SigningKey::generate(&mut rand::rngs::OsRng);
    let spki = |vk: &VerifyingKey| -> Vec<u8> {
        // SPKI DER for Ed25519: 302a300506032b6570032100 || 32B key
        let mut v = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
        v.extend_from_slice(&vk.to_bytes());
        v
    };
    let file = vec![0x42u8; 64 * 1024]; // one 64KB packet
    let digest: [u8; 32] = sha2::Sha256::digest(&file).into();
    // command payload: "FNEW " + FileInfo(sndKey SPKI short, size u32, digest short) + rKeys(count+SPKI) + auth('0')
    let mut cmd = b"FNEW ".to_vec();
    let snd_spki = spki(&snd.verifying_key());
    cmd.push(snd_spki.len() as u8);
    cmd.extend_from_slice(&snd_spki);
    cmd.extend_from_slice(&(file.len() as u32).to_be_bytes());
    cmd.push(32u8);
    cmd.extend_from_slice(&digest);
    let rcv_spki = spki(&rcv.verifying_key());
    cmd.push(1u8); // NonEmpty count
    cmd.push(rcv_spki.len() as u8);
    cmd.extend_from_slice(&rcv_spki);
    cmd.push(b'0'); // Maybe BasicAuth = Nothing

    let corr: Vec<u8> = (0..24).map(|_| rand::random::<u8>()).collect();
    let mut t = Vec::new();
    t.push(sid.len() as u8);
    t.extend_from_slice(&sid);
    t.push(corr.len() as u8);
    t.extend_from_slice(&corr);
    t.push(0u8); // empty entity (FNEW must have empty entity)
    t.extend_from_slice(&cmd);
    // sign over t (sessionId|corrId|entityId|command) — tForAuth
    let sig: Signature = snd.sign(&t);
    let mut inner = Vec::new();
    inner.push(64u8); // auth = shortString(sig 64B)
    inner.extend_from_slice(&sig.to_bytes());
    inner.extend_from_slice(&t);
    let mut batch = vec![1u8];
    batch.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    batch.extend_from_slice(&inner);
    let mut blk = Vec::new();
    blk.extend_from_slice(&(batch.len() as u16).to_be_bytes());
    blk.extend_from_slice(&batch);
    blk.resize(BLOCK, 0x23);
    let fr = post(&mut h2, Bytes::from(blk), &host).await;
    let fl = u16::from_be_bytes([fr[0], fr[1]]) as usize;
    let fp = &fr[2..(2 + fl).min(fr.len())];
    println!("FNEW -> {} bytes", fr.len());
    println!("  payload hex: {}", hex(&fp[..fp.len().min(80)]));
    if let Some(pos) = fp.windows(4).position(|w| w == b"SIDS") {
        println!("  SIDS at {pos}: {:?}", String::from_utf8_lossy(&fp[pos..(pos + 80).min(fp.len())]));
    } else if let Some(pos) = fp.windows(3).position(|w| w == b"ERR") {
        println!("  ERR: {:?}", String::from_utf8_lossy(&fp[pos..(pos + 40).min(fp.len())]));
    }
}

fn base64_decode(s: &str) -> Vec<u8> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut nbits = 0;
    for &c in s.as_bytes() {
        if c == b'=' { break; }
        let v = T.iter().position(|&x| x == c).unwrap_or(0) as u32;
        buf = (buf << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((buf >> nbits) as u8);
        }
    }
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[derive(Debug)]
struct NoVerify;
impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms.supported_schemes()
    }
}
