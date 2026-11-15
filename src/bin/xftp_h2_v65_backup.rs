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

    let _roots = rustls::RootCertStore::empty();
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
        eprintln!("  [dbg] request sent, sending {} bytes", body.len());
        stream.send_data(body.clone(), true).expect("send_data");
        eprintln!("  [dbg] body sent, awaiting response");
        let resp = tokio::time::timeout(std::time::Duration::from_secs(20), resp).await.expect("resp timeout").expect("resp");
        let status = resp.status();
        eprintln!("  [dbg] got response {status}");
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
                Err(_) => {
                    eprintln!("  [dbg] body read timeout after {} bytes", data.len());
                    break;
                }
            }
        }
        let data = Bytes::from(data);
        println!("  POST {} bytes -> HTTP {status}, {} bytes", body.len(), data.len());
        data
    }

    // 1. handshake starts with clientHello on v7+ (sessionIdentifier negotiated after clientHello)
    //    wire block = u16 BE unpadded-length + payload + 0x23 padding to 16384
    //    payload (xftp v7): xftpVersion(u16) + keyHash(shortString 32B)
    //    -> server answers paddedRouterHello = versionRange(min,max) + sessionId(short) + authPubKey + ...
    let mut ch = Vec::new();
    let vmin = 7u16; let vmax = 7u16;
    ch.extend_from_slice(&vmin.to_be_bytes());
    ch.extend_from_slice(&vmax.to_be_bytes());
    // xftp v7 clientHello: version + keyHash + entitlementProof('0' = nothing) + ignored
    ch.push(32u8);
    ch.extend_from_slice(&[0u8; 32]);
    ch.push(b'0'); // entitlementProof = Nothing
    let ca = smp_rs::crypto::x25519_keypair();
    let ca_spki = smp_rs::crypto::spki_x25519(ca.public.as_bytes());
    ch.push(ca_spki.len() as u8);
    ch.extend_from_slice(&ca_spki);
    ch.resize(BLOCK, 0x23);
    let hello = post(&mut h2, Bytes::from(ch), &host).await;
    println!("clientHello v{vmin}..v{vmax} -> routerHello {} bytes", hello.len());
    let hp = &hello[2..hello.len().min(96 + 2)];
    let vmin_srv = u16::from_be_bytes([hp[0], hp[1]]);
    let vmax_srv = u16::from_be_bytes([hp[2], hp[3]]);
    let sidl = hp[4] as usize;
    if hp.len() < 5 + sidl {
        println!("routerHello truncated sessionId — stop");
        return;
    }
    let sid = hp[5..5 + sidl].to_vec();
    let sid_use: Vec<u8> = Vec::new(); // TLS 1.3: sessionId = tls-unique = ""
    println!("server xftp version range {vmin_srv}..{vmax_srv} sessionId(73)={}; transmission uses empty sessionId (tls-unique)", hex(&sid));

    // keyHash = SHA-256 of CA certificate DER (arg 3 = path to ca.crt PEM, optional)
    let _key_hash: [u8; 32] = match std::env::args().nth(3) {
        Some(p) => {
            use sha2::Digest;
            let b = std::fs::read(&p).expect("ca cert");
            let mut h = sha2::Sha256::new();
            h.update(&b);
            h.finalize().into()
        }
        None => [0u8; 32],
    };

    // 2. handshake finalized with empty response (clientHello first) — PING next.

    // 3. PING: block = u16 len + tEncodeBatch1 = 01 + Large(u16 + auth(0x00) + transmission)
    //    transmission = short(sessionId 32B) + short(corrId 24B) + short(entityId "") + "PING"
    let corr: Vec<u8> = (0..24).map(|_| rand::random::<u8>()).collect();
    let mut t = Vec::new();
    t.push(sid_use.len() as u8);
    t.extend_from_slice(&sid_use);
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
    use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
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
    t.push(sid_use.len() as u8);
    t.extend_from_slice(&sid_use);
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
    let pos = fp.windows(4).position(|w| w == b"SIDS").expect("SIDS");
    if let Some(pos) = fp.windows(3).position(|w| w == b"ERR") {
        println!("  ERR: {:?}", String::from_utf8_lossy(&fp[pos..(pos + 40).min(fp.len())]));
        return;
    }
    // parse SIDS: "SIDS " + senderId short + count + recipientId short ...
    let mut p = pos + 5;
    let sidl2 = fp[p] as usize; p += 1;
    let sender_id = fp[p..p + sidl2].to_vec(); p += sidl2;
    let nrcv = fp[p] as usize; p += 1;
    let ridl = fp[p] as usize; p += 1;
    let rcv_id = fp[p..p + ridl].to_vec();
    println!("  senderId({})={} nRcv={nrcv} rcvId({})={}", sidl2, hex(&sender_id), ridl, hex(&rcv_id));

    // helper: send signed command, optional extra body bytes (file chunk)
    async fn send_cmd(
        h2: &mut h2::client::SendRequest<Bytes>,
        host: &str,
        sid: &[u8],
        corr: &[u8],
        entity: &[u8],
        cmd: &[u8],
        sig: &[u8],
        extra: &[u8],
    ) -> Bytes {
        let mut t = Vec::new();
        t.push(sid.len() as u8);
        t.extend_from_slice(sid);
        t.push(corr.len() as u8);
        t.extend_from_slice(corr);
        t.push(entity.len() as u8);
        t.extend_from_slice(entity);
        t.extend_from_slice(cmd);
        let mut inner = Vec::new();
        inner.push(sig.len() as u8);
        inner.extend_from_slice(sig);
        inner.extend_from_slice(&t);
        let mut batch = vec![1u8];
        batch.extend_from_slice(&(inner.len() as u16).to_be_bytes());
        batch.extend_from_slice(&inner);
        let mut blk = Vec::new();
        blk.extend_from_slice(&(batch.len() as u16).to_be_bytes());
        blk.extend_from_slice(&batch);
        blk.resize(BLOCK, 0x23);
        blk.extend_from_slice(extra); // file chunk streamed after the command block
        post(h2, Bytes::from(blk), host).await
    }

    // 5. FPUT: entity = senderId, cmd "FPUT", body = block + packet bytes (the exact bytes hashed in FNEW)
    let corr: Vec<u8> = (0..24).map(|_| rand::random::<u8>()).collect();
    let mut t = Vec::new();
    t.push(sid.len() as u8); t.extend_from_slice(&sid);
    t.push(corr.len() as u8); t.extend_from_slice(&corr);
    t.push(sender_id.len() as u8); t.extend_from_slice(&sender_id);
    t.extend_from_slice(b"FPUT");
    let sig = snd.sign(&t);
    let pr = send_cmd(&mut h2, &host, &sid, &corr, &sender_id, b"FPUT", &sig.to_bytes(), &file).await;
    let pl = u16::from_be_bytes([pr[0], pr[1]]) as usize;
    let pp = &pr[2..(2 + pl).min(pr.len())];
    println!("FPUT -> {} bytes (block) + {} chunk; resp tail: {:?}", BLOCK, file.len(), String::from_utf8_lossy(&pp[pp.len().saturating_sub(24)..]));

    // 6. FGET as recipient: entity = rcvId, cmd "FGET " + rDhKey(X25519 SPKI), signed with rcv Ed25519 key
    let (r_dh_secret, r_dh_pub) = {
        let sk = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let pk = x25519_dalek::PublicKey::from(&sk);
        (sk, pk)
    };
    let rdh_spki = smp_rs::crypto::spki_x25519(r_dh_pub.as_bytes());
    let mut gcmd = b"FGET ".to_vec();
    gcmd.push(rdh_spki.len() as u8);
    gcmd.extend_from_slice(&rdh_spki);
    let corr: Vec<u8> = (0..24).map(|_| rand::random::<u8>()).collect();
    let mut t = Vec::new();
    t.push(sid.len() as u8); t.extend_from_slice(&sid);
    t.push(corr.len() as u8); t.extend_from_slice(&corr);
    t.push(rcv_id.len() as u8); t.extend_from_slice(&rcv_id);
    t.extend_from_slice(&gcmd);
    let sig = rcv.sign(&t);
    // send_cmd rebuilds corr — so do it manually here to keep sig consistent
    let mut inner = Vec::new();
    inner.push(64u8); inner.extend_from_slice(&sig.to_bytes()); inner.extend_from_slice(&t);
    let mut batch = vec![1u8];
    batch.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    batch.extend_from_slice(&inner);
    let mut blk = Vec::new();
    blk.extend_from_slice(&(batch.len() as u16).to_be_bytes());
    blk.extend_from_slice(&batch);
    blk.resize(BLOCK, 0x23);
    let gr = post(&mut h2, Bytes::from(blk), &host).await;
    println!("FGET -> {} bytes total", gr.len());
    let gl = u16::from_be_bytes([gr[0], gr[1]]) as usize;
    let gp = &gr[2..(2 + gl).min(gr.len())];
    if let Some(pos) = gp.windows(4).position(|w| w == b"FILE") {
        println!("  FILE raw: {}", hex(&gp[pos..(pos + 90).min(gp.len())]));
        // "FILE " + sDhKey short(SPKI) + nonce 24B raw
        let mut q = pos + 5;
        let kl = gp[q] as usize; q += 1;
        let sdh_spki = &gp[q..q + kl]; q += kl;
        let nonce: [u8; 24] = gp[q..q + 24].try_into().unwrap();
        let (_, sdh_raw) = smp_rs::crypto::parse_spki(sdh_spki).expect("sDhKey");
        let shared = smp_rs::crypto::x25519_dh(&r_dh_secret, &smp_rs::crypto::x25519_public(sdh_raw));
        let enc_packet = &gr[BLOCK..]; // packet body streamed after the command block
        println!("  FILE sDhKey={} nonce={} enc_packet={} bytes", hex(&sdh_raw), hex(&nonce), enc_packet.len());
        // dump for python cross-check (only when XFTP_DUMP is set; path from env, default = temp dir)
        if std::env::var("XFTP_DUMP").is_ok() {
            let dump = format!(
                "{{\"r_priv\":\"{}\",\"r_pub\":\"{}\",\"sdh\":\"{}\",\"nonce\":\"{}\",\"enc\":\"{}\"}}",
                hex(r_dh_secret.as_bytes()), hex(r_dh_pub.as_bytes()), hex(&sdh_raw), hex(&nonce), hex(enc_packet)
            );
            let p = std::env::var("XFTP_DUMP").unwrap_or_default();
            let p = if p.is_empty() || p == "1" { std::env::temp_dir().join("fget_dump.json") } else { std::path::PathBuf::from(p) };
            let _ = std::fs::write(p, dump);
        }
        // server: LC.cbInit(dhSecret) where DhSecret is the crypto_box beforenm key (HSalsa20(shared, 0^16)),
        // streamed XSalsa20-Poly1305 with TAIL tag -> reorder ct||mac to mac||ct for NaCl-order decrypt
        let reordered = [&enc_packet[enc_packet.len() - 16..], &enc_packet[..enc_packet.len() - 16]].concat();
        if let Some(pt) = smp_rs::crypto::secretbox_decrypt(&shared, &nonce, &reordered) {
            println!("  [tail-tag raw box] decrypted {} bytes, matches uploaded: {}, sha256={}", pt.len(), pt == file, hex(&smp_rs::crypto::sha256(&pt)));
        } else {
            println!("  DECRYPT FAILED (tail-tag raw)");
        }
    } else if let Some(pos) = gp.windows(3).position(|w| w == b"ERR") {
        println!("  ERR: {:?}", String::from_utf8_lossy(&gp[pos..(pos + 40).min(gp.len())]));
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
