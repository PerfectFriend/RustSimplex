//! smp-v71: minimal live SMP client for public simplexmq v7.1 relays (port 5223).
//!   smp-v71 [IP:port] [keyHashB64url-no-pad]
//! Uses openssl (not rustls): hs-tls on v7.1 requires ed448 in signature_algorithms and
//! TLS Finished as sessionId, both unavailable in rustls 0.23. No SNI, ALPN smp/1, TLS1.3.
//! Flow: read serverHello (vRange 15..23, sessionId, CertChainPubKey) -> send clientHello v23
//! (keyHash=CA DER sha256, authPubKey=Just X25519 SPKI, proxyServer 'F', clientService '0')
//! -> init block-encryption chain from DH(server session pub, client eph priv) -> encrypted PING.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use openssl::ssl::{Ssl, SslConnector, SslMethod, SslVerifyMode, SslVersion};
use sha2::{Digest, Sha256, Sha512};

use smp_rs::crypto::*;
use smp_rs::encoding::{pad, unpad, w_large, w_short, w_u16, EncodeError, Reader, BLOCK_SIZE};
use smp_rs::protocol::*;
use smp_rs::transport::{read_block, write_block};

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
            if c == b'=' { break; }
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

fn b64url_nopad(b: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    for chunk in b.chunks(3) {
        let n = chunk.len();
        let v = ((chunk[0] as u32) << 16) | ((*chunk.get(1).unwrap_or(&0) as u32) << 8) | (*chunk.get(2).unwrap_or(&0) as u32);
        s.push(T[(v >> 18) as usize & 63] as char);
        s.push(T[(v >> 12) as usize & 63] as char);
        if n > 1 { s.push(T[(v >> 6) as usize & 63] as char); }
        if n > 2 { s.push(T[v as usize & 63] as char); }
    }
    s
}

fn hmac_sha512(key: &[u8], msg: &[u8]) -> [u8; 64] {
    let mut k = [0u8; 128];
    if key.len() > 128 {
        let d = Sha512::digest(key);
        k[..64].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 128];
    let mut opad = [0x5cu8; 128];
    for i in 0..128 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha512::new();
    inner.update(ipad);
    inner.update(msg);
    let ih = inner.finalize();
    let mut outer = Sha512::new();
    outer.update(opad);
    outer.update(ih);
    let mut out = [0u8; 64];
    out.copy_from_slice(&outer.finalize());
    out
}

fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], n: usize) -> Vec<u8> {
    let prk = hmac_sha512(salt, ikm);
    let mut out = Vec::new();
    let mut t: Vec<u8> = Vec::new();
    let mut i = 1u8;
    while out.len() < n {
        let mut m = t.clone();
        m.extend_from_slice(info);
        m.push(i);
        t = hmac_sha512(&prk, &m).to_vec();
        out.extend_from_slice(&t);
        i += 1;
    }
    out.truncate(n);
    out
}

struct Chain { ck: [u8; 32] }
impl Chain {
    fn step(&mut self) -> ([u8; 32], [u8; 24]) {
        let out = hkdf(&[], &self.ck, b"SimpleXSbChain", 88);
        let mut ck = [0u8; 32];
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 24];
        ck.copy_from_slice(&out[..32]);
        key.copy_from_slice(&out[32..64]);
        nonce.copy_from_slice(&out[64..88]);
        self.ck = ck;
        (key, nonce)
    }
}

fn encode_batch_plain(wires: &[Vec<u8>]) -> Result<Vec<u8>, EncodeError> {
    let mut content = Vec::new();
    content.push(wires.len() as u8);
    for w in wires {
        w_large(&mut content, w)?;
    }
    pad(&content, BLOCK_SIZE - 16) // secretbox tag(16) -> exactly BLOCK_SIZE on the wire
}

fn decode_batch_plain(pt: &[u8]) -> Result<Vec<Vec<u8>>, EncodeError> {
    let content = unpad(pt)?;
    let mut r = Reader::new(&content);
    let count = r.u8()? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(r.large()?);
    }
    Ok(out)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let addr: SocketAddr = args.first().map(|s| s.as_str()).unwrap_or("23.128.248.121:5223").parse().expect("host:port");
    let host = std::env::var("SMP_HOST").unwrap_or_else(|_| "smp11.simplex.im".to_string());
    let key_hash_b64 = args.get(1).cloned().unwrap_or_else(|| "1OwYGt-yqOfe2IyVHhxz3ohqo3aCCMjtB-8wn4X_aoY".to_string());
    let key_hash = b64url_dec(&key_hash_b64).expect("keyHash b64");
    let key_hash32: [u8; 32] = key_hash.try_into().expect("keyHash 32B");

    // TLS1.3, ALPN smp/1, ed448-capable sigalgs (v7.1 hs-tls requirement), NO SNI.
    let mut builder = SslConnector::builder(SslMethod::tls()).expect("connector");
    builder.set_verify(SslVerifyMode::NONE); // we pin manually by CA sha256 below
    builder.set_min_proto_version(Some(SslVersion::TLS1_3)).expect("tls13");
    builder.set_sigalgs_list("ed448:ed25519:ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512").expect("sigalgs");
    let connector = builder.build();
    let tcp = TcpStream::connect(addr).expect("tcp");
    tcp.set_read_timeout(Some(Duration::from_secs(6))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(25))).ok();
    let mut ssl = Ssl::new(connector.context()).expect("ssl");
    ssl.set_alpn_protos(b"\x05smp/1").expect("alpn ssl");
    ssl.set_hostname(&host).expect("sni"); // port 5223 + SNI still serves the SMP chain
    let mut stream = ssl.connect(tcp).expect("tls handshake");
    println!("tls ok: alpn={:?}", stream.ssl().selected_alpn_protocol());

    // pin: keyHash = sha256 of any cert in peer chain (CA = last)
    let chain = stream.ssl().peer_cert_chain().expect("peer chain");
    let mut pinned = false;
    for c in chain.iter() {
        let der = c.to_der().expect("der");
        if Sha256::digest(&der).as_slice() == key_hash32 {
            pinned = true;
        }
        println!("chain cert sha256={}", b64url_nopad(&Sha256::digest(&der)));
    }
    assert!(pinned, "keyHash not in peer chain");
    let mut fin = [0u8; 64];
    let fin_len = stream.ssl().finished(&mut fin);
    let finished = fin[..fin_len].to_vec();
    println!("client Finished: {}B {}", finished.len(), hex(&finished));

    // server speaks first: full 16384B serverHello block
    let sh = read_block(&mut stream).expect("serverHello block");
    println!("serverHello block {}B head {}", sh.len(), hex(&sh[..48]));
    let c = unpad(&sh).expect("unpad hello");
    let mut r = Reader::new(&c);
    let vmin = r.u16().expect("vmin");
    let vmax = r.u16().expect("vmax");
    let sid = r.short().expect("sid");
    let cert_count = r.u8().expect("cert count");
    let mut certs = Vec::new();
    for _ in 0..cert_count {
        certs.push(r.large().expect("cert"));
    }
    let signed = r.large().expect("signed");
    println!("serverHello: vRange {vmin}..{vmax} sid={}B certs={} signed={}B", sid.len(), certs.len(), signed.len());
    println!("sid == client Finished: {}", sid == finished);

    // clientHello v23
    let _eph = x25519_keypair();
    let v: u16 = std::env::var("SMP_V").ok().and_then(|s| s.parse().ok()).unwrap_or(17);
    let mut c = Vec::new();
    w_u16(&mut c, v);
    w_short(&mut c, &key_hash32).unwrap();
    // v>=7 authPubKey = `maybe "" smpEncode authPubKey` — Just is the SPKI shortString with NO '0'/'1' Maybe tag
    // probe-verified: v17 clientHello sends authPubKey = EMPTY (zero bytes, v>=7)
    c.push(b'F'); // proxyServer = False
    c.push(b'0'); // clientService = Nothing (v>=16)
    // hello blocks: pad() itself prepends word16BE(len) — do NOT add another prefix
    let ch = pad(&c, BLOCK_SIZE).unwrap();
    write_block(&mut stream, &ch).expect("write clientHello");
    println!("clientHello sent: v{v} keyHash={} authPubKey=Just proxy=F clientService=0", b64url_nopad(&key_hash32));
    if std::env::var("SMP_NO_PING").as_deref() == Ok("1") {
        let r = read_block(&mut stream);
        println!("after-hello read: {:?}", r.map(|b| b.len()));
        return;
    }

    // v17 public-relay path (probe-verified vs smp11:5223): NO transport block encryption, NO authPubKey.
    let t = Transmission { authenticator: Vec::new(), corr_id: random_bytes(24), entity_id: Vec::new(), command: encode_command(&Command::Ping).unwrap() };
    let wire = encode_transmission(&t).unwrap();
    let blk = encode_block(&[wire]).unwrap();
    write_block(&mut stream, &blk).expect("write PING block");
    let rb = read_block(&mut stream).expect("read PING response");
    let wires = decode_block(&rb).expect("decode response");
    for w in wires {
        let t = decode_transmission(&w).expect("decode transmission");
        let msg = parse_broker(&t.command).expect("parse broker");
        println!("response: {msg:?}");
        if matches!(msg, BrokerMsg::Pong) {
            println!("LIVE SMP INTEROP OK: PING -> PONG against {}", addr);
        }
    }
}
