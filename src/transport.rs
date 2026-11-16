//! Transport: SMP handshake blocks + fixed 16384-byte block I/O over a byte stream,
//! plus optional TLS 1.3 (rustls) matching simplexmq's network surface:
//!   - ALPN "smp/1", TLS 1.3 only, self-signed 2-cert Ed25519 chain (offline+online)
//!   - client pins the router by keyHash = SHA-256(offline SPKI)
//!
//! After (optional) TLS the router sends padded routerHello, the client answers
//! padded clientHello. For plain TCP sessionId = "" ; over TLS we also use "" on
//! both ends (channel binding to tls-unique is a known follow-up for real-client interop).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error as TlsError, ServerConfig,
    ServerConnection, SignatureScheme, StreamOwned,
};

use crate::encoding::*;
use crate::identity::{cert_fingerprint, RouterIdentity};

pub const ALPN_SMP: &[u8] = b"smp/1";

// ---------- handshake blocks ----------

pub fn server_hello_block(min_v: u16, max_v: u16, session_id: &[u8]) -> Result<Vec<u8>, EncodeError> {
    server_hello_block_key(min_v, max_v, session_id, None)
}

/// Server hello with optional X25519 session pubkey (authPubKey = Just) used for SMP proxy sessions.
pub fn server_hello_block_key(min_v: u16, max_v: u16, session_id: &[u8], auth_pub: Option<&[u8; 32]>) -> Result<Vec<u8>, EncodeError> {
    // SMPServerHandshake: smpEncode (vRange, sessionId) <> authPubKey(maybe, v>=7).
    let mut c = Vec::new();
    w_u16(&mut c, min_v);
    w_u16(&mut c, max_v);
    w_short(&mut c, session_id)?;
    match auth_pub {
        Some(pk) => {
            c.push(b'1'); // Maybe = Just
            w_short(&mut c, &crate::crypto::spki_x25519(pk))?;
        }
        None => c.push(b'0'), // authPubKey = Nothing
    }
    pad(&c, BLOCK_SIZE)
}

pub fn parse_server_hello(block: &[u8]) -> Result<(u16, u16, Vec<u8>), EncodeError> {
    let (min, max, sid, _auth) = parse_server_hello_key(block)?;
    Ok((min, max, sid))
}

/// (min, max, sessionId, authPubKey SPKI DER if Just).
pub type ServerHelloKey = (u16, u16, Vec<u8>, Option<Vec<u8>>);
pub fn parse_server_hello_key(block: &[u8]) -> Result<ServerHelloKey, EncodeError> {
    let c = unpad(block)?;
    let mut r = Reader::new(&c);
    let min = r.u16()?;
    let max = r.u16()?;
    let sid = r.short()?;
    let auth = match r.u8()? {
        b'0' => None,
        b'1' => Some(r.short()?),
        t => return Err(EncodeError(format!("bad Maybe tag {t} in server hello"))),
    };
    Ok((min, max, sid, auth))
}

pub fn client_hello_block(version: u16, key_hash: &[u8], proxy: bool) -> Result<Vec<u8>, EncodeError> {
    client_hello_block_key(version, key_hash, proxy, None)
}

/// Client hello with optional X25519 pubkey (authPubKey = Just) — used by proxy sessions.
pub fn client_hello_block_key(version: u16, key_hash: &[u8], proxy: bool, auth_pub: Option<Vec<u8>>) -> Result<Vec<u8>, EncodeError> {
    let mut c = Vec::new();
    w_u16(&mut c, version);
    w_short(&mut c, key_hash)?;
    match &auth_pub {
        Some(k) => {
            c.push(b'1');
            w_short(&mut c, k)?;
        }
        None => {
            c.push(b'0'); // authPubKey = Nothing (Maybe tag, all versions)
        }
    }
    // v0.26: SMP clients MUST send authPubKey (X25519) — agreeSecret=True in defaultSMPClientConfig
    // proxyServer :: Bool — 'T'/'F' chars at ALL versions (v14+ gate was wrong)
    c.push(if proxy { b'T' } else { b'F' });
    if version >= 16 {
        c.push(b'0'); // clientService = Nothing (ifHasService v>=16)
    }
    pad(&c, BLOCK_SIZE)
}

pub fn parse_client_hello(block: &[u8]) -> Result<(u16, Vec<u8>, bool), EncodeError> {
    let (v, kh, proxy, _auth) = parse_client_hello_key(block)?;
    Ok((v, kh, proxy))
}

/// (version, keyHash, proxyServer, authPubKey SPKI DER if Just).
pub type ClientHelloKey = (u16, Vec<u8>, bool, Option<Vec<u8>>);
pub fn parse_client_hello_key(block: &[u8]) -> Result<ClientHelloKey, EncodeError> {
    let c = unpad(block)?;
    let mut r = Reader::new(&c);
    let v = r.u16()?;
    let kh = r.short()?;
    // For v>=7 a Nothing authPubKey is encoded as ZERO bytes (maybe "" smpEncode),
    // so only consume a Maybe tag when the next byte is actually '0'/'1'.
    let auth = match r.peek_u8()? {
        b'0' => { r.u8()?; None }
        b'1' => { r.u8()?; Some(r.short()?) }
        _ => None,
    };
    let proxy = if v >= 14 { r.bool()? } else { false };
    Ok((v, kh, proxy, auth))
}

// ---------- block I/O ----------

/// Tolerant write: retries on WouldBlock/TimedOut (for non-blocking sockets / TLS).
pub fn write_all_tol(w: &mut impl Write, buf: &[u8]) -> std::io::Result<()> {
    let mut off = 0;
    while off < buf.len() {
        match w.write(&buf[off..]) {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "write 0")),
            Ok(n) => off += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(e) => return Err(e),
        }
    }
    w.flush()
}

/// Tolerant read_exact: retries on WouldBlock/TimedOut until the buffer is full.
pub fn read_exact_tol(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<()> {
    let mut off = 0;
    while off < buf.len() {
        match r.read(&mut buf[off..]) {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof")),
            Ok(n) => off += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

pub fn write_block(w: &mut impl Write, block: &[u8]) -> std::io::Result<()> {
    write_all_tol(w, block)
}

/// Blocking read of one full block (client side).
pub fn read_block(r: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; BLOCK_SIZE];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Tolerant read of one full block (handshake on a non-blocking socket).
pub fn read_block_tol(r: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; BLOCK_SIZE];
    read_exact_tol(r, &mut buf)?;
    Ok(buf)
}

pub fn read_block_stream(s: &TcpStream) -> std::io::Result<Vec<u8>> {
    let mut s = s;
    read_block(&mut s)
}

// ---------- generic stream ----------

pub trait RW: Read + Write + Send + 'static {}
impl<T: Read + Write + Send + 'static> RW for T {}
pub type BoxStream = Box<dyn RW>;

// ---------- TLS ----------

pub fn tls_server_config(id: &RouterIdentity) -> Arc<ServerConfig> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut cfg = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls13")
        .with_no_client_auth()
        .with_single_cert(id.cert_chain(), PrivateKeyDer::Pkcs8(id.private_key()))
        .expect("cert");
    cfg.alpn_protocols = vec![ALPN_SMP.to_vec()];
    Arc::new(cfg)
}

/// Client-side certificate verifier: pins the router by keyHash (SHA-256 of offline SPKI)
/// found anywhere in the presented chain; handshake CertificateVerify is checked against
/// the leaf key via the provider's signature algorithms.
#[derive(Debug)]
pub struct PinVerifier {
    pub key_hash: [u8; 32],
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        use webpki::{anchor_from_trusted_cert, EndEntityCert, KeyUsage, ALL_VERIFICATION_ALGS};
        // SEC-01: pin strictly to the last certificate in the chain (offline CA), never "any cert in chain".
        let pinned = intermediates.last().unwrap_or(end_entity);
        if cert_fingerprint(pinned.as_ref()) != self.key_hash {
            return Err(TlsError::InvalidCertificate(rustls::CertificateError::UnknownIssuer));
        }
        // Verify the leaf is actually signed by the pinned CA (blocks [evil_leaf, pinned_CA] MITM).
        let anchor = anchor_from_trusted_cert(pinned)
            .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::UnknownIssuer))?;
        let ee = EndEntityCert::try_from(end_entity)
            .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        ee.verify_for_usage(
            ALL_VERIFICATION_ALGS,
            std::slice::from_ref(&anchor),
            &[],
            now,
            KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::UnknownIssuer))?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("tls1.2 disabled".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // v0.26: no-SNI public relay may serve an ECDSA/RSA cert — widen schemes
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

pub fn tls_client_config(key_hash: [u8; 32]) -> Arc<ClientConfig> {
    // v0.26: match simplexmq defaultSupportedParams — CHACHA20-POLY1305 for TLS1.3,
    // groups X448+X25519 (no-SNI public relay otherwise answers HandshakeFailure)
    // v0.26: default aws-lc-rs suites work with the public relay (verified via openssl/python:
    // no-SNI + ALPN smp/1 negotiates TLS_AES_256_GCM_SHA384) — keep provider defaults.
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls13")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier { key_hash }))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![ALPN_SMP.to_vec()];
    Arc::new(cfg)
}

/// Accept a TLS connection (server side). Underlying socket set non-blocking for the pump.
pub fn accept_tls(listener: &TcpListener, cfg: Arc<ServerConfig>) -> std::io::Result<BoxStream> {
    let (tcp, _peer) = listener.accept()?;
    tcp.set_nonblocking(true)?;
    let conn = ServerConnection::new(cfg).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(Box::new(StreamOwned::new(conn, tcp)))
}

/// Accept a plain TCP connection (server side). Non-blocking for the pump.
pub fn accept_plain(listener: &TcpListener) -> std::io::Result<BoxStream> {
    let (tcp, _peer) = listener.accept()?;
    tcp.set_nonblocking(true)?;
    Ok(Box::new(tcp))
}

/// Connect over TLS 1.3 to a router, pinning `key_hash`. Client socket stays blocking.
pub fn connect_tls(addr: SocketAddr, host: &str, key_hash: [u8; 32]) -> std::io::Result<BoxStream> {
    connect_tls_sni(addr, host, key_hash, true)
}

/// v0.26: `with_sni=false` connects WITHOUT SNI — public simplex relays serve the HTTPS/web
/// cert on SNI and route those connections to the web handler; no-SNI gets the SMP cert.
pub fn connect_tls_sni(addr: SocketAddr, host: &str, key_hash: [u8; 32], with_sni: bool) -> std::io::Result<BoxStream> {
    Ok(connect_tls_sni_bound(addr, host, key_hash, with_sni)?.0)
}

/// TLS connect that also completes the handshake and returns a TLS channel binding
/// (exporter label) for SEC-04 `verify_channel_binding`.
pub fn connect_tls_sni_bound(addr: SocketAddr, host: &str, key_hash: [u8; 32], with_sni: bool) -> std::io::Result<(BoxStream, [u8; 32])> {
    let tcp = TcpStream::connect(addr)?;
    // P1: bounded I/O — a stalled peer must not hang the client forever
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    tcp.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
    let name = if with_sni {
        ServerName::try_from(host.to_string())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?
    } else {
        ServerName::try_from("localhost".to_string())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?
    };
    let mut cfg = (*tls_client_config(key_hash)).clone();
    if !with_sni {
        cfg.enable_sni = false;
    }
    let conn = ClientConnection::new(Arc::new(cfg), name)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut stream = StreamOwned::new(conn, tcp);
    stream.conn.complete_io(&mut stream.sock).map_err(std::io::Error::other)?;
    let mut binding = [0u8; 32];
    stream
        .conn
        .export_keying_material(&mut binding, b"SimpleX-channel-binding", None)
        .map_err(std::io::Error::other)?;
    Ok((Box::new(stream), binding))
}

/// Connect over plain TCP. Client socket stays blocking.
pub fn connect_plain(addr: SocketAddr) -> std::io::Result<BoxStream> {
    let tcp = TcpStream::connect(addr)?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    tcp.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
    Ok(Box::new(tcp))
}

/// Optional SOCKS5 proxy (Tor/Orbot). DNS is resolved REMOTELY (ATYP=0x03 domain).
#[derive(Clone, Debug)]
pub struct Socks5Config {
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub pass: Option<String>,
}

/// Connect through SOCKS5 to `dest_host:dest_port` with remote DNS (domain sent to proxy).
pub fn connect_socks5(proxy: &Socks5Config, dest_host: &str, dest_port: u16) -> std::io::Result<TcpStream> {
    use std::io::{Read, Write};
    let mut s = TcpStream::connect((proxy.host.as_str(), proxy.port))?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    s.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
    let methods: &[u8] = if proxy.user.is_some() { &[0x05, 0x02, 0x00, 0x02] } else { &[0x05, 0x01, 0x00] };
    s.write_all(methods)?;
    let mut hdr = [0u8; 2];
    s.read_exact(&mut hdr)?;
    if hdr[0] != 0x05 { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "not socks5")); }
    match hdr[1] {
        0x00 => {}
        0x02 => {
            let u = proxy.user.clone().unwrap_or_default();
            let p = proxy.pass.clone().unwrap_or_default();
            let mut a = vec![0x01u8, u.len() as u8];
            a.extend_from_slice(u.as_bytes());
            a.push(p.len() as u8);
            a.extend_from_slice(p.as_bytes());
            s.write_all(&a)?;
            let mut r = [0u8; 2];
            s.read_exact(&mut r)?;
            if r[1] != 0x00 { return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "socks5 auth failed")); }
        }
        m => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("socks5 method {m} unsupported"))),
    }
    let host_b = dest_host.as_bytes();
    if host_b.len() > 255 { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "host too long")); }
    let mut req = vec![0x05u8, 0x01, 0x00, 0x03, host_b.len() as u8];
    req.extend_from_slice(host_b);
    req.extend_from_slice(&dest_port.to_be_bytes());
    s.write_all(&req)?;
    let mut rh = [0u8; 4];
    s.read_exact(&mut rh)?;
    if rh[1] != 0x00 { return Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, format!("socks5 connect err {}", rh[1]))); }
    let skip = match rh[3] { 0x01 => 4, 0x04 => 16, 0x03 => { let mut l=[0u8;1]; s.read_exact(&mut l)?; l[0] as usize }, _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad atyp")) };
    let mut buf = vec![0u8; skip + 2];
    s.read_exact(&mut buf)?;
    Ok(s)
}

/// Plain TCP through SOCKS5, remote DNS by hostname (no local resolve).
pub fn connect_plain_proxy(host: &str, port: u16, proxy: &Socks5Config) -> std::io::Result<BoxStream> {
    let tcp = connect_socks5(proxy, host, port)?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    tcp.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
    Ok(Box::new(tcp))
}

/// TLS 1.3 through SOCKS5 with remote DNS; SNI still uses `host` (PinVerifier by key_hash).
pub fn connect_tls_sni_proxy(host: &str, port: u16, key_hash: [u8; 32], with_sni: bool, proxy: &Socks5Config) -> std::io::Result<(BoxStream, [u8; 32])> {
    let tcp = connect_socks5(proxy, host, port)?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    tcp.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
    let name = if with_sni {
        ServerName::try_from(host.to_string()).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?
    } else {
        ServerName::try_from("localhost".to_string()).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?
    };
    let mut cfg = (*tls_client_config(key_hash)).clone();
    if !with_sni { cfg.enable_sni = false; }
    let conn = ClientConnection::new(Arc::new(cfg), name).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut stream = StreamOwned::new(conn, tcp);
    stream.conn.complete_io(&mut stream.sock).map_err(std::io::Error::other)?;
    let mut binding = [0u8; 32];
    stream.conn.export_keying_material(&mut binding, b"SimpleX-channel-binding", None).map_err(std::io::Error::other)?;
    Ok((Box::new(stream), binding))
}
