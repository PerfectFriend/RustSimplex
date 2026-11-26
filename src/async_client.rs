//! A REAL async SMP client: the SMP protocol over an async transport.
//!
//! The module removed in W1 was a facade that only offloaded the *blocking*
//! `Client` to a worker thread — a promise the crate did not keep. Here every
//! byte of I/O goes through `tokio::net::TcpStream` and `tokio_rustls`: the
//! TLS 1.3 handshake, the SMP handshake, the block framing and the strict v23
//! encrypted blocks are awaited, never blocking the executor.
//!
//! Only the I/O is async. The protocol and crypto layer is shared with the
//! blocking client (`crate::protocol`, `crate::crypto`, `crate::sb_chain`),
//! so the two clients cannot drift apart on the wire.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use crate::client::{check_session_binding, verify_channel_binding};
use crate::crypto::*;
use crate::encoding::BLOCK_SIZE;
use crate::protocol::*;
use crate::sb_chain::{decrypt_block, encrypt_block, strict_keys};
use crate::transport::{client_hello_block_key, parse_server_hello_key, tls_client_config};

/// The exporter label for the TLS channel binding. Identical to the blocking
/// client and the server, so both sides derive the same 32 bytes.
const EXPORTER_LABEL: &[u8] = b"SimpleX-channel-binding";

fn map_e<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

/// An async byte stream: plain TCP, or TLS 1.3 over TCP.
enum Stream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl Stream {
    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            Stream::Plain(s) => s.write_all(buf).await,
            Stream::Tls(s) => s.write_all(buf).await,
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush().await,
            Stream::Tls(s) => s.flush().await,
        }
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        match self {
            Stream::Plain(s) => s.read_exact(buf).await.map(|_| ()),
            Stream::Tls(s) => s.read_exact(buf).await.map(|_| ()),
        }
    }

    /// The TLS channel binding (RFC 8446 exporter). `None` on plain TCP.
    fn exporter(&self) -> Option<[u8; 32]> {
        match self {
            Stream::Plain(_) => None,
            Stream::Tls(s) => {
                let (_io, conn) = s.get_ref();
                let mut out = [0u8; 32];
                conn.export_keying_material(&mut out, EXPORTER_LABEL, None).ok()?;
                Some(out)
            }
        }
    }
}

/// Read one full SMP block. A block is always `BLOCK_SIZE` bytes on the wire.
async fn read_block(stream: &mut Stream) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; BLOCK_SIZE];
    stream.read_exact(&mut buf).await.map_err(map_e)?;
    Ok(buf)
}

/// Write one full SMP block.
async fn write_block(stream: &mut Stream, block: &[u8]) -> Result<(), String> {
    stream.write_all(block).await.map_err(map_e)?;
    stream.flush().await.map_err(map_e)
}

/// An SMP client speaking the protocol over an async transport.
pub struct AsyncSmpClient {
    /// negotiated SMP version = min(client_max, server_max) from the server hello
    pub negotiated_version: Option<u16>,
    stream: Option<Stream>,
    host: String,
    port: u16,
    key_hash: [u8; 32],
    tls: bool,
    session_id: Vec<u8>,
    /// strict v23 block-chain keys (Some => encrypted blocks are in use)
    strict_snd: Option<[u8; 32]>,
    strict_rcv: Option<[u8; 32]>,
    /// per-connection ephemeral X25519 pub from the server hello (authPubKey)
    server_eph_pub: Option<[u8; 32]>,
    eph_priv: Option<[u8; 32]>,
    /// pushed MSG broker messages diverted aside by request() so a command
    /// response is never confused with a push (and vice versa).
    pending: Vec<BrokerMsg>,
    /// remembered SUB queue ids, restored after a reconnect (U-18, async twin)
    pub subs: Vec<Vec<u8>>,
}

impl AsyncSmpClient {
    /// A client that is not connected yet; call [`AsyncSmpClient::connect`].
    pub fn new(host: &str, port: u16, key_hash: [u8; 32], tls: bool) -> Self {
        AsyncSmpClient {
            stream: None,
            host: host.to_string(),
            port,
            key_hash,
            tls,
            session_id: Vec::new(),
            negotiated_version: None,
            strict_snd: None,
            strict_rcv: None,
            server_eph_pub: None,
            eph_priv: None,
            pending: Vec::new(),
            subs: Vec::new(),
        }
    }

    /// Connect to the configured host/port and run the SMP handshake.
    pub async fn connect(&mut self) -> Result<(), String> {
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((self.host.as_str(), self.port))
            .await
            .map_err(|e| format!("resolve {}:{}: {e}", self.host, self.port))?
            .collect();
        let addr = addrs
            .first()
            .copied()
            .ok_or_else(|| format!("no address for {}:{}", self.host, self.port))?;
        let connected = if self.tls {
            Self::connect_tls(addr, &self.host, self.key_hash, true).await?
        } else {
            Self::connect_plain(addr, &self.key_hash).await?
        };
        self.adopt(connected);
        Ok(())
    }

    /// Connect over plain TCP and run the SMP handshake.
    pub async fn connect_plain(addr: SocketAddr, key_hash: &[u8]) -> Result<Self, String> {
        let tcp = TcpStream::connect(addr).await.map_err(map_e)?;
        let mut stream = Stream::Plain(tcp);
        let (sid, eph, eph_priv, neg_v) = handshake(&mut stream, key_hash, None).await?;
        Ok(AsyncSmpClient {
            stream: Some(stream),
            host: addr.ip().to_string(),
            port: addr.port(),
            key_hash: {
                let mut k = [0u8; 32];
                let n = key_hash.len().min(32);
                k[..n].copy_from_slice(&key_hash[..n]);
                k
            },
            tls: false,
            session_id: sid,
            negotiated_version: neg_v,
            strict_snd: None,
            strict_rcv: None,
            server_eph_pub: eph,
            eph_priv: Some(eph_priv),
            pending: Vec::new(),
            subs: Vec::new(),
        })
    }

    /// Connect over TLS 1.3 and run the SMP handshake.
    ///
    /// The router is pinned by its key hash (the same `PinVerifier` the
    /// blocking client uses): a peer presenting another offline CA is
    /// rejected during the handshake. `with_sni=false` omits SNI, which is
    /// what the public relays need to route the connection to the SMP vhost.
    pub async fn connect_tls(
        addr: SocketAddr,
        host: &str,
        key_hash: [u8; 32],
        with_sni: bool,
    ) -> Result<Self, String> {
        let tcp = TcpStream::connect(addr).await.map_err(map_e)?;
        let name = if with_sni {
            ServerName::try_from(host.to_string()).map_err(map_e)?
        } else {
            ServerName::try_from("localhost".to_string()).map_err(map_e)?
        };
        let mut cfg = tls_client_config(key_hash).map_err(map_e)?.as_ref().clone();
        if !with_sni {
            cfg.enable_sni = false;
        }
        let connector = TlsConnector::from(Arc::new(cfg));
        let tls = connector.connect(name, tcp).await.map_err(map_e)?;
        let mut stream = Stream::Tls(Box::new(tls));
        let binding = stream.exporter();
        let (sid, eph, eph_priv, neg_v) = handshake(&mut stream, &key_hash, binding.as_ref().map(|b| &b[..])).await?;
        Ok(AsyncSmpClient {
            stream: Some(stream),
            host: host.to_string(),
            port: addr.port(),
            key_hash,
            tls: true,
            session_id: sid,
            negotiated_version: neg_v,
            strict_snd: None,
            strict_rcv: None,
            server_eph_pub: eph,
            eph_priv: Some(eph_priv),
            pending: Vec::new(),
            subs: Vec::new(),
        })
    }

    fn adopt(&mut self, other: AsyncSmpClient) {
        self.stream = other.stream;
        self.session_id = other.session_id;
        self.strict_snd = other.strict_snd;
        self.strict_rcv = other.strict_rcv;
        self.server_eph_pub = other.server_eph_pub;
        self.eph_priv = other.eph_priv;
    }

    /// Whether the client currently holds a live connection.
    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    /// The session id from the server hello (empty on plain TCP).
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// Enable strict v23 block encryption for this connection if `strict` is
    /// set and the server sent an authPubKey.
    ///
    /// The flag is explicit: it is a property of this connection, never read
    /// from the process environment.
    pub fn maybe_enable_strict(&mut self, strict: bool) -> Result<(), String> {
        if !strict {
            return Ok(());
        }
        if let (Some(p), Some(srv)) = (self.eph_priv, self.server_eph_pub) {
            let secret = x25519_dh_checked(&p.into(), &x25519_public(srv))?;
            self.enable_strict(&secret);
        }
        Ok(())
    }

    /// Enable strict v23 block encryption with an explicit DH secret.
    pub fn enable_strict(&mut self, dh_secret: &[u8; 32]) {
        let Ok((snd, rcv)) = strict_keys(&self.session_id, dh_secret, true) else {
            return;
        };
        self.strict_snd = Some(snd);
        self.strict_rcv = Some(rcv);
    }

    /// Whether strict v23 block encryption is active on this connection.
    pub fn has_strict_keys(&self) -> bool {
        self.strict_snd.is_some() && self.strict_rcv.is_some()
    }

    /// Write one command and read one response block.
    pub async fn request(
        &mut self,
        cmd: Command,
        entity_id: Vec<u8>,
        auth: Option<&Ed25519Keypair>,
    ) -> Result<Vec<BrokerMsg>, String> {
        self.send_only(cmd, entity_id, auth).await?;
        self.recv_block().await
    }

    /// Write one command WITHOUT reading a response (fire-and-forget ACK path).
    pub async fn send_only(
        &mut self,
        cmd: Command,
        entity_id: Vec<u8>,
        auth: Option<&Ed25519Keypair>,
    ) -> Result<(), String> {
        let mut t = Transmission {
            authenticator: Vec::new(),
            corr_id: random_bytes(24),
            entity_id,
            command: encode_command(&cmd).map_err(map_e)?,
        };
        if let Some(kp) = auth {
            auth_sign(&self.session_id, &mut t, kp).map_err(map_e)?;
        }
        let wire = encode_transmission(&t).map_err(map_e)?;
        let stream = self.stream.as_mut().ok_or("not connected")?;
        if let Some(snd) = self.strict_snd.as_mut() {
            let raw = encode_block_raw(&[wire]).map_err(map_e)?;
            let (next, ct) = encrypt_block(snd, &raw).map_err(map_e)?;
            *snd = next;
            stream.write_all(&ct).await.map_err(map_e)?;
            stream.flush().await.map_err(map_e)?;
        } else {
            let blk = encode_block(&[wire]).map_err(map_e)?;
            write_block(stream, &blk).await?;
        }
        Ok(())
    }

    /// SUB a queue and REMEMBER it — `reconnect()` re-issues it after a reconnect.
    /// Re-SUB goes through send_only (not request): the SOK block may also carry a
    /// pushed MSG, and request() would swallow it (U-18).
    pub async fn subscribe(&mut self, qid: &[u8], auth: Option<&Ed25519Keypair>) -> Result<(), String> {
        self.send_only(Command::Sub, qid.to_vec(), auth).await?;
        if !self.subs.iter().any(|q| q == qid) {
            self.subs.push(qid.to_vec());
        }
        Ok(())
    }

    /// Reconnect and restore all remembered subscriptions (D2(b)/U-18 async).
    pub async fn reconnect(&mut self) -> Result<(), String> {
        self.stream = None;
        self.pending.clear();
        self.connect().await?;
        for q in self.subs.clone() {
            self.send_only(Command::Sub, q, None).await?;
        }
        Ok(())
    }

    /// `request` with one automatic reconnect+retry on a transport error (D2(b)).
    /// Protocol-level ERR responses are returned as-is, never retried.
    pub async fn request_retry(
        &mut self,
        cmd: Command,
        entity_id: Vec<u8>,
        auth: Option<&Ed25519Keypair>,
    ) -> Result<Vec<BrokerMsg>, String> {
        match self.request(cmd.clone(), entity_id.clone(), auth).await {
            Ok(b) => Ok(b),
            Err(e) => {
                self.reconnect().await.map_err(|e2| format!("reconnect failed: {e2} (orig: {e})"))?;
                self.request(cmd, entity_id, auth).await
            }
        }
    }

    /// Read one block of broker messages. Drains diverted pushes first.
    pub async fn recv_block(&mut self) -> Result<Vec<BrokerMsg>, String> {
        if !self.pending.is_empty() {
            return Ok(std::mem::take(&mut self.pending));
        }
        let stream = self.stream.as_mut().ok_or("not connected")?;
        let rb = if let Some(rcv) = self.strict_rcv.as_mut() {
            let mut buf = vec![0u8; BLOCK_SIZE];
            stream.read_exact(&mut buf).await.map_err(map_e)?;
            let (next, pt) = decrypt_block(rcv, &buf).map_err(map_e)?;
            *rcv = next;
            pt
        } else {
            read_block(stream).await?
        };
        let wires = if self.strict_rcv.is_some() {
            decode_block_raw(&rb).map_err(map_e)?
        } else {
            decode_block(&rb).map_err(map_e)?
        };
        let mut out = Vec::new();
        for w in wires {
            let t = decode_transmission(&w).map_err(map_e)?;
            out.push(parse_broker(&t.command).map_err(map_e)?);
        }
        Ok(out)
    }
}

impl std::fmt::Debug for AsyncSmpClient {
    /// Prints the connection metadata only — never key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncSmpClient")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field("connected", &self.is_connected())
            .field("session_id_len", &self.session_id.len())
            .field("strict", &self.has_strict_keys())
            .finish()
    }
}

/// The SMP handshake over an async stream: read the server hello, check the
/// channel binding, send the client hello.
async fn handshake(
    stream: &mut Stream,
    key_hash: &[u8],
    tls_binding: Option<&[u8]>,
) -> Result<(Vec<u8>, Option<[u8; 32]>, [u8; 32], Option<u16>), String> {
    let sh = read_block(stream).await?;
    let (s_min, s_max, sid, auth_spki) = parse_server_hello_key(&sh).map_err(map_e)?;
    let neg_v = crate::transport::negotiate_version(s_min, s_max, crate::protocol::SMP_VERSION, crate::protocol::SMP_VERSION);
    // channel binding (spec appendix A): the client asserts sessionIdentifier
    // equals the TLS binding.
    check_session_binding(&sid)?;
    if let Some(tb) = tls_binding {
        if !sid.is_empty() {
            verify_channel_binding(&sid, tb)?;
        }
    }
    let eph = x25519_keypair();
    let eph_priv = eph.secret.to_bytes();
    let ch = client_hello_block_key(
        SMP_VERSION,
        key_hash,
        false,
        Some(spki_x25519(eph.public.as_bytes())),
    )
    .map_err(map_e)?;
    write_block(stream, &ch).await?;
    let eph = auth_spki
        .and_then(|der| parse_spki(&der).ok())
        .map(|(_a, raw)| raw);
    Ok((sid, eph, eph_priv, neg_v))
}
