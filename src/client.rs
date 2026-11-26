//! SMP client over plain TCP or TLS 1.3 (rustls), pinning the router by keyHash.

use std::net::SocketAddr;

use crate::sb_chain::{read_block_encrypted, strict_keys, write_block_encrypted};
use crate::crypto::*;
use crate::encoding::{pad, unpad};
use crate::protocol::*;
use crate::transport::*;

pub type ClResult<T> = Result<T, String>;

/// Channel binding (spec appendix A): client asserts sessionIdentifier == tls-unique.
/// TLS 1.3 has empty tls-unique (RFC 5929) and plain TCP uses "" — so sessionId must be empty.
pub fn check_session_binding(sid: &[u8]) -> ClResult<()> {
    // v0.26: in TLS mode the sessionId is a TLS channel binding; plain TCP may be empty.
    // The upstream binding is the TLS 1.3 Finished verify_data, whose length is the
    // negotiated suite's hash length: 32 bytes for SHA-256, 48 for SHA-384. The
    // rustls exporter binding is always 32 bytes.
    // Length is enforced here; equality with the live TLS binding is verify_channel_binding().
    if !(sid.is_empty() || sid.len() == 32 || sid.len() == 48) {
        return Err("bad session id length".into());
    }
    Ok(())
}

/// SEC-04: when the caller has the live TLS binding (Finished verify_data or exporter),
/// sessionId MUST equal it — rejects a MITM that rewrites serverHello sessionId.
pub fn verify_channel_binding(sid: &[u8], tls_binding: &[u8]) -> ClResult<()> {
    if sid == tls_binding && !sid.is_empty() {
        Ok(())
    } else {
        Err("channel binding mismatch".into())
    }
}

fn map_e<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

pub struct Client {
    stream: BoxStream,
    session_id: Vec<u8>,
    /// strict v23 block-chain keys (Some => encryptBlock enabled); client side is swapped vs server
    strict_snd: Option<[u8; 32]>,
    strict_rcv: Option<[u8; 32]>,
    pub server_key_hash: Vec<u8>,
    /// per-connection ephemeral X25519 pub from server hello (authPubKey), used for box auth
    pub server_eph_pub: Option<[u8; 32]>,
    /// negotiated SMP version = min(client_max, server_max) from the server hello (plan item 15)
    pub negotiated_version: Option<u16>,
    eph_priv: Option<[u8; 32]>,
    /// pushed MSG broker messages diverted aside by request() so a command response
    /// is never confused with a push (and vice versa); recv_block drains these first.
    pending: Vec<BrokerMsg>,
}

/// (sessionId, tlsBinding, keyHash) extracted from a server hello.
pub type HandshakeKeys = (Vec<u8>, Option<[u8; 32]>, [u8; 32], Option<u16>);

impl Client {
    fn handshake(stream: &mut BoxStream, key_hash: &[u8], tls_binding: Option<&[u8]>) -> ClResult<HandshakeKeys> {
        let sh = read_block(stream).map_err(map_e)?;
        let (s_min, s_max, sid, auth_spki) = parse_server_hello_key(&sh).map_err(map_e)?;
        let negotiated = crate::transport::negotiate_version(s_min, s_max, SMP_VERSION, SMP_VERSION);
        // channel binding (spec appendix A): client MUST assert sessionIdentifier == tls-unique.
        check_session_binding(&sid)?;
        // SEC-04: enforce binding when the relay supplied a non-empty sessionId (TLS Finished); plain/local sid is empty.
        if let Some(tb) = tls_binding { if !sid.is_empty() { verify_channel_binding(&sid, tb)?; } }
        let eph = x25519_keypair();
        let eph_priv = eph.secret.to_bytes();
        let ch = client_hello_block_key(SMP_VERSION, key_hash, false, Some(spki_x25519(eph.public.as_bytes()))).map_err(map_e)?;
        write_block(stream, &ch).map_err(map_e)?;
        let eph = auth_spki.and_then(|der| parse_spki(&der).ok()).map(|(_a, raw)| raw);
        Ok((sid, eph, eph_priv, negotiated))
    }

    /// Run the SMP handshake over an already-connected stream (e.g. openssl probe),
    /// then return a ready Client. `tls_binding` = TLS exporter for channel binding.
    pub fn handshake_over(mut s: BoxStream, key_hash: &[u8], tls_binding: Option<&[u8]>) -> ClResult<Client> {
        let (sid, eph, eph_priv, neg_v) = Self::handshake(&mut s, key_hash, tls_binding)?;
        let mut c = Client { stream: s, session_id: sid, strict_snd: None, strict_rcv: None, server_key_hash: key_hash.to_vec(), server_eph_pub: eph, negotiated_version: neg_v, eph_priv: Some(eph_priv), pending: Vec::new() };
        // The default is taken from the environment once, at connect time.
        let strict = std::env::var("SMP_STRICT").as_deref() == Ok("1");
        c.maybe_enable_strict(strict)?;
        Ok(c)
    }

    /// Wrap an already-handshaken stream (used by async/proxy wrappers).
    pub fn from_stream(s: BoxStream, key_hash: [u8; 32]) -> Client {
        Client { stream: s, session_id: vec![], strict_snd: None, strict_rcv: None, server_key_hash: key_hash.to_vec(), server_eph_pub: None, negotiated_version: None, eph_priv: None, pending: Vec::new() }
    }

    pub fn connect_plain(addr: SocketAddr, key_hash: &[u8]) -> ClResult<Client> {
        // The default is taken from the environment once, at connect time; the
        // resulting setting is per-connection and never re-read.
        let strict = std::env::var("SMP_STRICT").as_deref() == Ok("1");
        Self::connect_plain_with_strict(addr, key_hash, strict)
    }

    /// Connect in plain mode with an explicit strict-mode setting.
    ///
    /// The strict flag is per-connection: it is not read from the process
    /// environment, so two connections in the same process (or two tests running
    /// in parallel) cannot influence each other.
    pub fn connect_plain_with_strict(addr: SocketAddr, key_hash: &[u8], strict: bool) -> ClResult<Client> {
        let mut s = connect_plain(addr).map_err(map_e)?;
        let (sid, eph, eph_priv, neg_v) = Self::handshake(&mut s, key_hash, None)?;
        { let mut c = Client { stream: s, session_id: sid, strict_snd: None, strict_rcv: None, server_key_hash: key_hash.to_vec(), server_eph_pub: eph, negotiated_version: neg_v, eph_priv: Some(eph_priv), pending: Vec::new() }; c.maybe_enable_strict(strict)?; Ok(c) }
    }

    pub fn connect_tls(addr: SocketAddr, host: &str, key_hash: [u8; 32]) -> ClResult<Client> {
        Self::connect_tls_sni(addr, host, key_hash, true)
    }

    /// Enable strict v23 block encryption for this connection if `strict` is set
    /// and the server sent an authPubKey.
    ///
    /// The flag is passed in explicitly: it is a property of this connection, not
    /// of the process.
    /// U-07: returns Err on a non-contributory server key — strict mode must fail
    /// closed, never silently stay plaintext.
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

    /// Whether strict v23 block encryption is active on this connection.
    pub fn has_strict_keys(&self) -> bool {
        self.strict_snd.is_some() && self.strict_rcv.is_some()
    }

    /// v0.26: with_sni=false — public relays route SNI connections to the web handler;
    /// no-SNI gets the SMP protocol cert (same trick as XFTP v0.25).
    pub fn connect_tls_sni(addr: SocketAddr, host: &str, key_hash: [u8; 32], with_sni: bool) -> ClResult<Client> {
        // The default is taken from the environment once, at connect time.
        let strict = std::env::var("SMP_STRICT").as_deref() == Ok("1");
        Self::connect_tls_sni_with_strict(addr, host, key_hash, with_sni, strict)
    }

    /// Connect over TLS with an explicit strict-mode setting.
    pub fn connect_tls_sni_with_strict(
        addr: SocketAddr,
        host: &str,
        key_hash: [u8; 32],
        with_sni: bool,
        strict: bool,
    ) -> ClResult<Client> {
        let (mut s, binding) = crate::transport::connect_tls_sni_bound(addr, host, key_hash, with_sni).map_err(map_e)?;
        let (sid, eph, eph_priv, neg_v) = Self::handshake(&mut s, &key_hash, Some(&binding))?;
        { let mut c = Client { stream: s, session_id: sid, strict_snd: None, strict_rcv: None, server_key_hash: key_hash.to_vec(), server_eph_pub: eph, negotiated_version: neg_v, eph_priv: Some(eph_priv), pending: Vec::new() }; c.maybe_enable_strict(strict)?; Ok(c) }
    }

    /// Enable strict v23 transport block encryption for this session (requires authPubKey/sessSecret).
    pub fn enable_strict(&mut self, dh_secret: &[u8; 32]) {
        let Ok((snd, rcv)) = strict_keys(&self.session_id, dh_secret, true) else { return; };
        self.strict_snd = Some(snd);
        self.strict_rcv = Some(rcv);
    }

    /// X25519 box-auth shared secret for a queue whose auth key is `qauth_kp`:
    /// dhSecret = DH(queue auth priv, server per-connection eph pub) — C.cbAuthenticate k pk.
    pub fn box_secret(&self, qauth_kp: &X25519Keypair) -> Option<[u8; 32]> {
        let srv = self.server_eph_pub?;
        x25519_dh_checked(&qauth_kp.secret, &x25519_public(srv)).ok()
    }

    /// Write one command and read one response block. NOTE: a pushed MSG block that
    /// arrives before the response is returned as-is (callers that only want responses
    /// must tolerate Msg entries — receive loops skip them; fire-and-forget commands
    /// like ACK use send_only to avoid swallowing pushes).
    pub fn request(&mut self, cmd: Command, entity_id: Vec<u8>, auth: Option<&Ed25519Keypair>) -> ClResult<Vec<BrokerMsg>> {
        self.send_only(cmd, entity_id, auth)?;
        self.recv_block()
    }

    /// Write one command WITHOUT reading a response. Use for fire-and-forget commands
    /// (e.g. ACK) inside receive loops: request() would swallow a concurrently pushed
    /// MSG block as the "response" and lose it for the agent layer.
    pub fn send_only(&mut self, cmd: Command, entity_id: Vec<u8>, auth: Option<&Ed25519Keypair>) -> ClResult<()> {
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
        if let Some(snd) = self.strict_snd.as_mut() {
            let raw = encode_block_raw(&[wire]).map_err(map_e)?;
            write_block_encrypted(&mut self.stream, snd, &raw).map_err(map_e)?;
        } else {
            let blk = encode_block(&[wire]).map_err(map_e)?;
            write_block(&mut self.stream, &blk).map_err(map_e)?;
        }
        Ok(())
    }

    /// Send one command authorized with the X25519 crypto_box authenticator
    /// (secretbox(dhSecret, cbNonce(corrId), sha512(authorized)) = 80 bytes) and read one response block.
    pub fn request_box(&mut self, cmd: Command, entity_id: Vec<u8>, dh_secret: &[u8; 32]) -> ClResult<Vec<BrokerMsg>> {
        let mut t = Transmission {
            authenticator: Vec::new(),
            corr_id: random_bytes(24),
            entity_id,
            command: encode_command(&cmd).map_err(map_e)?,
        };
        auth_box(&self.session_id, &mut t, dh_secret).map_err(map_e)?;
        let wire = encode_transmission(&t).map_err(map_e)?;
        if let Some(snd) = self.strict_snd.as_mut() {
            let raw = encode_block_raw(&[wire]).map_err(map_e)?;
            write_block_encrypted(&mut self.stream, snd, &raw).map_err(map_e)?;
        } else {
            let blk = encode_block(&[wire]).map_err(map_e)?;
            write_block(&mut self.stream, &blk).map_err(map_e)?;
        }
        self.recv_block()
    }

    /// session id from the server hello (plain mode: empty)
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// Send a command to `dest` through the onion chain `hops`, reusing THIS
    /// connection as the entry point into the first hop.
    ///
    /// The connection must already be established to `hops[0]`: the outermost
    /// onion layer is keyed with that hop's server public key, so a connection
    /// to any other peer would produce an unroutable chain. The mismatch is
    /// detected here and reported instead of failing later as a decrypt error.
    ///
    /// `dest` carries both the destination address and its server public key.
    pub fn onion_send(
        &mut self,
        hops: &[crate::onion::OnionHop],
        dest: &crate::onion::OnionHop,
        cmd: crate::protocol::Command,
        entity: Vec<u8>,
        auth_kp: Option<&crate::crypto::Ed25519Keypair>,
    ) -> Result<Vec<crate::protocol::BrokerMsg>, String> {
        let first = hops
            .first()
            .ok_or_else(|| "onion_send: at least one hop required".to_string())?;
        match self.server_eph_pub {
            Some(pub_key) if pub_key == first.server_pub => {}
            _ => {
                return Err(
                    "onion_send: the client connection is not to the first hop".to_string()
                )
            }
        }
        crate::onion::onion_request_with(
            self,
            hops,
            dest.addr,
            dest.server_pub,
            cmd,
            entity,
            auth_kp,
        )
    }

    /// Write one raw 16384-byte block (used by onion routing to send a nested [Proxy, Pfwd] block).
    pub fn write_raw_block(&mut self, block: &[u8]) -> ClResult<()> {
        crate::transport::write_block(&mut self.stream, block).map_err(map_e)
    }

    /// Read one raw 16384-byte block.
    pub fn read_raw_block(&mut self) -> ClResult<Vec<u8>> {
        crate::transport::read_block(&mut self.stream).map_err(map_e)
    }

    /// Read one block of broker messages. Drains diverted pushes (see `pending`) first,
    /// so pushed MSGs are never lost to command-response reads.
    pub fn recv_block(&mut self) -> ClResult<Vec<BrokerMsg>> {
        if !self.pending.is_empty() {
            return Ok(std::mem::take(&mut self.pending));
        }
        self.recv_block_raw()
    }

    fn recv_block_raw(&mut self) -> ClResult<Vec<BrokerMsg>> {
        let rb = if let Some(rcv) = self.strict_rcv.as_mut() {
            read_block_encrypted(&mut self.stream, rcv).map_err(map_e)?
        } else {
            read_block(&mut self.stream).map_err(map_e)?
        };
        // U-20: raw block dump is a debug-only feature — compiled out unless the
        // `debug-dump` cargo feature is enabled; the file holds session traffic,
        // so it is created 0o600 on unix.
        #[cfg(feature = "debug-dump")]
        if let Ok(path) = std::env::var("SMP_DUMP_RAW") {
            use std::io::Write;
            let p = if path.is_empty() || path == "1" {
                std::env::temp_dir().join("raw_blocks.hex")
            } else {
                std::path::PathBuf::from(path)
            };
            let mut oo = std::fs::OpenOptions::new();
            oo.create(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                oo.mode(0o600);
            }
            if let Ok(mut f) = oo.open(p) {
                let _ = writeln!(f, "{}", rb.iter().map(|b| format!("{b:02x}")).collect::<String>());
            }
        }
        let wires = if self.strict_rcv.is_some() { decode_block_raw(&rb).map_err(map_e)? } else { decode_block(&rb).map_err(map_e)? };
        let mut out = Vec::new();
        for w in wires {
            let t = decode_transmission(&w).map_err(map_e)?;
            out.push(parse_broker(&t.command).map_err(map_e)?);
        }
        Ok(out)
    }

    /// PRXY: ask this router to open a proxied session to dest. Returns the PKEY.
    pub fn proxy_open(&mut self, dest_host: &str, dest_port: u16) -> ClResult<BrokerMsg> {
        let r = self
            .request(
                Command::Proxy { host: dest_host.as_bytes().to_vec(), port: dest_port.to_string().into_bytes(), auth: None },
                vec![],
                None,
            )
            .map_err(map_e)?;
        r.into_iter().next().ok_or_else(|| "empty PRXY response".into())
    }

    /// PFWD: send a command via the proxy session to the destination router.
    /// `pkey` = the PKEY response; returns decrypted broker messages from PRES.
    pub fn pfwd(&mut self, pkey: &BrokerMsg, cmd: Command, entity_id: Vec<u8>, auth: Option<&Ed25519Keypair>) -> ClResult<Vec<BrokerMsg>> {
        let BrokerMsg::Pkey { session_id, cert_key, .. } = pkey else {
            return Err("expected PKEY".into());
        };
        let (_a, dest_pub_raw) = parse_spki(cert_key).map_err(map_e)?;
        let dest_pub = x25519_public(dest_pub_raw);
        // per-command ephemeral key
        let eph = x25519_keypair();
        let client_sess = x25519_dh_checked(&eph.secret, &dest_pub)?;
        // inner transmission (signed with OUR session id on the proxy connection, as usual)
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
        let padded = pad(&wire, crate::proxy::PROXIED_T_LEN).map_err(map_e)?;
        let nonce = cb_nonce(&t.corr_id);
        let enc = secretbox_encrypt(&client_sess, &nonce, &padded)?;
        // PFWD transmission: entity = proxy session id, unsigned
        let pfwd_cmd = Command::Pfwd { version: SMP_VERSION, command_key: spki_x25519(&eph.public.to_bytes()), enc };
        let pt = Transmission {
            authenticator: Vec::new(),
            corr_id: t.corr_id.clone(),
            entity_id: session_id.clone(),
            command: encode_command(&pfwd_cmd).map_err(map_e)?,
        };
        let pwire = encode_transmission(&pt).map_err(map_e)?;
        let blk = encode_block(&[pwire]).map_err(map_e)?;
        write_block(&mut self.stream, &blk).map_err(map_e)?;
        let msgs = self.recv_block()?;
        for m in &msgs {
            if let BrokerMsg::Pres { enc } = m {
                let rn = crate::proxy::reverse_nonce(&nonce);
                let plain = secretbox_decrypt(&client_sess, &rn, enc).ok_or("PRES decrypt failed")?;
                let inner = unpad(&plain).map_err(map_e)?;
                let it = decode_transmission(&inner).map_err(map_e)?;
                return Ok(vec![parse_broker(&it.command).map_err(map_e)?]);
            }
        }
        Ok(msgs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enable_strict_sets_swapped_client_chain_keys() {
        let mut c = Client {
            stream: Box::new(std::io::Cursor::new(Vec::new())),
            session_id: b"sid".to_vec(),
            strict_snd: None,
            strict_rcv: None,
            server_key_hash: vec![],
            server_eph_pub: None, negotiated_version: None,
            eph_priv: None,
            pending: Vec::new(),
        };
        let secret = [7u8; 32];
        c.enable_strict(&secret);
        let (a, b) = crate::sb_chain::sbc_init(b"sid", &secret).unwrap(); // test-only
        assert_eq!(c.strict_snd.unwrap(), b);
        assert_eq!(c.strict_rcv.unwrap(), a);
    }
}
