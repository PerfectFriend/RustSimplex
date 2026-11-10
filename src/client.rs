//! SMP client over plain TCP or TLS 1.3 (rustls), pinning the router by keyHash.

use std::net::SocketAddr;

use crate::crypto::*;
use crate::protocol::*;
use crate::transport::*;

pub type ClResult<T> = Result<T, String>;

fn map_e<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

pub struct Client {
    stream: BoxStream,
    session_id: Vec<u8>,
    pub server_key_hash: Vec<u8>,
}

impl Client {
    fn handshake(stream: &mut BoxStream, key_hash: &[u8]) -> ClResult<Vec<u8>> {
        let sh = read_block(stream).map_err(map_e)?;
        let (_min, _max, sid) = parse_server_hello(&sh).map_err(map_e)?;
        let ch = client_hello_block(SMP_VERSION, key_hash, false).map_err(map_e)?;
        write_block(stream, &ch).map_err(map_e)?;
        Ok(sid)
    }

    pub fn connect_plain(addr: SocketAddr, key_hash: &[u8]) -> ClResult<Client> {
        let mut s = connect_plain(addr).map_err(map_e)?;
        let sid = Self::handshake(&mut s, key_hash)?;
        Ok(Client { stream: s, session_id: sid, server_key_hash: key_hash.to_vec() })
    }

    pub fn connect_tls(addr: SocketAddr, host: &str, key_hash: [u8; 32]) -> ClResult<Client> {
        let mut s = connect_tls(addr, host, key_hash).map_err(map_e)?;
        let sid = Self::handshake(&mut s, &key_hash)?;
        Ok(Client { stream: s, session_id: sid, server_key_hash: key_hash.to_vec() })
    }

    /// Send one command transmission (signed if `auth` given) and read one response block.
    pub fn request(&mut self, cmd: Command, entity_id: Vec<u8>, auth: Option<&Ed25519Keypair>) -> ClResult<Vec<BrokerMsg>> {
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
        let blk = encode_block(&[wire]).map_err(map_e)?;
        write_block(&mut self.stream, &blk).map_err(map_e)?;
        self.recv_block()
    }

    /// Read one block and parse all broker messages in it (responses + pushed MSG).
    pub fn recv_block(&mut self) -> ClResult<Vec<BrokerMsg>> {
        let rb = read_block(&mut self.stream).map_err(map_e)?;
        let wires = decode_block(&rb).map_err(map_e)?;
        let mut out = Vec::new();
        for w in wires {
            let t = decode_transmission(&w).map_err(map_e)?;
            out.push(parse_broker(&t.command).map_err(map_e)?);
        }
        Ok(out)
    }
}
