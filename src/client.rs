//! SMP client.

use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use crate::crypto::*;
use crate::protocol::*;
use crate::transport::*;

pub type ClResult<T> = Result<T, String>;

fn map_e<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

pub struct Client {
    reader: TcpStream,
    writer: Arc<Mutex<TcpStream>>,
    session_id: Vec<u8>,
    pub server_key_hash: Vec<u8>,
}

impl Client {
    pub fn connect(addr: &str, key_hash: &[u8]) -> ClResult<Client> {
        let stream = TcpStream::connect(addr).map_err(map_e)?;
        let reader = stream.try_clone().map_err(map_e)?;
        let writer = Arc::new(Mutex::new(stream));
        let mut r = reader.try_clone().map_err(map_e)?;
        let sh = read_block(&mut r).map_err(map_e)?;
        let (_min, _max, sid) = parse_server_hello(&sh).map_err(map_e)?;
        let ch = client_hello_block(SMP_VERSION, key_hash, false).map_err(map_e)?;
        write_block(&mut *writer.lock().unwrap(), &ch).map_err(map_e)?;
        Ok(Client {
            reader,
            writer,
            session_id: sid,
            server_key_hash: key_hash.to_vec(),
        })
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
        write_block(&mut *self.writer.lock().unwrap(), &blk).map_err(map_e)?;
        self.recv_block()
    }

    /// Read one block and parse all broker messages in it.
    pub fn recv_block(&mut self) -> ClResult<Vec<BrokerMsg>> {
        let rb = read_block(&mut self.reader).map_err(map_e)?;
        let wires = decode_block(&rb).map_err(map_e)?;
        let mut out = Vec::new();
        for w in wires {
            let t = decode_transmission(&w).map_err(map_e)?;
            out.push(parse_broker(&t.command).map_err(map_e)?);
        }
        Ok(out)
    }
}
