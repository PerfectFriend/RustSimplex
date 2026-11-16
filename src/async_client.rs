//! Async facade over the sync Client: connect (optionally via SOCKS5) in a worker
//! thread, run requests with spawn_blocking, expose an async event loop later.
use crate::client::Client;
use crate::transport::{connect_plain_proxy, connect_tls_sni_proxy, Socks5Config};
use std::net::SocketAddr;

pub struct AsyncSmpClient {
    inner: Option<Client>,
    host: String,
    port: u16,
    key_hash: [u8; 32],
    tls: bool,
    proxy: Option<Socks5Config>,
}

impl AsyncSmpClient {
    pub fn new(host: &str, port: u16, key_hash: [u8; 32], tls: bool, proxy: Option<Socks5Config>) -> Self {
        Self { inner: None, host: host.to_string(), port, key_hash, tls, proxy }
    }

    pub async fn connect(&mut self) -> Result<(), String> {
        let (host, port, kh, tls, proxy) = (self.host.clone(), self.port, self.key_hash, self.tls, self.proxy.clone());
        let client = tokio::task::spawn_blocking(move || -> Result<Client, String> {
            if tls {
                if let Some(p) = &proxy {
                    let (stream, binding) = connect_tls_sni_proxy(&host, port, kh, true, p).map_err(|e| e.to_string())?;
                    let mut c = Client::from_stream(stream, kh);
                    // binding is available for verify_channel_binding when needed
                    let _ = binding;
                    return Ok(c);
                }
                let addr: SocketAddr = format!("{host}:{port}").parse().map_err(|_| "bad addr".to_string())?;
                Client::connect_tls(addr, &host, kh).map_err(|e| e.to_string())
            } else {
                if let Some(p) = &proxy {
                    let stream = connect_plain_proxy(&host, port, p).map_err(|e| e.to_string())?;
                    return Ok(Client::from_stream(stream, kh));
                }
                let addr: SocketAddr = format!("{host}:{port}").parse().map_err(|_| "bad addr".to_string())?;
                Client::connect_plain(addr, &kh).map_err(|e| e.to_string())
            }
        })
        .await
        .map_err(|e| e.to_string())??;
        self.inner = Some(client);
        Ok(())
    }

    pub async fn request(&mut self, cmd: crate::protocol::Command, entity_id: Vec<u8>, auth: Option<crate::crypto::Ed25519Keypair>) -> Result<Vec<crate::protocol::BrokerMsg>, String> {
        let mut inner = self.inner.take().ok_or("not connected")?;
        let (r, inner) = tokio::task::spawn_blocking(move || {
            let r = inner.request(cmd, entity_id, auth.as_ref());
            (r, inner)
        }).await.map_err(|e| e.to_string())?;
        self.inner = Some(inner);
        r
    }
}
