//! FFI-friendly facade (feature `ffi`): no std::env, opaque handles, String errors.
//! Ready for uniffi/cdylib binding to Android (Paranoid).
pub mod uniffi;

use crate::agent::Agent;
use crate::client::Client;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

fn agents() -> &'static Mutex<HashMap<u64, Agent>> {
    static A: OnceLock<Mutex<HashMap<u64, Agent>>> = OnceLock::new();
    A.get_or_init(|| Mutex::new(HashMap::new()))
}
fn next_id() -> u64 {
    static C: OnceLock<Mutex<u64>> = OnceLock::new();
    let c = C.get_or_init(|| Mutex::new(1));
    let mut g = c.lock().unwrap_or_else(|e| e.into_inner());
    let id = *g;
    *g += 1;
    id
}

/// Run `f` on the agent handle WITHOUT holding the global agents() lock during the
/// (possibly blocking, network-bound) operation: take the agent out, run, reinsert.
/// U-14 (audit #3): the old code held the global mutex across accept/await/recv,
/// serializing every agent in the process on one slow handle.
fn with_agent<T>(id: u64, f: impl FnOnce(&mut Agent) -> Result<T, String>) -> Result<T, String> {
    let mut g = agents().lock().unwrap_or_else(|e| e.into_inner());
    if g.contains_key(&id) {
        let mut agent = g.remove(&id).ok_or("bad handle")?;
        drop(g);
        let r = f(&mut agent);
        agents().lock().unwrap_or_else(|e| e.into_inner()).insert(id, agent);
        r
    } else {
        Err("bad handle".into())
    }
}

fn kh_from_hex(s: &str) -> Result<[u8; 32], String> {
    let v = crate::xftp::unhex(s).ok_or("bad keyhash hex")?;
    <[u8; 32]>::try_from(v.as_slice()).map_err(|_| "keyhash must be 32 bytes".to_string())
}

/// Create a contact queue; returns (handle, link).
pub fn create_contact(host: &str, port: u16, key_hash_hex: &str, profile: &str) -> Result<(u64, String), String> {
    let kh = kh_from_hex(key_hash_hex)?;
    let addr = format!("{host}:{port}").parse().map_err(|_| "bad addr".to_string())?;
    let client = Client::connect_plain(addr, &kh)?;
    let (agent, link) = Agent::create_contact(client, host, port, &kh, profile)?;
    let id = next_id();
    agents().lock().unwrap_or_else(|e| e.into_inner()).insert(id, agent);
    Ok((id, link))
}

/// Create a contact queue over TLS 1.3 pinned to `key_hash_hex`.
/// U-03 (audit #3): FFI never falls back to plaintext or no-verify TLS — the
/// connection goes through `connect_tls_sni` whose `PinVerifier` aborts on any
/// certificate whose fingerprint != key_hash.
pub fn create_contact_tls(host: &str, port: u16, key_hash_hex: &str, profile: &str) -> Result<(u64, String), String> {
    let kh = kh_from_hex(key_hash_hex)?;
    if kh == [0u8; 32] {
        return Err("key_hash must be non-zero for TLS".into());
    }
    let addr = format!("{host}:{port}").parse().map_err(|_| "bad addr".to_string())?;
    let client = Client::connect_tls_sni(addr, host, kh, true)?;
    let (agent, link) = Agent::create_contact(client, host, port, &kh, profile)?;
    let id = next_id();
    agents().lock().unwrap_or_else(|e| e.into_inner()).insert(id, agent);
    Ok((id, link))
}

/// Join a contact link; returns handle.
pub fn join_contact(host: &str, port: u16, key_hash_hex: &str, link: &str) -> Result<u64, String> {
    let kh = kh_from_hex(key_hash_hex)?;
    let addr = format!("{host}:{port}").parse().map_err(|_| "bad addr".to_string())?;
    let client = Client::connect_plain(addr, &kh)?;
    let agent = Agent::join_contact(client, link)?;
    let id = next_id();
    agents().lock().unwrap_or_else(|e| e.into_inner()).insert(id, agent);
    Ok(id)
}

/// Join a contact link over TLS 1.3 pinned to `key_hash_hex` (U-03, see create_contact_tls).
pub fn join_contact_tls(host: &str, port: u16, key_hash_hex: &str, link: &str) -> Result<u64, String> {
    let kh = kh_from_hex(key_hash_hex)?;
    if kh == [0u8; 32] {
        return Err("key_hash must be non-zero for TLS".into());
    }
    let addr = format!("{host}:{port}").parse().map_err(|_| "bad addr".to_string())?;
    let client = Client::connect_tls_sni(addr, host, kh, true)?;
    let agent = Agent::join_contact(client, link)?;
    let id = next_id();
    agents().lock().unwrap_or_else(|e| e.into_inner()).insert(id, agent);
    Ok(id)
}

pub fn accept_contact(id: u64) -> Result<(), String> {
    with_agent(id, |a| a.accept_contact())
}
pub fn await_hello(id: u64) -> Result<(), String> {
    with_agent(id, |a| a.await_hello())
}
pub fn send_msg(id: u64, body_hex: &str) -> Result<i64, String> {
    let body = crate::xftp::unhex(body_hex).ok_or("bad body hex")?;
    with_agent(id, |a| a.send_msg(&body))
}
/// Receive next agent message; returns hex of raw agent wire (caller decrypts/parses in Kotlin layer if needed).
pub fn recv_agent_hex(id: u64) -> Result<String, String> {
    Ok(recv_agent_full(id)?.0)
}

/// U-21 (audit #3): like recv_agent_hex but also returns the REAL msg_id and
/// prev_hash of the agent message (hex) — the old version discarded msg_id and
/// passed a zero prev_hash to encode_agent.
pub fn recv_agent_full(id: u64) -> Result<(String, String, String), String> {
    let (mid, am) = with_agent(id, |a| a.recv_agent())?;
    let prev = match &am {
        crate::agent::AgentMsg::Msg { prev_hash, .. } => prev_hash.clone(),
        _ => Vec::new(),
    };
    Ok((crate::xftp::hex(&crate::agent::encode_agent(&am, 0, &prev)), crate::xftp::hex(&mid), crate::xftp::hex(&prev)))
}
pub fn drop_agent(id: u64) {
    agents().lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
}
