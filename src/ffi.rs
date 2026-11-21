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

pub fn accept_contact(id: u64) -> Result<(), String> {
    agents().lock().unwrap_or_else(|e| e.into_inner()).get_mut(&id).ok_or("bad handle")?.accept_contact()
}
pub fn await_hello(id: u64) -> Result<(), String> {
    agents().lock().unwrap_or_else(|e| e.into_inner()).get_mut(&id).ok_or("bad handle")?.await_hello()
}
pub fn send_msg(id: u64, body_hex: &str) -> Result<i64, String> {
    let body = crate::xftp::unhex(body_hex).ok_or("bad body hex")?;
    agents().lock().unwrap_or_else(|e| e.into_inner()).get_mut(&id).ok_or("bad handle")?.send_msg(&body)
}
/// Receive next agent message; returns hex of raw agent wire (caller decrypts/parses in Kotlin layer if needed).
pub fn recv_agent_hex(id: u64) -> Result<String, String> {
    let (_mid, am) = agents().lock().unwrap_or_else(|e| e.into_inner()).get_mut(&id).ok_or("bad handle")?.recv_agent()?;
    Ok(crate::xftp::hex(&crate::agent::encode_agent(&am, 0, &[])))
}
pub fn drop_agent(id: u64) {
    agents().lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
}
