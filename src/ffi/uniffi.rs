//! uniffi bindings for the FFI facade (W5-Task 5.2).
//!
//! The plain Rust facade lives in the parent module (`crate::ffi`); these
//! wrappers are what a Kotlin/Android caller actually sees. They stay thin on
//! purpose: one place implements the behaviour, the other only describes it
//! to the bindings generator.
//!
//! Every function returns `Result<_, String>`: the facade's errors are
//! already plain strings, so they cross the FFI boundary unchanged instead of
//! being flattened into an opaque code.

use crate::ffi;

/// A facade error on its way across the FFI boundary.
///
/// The facade's own errors are plain strings; this wrapper makes one
/// `std::error::Error` out of them so uniffi can carry the text to Kotlin
/// unchanged (a flat error becomes a generic foreign exception whose message
/// is this string).
#[derive(Debug)]
pub struct FfiError(pub String);

impl std::fmt::Display for FfiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for FfiError {}

/// The error type of every exported call.
///
/// uniffi has no "arbitrary string" error type, so the message travels inside
/// a flat error instead of being flattened into an opaque code.
#[derive(Debug, uniffi::Error)]
#[uniffi(flat_error)]
pub enum FfiErrorKind {
    /// The call failed; the payload carries the facade's error message.
    Failed(FfiError),
}

impl std::fmt::Display for FfiErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FfiErrorKind::Failed(e) => write!(f, "{e}"),
        }
    }
}

fn err(message: String) -> FfiErrorKind {
    FfiErrorKind::Failed(FfiError(message))
}

/// The result of creating a contact: the agent handle and the contact link.
///
/// A record rather than a tuple: uniffi has no tuple type on the wire, and a
/// named record keeps the Kotlin side readable (`result.id`, `result.link`).
#[derive(uniffi::Record)]
pub struct ContactCreated {
    /// The agent handle to pass to the other calls.
    pub id: u64,
    /// The contact link to share with the peer.
    pub link: String,
}

/// Create a contact queue; returns the handle and the link.
#[uniffi::export]
pub fn create_contact(
    host: String,
    port: u16,
    key_hash_hex: String,
    profile: String,
) -> Result<ContactCreated, FfiErrorKind> {
    let (id, link) = ffi::create_contact(&host, port, &key_hash_hex, &profile).map_err(err)?;
    Ok(ContactCreated { id, link })
}

/// Join a contact link; returns the handle.
#[uniffi::export]
pub fn join_contact(
    host: String,
    port: u16,
    key_hash_hex: String,
    link: String,
) -> Result<u64, FfiErrorKind> {
    ffi::join_contact(&host, port, &key_hash_hex, &link).map_err(err)
}

/// Accept the contact that joined us.
#[uniffi::export]
pub fn accept_contact(id: u64) -> Result<(), FfiErrorKind> {
    ffi::accept_contact(id).map_err(err)
}

/// Wait for the peer's hello.
#[uniffi::export]
pub fn await_hello(id: u64) -> Result<(), FfiErrorKind> {
    ffi::await_hello(id).map_err(err)
}

/// Send a message; returns the message id.
#[uniffi::export]
pub fn send_msg(id: u64, body_hex: String) -> Result<i64, FfiErrorKind> {
    ffi::send_msg(id, &body_hex).map_err(err)
}

/// Receive the next agent message; returns the hex of the raw agent wire.
#[uniffi::export]
pub fn recv_agent_hex(id: u64) -> Result<String, FfiErrorKind> {
    ffi::recv_agent_hex(id).map_err(err)
}

/// Drop an agent and free its handle.
#[uniffi::export]
pub fn drop_agent(id: u64) {
    ffi::drop_agent(id);
}
