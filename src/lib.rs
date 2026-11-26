//! smp-rs — a Rust implementation of the SimpleX Messaging Protocol (SMP),
//! the wire protocol spoken between SimpleX Chat clients and simplexmq servers.
//!
//! Modules:
//!   encoding  — shortString/largeString/pad primitives (matches Simplex.Messaging.Encoding)
//!   crypto    — X25519/Ed25519, SPKI DER keys, XSalsa20-Poly1305 (NaCl crypto_box)
//!   protocol  — commands, broker messages, transmission & 16384-byte block codec
//!   transport — handshake hello blocks + block I/O
//!   server    — SMP router (queue store + command handling + auth verification)
//!   client    — SMP client

pub mod sb_chain;
pub use sb_chain as blockchain;
pub mod client;
pub mod async_client;
pub mod identity;
pub mod agent;
pub mod agent_link;
pub mod agent_envelope;
pub mod x448;
pub mod x3dh;
#[cfg(feature = "ffi")]
pub mod ffi;

// The uniffi scaffolding: it defines the crate's `UniFfiTag` (the type that
// parameterises the FFI converter traits) and the exported `extern "C"` entry
// points the generated Kotlin bindings call. It must live at the crate root.
#[cfg(feature = "ffi")]
uniffi::setup_scaffolding!("smp_rs");
pub mod chat;
pub mod crypto;
pub mod encoding;
pub mod protocol;
pub mod pq;
pub mod pqdr;
pub mod proxy;
pub mod reconnect;
pub mod onion;
pub mod server;
pub mod store;
pub mod transport;
pub mod xftp;
pub mod ntf;
pub mod ntf_server;
