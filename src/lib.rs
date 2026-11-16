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
pub mod identity;
pub mod agent;
pub mod async_client;
pub mod chat;
pub mod crypto;
pub mod encoding;
pub mod protocol;
pub mod pq;
pub mod pqdr;
pub mod proxy;
pub mod server;
pub mod store;
pub mod transport;
pub mod xftp;
