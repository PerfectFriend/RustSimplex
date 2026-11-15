#![allow(dead_code)]
//! smp-server: the Rust SMP router engine.
//!   smp-server [--bind 127.0.0.1:5223] [--tls <host>]
//! With --tls it generates a fresh router identity (Ed25519 offline+online certs)
//! and prints the smp://<keyHash>@<host>:<port> address. Without --tls it runs plain TCP.

use std::process::exit;

use smp_rs::protocol::SMP_VERSION;
use smp_rs::server::Engine;

fn arg(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1).cloned())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let bind = arg(&args, "--bind").unwrap_or_else(|| "127.0.0.1:5223".into());
    let store = arg(&args, "--store").map(std::path::PathBuf::from);
    match arg(&args, "--tls") {
        Some(host) => match Engine::bind_tls_store(&bind, &host, store) {
            Ok(e) => {
                eprintln!("[smp-server] TLS 1.3 listening on {bind} (SMP v{SMP_VERSION}, ALPN smp/1)");
                eprintln!("[smp-server] router address: {}", e.address().unwrap_or_default());
                if let Err(err) = e.serve() {
                    eprintln!("server error: {err}");
                    exit(1);
                }
            }
            Err(e) => {
                eprintln!("bind_tls error: {e}");
                exit(1);
            }
        },
        None => match Engine::bind_plain_store(&bind, store) {
            Ok(e) => {
                eprintln!("[smp-server] plain TCP listening on {bind} (SMP v{SMP_VERSION})");
                if let Err(err) = e.serve() {
                    eprintln!("server error: {err}");
                    exit(1);
                }
            }
            Err(e) => {
                eprintln!("bind error: {e}");
                exit(1);
            }
        },
    }
}
