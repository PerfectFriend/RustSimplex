#![allow(dead_code)]
//! smp-server: the Rust SMP router engine.
//!   smp-server [--bind 127.0.0.1:5223] [--tls <host>] [--store <path>]
//!              [--store-key-file <path>] [--insecure-plain-store]
//!   smp-server init [--bind 127.0.0.1:5223] [--tls <host>] [--store <path>]
//!              [--store-key-file <path>] [--insecure-plain-store]
//!
//! `init` creates (or opens) the store with a router identity and prints the stable
//! smp://<keyHash>@<host>:<port> address — P0-4: the keyHash survives restarts.
//! Without --tls the engine runs plain TCP. A configured store must be encrypted
//! (SMP_STORE_KEY / SMP_STORE_KEY_FILE / --store-key-file) unless --insecure-plain-store
//! is given explicitly (P1-5).

use std::path::PathBuf;
use std::process::exit;

use smp_rs::protocol::SMP_VERSION;
use smp_rs::server::{Engine, StoreOpts};
use smp_rs::store::StoreKey;

fn arg(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1).cloned())
}

fn store_opts(args: &[String]) -> Result<StoreOpts, String> {
    let mut opts = StoreOpts::from_env()?;
    if let Some(kf) = arg(args, "--store-key-file") {
        let s = std::fs::read_to_string(kf.trim())
            .map_err(|e| format!("cannot read --store-key-file {kf}: {e}"))?;
        opts.key = Some(StoreKey::from_hex(&s)?);
    }
    if args.iter().any(|a| a == "--insecure-plain-store") {
        opts.key = None;
        opts.allow_plain_store = true;
    }
    Ok(opts)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let bind = arg(&args, "--bind").unwrap_or_else(|| "127.0.0.1:5223".into());
    let store = arg(&args, "--store").map(PathBuf::from);
    let opts = match store_opts(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("[smp-server] {e}");
            exit(2);
        }
    };

    // `init`: create/open the store + router identity, print the stable address, exit.
    if args.first().map(|a| a == "init").unwrap_or(false) {
        let host = arg(&args, "--tls").unwrap_or_else(|| "localhost".into());
        let store = store.unwrap_or_else(smp_rs::store::default_store_path);
        match smp_rs::server::init_router_store(&bind, &host, &store, opts) {
            Ok(addr) => println!("{addr}"),
            Err(e) => {
                eprintln!("[smp-server] init error: {e}");
                exit(1);
            }
        }
        return;
    }

    // Single-instance guard: the store is a whole-file snapshot, so two
    // relays on one store would overwrite each other's queues. The lock is
    // held for the lifetime of the process.
    let _store_lock = match &store {
        Some(p) => match smp_rs::store::try_lock_store(p) {
            Ok(Some(l)) => Some(l),
            Ok(None) => {
                eprintln!("[smp-server] store {} is locked by another process", p.display());
                exit(1);
            }
            Err(e) => {
                eprintln!("[smp-server] cannot lock store {}: {e}", p.display());
                exit(1);
            }
        },
        None => None,
    };
    match arg(&args, "--tls") {
        Some(host) => match Engine::bind_tls_store_opts(&bind, &host, store, opts) {
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
        None => match Engine::bind_plain_store_opts(&bind, store, opts) {
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
