//! Structural invariant: the public API must not expose dead modules.
//!
//! A `pub mod` that nothing in the crate (and nothing in the test suite) ever
//! references is a promise the crate's public surface makes and does not keep.
//! Found by audit rev8 finding N-14: `async_client` and `reconnect` were both
//! `pub` with zero callers outside their own files.
//!
//! Feature-gated modules are exempt: they are opt-in surfaces for an out-of-tree
//! consumer (the `ffi` facade is consumed by the Android/Paranoid app, not by this
//! repository). The invariant for those is that they really are gated — an
//! unconditional `pub mod` with no caller is still a failure.

use std::path::{Path, PathBuf};

fn crate_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// Public modules declared in src/lib.rs, with the `#[cfg(...)]` gate (if any).
fn public_modules() -> Vec<(String, Option<String>)> {
    let lib = std::fs::read_to_string(crate_root().join("src/lib.rs")).expect("read src/lib.rs");
    let mut out = Vec::new();
    let mut pending_cfg: Option<String> = None;
    for line in lib.lines() {
        let t = line.trim();
        if t.starts_with("#[cfg(") {
            pending_cfg = Some(t.to_string());
            continue;
        }
        if let Some(rest) = t.strip_prefix("pub mod ") {
            let name = rest.split(';').next().unwrap_or("").trim().to_string();
            out.push((name, pending_cfg.take()));
            continue;
        }
        if !t.is_empty() && !t.starts_with("#[") && !t.starts_with("//") {
            pending_cfg = None;
        }
    }
    out
}

/// How many places outside the module's own file mention `module::`.
fn references_outside_own_file(module: &str) -> usize {
    let root = crate_root();
    let mut files: Vec<PathBuf> = Vec::new();
    for dir in ["src", "tests"] {
        collect_rs(&root.join(dir), &mut files);
    }
    let needle = format!("{module}::");
    let mut count = 0usize;
    for f in files {
        let rel = f.strip_prefix(&root).unwrap_or(&f);
        if rel == Path::new(&format!("src/{module}.rs")) || rel == Path::new("src/lib.rs") {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&f) {
            count += text.matches(&needle).count();
        }
    }
    count
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_rs(&p, out);
        } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(p);
        }
    }
}

#[test]
fn public_modules_are_not_dead() {
    let mut dead: Vec<String> = Vec::new();
    for (m, cfg) in public_modules() {
        if cfg.is_some() {
            // Opt-in surface for an out-of-tree consumer — allowed to have no
            // in-repo caller, but it must genuinely be gated.
            continue;
        }
        if references_outside_own_file(&m) == 0 {
            dead.push(m);
        }
    }
    assert!(
        dead.is_empty(),
        "public modules with no caller anywhere in src/ or tests/ (dead code): {dead:?}. \
         Wire them into a real call path with a test, or remove them from the public API."
    );
}

#[test]
fn async_client_is_exposed_and_really_async() {
    // W4-Task 4.1 supersedes W1-Task 1.1: `async_client` is back as a REAL async
    // client (tokio::net::TcpStream + tokio_rustls), required by gate G3 ("async
    // engine with auto-reconnect", ROADMAP #5). The old W1 assertion that
    // `pub mod async_client` must NOT exist encoded the state where the module
    // was a dead spawn_blocking facade over the sync client — obsolete now.
    // This test pins the new invariant instead: exposed, called from tests, and
    // genuinely async (no spawn_blocking facade).
    let lib = std::fs::read_to_string(crate_root().join("src/lib.rs")).expect("read src/lib.rs");
    assert!(
        lib.contains("pub mod async_client"),
        "async_client must be exposed: gate G3 needs a real async engine (W4-Task 4.1)"
    );
    let src =
        std::fs::read_to_string(crate_root().join("src/async_client.rs")).expect("read src/async_client.rs");
    assert!(
        src.contains("tokio::net::TcpStream"),
        "async_client must run on tokio TCP, not std::net"
    );
    assert!(
        src.contains("tokio_rustls"),
        "async_client must do a real async TLS 1.3 handshake via tokio-rustls"
    );
    assert!(
        !src.contains("spawn_blocking"),
        "async_client must NOT be a spawn_blocking facade over the sync client — \
         that is exactly what W1-Task 1.1 deleted as a lie"
    );
}

#[test]
fn every_ungated_public_module_is_reachable() {
    // Sanity check that the reachability scan itself works: `crypto` is used all
    // over the crate, so it must never be reported as dead.
    assert!(
        references_outside_own_file("crypto") > 0,
        "reachability scan is broken — crypto is referenced everywhere"
    );
}
