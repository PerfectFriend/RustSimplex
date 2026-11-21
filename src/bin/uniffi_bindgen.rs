//! The `uniffi-bindgen` CLI, vendored as a package binary.
//!
//! Why vendored: the Kotlin bindings must be regenerable offline, from the
//! built `libsmp_rs.so`, without installing a separate toolchain. The plan
//! calls it `cargo run --bin uniffi-bindgen generate --library ...`; that is
//! exactly this binary.
//!
//! Usage:
//!   cargo run --features ffi --bin uniffi-bindgen -- \
//!     generate --library target/release/libsmp_rs.so --language kotlin --out-dir kotlin/

fn main() {
    uniffi::uniffi_bindgen_main();
}
