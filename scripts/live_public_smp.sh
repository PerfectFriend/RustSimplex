#!/usr/bin/env bash
# Live regression harness: full SMP round-trip against the public relay smp11.simplex.im:5223 (v23 path).
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/build/bin:$PATH"
export CARGO_HOME="$HOME/build/rust/cargo"
export CARGO_TARGET_DIR="$HOME/build/cache/cargo-target/simplex-rs"
BIN="$CARGO_TARGET_DIR/debug/smp-v71"
[ -x "$BIN" ] || cargo build --offline --bin smp-v71
KH=1OwYGt-yqOfe2IyVHhxz3ohqo3aCCMjtB-8wn4X_aoY
out=$(SMP_NTF=0 timeout 90 "$BIN" 23.128.248.121:5223 "$KH" 2>&1 || true)
echo "$out" | tail -n 10
echo "$out" | grep -q "LIVE SMP FULL ROUND-TRIP OK"
echo "LIVE PUBLIC SMP HARNESS: OK"
