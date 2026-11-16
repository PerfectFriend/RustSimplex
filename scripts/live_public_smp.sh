#!/usr/bin/env bash
# Live regression harness: full SMP round-trip against the public relay smp11.simplex.im:5223 (v23 path).
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/build/bin:$PATH"
export CARGO_HOME="$HOME/build/rust/cargo"
export CARGO_TARGET_DIR="$HOME/build/cache/cargo-target/simplex-rs"
BIN="$CARGO_TARGET_DIR/debug/smp-v71"
[ -x "$BIN" ] || cargo build --offline --features v71-probes --bin smp-v71
KH=1OwYGt-yqOfe2IyVHhxz3ohqo3aCCMjtB-8wn4X_aoY
fail=0
for v in 17 18 19 20 21 22 23; do
  out=$(SMP_NTF=0 SMP_PROXY=0 SMP_V=$v timeout 90 "$BIN" 23.128.248.121:5223 "$KH" 2>&1 || true)
  if echo "$out" | grep -q "LIVE SMP FULL ROUND-TRIP OK"; then
    echo "v$v -> OK"
  else
    echo "v$v -> FAIL: $(echo "$out" | tail -n 1 | cut -c1-100)"
    fail=1
  fi
done
[ "$fail" -eq 0 ]
echo "LIVE PUBLIC SMP MATRIX (v17..v23): OK"
