#!/usr/bin/env bash
# One-shot verification gate: unit tests + clippy + optional live public interop harness.
# Usage: ./scripts/check.sh          # tests + clippy + live harness
#        SKIP_LIVE=1 ./scripts/check.sh  # tests + clippy only (offline)
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/build/bin:$PATH"
export CARGO_HOME="$HOME/build/rust/cargo"
export CARGO_TARGET_DIR="$HOME/build/cache/cargo-target/simplex-rs"
cargo test --offline -- --test-threads=1
cargo clippy --offline --all-targets
if [ "${STRICT:-0}" = "1" ]; then
  SMP_STRICT=1 cargo test --offline --test strict_e2e --test ntf --test proxy -- --test-threads=1
fi
if [ "${SKIP_LIVE:-0}" != "1" ]; then
  ./scripts/live_interop.sh
fi
echo "CHECK: OK"
