#!/usr/bin/env bash
# Live check against the PUBLIC SimpleX infrastructure, using the real
# client CLI (src/bin/smp_client.rs).
#
# What it proves:
#   the Rust client completes a full SMP round trip over TLS 1.3 against a
#   public relay, with the relay pinned by its keyHash - PING/PONG,
#   NEW->IDS, SUB->SOK, SEND->MSG (decrypted), ACK, DEL.
#
# What it does NOT prove:
#   the leg with a real mobile SimpleX client. That leg needs the agent
#   flow (a contact link the phone accepts), and smp-client is a queue
#   demo - it does not act as an agent peer. See docs/plans/
#   2026-11-22-release-closeout.md, item A9.
#
# Usage:
#   PIN=<base64url-nopad keyHash of the relay> HOST=smp11.simplex.im \
#   PORT=5223 bash scripts/mobile_interop.sh
#
# The PIN is the relay CA keyHash - copy it from the SimpleX app
# (Settings -> the server -> View certificate -> keyHash), or take it from
# the release notes of the relay. The script never guesses it.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

HOST="${HOST:-smp11.simplex.im}"
PORT="${PORT:-5223}"
PIN="${PIN:?set PIN to the relay keyHash (base64url, no padding)}"

export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"
CARGO_OFFLINE="${CARGO_OFFLINE:---offline}"

echo "relay: $HOST:$PORT"
echo "pin:   $PIN"
echo

cargo build $CARGO_OFFLINE --bin smp-client
exec "$CARGO_TARGET_DIR/debug/smp-client" --tls "$HOST" "$PIN" "$HOST:$PORT"
