#!/bin/bash
# Regenerate tests/fixtures/sntrup761_kat.txt — the SUPERCOP KAT vectors for
# SNTRUP761 — from the reference implementation vendored with simplexmq.
#
#   simplexmq/cbits/sntrup761.c  (supercop-20201130, public domain)
#   sha256 54f135627eb965bc41f3296e206b593694186060e08256c2a039bf1966e3e017
#
# Needs: gcc, libssl-dev (the vendored sha512.c is an OpenSSL wrapper),
#        python3, and the cargo toolchain for the Rust-side vectors.
#
# The fixture holds BOTH directions:
#   C  vectors produced by the reference (pk/sk/ct/ss),
#   R  vectors produced by the Rust port, with the shared secret the
#      REFERENCE computed for that very ciphertext.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${TMPDIR:-/tmp}/supercop-kat-$$"
mkdir -p "$WORK"
trap 'rm -rf "$WORK"' EXIT

CBITS="$ROOT/simplexmq/cbits"
cp "$CBITS/sntrup761.c" "$CBITS/sntrup761.h" "$CBITS/sha512.c" "$CBITS/sha512.h" "$WORK/"
cp "$ROOT/scripts/supercop_sntrup761_kat.c" "$WORK/kat_harness.c"

echo "[1/5] building the reference harness"
gcc -O2 -o "$WORK/kat" "$WORK/kat_harness.c" "$WORK/sntrup761.c" "$WORK/sha512.c" -lcrypto

echo "[2/5] reference vectors (deterministic entropy: SplitMix64 seed 0xC0FFEE)"
"$WORK/kat" gen 0xC0FFEE 2 > "$WORK/cside.txt"

echo "[3/5] Rust-side vectors"
(cd "$ROOT" && cargo test --offline --test pqdr_supercop -- --ignored regenerate_the_rust_side_vectors --nocapture)

echo "[4/5] reference decapsulation of the Rust ciphertexts"
"$WORK/kat" dec "$ROOT/tests/fixtures/sntrup761_rust_side.txt" > "$WORK/rust_side_ss.txt"

echo "[5/5] assembling the fixture"
python3 "$ROOT/scripts/supercop_kat_assemble.py" \
  "$WORK/cside.txt" \
  "$WORK/rust_side_ss.txt" \
  "$ROOT/tests/fixtures/sntrup761_kat.txt"

echo "done: $ROOT/tests/fixtures/sntrup761_kat.txt"
