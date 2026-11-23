#!/usr/bin/env bash
# FFI smoke test: prove the Kotlin consumer can actually call the Rust facade.
#
#   1) build libsmp_rs.so (crate-type = cdylib, feature `ffi`)
#   2) generate the uniffi Kotlin bindings from THAT .so
#   3) compile ffi-smoke/src/main/kotlin/SmokeTest.kt against them
#   4) run it — the native library is loaded through JNA, so this exercises
#      the whole chain: Kotlin -> uniffi -> JNA -> cdylib -> Rust facade
#
# The check is offline by design: createContact validates the key hash BEFORE
# it touches the network, so a bad key hash must come back as an ordinary
# typed error — not a crash and not a silent success.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# The local dev box has a vendored cargo registry under ~/build; CI does not.
# CARGO_OFFLINE can be emptied to build against the network registry.
if [ -d "$HOME/build/rust/cargo" ] && [ -z "${CARGO_HOME:-}" ]; then
  export CARGO_HOME="$HOME/build/rust/cargo"
  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/build/cache/cargo-target/simplex-rs}"
  export CARGO_OFFLINE="${CARGO_OFFLINE:---offline}"
  export PATH="$HOME/build/bin:$PATH"
else
  export CARGO_OFFLINE="${CARGO_OFFLINE:-}"
fi

OUT="${FFI_SMOKE_OUT:-${TMPDIR:-/tmp}/ffi-smoke-out}"
rm -rf "$OUT"
mkdir -p "$OUT"

echo "[1/5] building the cdylib"
cargo build $CARGO_OFFLINE --features ffi
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
SO="$(find "$TARGET_DIR/debug" -maxdepth 1 -name 'libsmp_rs.so' | head -1)"
[ -n "$SO" ] || { echo "FAIL: libsmp_rs.so was not built"; exit 1; }
echo "      $SO"

echo "[2/5] generating the Kotlin bindings"
cargo run $CARGO_OFFLINE --quiet --features ffi --bin uniffi-bindgen -- \
  generate --library "$SO" --language kotlin --out-dir kotlin/
BINDINGS="kotlin/uniffi/smp_rs/smp_rs.kt"
[ -f "$BINDINGS" ] || { echo "FAIL: the bindings were not generated"; exit 1; }

echo "[3/5] locating JNA + the Kotlin stdlib"
# `sed -n 1p` instead of `head -1`: head closes the pipe early, and with
# `set -o pipefail` the SIGPIPE would kill the script.
JNA_JAR="${JNA_JAR:-$(find "$HOME/build" "$HOME/.gradle" -name 'jna-5*.jar' 2>/dev/null | sed -n '1p')}"
if [ -z "$JNA_JAR" ]; then
  echo "      JNA not found locally — downloading it"
  JNA_JAR="$OUT/jna.jar"
  curl -fsSL -o "$JNA_JAR" \
    https://repo1.maven.org/maven2/net/java/dev/jna/jna/5.14.0/jna-5.14.0.jar
fi
KSTD="${KOTLIN_STDLIB:-$(find "$HOME/build" -name 'kotlin-stdlib.jar' 2>/dev/null | sed -n '1p')}"
if [ -z "$KSTD" ]; then
  echo "      Kotlin stdlib not found — downloading it"
  KSTD="$OUT/kotlin-stdlib.jar"
  curl -fsSL -o "$KSTD" \
    https://repo1.maven.org/maven2/org/jetbrains/kotlin/kotlin-stdlib/2.0.21/kotlin-stdlib-2.0.21.jar
fi
echo "      JNA:    $JNA_JAR"
echo "      stdlib: $KSTD"

echo "[4/5] compiling the smoke test"
kotlinc -cp "$JNA_JAR" -d "$OUT" \
  ffi-smoke/src/main/kotlin/SmokeTest.kt "$BINDINGS"

echo "[5/5] running it against the real native library"
# uniffi's Kotlin loader looks for <arch>/libsmp_rs.so on the resource path
mkdir -p "$OUT/linux-x86-64"
cp "$SO" "$OUT/linux-x86-64/libsmp_rs.so"
java -cp "$OUT:$KSTD:$JNA_JAR" smoke.SmokeTestKt

echo "FFI SMOKE: OK"
