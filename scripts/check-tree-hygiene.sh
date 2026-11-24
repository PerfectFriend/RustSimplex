#!/usr/bin/env bash
# Tree-hygiene gate for external-audit distribution.
# Scans TRACKED files only (git ls-files) — a filesystem scan would fail on
# build dirs (target/, dist/) by scanning itself.
#
# Fails on:
#   1. secret value shapes (token/key material) in any tracked file;
#   2. binary key-value stores by magic bytes (redb / sqlite / leveldb) —
#      text grep cannot see key material inside them;
#   3. tracked non-asset files > 1 MiB;
#   4. side-effect filenames (a data file named after a CLI flag = dispatcher bug).
#
# The patterns below are value-shaped on purpose: they match material, not the
# prose that names it, so this script does not trip on itself.
set -u
cd "$(git rev-parse --show-toplevel)"
fail=0

SECRET_RE='ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|[0-9]{8,10}:AA[A-Za-z0-9_-]{30,}|-----BEGIN (RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----'

echo "== 1/4 secret value shapes =="
hits=$(git grep -IlE "$SECRET_RE" -- . 2>/dev/null || true)
if [ -n "$hits" ]; then echo "$hits"; fail=1; else echo "OK: 0 hits"; fi

echo "== 2/4 binary key-value stores (magic bytes) =="
stores=$(git ls-files -z | while IFS= read -r -d '' f; do
  [ -f "$f" ] || continue
  m=$(head -c 4 "$f" 2>/dev/null | od -An -tx1 | tr -d ' \n')
  case "$m" in 72656462) echo "redb:    $f";; 53514c69) echo "sqlite:  $f";; 6c657665) echo "leveldb: $f";; esac
done)
if [ -n "$stores" ]; then echo "$stores"; fail=1; else echo "OK: 0 store files"; fi

echo "== 3/4 oversized tracked files (>1 MiB, assets/ and public/ exempt) =="
big=$(git ls-files -z | while IFS= read -r -d '' f; do
  [ -f "$f" ] || continue
  case "$f" in assets/*|public/*) continue;; esac
  s=$(stat -c%s "$f" 2>/dev/null || echo 0)
  [ "$s" -gt 1048576 ] && echo "$f ($s bytes)"
done)
if [ -n "$big" ]; then echo "$big"; fail=1; else echo "OK: none"; fi

echo "== 4/4 side-effect filenames (dispatcher-bug fingerprint) =="
side=$(git ls-files | grep -xE -- 'doctor|light|update|--help|--version|-h|-v' || true)
if [ -n "$side" ]; then echo "$side"; fail=1; else echo "OK: none"; fi

if [ "$fail" -ne 0 ]; then echo "TREE-HYGIENE: FAIL"; exit 1; fi
echo "TREE-HYGIENE: OK"
