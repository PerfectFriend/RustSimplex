#!/usr/bin/env python3
"""Assemble tests/fixtures/sntrup761_kat.txt from the reference output."""
import hashlib
import pathlib
import sys

C_PATH, R_PATH, OUT = sys.argv[1], sys.argv[2], sys.argv[3]

RUST_SEEDS = [
    ([0x01] * 32, [0xA1] * 32),
    ([0x02] * 32, [0xA2] * 32),
]

C_SRC = "simplexmq/cbits/sntrup761.c (supercop-20201130)"
C_SHA = "54f135627eb965bc41f3296e206b593694186060e08256c2a039bf1966e3e017"


def parse_blocks(path):
    blocks, cur = [], {}
    for line in pathlib.Path(path).read_text().splitlines():
        line = line.strip()
        if line.startswith("V "):
            if cur:
                blocks.append(cur)
            cur = {}
        elif line:
            tag, value = line.split()
            cur[tag] = value
    if cur:
        blocks.append(cur)
    return blocks


def parse_ss(path):
    out = []
    for line in pathlib.Path(path).read_text().splitlines():
        line = line.strip()
        if line:
            tag, value = line.split()
            assert tag == "SS", tag
            out.append(value)
    return out


cblocks = parse_blocks(C_PATH)
rss = parse_ss(R_PATH)
assert len(cblocks) == 2, cblocks
assert len(rss) == len(RUST_SEEDS), (len(rss), len(RUST_SEEDS))

rust_side = pathlib.Path(OUT).parent / "sntrup761_rust_side.txt"
pairs = []
for line in rust_side.read_text().splitlines():
    f = line.split()
    # keyseed encseed pk sk ct ss_rust
    pairs.append((f[2], f[3], f[4], f[5]))

lines = [
    "# SUPERCOP KAT vectors for SNTRUP761 (cross-implementation).",
    f"# Reference: {C_SRC}",
    f"# Reference sha256: {C_SHA}",
    "# C <pk> <sk> <ct> <ss>      - produced by the reference implementation",
    "# R <keyseed> <encseed> <pk> <sk> <ct> <ss_rust> <ss_ref>",
    "#                           - produced by the Rust port; ss_ref is the",
    "#                             shared secret the REFERENCE computed for",
    "#                             that very ciphertext",
    "# Regenerate: scripts/supercop_kat_regen.sh",
]
for b in cblocks:
    lines.append(f"C {b['PK']} {b['SK']} {b['CT']} {b['SS']}")
for (key_seed, enc_seed), (pk, sk, ct, ss_rust), ss_ref in zip(RUST_SEEDS, pairs, rss):
    ks = bytes(key_seed).hex()
    es = bytes(enc_seed).hex()
    lines.append(f"R {ks} {es} {pk} {sk} {ct} {ss_rust} {ss_ref}")

pathlib.Path(OUT).write_text("\n".join(lines) + "\n")
print(f"wrote {OUT} ({len(lines)} lines)")
