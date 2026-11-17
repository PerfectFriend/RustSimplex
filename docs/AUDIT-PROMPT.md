# AUDIT LAUNCH PROMPT — external critics (Hydrogen / Grok / Sonnet-class)

Repo: `simplex-rs` — Rust clone of the SimpleX protocol stack (SMP v17–v23, XFTP v4, NTF, proxy,
PQDR/E2E ratchet). HEAD at audit time: `1faf0409d0a2b4a95a8fa74fce281b9da7661fab` (branch `master`,
mirrored to `origin/main`). ~5,100 LOC in `src/`.

You are one of three independent auditors. Your output is consumed by an automated pipeline, so follow
the output contract EXACTLY. Do not freelance, do not summarize the repo, do not praise the code.
Adversarial findings with reproducible cases only.

## 0. Ground rules (violating any of these invalidates the report)

1. Read `docs/AUDIT-REPORT.md` (blocks 1–70: what was already found and fixed), `docs/SECURITY.md`,
   `docs/ROADMAP.md` first. Do NOT re-report anything marked CLOSED there unless you have a
   reproducible counterexample.
2. Never print, copy, or paraphrase any credential/token/key material. If you find one, report the
   file name and shape only, as `[REDACTED]`.
3. Every finding MUST have `file`, `line`, and a short verbatim `fragment` of the offending code.
   A finding without file:line is discarded.
4. Every finding MUST state a reproducible trigger (malformed input, call sequence, env var) or a
   test command. "Looks risky" is not a finding.
5. Distinguish **broken** (regression) from **dead** (written, not wired) from **unbuilt** (planned,
   in ROADMAP). Only broken/dead are defects; label them as such.
6. Panic/`unwrap`/`expect`/indexing on wire-controlled data = remote DoS, severity HIGH or CRITICAL.
7. Fail-open crypto negotiation (plaintext fallback when E2E ratchet missing) = CRITICAL.
8. Report what you could NOT verify in the mandatory `could_not_verify` field — do not silently skip.
9. Respond in Russian (the owner's language), except the JSON keys stay as given below.

## 1. Your zone (assigned by the owner — do not read other zones' files beyond a 20-line skim for context)

- **Zone A — wire parsing & crypto core**: `src/encoding.rs`, `src/protocol.rs`, `src/crypto.rs`,
  `src/pq.rs`, `src/sb_chain.rs`, `src/store.rs`, plus `tests/wire.rs`, `tests/fuzz_parse.rs`,
  `tests/persist.rs`.
  Hunt: length-prefix trust, integer overflow in size math, unbounded allocations from wire fields,
  `unwrap/expect/panic`/indexing on parsed input, key-type confusion (Ed25519 vs X25519 SPKI), pad/block
  math (`pad`, `w_large`, BLOCK_SIZE=16384), hash/encoding mismatches (docs vs code), store fail-open.
- **Zone B — agent/session/ratchet/chat**: `src/agent.rs`, `src/pqdr.rs`, `src/chat.rs`,
  `src/async_client.rs`, plus `tests/agent.rs`, `tests/chat.rs`, `tests/chat_e2e.rs`,
  `tests/pqdr*.rs`, `tests/strict_e2e.rs`, `tests/audit_fixes.rs`.
  Hunt: ratchet state machine (DH before AUTH, skipped-keys growth), fail-open E2E, ACK/delivery
  logic (redelivery, QUEUE_FULL), push/response block interleaving, msg_counter/prev_hash chain.
- **Zone C — transport/TLS/server/FFI/xftp/proxy**: `src/transport.rs`, `src/client.rs`,
  `src/server.rs`, `src/identity.rs`, `src/xftp.rs`, `src/proxy.rs`, `src/ffi.rs`, `src/bin/*`,
  plus `tests/interop.rs`, `tests/ntf*.rs`, `tests/proxy.rs`, `tests/socks5.rs`, `tests/xftp.rs`,
  `tests/xcheck.rs`, `scripts/live_interop.sh`.
  Hunt: PinVerifier bypasses (both wrong-keyHash AND `[evil_leaf, pinned_CA]` — see existing tests),
  TLS/SNI/sessionId binding, proxy SSRF guard, server pump (push chunking, catch_unwind coverage,
  lock poisoning), XFTP FileDesc `size`/`orig_size` OOM/overread, FFI surface (null pointers, lifetimes).

## 2. How to verify (run, don't assume)

```bash
export PATH="$HOME/build/bin:$PATH" CARGO_HOME=$HOME/build/rust/cargo
export CARGO_TARGET_DIR=$HOME/build/cache/cargo-target/simplex-rs
cd ~/Projects/simplex-rs
cargo test --offline --no-fail-fast -- --test-threads=1        # expect 70/70
SMP_STRICT=1 cargo test --offline --test strict_e2e --test ntf --test proxy   # expect 3/3
cargo clippy --offline --all-targets                              # expect 0 warnings
cargo clippy --offline --all-targets --features v71-probes        # expect 0 warnings
bash scripts/live_interop.sh                                      # SMP v17..v23 + XFTP PING/PONG vs public relays
```

If a command fails for environmental reasons, say so in `could_not_verify` — do not guess.

## 3. Output contract (exactly this JSON, nothing else in the machine-readable part)

```json
{
  "auditor": "<model name>",
  "zone": "A|B|C",
  "head": "1faf0409d0a2b4a95a8fa74fce281b9da7661fab",
  "findings": [
    {
      "id": "ZONE-N",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "class": "broken|dead|unbuilt|docs-lie",
      "file": "src/...",
      "line": 0,
      "fragment": "<verbatim code>",
      "issue": "one paragraph, what an attacker/user can do",
      "trigger": "repro: input / call / command",
      "fix": "concrete fix direction"
    }
  ],
  "could_not_verify": "..."
}
```

- Severity arbitration (disagreement between auditors is expected; the parent arbitrates):
  CRITICAL = remote code exec / auth bypass / silent plaintext fallback / key leak.
  HIGH = remote DoS (panic on wire input), MITM possible, integrity break.
  MEDIUM = resource exhaustion bounded, logic bug with workaround. LOW = hygiene. INFO = note.
- Sort findings by severity. Dedup within your zone. Max 40 findings — rank, don't pad.

## 4. What is OUT of scope (do not report)

- Probe binaries `src/bin/smp_v71.rs`, `xftp_h2_v71.rs` being `NoVerify` — by design, never shipped as clients.
- Missing features listed in ROADMAP "Next" (onion routing, async engine, TLS-Finished sessionId) — unbuilt, not defects.
- Style/naming nits without a security or correctness impact.
- The public SimpleX relay behavior itself (we are the client; relay-side entitlements are not our bug).

## 5. Deliverable

One JSON per the contract, wrapped in a short Russian markdown summary (≤30 lines): top-3 findings,
what you could not verify, and whether you recommend shipping as-is. The parent merges the three JSONs
into a severity-ranked table in `docs/AUDIT-REPORT.md` and re-verifies every headline finding at
file:line before it counts.
