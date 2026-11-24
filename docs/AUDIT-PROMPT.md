# AUDIT LAUNCH PROMPT — external critics (three independent champion models)

Repo: `simplex-rs` — Rust implementation of the SimpleX protocol stack (SMP v17–v23, XFTP v4,
NTF, proxy, PQDR/E2E ratchet). **Аудируемая база: ветка `main`, коммит `6cb00d4`** (public repo
PerfectFriend/RustSimplex). ~12,000 LOC in `src/`, ~178 тестов.

You are one of three independent auditors. Your output is consumed by an automated pipeline, so
follow the output contract EXACTLY. Do not freelance, do not summarize the repo, do not praise the code.
Adversarial findings with reproducible cases only.

## 0. Ground rules (violating any of these invalidates the report)

1. Read `docs/AUDIT-REPORT.md` (previous internal audit: what was found and fixed), `docs/AUDIT-RESPONSE.md`
   (status of the 2026-11-23 external audit — P0/P1/P2/P3 item by item), `docs/SECURITY.md`, `docs/ROADMAP.md`
   first. Do NOT re-report anything marked CLOSED/СДЕЛАНО there unless you have a reproducible counterexample.
2. Never print, copy, or paraphrase any credential/token/key material. If you find one, report the
   file name and shape only, as `[REDACTED]`. (History sweep at handoff: 0 hits for all token classes,
   0 key-value stores, 0 oversized files — `scripts/check-tree-hygiene.sh` enforces this in CI.)
3. Every finding MUST have `file`, `line`, and a short verbatim `fragment` of the offending code.
   A finding without file:line is discarded.
4. Every finding MUST state a reproducible trigger (malformed input, call sequence, env var) or a
   test command. "Looks risky" is not a finding.
5. Distinguish **broken** (regression) from **dead** (written, not wired) from **unbuilt** (planned,
   in ROADMAP). Only broken/dead are defects; label them as such.
6. Panic/`unwrap`/`expect`/indexing on wire-controlled data = remote DoS, severity HIGH or CRITICAL.
7. Fail-open crypto negotiation (plaintext fallback when E2E ratchet missing) = CRITICAL.
8. State-mutation-before-AEAD-verify in any decrypt path = CRITICAL (see closed P0-1 for the pattern).
9. Report what you could NOT verify in the mandatory `could_not_verify` field — do not silently skip.
10. Respond in Russian (the owner's language), except the JSON keys stay as given below.

## 1. Your zone (assigned by the owner — do not read other zones' files beyond a 20-line skim for context)

- **Zone A — wire parsing & crypto core & store**: `src/encoding.rs`, `src/protocol.rs`, `src/crypto.rs`,
  `src/x448.rs`, `src/pq.rs`, `src/sb_chain.rs`, `src/store.rs`, plus `tests/wire.rs`, `tests/fuzz_parse.rs`,
  `tests/persist.rs`, `tests/p0_store_failclosed.rs`, `tests/store_migration.rs`, `tests/p0_identity_persistence.rs`.
  Hunt: length-prefix trust, integer overflow in size math, unbounded allocations from wire fields,
  `unwrap/expect/panic`/indexing on parsed input, key-type confusion (Ed25519 vs X25519 SPKI), pad/block
  math (BLOCK_SIZE=16384), hash/encoding mismatches (docs vs code), store fail-open, snapshot trailer parsing.
- **Zone B — agent/session/ratchet/chat/e2e**: `src/agent.rs`, `src/agent_envelope.rs`, `src/agent_link.rs`,
  `src/pqdr.rs`, `src/chat.rs`, `src/async_client.rs`, `src/reconnect.rs`, plus `tests/agent.rs`, `tests/chat*.rs`,
  `tests/pqdr*.rs`, `tests/strict_e2e.rs`, `tests/p0_agent_no_loss.rs`, `tests/p0_delivery.rs`,
  `tests/p0_ratchet_atomicity.rs`, `tests/audit_fixes.rs`, `tests/reconnect*.rs`, `tests/async_client.rs`.
  Hunt: ratchet state machine (DH step before AUTH, skipped-keys growth/loss, replay), fail-open E2E,
  ACK/delivery logic (redelivery, QUEUE_FULL), push/response block interleaving, msg_counter/prev_hash chain.
- **Zone C — transport/TLS/server/identity/FFI/xftp/proxy/ntf/onion**: `src/transport.rs`, `src/client.rs`,
  `src/server.rs`, `src/identity.rs`, `src/ntf.rs`, `src/ntf_server.rs`, `src/onion.rs`, `src/proxy.rs`,
  `src/xftp.rs`, `src/ffi.rs`, `src/ffi/uniffi.rs`, `src/bin/*`, plus `tests/interop.rs`, `tests/ntf*.rs`,
  `tests/proxy.rs`, `tests/socks5.rs`, `tests/xftp*.rs`, `tests/tls_finished_binding.rs`, `tests/xcheck.rs`,
  `tests/public_api.rs`, `tests/env_isolation.rs`, `scripts/live_interop.sh`, `scripts/live_public_smp.sh`.
  Hunt: PinVerifier bypasses (both wrong-keyHash AND `[evil_leaf, pinned_CA]` — see existing tests),
  TLS/SNI/sessionId binding, proxy SSRF guard, server pump (push chunking, catch_unwind coverage,
  lock poisoning, persist-outside-lock), XFTP FileDesc size OOM/overread, FFI surface (null pointers,
  lifetimes, global Mutex on network calls, missing TLS pinning — open item P0-5), single-instance store lock.

## 2. How to verify (run, don't assume)

```bash
export PATH="$HOME/build/bin:$PATH" CARGO_HOME=$HOME/build/rust/cargo
export CARGO_TARGET_DIR=$HOME/build/cache/cargo-target/simplex-rs
cd ~/Projects/simplex-rs && git checkout 6cb00d4   # audited base
cargo test --locked -- --test-threads=1                              # expect 178 passed / 0 failed
SMP_STRICT=1 cargo test --locked --test strict_e2e -- --test-threads=1
SMP_STRICT=1 cargo test --locked --test ntf        -- --test-threads=1
SMP_STRICT=1 cargo test --locked --test proxy      -- --test-threads=1
cargo clippy --locked --all-targets -- -D warnings                   # expect 0
cargo test --locked --features v71-probes -- --test-threads=1
cargo test --locked --features ffi -- --test-threads=1
bash scripts/check-tree-hygiene.sh                                   # expect TREE-HYGIENE: OK
bash scripts/live_interop.sh                                         # SMP v17..v23 + XFTP vs public relays
```

If a command fails for environmental reasons, say so in `could_not_verify` — do not guess.

## 3. Output contract (exactly this JSON, nothing else in the machine-readable part)

```json
{
  "auditor": "<model name>",
  "zone": "A|B|C",
  "head": "6cb00d4",
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
  CRITICAL = remote code exec / auth bypass / silent plaintext fallback / key leak / state-desync on forged frame.
  HIGH = remote DoS (panic on wire input), MITM possible, integrity break.
  MEDIUM = resource exhaustion bounded, logic bug with workaround. LOW = hygiene. INFO = note.
- Sort findings by severity. Dedup within your zone. Max 40 findings — rank, don't pad.

## 4. What is OUT of scope (do not report)

- Probe binaries `src/bin/smp_v71.rs`, `src/bin/xftp_h2_v71.rs`, `src/bin/xftp_h2_v65_backup.rs`,
  `src/bin/ntf_probe.rs` being `NoVerify` — by design; CI job `probe-isolation` asserts they are
  excluded from the default build.
- Open items already accepted with an owner decision in `docs/AUDIT-RESPONSE.md`
  (P0-3 remainder, P0-5 FFI pinning+locks, P0-7 TlsBackend/interop-CI, P1-x) — report only NEW defects
  or a reproducible counterexample to a closed item.
- Missing features listed in ROADMAP — unbuilt, not defects.
- Style/naming nits without a security or correctness impact.
- The public SimpleX relay behavior itself (we are the client; relay-side entitlements are not our bug).

## 5. Deliverable

One JSON per the contract, wrapped in a short Russian markdown summary (≤30 lines): top-3 findings,
what you could not verify, and whether you recommend shipping as-is. The parent merges the three JSONs
into a severity-ranked table in `docs/AUDIT-REPORT.md` and re-verifies every headline finding at
file:line before it counts.
