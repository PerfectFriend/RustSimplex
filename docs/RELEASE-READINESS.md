# simplex-rs — Release Readiness Audit

Date: 2026-11-20 · Commit: `8b9af94` (v0.98) · Branch: `master` → `origin/main` (PerfectFriend/RustSimplex)

Audit method: local codebase inspection + executable verification (cargo test / clippy / live probes against
the public SimpleX infrastructure) + cross-check against the Haskell reference (`simplexmq/`,
`simplex-chat/`) checked out under `~/Projects/simplex-rs/`.

---

## 1. Verdict

**Release readiness: ~78% — NOT ready for a public production release; ready for a closed beta / library release.**

The wire-level protocol core is strong and proven against real infrastructure. The gaps are concentrated in
(a) the notification-server (NTF) command layer, (b) certificate pinning in the client paths, and
(c) packaging/distribution (no crates.io metadata, no CI matrix beyond one workflow, no fuzz target in CI).

| Area | Readiness | Evidence |
|---|---|---|
| SMP core (v17–v23) | **95%** | live full round-trip `NEW→IDS→SUB→SEND→MSG→ACK→DEL` on `smp11.simplex.im:5223`, all 7 versions green |
| SMP transport security | **90%** | TLS1.3, ALPN `smp/1`, SB-chain block encryption, channel-bound sessionId |
| XFTP v4 | **90%** | live `PING→PONG`, `FNEW→SIDS`, `FPUT 64KB→OK`, `FGET` decrypt byte-match, `FDEL→OK` on `xftp1.simplex.im:443` |
| Onion routing over SMP proxy | **85%** | 2-hop onion round-trip + wrong-hop-key negative test (local) |
| E2E PQDR ratchet | **80%** | init/encrypt/decrypt/rotate/skipped-key limits; `Agent::e2e` default-on, fail-closed |
| Reconnect / resilience | **80%** | exponential backoff, re-dial, strict-mode re-enable |
| NTF (notifications) | **45%** | handshake **accepted live** (negative control verified); command layer not yet implemented |
| Client UX / apps | **25%** | FFI façade only; no desktop/mobile UI in this repo |
| Packaging & release ops | **40%** | no crates.io metadata, single CI workflow, no release pipeline |

---

## 2. Verified state (executed, not claimed)

```
cargo test --offline                 -> 83 passed / 0 failed / 0 ignored
SMP_STRICT=1 cargo test (strict)     -> 3 passed / 0 failed
cargo clippy --all-targets           -> 0 warnings, 0 errors
cargo clippy --features v71-probes   -> 0 warnings, 0 errors
```

* **83/83** unit + integration tests green (20 test binaries), strict-mode suite **3/3**.
* **0 `unsafe`** blocks in the entire crate.
* **0 `unwrap`/`expect`** in library code paths — all 36 occurrences live inside `#[cfg(test)]` modules
  (`sb_chain.rs` 25, `reconnect.rs` 7, `client.rs` 3, `server.rs` 1).
* **4 `panic!`/`todo!`** — all inside diagnostic binaries (`src/bin/*`), none in the library.
* **No secrets**: scan for API keys/tokens/passwords/private-key PEM headers across `src/` and `docs/` → 0 hits.
* **Codebase size**: 9 464 lines across 27 source files + 20 test files.

### Live interoperability (this run and prior runs)

| Target | Result |
|---|---|
| `smp11.simplex.im:5223` (SMP v17–v23) | full round-trip OK, all 7 versions |
| `xftp1.simplex.im:443` (XFTP v4) | PING/PONG, FNEW/SIDS, FPUT 64 KB→OK, FGET decrypt match, FDEL→OK |
| `ntf2.simplex.im:443` (NTF, ALPN `ntf/1`) | **TLS1.3 + NTF handshake accepted** (server kept the session); negative control (corrupted keyHash) → server closed the connection |

---

## 3. Findings

### 3.1 Resolved during this run

| # | Finding | Resolution |
|---|---|---|
| N-1 | **NTF treated as SMP** — earlier probes sent an SMP client hello to the NTF vhost; the server closed the connection every time. | NTF is a *separate* protocol (simplexmq `Notifications/Transport.hs`): block size **512 B** (not 16384), own handshake `NtfServerHandshake`/`NtfClientHandshake`, own command tag set (`TNEW/SNEW/PING`, not `NKEY/NSUB`). Implemented in `src/ntf.rs`. |
| N-2 | **keyHash computed over the wrong certificate** | Correct rule: SHA-256 over the DER of the **CA certificate** in the served chain (Haskell `C.signedFingerprint` → `serverIdentity`). Proven against the official relay address `smp11=1OwYGt-…` (exact match) and `ntf=FB-Uop7…`. |
| N-3 | `parse_server_hello_key` rejected the NTF server hello | Haskell `Maybe` tag is ASCII `'0'/'1'`; the NTF vhost emits binary `0x00`. Parser now accepts both. |
| N-4 | rustls `HandshakeFailure` against the NTF vhost | openssl negotiates TLS1.3/CHACHA20/X25519 fine; NTF probes use openssl (diagnostics only, `v71-probes` feature). |
| N-5 | `Client::handshake` was private — no way to complete an SMP handshake over an externally-created TLS stream | Added `Client::handshake_over(stream, key_hash, tls_binding)`. |

### 3.2 Open issues, ranked

**HIGH**

1. **NTF command layer not implemented** (`src/ntf.rs` has the tag set, but no transport/client).
   Live-verified gap: after the handshake the server keeps the connection, but no NTF command has been
   round-tripped (`PING` → `PONG`, `SNEW` → `IDSUB`, `TNEW` → `IDTKN` still unproven).
   *Reachability*: high — push notifications are a core SimpleX feature.
   *Fix*: NTF transmission framing (`Transmission` + `auth` + entity ids, batch mode from v2) and a
   `NtfClient` wrapper over the 512-byte block transport.

2. **Certificate pinning is not enforced in the client paths.** The `NoVerify` verifier exists only in
   `v71-probes` diagnostic binaries (`src/transport.rs:320`, `src/bin/xftp_h2.rs:352`), and the public
   keyHash is *supplied by the caller* rather than verified against the served chain. A production client
   must compute the CA-DER fingerprint from the TLS chain and compare it to the pinned value
   (the rule is now implemented in `ntf::key_hash_from_ca_der` but is not wired into `AsyncSmpClient`).
   *Severity*: HIGH for a privacy product; the MITM test is still missing.

**MEDIUM**

3. **No crates.io/package metadata** — `Cargo.toml` has no `description`, `license`, `repository`,
   `keywords`, `categories`; the crate cannot be published as-is.
4. **CI coverage is thin** — one workflow; no matrix over `default / v71-probes / no-default-features / ffi`,
   no `cargo audit`, no fuzz job (a `tests/fuzz_parse.rs` exists but is not run under `cargo-fuzz`).
5. **No release pipeline** — no versioned tags, no changelog generator wired to `git log`, no reproducible
   release build.
6. **Fuzzing is smoke-level** — `tests/fuzz_parse.rs` uses hand-written vectors, not a coverage-guided fuzzer.

**LOW**

7. `src/bin/*` diagnostic binaries still contain `panic!`/`expect` (acceptable for probes, but they must
   stay behind the `v71-probes` feature and out of release artifacts).
8. `docs/` still describes NTF as SMP-like in places (updated in this release, but the audit prompt
   `docs/AUDIT-PROMPT.md` needs a refresh for external reviewers).

---

## 4. Classification of gaps (per project convention)

* **broken** (regression): none found — every defect discovered this run was fixed and covered by a test.
* **dead** (written but not wired): `src/ntf.rs` command/tag layer is implemented but not yet reachable from
  a client; `Client::handshake_over` is used only by probes.
* **unbuilt** (planned, not implemented): NTF command round-trip, pinning enforcement inside the client,
  crates.io packaging, release CI, coverage-guided fuzzing, UI clients.

No unbuilt item is reported as a defect, and no defect is reported as unbuilt.

---

## 5. Release gates — what must be true for v1.0

| Gate | Current | Action |
|---|---|---|
| All tests green, clippy clean | ✅ 83/83 + 0 warnings | keep in CI |
| SMP live interop v17–v23 | ✅ verified | re-run `scripts/live_interop.sh` per release |
| XFTP live interop | ✅ verified | same |
| NTF live command round-trip | ❌ handshake only | implement NTF client, prove `PING→PONG` and `SNEW→IDSUB` |
| Pinning enforced + MITM negative test | ❌ | wire `key_hash_from_ca_der` into `AsyncSmpClient`, add MITM test |
| No `unsafe`, no library panics | ✅ | keep |
| No secrets in tree | ✅ verified | keep CI grep |
| Package metadata + license | ❌ | add `Cargo.toml` metadata, `LICENSE`, `README` badge |
| CI matrix + `cargo audit` + fuzz job | ❌ | expand workflow |
| External security review | ❌ | `docs/AUDIT-PROMPT.md` exists; needs refreshing + a reviewer |

**Recommendation:** ship **v0.98 as a pre-release library** (crates.io + GitHub tag `v0.98.0`, `pre-release`
marker) for closed-beta integrators. Gate **v1.0** on the NTF command round-trip, pinning enforcement with
a MITM negative test, and package/CI hygiene.

---

## 6. How to reproduce this audit

```bash
cd ~/Projects/simplex-rs
export PATH="$HOME/build/bin:$PATH" CARGO_HOME="$HOME/build/rust/cargo"

cargo test --offline -- --test-threads=1                     # 83 passed
SMP_STRICT=1 cargo test --offline --test strict_e2e --test ntf --test proxy   # 3 passed
cargo clippy --offline --all-targets                         # 0 warnings
cargo clippy --offline --features v71-probes --all-targets   # 0 warnings
./scripts/live_interop.sh                                    # SMP v17..v23 + XFTP v4

# NTF handshake probe (diagnostics, openssl backend, NoVerify)
cargo build --offline --features v71-probes --bin ntf-probe
"$HOME/build/cache/cargo-target/simplex-rs/debug/ntf-probe" ntf2.simplex.im 443
NTF_BAD_HASH=1 "$HOME/build/cache/cargo-target/simplex-rs/debug/ntf-probe" ntf2.simplex.im 443   # negative control
```

No credentials, tokens or private keys are required or stored anywhere in this repository.
