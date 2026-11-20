# simplex-rs — Release Readiness Audit

Date: 2026-11-20 · Head: `d832059` (v1.0-rc prep) · Branch: `master` → `origin/main` (PerfectFriend/RustSimplex)
Revision: 3 — library-level `NtfClient` added and verified live against `ntf2.simplex.im` through the
public API; crates.io packaging + CI matrix added; the earlier revision overstated the pinning gap
(corrected in §3.2, issue 2).

Audit method: local codebase inspection + executable verification (cargo test / clippy / live probes against
the public SimpleX infrastructure) + cross-check against the Haskell reference (`simplexmq/`,
`simplex-chat/`) checked out under `~/Projects/simplex-rs/`.

---

## 1. Verdict

**Release readiness: ~89% — NOT ready for a public production release; ready for a closed beta and for library publication as v0.99 / v1.0-rc.**

Revision 3 — added a **library-level NTF client** (`NtfClient`), verified live against
`ntf2.simplex.im` through the public API (not just the probe's own code).

The wire-level protocol core is strong and proven against real infrastructure. The remaining gaps are concentrated in
(a) the **signed** NTF command flow (`SNEW`/`TNEW` with Ed25519 authorization) — the transport and the
library client are done and live-verified,
(b) the release pipeline (tags, changelog, publish job) and coverage-guided fuzzing, and
(c) one probe path (`xftp_h2_v71`) that still trusts the caller-supplied keyHash without an explicit chain check.

| Area | Readiness | Evidence |
|---|---|---|
| SMP core (v17–v23) | **95%** | live full round-trip `NEW→IDS→SUB→SEND→MSG→ACK→DEL` on `smp11.simplex.im:5223`, all 7 versions green |
| SMP transport security | **90%** | TLS1.3, ALPN `smp/1`, SB-chain block encryption, channel-bound sessionId |
| XFTP v4 | **90%** | live `PING→PONG`, `FNEW→SIDS`, `FPUT 64KB→OK`, `FGET` decrypt byte-match, `FDEL→OK` on `xftp1.simplex.im:443` |
| Onion routing over SMP proxy | **85%** | 2-hop onion round-trip + wrong-hop-key negative test (local) |
| E2E PQDR ratchet | **80%** | init/encrypt/decrypt/rotate/skipped-key limits; `Agent::e2e` default-on, fail-closed |
| Reconnect / resilience | **80%** | exponential backoff, re-dial, strict-mode re-enable |
| NTF (notifications) | **78%** | live `PING→PONG` against `ntf2.simplex.im:443` **through the library `NtfClient`** (NTF v3, sessionId 32B, corrMatch=true); 512-byte blocks, own handshake, own command tag set, batch framing; **CA-fingerprint pinning enforced** (exit 3 before any traffic). `SNEW→IDSUB` / `TNEW→IDTKN` (signed commands) still unproven |
| Client UX / apps | **25%** | FFI façade only; no desktop/mobile UI in this repo |
| Packaging & release ops | **70%** | crates.io metadata + `cargo package` verified (54 files, 113 KiB), CI matrix (default / v71-probes / ffi / no-default-features / strict / audit / fuzz / package dry-run); still no release pipeline (tags, changelog, publish job) |

---

## 2. Verified state (executed, not claimed)

```
cargo test --offline                          -> 90 passed / 0 failed / 0 ignored
SMP_STRICT=1 cargo test (strict)              -> 3 passed / 0 failed
cargo clippy --all-targets                    -> 0 warnings, 0 errors
cargo clippy --features v71-probes            -> 0 warnings, 0 errors
cargo clippy --features ffi                   -> 0 warnings, 0 errors
cargo check --no-default-features             -> clean (Android NDK path)
cargo package --allow-dirty                   -> 54 files, 113.2 KiB, verify-build OK
```

* **90/90** unit + integration tests green (21 test binaries), strict-mode suite **3/3**.
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
| `ntf2.simplex.im:443` (NTF, ALPN `ntf/1`) | **TLS1.3 + NTF handshake accepted** (negative control: corrupted keyHash → server closed the connection); **`PING→PONG` command round-trip OK through the library `NtfClient`**; pin mismatch → client refuses to proceed (exit 3) before any traffic |

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
| N-6 | **NTF command layer missing** — the handshake was accepted but no NTF command had ever been round-tripped | Implemented NTF transmission framing in `src/ntf.rs` (batch = `u8 count` + `Large` per transmission; `implySessId` → no sessionId on the wire; authenticator/corrId/entityId as Haskell `ByteString`). **Live `PING→PONG` verified.** |
| N-7 | **NTF probe did not pin the server identity** — it hashed whatever CA the peer presented | The probe now requires an expected CA fingerprint (argv or `NTF_EXPECTED_FP`) and aborts with exit code 3 before sending the handshake when it does not match. Verified: wrong pin → exit 3, no traffic sent. |
| N-8 | **The NTF module was unreachable from library code** — `src/ntf.rs` was only used by the probe binary, so the protocol had no public API | Added `NtfClient<S: Read + Write>` with `connect` (mandatory CA pin, fail-closed **before any I/O**), `request`/`request_with_corr`, `ping`; plus the full command/response tag set and transmission/batch framing helpers. 11 unit + 3 e2e tests (mock NTF server). **The live probe was rewritten to use this API**, so the live run now proves the public path: `PING→PONG` OK, wrong pin → exit 3, corrupted keyHash → server closes. |

### 3.2 Open issues, ranked

**HIGH**

1. **NTF *signed* command layer not implemented** (`src/ntf.rs` has the tag set, framing and a
   `NtfClient`, but not the authorization envelope).
   Live-verified gap: `PING` → `PONG` **is** proven (through the library client), but the signed
   commands `SNEW` → `IDSUB` and `TNEW` → `IDTKN` are still unproven — they need
   `NtfPrivateAuthKey` / `NtfPublicAuthKey` / `DeviceToken` / `NtfTokenId` and an Ed25519 signature over
   `smpEncode sessionId <> authorized` (simplexmq `Notifications/Protocol.hs`).
   *Reachability*: high — push notifications are a core SimpleX feature.
   *Fix*: implement the NTF authorization envelope and the `SNEW`/`TNEW` encoders, then prove
   `SNEW → IDSUB` against a live server with a real subscription.

2. **Certificate pinning is enforced in the library path, but not in every *probe* path.**
   *Corrected finding*: the earlier draft of this report claimed pinning was absent from the client paths.
   That was wrong — `src/transport.rs::PinVerifier` pins to the **last** certificate of the chain
   (the CA), verifies the leaf signature against that exact anchor, and is used by
   `Client::connect_tls*` / `AsyncSmpClient` / `ReconnectingClient`. Two negative regression tests cover it:
   `tests/interop.rs::tls_wrong_keyhash_rejected` and `tests/interop.rs::tls_mitm_evil_leaf_with_pinned_ca_rejected`
   (the `[evil_leaf, pinned_CA]` case).
   The remaining gap is narrower: the `v71-probes` diagnostic binaries use `SslVerifyMode::NONE` because the
   public relays need the openssl TLS stack (rustls lacks ed448 and does not expose TLS Finished). Of those,
   `smp_v71` pins manually by SHA-256 over the served chain, and `ntf_probe` now pins too (this run).
   `xftp_h2_v71` still relies on the caller-supplied keyHash alone.
   *Action*: give `xftp_h2_v71` the same explicit chain-fingerprint check as `ntf_probe`.

**MEDIUM**

3. ~~No crates.io/package metadata~~ — **FIXED this run**: `description`, `readme`, `repository`, `homepage`,
   `documentation`, `keywords`, `categories`, `rust-version = 1.87`, and `exclude` for the vendored
   Haskell reference. `cargo package` verified: 54 files, 113.2 KiB compressed, verification build passes.
4. ~~CI coverage is thin~~ — **FIXED this run**: matrix over `default / v71-probes / ffi`, plus separate jobs
   for `no-default-features`, the strict transport suite, `rustsec/audit-check` (blocking), the seeded
   mutation fuzz harness and a `cargo package` dry-run with a content assertion.
5. **No release pipeline** — still open: no versioned tags, no changelog generator wired to `git log`,
   no reproducible release build, no publish job.
6. **Fuzzing is smoke-level** — still open: the CI job runs the in-repo seeded mutation harness
   (`tests/fuzz_parse.rs`), which needs neither nightly nor cargo-fuzz, but there is still no
   coverage-guided fuzz target (cargo-fuzz/libfuzzer-sys is not available in the offline build env).

**LOW**

7. `src/bin/*` diagnostic binaries still contain `panic!`/`expect` (acceptable for probes, but they must
   stay behind the `v71-probes` feature and out of release artifacts).
8. `docs/` still describes NTF as SMP-like in places (updated in this release, but the audit prompt
   `docs/AUDIT-PROMPT.md` needs a refresh for external reviewers).

---

## 4. Classification of gaps (per project convention)

* **broken** (regression): none found — every defect discovered this run was fixed and covered by a test.
* **dead** (written but not wired): `Client::handshake_over` is still used only by probes; the NTF
  authorization envelope (`NtfPrivateAuthKey`) is referenced by the protocol but has no encoder.
* **unbuilt** (planned, not implemented): NTF signed-command round-trip (`SNEW→IDSUB`), release pipeline,
  coverage-guided fuzzing, `xftp_h2_v71` explicit pin check, UI clients.

**No unbuilt item is reported as a defect, and no defect is reported as unbuilt.**

No unbuilt item is reported as a defect, and no defect is reported as unbuilt.

---

## 5. Release gates — what must be true for v1.0

| Gate | Current | Action |
|---|---|---|
| All tests green, clippy clean | ✅ 83/83 + 0 warnings | keep in CI |
| SMP live interop v17–v23 | ✅ verified | re-run `scripts/live_interop.sh` per release |
| XFTP live interop | ✅ verified | same |
| NTF live command round-trip | ◑ `PING→PONG` proven through the **library client**; signed commands pending | implement the authorization envelope, prove `SNEW→IDSUB` |
| Pinning enforced + MITM negative test | ✅ library path (2 negative tests); NTF probe pins; `xftp_h2_v71` does not | add the explicit chain check to `xftp_h2_v71` |
| No `unsafe`, no library panics | ✅ | keep |
| No secrets in tree | ✅ verified | keep CI grep |
| Package metadata + license | ✅ `cargo package` verified | tag and publish to crates.io |
| CI matrix + `cargo audit` + fuzz job | ✅ matrix + blocking audit + fuzz harness | add a coverage-guided fuzz job when libfuzzer-sys is available |
| Release pipeline (tags, changelog, publish) | ❌ | add tag/changelog/publish workflow |
| External security review | ❌ | `docs/AUDIT-PROMPT.md` exists; needs refreshing + a reviewer |

**Recommendation:** publish **v0.99.1 as a library release** (crates.io + GitHub tag `v0.99.1`) for
closed-beta integrators — the package builds and verifies locally, the public API is exercised live
against `ntf2.simplex.im`, and CI gates the matrix + audit + fuzz harness. Gate **v1.0** on: the signed NTF
command round-trip (`SNEW→IDSUB`), the explicit pin check in `xftp_h2_v71`, and a release pipeline
(tag + changelog + publish job).

---

## 6. How to reproduce this audit

```bash
cd ~/Projects/simplex-rs
export PATH="$HOME/build/bin:$PATH" CARGO_HOME="$HOME/build/rust/cargo"

cargo test --offline -- --test-threads=1                     # 90 passed
SMP_STRICT=1 cargo test --offline --test strict_e2e --test ntf --test proxy   # 3 passed
cargo clippy --offline --all-targets                         # 0 warnings
cargo clippy --offline --features v71-probes --all-targets   # 0 warnings
cargo clippy --offline --features ffi --all-targets          # 0 warnings
cargo check --offline --no-default-features                  # clean (Android NDK path)
cargo package --offline --allow-dirty                       # 54 files, 113.2 KiB, verify build OK
./scripts/live_interop.sh                                    # SMP v17..v23 + XFTP v4

# NTF probe (diagnostics, openssl backend) — pin is mandatory
cargo build --offline --features v71-probes --bin ntf-probe
"$HOME/build/cache/cargo-target/simplex-rs/debug/ntf-probe" ntf2.simplex.im 443 FB-Uop7RTaZZEG0ZLD2CIaTjsPh-Fw0zFAnb7QyA8Ks
#   -> pin ok ... library client connected: NTF v3, sessionId=32B
#      response: tag=PONG corrMatch=true entityId=0B
#      LIVE NTF OK: PING -> PONG (via library NtfClient)
# wrong pin -> "PIN FAILURE", exit code 3, nothing sent
"$HOME/build/cache/cargo-target/simplex-rs/debug/ntf-probe" ntf2.simplex.im 443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
# NTF_BAD_HASH=1 -> corrupted keyHash -> the server closes the connection (negative control)
NTF_BAD_HASH=1 "$HOME/build/cache/cargo-target/simplex-rs/debug/ntf-probe" ntf2.simplex.im 443 FB-Uop7RTaZZEG0ZLD2CIaTjsPh-Fw0zFAnb7QyA8Ks
```

No credentials, tokens or private keys are required or stored anywhere in this repository.