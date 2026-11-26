# Changelog

All notable changes to `smp-rs` are recorded here. The release workflow appends a section per
tag on push (`git tag vX.Y.Z` → GitHub Actions → crates.io publish + GitHub release).

## Unreleased

Work in progress toward v1.0. See `docs/RELEASE-READINESS.md` for the readiness audit and the
remaining gates.

- audit #3 remediation (Sprints A/B/C, 2026-11-25): fail-closed E2E decode (U-01), RFWD fixed-array
  try_into (U-02), SKEY by snd_id with mandatory signature + KEY sets rcv_auth (U-04), persist
  revision+mutex race fix (U-05), fail-closed store update (U-06), x25519_dh_checked everywhere
  (U-07), mandatory KEM ct on DH ratchet (U-08), NoVerify behind v71-probes (U-09), full SSRF
  range guard incl. IPv4-mapped v6 (U-10), strict mode fails closed (U-11), ACK-after-decrypt and
  no message loss in chat (U-12), conn cap + handshake timeout + store/XFTP quotas (U-13/U-19),
  parser checked_add + SOCKS5 field lengths + debug-dump feature gate (U-20/U-20b), XFTP download
  verify-before-rename with 0o600 tmp (U-17), reconnect re-SUB via send_only (U-18), TLS refuse
  empty session binding (U-16), proxy/onion TLS+pinning (U-15), FFI pinned TLS + real msg_id
  (U-03/U-21), CI hygiene+MSRV jobs, CHANGELOG dedup, portable scripts.

## v0.99.1 — library release candidate

- **NTF client made reachable from library code**: `NtfClient` (`connect` with a mandatory
  CA-fingerprint pin that fails closed before any I/O, `request`/`request_with_corr`, `ping`),
  the full NTF command/response tag set, and the transmission/batch framing helpers.
  Live-verified through the public API against `ntf2.simplex.im:443`: `PING→PONG` (NTF v3).
- **NTF pinning enforced**: the probe aborts with exit code 3 before sending anything when the
  served CA fingerprint does not match the expected one; a corrupted keyHash is rejected by the
  server (negative control).
- **XFTP probe pinning fixed**: `xftp-h2-v71` now requires an expected CA fingerprint and refuses
  to continue when the served chain does not match. Live-verified full cycle against
  `xftp1.simplex.im:443`: `PING→PONG / FNEW→SIDS / FPUT→OK / FGET→FILE (byte-exact) / FDEL→OK`.
- **crates.io packaging**: description, readme, repository, keywords, categories, MSRV 1.87 and
  an `exclude` list for the vendored Haskell reference. `cargo package` verified.
- **CI matrix**: `default / v71-probes / ffi`, plus `no-default-features`, the strict transport
  suite, a blocking `rustsec/audit-check`, the seeded mutation fuzz harness and a
  `cargo package` dry-run with a content assertion.

## v0.98

- SMP v17..v23 full round-trip live against the public relay
  (`PING→PONG, NEW→IDS, SUB→SOK, SEND→MSG(decrypt), ACK→OK, DEL→OK`).
- XFTP v4 live full cycle against `xftp1.simplex.im`.
- NTF transport handshake accepted live (the command layer came later, in v0.99.1).

## v0.97

- Release-readiness audit, security documentation and the external-auditor prompt
  (`docs/RELEASE-READINESS.md`, `docs/SECURITY.md`, `docs/AUDIT-PROMPT.md`).

## v0.99.3

- fix(tests): remove hardcoded /home/thomas scratch path from the test suite (bbba0ab)
- release: v0.99.3 — X448 security fix (RUSTSEC-2026-0387) + CI pipeline repair (41d1025)
- fix(security): replace cx448 with RustCrypto x448 — clears RUSTSEC-2026-0387 (96d8f96)
- docs: readiness revision 12 — v0.99.2 published with trilingual README (a85dda5)

- fix(release): keep the working tree clean for cargo publish (0c2d729)
