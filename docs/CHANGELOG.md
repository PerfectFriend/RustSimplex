# Changelog

All notable changes to `smp-rs` are recorded here. The release workflow appends a section per
tag on push (`git tag vX.Y.Z` → GitHub Actions → crates.io publish + GitHub release).

## Unreleased

Work in progress toward v1.0. See `docs/RELEASE-READINESS.md` for the readiness audit and the
remaining gates.

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
