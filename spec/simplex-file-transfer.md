# SimpleX File Transfer Protocol (XFTP) — implementation notes

This file was a 404 stub; the authoritative protocol text lives in
`spec/simplex-messaging.md` (XFTP section) and in the Haskell reference clone
(`simplexmq/`, `Simplex.FileTransfer.*`). Implementation notes for `smp-rs`:

- FNEW declares `size` (padded length), sha256 `digest`, and a sender Ed25519 SPKI;
  the server binds a random `packet_id` (FID) to it. Quotas: per-file size,
  packet count, aggregate bytes, chunk size (see `MAX_XFTP_*` in `src/server.rs`).
- FPUT carries `offset` = **chunk index** (u32), not a byte offset, and a
  secretbox chunk; the chunk must be signed by the sender key.
- FGET returns FDATA chunks from `offset` on, packed into 16 KiB blocks.
- Download path (`src/xftp.rs::download_file_stream`) streams into a 0o600
  `.part` file, verifies size + sha256, then atomically renames; on any error
  the temp file is removed and the final path is never written (U-17).