# SHA256SUMS is signed by `release-sign.sh`, the Mac sums are not

Date: 2026-11-13. Status: implemented in `claude/release-wiring`.

- `release-sign.sh` writes the release assets and signs `SHA256SUMS` itself, before it removes the
  key, rather than the workflow importing the key a second time. One import, one place that checks
  the key's shape and expiry, one verification path. The tool still runs only while the key is
  loaded, as it already did for `zig build packages`.
- One timestamp: `ZIGBOX_SIGNED_AT`, taken by the `linux` job after the owner's approval. It is
  the apt `Release` date, and the `-Dsource-date-epoch` of the tarballs and the SBOM. Taken in
  `linux`, not `plan`, so a long wait for approval does not use up `Valid-Until`.
- `SHA256SUMS` covers the Linux assets. The Mac zip is built in another job, which holds no gpg
  key, so it writes `SHA256SUMS.macos` with `release-sums` and leaves signing to Developer ID and
  notarization. `SHA256SUMS.macos` has no `.asc`.
- `prepare` verifies `SHA256SUMS.asc` with the keyring in the archive and fails unless the signing
  key is a subkey of the primary fingerprint pinned in `release.yml` (now a workflow-level `env`,
  used by `linux` and `prepare`).
