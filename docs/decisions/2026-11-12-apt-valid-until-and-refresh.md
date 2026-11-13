# apt `Valid-Until`, and a weekly re-sign in a second environment

Date: 2026-11-12. Status: proposed by the implementer of release rework B; the owner accepts it by
creating the `package-refresh` environment (docs/releases/packaging.md, "Keeping apt fresh").

## Problem

The apt `Release` had a fixed `Date` and no `Valid-Until`, so a client could not tell a signed
`InRelease` from an old, replayed or frozen one. Adding `Valid-Until` makes the metadata expire,
and an expiring `InRelease` needs re-signing before it does, long before the next release.

## Decision

1. `Release` carries `Date` = the signing time and `Valid-Until` = Date + 21 days
   (`constants.apt_valid_seconds`). The time is the build option `-Dsigned-at=<unix seconds>`;
   the same input gives the same bytes. A build without it keeps the fixed 1980 `Date` and no
   `Valid-Until` (the test key and the demos). rpm `repomd.xml` is unchanged: dnf has no
   comparable expiry field, and its `revision` stays fixed.
2. `zig build packages-redate` rewrites only those two lines of an existing tree, so the weekly
   job re-dates a published release's metadata without rebuilding a package.
3. `.github/workflows/package-refresh.yml` runs weekly (Monday 05:17 UTC) and on dispatch, in a
   new environment `package-refresh`: main only, no reviewer, holding `ZIGBOX_SIGNING_KEY`,
   `ZIGBOX_SIGNING_PASSPHRASE` and the release App's credentials. It re-signs, uploads with
   `--clobber`, dispatches the zigbox.org deploy and waits, and fails unless the served
   `InRelease` is valid for at least ten more days.

## What it trades

The `release` environment makes the owner approve every use of the signing subkey. The refresh
environment has no approver, so anyone who can merge to `main` can change the workflow that
holds the subkey, and a compromised workflow could sign anything the subkey can. This is a
weaker gate than one approval per signing, bought for freshness: three weeks without a release
must not make `apt update` fail for every user.

What bounds the loss:

- The subkey is the same one `release` uses. It signs metadata; the primary stays offline, and
  a leaked subkey is revoked and replaced with the primary as before.
- The refresh script re-signs only an archive whose existing `Release` was signed by a subkey
  of the pinned primary, and whose listed files match its sums; the packages inside carry their
  own signatures from the release (rpm) or are covered by the `Release` sums (deb). It builds
  and takes no code from the release; the script and the Zig tool run from `main`.
- A malicious `main` can sign a `Release` over other packages, but it could also change
  `release.yml` and wait for the next release approval, so the added exposure is timing (no
  approval step), not a new capability.
- Environment protection: deployment branch policy `main` only, and the branch ruleset that
  guards `main`.

If the owner judges that unsafe, the alternative is a longer `Valid-Until` (for example 90 days,
a build constant) refreshed by the `release` environment's manual runs only. The implementer
judged the added exposure acceptable and built it; this file records the choice so it can be
reversed by deleting the workflow and the environment.

## Consequences

- The refresh signs again only what the owner's current key already signed (review of #129): old
  signatures are checked against the public part of `ZIGBOX_SIGNING_KEY`, never the archive's
  keyring; the signed `SHA256SUMS` must list the archive; the packages must be the tag's version;
  the archive must not be older than the served `InRelease`; a revoked or expired key is refused.
  A release without a signed `SHA256SUMS`, and an archive signed by a subkey the owner has since
  replaced, are refused until a new release is cut (packaging.md, "Keeping apt fresh").

- `zigbox-repos.tar.gz`, `SHA256SUMS` and `SHA256SUMS.asc` are replaced weekly; the archive's hash changes each time, so a user who pinned the first hash
  must use `SHA256SUMS` from the current release.
- The first refresh of a release is the first time its `Release` has a `Valid-Until`; releases
  signed before this change keep the old `Release` until then.
- `-Dsigned-at` must be the same in all of `release-sign.sh`'s `packages` runs (wiring below in
  packaging.md).
