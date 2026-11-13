# Packaging a release: the release workflow

`zig build packages` writes the `zigbox` deb and rpm for x86_64 and aarch64 and the apt and dnf
repository trees around them under `zig-out/packages/`. It never runs `gpg` and never holds the
release key. Signing is the release workflow's job
([decision](../decisions/2026-11-11-ci-signs-packages-with-a-subkey.md)): it runs `gpg` with a
signing subkey that is a secret of the GitHub environment `release`, and the primary key stays
offline. The output is reproducible: the same inputs give the same bytes.

Inputs are the release `zbx` binaries (`zig build release`), `build.zig.zon`'s version and
`LICENSE`; the step wires them itself.

## The owner's part

Once, set up the key (next section). For each release: cut the tag from a gated commit (see
AGENTS.md, "Releases"), create the GitHub release for it, and approve the `release` run of
`.github/workflows/release.yml`. The workflow does the rest and attaches `zigbox-repos.tar.gz` to
the release. 0.4.0 gets no archive ([decision](../decisions/2026-11-11-no-package-archive-for-0.4.0.md)).

The workflow runs on a push of a `v*` tag, and on `workflow_dispatch` with a `tag` input to sign
an existing release again. Start a manual run from the tag itself (Run workflow, "Use workflow
from": the tag): the `release` environment only deploys tags, and the run refuses a `tag` input
that is not the ref it started from, or is not `vX.Y.Z` (a pre-release suffix such as `-rc.1` is accepted, and signs as usual). The run fails before signing when the
GitHub release does not exist yet; create it and re-run.

Before approving a `release` run, open the run and check that its commit is the release-gated
commit on `main` (the tag points at it, and `release.yml` and `release-sign.sh` are as reviewed):
the workflow and script that run are the ones at the tag, so an approval hands the key to
whatever that commit holds. Set up, once, on the repository: a tag ruleset that restricts who can
create `v*` tags, and on the `release` environment "Prevent self-review", the two secrets as
environment secrets (not repository secrets) and a deployment policy that admits tags only.

## The release key

Users verify the keyring against the primary key's fingerprint (RSA 4096, certify-only primary;
the signing subkey expires after a year and is renewed):

```
09991DC39816D3C914E2A22C5AB00BC328B7DBB7
```

## One-off key setup

Use a machine you trust; `$KEY` is the primary key's fingerprint. Quote the subkey as
`"$SUBKEY"'!'`: a `!` inside double quotes is history expansion in zsh. The key already exists;
these commands are the record of how it was made and how to renew it.

```sh
# A certify-only RSA 4096 primary key, no expiry: it only certifies subkeys.
gpg --quick-generate-key "Zigbox releases <releases@zigbox.org>" rsa4096 cert never
KEY=$(gpg --list-keys --with-colons "Zigbox releases" | awk -F: '$1 == "fpr" { print $10; exit }')

# The signing subkey, valid one year.
gpg --quick-add-key "$KEY" rsa4096 sign 1y
SUBKEY=$(gpg --list-keys --with-colons "$KEY" | awk -F: '$1 == "sub" { s = 1; next } $1 == "fpr" && s { print $10; exit }')

# Offline backup of the whole secret key and a revocation certificate, straight onto media kept offline (never the setup machine's disk).
gpg --armor --export-secret-keys "$KEY" > /media/OFFLINE/zigbox-primary-backup.asc
gpg --gen-revoke "$KEY" > /media/OFFLINE/zigbox-revoke.asc
```

Later, `gpg --edit-key "$KEY"`, `key 0`, `keytocard` moves the primary onto a YubiKey. Store the
backup before that, as `keytocard` replaces the key on disk with a stub.

Give the `release` environment its two secrets (the environment, with owner approval and a
tag-only deployment policy, already exists). The subkey export contains the subkey's secret part
only, with the primary stubbed, and stays protected by its passphrase:

```sh
gpg --armor --export-secret-subkeys "$SUBKEY"'!' |
  gh secret set ZIGBOX_SIGNING_KEY --env release --repo Zigbox/zigbox
gh secret set ZIGBOX_SIGNING_PASSPHRASE --env release --repo Zigbox/zigbox
```

The primary key's fingerprint is not a setting: it is written in `release.yml` (the `Sign` step),
in reviewed code, and the workflow fails unless every signature is by one of its subkeys. A new
primary key is a reviewed change to that file and to the fingerprint above. Publish the primary's public key
(`gpg --armor --export "$KEY"`) wherever users look for it; each release's archive also carries
the current public key as `zigbox-archive-keyring.asc` and `.gpg`.

### Yearly renewal

The subkey expires after one year, and a signature made after that is refused by the workflow
(it takes no expired subkey). Before it does, with the primary key:

```sh
gpg --quick-set-expire "$KEY" 1y "$SUBKEY"     # extend, or add a new subkey as above
gpg --armor --export-secret-subkeys "${NEWSUBKEY:-$SUBKEY}"'!' |
  gh secret set ZIGBOX_SIGNING_KEY --env release --repo Zigbox/zigbox
```

Renewal does **not** reach existing installs by itself. Users fetched the keyring once
(`curl` into `/usr/share/keyrings/zigbox.gpg`) and nothing updates that file, so apt on every
installed machine keeps the old expiry date and `apt update` fails with `EXPKEYSIG` the day the
original expiry passes, even when the owner renewed in time. dnf reads the `.repo` file's
`gpgkey=` URL when it first imports the key and then uses rpm's stored copy, with the old expiry,
so a renewal is not picked up there either (a rpm that enforces key expiry refuses it). So each renewal is
also a user action, and the owner:

- renews at least 28 days before the expiry (the refresh refuses a closer key anyway), so users
  have the weeks before the old expiry to act;
- puts the "re-fetch the keyring" notice in the release notes of the first release after the
  renewal and in the announcement (template below), and keeps it in the next release's notes too;
- checks that `https://zigbox.org/zigbox-archive-keyring.gpg` carries the new expiry.

Users re-fetch with the install command (`curl ... | sudo tee /usr/share/keyrings/zigbox.gpg`);
for dnf, `sudo rpm --import https://zigbox.org/zigbox-archive-keyring.asc`. A
`zigbox-archive-keyring` package that updates the file through `apt upgrade` is the lasting fix and
is a follow-up
([decision](../decisions/2026-11-13-keyring-renewal-needs-refetch.md)).

Release-notes line for the first release after a renewal:

> The signing subkey was renewed. Fetch the keyring again before `YYYY-MM-DD` (the old expiry), or
> `apt update` and `dnf` will refuse the repository: see "Renewing the keyring" in the install guide.

If the subkey leaks, revoke it with the primary key and set a new one the same way.

## What the workflow runs

`.github/release-sign.sh` (the whole signing logic; the `test` job runs the same file):

1. Imports `ZIGBOX_SIGNING_KEY` from stdin into a throwaway `GNUPGHOME` (`mktemp`, mode 0700,
   removed on exit, also on failure). The passphrase is a 0600 file in that home, used with
   `--pinentry-mode loopback --passphrase-file`. Neither is printed, written to the workspace or
   passed as an argument, and there is no `set -x`.
2. Checks the key's primary fingerprint is `ZIGBOX_SIGNING_FPR` (set by the workflow to the
   pinned value), that the primary and the signing subkey are RSA 4096 and neither expires within
   28 days of the signing time (the rule and messages of the weekly refresh), and picks the one
   subkey.
3. Round 1: `zig build packages` writes unsigned rpms and `zig-out/packages/to-sign/<rpm>.header`;
   each header gets a binary detached signature, `<rpm file>.header.sig`, in a fresh directory.
   Each is tied to the header it signs (its 16 digest bits and its issuer fingerprint), so a
   swapped or missing `.header.sig` is refused. RSA (including 4096-bit) and Ed25519 are read; a
   signature may be up to 1024 bytes (`docs/decisions/2026-11-08-openpgp-signature-bound.md`).
4. Round 2: `zig build packages -Dsignatures=DIR` embeds them and rewrites the trees (the rpm
   digests now cover the signed files). Then `InRelease` (clearsigned `Release`), `Release.gpg`
   and both `repomd.<arch>.xml.asc` are signed.
5. A final `zig build packages -Dsigned-at=N -Dsignatures=DIR` places them, and `zig build
   packages-check -Dsigned-at=N -Dsignatures=DIR` (the same `N` as every other run) reads the tree back: every file against the metadata that names it, every
   signature file against the file beside it, all by one key. That check compares the 16 digest
   bits, so it catches a swapped or stale file and not a forged one; the next step verifies.
6. Exports the public keyring as `zigbox-archive-keyring.asc` and `.gpg`, then, in a home that
   holds only that public key, runs `gpg --verify` on `Release.gpg`, `InRelease` and both
   `repomd.xml.asc`, and `rpm -Kv` on both rpms (the key imported with `rpmkeys` into a
   throwaway database). It fails unless each signature is good and by a subkey, not the primary,
   of `ZIGBOX_SIGNING_FPR`.
7. Writes `zigbox-repos.tar.gz`: `apt`, `rpm` and the two keyring files, and nothing else (not
   `to-sign/`, not the test key files).

The `sign` job then attaches the archive to the release. The release has no other assets from the
workflow: the release binaries are not attached by it.

Each `zig build packages` run deletes `apt/`, `rpm/` and `to-sign/` under the output directory
first, so the files of an earlier run never stay beside this one's.

### Dispatching the site deploy

The site's deploy (`.github/workflows/deploy.yml` in `Zigbox/zigbox.github.io`, every six hours or
on `workflow_dispatch`) copies the newest release's asset to `https://zigbox.org/apt`, `/rpm` and
the two keyring files byte for byte
([decision](../decisions/2026-11-10-packages-on-zigbox-org.md)). It refuses an asset that holds
anything else (links, dot files, `.html`, `to-sign/`, the test key) or lacks `InRelease`,
`Release.gpg` or a `repomd.xml.asc`, and after deploying it fetches every file back and fails
unless zigbox.org serves the same bytes.

The refresh workflow sends it `repository_dispatch` of type `site` with the release App's token
(`GITHUB_TOKEN` cannot write to `Zigbox/zigbox.github.io`). Check a client with `apt update` and
`dnf makecache` against zigbox.org.

## Release assets

`zig build release-assets` writes, under `zig-out/release-assets/`, what a release carries besides
the signed packages. All of it is reproducible (fixed mtime, owner and order; gzip with no time):

- `zbx-<v>-linux-x86_64.tar.gz` and `zbx-<v>-linux-aarch64.tar.gz`: the static ReleaseSafe `zbx`,
  `LICENSE` and a short `README.txt`.
- `zbx-<v>.cdx.json`: a CycloneDX 1.5 SBOM (version, licence, purl `pkg:github/zigbox/zigbox@v<v>`,
  the SHA-256 of each binary, the Zig toolchain version, and the statement that there are no
  third-party components).
- With `-Dpackages-dir=zig-out/packages` (the tree `release-sign.sh` signed), the debs and rpms,
  and with `-Drepos-archive=FILE` the `zigbox-repos.tar.gz`; `-Dno-packages` writes the rest
  without them. `-Dsource-date-epoch=N` sets the timestamps.
- `SHA256SUMS`, in `sha256sum -c` format, over every asset the directory holds.

The Mac zip is built later, in another job. Put it in the directory and run
`zig build release-sums -Dassets-dir=DIR` (not `release-assets`, which clears the directory) to
write `SHA256SUMS` over everything the directory holds again, or add `-Dsums-name=SHA256SUMS.macos`
to write a separate file and leave the signed one alone. Sign `SHA256SUMS` after this last step.

`SHA256SUMS` is meant to be signed: a detached `SHA256SUMS.asc` by the release subkey, made after
every asset is in the directory. In `release-sign.sh` that is one line beside the others:
`sign_with -ab -o "$output/SHA256SUMS.asc" "$output/SHA256SUMS"`, checked with `check_gpg`.
`package-refresh.sh` re-signs `SHA256SUMS` itself because the archive's line changes, and only after checking the old signature.

## Keeping apt fresh

`Release` carries `Date` = the signing time and `Valid-Until` = Date + 21 days when the build is
given `-Dsigned-at=<unix seconds>`; `release-sign.sh` must pass the same value to all three of its
`zig build packages` runs, or the files it signs are not the files it places. Without the option
(the test key, demos) `Date` is fixed and there is no `Valid-Until`. rpm `repomd.xml` is not
changed: dnf has no expiry to set.

`zig build packages-redate -Dsigned-at=N -Dpackages-dir=DIR` rewrites only `Release`'s two lines in
an existing tree and deletes the `InRelease` and `Release.gpg` that no longer match.
`packages-check` fails when `Valid-Until` is not Date + 21 days.

`.github/workflows/package-refresh.yml` runs `.github/package-refresh.sh` weekly (Monday 05:17 UTC)
and on dispatch, in the environment `package-refresh`
([decision](../decisions/2026-11-12-apt-valid-until-and-refresh.md)). It signs again only what the
owner's key already signed and published. It takes the newest release's `zigbox-repos.tar.gz`,
`SHA256SUMS` and `SHA256SUMS.asc`, and the `InRelease` zigbox.org serves now, and refuses (one
line, nothing signed) unless all of these hold:

- The key is the pinned primary's one signing subkey, not revoked and not expired at the signing
  time, and the primary is not revoked or expired. Both must also stay valid for 28 days after the
  signing time: `Valid-Until` is 21 days after it, and the 7 days after that are the owner's
  margin to renew. A signature by a key that has expired fails in apt however much of
  `Valid-Until` is left, so a key that expires within 28 days is refused with a line asking the
  owner to renew it. A weekly run therefore always leaves time to renew before the key lapses.
- Every old signature (`Release.gpg`, `InRelease`, `SHA256SUMS.asc`, the served `InRelease`) is by
  that subkey, checked against the public part of `ZIGBOX_SIGNING_KEY`. The keyring inside the
  archive is never trusted, so a revoked subkey's signature is refused even when the archive ships a
  keyring without the revocation. After the subkey is replaced, the old archive no longer verifies:
  cut a release (or re-run `release-sign.sh` for the tag) before the next refresh.
- The archive's hash is the line in the signed `SHA256SUMS`, checked before the archive is listed
  or extracted. Every file the `Release` lists matches its sum, and the packages in it are the
  tag's version.
- The archive's `Release` is not older than the served `InRelease` (its `Date` is read from the
  text gpg verified, never from bytes outside the signed block), and the new `Date` is later than
  the archive's own. A release without a signed `SHA256SUMS` is refused: it has nothing to bind the
  archive to.

It then re-dates, signs `InRelease` and `Release.gpg`, verifies them, signs the new `SHA256SUMS`, and
saves the archive and both sums files as the workflow artifact `package-refresh-<tag>` (30 days),
then uploads them with `--clobber`, one file at a time, trying up to three times. It then
dispatches the zigbox.org deploy, waits for it, and fails unless the served `InRelease` is valid for
at least ten more days. Any failure fails the run; GitHub's notification of a failed scheduled run is
the alarm, and a failed week leaves 14 days before expiry. `.github/package-refresh-test.sh` runs the
refresh and each refusal with a throwaway key in the release workflow's `test` job.

**Recovery from a half-finished upload.** `--clobber` can leave the release with a mix (the new
archive and the old sums, or the new archive and sums and the old `SHA256SUMS.asc`); the refresh
refuses a mix, so dispatching the workflow again does not repair it, and "Re-run failed jobs" would
build a different tarball. Download the artifact `package-refresh-<tag>` of the failed run and
upload its three files again:

```sh
gh run download RUN_ID --repo Zigbox/zigbox -n package-refresh-vX.Y.Z --dir saved
gh release upload vX.Y.Z saved/zigbox-repos.tar.gz saved/SHA256SUMS saved/SHA256SUMS.asc \
  --clobber --repo Zigbox/zigbox
```

Then dispatch the workflow: the next refresh accepts the restored set (`package-refresh-test.sh`
reproduces both mixes and this recovery). If the artifact has expired, sign by hand in the
`release` environment (re-run `release-sign.sh` for the tag).

GitHub disables a scheduled workflow after 60 days without repository activity, silently. A quiet
project must check the Actions tab at least every 50 days and re-enable `package-refresh`; no run
means no alarm, and apt fails with "Release file is expired" 21 days after the last signing.

Owner setup, once: create the environment `package-refresh` on `Zigbox/zigbox` with no required
reviewer, a deployment branch policy of `main` only, and the secrets `ZIGBOX_SIGNING_KEY`,
`ZIGBOX_SIGNING_PASSPHRASE` and `RELEASE_APP_PRIVATE_KEY` plus the variable `RELEASE_APP_ID` (the
same subkey export and App as `release`):

```sh
gh api -X PUT repos/Zigbox/zigbox/environments/package-refresh \
  -F deployment_branch_policy[protected_branches]=false -F deployment_branch_policy[custom_branch_policies]=true
gh api -X POST repos/Zigbox/zigbox/environments/package-refresh/deployment-branch-policies -f name=main
gpg --armor --export-secret-subkeys "$SUBKEY"'!' |
  gh secret set ZIGBOX_SIGNING_KEY --env package-refresh --repo Zigbox/zigbox
gh secret set ZIGBOX_SIGNING_PASSPHRASE --env package-refresh --repo Zigbox/zigbox
gh secret set RELEASE_APP_PRIVATE_KEY --env package-refresh --repo Zigbox/zigbox
gh variable set RELEASE_APP_ID --env package-refresh --repo Zigbox/zigbox
```

Renew the subkey in this environment too (the yearly renewal section): an expired subkey makes the
refresh fail, loudly. Until the environment exists the workflow fails at the key import.

## Doing it by hand

Only to debug a release. With the subkey in your own keyring, `.github/release-sign.sh` is the
same procedure; `zig build packages` prints the `gpg` command for each file it needs signed
(rounds 1 and 2 above). `gpg --batch -o` will not overwrite a file, so use an empty signatures
directory every time.

## CI and the test keys

`-Dtest-key` signs everything with a fixed key that vouches for nothing, and writes its public key
as `zigbox-test-key.asc` and `zigbox-test-key.gpg` beside the trees. `zig build packages -Dtest-key`
then `zig build packages-check -Dtest-key` (which recomputes every signature; Ed25519 is
deterministic) is the whole pipeline without the owner. Never publish a tree made this way.

The release workflow's `test` job (pull requests that touch the release files, and pushes to
`release-test/*`) runs `.github/release-sign.sh` itself, with a throwaway RSA 4096 key made like
the release key (certify-only primary, one signing subkey, passphrase, subkey-only export). It
attaches and dispatches nothing and never uses the `release` environment. The fixed `-Dtest-key`
is an Ed25519 key inside the package tool that `gpg` cannot import, so it cannot exercise the
import and subkey checks.

## Known differences

- Fedora's rpm 6 refuses a signature from a key it has not imported: import the key first
  (`rpmkeys --import`), also for the test key.
- The dnf `primary.xml` has a fixed `<time file>` epoch (reproducibility), so it differs from
  `createrepo_c`'s output in that one attribute. `filelists` and `other` are byte-equal.
- The rpm carries no `PAYLOADDIGESTALT`.
