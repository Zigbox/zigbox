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
that is not the ref it started from, or is not `vX.Y.Z`. The run fails before signing when the
GitHub release does not exist yet; create it and re-run.

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

# Offline backup of the whole secret key and a revocation certificate, onto media kept offline.
gpg --armor --export-secret-keys "$KEY" > zigbox-primary-backup.asc
gpg --gen-revoke "$KEY" > zigbox-revoke.asc
```

Later, `gpg --edit-key "$KEY"`, `key 0`, `keytocard` moves the primary onto a YubiKey. Store the
backup before that, as `keytocard` replaces the key on disk with a stub.

Give the `release` environment its three values (the environment, with owner approval and a
tag-only deployment policy, already exists). The subkey export contains the subkey's secret part
only, with the primary stubbed, and stays protected by its passphrase:

```sh
gpg --armor --export-secret-subkeys "$SUBKEY"'!' |
  gh secret set ZIGBOX_SIGNING_KEY --env release --repo Zigbox/zigbox
gh secret set ZIGBOX_SIGNING_PASSPHRASE --env release --repo Zigbox/zigbox
gh variable set ZIGBOX_SIGNING_FPR --env release --repo Zigbox/zigbox --body "$KEY"
```

`ZIGBOX_SIGNING_FPR` is the primary key's fingerprint: users trust it, and the workflow fails
unless every signature is by one of its subkeys. Publish the primary's public key
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

Then the next release's archive carries the updated public key; users who trust the primary
key's fingerprint need do nothing (apt and dnf read the keyring files from zigbox.org). The
workflow takes the subkey that is unexpired and can sign, and fails if there are none or two.
If the subkey leaks, revoke it with the primary key and set a new one the same way.

## What the workflow runs

`.github/release-sign.sh` (the whole signing logic; the `test` job runs the same file):

1. Imports `ZIGBOX_SIGNING_KEY` from stdin into a throwaway `GNUPGHOME` (`mktemp`, mode 0700,
   removed on exit, also on failure). The passphrase is a 0600 file in that home, used with
   `--pinentry-mode loopback --passphrase-file`. Neither is printed, written to the workspace or
   passed as an argument, and there is no `set -x`.
2. Checks the key's primary fingerprint is `ZIGBOX_SIGNING_FPR` and picks its one signing subkey.
3. Round 1: `zig build packages` writes unsigned rpms and `zig-out/packages/to-sign/<rpm>.header`;
   each header gets a binary detached signature, `<rpm file>.header.sig`, in a fresh directory.
   Each is tied to the header it signs (its 16 digest bits and its issuer fingerprint), so a
   swapped or missing `.header.sig` is refused. RSA (including 4096-bit) and Ed25519 are read; a
   signature may be up to 1024 bytes (`docs/decisions/2026-11-08-openpgp-signature-bound.md`).
4. Round 2: `zig build packages -Dsignatures=DIR` embeds them and rewrites the trees (the rpm
   digests now cover the signed files). Then `InRelease` (clearsigned `Release`), `Release.gpg`
   and both `repomd.<arch>.xml.asc` are signed.
5. A final `zig build packages -Dsignatures=DIR` places them, and `zig build packages-check
   -Dsignatures=DIR` reads the tree back: every file against the metadata that names it, every
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

This workflow does not yet send it `repository_dispatch` of type `site`, because this repository
holds no token that can write to `Zigbox/zigbox.github.io` (`GITHUB_TOKEN` cannot). Until the
owner adds one, run the deploy by hand after a release, or wait up to six hours. Then check a
client with `apt update` and `dnf makecache` against zigbox.org.

The `Release` file has a fixed `Date` and no `Valid-Until`, and `repomd.xml` a fixed `revision`
(reproducibility): a client cannot tell an old signed `InRelease` from a new one, so there is no
replay or freeze protection.

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
