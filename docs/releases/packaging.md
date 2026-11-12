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

A release is automated ([spec and setup guide](automation.md),
[decision](../decisions/2026-11-12-release-draft-first-hosted-mac.md)). The owner sets up the
secrets, the App and the environments once (the guide's "Setup guide"). For each release the
supervisor merges the release PR (version in `build.zig.zon`, notes in `docs/releases/<v>.md`,
gates quoted). When `ci` is green on that commit, `.github/workflows/release.yml` runs: it checks
everything that can refuse, makes a **draft** release (no tag yet), and waits for the owner's one
approval of the `release` environment. Nobody tags by hand. After the approval:

- `linux` signs the apt and dnf trees and attaches `zigbox-repos.tar.gz` (the rest of this file);
- `mac`, on a GitHub-hosted macOS runner, builds `zbx` for arm64 and x86_64, joins them with
  `lipo`, signs the result with the Developer ID certificate in a temporary keychain, notarizes
  it, and attaches `zbx-<v>-macos-universal.zip`, its `.sha256` and the formula to the draft;
- `prepare` checks the draft's four assets and the tap diff; `publish` publishes the draft, which
  creates the tag at the release commit;
- `tap` and `site` (environment `release-publish`, `main` only, no reviewers) commit the formula
  to `Zigbox/homebrew-tap` and run the zigbox.org deploy, waiting for it;
- `verify`, on `macos-15` and `macos-15-intel`, checks the public zip and runs
  `brew install zigbox/tap/zigbox`, `zbx --version` and `brew test zigbox`.

A failure before `publish` leaves a draft and nothing public; the formula and the site name the
release only after it is public. If a job fails, re-run the failed jobs, or start `release` by
hand (`workflow_dispatch`, from `main`, with the `version` input); every job is safe to repeat.

The workflow runs from `main` (the `release` environment deploys `main` only). Before approving,
open the run and check that its commit is the release-gated commit on `main`: the workflow and
script that run are the ones at that commit, so an approval hands the key to whatever it holds. Set
up, once: on the `release` environment "Prevent self-review", the secrets as environment secrets
(not repository secrets) and a deployment policy that admits `main` only.

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
2. Checks the key's primary fingerprint is `ZIGBOX_SIGNING_FPR` (set by the workflow to the
   pinned value), that the primary and the signing subkey are RSA 4096, and picks the one subkey.
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

The `linux` job then attaches the archive to the release. The release has no other assets from the
workflow: the release binaries are not attached by it.

Each `zig build packages` run deletes `apt/`, `rpm/` and `to-sign/` under the output directory
first, so the files of an earlier run never stay beside this one's.

### The site deploy

The site's deploy (`.github/workflows/deploy.yml` in `Zigbox/zigbox.github.io`) copies the newest
release's asset to `https://zigbox.org/apt`, `/rpm` and the two keyring files byte for byte
([decision](../decisions/2026-11-10-packages-on-zigbox-org.md)). It refuses an asset that holds
anything else (links, dot files, `.html`, `to-sign/`, the test key) or lacks `InRelease`,
`Release.gpg` or a `repomd.xml.asc`, and after deploying it fetches every file back and fails
unless zigbox.org serves the same bytes. The release's `publish` job sends it `repository_dispatch`
of type `site` with the release App's token (`GITHUB_TOKEN` cannot write to that repository), finds
the run that started and fails unless it succeeded. The deploy also runs every six hours on its own.
After a release, check a client with `apt update` and `dnf makecache` against zigbox.org.

The `Release` file has a fixed `Date` and no `Valid-Until`, and `repomd.xml` a fixed `revision`
(reproducibility): a client cannot tell an old signed `InRelease` from a new one, so there is no
replay or freeze protection.

## Doing it by hand

The fallback, when the automation is down or to debug a release. For the Linux packages, with the
subkey in your own keyring, `.github/release-sign.sh` is the same procedure; `zig build packages`
prints the `gpg` command for each file it needs signed (rounds 1 and 2 above). `gpg --batch -o`
will not overwrite a file, so use an empty signatures directory every time. The tag is made by
publishing the draft release in `release.yml`, never by hand; only with the owner's written
go-ahead in `docs/decisions/` create the tag and release with `gh release create` from the gated
commit, run `release.yml` by `workflow_dispatch`, and start the site deploy with `gh workflow run deploy.yml --repo
Zigbox/zigbox.github.io`.

For the Mac zip, on a Mac with the Developer ID certificate in the login keychain and a notary
profile there (`xcrun notarytool store-credentials zbx-notary`), from a logged-in graphical
session: `SDK="$(xcrun --show-sdk-path)"; zig build mac-release --sysroot "$SDK" -Dsdk -Dnotarize`
(`--sysroot` and `-Dsdk`, because both architectures are cross-built and a cross-built target
finds no SDK by itself; no `-Dkeychain`: it uses the login keychain; it builds both architectures and joins
them with `lipo`). Attach
`zig-out/mac-release/zbx-<v>-macos-universal.zip` to the release and commit `zig-out/mac-release/zigbox.rb`
to `Formula/zigbox.rb` of `Zigbox/homebrew-tap` by hand. `-Dkeychain=FILE` points `codesign` and
`notarytool` at another keychain file, as the workflow does with its temporary one.

## Testing the automation

`test` (Linux, throwaway key), `mac-test` (`macos-15`, a throwaway self-signed identity in a
temporary keychain, no notarization, no upload, no secret; builds the universal zip) and
`draft-test` (a throwaway prerelease draft: upload, download, publish, tag, then deleted) run on
pull requests that touch the release files and on pushes to `release-test/**`; `mac-test` never
runs for a pull request from a fork. The jobs that need the owner's secrets (real signing,
`publish`, `tap`, `site`) are tried only by the `v0.5.1-rc.1` dry run ([spec](automation.md)).

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
