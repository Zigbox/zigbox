# Release automation: spec, bill of materials, setup

Status: spec, reworked 2026-11-12 (draft first, publish last; hosted Macs; universal zip; see
[the decision](../decisions/2026-11-12-release-draft-first-hosted-mac.md), which supersedes parts
of [the first one](../decisions/2026-11-12-release-automation-before-0.5.1.md)). Lands before the
0.5.1 tag. Until it lands, the runbook is [packaging.md](packaging.md) and the steps by hand in it.

## Goal

The owner's only act in a release is one approval of the `release` environment. Everything
before it (the checks, the draft release) and everything after it (the apt and rpm archive, the
notarized Mac zip, the public release and its tag, the Homebrew tap, zigbox.org, an install on
two Macs) runs without anyone. The gates do not change: a release PR still carries the extended
fuzz line and both review verdicts, and the supervisor still merges it.

Two rules shape the flow:

- **Draft first, publish last.** The release is a draft until every asset exists and every check
  that can refuse has run. A draft has no tag, so a failure before the last step leaves a draft
  and nothing else: no tag, no formula, no site change, no release anyone can see.
- **No release job runs on a person's machine.** Signing and notarization run on GitHub-hosted
  macOS runners, each a fresh virtual machine that is gone when the job ends.

## The flow

One workflow, `release.yml`, one run, a `needs:` chain. `tag.yml` is gone.

```
release PR merged to main (supervisor; version in build.zig.zon, notes in docs/releases/<v>.md)
  └─ ci green on that main commit  ──►  release.yml (workflow_run), or by hand with the version
       │
       ├─ plan        reads nothing secret: is this the release commit, is ci green, is the tag
       │              absent or at this commit, is the release already public
       ├─ mac-check   macos-15: zig build check at the release commit (replaces waiting for mac.yml)
       ├─ preflight   env release-publish: App token mints, tap formula readable, site workflow found
       ├─ draft       a DRAFT release (--draft --target <sha>), notes from docs/releases/<v>.md
       │              ── nothing above wrote anything public; nothing below does until `publish` ──
       ├─ linux       env release ┐ the owner's ONE approval covers both
       │    sign apt and rpm, write the release assets and SHA256SUMS, sign it (SHA256SUMS.asc),
       │    attach all of it to the draft
       ├─ mac         env release ┘ macos-15 (hosted)
       │    build arm64 and x86_64, lipo, sign, notarize, check, attach
       │    zbx-<v>-macos-universal.zip, its .sha256, SHA256SUMS.macos and the formula to the draft
       ├─ prepare     env release-publish: the draft holds exactly the expected assets, each checked,
       │              both sums files match, SHA256SUMS.asc is by a subkey of the pinned key;
       │              the tap's formula differs only in url, version, sha256 (and the one-off lines)
       ├─ publish     the draft becomes the release; THIS creates the tag, at the release commit
       ├─ tap         env release-publish: commit Formula/zigbox.rb to Zigbox/homebrew-tap main
       ├─ site        repository_dispatch to Zigbox/website, wait for the deploy
       └─ verify      macos-15 and macos-15-intel: the public zip (signature, Gatekeeper,
                      both architectures, zbx --version), then brew install, zbx --version, brew test
```

`test`, `mac-test` and `draft-test` try the same steps on `release-test/**` pushes and pull
requests that touch what the release reads, with throwaway keys and no secret.

### Every job is idempotent

Re-running a failed run, or starting `release` by hand (`workflow_dispatch`, from `main`) with the
version, finishes a half-done release:

- no draft: it is created; a draft exists: it is reused (its target must be the release commit,
  its notes are refreshed, its assets are replaced with `--clobber`);
- the release is already public (`plan` sees it): `draft`, `linux`, `mac`, `prepare`, `publish`
  are skipped, and the run goes on to `tap`, `site` and `verify`;
- the tag exists at another commit: `plan` refuses, before anything is written.

By hand, the commit is found, not given: it is the commit of `main` that added
`docs/releases/<version>.md`, and `build.zig.zon` must say that version there. The search
follows `main`'s first parents, so a release merged with a merge commit resolves to that merge
commit, the one `ci` ran on.

### What refuses before `publish`, and where

| Check | Job |
|---|---|
| version in `build.zig.zon` is a version; notes file exists; this commit added it | `plan` |
| `ci` green on the commit (the API, not the event) | `plan` |
| tag absent or at this commit; no published release at another commit | `plan` |
| macOS build and every gate | `mac-check` |
| App token mints for the tap and the site; tap formula readable; site `deploy.yml` found | `preflight` |
| a draft at another commit; two drafts | `draft`, `find-draft` |
| signature, notarization, `lipo -archs` (both), `spctl`, `zbx --version` of the signed zip | `mac` |
| the draft's assets (exactly), `SHA256SUMS` and `SHA256SUMS.macos` against them, the signature on `SHA256SUMS`, the formula's url, version and hash, the archive listing | `prepare` |
| the tap diff touches only the lines it may | `prepare` (again in `tap` before the write) |

### Prereleases

`X.Y.Z-rc.N` takes the same path and is published as a prerelease (`--prerelease`, not marked
latest). It still commits the formula to the tap, so a dry run is reverted by hand afterwards.

### The universal zip

`zig build mac-release` builds `zbx` for `aarch64-macos` and `x86_64-macos`, joins them with
`/usr/bin/lipo -create`, signs the result (hardened runtime, the virtualization entitlement),
notarizes it, and writes `zbx-<v>-macos-universal.zip`, its `.sha256` and the formula. After signing
it checks `codesign --verify --strict`, that the archive's code is the signed code (CDHash of each
slice), `lipo -archs` (exactly arm64 and x86_64), and, in the workflow, `spctl --assess` and the
version string. The zip holds `zbx` alone. The formula keeps `depends_on arch: :arm64` (the owner dropped Intel on Mac; the universal zip stays).

The x86_64 slice is checked on `macos-15-intel` as a zip only (`mac-check-zip`: signature,
Gatekeeper, architectures, version); `brew install` is skipped there because the formula needs
Apple silicon, whose kernel the VM requires.

### The tap

`tap` takes the formula from the published release (not from an artifact), checks its hash
against the zip's, fetches the tap's current `Formula/zigbox.rb` through the API, and refuses unless
the difference is only `url`, `version` and `sha256` lines. The first universal release also
changes the header comment (and the formula may still drop the `depends_on arch: :arm64` line
if the owner later allows Intel), so those two are allowed (`.github/actions/tap-formula`). The write is one contents-API call with the blob SHA it
read, so a concurrent change to the formula makes it fail, never overwrite.

## Security notes

- The Mac secrets reach a GitHub-hosted runner: a virtual machine made for the job, which no
  pull request job shares and which is destroyed afterwards. They enter only through `env:` of
  the signing step, in mode-600 files that are deleted in the step, and in a temporary keychain
  under `$RUNNER_TEMP`, deleted in an `always()` step. The `release` environment's approval and its
  `main`-only policy are what stop a pull request from reaching them.
- The temporary keychain is put on the user search list for the signing step, because `codesign`
  needs it there to resolve the chain; the `always()` step restores the list the job found. Both
  steps are the same in `mac-test`.
- The App can write the contents of two repositories, `homebrew-tap` and `website`, and
  read Actions on the site; it is not installed on `Zigbox/zigbox`. Its key is a secret of
  `release-publish` alone (no reviewers, `main` only): `preflight`, `prepare`, `tap` and `site`
  can read it. Tokens are minted per job for the repositories that job needs.
- `publish` and the draft use `GITHUB_TOKEN` with `contents: write` on `Zigbox/zigbox`, in jobs that
  hold no signing secret. A tag made with `GITHUB_TOKEN` starts no workflow, and none is meant to.
- Nothing prints a secret, and no secret is a command-line argument: secrets enter through `env:`
  and files with mode 600. The only passwords on argv (`security create-keychain -p`,
  `unlock-keychain -p`, `import -P`) are random values made in the job; `MAC_CERT_PASSWORD` reaches
  only `openssl` through `env:`. The tap write passes the formula (public) in the request, the
  token only in `GH_TOKEN`.
- Every tool is pinned: Zig by SHA-256 (`setup-zig`, `setup-zig-macos`), `gh` 2.74.0 by SHA-256
  (`setup-gh`), every action by full commit SHA. Every checkout sets `persist-credentials: false`.
- The system tools are called by absolute path where a secret is in reach.

## Bill of materials

| # | Item | Kind | Where | Owner of it | Exists? |
|---|---|---|---|---|---|
| 1 | GitHub App "Zigbox Release": Contents read and write, Metadata read, Actions read | GitHub App | Zigbox org, installed on `homebrew-tap` and `website` only | owner | new (uninstall from `zigbox` if installed) |
| 2 | `RELEASE_APP_ID` | variable | env `release-publish` | owner | new |
| 3 | `RELEASE_APP_PRIVATE_KEY` (the App's `.pem`) | secret | env `release-publish` | owner | new |
| 4 | Environment `release-publish`: deployments from `main` only, no reviewers | environment | Zigbox/zigbox | owner | new |
| 5 | Environment `release`: owner approval, deployments from `main` only | environment | Zigbox/zigbox | owner | exists (policy changes from tags `v*`) |
| 6 | `ZIGBOX_SIGNING_KEY`, `ZIGBOX_SIGNING_PASSPHRASE` | secrets | env `release` | owner | exist |
| 7 | `MAC_CERT_P12`: Developer ID Application certificate and key, `.p12`, base64 | secret | env `release` | owner | new |
| 8 | `MAC_CERT_PASSWORD`: the `.p12` export password | secret | env `release` | owner | new |
| 9 | `MAC_NOTARY_KEY`: App Store Connect API key, `.p8` contents (role Developer) | secret | env `release` | owner | new |
| 10 | `MAC_NOTARY_KEY_ID`, `MAC_NOTARY_ISSUER_ID` | variables | env `release` | owner | new |
| 11 | GitHub-hosted runners `ubuntu-24.04`, `macos-15`, `macos-15-intel` | runners | GitHub | GitHub | exist |
| 12 | Zig 0.17.0, `gh` 2.74.0 (SHA-256 pinned), `actions/*` (full SHA) | tools | `.github/actions/`, `release.yml` | implementer | changed |
| 13 | `release.yml`: `plan`, `mac-check`, `preflight`, `draft`, `linux`, `mac`, `prepare`, `publish`, `tap`, `site`, `verify`, `test`, `mac-test`, `draft-test` | workflow | Zigbox/zigbox | implementer | changed |
| 14 | `.github/actions/`: `setup-gh`, `find-draft`, `tap-formula`, `mac-check-zip` | actions | Zigbox/zigbox | implementer | new |
| 15 | `zig build mac-release` builds and joins both architectures; tests | code | Zigbox/zigbox | implementer | changed |
| 16 | `packaging.md`, this file, AGENTS.md line, STYLE.md (`lipo`), decision | docs | Zigbox/zigbox | implementer, supervisor | changed |
| 17 | Site `deploy.yml` accepting `repository_dispatch` type `site` | workflow | Zigbox/website | — | exists |

No longer needed: the `release-tag` environment, the `MAC_RELEASE_RUNNER_LABEL` variable, the
self-hosted release runner and its separate macOS user, the runner group. (`MAC_RUNNER_LABEL` and
`mac.yml` are untouched: they are the pull request runner for the VM demos, which hosted
runners cannot run.) A ruleset that protects `v*` tags needs nothing: the tag is made by the
`github-actions` bot through `GITHUB_TOKEN`; if the ruleset blocks it, say so (the first publish
shows it).

**Owner, recommended: a tag ruleset.** `publish` checks just before publishing that the tag is
still absent and refuses if it exists, which leaves a window of seconds, not hours. Closing it needs
a repository ruleset that targets tags `v*` and restricts creation so that only the release
workflow's identity (`github-actions`) can create them. Sessions cannot set rulesets: Settings →
Rules → Rulesets → New tag ruleset.

## Setup guide (owner, once)

Every value goes in through `gh`'s standard input or a prompt, never on the command line. There is
no runner to set up and no macOS user to make.

**1. The GitHub App.** In the browser: Zigbox organisation → Settings → Developer settings →
GitHub Apps → New GitHub App. Name `Zigbox Release`; no webhook (untick Active); repository
permissions **Contents: Read and write**, **Actions: Read**, Metadata: Read; "Only on this
account". Create it, note the App ID, and **Generate a private key** (a `.pem` downloads). Then
**Install App** → Zigbox → Only select repositories: `homebrew-tap` and `website`
(not `zigbox`).

**2. The environment `release-publish`, and the `release` policy.**

```bash
gh api -X PUT repos/Zigbox/zigbox/environments/release-publish -F 'deployment_branch_policy[protected_branches]=false' -F 'deployment_branch_policy[custom_branch_policies]=true'
```

```bash
gh api -X POST repos/Zigbox/zigbox/environments/release-publish/deployment-branch-policies -f name=main -f type=branch
```

`release` used to deploy from tags `v*`; the release now runs from `main`. Add the branch and
delete the tag policy (list them first with
`gh api repos/Zigbox/zigbox/environments/release/deployment-branch-policies`, then
`gh api -X DELETE .../deployment-branch-policies/<id>` for the `v*` one):

```bash
gh api -X POST repos/Zigbox/zigbox/environments/release/deployment-branch-policies -f name=main -f type=branch
```

If you made `release-tag` for an earlier version of this guide, delete it:
`gh api -X DELETE repos/Zigbox/zigbox/environments/release-tag`.

**3. The App's id and key.** Replace `123456` with the App ID and the path with the downloaded
`.pem`.

```bash
gh variable set RELEASE_APP_ID --env release-publish --repo Zigbox/zigbox --body 123456
```

```bash
gh secret set RELEASE_APP_PRIVATE_KEY --env release-publish --repo Zigbox/zigbox < ~/Downloads/zigbox-release.private-key.pem
```

Then delete the `.pem` from Downloads (the App can issue a new one).

**4. The Developer ID certificate.** Keychain Access → login → My Certificates → "Developer ID
Application: …" → right-click → Export → `.p12`, with an export password.

```bash
base64 -i ~/Desktop/DeveloperID.p12 | gh secret set MAC_CERT_P12 --env release --repo Zigbox/zigbox
```

```bash
gh secret set MAC_CERT_PASSWORD --env release --repo Zigbox/zigbox
```

(`gh` prompts for the value.) Delete the `.p12` afterwards.

**5. The notary key.** App Store Connect → Users and Access → Integrations → App Store Connect
API → Team Keys → generate a key with role **Developer**. Note the Key ID and the Issuer ID and
download `AuthKey_<KEYID>.p8` (it downloads once).

```bash
gh secret set MAC_NOTARY_KEY --env release --repo Zigbox/zigbox < ~/Downloads/AuthKey_KEYID.p8
```

```bash
gh variable set MAC_NOTARY_KEY_ID --env release --repo Zigbox/zigbox --body KEYID
```

```bash
gh variable set MAC_NOTARY_ISSUER_ID --env release --repo Zigbox/zigbox --body ISSUER-UUID
```

**6. Check.**

```bash
gh secret list --env release --repo Zigbox/zigbox
```

```bash
gh variable list --env release --repo Zigbox/zigbox
```

```bash
gh secret list --env release-publish --repo Zigbox/zigbox
```

Expect `ZIGBOX_SIGNING_KEY`, `ZIGBOX_SIGNING_PASSPHRASE`, `MAC_CERT_P12`, `MAC_CERT_PASSWORD`,
`MAC_NOTARY_KEY` in `release`, `MAC_NOTARY_KEY_ID`, `MAC_NOTARY_ISSUER_ID` as its variables, and
`RELEASE_APP_PRIVATE_KEY` in `release-publish`. Tell the supervisor; the `v0.5.1-rc.1` dry run
follows.

## A release afterwards

1. The supervisor merges the release PR (version bumped, `docs/releases/<v>.md` written, gates
   quoted).
2. `ci` goes green on `main`; `release` starts, runs `plan`, `mac-check`, `preflight` and makes the
   draft.
3. The owner approves `release` once (`linux` and `mac` wait together).
4. `prepare`, `publish`, `tap`, `site`, `verify` run; the supervisor reports the run link and
   updates README and site status.
5. If a job fails: re-run the failed jobs, or start `release` from `main` with the version. A
   failure before `publish` left a draft; delete it on the releases page to start clean.

## Slices

1. **Sonnet (done, 2026-11-12):** `--keychain` in `mac_release.zig` and `build.zig` with its test;
   the first `release.yml` and `tag.yml`; `packaging.md`.
2. **Sonnet (this rework):** draft first, hosted Macs, universal zip, one workflow
   (items 1 to 3 of the rework brief). Tried on a `release-test/**` branch.
3. **Sonnet (next):** Linux tarballs, `SHA256SUMS`, SBOM; apt `Valid-Until` with weekly re-signing.
4. **Owner:** the setup guide above.
5. **Supervisor:** the `v0.5.1-rc.1` dry run, cleanup, the run link in the decision.
