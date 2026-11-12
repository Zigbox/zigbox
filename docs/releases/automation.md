# Release automation: spec, bill of materials, setup

Status: spec, 2026-11-12. Lands before the 0.5.1 tag
([decision](../decisions/2026-11-12-release-automation-before-0.5.1.md)). Until it lands, the
runbook is [packaging.md](packaging.md) and the steps by hand in it.

## Goal

The owner's only act in a release is one approval of the `release` environment. Everything
before it (the tag, the GitHub release) and everything after it (signed apt and rpm archive,
the notarized Mac zip, the Homebrew tap, zigbox.org) runs without anyone. The gates do not
change: a release PR still carries the extended fuzz line and both review verdicts, and the
supervisor still merges it.

Today the owner does five things by hand: create the release and tag, approve `release`, build
and notarize the Mac zip on their Mac and upload it, start the zigbox.org deploy, and wait for
the tap bump. After this change, four of them are gone.

## The flow

```
release PR merged to main (supervisor; version in build.zig.zon, notes in docs/releases/<v>.md)
  └─ ci and mac both green on that main commit
       └─ tag.yml          env release-tag (main only, no reviewers)
            creates tag v<v> and the GitHub release (notes from docs/releases/<v>.md),
            pushed with the release App's token so that release.yml starts
            └─ release.yml on the tag
                 ├─ linux  env release  ── waits for the owner's one approval ──┐
                 │    sign apt and rpm, attach zigbox-repos.tar.gz             │ (one approval
                 ├─ mac    env release, self-hosted Mac runner ────────────────┘  covers both)
                 │    temporary keychain from secrets, codesign, notarize,
                 │    upload zbx-<v>-macos-arm64.zip and the generated formula
                 └─ publish  env release-publish (tags only, no reviewers), needs linux and mac
                      ├─ tap:  commit Formula/zigbox.rb to Zigbox/homebrew-tap main
                      ├─ site: repository_dispatch `site` to Zigbox/zigbox.github.io,
                      │        wait for that deploy run, fail unless it succeeded
                      └─ verify (Mac runner): brew install from the tap, zbx --version
```

### tag.yml (new)

- **Trigger:** `workflow_run` of `ci` and of `mac`, type `completed`, branch `main`. Whichever
  finishes second does the work; the first finds the other not green and stops quietly.
- **Job `tag`**, `environment: release-tag`, `ubuntu-24.04`, no checkout credentials kept:
  1. Read `version` from `build.zig.zon` at `head_sha`. Stop quietly unless
     `docs/releases/<version>.md` exists at that commit and no tag `v<version>` exists.
  2. Through the REST API, require that the latest `ci` and `mac` runs for `head_sha` both
     concluded `success`. Otherwise stop quietly (the other run will come back here).
  3. Mint a token with `actions/create-github-app-token` (pinned to a full SHA, as every action
     here is), scoped to `Zigbox/zigbox`, and create the release:
     `gh release create v<version> --target <head_sha> --notes-file docs/releases/<version>.md`.
     A tag pushed with `GITHUB_TOKEN` would not start `release.yml`; the App's token does.
- Idempotent: a second run finds the tag and stops. A version with no notes file is not a release.

### release.yml (changed)

- **`linux`:** today's `sign` job, renamed, unchanged in substance. It no longer refuses to run
  when the release is missing, because `tag.yml` made it; the check stays as an assertion.
- **`mac` (new)**, `environment: release`, `runs-on: ${{ vars.MAC_RUNNER_LABEL }}`,
  `if: vars.MAC_RUNNER_LABEL != ''` (no runner: the job is skipped and `publish` fails loudly,
  so a release never ships the tap out of date by accident).
  1. Refuse anything but a release tag, as `linux` does, before any secret is read.
  2. Check out the tag with `persist-credentials: false`; setup-zig-macos with no cache (the
     toolchain runs while the key is unlocked, as on Linux).
  3. **Keychain**, from secrets passed through the environment, never argv and never echoed:
     create `$RUNNER_TEMP/zbx-release.keychain-db` with a random password generated in the step;
     unlock it with no auto-lock timeout shorter than the job. `security import` takes a `.p12`
     password only on argv, so the `.p12` is first re-wrapped with a second random password:
     `openssl pkcs12 -passin env:MAC_CERT_PASSWORD -passout env:<throwaway>`; the re-wrapped
     file is imported with that throwaway password and `-T /usr/bin/codesign`; `security set-key-partition-list -S
     apple-tool:,apple:,codesign:` so `codesign` can use the key from a non-GUI session (this is
     what `errSecInternalComponent` in `keychain_message` was about). Then
     `xcrun notarytool store-credentials zbx-notary --key <p8 file> --key-id
     $MAC_NOTARY_KEY_ID --issuer $MAC_NOTARY_ISSUER_ID --keychain <that keychain>`; the `.p8`
     is written to `$RUNNER_TEMP` with mode 600 and deleted at once. The temporary keychain is
     never added to the user's search list or made default: the runner is a person's Mac.
  4. `zig build mac-release -Dnotarize -Dkeychain=$RUNNER_TEMP/zbx-release.keychain-db`.
  5. Check the zip's SHA-256 against the `.sha256` the tool wrote; upload the zip with
     `gh release upload --clobber`; keep the generated formula as a job artifact for `publish`.
  6. `if: always()`: `security delete-keychain`, remove every file the job wrote under
     `$RUNNER_TEMP`. A later pull request job on the same runner must find nothing.
- **`publish` (new)**, `environment: release-publish`, `needs: [linux, mac]`, `ubuntu-24.04`:
  1. Mint an App token for `Zigbox/homebrew-tap` and `Zigbox/zigbox.github.io`.
  2. **Tap:** check out the tap, replace `Formula/zigbox.rb` with the artifact, refuse unless the
     diff touches only `url`, `version` and `sha256` lines; commit `zigbox <version>` to `main`
     and push. (No PR: the formula is generated from reviewed code and its hash from the job
     that uploaded the zip.)
  3. **Site:** `POST repos/Zigbox/zigbox.github.io/dispatches` with `event_type: site`; find the
     `deploy.yml` run it started (created after the dispatch, event `repository_dispatch`), wait
     for it (timeout 30 min), fail unless `success`. That deploy already fetches every apt and rpm
     file back from zigbox.org and compares bytes.
- **`verify` (new)**, `needs: publish`, the Mac runner, no environment and no secrets:
  `brew update`, `brew install zigbox/tap/zigbox` (or `brew upgrade`), `zbx --version` must print
  the release's version, `brew test zigbox`. The install stays; it is the runner's zbx.
- The `test` job gains a `mac-test` twin for `release-test/**` branches and pull requests: the same
  keychain steps with a throwaway self-signed identity created in the job, `-Dsign-identity` of
  that identity, no `-Dnotarize`, no upload. No secret is available to it.

### Code change

`src/mac_release.zig` and `build.zig` gain `--keychain PATH` / `-Dkeychain=PATH`, passed to
`codesign --keychain` and to `notarytool submit --keychain`. Unset, behaviour is as today (the
login keychain), so the owner's hand-run path keeps working. A unit test covers the arguments
built with and without it.

### Docs

`packaging.md` describes the automated flow and keeps "Doing it by hand" as the fallback;
`release-workflow-does-not-dispatch-the-site.md` and `mac-release-signed-by-owner-for-0.5.0.md`
are superseded by the decision above (they are not edited). AGENTS.md "Releases" gains one line:
the tag is made by `tag.yml`, never by hand.

## What is checked before 0.5.1 uses it

A dry run on a pre-release tag, `v0.5.1-rc.1`, with a notes file `docs/releases/0.5.1-rc.1.md`:
every job green, the zip notarized (`notarytool` accepted it), the tap commit made, the site
deployed. The rc's tap commit is reverted by hand and its release deleted afterwards; the
decision records the run link. The `release` approval prompt must show `linux` and `mac` together
so one click covers both; if GitHub asks twice, that is recorded and accepted, not worked around.

## Security notes

- The Mac secrets reach a self-hosted runner, which is a person's machine. They exist there only
  inside the `mac` job, in a keychain under `$RUNNER_TEMP` deleted in an `always()` step. The
  `release` environment's approval and its tag-only policy are what stop a pull request from
  reaching them; `mac.yml` runs pull requests on the same runner, but never in that environment.
- The App can write to three repositories' contents and nothing else. Its key lives in two
  environments, `release-tag` (deployable from `main` only) and `release-publish` (tags `v*`
  only); no job outside them can read it.
- Nothing prints a secret, and no secret is a command-line argument: secrets enter through `env:`
  and files with mode 600. The only passwords on argv (`security create-keychain -p`, `unlock-keychain
  -p`, `import -P`) are random values made in the job; `MAC_CERT_PASSWORD` reaches only
  `openssl` through `env:`.

## Bill of materials

| # | Item | Kind | Where | Owner of it | Exists? |
|---|---|---|---|---|---|
| 1 | GitHub App "Zigbox Release": Contents read and write, Metadata read, Actions read | GitHub App | Zigbox org, installed on `zigbox`, `homebrew-tap`, `zigbox.github.io` | owner | new |
| 2 | `RELEASE_APP_ID` | variable | envs `release-tag`, `release-publish` | owner | new |
| 3 | `RELEASE_APP_PRIVATE_KEY` (the App's `.pem`) | secret | envs `release-tag`, `release-publish` | owner | new |
| 4 | Environment `release-tag`: deployments from `main` only, no reviewers | environment | Zigbox/zigbox | owner | new |
| 5 | Environment `release-publish`: deployments from tags `v*` only, no reviewers | environment | Zigbox/zigbox | owner | new |
| 6 | Environment `release`: owner approval, tags `v*` only | environment | Zigbox/zigbox | owner | exists |
| 7 | `ZIGBOX_SIGNING_KEY`, `ZIGBOX_SIGNING_PASSPHRASE` | secrets | env `release` | owner | exist |
| 8 | `MAC_CERT_P12`: Developer ID Application certificate and key, `.p12`, base64 | secret | env `release` | owner | new |
| 9 | `MAC_CERT_PASSWORD`: the `.p12` export password | secret | env `release` | owner | new |
| 10 | `MAC_NOTARY_KEY`: App Store Connect API key, `.p8` contents (role Developer) | secret | env `release` | owner | new |
| 11 | `MAC_NOTARY_KEY_ID`, `MAC_NOTARY_ISSUER_ID` | variables | env `release` | owner | new |
| 12 | `MAC_RUNNER_LABEL` | variable | repository | owner | exists |
| 13 | Self-hosted Mac runner, Apple Silicon, Xcode command line tools, Homebrew, awake during releases | machine | owner's Mac | owner | exists |
| 14 | `actions/create-github-app-token`, pinned to a full SHA | action | `tag.yml`, `release.yml` | implementer | new |
| 15 | `.github/workflows/tag.yml` | workflow | Zigbox/zigbox | implementer | new |
| 16 | `release.yml`: `linux`, `mac`, `publish`, `verify`, `mac-test` | workflow | Zigbox/zigbox | implementer | changed |
| 17 | `--keychain` / `-Dkeychain` in `src/mac_release.zig`, `build.zig`, with a test | code | Zigbox/zigbox | implementer | new |
| 18 | `packaging.md`, AGENTS.md line, decision | docs | Zigbox/zigbox | implementer, supervisor | changed |
| 19 | Site `deploy.yml` accepting `repository_dispatch` type `site` | workflow | Zigbox/zigbox.github.io | — | exists |
| 20 | Tag rule: if a ruleset protects `v*` tags, the App is on its bypass list | ruleset | Zigbox/zigbox | owner | check |

## Setup guide (owner, once)

Every value goes in through `gh`'s standard input or a prompt, never on the command line.

**1. The GitHub App.** In the browser: Zigbox organisation → Settings → Developer settings →
GitHub Apps → New GitHub App. Name `Zigbox Release`; no webhook (untick Active); repository
permissions **Contents: Read and write**, **Actions: Read**, Metadata: Read; "Only on this
account". Create it, note the App ID, and **Generate a private key** (a `.pem` downloads). Then
**Install App** → Zigbox → Only select repositories: `zigbox`, `homebrew-tap`, `zigbox.github.io`.

**2. The two new environments.**

```bash
gh api -X PUT repos/Zigbox/zigbox/environments/release-tag -F 'deployment_branch_policy[protected_branches]=false' -F 'deployment_branch_policy[custom_branch_policies]=true'
```

```bash
gh api -X POST repos/Zigbox/zigbox/environments/release-tag/deployment-branch-policies -f name=main -f type=branch
```

```bash
gh api -X PUT repos/Zigbox/zigbox/environments/release-publish -F 'deployment_branch_policy[protected_branches]=false' -F 'deployment_branch_policy[custom_branch_policies]=true'
```

```bash
gh api -X POST repos/Zigbox/zigbox/environments/release-publish/deployment-branch-policies -f name='v*' -f type=tag
```

**3. The App's id and key in both.** Replace `123456` with the App ID and the path with the
downloaded `.pem`.

```bash
for env in release-tag release-publish; do gh variable set RELEASE_APP_ID --env "$env" --repo Zigbox/zigbox --body 123456; done
```

```bash
for env in release-tag release-publish; do gh secret set RELEASE_APP_PRIVATE_KEY --env "$env" --repo Zigbox/zigbox < ~/Downloads/zigbox-release.private-key.pem; done
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

**6. Tag rules.** If a ruleset protects tags (`gh api repos/Zigbox/zigbox/rulesets`), add the
`Zigbox Release` App to its bypass list.

**7. Check.**

```bash
gh secret list --env release --repo Zigbox/zigbox
```

```bash
gh variable list --env release --repo Zigbox/zigbox
```

Expect `ZIGBOX_SIGNING_KEY`, `ZIGBOX_SIGNING_PASSPHRASE`, `MAC_CERT_P12`, `MAC_CERT_PASSWORD`,
`MAC_NOTARY_KEY` as secrets and `MAC_NOTARY_KEY_ID`, `MAC_NOTARY_ISSUER_ID` as variables. Tell
the supervisor; the `v0.5.1-rc.1` dry run follows.

## A release afterwards

1. The supervisor merges the release PR (version bumped, `docs/releases/<v>.md` written, gates
   quoted).
2. `ci` and `mac` go green on `main`; `tag.yml` tags and creates the release.
3. The owner approves `release` once (keep the Mac runner awake).
4. `linux`, `mac`, `publish`, `verify` run; the supervisor reports the run link and updates
   README and site status.

## Slices

1. **Sonnet:** `--keychain` in `mac_release.zig` and `build.zig` with its test; `release.yml`
   `mac`, `publish`, `verify`, `mac-test`; `tag.yml`; `packaging.md`. Tried on a
   `release-test/**` branch (the `test` and `mac-test` jobs) before the PR. Opus review.
2. **Owner:** the setup guide above (can run in parallel with slice 1).
3. **Supervisor:** the `v0.5.1-rc.1` dry run, cleanup, the run link in the decision.
