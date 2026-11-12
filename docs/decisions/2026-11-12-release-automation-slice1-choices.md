# Release automation, slice 1: choices made while building it

Status: accepted by the implementer; the supervisor may overrule. It supersedes nothing.
It adds to `2026-11-12-release-automation-before-0.5.1.md`.

- **The test identity is signed with by certificate hash.** `codesign --sign <common name>` finds
  only identities the system trusts, and the throwaway self-signed identity in `mac-test` is not
  trusted (the first run on the Mac runner said `no identity found`). `mac-test` therefore passes
  the certificate's SHA-1 to `-Dsign-identity`. The hash is public data. Whether `codesign` accepts
  an untrusted identity by hash is confirmed only by a `mac-test` run on the runner.
- **Job paths go through `GITHUB_ENV`.** `runner.*` is not allowed in job-level `env:`, and a
  workflow with that mistake fails as a 0-second run on push, with no log. The first step of `mac`
  and `mac-test` writes `KEYCHAIN` and `SECRETS_DIR` there.
- **`--keychain` reaches both `codesign` and `notarytool`**, and nothing else. The tool never adds the
  keychain to the search list; the workflow fails if it finds it there.
- **The Mac runner needs `gh`**, which the spec's bill of materials does not list. `mac` checks for it.
- **`tag.yml` tags only pushes from this repository** (`event == push`, same head repository), so a
  fork pull request from a branch named `main` cannot be tagged.
- **`app-id` is deprecated in `create-github-app-token` in favour of `client-id`.** The workflows use
  `app-id` and `RELEASE_APP_ID`, as the spec says; expect a deprecation warning.
- **Not run before the first real release:** `tag.yml`, `mac` with the real secrets, `publish` (App
  token, tap push, site dispatch) and `verify`. They need the owner's setup.

## Review fixes on #121

- The `mac` keychain step pins `PATH` to the system directories, calls `/usr/bin/security` and
  `xcrun` by absolute path, and unsets each secret once its file is written. `mac_release.zig`
  already spawns `codesign`, `xcrun` and `ditto` by absolute path.
- The `mac` job uses a Zig global cache under `$RUNNER_TEMP`, removed in the cleanup.
- Signing is by the certificate hash read from `find-identity`, which must report exactly one
  valid identity.
- `tag.yml` tags only a commit that added `docs/releases/<version>.md`; a later green commit is
  never tagged as the release. Re-run the failed workflow on the release commit.
- Every step of the `mac` and `mac-test` jobs runs under `/bin/bash --noprofile --norc -euo
  pipefail {0}` (job `defaults.run.shell`), so no `bash` is found through `PATH`. `xcrun` is run
  with `--no-cache` in the workflow and in `mac_release.zig`. `tag.yml` tags only a commit that
  added the notes (`--diff-filter=A`), and its concurrency group is per commit. A fix after a
  failed release needs a new version, or the owner's written go-ahead.
- **Owner precondition, not fixable in code.** A process of the same macOS user can read the
  Developer ID key, its password and the notary key (`ps -E` on the step's initial environment,
  the mode-600 files while they exist, the keychain passwords on argv with a copy of the
  keychain file), and can use the unlocked keychain for up to an hour. The first three are a
  permanent compromise. Before any secret is added to the `release` environment the owner runs a
  separate macOS user with its own runner instance, in a runner group limited to `release.yml`
  on tags (steps in `docs/releases/automation.md`, step 0). The code may merge before that: with
  no secrets every secret-bearing step fails closed.
