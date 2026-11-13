# Release: draft first, publish last; sign on hosted Macs; one universal zip

Date: 2026-11-12. Status: implemented in PR #121, rework of its first version; tried on a
`release-test/**` branch, not yet by the `v0.5.1-rc.1` dry run.

Supersedes, without editing them: from
[2026-11-12-release-automation-before-0.5.1.md](2026-11-12-release-automation-before-0.5.1.md) the
two-workflow flow (`tag.yml` then `release.yml`), the `release-tag` environment, the App on
`Zigbox/zigbox`, and the self-hosted Mac runner; from
[2026-11-12-release-automation-slice1-choices.md](2026-11-12-release-automation-slice1-choices.md)
the runner-label guard and the `macos-arm64` zip name. Everything else in them stands.

## Decisions

1. **One workflow, draft first.** `release.yml` is a `needs:` chain: `plan`, `mac-check`,
   `preflight`, `draft`, then `linux` and `mac` (one `release` approval covers both), `prepare`,
   `publish`, `tap`, `site`, `verify`. The release is a draft until `publish`, which patches the
   draft public with `GITHUB_TOKEN`; that makes the tag at the release commit. Everything that can
   refuse without writing runs before it. A failure earlier leaves a draft and nothing public; the
   formula and the site name the release only after it is public. Every job is idempotent, and a
   re-run or `workflow_dispatch` (from `main`, with the version) finishes a half-done release.
   `tag.yml` is deleted. The edit to `AGENTS.md` ("the tag is made by publishing the draft release
   in `release.yml`") is the minimal change this needs; the owner should look at it.
2. **The App is off `Zigbox/zigbox`.** It is installed on `homebrew-tap` and `zigbox.github.io`
   only (contents write; actions read on the site). The `release-tag` environment is dropped.
   `release-publish` (the App's secret, no reviewers) now deploys from `main`, not tags, and the
   `release` environment likewise: a branch policy replaces the tag policy.
3. **Hosted macOS runners.** `mac`, `verify` and `mac-test` run on `macos-15` (arm64);
   `verify` also on `macos-15-intel`. No release job runs on a self-hosted runner.
   `MAC_RELEASE_RUNNER_LABEL`, the `mac-runner` job and the separate-macOS-user precondition are
   gone. The protections stay: secrets through `env:` and mode-600 files only, the `.p12`
   re-wrapped with a throwaway password through `openssl -passin env:`, a temporary keychain with
   random passwords, removed in an `always()` step. The workflow waits for nothing from `mac.yml`:
   `mac-check` runs `zig build check` on `macos-15` at the release commit inside the run.
4. **The keychain joins the user search list for the signing step only.** `mac-test` showed that
   `codesign` does not find the identity through `--keychain` alone (its man page says the file is
   not searched to resolve the chain unless it is also on the search list). So `mac` saves
   `security list-keychains -d user`, sets the list to the temporary keychain plus the saved
   entries before `Sign and notarize`, and the `always()` cleanup restores the saved list; `mac-test`
   does the same. The identity is still chosen by hash after `find-identity` finds exactly one, and
   `--keychain` is still passed. The exposure the old rule guarded against does not exist on a
   one-job virtual machine that no pull request shares.
5. **Pinned tools.** Zig by SHA-256 (as before, plus `setup-zig-macos`), `gh` 2.74.0 by SHA-256
   (`.github/actions/setup-gh`, for ubuntu and both macOS architectures), every action by full
   commit SHA. Every checkout has `persist-credentials: false`.
6. **Universal zip.** `zig build mac-release` builds `aarch64-macos` and `x86_64-macos`, joins
   them with `/usr/bin/lipo -create`, signs the joined binary, and names the asset
   `zbx-<v>-macos-universal.zip` (plus `.sha256` and the formula). After signing: `codesign
   --verify --strict`, the CDHash of each slice against the zip's, `lipo -archs` (exactly arm64
   and x86_64), `spctl --assess`, and the version string. `lipo` joins `ditto` and `codesign` in
   the allowed macOS programs in `docs/STYLE.md`.
7. **The tap diff allows two one-off lines.** The first universal release changes the formula's
   header comment and removes `depends_on arch: :arm64`; `tap-formula` allows exactly those two
   (and `url`, `version`, `sha256`), so a surprise elsewhere still refuses.
8. **The finding on the runner-label guard is moot.** There is no label to guard. The other open
   re-review finding is applied: `mac-test` imports with `security import -x` and removes with
   `/bin/rm`.

## What the scratch run showed

- `gh release create --draft`, `upload`, `download` and `view` by tag work on a draft, and a draft
  makes no tag. `find-draft` finds a draft by listing releases.
- **Publishing a draft with `draft=false` alone does not create the `v` tag**: the release goes
  public under its placeholder `untagged-...` name. The publish call now passes `tag_name` and
  `target_commitish` too, and `publish` checks the tag is at the release commit. This is why the
  release test exists; the first scratch run leaked one such throwaway prerelease (release id
  443571427, name "draft check"), which `draft-test` now deletes by id on its next run, and the
  owner may delete by hand.

## Open, for the owner and the dry run

- **Intel.** The VM kernel is arm64-only, so on an Intel Mac `zbx` runs `--version`, `doctor` and
  `brew test`, but no VM. The owner dropped Intel on Mac, so the formula keeps
  `depends_on arch: :arm64` and the Intel `verify` leg checks the zip only; the universal zip
  stays.
- Not verified before a real run: `spctl` on a bare Mach-O, `codesign --architecture` for the
  per-slice CDHash, the x86_64 cross-build with frameworks on the arm64 runner, and
  `macos-15-intel` as a label. Each fails loudly in `mac`, `mac-test` or `verify`.
- Environment policy changes (owner): `release` and `release-publish` deploy from `main`;
  delete `release-tag`; reinstall the App on two repositories only
  ([setup guide](../releases/automation.md)).
- Items 4 and 5 (Linux tarballs, `SHA256SUMS`, SBOM; apt `Valid-Until` with weekly re-signing) are
  not started.
