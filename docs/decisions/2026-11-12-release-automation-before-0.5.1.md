# Release automation lands before 0.5.1

Date: 2026-11-12. Decided by: the owner.

## Decision

Before the 0.5.1 tag, a release needs one act from the owner: approving the `release`
environment. `tag.yml` tags a merged release PR once `ci` and `mac` are green; `release.yml`
signs the apt and rpm archive, builds, signs and notarizes the Mac zip on the self-hosted Mac
runner, commits the formula to the Homebrew tap and dispatches the zigbox.org deploy, then checks
both. The spec, bill of materials and setup guide are [automation.md](../releases/automation.md).

The Mac signing certificate and the notary key are secrets of the `release` environment, like
the package signing subkey, and reach the runner only inside the approved `mac` job, in a
temporary keychain deleted when the job ends. A GitHub App holds the cross-repository writes
(tap, site) in two environments of its own, `release-tag` (`main` only) and `release-publish`
(tags only).

## Supersedes

- `2026-11-11-release-workflow-does-not-dispatch-the-site.md`: the release dispatches the site.
- `2026-11-11-mac-release-signed-by-owner-for-0.5.0.md`, for 0.5.1 onward: CI signs and
  notarizes the Mac build with the owner's certificate. Signing by hand stays the fallback.

## Unchanged

The release gates (check, extended fuzz run, two independent reviews), the supervisor's merge of
the release PR, and the 0.5.1 guide-tour gate.
