# The release workflow does not dispatch the zigbox.org deploy

Date: 2026-11-11. Amends `2026-11-11-ci-signs-packages-with-a-subkey.md`, which is merged and not
edited.

That decision says the workflow "dispatches the zigbox.org deploy (`repository_dispatch` type
`site`)". It does not: this repository has no token that can write to `Zigbox/zigbox.github.io`.
The site deploy picks the release asset up on its own schedule, every six hours (see
`docs/releases/packaging.md`, "Dispatching the site deploy"). Everything else in that decision
stands. Also changed in the review of PR #99: the primary key's fingerprint is pinned in
`release.yml`, not read from a repository variable.
