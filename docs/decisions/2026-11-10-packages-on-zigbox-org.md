# The apt and dnf repositories are served from zigbox.org

Date: 2026-11-10. Decided by: the owner.

Supersedes the hosting clause of [2026-11-04-package-signing-hosting.md](2026-11-04-package-signing-hosting.md)
(GitHub Pages). Signing is unchanged.

## Why

zigbox.org moved off GitHub Pages to a Cloudflare Worker with static assets on 2026-11-05,
built from `Zigbox/zigbox.github.io` (its AGENTS.md). The README's install commands already
name `https://zigbox.org/apt`.

## The decision

- The repositories live at `https://zigbox.org/apt` and `https://zigbox.org/rpm`, with
  `zigbox-archive-keyring.gpg` and `.asc` beside them.
- The owner-signed `apt/` and `rpm/` trees still reach the site as one release asset. The site's
  deploy workflow (`.github/workflows/deploy.yml` in `Zigbox/zigbox.github.io`) copies the latest
  Zigbox release's asset in byte for byte, as it copies `site/errors/`. CI never builds or signs
  these bytes.
- `/apt` and `/rpm` are new top-level paths on zigbox.org, owned by this release asset; they are
  not hand-edited, like the error pages.
- M8 slice 8 makes the change in `Zigbox/zigbox.github.io` instead of Zigbox's Pages workflow,
  and checks that the Worker serves the tree's files unchanged (no `.html` redirect or content
  rewriting applies to `Release`, `InRelease`, `Packages*`, `repomd.xml` or the packages).
