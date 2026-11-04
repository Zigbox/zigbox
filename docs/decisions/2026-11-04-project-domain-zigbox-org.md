# The project domain is zigbox.org

*Decided 2026-11-04, by the owner (the domain) and the supervisor (the layout and the order of work).*

## Decision

The owner named the project domain: **"Domain=zigbox.org"**. Earlier they said that error links and schema ids move to it as well ("Yes, error links and schema id move"). This file fills in the `<project domain>` placeholder that `2026-11-04-m8-owner-answers.md` ("Follow-ups", item 1) and `docs/briefs/M8-trust.md` ("Our type URIs") left open. M8 slice 2 is no longer blocked.

| What | Today | From now on |
|---|---|---|
| M8 `type_uri_base` | `https://<project domain>` | `https://zigbox.org` |
| Sign predicate type | — | `https://zigbox.org/attestation/sign/v1` |
| Provenance `buildType` | — | `https://zigbox.org/build/v1` |
| Error pages (`constants.docs_url_base`) | `https://zigbox.github.io/zigbox/errors/` | `https://zigbox.org/errors/` |
| Site root (`errors_site.zig` `site_url`) | `https://zigbox.github.io/zigbox/` | `https://zigbox.org/` |
| JSON schema `$id` (`schemas.zig`) | `https://zigbox.github.io/zigbox/schema/<name>/1` | `https://zigbox.org/schema/<name>/1` |

The paths keep their current shape. Only the scheme and host prefix change, and the `/zigbox/` project prefix drops out, because the site is served from the root of the domain.

## Rules

- **One constant per base.** Code, goldens, the demos and the tests build every URL from `docs_url_base`, `site_url`, the schema base and `type_uri_base`, and never spell a URL out. The move rewrites these constants, then regenerates the goldens and snapshots from them. A URL written out literally where a constant exists is a review finding. VM demo expectations (`src/testing/vm/agent_json_*.zig`, `checks*.zig`) and the `src/testdata/` goldens count as goldens: regenerate them, do not hand-edit them.
- **The type URIs are format.** Once a signature has been made with `https://zigbox.org/attestation/sign/v1` or `/build/v1`, changing either one is a format change (M8 brief). Pages for these URIs are welcome but not required: they are identifiers, not links.
- **Schema `$id` is a format change too, and it ships in 0.4.0, not in a 0.3.x patch.** A consumer that pinned the old `$id` sees a new id, and the schema number (`/1`) stays the same. The 0.4.0 release notes must say so.
- **Old links must keep working.** Binaries already released print `zigbox.github.io/zigbox/errors/...`. When a project site has a custom domain, GitHub Pages redirects its `github.io` URLs to that domain, so old links reach the new pages without anything else in place. The move does not merge until that redirect has been checked from outside: `curl -sI https://zigbox.github.io/zigbox/errors/E0101.html` must return a 301 to `https://zigbox.org/errors/E0101.html`.

## Order of work

1. **The owner** (DNS and repository settings, which no session can do):
   - Point `zigbox.org` at GitHub Pages: the apex `A` and `AAAA` records GitHub documents, and `www` as a `CNAME` to `zigbox.github.io`.
   - Set the custom domain `zigbox.org` under *Settings → Pages* of `zigbox/zigbox` and turn on *Enforce HTTPS*.
   - Optionally, verify the domain for the organisation, which stops anyone else's repository from claiming it.
2. **After 0.3.1 is tagged**, so the in-flight release is not disturbed, a Haiku session makes the mechanical move. It changes the constants in the table, regenerates the goldens, moves the M8 brief's `<project domain>` to `zigbox.org`, and updates links in the README, the site and the docs. A pull request with the `full-ci` label carries it, because it touches every demo's expectations.
3. **M8 slice 2** writes `type_uri_base = "https://zigbox.org"` in `constants.zig`, as its brief already requires.

## Zigcube

Zigcube's error pages (`ZC-`, `docs_url_base` in Zigcube's `src/diag.zig`, today `https://zigbox.github.io/zigcube/errors/`) are a separate Pages site. It cannot also be served from the root of `zigbox.org`. Its address is decided in a Zigcube decision of its own. Until then it stays where it is, and Zigcube's links to Zigbox pages follow whatever the pinned Zigbox prints.
