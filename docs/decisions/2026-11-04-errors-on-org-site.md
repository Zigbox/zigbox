# zigbox.org is served by the organisation site; error pages move to /errors/box/

*Decided 2026-11-04, by the owner (one site for the domain, errors under `/box` and `/cube`) and the supervisor (the repository and the layout).*

Supersedes part of `2026-11-04-project-domain-zigbox-org.md`: the error-page address, which repository serves `zigbox.org`, and the redirect check. Everything else in that decision stands: `type_uri_base = https://zigbox.org`, the type URIs, the schema `$id` (in 0.4.0), one constant per base, goldens regenerated and never hand-edited, and the order of work.

## Decision

`zigbox.org` is served by a dedicated repository, `Zigbox/zigbox.github.io`: GitHub's organisation site, with the custom domain `zigbox.org`. Zigbox's and Zigcube's error pages both live there, side by side.

| What | Decided in #56 | From now on |
|---|---|---|
| Repository with the custom domain | `Zigbox/zigbox` | `Zigbox/zigbox.github.io` (the organisation site) |
| Error pages (`constants.docs_url_base`) | `https://zigbox.org/errors/` | `https://zigbox.org/errors/box/` |
| Site root (`errors_site.zig` `site_url`) | `https://zigbox.org/` | unchanged |
| Zigbox's status site | `https://zigbox.org/` | `https://zigbox.org/zigbox/` (still `site/` in this repository) |

The error pages are still generated here (`zig build errors-site`, checked by `errors-site-check`) into `site/errors/`. The organisation site's Pages workflow copies `site/errors/*.html` from `main` into `/errors/box/` on every deploy (a push to its `main`, every six hours, or a dispatch). Nothing in this repository builds or pushes to it.

## Old links

With a custom domain on the organisation site, GitHub serves every project site without a domain of its own under it, and redirects `zigbox.github.io/<repo>/...` to `zigbox.org/<repo>/...`. So `https://zigbox.github.io/zigbox/errors/E0101.html`, which released binaries print, answers with a 301 to `https://zigbox.org/zigbox/errors/E0101.html`, which this repository's own Pages still serves. No stub pages are needed, and this repository must keep publishing `site/errors/` in its own Pages site for as long as released binaries print the old address.

`Zigbox/zigbox` must not get a custom domain of its own: that would take it out from under `zigbox.org/zigbox/` and break the redirect above.

The move does not merge until both are checked from outside:

- `curl -sI https://zigbox.github.io/zigbox/errors/E0101.html` returns a 301 to `https://zigbox.org/zigbox/errors/E0101.html`;
- `curl -sI https://zigbox.org/errors/box/E0101.html` returns 200.

## Owner steps (replacing step 1 of #56)

- DNS: the apex `A` and `AAAA` records GitHub documents for Pages, and `www` as a `CNAME` to `zigbox.github.io`.
- Verify `zigbox.org` for the organisation (*Organisation settings → Pages*).
- On `Zigbox/zigbox.github.io`: *Settings → Pages*, source GitHub Actions, custom domain `zigbox.org`, *Enforce HTTPS*.
