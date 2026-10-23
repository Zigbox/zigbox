# Zigbox

Rootless, daemonless, content-addressed container runtime, image store and builder, written in Zig. Pre-alpha; no code yet.

- Every failure path follows `DIAGNOSTICS.md`. This repo holds the canonical copy; `Zigbox/zigcube` carries an identical one, so change both together.
- The runtime will be consumed as a library by Zigcube's node agent; its interface is drafted in `Zigbox/zigcube` `HANDOFF.md` (the `Runtime` contract). Coordinate before changing its semantics.
- The project website is `site/index.html`; milestone status and demo output live in the data objects at the top of its script.
- Commits: small, signed off (`git commit -s`), Apache 2.0.
