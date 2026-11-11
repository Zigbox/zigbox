# Zigbox guide

Zigbox runs Linux containers without a daemon and without root. One static binary, `zbx`,
pulls images, runs them, keeps their data, builds new images and signs them. Every container
starts with no network unless you grant one. Every error is one line with a code, a cause and a
command that fixes it. On a Mac, `zbx` runs the same containers in a small Linux virtual machine
that starts and stops by itself.

## Status: public beta

Zigbox is a beta. The core loop works and is tested on every change in an Ubuntu 24.04
virtual machine: check the host, pull, run, publish a port, keep state, read logs, exec, build,
sign, verify and push. It is young software: expect rough edges, and do not trust it with data
you have not backed up. Some things that work in Docker are not built, and some never will be;
[Known limits](known-limits.md) lists them, along with problems we know about and how to report
a new one.

<!-- owner: the examples in this guide were run with zbx 0.4.0 (built from the v0.4.0 tag), the
newest release on 2026-11-11. Re-run them with 0.5.1 before the beta is announced. -->

## Try it

- **[Try on a Mac](try-mac.md)**: Apple Silicon, `brew install`, about five minutes.
- **[Try on Linux](try-linux.md)**: a signed package from our apt and dnf repositories, then
  `zbx doctor`.
- **[Try in Claude Code](try-claude-code.md)**: containers inside a Claude Code cloud session,
  where Docker's daemon does not run, and an agent driving `zbx` through its JSON output.

Then take the **[tour](tour.md)**: one short example of each command in the core loop.
