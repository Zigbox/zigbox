# Rosetta's cache is not in a build step's output

*Decided 2026-11-15, by the supervisor, on the evidence of PR #168's Mac runs.*

## Problem

`demo-mac`'s m9.4 builds demo-m9's project, locked to linux/amd64, on an Apple silicon Mac,
where the steps run under Rosetta. The digest did not match the golden that was recorded in a
Linux VM. The tree listing m9.4 prints on a mismatch (Mac run 43747691774, job 132914506875)
showed exactly two extra entries, both empty directories made by Rosetta while the final
stage's `RUN` ran (`HOME=/root`, from `key.fixed_env`):

    /root/.cache 755 0:0 directory
    /root/.cache/rosetta 755 0:0 directory

Every file matched, including the Go binary compiled under Rosetta, and so did the config.
These directories depend on the machine that ran the step, not on the step, so they break a
build's reproducibility across machines.

## Decision

A root step (`.output = .root`) whose platform's architecture is not the machine's (`uname`)
runs under the platform fallback: Rosetta on a Mac. Its commit (`step.commit_output`) leaves
these paths as the base tree has them:

- `<home>/.cache/rosetta`, where `<home>` is the step's own `HOME`: its user's home, or `/root`.
- `<home>/.cache`, but only when the base tree has no directory there and the step's layer
  holds nothing in it but `rosetta`.

Nothing else changes:

- A `.cache` that the base already has keeps its base contents.
- The step's own files under `.cache` stay.
- A step on the machine's own architecture is not affected.

No bound, limit, default or code changes. A `/out` step's output is a directory the step
writes on purpose, so it is untouched.

## Options not taken

- **A per-arch golden.** Not taken because this is not an arch difference.
- **A tmpfs over the cache.** Not taken because it still leaves the `.cache` parent behind.
- **Adding the path to `pin.default_excludes`.** Not taken because it is a user-visible default,
  and it would still leave `.cache` behind.

## Tests

The tests are in `src/build/step_root_tests.zig`, on the simulator, whose machine is x86_64, so
a `linux/arm64` step counts as foreign:

- A foreign step whose layer holds only the two directories has its base as its output. The
  same layer on the machine's own platform keeps them.
- A foreign step keeps its own `/root/.cache/own`.
- A foreign step whose base has `/root/.cache/kept` outputs that base unchanged.
