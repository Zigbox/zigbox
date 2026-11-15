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

## Entries an older zbx wrote (*added 2026-11-15, after Mac job 132951593134*)

The rule above changes what a foreign root step's output is, but not the step's key: the Mac's
store outlives a run, so the next run's m9.2 was all hits on the entry the previous zbx wrote,
and m9.4 still printed the digest with both directories. The rule is therefore also checked on
a hit. Before a run step's hit is used, `step.cached_output_holds` asks whether its output is
one the commit could make on this machine: on a foreign root step, `<home>/.cache/rosetta` as
the base has it, and no empty `<home>/.cache` the base lacks. An output that fails is an older
zbx's: `cache.forget` removes its entry (only if it still names that output) and the step runs
as on a miss, so its new output is recorded. Every other entry, and every native step, is
untouched.

`build_step_format_version` is not bumped: the M9 brief keeps it (`demo-m7`'s golden keys are
the proof), the constant says a patch release keeps it and the cache with it, and a bump would
rebuild every entry on every machine to repair the few a Mac wrote for foreign root steps.

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

In `src/build/compose_tests.zig`, on an aarch64 machine with a linux/amd64 step, as on the Mac:
an entry planted under the step's key whose output holds `/root/.cache/rosetta` is not a hit,
and is removed. The same entry on an x86_64 machine is a hit, and so is an entry whose
`.cache` holds a file of the step's.
