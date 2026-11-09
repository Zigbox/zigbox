# The run record carries the run's binding (record version 9)

Date: 2026-11-08. Decided by the supervisor for M8 slice 3.

## Decision

- A run record (`runtime/records.zig`) gains `.binding`, spelled `"none"`, `"result:<64 hex>"` or
  `"manifest:<64 hex>"`. `record_version` goes from 8 to 9.
- `zbx exec` re-judges the container against the current policy at exec time, with the tree and
  the binding the record holds. It does not hash again. The code is E0905, as for a run.
- A v8 record has no binding. It is judged as `.none`: only tree-only statements count for it
  (fail closed). A record of a newer version is skipped, as before.

## Why

A statement bound to a result or an image counts only for that run; exec has no other way to
know which run a container is. Storing the binding at start keeps exec and run on the one
verdict (`verdict.judge`).
