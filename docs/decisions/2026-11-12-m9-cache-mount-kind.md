# M9: caches get their own mount kind

*Decided 2026-11-12, by the supervisor, for M9 slice 2.*

A step with `.caches` and a non-root `.user` needs a writable directory that the user can write
to, and the writable-mount rule (a writable source must lie inside the project) forbids the
store's caches root. Three options were put to the supervisor; this is the one chosen (a).

**Decision.** Cache directories are mounted with a new mount kind, `cache`. It is writable and
exempt from the "writable mount source outside the project" rule, and only for a directory under
the store's caches root, which the store creates and owns. Every other writable mount keeps the
rule. The step's `.user` owns the mounted directory for the run (the store chowns the cache
directory to the mapped id before the container starts), so a non-root step can write it.

**Why not the others.** Widening the rule for every writable mount would let any mount write
outside the project. Refusing `.caches` with a non-root `.user` would make the common Dockerfile
shape (`USER app`, `RUN --mount=type=cache`) unimportable.

**Not in the cache key.** Caches stay out of the key, as the brief says: a cache is a speed-up and
never changes a step's identity.

The root-output handoff, `2026-11-12-m9-slice2-root-steps.md`, is merged and not edited; this
file adds to it.
