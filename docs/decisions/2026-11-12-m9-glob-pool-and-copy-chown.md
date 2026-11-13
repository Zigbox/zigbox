# M9 slice 2: glob matched-path pool and copy chown

Date: 2026-11-12. Decided by the supervisor, relayed to the slice 2 implementer.

## Glob matched-path pool

A build holds at most `constants.build_glob_matches_max` (65,536) matched paths across all of
its input globs. The pool is allocated once at startup, with a byte pool of
`build_glob_pool_bytes_max` (4 MiB) beside it, as STYLE.md requires. A glob that would exceed
either is refused with one line naming the input and the bound.

The new code is **E0818** ("a glob matched more paths than a build can hold"), registered with
its explain text, goldens and errors-site page. It sits in the import range E0810-E0819, where
E0818 was unassigned.

## Copy chown

Copy steps do not chown in the parent. AGENTS.md puts all namespace work in the
single-threaded child, and `fchown` to mapped ids is refused outside the new user namespace
(`src/build/input_job.zig` already imports a step's inputs inside it; see compose_tests.zig,
"a step's inputs are imported inside the new user namespace"). A copy that sets owners writes
its tree through that same child job. The parent may only do owner-less work, as
`assemble_image` does.
