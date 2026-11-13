# M9 slice 2 handoff: caches done, binds not

Built (commits 6014eda, 8fcb014): the `cache` mount kind (writable below `Writable.caches_root`,
exempt from E0213); step mounts and cache directories (`step.make_caches`,
`build/caches/<group>/<dirname>`, `~` prefix for a leading dot, `/` as `%`); `key.Spec.caches`
(not read by `compute`); one edge per cache id to the nearest earlier holder (`compose.cache_edges`);
the `.caches` E0802 refusal removed.

Not built, in order for the next session:
1. `.binds`: `input_job.Request.bind`, `compose.resolve_binds` (select with `copy.select(..., "/")`,
   `spec.binds = ws.bind_keys[..]`, unroot after), remove the `.binds` line in `graph.unrunnable`.
   Refuse file and locked-image sources. `Workspace.bind_keys` and `step.Paths.binds` exist unused.
2. Report `cache` marker (additive JSON, `schemas.zig`, golden), `warn_caches` / W0802 like `warn_network`.
3. `--clear-caches` (cli, help, schema; empties `build/caches/<group>`).
4. Items 6 (root-output tests) and 7 (random-chain fuzzer) from the earlier handoff.

Traps: the sim world needs `add_node` for a bind source; `fuzz_state` asserts about every `Kind`;
`compose.cache_edges` is `pub` for the test. A non-root `.user` with a writable `/out` is still
refused by `needs_root` (undecided). Known gap: command-step input tree and copy selection tree are
unrooted between write and use. No VM demo was run (cloud container is not a test host).
