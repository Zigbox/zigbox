# M7 · Slice 2: review fixes and the composition

*Decided in the slice 2 review.*

- **Composition.** `zbx build` (without `--graph`) is `build/compose.zig`: per step, in graph order, base from `zbx.lock` (E0804 when not locked, or locked but its image is not in the store: the fix is `zbx pull`; pull by locked digest is slice 3), key, input import, cache lookup, `run_step`, record. One row per step, `<step>  hit|built  <digest>`. A failure stops the build.
- **`TERM=dumb`** is in the key's fixed environment (`key.fixed_env`) and cannot be set by a step's `.env`: the run added the host's TERM, so one key gave different outputs on different hosts.
- **stdin is /dev/null** for a step (`SpawnFlags.stdin_null`), not the caller's.
- **Logs are keyed by build file**: `build/logs/<group>/<step>.log`, the group being 16 hex digits of the digest of the build file's absolute path; two projects' steps of one name no longer share a log.
- **Locks.** A step holds the store lock shared while it runs; `step.sweep` takes it exclusive, once per build before its steps, and does nothing if busy (another build is running). The sweep child takes no lock of its own (it would deadlock against the parent's exclusive hold).
- **A failed start** discards the run record if one was saved.
- **A SIGKILLed `zbx`** leaves its `build-*` run record; the run layer's reconciliation of dead runs handles it as for any run. Not solved here. The sim tests plant leftover work directories and a log temporary and sweep them; the real SIGKILL is a VM check.
- **Nested inputs through a link** are refused as overlapping by their written text (E0803) before any resolution.
- **An over-limit `/out` is E0415** (accepted); the brief and E0806's text say so.
- **Farm format marker (required before demo-m7's golden digest and slice 4's upgrade path).** Farm directories made before this slice keep their 2000-01-01 mtimes; new ones are stamped differently. A marker for the farm format (rebuild or restamp old farms) must exist before a golden digest or an upgrade is promised.
- **Not done, on purpose:** no cache pruning; `store verify` and `store du` do not know the cache. Both are noted in `docs/demos/m7.md`.
