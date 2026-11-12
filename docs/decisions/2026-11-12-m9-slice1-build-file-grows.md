# M9 slice 1: the build file grows (decisions)

Status: taken by the slice 1 implementer; the supervisor reviews each item.

## Reading of the brief

- **`from` on a copy or a bind.** Absent means the project. `step:<name>` is a graph edge.
  Anything else must parse as a locked image reference (slice 2 resolves it). The brief's literal
  text did not say what a bare word means; refusing it early keeps `from = "foo"` from being
  taken for a step.
- **Mounts.** A step's mounts are `needs + binds + 2` (the 2 is dropped for `.output = .root`)
  and must be at most `mounts_max` (8). Caches are not counted. `too_many_mounts` and
  `mount_twice` are E0802.
- **A step has exactly one of `.run` and `.copy`** (`run_or_copy`, E0801). A copy step may carry
  `.env`, `.network` and `.user`; slice 2 decides what they mean.
- **`config.user` accepts names** (`app`, `app:app`, `0`). Numeric `uid:gid` is unchanged.
- **An input with `* ? [ \` is a glob.** This changes M7 for a file or directory whose name has
  one of those bytes: it is now matched as a pattern. Globs are validated in slice 1, not yet
  resolved on disk.

## Guard

`zbx build` refuses a file that uses a field slice 1 reads but cannot run (root output, user,
workdir, copy, caches, binds, exclude, input globs, `step:` bases, named `config.user`) with
E0802 and a cause naming the field. No new code: the brief registers none for this and the guard
leaves with slice 2. `zbx build --graph` shows everything.

## Bounds (derived; the supervisor may want different numbers)

- `build_steps_max` 256 (a byte indexes steps), pool and file bounds 256 KiB.
- `build_step_edges_max` is the sum of the per-step lists that can name a step.
- `provenance_bases_max = lock_entries_max` (256): each step with an image base adds one.
- `signature_record_bytes_max` is now 9.79 MB, so the assert ceiling went from 4 to 16 MiB.
- `build_result_label_bytes_max` stays 64 KiB (the label length is a `u16`).
- `sim_fs_pool_bytes_max` stays 3 MiB (`HostSim` is on the stack); the record oversize tests
  use a static array and one on-disk oversize case was replaced.

## Key

The M9 fields are tagged extensions 12 to 16 after `ZBX_BUILD_STEP=<name>`, added only when set;
`step_format_version` is unchanged, so an M7 file's keys are byte for byte what they were.
Caches and `.exclude` are not in a key: an exclude acts through the tree digests it shapes.

## Tests

The test binaries use `.code_model = .medium` on x86_64: the static .bss passed 2 GiB.

## For slice 2

`compose.zig` builds the scheduler plan from `needs` only. Feed it from `graph.after_slice`
(needs, then base, copy froms, bind froms), widen `schedule.Plan` to `build_step_edges_max`, and
delete `graph.unrunnable` and `diagnose.unrunnable` when each field runs.
