# M9 slice 1: the build file grows (decisions)

Status: taken by the slice 1 implementer; the supervisor reviews each item.

## Reading of the brief

- **`from` on a copy or a bind.** Absent means the project. `step:<name>` is a graph edge.
  Anything else must parse as a locked image reference (slice 2 resolves it). The brief's literal
  text did not say what a bare word means; refusing it early keeps `from = "foo"` from being
  taken for a step.
- **`from` names.** `step:<name>` is always a step, so an image called `step` with a tag (as in
  `step:1.0`) cannot be written as a bare reference there; write `docker.io/library/step:1.0`.
  A bare `.from = "build"` is the image `docker.io/library/build`, never a step: slice 2's error
  for an image it cannot find should hint `step:build` when a step of that name exists.
- **Mounts.** A step's mounts are `needs + binds + caches + 2` (the 2 is dropped for
  `.output = .root`) and must be at most `mounts_max` (8). Each cache is a mount at run time,
  and the E0802 text already said so; the brief left caches out of the count, and review
  (MUST) found that a step of 6 needs and a cache would overflow the run's mount plan.
  `too_many_mounts` and `mount_twice` are E0802.
- **A step has exactly one of `.run` and `.copy`** (`run_or_copy`, E0801). A copy step may carry
  `.env`, `.network` and `.user`; slice 2 decides what they mean.
- **`config.user` accepts names** (`app`, `app:app`, `0`). Numeric `uid:gid` is unchanged.
- **An input with `* ? [ \` is a glob.** This changes M7 for a file or directory whose name has
  one of those bytes: it is now matched as a pattern (`data[1].csv` is the pattern for
  `data1.csv`). Globs are validated in slice 1, not yet resolved on disk, and the guard below
  refuses such a file, so an old file fails loudly and nothing builds on the new meaning
  silently. Pinned by a test in `inputs.zig`. **Upgrade note for the release:** an M7 project
  with a glob byte in an input name must wait for slice 2's escapes (`\[`) or rename the file.
- **Globs follow Docker only where they agree.** The matcher refuses a `**` that is not a whole
  segment (`a**b`, `**.log`) and a negated class (`[!a]`, `[^a]`) with `bad_pattern`, because
  moby reads those another way (`**.log` does not match `a.log`; `[!a]` holds a `!`; `[^a]`
  takes `/`). The `dockerignore` fuzzer's reference is a text matcher built the way moby builds
  its expression, apart from the reader's tokens.
- **Empty lists.** `.copy = .{}` and a copy's `.src = .{}` are refused. A user number has no
  leading zeros (`007` is refused, `7` is the id), so one id has one spelling in a key.
- **Edges.** `--graph` lists an edge once, however many ways a step names another.

## Guard

`zbx build` refuses a file that uses a field slice 1 reads but cannot run (root output, user,
workdir, copy, caches, binds, exclude, input globs, `step:` bases, named `config.user`) with
E0802 and a cause naming the field. No new code: the brief registers none for this and the guard
leaves with slice 2; **no release is cut with it in place**. E0802's explanation and page now
say what it refuses. `zbx build --graph` shows everything.

## Bounds (derived; the supervisor may want different numbers)

- `build_steps_max` 256 (a byte indexes steps), pool and file bounds 256 KiB.
- `build_step_edges_max` is the sum of the per-step lists that can name a step.
- `provenance_bases_max = lock_entries_max` (256): each step with an image base adds one.
- `signature_record_bytes_max` is now 9.79 MB, so the assert ceiling went from 4 to 16 MiB. An
  older zbx bounds a record at 4 MiB and calls a larger one damaged: **upgrade note** for the
  release (a record this large needs 256 steps' worth of provenance, so only a large build
  reaches it). The on-disk oversize test is not restored: the simulated disk holds 3 MiB, so
  the byte bound is tested on the parser and the load path's `FileTooLarge` mapping is read,
  not run, at this size.
- `build_result_label_bytes_max` stays 64 KiB (the label length is a `u16`).
- `sim_fs_pool_bytes_max` stays 3 MiB (`HostSim` is on the stack); the record oversize tests
  use a static array and one on-disk oversize case was replaced.

## Key

The M9 fields are tagged extensions 12 to 16 after `ZBX_BUILD_STEP=<name>`, added only when set;
`step_format_version` is unchanged, so an M7 file's keys are byte for byte what they were.
Caches and `.exclude` are not in a key: an exclude acts through the tree digests it shapes.
demo-m7 records no per-step keys, so "M7 keys are unchanged" is shown by a synthetic golden and
by construction (the new fields are encoded only when set), not against a recorded run.

## Tests

The test binaries use `.code_model = .medium` on x86_64: the static .bss passed 2 GiB.

## Wording to fix in slice 2

E0817's explanation now says a `step:NAME` base is looked up when the step starts, after the
earlier steps ran. The cause text ("of its base") is already right.

## For slice 2

`compose.zig` builds the scheduler plan from `needs` only. Feed it from `graph.after_slice`
(needs, then base, copy froms, bind froms), widen `schedule.Plan` to `build_step_edges_max`, and
delete `graph.unrunnable` and `diagnose.unrunnable` when each field runs.

## Review fixes (second pass)

- `config.user` keeps M7's numeric form: `uid:gid` with leading zeros still parses there. The no-leading-zeros rule applies to the new `.user` and `.chown` fields only, where the spelling is part of a key.
- A class in a glob is refused (`bad_class`) when it holds an unescaped `*` or `?`, a `/`, or a range across `/`, because Docker rewrites or widens those. With `[!`, `[^` and a `**` that is not a whole segment, the matcher now reads only what Docker reads the same way.
- An empty `.copy` or `.src` list is its own refusal (`empty_list`), not `run_or_copy` or `missing_field`.
- For slice 3: the importer keeps needs + binds + caches at 6 or fewer per step, or refuses the Dockerfile line.
- `compose.zig`'s `begin` left the M9 key fields undefined (`= undefined` applies no defaults), which broke every M7 build with E0805. `begin` now sets them; a compose test drives `begin` on an M7 step.
