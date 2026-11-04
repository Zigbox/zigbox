# M7 · Slice 2c: how a step runs (for review)

*Decided 2026-11-02 by the slice 2c implementer, for review.* The brief was silent on these; each is the smaller option.

- **`/out` and the project rule.** The step's run names its work directory, `build/work/<container name>`, as `Spec.project`, and `/out` is a `.mount` of `build/work/<name>/out`. The rule that a writable mount is inside the project holds as it is: no rule was widened.
- **Hostname and umask.** `Spec` gains two additive fields, `hostname` (checked as a container name is) and `umask`. The umask is a step of the child's plan (`set_umask`), only when `Spec.umask` is set, so every earlier plan is unchanged. A step runs with hostname `build` and umask 022.
- **Limits.** A step's memory (1 GiB), PIDs (1024) and timeout (30 minutes) are new constants, `build_step_*`. CPU is not limited. A run's limits have no defaults, so "the default limits" of the brief are these.
- **The E0805 headline.** The brief's stderr starts `error[ZBX-E0805]: build step "fetch" failed: exit 6`, which is not the registry's summary. `Diag` gains a headline, which overrides the summary in every renderer and goes over the store child's pipe. M2's long wording ("ran out of memory at its limit of ...") is the first cause.
- **The step log.** The parent copies the run's log, both streams in order, as plain text to `build/logs/<group>/<step>.log` (a temporary file and a rename), and keeps its last line for E0805. The run's own record and logs are then discarded (`run.discard`): a step leaves nothing in `zbx ps -a`.
- **The output import.** In the store's child: owners 0:0, no xattrs (`drop_xattrs`), and no root record (`save_root = false`); the cache entry roots the tree. A device, FIFO or socket under `/out` is E0806 with its path relative to `/out` (`refuse_special`). Between the import and the cache entry, gc may remove the tree; the entry's lookup then misses.
- **Output limits keep E0415.** A tree over the store's file, path or depth limits is E0415 (`too_big`), as for any import. E0806 is only a file kind the store refuses. The brief lists "a limit on files or depth" under E0806; E0806's explanation says the limits stay E0415.
- **The work directory** is removed in the store's child on every path after the prepare, best effort: one left behind by a crash (SIGKILL of `zbx`) is removed by the next build's sweep (`step.sweep`, below).
- **Cuts, for slice 3:** a step's stdin is the caller's; looking a base up in `zbx.lock` (E0804) is the scheduler's, so this slice has only the diagnostic.
