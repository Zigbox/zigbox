# The input import of `zbx build` runs in the store's namespace

Found by the first live `demo-m7` run (M7 slice 4): the first build as an ordinary user failed
with ZBX-E0417 (`fchown(fd, 0, 0)` = EPERM) while importing `go.mod`. The input tree records
every file as owner 0:0, and writing that object is a `chown` only root of the user namespace can
do. The slice 2 import ran in the parent, so it only worked as real root (the cloud container,
the simulated host); it never ran as an ordinary user before the VM demo.

Decision: `src/build/input_job.zig` runs `input_tree.import` in the `namespace.run` child, like
the step's own store work, and returns the digest (or the encoded diagnostic) on a pipe.
Each step's import now does its own `clone3` and `newuidmap` round trip (one namespace child per
step, not one per build); the cost is small next to a step.

The parent-side writes that remain do not chown: `cache.record`, `roots.remove`, `assemble` and
`result_mod.save` write only the cache entry, the root link, the image's config and the result
record, as the user. Only objects that carry the tree's owners need the namespace.

Lesson, and its test: the simulated host used to allow a `chown` by anyone, so only the VM demo
showed this. `SimFs.faults.owner_gate` now refuses `set_owner` with EPERM unless the current
simulated process has a new user namespace (`sim_world` `new_user`). `compose_tests.zig`, "a
step's inputs are imported inside the new user namespace", imports through `input_job` with the
gate on; with the import back in the parent it fails with the E0417 of the first live run.
