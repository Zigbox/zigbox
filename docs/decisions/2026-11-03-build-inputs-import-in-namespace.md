# The input import of `zbx build` runs in the store's namespace

Found by the first live `demo-m7` run (M7 slice 4): the first build as an ordinary user failed
with ZBX-E0417 (`fchown(fd, 0, 0)` = EPERM) while importing `go.mod`. The input tree records
every file as owner 0:0, and writing that object is a `chown` only root of the user namespace can
do. The slice 2 import ran in the parent, so it only worked as real root (the cloud container,
the simulated host); it never ran as an ordinary user before the VM demo.

Decision: `src/build/input_job.zig` runs `input_tree.import` in the `namespace.run` child, like
the step's own store work, and returns the digest (or the encoded diagnostic) on a pipe.
Lesson: the simulated host does not refuse a `chown` by a non-root; only the VM demo shows it.
