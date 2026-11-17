# M2b: a read-only tmpfs covers /sys/fs/cgroup before the cgroup view

*Decided 2026-11-17, by the supervisor, ruling on the reviews of PR #180 (M2b slice 2).*

This supersedes one sentence of
[the runtime measurement](2026-11-17-m2b-runtime-cgroup-view.md): "The simulator does not model
that refusal." It now does, and the cover is a mount of its own, not part of `mount_cgroup2`.

## The deviation from the brief

The brief (`docs/briefs/M2b-workload-knobs.md`, section 4) says the view goes on top of the bound
host tree under `--net host`, and, if that mount fails, to "bind only the parts of host `/sys`
that are not `fs/cgroup`, and record how". The mount did fail on the VM: the host's cgroup2 is
mounted on the bound `/sys`'s `fs/cgroup`, and the kernel refuses its superblock again on that
mount (`EBUSY`).

Slice 2 did not take the brief's fallback. It covers `<rootfs>/sys/fs/cgroup` with a small tmpfs
(`ro,nosuid,nodev,noexec`, mode 0555, 4 KiB) and mounts the view on the cover. The supervisor
keeps the cover:

- It fails closed. The cover and the view are one step of the child's plan, not tolerant: a
  failure of either is E0323, never a container without a view. The container cannot unmount
  the cover or the view, because the seccomp filter denies `umount2` and the whole mount family.
- It is one mount sequence in every network mode, and the VM measured it in all three. The
  cover is mounted in the isolated modes too, where nothing needs it; that costs one line of
  the mount table.
- Binding the non-`fs/cgroup` parts of `/sys` one by one would be a list of host paths to keep
  in step with every kernel.

## What a container sees under `--net host`

`/proc/self/mountinfo` lists three mounts on `/sys/fs/cgroup`, in order: the host's cgroup2,
which came with the recursive bind of `/sys` (its root reads `/../../../../..`, the host's root
seen from the container's cgroup namespace), the cover, and the view, with root `/`. The brief
says mountinfo lists cgroup2 at `/sys/fs/cgroup` with root `/`; that is the last entry, which is
what a path lookup reaches. A tool that takes the *first* cgroup2 line of mountinfo for that
path, rather than the last, reads the host's entry and finds no files at the joined path. The
four runtimes measured (Java, Go, .NET, Node) all take the last. The host's tree is not
reachable: the cover and the view hide it.

## How it is tested

- `host.MountKind.cgroup_cover` is a mount request of its own, so the simulator sees it. The
  simulator refuses a cgroup2 on the `fs/cgroup` of a bound /sys with `EBUSY` unless the cover is
  there, which the run reports as E0323. Removing the cover from the child's step fails the
  simulated runs with `--net host` and the run fuzzer.
- The read-only bit of every fresh mount comes from `host.mounted_read_only`: the simulator
  records it from there, and a test in `src/host_real.zig` checks the real host's mount flags
  against it and checks the view's and the cover's `RDONLY`, `NOSUID`, `NODEV` and `NOEXEC`.
