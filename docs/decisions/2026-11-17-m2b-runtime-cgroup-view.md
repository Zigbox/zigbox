# M2b: what language runtimes read from the cgroup, with the cgroup view

*Decided 2026-11-17, by the slice (M2b slice 2), from a measurement.*

This is the after-measurement for [the before table](2026-11-16-m2b-runtime-cgroup-reading.md),
taken under slice 2's binary: a cgroup namespace of the container's own and a read-only cgroup2
on `/sys/fs/cgroup` in every scoped run, in all three network modes. Every runtime now finds the
container's limits, and finds the same ones whatever the network mode.

## How it was measured

`demo-m2b-probe` ([run 44016357566](https://github.com/Zigbox/zigbox/actions/runs/44016357566)),
on commit f33e0e2, in the same VM as before (Ubuntu 24.04, 2 CPUs, about 2 GiB of RAM), as
the user `demo`, with the same Alpine 3.20 root and runtimes (OpenJDK 21.0.8, Node, .NET 8,
Go 1.25.0) and the same `strace`. The one change from the before table is the limit:
`zbx run --memory 256m --cpus 1` rather than `--cpus 1.5`, as that table asked, so that a CPU
limit below the VM's 2 CPUs can show. The probe also ran under `--net user` this time.

## What each runtime reports

The three network modes (default, `--net host`, `--net user`) gave identical numbers for every
runtime, so one column stands for all three.

| Runtime | Before, default network | Before, `--net host` | After, every mode |
| --- | --- | --- | --- |
| Java: `MaxHeapSize` | 515899392 (492 MiB) | 132120576 (126 MiB) | 132120576 (126 MiB) |
| Java: `-XshowSettings:system` | "No metrics available" | cgroupv2, 2 CPUs, quota 150000/100000, 256 MiB | cgroupv2, 1 CPU, quota 100000/100000, 256 MiB, pids 2315 |
| Go: `GOMAXPROCS` | 2 | 2 | 2 |
| .NET: `TotalAvailableMemoryBytes` | 2063208448 (host RAM) | 201326592 (192 MiB) | 201326592 (192 MiB) |
| .NET: `ProcessorCount` | 2 | 2 | 1 |
| Node: `constrainedMemory()` | 0 | 268435456 | 268435456 |
| Node: `heap_size_limit` | 1056964608 | 271581184 | 271581184 |
| Node: `availableParallelism()` | 2 | 2 | 2 |

The before columns ran with `--cpus 1.5`, so their CPU rows are not comparable with the after
column's; the memory rows are.

## What the container sees

- `/proc/self/cgroup` reads `0::/` in every mode: the namespace's root is the scope.
- `/sys/fs/cgroup` is a cgroup2, `ro,nosuid,nodev,noexec`, whose files are the scope's own:
  `memory.max` 268435456, `cpu.max` `100000 100000`, `pids.max` 2315. `touch` on it fails with
  "Read-only file system".
- Under `--net host`, `mountinfo` also lists the host's cgroup2 that came with the bound `/sys`,
  with the root `/../../../../..` (the host's root, seen from the namespace), below the view.
  Every runtime above took the view, the last mount on that path.
- The runtimes read the same files as before (Java `cpu.max` and `memory.max`; Go `cpu.max`;
  .NET `cpu.max`, `memory.max`, `memory.current`, `memory.stat`; Node `memory.max` and
  `memory.high`), now at the mount's root (`/sys/fs/cgroup/...`) in every mode.

## Readings that are the runtime's, not the view's

- **Go** reads `cpu.max` and still reports `GOMAXPROCS` 2: Go 1.25 does not set it below 2 from
  a cgroup limit. It never reads `memory.max`, so `GOMEMLIMIT` stays unset, as the before
  table found.
- **Node**'s `availableParallelism()` counts the CPUs it may run on, not the quota, so it stays 2.
- **Java** uses the quota, as does **.NET**: both report 1 CPU.

## Found by this measurement

The first after run (on cdd8ae4) failed every `--net host` run with E0323. Below the bound host
`/sys`, the host's own cgroup2 is already mounted on `fs/cgroup`. The kernel refuses that same
superblock again on the root of an existing mount of it (`EBUSY`). The real host now covers the
target with a small read-only tmpfs before mounting the view (`mount_cgroup2` in
`src/host_real.zig`). The simulator does not model that refusal. demo-m2's provisioning
(`apk add` under `--net host`) is where the demos caught it.

## The decision

The design of slice 1's decision stands and is now measured. No runtime needs a further file or
path from the view.
