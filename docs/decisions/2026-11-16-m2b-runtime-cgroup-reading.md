# M2b: what language runtimes read from the cgroup, before the cgroup view

*Decided 2026-11-16, by the slice (M2b slice 1), from a measurement.*

The M2b brief ([item 7](../briefs/M2b-workload-knobs.md)) asks for this measurement before any code
for the cgroup namespace and the read-only cgroup2 view. It confirms the brief's expectations:
under the default network a runtime finds no cgroup and sizes itself from the host; under
`--net host` it finds the limits, but through the host's whole cgroup tree. Slice 3 repeats this
table as the after.

## How it was measured

`demo-m2b-probe` ([run 43931483466](https://github.com/Zigbox/zigbox/actions/runs/43931483466)) in the VM: Ubuntu 24.04, kernel 6.8.0-147-generic,
2 CPUs, about 2 GiB of RAM. Each runtime ran as the ordinary user `demo` under
`zbx run --memory 256m --cpus 1.5`, from an Alpine 3.20 root with `openjdk21-jre-headless`
(21.0.8), `nodejs`, the .NET 8 SDK (the probe is published, then run with `dotnet`) and Go
1.25.0, with `strace -f -e trace=open,openat,statfs` inside the container.

## What each runtime reports

| Runtime | Default network | `--net host` |
| --- | --- | --- |
| Java: `MaxHeapSize` | 515899392 (492 MiB, a quarter of host RAM) | 132120576 (126 MiB) |
| Java: `-XshowSettings:system` | "No metrics available for this platform" | cgroupv2, 2 effective CPUs, quota 150000/100000, memory limit 256 MiB |
| Go: `GOMAXPROCS` | 2 | 2 |
| .NET: `TotalAvailableMemoryBytes` | 2063208448 (host RAM) | 201326592 (192 MiB, 75 % of the limit) |
| .NET: `ProcessorCount` | 2 | 2 |
| Node: `constrainedMemory()` | 0 (none found) | 268435456 |
| Node: `heap_size_limit` | 1056964608 | 271581184 |
| Node: `availableParallelism()` | 2 | 2 |

## What each runtime reads

- **The container's view today.** Default network: `/sys/fs/cgroup` is an empty directory on a
  fresh sysfs, and `mountinfo` lists no cgroup2. `--net host`: the host's cgroup2 is mounted
  read-only at `/sys/fs/cgroup` (the bound host `/sys`), and `/proc/self/cgroup` is the scope's
  full host path, `0::/user.slice/user-1000.slice/user@1000.service/app.slice/zbx-zbx-<id>.scope`.
- **Java (HotSpot 21)** opens `/proc/cgroups`, `/proc/self/cgroup` and `/proc/self/mountinfo`,
  then, when it finds the mount, `<mount>/<path>/cpu.max` and `memory.max`.
- **Go 1.25** opens `/proc/self/mountinfo` first and stops when it lists no cgroup2. With the
  mount it reads `/proc/self/cgroup` and `cpu.max`. It never reads `memory.max`.
- **.NET 8** reads `mountinfo` and `statfs("/sys/fs/cgroup")` (`SYSFS_MAGIC` by default,
  `CGROUP2_SUPER_MAGIC` with `--net host`); with the mount, `/proc/self/cgroup`, then
  `cpu.max`, `memory.max`, `memory.current` and `memory.stat`.
- **Node** reads `/proc/self/cgroup` and opens `/sys/fs/cgroup/<path>/memory.max` and
  `memory.high` directly, without `mountinfo`. By default both fail with `ENOENT`.

## The decision

The brief's design stands: a private cgroup namespace whose root is the scope, and a fresh
read-only cgroup2 mounted at `/sys/fs/cgroup` in every scoped run, whatever the network mode.
Each runtime above then reads `/proc/self/cgroup` as `0::/` and finds the scope's files at
the mount's root, which is the path every one of them already takes.

## Limits of the measurement

- The VM has 2 CPUs, so `--cpus 1.5` rounds up to the host's count: `GOMAXPROCS`,
  `ProcessorCount` and `availableParallelism` read 2 either way. Only Java's report shows the
  quota. Slice 3's after-measurement should use `--cpus 1` so a CPU limit is visible.
- The brief asks for the 0.5.2 release binary. The probe ran the branch's binary, which reports
  `zbx 0.5.2` and differs from the release only in docs and the probe itself.
- The brief names `dotnet8-runtime` and an Alpine `go`. Alpine 3.20 ships Go 1.22, which predates
  cgroup-aware `GOMAXPROCS`, so Go 1.25.0 came from go.dev. The .NET SDK was installed so the
  probe could be built in the container.
