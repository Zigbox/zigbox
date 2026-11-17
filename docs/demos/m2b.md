# M2b demo: workload knobs

The common server workloads start under zbx without hacks: `--ulimit`, `--shm-size`,
`--sysctl`, `--require-host`, a read-only cgroup2 view of the container's own scope, and the NUMA
memory-policy calls. `zig build demo-m2b` (KVM; `-Daccel=tcg` without it) runs the steps below
in an Ubuntu 24.04 VM as the ordinary user `demo` (uid 1000), with the pinned Alpine minirootfs
from M1/M2. The harness is `src/testing/vm/main_m2b.zig`; every assertion is a unit-tested
function in `checks_m2b.zig` (or M2's `checks_m2.zig`). CI runs it as the `demo-m2b` job; a push
to `vm/m2b-<anything>` runs it alone (`vm.yml`).

## Setup

- The VM's privileged setup (root, inside the VM only) installs this `zbx` and the v0.5.2
  release binary (`zbx-old`, for the upgrade test and the NUMA "before"), unpacks the rootfs as
  `demo` into `/home/demo/alpine`, and quiets the kernel's console (`dmesg -n 1`; every OOM kill
  prints a report there).
- `numactl` goes into the rootfs by `apk` inside zbx, as M2 provisions `stress-ng`:
  `zbx run --net host --rootfs ./alpine -- apk add --no-cache numactl-tools` (with
  `/etc/resolv.conf` and the http v3.20 repositories written into the rootfs first).
- `numa-probe` (`src/testing/vm/numa_probe/`, static, no libc, built by `build.zig`) is copied
  in as `/numa-probe`. It makes each of `mbind`, `set_mempolicy`, `set_mempolicy_home_node`,
  `get_mempolicy`, `move_pages` and `migrate_pages` once and prints `<call> ok` or
  `<call> E<NAME>`.
- `sysctl -w vm.max_map_count=65530`: the kernel's default. Ubuntu 24.04 ships 1048576, which
  would hide step 4's refusal.

## The steps by hand

Run as an ordinary user with a systemd user manager (the scope needs it), from a directory with
an Alpine minirootfs in `./alpine`.

1. **rlimits.**
   ```
   $ zbx run --rootfs ./alpine --ulimit nofile=4096:8192 -- sh -c 'ulimit -n; ulimit -Hn'
   4096
   8192
   $ ulimit -Hn
   524288
   $ zbx run --rootfs ./alpine --ulimit nofile=524289 -- true
   error[ZBX-E0311]: --ulimit is above your own hard limit
   ```
   exit 125, before anything starts. The cause names your hard limit; the fixes are the
   `/etc/security/limits.conf` line (log in again after) and `systemctl edit user@<uid>.service`,
   whose sentence names the line to add, `LimitNOFILE=<value>` under `[Service]` (also in
   `--output json`'s `context.unit`).
2. **`/dev/shm`.**
   ```
   $ zbx run --rootfs ./alpine --shm-size 256m -- df -k /dev/shm
   Filesystem           1K-blocks      Used Available Use% Mounted on
   shm                     262144         0    262144   0% /dev/shm
   $ zbx run --rootfs ./alpine --memory 128m --shm-size 256m -- true
   error[ZBX-E0314]: --shm-size is larger than --memory
   ```
   The cause: `/dev/shm`'s pages are charged to the container's memory limit.
3. **Sysctls.**
   ```
   $ zbx run --rootfs ./alpine --sysctl net.core.somaxconn=8192 -- cat /proc/sys/net/core/somaxconn
   8192
   $ zbx run --rootfs ./alpine --sysctl vm.max_map_count=262144 -- true
   error[ZBX-E0316]: a --sysctl is a host setting
   $ zbx run --rootfs ./alpine --net host --sysctl net.core.somaxconn=8192 -- true
   error[ZBX-E0317]: a --sysctl net.* key with --net host
   ```
   E0316's fixes are `sudo sysctl -w` on the host and `--require-host`; E0317's is to drop
   `--net host`.
4. **Host preflight.**
   ```
   $ zbx run --rootfs ./alpine --require-host 'vm.max_map_count>=262144' -- true
   error[ZBX-E0319]: vm.max_map_count is 65530, needs >=262144
     fix    set it on the host (a file in /etc/sysctl.d/ keeps it across boots):   sudo sysctl -w vm.max_map_count=262144
   $ zbx doctor
   ok   host-settings  vm.max_map_count 65530, fs.aio-max-nr ..., vm.overcommit_memory ..., transparent_hugepage ...
   $ sudo sysctl -w vm.max_map_count=262144
   $ zbx run --rootfs ./alpine --require-host 'vm.max_map_count>=262144' -- true; echo $?
   0
   ```
5. **The cgroup view.**
   ```
   $ zbx run --rootfs ./alpine --memory 256m --cpus 1.5 -- \
       sh -c 'cat /proc/self/cgroup /sys/fs/cgroup/memory.max /sys/fs/cgroup/cpu.max'
   0::/
   268435456
   150000 100000
   $ zbx run --rootfs ./alpine --memory 256m -- sh -c 'echo 1 > /sys/fs/cgroup/memory.max'
   sh: can't create /sys/fs/cgroup/memory.max: Read-only file system
   ```
6. **NUMA.**
   ```
   $ zbx run --rootfs ./alpine -- numactl --interleave=all true; echo $?
   0
   $ zbx run --rootfs ./alpine -- /numa-probe
   mbind ok
   set_mempolicy ok
   set_mempolicy_home_node ok
   get_mempolicy ok
   move_pages EPERM
   migrate_pages EPERM
   ```
   The same `numactl` under v0.5.2, recorded by the demo:
   ```
   $ zbx-old run --rootfs ./alpine -- numactl --interleave=all true
   set_mempolicy: Operation not permitted
   setting interleave mask: Operation not permitted
   $ echo $?
   1
   ```

The demo uses `--net none` (the default) explicitly in steps 1 to 6 so that no network note
mixes into the lines it compares.

## The checks beyond the six steps

- **`/dev/shm` fills the memory limit.** `--memory 64m --shm-size 64m -- dd if=/dev/zero
  of=/dev/shm/fill bs=1M count=100` is OOM-killed: exit 137 and M2's last line
  `zbx: killed: out of memory (limit 64 MiB)`.
- **The host's cgroup tree is not reachable.** Under `--net host` (the host's `/sys` is bound)
  and under the default, `/sys/fs/cgroup` lists only the scope's own files (no `*.slice`,
  `init.scope` or `*.service`), `memory.max` is the limit, and `/proc/self/cgroup` is `0::/`.
  Mountinfo is not checked (see the cuts).
- **The scripted agent.** Steps 1 to 5 again with `--output json` and `zbx explain` only: the
  knobs read back from the `container_exit` line (`ulimits`, `shm_bytes`, `sysctls`); each
  refusal's code, context (`asked`, `hard`, `unit`; `size`; `sysctl`; `key`, `host`, `needed`)
  and fix commands read from the diagnostic's fields; `zbx explain <code> --output json` agrees
  with each. The agent applies E0319's root fix (the harness stands in for the person with
  sudo), runs E0319's second fix (`zbx doctor`, as JSON) to see 262144, and reruns to exit 0.
- **The upgrade test.** v0.5.2 starts three detached containers (`zbx-old run -d ... -- sleep
  300`): plain (`m2bold`), with `--net user --publish 18080:80` (`m2bpub`; v0.5.2 has no `-p`) and
  with `--device /dev/fuse` (`m2bdev`). This `zbx` lists each running with `ps --output json`
  (`m2bpub` under `user` with its one forward), reads each run record (version 9, 9 with its forward
  in `.publish`, and 10 with its `.devices` line), stops each with `zbx stop`, and `ps --all
  --output json` then lists none of them running.

## Language runtimes, before and after

From `docs/decisions/2026-11-16-m2b-runtime-cgroup-reading.md` (v0.5.2, `--memory 256m --cpus
1.5`) and `docs/decisions/2026-11-17-m2b-runtime-cgroup-view.md` (slice 2, `--memory 256m --cpus
1`, the same numbers in the default network, `--net host` and `--net user`). The CPU rows are
not comparable across the two limits; the memory rows are.

| Runtime | Before, default network | Before, `--net host` | After, every mode |
| --- | --- | --- | --- |
| Java: `MaxHeapSize` | 515899392 (492 MiB, host RAM / 4) | 132120576 (126 MiB) | 132120576 (126 MiB) |
| Java: `-XshowSettings:system` | "No metrics available" | cgroupv2, 2 CPUs, 256 MiB | cgroupv2, 1 CPU, 256 MiB |
| Go: `GOMAXPROCS` | 2 | 2 | 2 |
| .NET: `TotalAvailableMemoryBytes` | 2063208448 (host RAM) | 201326592 (192 MiB) | 201326592 (192 MiB) |
| .NET: `ProcessorCount` | 2 | 2 | 1 |
| Node: `constrainedMemory()` | 0 | 268435456 | 268435456 |
| Node: `heap_size_limit` | 1056964608 | 271581184 | 271581184 |
| Node: `availableParallelism()` | 2 | 2 | 2 |

Before, the default network had no cgroup2 mounted, so Java, .NET and Node sized themselves from
the host (a JVM heap a quarter of host RAM, which `--memory` OOM-kills); `--net host` got the
right numbers only by reading the host's whole tree. After, every mode sees the scope alone.
This is a change in what a container sees, accepted as a default; podman and Docker on cgroup v2
do the same with a private cgroup namespace.

## Cuts and deviations

- **Step 3 sets `net.core.somaxconn` to 8192, not the brief's 4096** (slice 3). 4096 is the
  VM kernel's default (since Linux 5.4), so the brief's step would pass with the knob doing
  nothing ([decision](../decisions/2026-11-16-m2b-sysctl-keys.md)).
- **The view check runs under `--net host`, `--net none` and `--net user`** (slice 3 fix). Under
  `--net user` the demo also reads a `net` sysctl back after pasta has set the network up, so a
  key pasta reset would show there.
- **The upgrade reads a version-10 record from `--device`, not from `--publish`** (slice 3 fix).
  v0.5.2 writes version 10 only for a run with a listener or devices; a `--publish` run (v0.5.2 has
  no `-p`) is version 9 with its forward in `.publish`. The demo starts both, so it reads a v9
  record with a forward and a v10 record. `/dev/fuse` because v0.5.2 binds `/dev/null` and the other
  standard devices itself and refuses them as `--device`.
- **ci-changes.sh has no separate rules for the policy files, the plan, the child or doctor**
  (slice 3). They fall through to the rule that selects every demo, `m2b` among them; the table
  test pins that for `sysctls.zon`, `plan.zig` and `doctor.zig`.

- **The cgroup view under `--net host` sits on a cover, not on a partial bind of /sys**
  (slice 2). The brief's fallback, if the view could not be mounted over the bound host `/sys`,
  was to bind only the parts of `/sys` that are not `fs/cgroup`. Slice 2 instead covers
  `/sys/fs/cgroup` with a small read-only tmpfs and mounts the view on it, in every network mode
  ([decision](../decisions/2026-11-17-m2b-cgroup-cover.md)).
- **Under `--net host`, the host's cgroup2 stays listed in mountinfo** beneath the cover and the
  view, with the root `/../../../../..`. The view is the last entry on `/sys/fs/cgroup`, with root
  `/`, and the only one a path lookup reaches. A tool that takes the first cgroup2 line for that
  path reads the host's entry instead.

## Upgrade notes

- **`zbx doctor --json` (`zbx.doctor/1`): `checks` grows.** Slice 2 adds the `host-settings`
  check, in the middle of the array, and a new value of the `id` enum; earlier checks after it
  move one place down. Readers should find a check by its `id`, never by its position, and accept
  `id` values they do not know. The new top-level `host_settings` object is additive. Upgrading
  `zbx` alone is enough; no stored record changes.
- **`zbx exec` joins the container's cgroup namespace** (slice 2). An exec'd command in a scoped
  container reads `0::/` in `/proc/self/cgroup` and sees the view, as the container's own command
  does. A container started by a release before slice 2 has no cgroup namespace of its own, so
  an exec into it stays in zbx's, as before; restart the container to give it one. demo-m6b's
  EXEC 3 checks for `0::/` now, where it checked for the scope's host path before.

## Not in M2b

- **Adding capabilities is parked:** `IPC_LOCK` (Vault's `mlock`), `NET_ADMIN` and `NET_RAW` in
  the container's own network namespace (VPNs, mesh init containers) and `SYS_NICE`
  (ClickHouse). It is an open question in the spec.
- **`--device /dev/net/tun` is accepted but unusable.** The node is there, but `TUNSETIFF`
  needs `CAP_NET_ADMIN`, which the container does not have, so a VPN client fails with
  `Operation not permitted`. Refusing it is deferred until the capability question is decided
  (supervisor, 2026-11-16). The M10 device notes say the same.
- Non-goals (spec): io_uring; cpuset pinning, `io.max`/`io.weight` and hugetlb; nested
  containers.
- Setting any host value: `--require-host` only checks. On a Mac, `--require-host` checks the
  guest's kernel.
- rlimits other than `nofile`, `nproc`, `memlock` and `stack`.

## Failure modes

- **A host hard limit too low.** A rootless run cannot raise a hard limit above the invoking
  user's, so `--ulimit` above it is E0311. Raise it for login sessions in
  `/etc/security/limits.conf` (`<user> hard nofile 1048576`), then log in again; for the
  systemd user manager, which starts the services and `systemd-run` units of that user,
  `sudo systemctl edit user@<uid>.service` and add `LimitNOFILE=1048576` under `[Service]`, then
  `sudo systemctl restart user@<uid>.service` (or reboot). The two are separate: a shell from
  `ssh` gets the first, a user service the second. The user manager's `memlock` default is often
  8 MiB.
- **`nproc` counts the user's own processes.** The kernel counts processes per real user, and
  the container's root is the invoking user, so `--ulimit nproc=N` counts that user's processes
  outside the container too. A value below them makes the next `fork` fail with `EAGAIN`; with
  `--user`, the switch itself can fail (E0312's explanation says so).
- **`/dev/shm` fills the memory limit.** tmpfs pages are charged to the cgroup of the task that
  touches them, so a full `/dev/shm` is memory: with `--memory`, filling it ends in an OOM kill
  (the extra check above). `--shm-size` larger than `--memory` is refused (E0314); the default
  64 MiB is not checked against a smaller `--memory`.
- **A sysctl that pasta or the kernel resets.** zbx writes each `--sysctl` once, in the child,
  before the program starts. pasta sets addresses and routes, not sysctls, and kept all 15 `net`
  keys in the slice 1 check (demo-m2b reads `net.core.somaxconn` back under `--net user` on
  every run); but anything that writes the key later inside the container (the
  program, a network helper, a kernel event such as an interface coming up for the per-interface
  keys) wins, and zbx does not re-check. Read the value back from `/proc/sys` inside if it
  matters.
- **A host setting changed back after a reboot.** `sudo sysctl -w` lasts until the next boot.
  To keep it, write it to a file in `/etc/sysctl.d/` (`echo vm.max_map_count=262144 | sudo tee
  /etc/sysctl.d/90-zbx.conf`); E0319's fix line says so. `--require-host` then catches a host
  where it did not stick.
- **A runtime that still ignores the cgroup view.** The view gives the limits at
  `/sys/fs/cgroup` with `/proc/self/cgroup` `0::/`. A runtime that reads neither, or reads only
  some files, still sizes itself from the host: Go never reads `memory.max` (set `GOMEMLIMIT`
  yourself) and does not set `GOMAXPROCS` below 2; Node's `availableParallelism()` counts CPUs,
  not the quota. Under `--net host`, a tool that takes the first cgroup2 line of `mountinfo` for
  `/sys/fs/cgroup` reads the host's entry (see the cuts). A run without a scope (`W0301`) gets
  no view at all.
- **`pids.max` shows one more than `--pids`.** The scope holds the container and zbx's keeper
  process, so its `TasksMax` is `--pids` plus one, and that is what `pids.max` reads inside.
- **`/proc/sys` is not masked.** The container's processes can read every key under
  `/proc/sys`, the host's included; they cannot write any after the capability drop. Masking it
  read-only is later hardening, not an M2b knob.
- **`zbx exec` does not get the container's `--ulimit`.** An exec runs its own plan, so its
  process inherits the caller's limits.
