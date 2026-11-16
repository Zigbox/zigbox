# Brief: M2b · Workload knobs

Read these first:
- `AGENTS.md`, `REVIEW.md`, `docs/STYLE.md` and `DIAGNOSTICS.md`.
- The M2b section of the live design doc (snapshot: `docs/SPEC.md`, "M2b · Workload knobs"), its "Non-goals" and its "Open questions". If the live doc disagrees with this brief, stop and report; do not pick one.
- `docs/decisions/2026-11-16-m2b-workload-knobs.md` (the owner's choice and the supervisor defaults), `docs/briefs/M2-limits.md` (the scope, hardening order and library contract this extends), and `docs/demos/m2.md`.
- The code this changes:
  - `src/runtime/policy/seccomp.zon` and `capabilities.zon`, and `src/runtime/seccomp.zig`.
  - `src/runtime/scope.zig` and `src/dbus/systemd.zig`.
  - `src/runtime/spec.zig`, where `Spec` and `Limits` are re-exported by `src/zigbox.zig`.
  - `src/runtime/plan.zig`: `push_sys` and `mount_proc`.
  - `src/runtime/child.zig` and `src/runtime/session.zig`.
  - `src/host_real.zig`: the `/dev/shm` mount near `shm_tmpfs`, and the `clone_flags` near line 1701.
  - The `zbx run` options in `src/cli.zig`.
  - `src/doctor.zig`.

M2b adds knobs to M2. It does not change M2's model: one transient systemd user scope per container, capabilities from the allowlist, the seccomp allowlist, `no_new_privs`, and all namespace work in the single-threaded child before `execve`. Every earlier demo must keep passing. No capability is added (that is parked, below).

## Goal and demo (from the live doc)

The common server workloads people run on Kubernetes start under zbx without hacks: databases, search engines, JVM, Go, .NET and Node services. The image needs no wrapper script, no `--privileged` and no host tweak that zbx did not name.

The demo uses the Alpine rootfs from the M1/M2 demos, with `numactl` provisioned by `apk` inside a `zbx run` during setup, as M2 provisions `stress-ng`. It also uses `numa-probe`, a small static Zig test helper from `src/testing/vm/` copied into the rootfs. It runs as the VM's ordinary user.

1. **rlimits.**
   - `zbx run --rootfs ./alpine --ulimit nofile=4096:8192 -- sh -c 'ulimit -n; ulimit -Hn'` prints `4096` and `8192`.
   - `--ulimit nofile=N`, with `N` one above the presenter's `ulimit -Hn`, is refused with one line. The line names the user's hard limit and the fix: `limits.conf`, or `LimitNOFILE=` for the systemd user manager.
2. **`/dev/shm`.**
   - `zbx run --rootfs ./alpine --shm-size 256m -- df -k /dev/shm` shows `262144` 1K-blocks.
   - `--memory 128m --shm-size 256m` is refused before start, with one line saying `/dev/shm` counts against `--memory`.
3. **Sysctls.**
   - `zbx run --rootfs ./alpine --sysctl net.core.somaxconn=4096 -- cat /proc/sys/net/core/somaxconn` prints `4096`.
   - `--sysctl vm.max_map_count=262144` is refused with one line saying it is a host setting and pointing at `--require-host`.
   - `--net host --sysctl net.core.somaxconn=4096` is refused with one line saying `net.*` keys need the container's own network.
4. **Host preflight.**
   - The VM's privileged setup sets `vm.max_map_count=65530`. That is the kernel's default; Ubuntu 24.04 ships 1048576, which would hide the refusal.
   - `zbx run --rootfs ./alpine --require-host 'vm.max_map_count>=262144' -- true` is refused before anything starts. The one line names the setting, the host value `65530`, the needed value and the fix `sudo sysctl -w vm.max_map_count=262144`.
   - `zbx doctor` shows the same value in its host-settings line.
   - The setup applies the fix, and the same run exits 0.
5. **The cgroup view.**
   - `zbx run --rootfs ./alpine --memory 256m --cpus 1.5 -- sh -c 'cat /proc/self/cgroup /sys/fs/cgroup/memory.max /sys/fs/cgroup/cpu.max'` prints `0::/`, `268435456` and `150000 100000`.
   - `echo 1 > /sys/fs/cgroup/memory.max` inside fails: the view is read-only.
6. **NUMA.**
   - `zbx run --rootfs ./alpine -- numactl --interleave=all true` exits 0. With 0.5.x it fails with `set_mempolicy: Operation not permitted`; record that output in `docs/demos/m2b.md`.
   - `zbx run --rootfs ./alpine -- /numa-probe` prints `mbind ok`, `set_mempolicy ok`, `set_mempolicy_home_node ok` and `get_mempolicy ok`.
   - The same probe prints `move_pages EPERM` and `migrate_pages EPERM`, because those stay out.

Acceptance criteria:
- Each knob reaches the workload exactly as asked. The values are read back from inside the container: `/proc/self/limits`, `df`, `/proc/sys`, and `/sys/fs/cgroup`.
- Nothing is clamped silently. Every refusal is one coded line naming what was asked, what the host allows and the fix, before any process starts (exit 125).
- With no new flag, a run behaves as in 0.5.x, except for:
  - the NUMA calls, now allowed;
  - the cgroup view, below.
- The cgroup view shows only the container's own scope, read-only, whether the run uses `--net none`, `--net user` or `--net host`. The host's cgroup tree is not visible in any mode, which closes today's `--net host` exposure.
- `zbx run --plan` shows every new step.
- `--output json` carries the new knobs in `run` and `ps`, with the schemas bumped.
- The library takes the same knobs on `Spec` (below).
- The production-readiness checklist:
  - **Upgrade test.** The new binary reads run records written by the previous tagged release, and `demo-m2` still passes unchanged.
  - **Stable diagnostics.** Every new failure path has a registered code in `E0310`–`E0324`, with a fix, a golden and an error page. No existing code changes its meaning.
  - **Documented failure modes.** `docs/demos/m2b.md` lists them (slice 3).
  - **Agent test.** A scripted agent runs steps 1 to 5 using only `--output json` and `zbx explain`. It reads the refused value, the host value and the fix command from the diagnostic's fields, never from prose.

## Fixed decisions

### 1. `--ulimit` (rlimits)

- **Syntax.** `--ulimit <name>=<soft>[:<hard>]`, repeatable, at most once per name.
  - Names: `nofile`, `nproc`, `memlock` and `stack`. Any other name is a user diagnostic that lists the four.
  - Values: `nofile` and `nproc` take counts. `memlock` and `stack` take sizes in `--memory`'s syntax (`k`/`m`/`g`, binary units). Any of them may be `unlimited`.
  - A single value sets both soft and hard. That is Docker's meaning, and the least surprising one for `nofile=65536`.
  - A soft limit above the hard one is a user diagnostic.
- **Bounded by the invoking user, never clamped.**
  - The parent reads its own limits with `prlimit64` before it starts anything.
  - A hard value above the parent's hard limit is refused. Raising a hard limit needs `CAP_SYS_RESOURCE` in the initial user namespace, which a rootless run never has.
  - The refusal is one coded line. It names the resource, the value asked for and the user's hard limit. Its fix has two parts: `/etc/security/limits.conf` for login sessions, and `LimitNOFILE=` (or `LimitNPROC=`, `LimitMEMLOCK=`, `LimitSTACK=`) on `user@<uid>.service` for the systemd user manager. In both cases the user logs in again afterwards.
  - Never set a lower value than was asked to make a run work.
- **Default: inherit.** Without `--ulimit`, the container inherits the parent's limits, as today. Do not change that.
- **Where.** In the child, as a new plan step: after the mounts, before the capability drop and seccomp. It calls `setrlimit` (`prlimit64` on self) for each requested resource. A failure here should not happen after the parent's check, and it is a coded environment diagnostic naming the step.
- **Failure modes to document.**
  - `nproc` is counted per real user. The container's root maps to the invoking user, so the count includes that user's processes outside the container.
  - The user manager's `memlock` default is often 8 MiB.

### 2. `--shm-size`

- **Syntax.** `--shm-size <size>` in `--memory`'s syntax. The default stays 64 MiB. Replace the literal `size=65536k` in `host_real.zig` with a named constant, `shm_bytes_default`, in `constants.zig`.
- **Bounds.**
  - The size must be at least one page.
  - With `--memory`, it is refused if larger than `--memory`. Equal is allowed.
  - Without `--memory`, it is refused above the host's `MemTotal`. This is a supervisor default; record it.
  - The refusal says that `/dev/shm` pages are charged to the container's memory limit.
- **Accounting.** tmpfs pages are charged to the memory cgroup of the task that touches them, so `/dev/shm` already counts against `--memory`. Assert it in the VM: a run with `--memory 64m --shm-size 64m` that fills `/dev/shm` with `dd` is OOM-killed with the M2 exit report, not left with a full host.
- The mount keeps its flags (`nosuid,nodev,noexec`, mode 1777). Only `size=` changes.

### 3. NUMA memory policy in the seccomp allowlist

- **Add `mbind`, `set_mempolicy` and `set_mempolicy_home_node` to the memory group in `seccomp.zon`, unconditionally.** Give a `why` naming MySQL/MariaDB (`innodb_numa_interleave` and `mbind: Operation not permitted`), `numactl --interleave` for MongoDB, and ClickHouse.
- `set_mempolicy_home_node` is new in Linux 5.17. Check that `std.os.linux.SYS` names it on both architectures, because the build fails otherwise (`seccomp.zon`'s rule). If std lacks it, stop and ask; do not hard-code a number.
- **Docker gates these on `CAP_SYS_NICE`.** moby's default profile allows all four only in a block that includes that capability, so a default `docker run` refuses `mbind` too. The usual fix there is `--cap-add SYS_NICE`. zbx allows them without the capability, as it already allows `get_mempolicy`. This is safe because the kernel still demands `CAP_SYS_NICE` for the privileged flag (`MPOL_MF_MOVE_ALL`), which the container does not have. Say so in the `why`.
- **`move_pages` and `migrate_pages` stay out.**
  - Docker and containerd do not allow them.
  - Both can act on another process's pages.
  - The motivating workloads set a policy; they do not move pages.
  - **Confirm it in slice 1:** on the VM host, outside zbx, run `strace -f -e trace=mbind,set_mempolicy,set_mempolicy_home_node,get_mempolicy,move_pages,migrate_pages` over the start of `mariadbd --innodb-numa-interleave=1`, `numactl --interleave=all mongod --version` (or a short `mongod` start), and `clickhouse-server` (Alpine packages or upstream static binaries; if one is not available, say so).
  - Record the calls seen in `docs/decisions/YYYY-MM-DD-m2b-numa-syscalls.md`. If either call shows up, stop and ask before adding it.
- Tests: an allow case per new syscall and a deny case for `move_pages` and `migrate_pages`, in the BPF interpreter tests. Also extend the seccomp-compiler fuzzer's corpus with the new names.

### 4. `--sysctl` (namespaced sysctls only)

- **Syntax.** `--sysctl <key>=<value>`, repeatable, at most `sysctls_max` (16) per run.
  - Keys are in dot form.
  - A value is printable ASCII, without a newline, of at most `sysctl_value_bytes_max` (256) bytes.
  - Both bounds are new constants; record them.
- **The allowlist is a checked-in, reviewed file, `src/runtime/policy/sysctls.zon`,** like the seccomp profile. Each entry names its key, its namespace (`ipc` or `net`) and a `why`. The references are Kubernetes' safe set and its "unsafe but namespaced" set. Start from:
  - **ipc:**
    - `kernel.shmmax`, `kernel.shmall`, `kernel.shmmni` and `kernel.shm_rmid_forced`;
    - `kernel.msgmax`, `kernel.msgmnb` and `kernel.msgmni`;
    - `kernel.sem`;
    - `fs.mqueue.msg_max`, `fs.mqueue.msgsize_max`, `fs.mqueue.queues_max`, `fs.mqueue.msg_default` and `fs.mqueue.msgsize_default`.
    - Not `*_next_id`: those exist for checkpoint/restore, which is a non-goal.
  - **net:**
    - Kubernetes' safe set: `net.ipv4.ip_local_port_range`, `net.ipv4.ip_local_reserved_ports`, `net.ipv4.ip_unprivileged_port_start`, `net.ipv4.ping_group_range`, `net.ipv4.tcp_syncookies`, `net.ipv4.tcp_keepalive_time`, `net.ipv4.tcp_keepalive_intvl`, `net.ipv4.tcp_keepalive_probes`, `net.ipv4.tcp_fin_timeout`, `net.ipv4.tcp_rmem` and `net.ipv4.tcp_wmem`.
    - Common namespaced keys: `net.core.somaxconn`, `net.ipv4.tcp_max_syn_backlog`, `net.ipv4.tcp_tw_reuse` and `net.ipv6.conf.all.disable_ipv6`.
  - Verify each key in the VM in slice 1. It must be per-namespace on the VM's kernel, and writable from the container's user namespace. A key that is not drops out of the file, with the reason in the demo document. No key outside these two namespaces is ever added.
- **Refusals.**
  - Any key not on the list is refused. The line says it is a host setting that a container cannot set, and points at `--require-host` when the key is one of its settings.
  - A `net.*` key with `--net host` is refused, because the host's network namespace is shared.
  - A value the kernel rejects (`EINVAL`) is refused with the key and the value.
- **Where.** In the child, as a plan step after `/proc` is mounted and before the capability drop. Writing a namespaced sysctl needs `CAP_NET_ADMIN` or `CAP_SYS_ADMIN` over the namespace's owning user namespace, which the child has until the drop. The step opens `/proc/sys/<key with dots as slashes>` beneath the container's `/proc` and writes the value. Note for the failure modes: zbx does not mask `/proc/sys` today, so the container's processes can read every key; they cannot write any after the drop.
- With `--net user` (pasta), the sysctls are written before pasta attaches. Check that pasta does not overwrite any of them; record what it sets.

### 5. `--require-host` (host-setting preflight)

- **Surface.** `--require-host <setting><op><value>`, repeatable, once per setting. The settings and their operators:

  | Setting | Read from | Operator |
  | --- | --- | --- |
  | `vm.max_map_count` | `/proc/sys/vm/max_map_count` | `>=` |
  | `fs.aio-max-nr` | `/proc/sys/fs/aio-max-nr` | `>=` |
  | `vm.overcommit_memory` | `/proc/sys/vm/overcommit_memory` | `=`, value `0`, `1` or `2`, or a comma list |
  | `transparent_hugepage` | `/sys/kernel/mm/transparent_hugepage/enabled`, the bracketed word | `=`, value `always`, `madvise` or `never`, or a comma list |

  For example: `--require-host 'vm.max_map_count>=262144'`, `--require-host vm.overcommit_memory=1`, `--require-host transparent_hugepage=never,madvise`. Any other setting is a user diagnostic listing the four.
- **The check.** The parent checks before the scope, the namespaces or any process. A setting below its requirement is refused with one coded line:
  - it names the setting, the host value and the needed value;
  - its fix command is `sudo sysctl -w vm.max_map_count=262144`, or for THP `echo never | sudo tee /sys/kernel/mm/transparent_hugepage/enabled`;
  - the fix sentence mentions `/etc/sysctl.d/` to make the setting persist.
  - It refuses; it never attempts the write.
  - A setting the host does not expose (no THP support) is its own line.
- **Doctor.** `zbx doctor` gains a `host-settings` line reporting all four values. It is information only: it passes whatever the values are, and doctor's exit status does not change. `zbx doctor --require-host …` takes the same requirements and fails the line on a miss, with the same code and fix, so an operator can check a host before deploying. The doctor JSON schema gains the four values, and the doctor fixtures and `demo-m0`'s expectations are updated.
- **Pure core.** Parsing the requirement and comparing it to a `HostSettings` value is a pure function in the library, with unit tests and a seeded fuzzer, `host_settings`, over the requirement syntax and the four files' contents. Reading the files goes through the host interface, with `host_sim` fixtures.
- **For Zigcube later.** The agent can call `host_settings_read` and report the values as node facts. The scheduler can then place a service that declares `host_requirements` only on nodes that meet them. Nothing in Zigcube is built here.

### 7. The cgroup namespace and the read-only cgroup2 view

- **Measure first (slice 1, before any code for this item).**
  - In the VM, under the 0.5.2 release binary, run each runtime with `--memory 256m --cpus 1.5`, under both the default network and `--net host`. Use Alpine packages provisioned like `stress-ng`: `openjdk21-jre-headless`, `go` 1.25 or later, `dotnet8-runtime` and `nodejs`.
  - Record what each reports:
    - Java: `java -XshowSettings:system -version` and `-XX:+PrintFlagsFinal` (`MaxHeapSize`, `ActiveProcessorCount`).
    - Go: a two-line program printing `runtime.GOMAXPROCS(0)`.
    - .NET: `GC.GetGCMemoryInfo().TotalAvailableMemoryBytes` and `Environment.ProcessorCount`.
    - Node: `process.constrainedMemory()`, `os.availableParallelism()` and `v8.getHeapStatistics().heap_size_limit`.
  - Record also what each runtime reads, from `strace -e trace=openat`: `/proc/self/cgroup`, `/proc/self/mountinfo`, `memory.max` and `cpu.max`.
  - Write it to `docs/decisions/YYYY-MM-DD-m2b-runtime-cgroup-reading.md`. Repeat the table under M2b in slice 3, as the before and after.
- **What to expect, from the code today and the runtimes' sources (to be confirmed by the measurement, not assumed):**
  - **zbx has no cgroup namespace.**
    - With the default isolated network, `/sys` is a fresh read-only sysfs, so `/sys/fs/cgroup` is an empty directory and `/proc/self/mountinfo` lists no cgroup2.
    - With `--net host`, the host's `/sys` is bind-mounted read-only and recursively. The host's whole cgroup tree is visible, and `/proc/self/cgroup` shows the scope's full host path, `0::/user.slice/…/zbx-<name>.scope`.
  - **HotSpot (JDK 17, 21) and .NET (6+)** find the cgroup2 mount in `mountinfo` and join it with the path from `/proc/self/cgroup`, then read `memory.max` and `cpu.max`.
    - Default network: no mount, so they fall back to the host's RAM and CPUs. A JVM's default heap is then a quarter of host RAM, which `--memory` OOM-kills.
    - `--net host`: probably correct, by reading the host tree.
  - **Go (1.25+)** sets `GOMAXPROCS` from `cpu.max` the same way, walking up the ancestors. It does not read `memory.max`; `GOMEMLIMIT` is never automatic.
  - **Node (libuv)** reads `/proc/self/cgroup` and opens `/sys/fs/cgroup/<path>/memory.max` directly, without `mountinfo`. That fails today in the default mode.
- **The change.**
  - Once the child is in the scope (after `JobRemoved`, as now), it calls `unshare(CLONE_NEWCGROUP)`, so the namespace's root is the scope. This happens once, in the child, before `pivot_root`.
  - It then mounts a fresh cgroup2 at `<rootfs>/sys/fs/cgroup` with `MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC`.
    - With the default network, the mount goes on top of the fresh sysfs.
    - With `--net host`, it goes on top of the bound host tree, so the host's hierarchy is hidden. Check that mounting over the locked recursive bind works in a user namespace. If it does not, bind only the parts of host `/sys` that are not `fs/cgroup`, and record how.
  - Inside, `/proc/self/cgroup` is `0::/`, `mountinfo` lists cgroup2 at `/sys/fs/cgroup` with root `/`, and `memory.max`, `cpu.max` and `pids.max` are the scope's.
- **Only with a scope.** A run without a scope (no limits and no user bus: `W0301`) gets no cgroup namespace and no view, as today: unsharing there would expose the user's session cgroup.
- **No flag.** The view is on for every scoped run; that is the point of the item. This is a change in what a container sees. The supervisor accepted it as a default (decision above): podman and Docker on cgroup v2 do the same with a private cgroup namespace. It also closes the `--net host` exposure of the host's cgroup tree. The demo document says so.
- **Seccomp unchanged.** `clone` with `CLONE_NEWCGROUP` and `unshare` stay denied inside, because the unshare happens before seccomp is installed.
- **Known detail.** The scope holds the container and zbx's keeper process, so `pids.max` inside reads `--pids` plus one (`TasksMax`). Document it; do not hide it.
- **Doctor.** No new check. A kernel without cgroup namespaces is below the baseline already, but the unshare failing is still a coded line.

### In the library

`Spec` and `Limits` (`src/runtime/spec.zig`, re-exported by `zigbox`) gain fields. All of them are optional, and the defaults keep today's behaviour:

- `Limits.shm_bytes: ?u64`. Null means `shm_bytes_default`.
- `Spec.rlimits: Rlimits = .{}`, a struct with `nofile`, `nproc`, `memlock` and `stack`, each `?Rlimit`. `Rlimit = struct { soft: u64, hard: u64 }`, where `std.math.maxInt(u64)` means unlimited. Null means inherit.
- `Spec.sysctls: []const Sysctl = &.{}`, with `Sysctl = struct { key: []const u8, value: []const u8 }`, at most `sysctls_max` entries.
- `Spec.host_requirements: []const HostRequirement = &.{}`.
  - `HostRequirement = struct { setting: HostSetting, minimum: u64, allowed: HostValueSet }`.
  - `HostSetting` is an enum: `max_map_count`, `aio_max_nr`, `overcommit_memory` and `transparent_hugepage`.
  - `minimum` is used by the first two and `allowed` (a small bit set) by the last two.
- `zigbox.host_settings_read(host, out: *HostSettings, diag)` and the pure `zigbox.host_requirements_check(settings, requirements, diag)`. `HostSettings` holds the four values, and THP may be absent.
- The library validates every field the same way the CLI does, and refuses with the same codes. It never reads the environment or the host's limits behind the caller's back, except through the host interface during `start`.

The run record takes the next version: S2's PR #169 takes v11, so check `main` when you start. The record adds the knobs, so `zbx ps` and a re-adopted handle can show them. The upgrade test reads the previous version unchanged.

### Diagnostics

`E0310`–`E0324` are reserved for M2b: the next free block in `03xx`, the limits range (supervisor, 2026-11-16). Take codes in order. Ask before going outside the block, or before using a `W` code. A first allocation:

| Code | What | Blame |
| --- | --- | --- |
| E0310 | `--ulimit`: unknown name, unparsable value, or soft above hard | user |
| E0311 | `--ulimit` above the invoking user's hard limit (the `limits.conf` and `LimitNOFILE=` fix) | environment |
| E0312 | `setrlimit` failed in the child (names the step) | environment |
| E0313 | `--shm-size`: unparsable, below a page, or above `MemTotal` | user |
| E0314 | `--shm-size` larger than `--memory` | user |
| E0315 | `--sysctl`: malformed, too many, or value too long | user |
| E0316 | `--sysctl` key is a host setting (not on the allowlist) | user |
| E0317 | `--sysctl net.*` with `--net host` | user |
| E0318 | the kernel refused a sysctl value, or the write failed | user |
| E0319 | `--require-host`: setting below the requirement (`sysctl -w` fix); also the doctor line | environment |
| E0320 | `--require-host`: unknown setting or malformed requirement | user |
| E0321 | `--require-host`: setting not exposed or unreadable on this host | environment |
| E0322 | `unshare(CLONE_NEWCGROUP)` failed | environment |
| E0323 | mounting the read-only cgroup2 view failed | environment |

`E0324` is spare. Every code has a cause, a fix (command separate from sentence), a golden and an error page. Under the decided exit codes, each is exit 125 for `zbx run`.

**Trap: the code enum is full.** `Code` in `src/diag/codes.zig` is `enum(u8)` and already has 255 tags. M6d and S2 (#169) also add codes, so whichever lands first must widen it to `u16`. Check `main`. If it is still `u8`, widen it in its own commit (mechanical) and check that nothing stores the tag as a byte, such as bundles, JSON or records.

**Numbering.** M2b's codes are limits, so they go in `03xx` (the registry's numbering), after M2's `E0309`. They do not touch `05xx`, where M6c and M6d take theirs.

## Not in M2b (record in `docs/demos/m2b.md`)

- **Adding capabilities (parked).** `IPC_LOCK` (Vault's `mlock`), `NET_ADMIN` and `NET_RAW` in the container's own netns (VPNs, mesh init containers), and `SYS_NICE` (ClickHouse). This is an open question in the spec. Until it is decided, `--device /dev/net/tun` is accepted but unusable without `NET_ADMIN`. Slice 3 documents that in `docs/demos/m2b.md` and in the M10 device notes. Refusing it is deferred until the parked item is decided (supervisor, 2026-11-16).
- **Non-goals** (spec): io_uring; cpuset pinning, `io.max`/`io.weight` and hugetlb; nested containers (`unshare`, namespace `clone` flags, `mount`, `/dev/fuse` inside, Docker-in-Docker, rootless BuildKit inside zbx).
- Masking `/proc/sys` or other `/proc` paths read-only: later hardening, not a knob (supervisor, 2026-11-16). Note it as a failure mode.
- Setting any host value. `--require-host` only checks.
- rlimits other than the four. `core`, `rtprio` and the rest are not asked for.
- Mac: the forwarded `zbx run` passes the new flags to the guest unchanged. `--require-host` there checks the guest's kernel; say so. Do not add Mac-specific work.

## Slices (commit and stop for review after each)

1. **Measurements and the child-side knobs.**
   - The runtime measurement and the NUMA `strace` check, each recorded in its decision file, before code.
   - `--ulimit`, `--shm-size` with `shm_bytes_default`, the seccomp NUMA entries with their BPF tests, `--sysctl` with `sysctls.zon` and its per-key VM verification.
   - The plan steps, faulted by the `run` fuzzer.
   - The `Spec` and `Limits` fields, the codes `E0310`–`E0318` with goldens and pages, the `--plan` lines, and the run JSON and its schema.
   - The run record version with its upgrade test.
   - VM checks: `vm/m2-…` (`demo-m2` unchanged and green), plus a scratch run of steps 1, 2, 3 and 6 by hand, recorded in the report.
2. **The cgroup view and host preflight.**
   - The cgroup namespace and the read-only cgroup2 mount in all three network modes, faulted by the `run` fuzzer.
   - `--require-host` with its pure core and the `host_settings` fuzzer, `host_settings_read` and `host_requirements_check` in the library, and the doctor line and `--require-host` on doctor.
   - The codes `E0319`–`E0323`.
   - VM checks: `demo-m0` (doctor expectations) and `demo-m2`, and the runtime table measured again under the new binary.
3. **VM, CI and docs.**
   - `zig build demo-m2b` with the six steps exactly. Every assertion is a unit-tested pure function.
   - The `numa-probe` helper; the `/dev/shm` OOM check; the `--net host` cgroup check (the host tree not visible).
   - The agent JSON test and the upgrade test.
   - The CI job, `m2b` in `vm.yml`'s picker, and `.github/ci-changes.sh` (`m2b` in `demos`, after `m2`, with path rules for `src/runtime/policy/`, the plan, the child and doctor).
   - `docs/demos/m2b.md`: the by-hand steps, the before-and-after runtime table, the cuts above, the `/dev/net/tun` note, and the failure modes:
     - a host hard limit too low, and how to raise it for login sessions and for the user manager;
     - `nproc` counting the user's own processes;
     - `/dev/shm` filling the memory limit;
     - a sysctl that pasta or the kernel resets;
     - a host setting changed back after a reboot (`/etc/sysctl.d/`);
     - a runtime that still ignores the cgroup view;
     - `pids.max` showing one more than `--pids`.

The slices run one after another, in order.

**Mechanical parts (delegate):**
- widening `Code` to `u16`, if still needed;
- the error pages written from the goldens;
- threading the new `Spec` fields through the CLI-to-spec mapping once the first one is done by hand;
- the doctor fixture updates;
- the `vm.yml` picker entry, the CI job boilerplate and the `ci-changes.sh` demo list;
- the README and site status (supervisor).

## Defaults and limits this brief sets (supervisor defaults, 2026-11-16; ask before changing)

- No default changes except:
  - the three NUMA syscalls;
  - the cgroup view on scoped runs.
- New bounds:
  - `sysctls_max` = 16;
  - `sysctl_value_bytes_max` = 256;
  - `--shm-size` at least one page, and at most `--memory` or `MemTotal`;
  - one `--ulimit` per name;
  - one `--require-host` per setting.
- `--ulimit` with one value sets soft and hard, as in Docker.

## Release

M2b ships in 0.5.3, with M6d (owner, 2026-11-16: docs/decisions/2026-11-16-0.5.3-scope.md). It does not block 0.5.2, M6d or S2. Merge order with them only matters for the code enum width, the run record version and `ci-changes.sh`; check `main` at the start of each slice.

## Done means

- All gates pass (`zig build check`). The `run`, seccomp-compiler and new `host_settings` fuzzers run at 10,000 iterations.
- `demo-m2b` is green in CI with every earlier demo still green. Until then M2b is "built, not demonstrated".
- Your report lists:
  - what you ran and its output, and what you did not run and why;
  - which REVIEW.md items you touched;
  - every deviation from this brief;
  - anything in the spec, this brief or `DIAGNOSTICS.md` that seemed wrong.
