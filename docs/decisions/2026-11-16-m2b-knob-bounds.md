# M2b slice 1: the knobs' bounds and the cuts

*Decided 2026-11-16, by the slice (M2b slice 1), within the brief's fixed defaults and limits.*

The brief ([docs/briefs/M2b-workload-knobs.md](../briefs/M2b-workload-knobs.md)) fixes the
defaults and limits; this file records the choices it left to the slice. The constants are in
`src/constants.zig` and the parsers in `src/runtime/knobs.zig`.

- **`--shm-size`** defaults to 64 MiB (`shm_bytes_default`), the size the hard-coded
  `size=65536k` gave before, so a run without the flag mounts the same `/dev/shm`. The smallest
  size is one 4 KiB page (`shm_bytes_min`). A size above `--memory` is refused (ZBX-E0314); a
  size above the host's memory, or a host whose `/proc/meminfo` cannot be read, is ZBX-E0313.
- **`--ulimit`** accepts `nofile`, `nproc`, `memlock` and `stack`. Zero is accepted (a container
  may want no core of memlock); a soft value above the hard one, or a resource named twice, is
  refused. A hard value above the invoking user's hard limit is refused before the child starts
  (ZBX-E0311), never clamped; the child's `setrlimit` failing anyway, or the parent failing to
  read its own limit, is ZBX-E0312. `nofile` has no `unlimited`: the kernel caps it at
  `fs.nr_open` and refuses `RLIM_INFINITY`, so it is refused as ZBX-E0310 at parse time, and a
  record that holds one is malformed. E0311's fix prints the `limits.conf` line in KiB for
  `memlock` and `stack` (rounded up) and the systemd `Limit*=` line in bytes, as each reads.
- **Order of the knobs in the plan.** The rlimits are set before the CDI `ldconfig` step, so
  `ldconfig` runs under the container's limits, as everything after the knobs does. That is
  deliberate: the limits are the container's from its first program on. A `nofile` or `stack`
  too small for `ldconfig` fails that step, and E0312's explanation says so.
- **`--sysctl`**: at most 16 (`sysctls_max`), values of 1 to 256 printable bytes
  (`sysctl_value_bytes_max`). A key is dotted letters, digits, `_` and `-` with no empty part;
  a well-formed key that is not in `src/runtime/policy/sysctls.zon` is ZBX-E0316, so no key
  length bound is needed beyond the longest listed key. A key given twice is ZBX-E0315, not a
  last-one-wins. ZBX-E0316 names `--require-host` for the host settings the brief lists
  (`vm.max_map_count`, `fs.aio-max-nr`, `vm.overcommit_memory`); that flag is slice 2's.
- **The allowlist** is the 28 ipc and net keys in `sysctls.zon`. Each passed the check that
  file's header describes on the VM's kernel ([2026-11-16-m2b-sysctl-keys.md](2026-11-16-m2b-sysctl-keys.md),
  VM run 43931483466), so none drops out.
- **The demo** uses `net.core.somaxconn=8192`, not 4096 (4096 is the 6.8 default, so a write of
  it proves nothing). The brief's `--plan` lines are cut: `zbx run --plan` does not exist.
- **Known gaps,** to be recorded in `docs/demos/m2b.md` when the demo document is written:
  - A process started by `zbx exec` does not get the container's `--ulimit` values; `exec`
    runs its own plan.
  - The default 64 MiB `/dev/shm` is not checked against a smaller `--memory`; only a size
    given with `--shm-size` is (ZBX-E0314).
  - The rlimits are set before the child switches to `--user`, so with `--user` an `nproc`
    below the processes that user already runs makes the next fork or `setuid` fail with
    EAGAIN. E0312's explanation says so.
  - A `--shm-size` that is not a whole number of pages is rounded up by tmpfs, not refused;
    the help text has no room for the note (it keeps 512 bytes of its buffer free). Refusing
    it would change a bound the brief fixes.
