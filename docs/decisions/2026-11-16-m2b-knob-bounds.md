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
  (ZBX-E0311), never clamped; the child's `setrlimit` failing anyway is ZBX-E0312.
- **`--sysctl`**: at most 16 (`sysctls_max`), values of 1 to 256 printable bytes
  (`sysctl_value_bytes_max`). A key is dotted letters, digits, `_` and `-` with no empty part;
  a well-formed key that is not in `src/runtime/policy/sysctls.zon` is ZBX-E0316, so no key
  length bound is needed beyond the longest listed key. A key given twice is ZBX-E0315, not a
  last-one-wins. ZBX-E0316 names `--require-host` for the host settings the brief lists
  (`vm.max_map_count`, `fs.aio-max-nr`, `vm.overcommit_memory`); that flag is slice 2's.
- **The allowlist** is the 28 ipc and net keys in `sysctls.zon`. Each must still pass the check
  that file's header describes on the VM's kernel before the slice is called done.
- **The demo** uses `net.core.somaxconn=8192`, not 4096 (4096 is the 6.8 default, so a write of
  it proves nothing). The brief's `--plan` lines are cut: `zbx run --plan` does not exist.
- **Known gap:** a process started by `zbx exec` does not get the container's `--ulimit` values;
  `exec` runs its own plan. Recorded in `docs/demos/m2b.md` when the demo document is written.
