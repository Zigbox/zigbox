# M10 slice 1: devices and groups

Date: 2026-11-12. Slice: M10 slice 1 (`docs/briefs/M10-gpu.md`). Owner of the decision: the slice
implementer, within the brief; the items marked "bound" are for the supervisor to confirm.

## Decisions

- **`Host.set_user(uid, gid, keep_groups)`.** A run with devices keeps the user's supplementary
  groups in both mapping modes: `set_user` is told not to drop them, and no step calls
  `setgroups`. The single-id map still writes `deny` to `setgroups` in the parent (the kernel
  requires it before an unprivileged `gid_map`), which is not a `setgroups` call. The simulator
  counts calls (`World.setgroups_calls`); the tests assert zero for a run with devices.
- **`exec` still passes `false`.** `zbx exec` into a container started with devices drops the
  groups of the exec'd process. The record knows the devices, so slice 2 can pass `true` there.
  Left alone here because the brief names only `run`.
- **Path rules.** `--device` takes `/dev/<name>[/<name>...]` only: no `..`, no empty or `.` part,
  no space, quote, backslash, `:`, control or non-ASCII byte, nothing M1 already makes
  (`null`, `zero`, ..., `shm`, `pts`, the links) and no name starting with `.` (the runtime's
  staging names). Reason: the run record keeps the paths in one string separated by spaces, and
  forbidding bytes that need an escape keeps the record's worst case inside 64 KiB.
- **Bounds (bound).** `run_devices_max` = 16 (the brief). `device_path_bytes_max` = 48.
  `plan_paths_bytes_max` 96 -> 104 KiB, for the paths of the device steps. `sim_mounts_max`
  32 -> 64 and `sim_nodes_max` 160 -> 192, each with a comptime assert against the worst run.
  The simulator's tables are in every test binary that holds a `HostSim`; at 256 nodes the main
  test binary's `.bss` passed 2 GiB and the linker refused (`R_X86_64_32S`), so 192 is the
  largest that fits the assert (`160 + 2 * run_devices_max`).
- **Records.** Version 10 is written only for a run with a listener or devices; a run with
  neither writes version 9 byte for byte as before (a golden test holds this).
- **Codes.** `E0225` (a device that cannot be bound) and `W0209` (groups show as `nogroup`), the
  two the brief names. W0209 is a note after the node checks pass, never an end of the run.

## VM check

`.github/workflows/vm.yml` accepts only `m0`..`m8`, `m8b`, `z7` and `all`, and `build.zig` is
off limits to this slice. The check is therefore an extra step of the M1 guest
(`extra_devices` in `src/testing/vm/main_m1.zig`, run by pushing `vm/m1-<slug>`): root makes a
0660 root:render node and a 0660 root:daemon node; user `demo`, put in `render`, opens the first
inside the container for reading and writing; the second is refused with E0225 and exit 125. A
later slice that adds `demo-m10` should move the step there.
