# Brief: M2 · Limits

Read `AGENTS.md`, `docs/STYLE.md`, `DIAGNOSTICS.md`, the M2 section and the "Production readiness" section of `docs/SPEC.md`, `docs/DECISIONS.md` (the M2 cgroup decision), and the "Notes for M2" in `docs/briefs/M1-shell.md` first. This brief settles what they leave open. Do not touch anything from M3 onward. `demo-m0` and `demo-m1` must keep passing in every slice.

## Goal and demo (from the spec, live doc rev 47)

A misbehaving container cannot take down the host or regain privilege.

1. `zbx run --rootfs ./alpine --pids 64 -- sh -c 'b(){ b|b& }; b; wait'`: the fork bomb stalls, the host stays responsive, and `zbx` exits reporting the PID limit. (Spec rev 48 changed this from `:(){ :|:& };:`, which Alpine's `sh` rejects and which lets PID 1 exit before the limit is hit.)
2. `zbx run --rootfs ./alpine --memory 128m -- stress-ng --vm 1 --vm-bytes 512m`: output ends with `killed: out of memory (limit 128 MiB)`.
3. `zbx run --rootfs ./alpine -- mount -t tmpfs none /mnt` fails with `operation not permitted`.
4. `zbx run --rootfs ./alpine --read-only -- touch /x` fails; `touch /tmp/x` succeeds (tmpfs).

Acceptance criteria:
- Limits are visible in `/sys/fs/cgroup` under the user's slice while running, and gone after exit.
- The seccomp profile is a checked-in, reviewed file, not an inline list.
- OOM, PID-limit and signal exits are distinguished in the exit report.
- The production-readiness checklist (upgrade test, stable diagnostics, documented failure modes).
- From M2 on, every new command's result has a JSON form with a schema, and nothing prompts without a terminal (spec, "Agent operability").

## Fixed decisions

### The cgroup: a transient systemd user scope over D-Bus (see `docs/DECISIONS.md`)

- **The D-Bus client.** `src/dbus/` speaks the wire protocol in Zig with std only:
  - it connects to the address from `DBUS_SESSION_BUS_ADDRESS` (only `unix:path=`; anything else is a diagnostic), falling back to `$XDG_RUNTIME_DIR/bus`;
  - authenticates with SASL `EXTERNAL` (the uid in hex), then `Hello`;
  - marshals only the types it needs: `y b n q i u x t s o g a( ) v` and the struct and array forms that `StartTransientUnit` takes;
  - parses replies and signals, and matches `JobRemoved` with an `AddMatch` rule.
- **Bounds.** Message bytes, header fields, array elements, nesting depth and reply timeouts are bounded in `constants.zig`. The parser gets a seeded fuzzer, `dbus`, with truncated, oversized, wrongly aligned, wrong-endian and deeply nested messages.
- **The scope.**
  - Its name is `zbx-<container name>.scope`. A name that is taken is a coded diagnostic, never a silent reuse.
  - Before `exec`, the parent calls `StartTransientUnit(name, "fail", properties, [])` on `org.freedesktop.systemd1`:
    - `PIDs=[child]`, `Delegate=true`, `Slice=` the user's `app.slice` (or the manager's default if absent);
    - `CPUAccounting`, `MemoryAccounting`, `IOAccounting`, `TasksAccounting=true`;
    - `Description=zbx: <name>`;
    - the limits.
  - It waits for `JobRemoved` with result `done` before releasing the child to `exec`.
  - This follows runc's systemd driver. We drop runc's `cgroupsPath` syntax and its `org.systemd.property.*` annotations, because zbx has no OCI input. Record that in `docs/demos/m2.md`.
- **The limits.**
  - `--memory <size>` (`k`/`m`/`g`, binary units) sets `MemoryMax`, and `MemorySwapMax=0` so the limit means something.
  - `--pids <n>` sets `TasksMax`.
  - `--cpus <decimal>` sets `CPUQuota` (for example 0.5 means 50%).
  - A property the running systemd does not support is written to the scope's cgroupfs files instead; read `Version` first. Bound and validate every value: a zero, absurd or unparsable limit is a user diagnostic (`E03xx`).
- **No user bus or no delegation.** If the user bus is unreachable, auth is refused or the job fails, `zbx run` fails with a coded diagnostic (`E03xx`, environment, exit 125) that names the cause and points at `zbx doctor`. Flags that need a cgroup are refused without one. A run **with no limit flags** still works without a bus: it prints the warning `W0301` once and runs without a scope, like M1. The demo VM has a user manager, so the demo always gets a scope.
- **Doctor.** The cgroup check also connects to the user bus and calls `GetUnit` or `Version` (read-only). Its result is part of the cgroup check: an unreachable bus is a FAIL with a fix (lingering, or log in through PAM). Update the fixtures.

### Exit reasons

- **How each is detected.** After the child exits, the parent reads the scope's `memory.events` (`oom_kill`) and `pids.events` (`max`).
  - An OOM kill gives the exit report `killed: out of memory (limit 128 MiB)` and `ExitReason.oom`.
  - A PID limit that was hit and the container ended gives `stopped: process limit reached (limit 64)` and `ExitReason.pid_limit`.
  - Anything else keeps M1's signal and exit reporting.
- **Exit codes.** OOM is `128+9`, the real signal. The PID limit is whatever the process returned, plus the report line. Both are distinguishable through JSON's `container_exit` (`"reason":"oom"|"pid_limit"|"signal"|"exited"`).
- **Cleanup.** The scope goes away when its last process exits. Assert it is gone, or stop it with `StopUnit` if it lingers. Then it is not visible under `/sys/fs/cgroup` afterwards.

### Hardening (in the child, after the setup plan, before `exec`)

1. **Capabilities.** Drop to an allowlist in the bounding, effective, permitted and inheritable sets, and clear the ambient set. The allowlist is Docker's default set minus `CAP_NET_RAW` and `CAP_MKNOD`: `CHOWN DAC_OVERRIDE FOWNER FSETID KILL SETGID SETUID SETPCAP NET_BIND_SERVICE SYS_CHROOT AUDIT_WRITE SETFCAP`. `CAP_SYS_ADMIN` is not on it, which is why `mount` fails. The list lives in a checked-in file next to the seccomp profile, with a reason per capability.
2. **`no_new_privs`** is always set.
3. **Seccomp.**
   - The default profile is a checked-in, reviewed file, `src/runtime/policy/seccomp.zon`. It is an allowlist of syscall names with argument rules only where Docker's default profile has them (`clone`/`clone3` namespace flags, `personality`, `socket` address families). Each entry is grouped with a comment saying why.
   - At comptime it compiles to a classic BPF program for x86_64 and aarch64 (syscall numbers from `std.os.linux.SYS`), with an architecture check. Any other syscall returns `EPERM`, not kill, as in Docker, so programs fail politely.
   - It is installed last, just before `execve`, with `SECCOMP_SET_MODE_FILTER`.
   - The filter is unit-tested by running the BPF interpreter in tests against the syscall list, with an allow and a deny case per group.
4. **`--read-only`.**
   - Remount the rootfs bind read-only (`MS_REMOUNT|MS_BIND|MS_RDONLY`, keeping the original flags as the kernel requires in a user namespace).
   - Mount a tmpfs at `/tmp` and `/run` (mode 1777 and 0755, sized by `tmpfs_bytes_max`), creating the mountpoints in the rootfs beforehand if missing. If the rootfs lacks them and is not writable, that is a diagnostic.
   - Without `--read-only` the rootfs stays writable, as in M1.
5. These steps join the M1 setup plan as steps, so the `run` fuzzer faults them too.

### The library, for Zigcube (the "Notes for M2" in the M1 brief)

- **Per-caller storage.** Replace the module-level statics (bundle workspace, `doctor.Facts`, run handle) with per-caller storage: caller-provided buffers or one per `Handle`. Keep the stack small, and say how in the module doc.
- **The rest of the contract.** Add what Zigcube's `Runtime` contract needs, in `src/runtime/` (`zigbox` module):
  - `stop(handle, grace_ms)`: `SIGTERM`, then `SIGKILL` after the grace;
  - detached start: `zbx run -d` returns once the command has started, and the scope and run record carry the container;
  - `list()` from run records plus live scopes, with labels;
  - re-adoption: a new process can attach to a running container by name, via its scope and PID 1;
  - an event stream: status changes, polled from the scope's `cgroup.events` and the record. Document the poll interval bound.
  - `Spec` gains `limits` (cpu_millis, memory_bytes, pids), matching the contract.
  - Still no image digests; that is M3/M4.
- **CLI, minimal:**
  - `zbx run -d`;
  - `zbx stop <name> [--grace <ms>]`;
  - `zbx ps`, with `--output json` and its schema;
  - `zbx logs` is cut; record it.
- **Run record version 2.** It adds limits, scope name, reason and detached. The upgrade test reads version 1 records unchanged.

### Agent operability, now

- Every new command (`stop`, `ps`, `run -d`) has a JSON result with a versioned schema, and `zbx schema <command>` prints it. Start the schema registry with `run`, `bundle`, `ps`, `stop` and `doctor`.
- Nothing prompts. `--timeout <ms>` exists on `run` (the total wall time, then stop with grace) and on `stop`.

### Diagnostics

`03xx` is limits and the cgroup. At least:
- no user bus;
- bus auth refused;
- a D-Bus protocol error;
- systemd refused the unit, or the job failed;
- the scope name is taken;
- an invalid limit value;
- a limit with no cgroup available;
- cgroupfs write failed;
- `W0301` (running without a scope).

Hardening failures (`capset`, `prctl`, `seccomp`, the remount) are `E02xx`, each naming its step. Each code has goldens and an error page. Under the decided exit codes, every `zbx run` failure before the command starts is exit 125.

## Slices (commit and stop for review after each; do not push)

1. **D-Bus and the scope.**
   - The wire client, SASL, marshalling and parsing, and the `dbus` fuzzer.
   - `StartTransientUnit`, the `JobRemoved` wait, and the limits as properties with the cgroupfs fallback.
   - `--memory`, `--pids` and `--cpus`; `W0301` and the `03xx` codes; the doctor bus check.
   - The simulator models a user bus and systemd: replies, job results, an absent bus and refusals.
   - The build container has no user systemd. Test against the simulator, and if you can, against a real `dbus-daemon` started by hand: `apt-get install dbus` is allowed here. Say exactly what ran.
2. **Exit reasons and cleanup.** `memory.events` and `pids.events` become reasons and report lines; `container_exit.reason`; the scope cleanup assertion; run record version 2 with the version 1 upgrade test.
3. **Hardening.** The capabilities allowlist file; `no_new_privs`; the seccomp profile file, its comptime BPF compiler, the BPF tests and a fuzzer over the compiler's input; `--read-only` with tmpfs `/tmp` and `/run`; the new plan steps, faulted by the `run` fuzzer.
4. **The library for Zigcube.** Per-caller storage; `stop`, detached start, `list`, re-adoption and events; `zbx run -d`, `zbx stop` and `zbx ps`; `zbx schema` with the first schemas; `--timeout`.
5. **VM and CI.** `demo-m2`, using the same VM:
   - Provision `stress-ng` into a copy of the Alpine rootfs with `apk` inside a `zbx run` during setup; the VM has network, and the container shares it in M2.
   - Assert all four demo steps and the acceptance criteria: limits visible under `/sys/fs/cgroup/user.slice/…/zbx-<name>.scope` while running and gone after; OOM, PID-limit and signal exits distinguished.
   - Also assert `zbx ps` JSON for a detached run, and `zbx stop`.
   - Add the `demo-m2` CI job.
   - Write `docs/demos/m2.md`: the by-hand steps, the cuts, the departures from runc, and the failure modes (no user bus, no lingering, a delegation missing a controller, an OOM that hits zbx's own memory, a seccomp denial that looks like a bug, a read-only rootfs without `/tmp`).
   - Run `demo-m2` locally under TCG, and `demo-m0` and `demo-m1` still pass.

## Notes for later milestones (found during M2)

- **Seccomp allowlist.** It follows Docker's default profile but has only been exercised with Alpine's busybox. Before M4 runs real images (Debian-based `python`, `postgres`), test a glibc rootfs, and grow the allowlist from what fails. A missing syscall shows up as `EPERM`, not a crash, so it can look like an application bug; the failure-modes section of `docs/demos/m2.md` should say so.
- **The `mount` refusal message.** Busybox prints "permission denied (are you root?)" for the kernel's `EPERM`, and glibc's `mount` prints "Operation not permitted". Demo assertions match the exit status and either text.
- **No `/sys` in the container.** M1 and M2 mount `/proc` and `/dev` but not `/sys`; stress-ng in the M2 demo prints `no CPUs found in /sys/devices/system/cpu`. Real images (M4) expect at least a read-only `/sys`. A rootless sysfs mount needs the container to own a network namespace, so decide this with networking.
- **Thread-local storage costs 256 KiB per thread.** std's default `signal_stack_size` gives every thread a `threadlocal` alternate signal stack, on top of its own stack (see `docs/demos/m2.md`). Zigcube's agent thread pool pays it per thread.

## Done means

- All gates pass, and every fuzzer runs at 10,000 iterations (`dbus` and the seccomp-compiler fuzzer are new).
- The CI `demo-m2` job is green, with `demo-m0` and `demo-m1` still green. Until then M2 is "built, not demonstrated".
- No tags. The owner tags `v0.0.0-m2`.
