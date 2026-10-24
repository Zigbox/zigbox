# Brief: M1 · Shell

Read `AGENTS.md`, `docs/STYLE.md`, `DIAGNOSTICS.md` and the M1 section of `docs/SPEC.md` first. This brief adds the decisions the spec leaves open. Do not touch anything from M2 onward. M0 is done; `demo-m0` must keep passing in every slice.

## Goal and demo (from the spec)

Run a shell inside an unpacked root filesystem, with no root privileges, isolated from the host. The demo, as a presenter types it:

1. As an ordinary user: `zbx run --rootfs ./alpine -- /bin/sh`.
2. Inside: `id` shows `uid=0(root)`; `ps` shows only PID 1 and `ps`; `hostname` shows the container name; `cat /etc/os-release` shows Alpine.
3. In a second host terminal: `ps -o user,pid,cmd` shows the shell running as the presenter's own UID.
4. Inside: `touch /etc/hacked`. On the host, `ls ./alpine/etc/hacked` shows it landed only in the rootfs.
5. Inside: `exit 42`. On the host, `echo $?` prints `42`.
6. `zbx run --rootfs ./alpine -- sleep 1000`, press Ctrl-C: it stops immediately.

Acceptance criteria (spec, live doc rev 43):
- No setuid bit on `zbx`; works with the setuid `newuidmap` only.
- Host mounts and processes are invisible from inside.
- Namespace setup happens before any thread is spawned, asserted in debug builds.
- Diagnostic bundles: `zbx bundle [--last | <container>]` and an automatic bundle on every bug diagnostic, redacted by default, with the CI redaction check.

## Fixed decisions

### Process model

- `zbx run` stays in the foreground as the parent, in the host PID namespace. It calls `clone3` with `CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC`. The child becomes PID 1 of the new PID namespace, sets up the container, closes every fd but 0, 1 and 2 (`close_range`), and `execve`s the command. There is no init shim, so `ps` inside shows only PID 1 and `ps`, as the demo requires.
- **No network namespace in M1.** The container shares the host network. That is the spec's scope; network isolation is M5. Record it in the demo document.
- **zbx is single-threaded for the whole of M1.** Before `clone3`, debug builds assert that `/proc/self/status` reports `Threads: 1`.
- **Parent–child sync** uses two pipes:
  - The child waits until the parent has written the id maps.
  - The parent learns of setup failure from a fixed-size failure record the child writes before exiting. The record carries the step and the errno, from which the parent builds the diagnostic.
  - `exec` success closes the pipe through `O_CLOEXEC`.
  - Nothing after `clone3` in the child allocates or formats text.
- **TTY:** no pty in M1. The container uses the terminal it was given. The shell runs in zbx's foreground process group, so job control inside is limited. Record that as a cut.

### Setup as a plan

The container setup (mounts, `pivot_root`, hostname, maps, exec) is computed as a **plan**: a fixed-size list of steps built by a pure function from the run spec, then executed step by step through `host.zig`.
- `host_real` executes it in the child.
- `host_sim` executes it against its model and injects a fault at any step.

This keeps `host.zig` the only file that names syscalls and paths. The fuzzer can then crash setup at every step and assert three things: the parent reports a coded diagnostic naming that step, nothing leaks onto the host (no mount, no process), and the exit code matches the blame.

### Ids

- **Default mapping: full range.** Container uid 0 maps to the user's own uid, and container ids 1–65536 map to the user's subuid/subgid range. The parent writes the maps by running the setuid `newuidmap` and `newgidmap`, the only external programs.
- **Fallback: single-UID.** If the helpers or ranges are missing, map only 0 to the user's uid. Write the maps directly, with `setgroups` set to `deny` first. Print one warning diagnostic, `ZBX-W0201`, whose fix names what `zbx doctor` names for subid. Then continue.
- **Never** setuid on zbx, and never write `setgroups=allow` without the helpers.

### Filesystem

1. Make the mount tree private (`MS_REC | MS_PRIVATE`).
2. Bind-mount the rootfs onto itself (`MS_BIND | MS_REC`).
3. Mount a fresh `/proc` (a new PID namespace's procfs).
4. `/dev` is a tmpfs (mode 0755) holding bind mounts of the host's `null`, `zero`, `full`, `random`, `urandom` and `tty`. `mknod` is not allowed in a user namespace. Add `/dev/shm` (tmpfs), `/dev/pts` (devpts with `newinstance,ptmxmode=0666`; if that mount is refused, skip it with a recorded note), and the usual symlinks (`fd`, `stdin`, `stdout`, `stderr`, `ptmx`).
5. `pivot_root` into the rootfs, `chdir("/")`, and unmount the old root with `MNT_DETACH`.

There is no `/sys` in M1; record that as a cut. The rootfs is used read-write in place, as the demo requires.

### Environment, name and hostname

- **Clean environment.** The command does not inherit the host environment. It gets:
  - `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`
  - `HOME=/root`
  - `HOSTNAME=<name>`
  - `TERM`, copied from the host if set

  There is no `-e` flag in M1.
- **Name:** `--name <name>`, defaulting to `zbx-` plus 6 random hex digits. It must be a valid hostname label: lowercase letters, digits and `-`, at most 63 characters. Anything else is a user diagnostic. `sethostname(name)` runs in the UTS namespace.

### Signals and exit codes

- **Forwarding.** The parent catches `SIGINT`, `SIGTERM`, `SIGHUP` and `SIGQUIT` and forwards each to the child. The wait loop cannot terminate by design except on the child's exit; assert that.
- **Ctrl-C on PID 1.** A PID 1 ignores every signal it has no handler for, so a plain `sleep` would survive Ctrl-C. When forwarding a terminating signal, the parent reads `SigCgt` from `/proc/<child>/status`. If the child has **no handler** for that signal, the parent sends `SIGKILL` instead, which reproduces the signal's default action. A shell, which catches `SIGINT`, keeps working.
- **Exit codes.** Exited with *n* means zbx exits *n*. Killed by signal *s* means zbx exits 128+*s*, with a one-line note on stderr naming the signal.
- **zbx's own failures** before the command starts use the standard's exit codes (1, 2, 70), with a coded diagnostic on stderr. `--output json` is how a script tells the two apart: add a final JSON line with `"container_exit"` when the container ran. Record the overlap with container exit codes 1 and 2 as an open question for the owner in the demo document. Do not invent new exit codes.

### Run records (the state the bundle needs)

- Each run writes a record to `$XDG_STATE_HOME/zbx/runs/<name>.zon`, or `~/.local/state/zbx/runs/` when that is unset. The record holds: name, rootfs path, command, start and end time, exit reason, zbx version, and the mapping mode used.
- At most `runs_max` (32) records are kept; the oldest is deleted. The record is written atomically (temp file, then rename).
- The record is not a container registry: there is no `list`, no re-adoption, no detached mode (that is M2, below).

### The runtime library (shaped for Zigcube)

- Put the runtime in `src/runtime/`. Export it from `build.zig` as a Zig module named `zigbox`, so Zigcube's agent can link it later. `cli.zig` calls it; it never prints.
- Its types mirror the `Runtime` contract in Zigcube's `HANDOFF.md`, so they map one to one later:
  - `Spec`: in M1 it holds the **rootfs path** where the contract will hold an image digest, plus command, name and labels. Labels are stored in the run record.
  - `ExitReason`: `exited`, `signaled`, `start_failed` (carrying the `Diag`) and `lost`. `oom` and `pid_limit` arrive with M2.
  - `Status`: `starting`, `running`, `stopped`.
  - `Handle`.
- M1 operations: `start(spec, *Diag) -> Handle`, `wait(handle) -> ExitReason`, `signal(handle, sig)`, `inspect(handle) -> Status`.
- `stop` with a grace period, `list`, re-adoption after a restart, the event stream and detached runs are **M2**, when Zigcube's C0 needs them. Do not build them, but do not design them out: say in a doc comment how each will fit.

### Diagnostics

Every new failure is a registered code in `src/diag/codes.zig` with a golden test. `02xx` is runtime and isolation. At least:
- `E0201`: the rootfs is missing or not a directory (user).
- `E0202`: the command was not found in the rootfs (user). Name the path that was looked up.
- `E0203`: the namespaces could not be created (environment). The cause comes from the same host facts doctor uses; point to `ZBX-E0101` and `zbx doctor`.
- `E0204`: writing the id maps failed (environment). Name the helper and its exit status.
- `E0205`: a setup step failed (environment). Name the step: the mount, `pivot_root` or `sethostname`.
- `E0206`: invalid container name (user).
- `W0201`: the single-UID fallback, as above.
- Any usage errors `zbx run` needs reuse `E00xx` where they fit.

### Bundles

- **`zbx bundle [--last | <name>]`** writes `~/.local/state/zbx/bundles/<UTC timestamp>-<name>.tar.gz`, using std's tar writer and gzip compressor, and prints the path. `DIAGNOSTICS.md` now says `.tar.gz` in both repos.
- **Contents:**
  - `MANIFEST.txt`, listing every file and why it is there;
  - the run record;
  - the last diagnostic in JSON, if the run failed;
  - `zbx --version`;
  - `zbx doctor` output in JSON, run in-process;
  - `uname`, `/etc/os-release` and `/proc/self/cgroup`;
  - the mapping mode.

  Every file is bounded; the manifest notes anything truncated.
- **Redaction by default.** Environment values, and anything matching the known secret patterns (`*_TOKEN`, `*_KEY`, `*_SECRET`, `*PASSWORD*`, bearer headers, `-----BEGIN … PRIVATE KEY-----`), become `[redacted:<kind>]`. `--no-redact` exists and prints a warning.
- **Automatic bundle on a bug.** A `bug[ZBX-B0001]` from a failed `zbx run` writes a bundle and prints its `saved` line. From the panic handler, write the bundle only if that can be done with the fixed buffers already in place. If not, keep the panic path as it is and say so; never risk a second panic.
- **CI redaction check.** A test creates a bundle with fake secrets in the environment and the run record, then fails if any of them appear unredacted. It runs in `zig build test`.

### The VM demo (`zig build demo-m1`)

- **Rootfs.** Pin the Alpine minirootfs tarball for x86_64, a dated 3.20.x release, by URL and SHA-256 in `src/testing/vm/alpine.zon`. Verify the SHA-256 against Alpine's published `.sha256` file when pinning. The harness downloads and verifies it like the Ubuntu image, then unpacks it in the guest as `demo` with `tar`. The rootfs is unpacked by the demo user and owned by them, which is how a presenter does it too.
- **Steps.** Each demo step becomes an assertion, driven over the serial console like `demo-m0`, with stdout and stderr kept apart:
  - Step 2 feeds commands to the shell on stdin.
  - Step 3 starts `sleep 1000` in the background and checks the host `ps` for the demo user's uid.
  - Step 6 sends a real Ctrl-C (byte `0x03`) over the serial console to a foreground `zbx run … sleep 1000`, and asserts that it stops within 2 s with exit 130.
- **Extra assertions.**
  - A host mount and a host process are invisible inside.
  - `/proc/self/uid_map` inside shows the full range.
  - A missing rootfs gives `E0201` with exit 1.
  - A bundle written after the run contains no secret planted in the environment.
- **CI.** Add a `demo-m1` job to `ci.yml`, a sibling of `demo-m0`. They can share the cached image.

## Slices (commit and stop for review after each)

**Slice 1 · Isolation core.**
- The `host.zig` additions (clone3, mount, pivot_root, sethostname, the id-map writes, setgroups, close_range and execve), each in `host_real` and `host_sim`.
- The plan and its executor; namespaces, the single-UID map, the filesystem and exec.
- The `E0201`, `E0202`, `E0203`, `E0205` and `E0206` diagnostics; the clean environment; exit-code propagation; the single-thread assert.
- A fuzzer that faults every plan step.
- Run it for real in the build container as root and as an unprivileged user, and paste what happens. The container has no `newuidmap`, so expect the fallback path.

**Slice 2 · Ids, signals, records and the library.**
- `newuidmap`/`newgidmap` full mapping and the `W0201` fallback; `E0204`.
- Signal forwarding, with the `SigCgt` rule tested in the simulator.
- Run records; the `zigbox` module export and its contract-shaped types.
- `zbx run`'s flags (`--rootfs`, `--name`, `--`), in `zbx help` and in snapshots.

**Slice 3 · Bundles.**
- `zbx bundle`, the automatic bundle on a bug, redaction, the CI redaction test and golden manifests.

**Slice 4 · VM and CI.**
- The Alpine pin, `demo-m1` and its CI job; `docs/demos/m1.md`, with the by-hand steps and the cuts.
- Run `zig build demo-m1 -Daccel=tcg` locally from a fresh VM, and paste the tail. `demo-m0` must still pass.

## Production readiness (live spec rev 46, from M1 on)

These are part of M1's acceptance criteria:
- **Upgrade test.** M0 wrote no state, so M1's upgrade test is a test that `zbx` handles a missing, empty or older-format run-record directory and older-format records without failing a run. A record it cannot read is skipped with a warning diagnostic, never a crash. Write the record format with a version field from the start.
- **Stable diagnostics.** Every new failure path has a registered code with a fix and golden tests; no M0 code changes its meaning.
- **Documented failure modes.** `docs/demos/m1.md` gets a "Failure modes" section. For each one it says what can go wrong in production, how it shows up (code, exit reason or log line) and how to recover. At least: no subuid range, AppArmor restriction, a rootfs owned by another user, a full disk for run records, and a command killed by a signal.

The upgrade test and the record version field belong in slice 2 (run records); the failure-modes section belongs in slice 4.

## Done means

- `zig build`, `test`, `tidy`, `release` and `errors-site-check` pass, and every fuzzer passes at 10,000 iterations, with commands and results in your report.
- The CI `demo-m1` job is green on the pushed branch, and `demo-m0` is still green. Until then, M1 is "built, not demonstrated".
- No tags. The owner tags `v0.0.0-m1`.
