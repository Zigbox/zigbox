# Zigcube's ZB-1 and ZB-2: the package writer from `zigbox`, and exec from a worker

*Decided 2026-11-13, by the slice (`claude/zigcube-zb1-zb2`), for Zigcube's C3 brief
("Zigbox requests").*

## ZB-1: the package writer is exported from the `zigbox` module

`zigbox.package` (src/zigbox.zig) is the M8 package writer, the same files
`zig build packages` uses, and the check that reads a tree back. The writer gained two
parameters so a second product names itself (review of #144): `apt.write` takes the repository's
`Identity` (Origin, Label, Description of `Release`), and `rpm.Options.build_host` is the rpm's
BUILDHOST, which dnf's `rpm:buildhost` now reads back from the rpm. Zigbox's own values moved to
`package_release.zig` (`apt_identity`: Zigbox, Zigbox, "Zigbox packages"; `rpm_build_host`:
`zigbox-build`), and `zig build packages` writes the same bytes as before: every file of the
tree was hashed on main (82af2c7) and on this branch, unsigned (19 files) and with `-Dtest-key`
(25 files), and the hashes match. The sha256 of each sorted `sha256sum` list, before and after:
`a5a994e632c01ffc...` (unsigned) and `bd513f6b1a948d3d...` (test key).

### The contract: these names and no others

The surface test in src/zigbox.zig compares each namespace's public names with this list, by
name and by count, so adding, renaming or removing one fails the build's tests.

- `zigbox.package`: `Package`, `File`, `Architecture`, `Built`, `TreeFile`, `Error`,
  `validate`, `describe`, the namespaces `deb`, `rpm`, `apt`, `dnf`, and the check:
  `check_tree`, `CheckOptions`, `CheckError`, `CheckSource`, `TreeSource`.
- `deb`: `write`, `file_name`.
- `rpm`: `Options` (`build_host`, required; `header_signature`, optional), `write`,
  `file_name`, `header_bytes`.
- `apt`: `Identity`, `write`.
- `dnf`: `write`.

Nothing else in `src/package/` (rpm's tag readers, apt's `redate`, deb's test sample, the
model's layout helpers) is part of it; those serve `zig build packages` and may change.

What Zigcube calls, with its own arena or other allocator and its own bytes:

```zig
const pkg = zigbox.package;

const files = [_]pkg.File{
    .{ .path = "/usr/bin/zigcube-agent", .mode = 0o755, .bytes = agent_bytes },
};
const package: pkg.Package = .{
    .name = "zigcube-agent", .version = "0.1.0", .architecture = .x86_64,
    .summary = "...", .description = "...", .license = "MIT",
    .homepage = "https://...", .maintainer = "Name <address>",
    .recommends_deb = &.{}, .recommends_rpm = &.{}, // optional
    .files = &files,
};
const rpm_options: pkg.rpm.Options = .{ .build_host = "zigcube-build" };
const identity: pkg.apt.Identity = .{
    .origin = "Zigcube", .label = "Zigcube", .description = "Zigcube packages",
};
try pkg.validate(&package);                                    // optional; write validates too
const deb_bytes = try pkg.deb.write(memory, &package);          // pkg.deb.file_name for its name
const rpm_bytes = try pkg.rpm.write(memory, &package, rpm_options); // pkg.rpm.file_name

// The repositories: one Built per package, all architectures together for apt, one
// architecture per dnf tree. Paths in the returned TreeFiles are relative to the tree's root
// (`apt/`, and `rpm/<architecture.rpm_name()>/` for dnf).
const apt_tree = try pkg.apt.write(memory, &debs, signed_at, &identity); // ?u64, null = fixed date
const dnf_tree = try pkg.dnf.write(memory, .x86_64, &rpms_x86_64);

// The check `zig build packages-check` runs, over the placed tree (both architectures, laid
// out as `apt/` and `rpm/<architecture>/`): one line per problem on `log`, CheckFailed if any.
var source: pkg.TreeSource = .{ .files = placed };
const strict: pkg.CheckOptions = .{ .signatures_required = true };
try pkg.check_tree(source.source(), memory, log, strict);
```

- Every returned slice is the caller's, from the allocator it passed (an arena is simplest).
- A refusal is `pkg.Error`; `pkg.describe(err)` gives its one-line text. An identity field or
  a build host that is empty, longer than 200 bytes or has a control byte (a newline included)
  is `BadText`.
- Choose the identity once: users' apt pins and unattended-upgrades match `Origin` and `Label`,
  so a change after the first signed release breaks them.
- Nothing is signed. `pkg.rpm.header_bytes(memory, &package, build_host)` gives the bytes an rpm
  header signature is made over (with the same build host as the rpm); the detached signature
  goes back in as `.header_signature` in `pkg.rpm.Options`. `Release` and each `repomd.xml`
  are signed by the caller after the trees are written, as Zigbox's own release does
  (docs/releases/packaging.md); `check_tree` with `signatures_required` then checks every
  signature file is placed and that one key made them all. OpenPGP signing is not exported.
- `CheckOptions` has one field, `signatures_required`, and `CheckError` is `CheckFailed` or
  `OutOfMemory` (follow-up, 2026-11-14): the check behind `zig build packages-check` also signs
  with Zigbox's fixed test key (`-Dtest-key`), which vouches for nothing, so that option and the
  openpgp errors it could raise stay inside Zigbox. The OpenPGP reader itself is still compiled
  into a caller, since `signatures_required` has to read the signature files; none of its names
  or errors is exported.
- The bounds a caller meets, as `Error` values: 64 files per package (`TooManyFiles`), 64 MiB
  per file (`FileTooLarge`), 98-byte paths (`BadPath`), and 32 packages per apt or dnf tree
  (`TooManyFiles`). An apt tree that keeps past versions for two architectures fills 32 after
  16 releases; keep only the versions users need.
- `dnf.write` takes rpms `rpm.write` made for the tree's architecture. Other bytes in a `Built`
  (a cut rpm, a changed main header, another package's rpm, another architecture's) are refused
  with `ForeignRpm` before anything is written (follow-up, 2026-11-14; it was an assertion). The
  signature header is not compared, so a header signature placed with `.header_signature` passes.
  The `dnf` fuzzer (`zig build fuzz -- dnf`) damages rpms and checks this.
- The same files are also the `zigbox_package` module. A compilation that links the runtime
  uses `zigbox.package` and never imports `zigbox_package` as well. Importing both fails the
  build with `error: file exists in modules 'zigbox' and 'zigbox_package'` (reviewer B checked
  this with a consumer package; it is the compiler's rule, not a Zigbox check).

`src/package_library_tests.zig` is the second caller: it builds a tiny two-file package for both
architectures through `zigbox.package` under its own identity and build host, assembles the apt
and dnf trees, checks them with `check_tree` unsigned, checks that no file names Zigbox (Release,
the rpm header, dnf's primary), that a rebuild is byte-identical and that one flipped byte of a
placed deb is caught, and that a relative path is `BadPath` from each writer and `validate`.

## ZB-2: exec from a worker, into a container a supervisor started

It works as it is; no fix was needed. `exec_start` never uses the `run.Handle` that started the
container. It finds the container by its run record under the state directory and checks its
PID 1 under /proc, reads the container's environment from `/proc/<pid>/environ`, joins the
namespaces through /proc, and joins the cgroup through the same driver the run used. So a worker
in another process can exec, given:

- the same uid as the supervisor;
- the same state directory: the same `XDG_STATE_HOME`, or, without it, the same `HOME`;
- the same cgroup driver's environment: `XDG_RUNTIME_DIR` (or `DBUS_SESSION_BUS_ADDRESS`) for
  systemd scopes, or the cgroupfs root variable on the cgroupfs driver;
- one thread when it calls `exec_start`, and that thread calls `exec_wait`
  (`exec_signal` may be called from another thread);
- with `terminal = false`, the command's stdin, stdout and stderr are the worker's own: give it
  the descriptors it should have (`/dev/null` for stdin, as demo-m6b does).

What Zigcube calls:

```zig
var handle: zigbox.ExecHandle = undefined; // about 400 KiB, at most 640 KiB: static or heap
var diag: zigbox.diag.Diag = undefined;
diag.reset();
const spec: zigbox.ExecSpec = .{ .name = container_name, .command = argv, .terminal = false };
try zigbox.exec_start(host, &spec, .{ .keep_history = false }, &handle, &diag);
const exit = zigbox.exec_wait(&handle);
```

`keep_history = false` keeps the worker's execs out of the container's `zbx exec` history;
leave it true if they belong there.

What `exec_wait` returns:

| Case | `exec_start` | `exec_wait` |
| --- | --- | --- |
| The command ends | ok | `.exited = n` (`code()` is n), or `.signaled = s` (128 + s) |
| The container ends while the command runs | ok | `.signaled = 9`, `code()` 137, `handle.container_ended == true`, at once (no hang) |
| The command is SIGKILLed while the container lives | ok | `.signaled = 9`, `container_ended == false` |
| The container ended before `exec_start` | `StartFailed`, E0220 (stopped or lost) | not called |
| No record under the worker's state directory | `StartFailed`, E0402 | not called |
| The wait itself failed | ok | `.lost`, `code()` null, `handle.lost_diag` says why |

The tests are `src/runtime/exec_worker_tests.zig`, on the simulated host: a container started
detached, its handle dropped, and a worker with only `HOME`, `XDG_RUNTIME_DIR` and a variable of
its own execs into it with no terminal (joins, exits 0, no history, and the command sees neither
the worker's variable nor the supervisor's); the container's PID 1 is killed under a running
exec (`.signaled = 9`, 137, `container_ended`), both with PID 1 left unreaped and, the usual
order on a real agent, with the supervisor's `run.wait` reaping it before the worker's
`exec_wait`; a worker with another home gets E0402, and after the container ended E0220. The
command SIGKILLed while the container lives is not worker-specific: `src/runtime/exec_tests.zig`
covers it ("a command killed by SIGKILL while its container lives says so at once"). The `.lost`
row is tested from a worker (follow-up, 2026-11-14): the reap step fails once, `exec_wait` gives
`.lost` with E0221 naming the reap, the command is killed and reaped, and the container lives.
`@sizeOf(ExecHandle)` is asserted at compile time to be at most
`constants.exec_handle_bytes_max` (640 KiB; about 400 KiB on x86_64 today). On a real host, demo-m6b runs `zbx exec` as its own process, without
a terminal, against a `zbx run -d` container, including EXEC 6 (the container killed under the
exec: code 137 and "the container ex4 ended, and the command with it") and EXEC 7 (E0220 on a
stopped container); its last run on main is green:
https://github.com/Zigbox/zigbox/actions/runs/43475100950/job/132057107623. No extra VM run was
needed, since nothing in exec changed.
