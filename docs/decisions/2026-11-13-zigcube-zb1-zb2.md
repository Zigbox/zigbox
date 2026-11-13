# Zigcube's ZB-1 and ZB-2: the package writer from `zigbox`, and exec from a worker

*Decided 2026-11-13, by the slice (`claude/zigcube-zb1-zb2`), for Zigcube's C3 brief
("Zigbox requests").*

## ZB-1: the package writer is exported from the `zigbox` module

`zigbox.package` (src/zigbox.zig) is the M8 package writer, the same files
`zig build packages` uses. No writer code changed, and `zig build packages` writes the same
bytes as before: every file of the tree was hashed on main (82af2c7) and on this branch, unsigned
(19 files) and with `-Dtest-key` (25 files), and the hashes match. The sha256 of each sorted
`sha256sum` list, before and after: `a5a994e632c01ffc...` (unsigned) and `bd513f6b1a948d3d...`
(test key).

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
try pkg.validate(&package);                                    // optional; write validates too
const deb_bytes = try pkg.deb.write(memory, &package);          // pkg.deb.file_name for its name
const rpm_bytes = try pkg.rpm.write(memory, &package, .{});    // pkg.rpm.file_name for its name

// The repositories: one Built per package, all architectures together for apt, one
// architecture per dnf tree. Paths in the returned TreeFiles are relative to the tree's root
// (`apt/`, and `rpm/<architecture.rpm_name()>/` for dnf).
const apt_tree = try pkg.apt.write(memory, &debs, signed_at);  // signed_at: ?u64, null = fixed date
const dnf_tree = try pkg.dnf.write(memory, .x86_64, &rpms_x86_64);
```

- Every returned slice is the caller's, from the allocator it passed (an arena is simplest).
- A refusal is `pkg.Error`; `pkg.describe(err)` gives its one-line text.
- Nothing is signed. `pkg.rpm.header_bytes(memory, &package)` gives the bytes an rpm header
  signature is made over; the detached signature goes back in as
  `pkg.rpm.write(memory, &package, .{ .header_signature = sig })`. `Release` and each
  `repomd.xml` are signed by the caller after the trees are written, as Zigbox's own release
  does (docs/releases/packaging.md). OpenPGP is not exported: signing stays in
  `package_release.zig` and `package_main.zig`.
- The same files are also the `zigbox_package` module. A compilation imports `zigbox` or
  `zigbox_package`, never both: Zig refuses a file that belongs to two modules.

`src/package_library_tests.zig` is the second caller: it builds a tiny two-file package for both
architectures through `zigbox.package`, assembles the apt and dnf trees, and checks them with
`package_check.check` (the `packages-check` reader), unsigned; it checks a rebuild is
byte-identical and that one flipped byte of a placed deb is caught.

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
var handle: zigbox.ExecHandle = undefined; // about 800 KiB: static or heap, not the stack
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
detached, its handle dropped, and a worker with only `HOME` and `XDG_RUNTIME_DIR` execs into it
with no terminal (joins, exits 0, no history); the container's PID 1 is killed under a running
exec (`.signaled = 9`, 137, `container_ended`); a worker with another home gets E0402, and after
the container ended E0220. On a real host, demo-m6b runs `zbx exec` as its own process, without
a terminal, against a `zbx run -d` container, including EXEC 6 (the container killed under the
exec: code 137 and "the container ex4 ended, and the command with it") and EXEC 7 (E0220 on a
stopped container); its last run on main is green:
https://github.com/Zigbox/zigbox/actions/runs/43475100950/job/132057107623. No extra VM run was
needed, since nothing in exec changed.
