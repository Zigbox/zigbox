//! The `zigbox` module: the container runtime as a library, for Zigcube's agent (and anything
//! else that wants to run a container without going through the `zbx` command line). Its types
//! follow the `Runtime` contract of Zigcube's HANDOFF.md one to one:
//!
//!   - `Spec`: what to run. In M1 the root is a directory (`rootfs`) where the contract will hold
//!     an image digest; the command, the name, the labels and the environment (`env`) are the
//!     contract's. `limits` (memory bytes, pids, CPU thousandths) is enforced by the container's
//!     cgroup scope.
//!   - `start(host, spec, options, handle, diag)`: starts it; on return the command is running.
//!     `StartOptions.detached` marks the run as one whose supervisor outlives the caller.
//!   - `wait(handle)`: how it ended, as an `ExitReason`. `StartOptions.timeout_ms` ends a run
//!     that lasts too long (SIGTERM, then SIGKILL after `grace_ms`); `timed_out(handle)` says so.
//!   - `signal(handle, number)`: sends it a signal, with the forwarding rule of PID 1.
//!   - `inspect(handle)`: a `Status`.
//!   - `lifecycle.stop(ref, grace_ms, kill_wait_ms)`: SIGTERM, then SIGKILL; `list`, `adopt` (a
//!     `Ref` to a container by name, from the record and the kernel, in any process), and
//!     `Watcher.poll` for the changes. See `runtime/lifecycle.zig` for how "alive" is decided
//!     and what the poll bound is.
//!
//! Storage is the caller's. The library keeps no module-level state (the real host's errno is per
//! thread; the panic handler's settings are the `zbx` program's): a `Handle` (about 480 KiB, with
//! the plan and the doctor's `Facts`) is passed by pointer and must not move while a run is going
//! on; a `bundle.Workspace` is the same for a bundle. Two callers on two threads each bring their
//! own and share nothing (`runtime/lifecycle_tests.zig` runs two at once). Keep a `Handle` in
//! static storage or on the heap, not on a small thread's stack.
//!
//! A failure is a `Diag` (code, causes, fixes), the same structure `zbx` and `zcube why` render.
//! Nothing here prints. Warnings go to the `Warn` in `StartOptions` as they happen.
//!
//! Where the contract as written cannot be met as is, docs/demos/m2.md says so (the shape of
//! `Spec` and `Status`, the poll-based event stream, `list` returning `Entry`).

const std = @import("std");

const run = @import("runtime/run.zig");

pub const Spec = run.Spec;
pub const Label = run.Label;
pub const Limits = run.Limits;
pub const Handle = run.Handle;
pub const Status = run.Status;
pub const ExitReason = run.ExitReason;
pub const StartOptions = run.StartOptions;
pub const Warn = run.Warn;
pub const Error = run.Error;

pub const start = run.start;
pub const wait = run.wait;
pub const signal = run.signal;
pub const inspect = run.inspect;
pub const failed_start = run.failed_start;
pub const timed_out = run.timed_out;

/// What a caller that did not start the container uses: list, adopt, stop, watch.
pub const lifecycle = @import("runtime/lifecycle.zig");
pub const Ref = lifecycle.Ref;
pub const Entry = lifecycle.Entry;
pub const Watcher = lifecycle.Watcher;
pub const list = lifecycle.list;
pub const adopt = lifecycle.adopt;
pub const stop = lifecycle.stop;
pub const ref_of = lifecycle.ref_of;

/// The kernel interface a run goes through: the real one for a program, the simulator for tests.
pub const host = @import("host.zig");
pub const host_real = @import("host_real.zig");
pub const host_sim = @import("host_sim.zig");

/// Diagnostics: the collector, the registry of codes, and the renderer.
pub const diag = @import("diag/diag.zig");
pub const codes = @import("diag/codes.zig");
pub const render = @import("diag/render.zig");

/// Run records: the state a run leaves in the state directory.
pub const records = @import("runtime/records.zig");

test "the module's surface is what the contract names" {
    // Goal: a rename or a removal in the runtime that Zigcube relies on fails here, loudly.
    _ = Spec;
    _ = Handle;
    _ = Status;
    _ = ExitReason;
    _ = start;
    _ = wait;
    _ = signal;
    _ = inspect;
    _ = stop;
    _ = list;
    _ = adopt;
    _ = Watcher;
    try std.testing.expect(std.meta.fieldNames(Status).len == 3);
}
