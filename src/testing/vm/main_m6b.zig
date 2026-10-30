//! The M6b demo (the dev loop), run in a real Ubuntu 24.04 VM (the harness of the M0 to M6
//! demos). It is a list of parts, run in order; each part is a function of `steps` below.
//!
//! UPGRADE (upgrade_m6b.zig): the merged M6 `zbx` (`m6b_commit` in `old_release.zon`) pulls
//!   alpine:3.20 and starts a detached container with a new `--state` volume; this `zbx` reads
//!   its store, lock and version-7 run record, execs into the container it did not start, finds
//!   `logs` of it a coded error, stops it, and uses its volume.
//! SPEC (spec_m6b.zig): the spec's five steps: python serves a mounted `./site`, an edit on the
//!   host is the next response, `exec` writes a file the host user owns, `logs` shows the two
//!   requests, and a mount outside the project is refused naming the rule.
//! WRITABLE (writable_m6b.zig): `--mount` and `--user`: the edit is seen, a file written inside
//!   is the host user's, the refusals (outside the project, a link out, a user that is not
//!   root), and that image with `--user 0`.
//! LOGS (logs_m6b.zig): `zbx logs`: a detached server's requests, the log after the starting
//!   `zbx` was killed, a foreground run on the terminal and in its log, `--follow` ending with
//!   the container, and a log at its cap.
//! EXEC (exec_m6b.zig): `zbx exec`: a file written through the mount is the user's, a refused
//!   syscall and a missing capability fail as in a run, the command is in the container's scope
//!   and under its `--pids`, its exit code and the bundle's note, a terminal under `script`,
//!   death with the container, a stopped one.
//! AGENT (agent_m6b.zig): the dev loop again, by JSON only (`--output json`, `zbx schema`,
//!   `zbx explain`); what it cannot read is a `FINDING`.
//! ACCEPT (accept_m6b.zig): a log is removed with its run record. It runs last: it prunes.
//!
//! `zig build demo-m6b -Daccel=tcg` for software emulation.

const std = @import("std");
const Io = std.Io;
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const accept = @import("accept_m4.zig");
const image = @import("image.zig");
const limits = @import("limits.zig");
const old_release = @import("old_release.zon");
const session_mod = @import("session.zig");
const old_wrapper = @import("upgrade_m5.zig");
const upgrade = @import("upgrade_m6b.zig");
const spec = @import("spec_m6b.zig");
const writable = @import("writable_m6b.zig");
const logs = @import("logs_m6b.zig");
const exec = @import("exec_m6b.zig");
const agent = @import("agent_m6b.zig");
const accept_m6b = @import("accept_m6b.zig");

const Session = session_mod.Session;
const H = harness;

pub fn main(init: std.process.Init) !u8 {
    harness.demo_name = "demo-m6b";
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const options = H.parse_options(init) catch |err| {
        try out.print("demo-m6b: bad arguments ({s})\n", .{@errorName(err)});
        return 2;
    };
    const started = session_mod.now_ms();
    const code = demo(init, out, options) catch |err| {
        if (err == error.NoKvm) return 1;
        try out.print("\ndemo-m6b: FAILED ({s})\n", .{@errorName(err)});
        return 1;
    };
    try out.print("\ndemo-m6b: PASSED in {d} s\n", .{(session_mod.now_ms() - started) / 1000});
    return code;
}

fn demo(init: std.process.Init, out: *Io.Writer, options: H.Options) !u8 {
    const io = init.io;
    const accel = harness.choose_accel(options.accel, H.kvm_usable(io)) catch |err| switch (err) {
        error.NoKvm => {
            try out.print("demo-m6b: /dev/kvm is not usable here; for software emulation " ++
                "(slow) add -Daccel=tcg\n", .{});
            return error.NoKvm;
        },
        error.BadAccel => return error.BadAccel,
    };
    const binary = try H.check_binaries(init, out, options);
    if (options.old_zbx.len == 0) {
        const missing = "demo-m6b: --old-zbx is missing: the upgrade test needs the M6 binary\n";
        try out.print(missing, .{});
        return error.MissingBinary;
    }
    const arena = init.arena.allocator();
    const old_binary = try Io.Dir.cwd().readFileAlloc(
        io,
        options.old_zbx,
        arena,
        .limited(limits.elf_bytes_max),
    );
    try out.print("demo-m6b: upgrade test from {s}: {s}, {d} bytes\n", .{
        old_release.m6b_commit, options.old_zbx, old_binary.len,
    });
    const base = try image.ensure(init, options.cache_dir, out);
    const overlay_pattern = "{s}/overlay-demo-m6b.qcow2";
    const overlay = try std.fmt.allocPrint(arena, overlay_pattern, .{options.cache_dir});
    if (!options.reuse_overlay) try image.make_overlay(init, base, overlay);
    defer if (!options.keep_overlay) Io.Dir.cwd().deleteFile(io, overlay) catch {};
    var ca_file: []const u8 = "";
    if (options.ca_file.len > 0) {
        const limit: Io.Limit = .limited(limits.http_body_bytes_max);
        ca_file = try Io.Dir.cwd().readFileAlloc(io, options.ca_file, arena, limit);
    }
    var session: Session = undefined;
    try session.start(init, out, overlay, accel, .{
        .user_data = @import("cloud_init.zig").user_data,
        .binary = binary,
        .old_binary = old_binary,
        .ca_file = ca_file,
    });
    defer session.deinit();
    var timer = H.Timer.start();
    try H.provision(&session, out, &timer, options.reuse_overlay);
    try H.install_binary(&session, out, &timer);
    try steps(&session, out, &timer, ca_file.len > 0);
    try session.shutdown();
    return 0;
}

/// The parts, in order. A part is `fn (*Session, *Io.Writer, *H.Timer) !void`.
const parts = [_]*const fn (*Session, *Io.Writer, *H.Timer) anyerror!void{
    upgrade.step_upgrade,
    spec.step_spec,
    writable.step_writable,
    logs.step_logs,
    exec.step_exec,
    agent.run_agent,
    accept_m6b.step_accept,
};

fn steps(session: *Session, out: *Io.Writer, timer: *H.Timer, with_ca: bool) !void {
    try accept.install_old(session, out);
    try common.write_wrappers(session, out, with_ca);
    try old_wrapper.write_old_wrapper(session, out, with_ca);
    inline for (parts) |part| try part(session, out, timer);
}

test {
    // The files this demo is made of carry their own unit tests; a test root reaches them here.
    _ = @import("checks_upgrade_m6b.zig");
    _ = @import("checks_spec_m6b.zig");
    _ = @import("checks_accept_m6b.zig");
    _ = @import("upgrade_m6b.zig");
    _ = @import("spec_m6b.zig");
    _ = @import("writable_m6b.zig");
    _ = @import("logs_m6b.zig");
    _ = @import("exec_m6b.zig");
    _ = @import("agent_m6b.zig");
    _ = @import("agent_json_m6b.zig");
    _ = @import("accept_m6b.zig");
}
