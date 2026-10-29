//! The M6 demo, run in a real Ubuntu 24.04 VM (the harness of the M0 to M5 demos). It is a list
//! of parts, run in order; each part is a function of `steps` below.
//!
//! UPGRADE (upgrade_m6.zig, M6 slice 4): the merged M5 `zbx` (`m6_commit` in `old_release.zon`)
//!   pulls alpine:3.20, runs it with `--net user`, commits, and pulls postgres:16; this `zbx`
//!   reads its store, version-2 image records, lock and version-4 run records beside its own
//!   version-6 ones, and runs postgres with a new `--state` volume on that store.
//! SPEC (spec_m6.zig): the spec's five steps: postgres with `--state` and `--publish`, a row
//!   written with `psql`, SIGKILL and the same command again, `state ls`, and a run without
//!   `--state`.
//! STATE (state_m6.zig, M6 slice 2): the acceptance checks of state volumes with postgres: a
//!   second writer refused, the owner inside, the lock free after each exit path, `state rm` and
//!   `state restore`. Slice 3's MOUNTS part (secret, bind, tmpfs, export) joins here when it
//!   moves from demo-m5, and the agent test of M6 after it.
//!
//! `zig build demo-m6 -Daccel=tcg` for software emulation.

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
const upgrade = @import("upgrade_m6.zig");
const spec = @import("spec_m6.zig");
const state = @import("state_m6.zig");
const mounts = @import("mounts_m6.zig");

const Session = session_mod.Session;
const H = harness;

pub fn main(init: std.process.Init) !u8 {
    harness.demo_name = "demo-m6";
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const options = H.parse_options(init) catch |err| {
        try out.print("demo-m6: bad arguments ({s})\n", .{@errorName(err)});
        return 2;
    };
    const started = session_mod.now_ms();
    const code = demo(init, out, options) catch |err| {
        if (err == error.NoKvm) return 1;
        try out.print("\ndemo-m6: FAILED ({s})\n", .{@errorName(err)});
        return 1;
    };
    try out.print("\ndemo-m6: PASSED in {d} s\n", .{(session_mod.now_ms() - started) / 1000});
    return code;
}

fn demo(init: std.process.Init, out: *Io.Writer, options: H.Options) !u8 {
    const io = init.io;
    const accel = harness.choose_accel(options.accel, H.kvm_usable(io)) catch |err| switch (err) {
        error.NoKvm => {
            try out.print("demo-m6: /dev/kvm is not usable here; for software emulation " ++
                "(slow) add -Daccel=tcg\n", .{});
            return error.NoKvm;
        },
        error.BadAccel => return error.BadAccel,
    };
    const binary = try H.check_binaries(init, out, options);
    if (options.old_zbx.len == 0) {
        try out.print("demo-m6: --old-zbx is missing: the upgrade test needs the M5 binary\n", .{});
        return error.MissingBinary;
    }
    const arena = init.arena.allocator();
    const old_binary = try Io.Dir.cwd().readFileAlloc(
        io,
        options.old_zbx,
        arena,
        .limited(limits.elf_bytes_max),
    );
    try out.print("demo-m6: upgrade test from {s}: {s}, {d} bytes\n", .{
        old_release.m6_commit, options.old_zbx, old_binary.len,
    });
    const base = try image.ensure(init, options.cache_dir, out);
    const overlay_pattern = "{s}/overlay-demo-m6.qcow2";
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
    state.step_state,
    mounts.step_mounts,
};

fn steps(session: *Session, out: *Io.Writer, timer: *H.Timer, with_ca: bool) !void {
    try accept.install_old(session, out);
    try common.write_wrappers(session, out, with_ca);
    try old_wrapper.write_old_wrapper(session, out, with_ca);
    inline for (parts) |part| try part(session, out, timer);
}

test {
    // The files this demo is made of carry their own unit tests; a test root reaches them here.
    _ = @import("checks_spec_m6.zig");
    _ = @import("checks_upgrade_m6.zig");
    _ = @import("spec_m6.zig");
    _ = @import("state_m6.zig");
    _ = @import("mounts_m6.zig");
    _ = @import("upgrade_m6.zig");
}
