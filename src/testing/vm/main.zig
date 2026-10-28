//! The M0 demo, run in a real Ubuntu 24.04 VM:
//!   1. `zbx doctor` on the fresh VM: every check ok, empty stderr, exit 0.
//!   2. With user namespaces disabled by sysctl, the userns check FAILs with its code on the
//!      stdout line (`[ZBX-E0101]`), stderr holds the `error[ZBX-E0101]` block with a fix that
//!      names the sysctl, and the exit code is 2; the sysctls are restored and doctor is ok.
//!   3. `file zbx` reports a statically linked ELF; both release binaries (x86_64 and aarch64)
//!      are checked here, in Zig, to be static ELF files under 4 MiB.
//!   4. `zbx frobnicate` prints `error[ZBX-E0001]` on stderr and exits 1.
//! The guest console merges stdout and stderr, so every `zbx` command runs through
//! `run_split`, which keeps stderr in a file in the guest and prints it after a marker.
//! Run it with `zig build demo-m0` (KVM) or `zig build demo-m0 -Daccel=tcg` (software
//! emulation, slow). See docs/demos/m0.md.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const checks = @import("checks.zig");
const cloud_init = @import("cloud_init.zig");
const image = @import("image.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");

const Session = session_mod.Session;
const harness = @import("harness.zig");
const H = harness;

pub fn main(init: std.process.Init) !u8 {
    harness.demo_name = "demo-m0";
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const options = H.parse_options(init) catch |err| {
        try out.print("demo-m0: bad arguments ({s}); see docs/demos/m0.md\n", .{@errorName(err)});
        return 2;
    };
    const started = session_mod.now_ms();
    const code = demo(init, out, options) catch |err| {
        // The no-KVM message is already the whole story: one line, no stack of noise.
        if (err == error.NoKvm) return 1;
        try out.print("\ndemo-m0: FAILED ({s})\n", .{@errorName(err)});
        return 1;
    };
    try out.print("\ndemo-m0: PASSED in {d} s\n", .{(session_mod.now_ms() - started) / 1000});
    return code;
}

fn demo(init: std.process.Init, out: *Io.Writer, options: H.Options) !u8 {
    const io = init.io;
    const accel = harness.choose_accel(options.accel, H.kvm_usable(io)) catch |err| switch (err) {
        error.NoKvm => {
            try out.print("demo-m0: /dev/kvm is not usable here; for software emulation " ++
                "(slow) add -Daccel=tcg\n", .{});
            return error.NoKvm;
        },
        error.BadAccel => return error.BadAccel,
    };
    const binary = try H.check_binaries(init, out, options);
    const base = try image.ensure(init, options.cache_dir, out);
    const arena = init.arena.allocator();
    const overlay_format = "{s}/overlay-demo-m0.qcow2";
    const overlay = try std.fmt.allocPrint(arena, overlay_format, .{options.cache_dir});
    if (!options.reuse_overlay) try image.make_overlay(init, base, overlay);
    defer if (!options.keep_overlay) Io.Dir.cwd().deleteFile(io, overlay) catch {};

    const user_data = if (options.delegate_dropin)
        cloud_init.user_data_with_delegate
    else
        cloud_init.user_data;
    var session: Session = undefined;
    try session.start(init, out, overlay, accel, .{ .user_data = user_data, .binary = binary });
    defer session.deinit();
    var timer = H.Timer.start();
    try H.provision(&session, out, &timer, options.reuse_overlay);
    try H.install_binary(&session, out, &timer);
    try step_doctor_ok(&session, out, &timer);
    try step_userns_fails(&session, out, &timer);
    try step_static(&session, out, &timer);
    try step_usage_error(&session, out, &timer);
    try session.shutdown();
    return 0;
}

// The doctor looks for the user's bus, so it runs with the demo user's session variables.
const doctor_as_demo = H.as_demo ++ "/home/demo/zbx doctor";

fn step_doctor_ok(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m0: STEP 1: zbx doctor on the fresh VM, as user demo\n", .{});
    const result = try H.run_split(session, doctor_as_demo);
    try H.show_split(out, doctor_as_demo, result);
    checks.check_all_ok(result.streams, result.status) catch |err| {
        try out.print("demo-m0: STEP 1 FAILED: expected seven lines, six `ok` and `net` ok or warn, empty stderr and " ++
            "exit 0 ({s})\n", .{
            @errorName(err),
        });
        return err;
    };
    try timer.lap(out, "step 1");
}

/// Copies a short sysctl value (digits) into `storage`, refusing anything else.
fn copy_value(storage: []u8, value: ?[]const u8) ![]const u8 {
    const text = std.mem.trim(u8, value orelse return error.BadSysctl, " \r");
    if (text.len == 0 or text.len > storage.len) return error.BadSysctl;
    for (text) |byte| {
        if (!std.ascii.isDigit(byte)) return error.BadSysctl;
    }
    @memcpy(storage[0..text.len], text);
    return storage[0..text.len];
}

const Case = struct {
    title: []const u8,
    set: []const u8,
    /// Text the block's fix must contain: the sysctl that was changed.
    fix_contains: []const u8,
};

fn step_userns_fails(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m0: STEP 2: disable user namespaces by sysctl; the userns check " ++
        "must FAIL as ZBX-E0101, with its block and a fix on stderr, and exit 2\n", .{});
    const read_sysctls = "sysctl -n kernel.apparmor_restrict_unprivileged_userns; " ++
        "sysctl -n user.max_user_namespaces";
    const original = try session.run(read_sysctls, limits.command_timeout_kvm_s);
    // `original.output` lives in the session's scratch buffer, which the next command
    // overwrites: copy the two values out before running anything else.
    var apparmor_storage: [16]u8 = undefined;
    var maximum_storage: [16]u8 = undefined;
    var values = std.mem.splitScalar(u8, original.output, '\n');
    const apparmor = try copy_value(&apparmor_storage, values.next());
    const maximum = try copy_value(&maximum_storage, values.next());
    const cases = [_]Case{
        .{
            .title = "AppArmor restriction on",
            .set = "kernel.apparmor_restrict_unprivileged_userns=1",
            .fix_contains = "kernel.apparmor_restrict_unprivileged_userns",
        },
        .{
            .title = "user.max_user_namespaces=0 (the restriction is still on)",
            .set = "user.max_user_namespaces=0",
            .fix_contains = "user.max_user_namespaces",
        },
    };
    for (cases) |case| {
        try expect_userns_failure(session, out, case);
    }
    var restore_buffer: [160]u8 = undefined;
    const restore_format = "sysctl -w kernel.apparmor_restrict_unprivileged_userns={s} " ++
        "user.max_user_namespaces={s}";
    const restore = try std.fmt.bufPrint(&restore_buffer, restore_format, .{ apparmor, maximum });
    try H.show(out, restore, try session.run(restore, limits.command_timeout_kvm_s));
    const again = try H.run_split(session, doctor_as_demo);
    try H.show_split(out, doctor_as_demo ++ "   (after restoring the sysctls)", again);
    checks.check_all_ok(again.streams, again.status) catch |err| {
        try out.print("demo-m0: STEP 2 FAILED: doctor is not ok after restoring ({s})\n", .{
            @errorName(err),
        });
        return err;
    };
    try timer.lap(out, "step 2");
}

fn expect_userns_failure(session: *Session, out: *Io.Writer, case: Case) !void {
    var command_buffer: [200]u8 = undefined;
    const command = try std.fmt.bufPrint(&command_buffer, "sysctl -w {s}", .{case.set});
    try out.print("\ndemo-m0: case: {s}\n", .{case.title});
    try H.show(out, command, try session.run(command, limits.command_timeout_kvm_s));
    const result = try H.run_split(session, doctor_as_demo);
    try H.show_split(out, doctor_as_demo, result);
    const expected: checks.Failure = .{
        .name = "userns",
        .code = "ZBX-E0101",
        .summary = "can't create a user namespace",
        .fix_contains = case.fix_contains,
    };
    checks.check_fails_with_fix(result.streams, result.status, expected) catch |err| {
        try out.print("demo-m0: STEP 2 FAILED: with `{s}` expected `FAIL userns ... " ++
            "[ZBX-E0101]`, an `error[ZBX-E0101]: can't create a user namespace` block whose " ++
            "fix names {s}, and exit 2 ({s})\n", .{ case.set, case.fix_contains, @errorName(err) });
        return err;
    };
}

fn step_static(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m0: STEP 3: file zbx\n", .{});
    const result = try session.run("file /home/demo/zbx", limits.command_timeout_kvm_s);
    try H.show(out, "file /home/demo/zbx", result);
    if (result.status != 0) return error.FileFailed;
    checks.check_file_says_static(result.output) catch |err| {
        try out.print("demo-m0: STEP 3 FAILED: `file` does not say statically linked ({s})\n", .{
            @errorName(err),
        });
        return err;
    };
    try timer.lap(out, "step 3");
}

// no-bus-env: a usage error is found before any bus is looked for.
const mistyped = "runuser -u demo -- /home/demo/zbx frobnicate";

fn step_usage_error(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m0: STEP 4: a mistyped command is a usage error, exit 1\n", .{});
    const result = try H.run_split(session, mistyped);
    try H.show_split(out, mistyped, result);
    checks.check_unknown_command(result.streams, result.status) catch |err| {
        try out.print("demo-m0: STEP 4 FAILED: expected `error[ZBX-E0001]: unknown command` " ++
            "on stderr, nothing on stdout, and exit 1 ({s})\n", .{@errorName(err)});
        return err;
    };
    try timer.lap(out, "step 4");
}

test {
    _ = @import("harness.zig");
    _ = @import("checks_m1.zig");
    _ = @import("checks.zig");
    _ = @import("cloud_init.zig");
    _ = @import("http_server.zig");
    _ = @import("image.zig");
    _ = @import("session.zig");
}
