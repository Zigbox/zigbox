//! The M7 demo (`zbx build`), run in a real Ubuntu 24.04 VM (the harness of the M0 to M6b
//! demos). It is a list of parts, run in order; each part is a function of `parts` below.
//!
//! Two VMs. The first runs these parts, in order:
//!
//! UPGRADE (upgrade_m7.zig): the 0.2.0 `zbx` (`m7_commit` in `old_release.zon`) pulls alpine:3.20
//!   and starts a container; this `zbx` reads its store and version-8 run record.
//! SPEC (spec_m6b.zig): the M6b spec part, still green with `zbx build` in the binary.
//! HELLO (hello_m7.zig): the brief's steps 1 to 4 on the Go hello-world.
//! ACCEPT (accept_m7.zig): graph, order, touch, the three refusals, a clean store.
//! AGENT (agent_m7.zig): `zbx build` by JSON only; what it cannot read is a `FINDING`.
//! BUILD, RESULT (spec_m7.zig, spec_m7_result.zig): slice 2 and 3's checks. They remove the base
//!   from the store, so they run last.
//!
//! The second VM is clean: HELLO's steps 5 and 6 (hello_m7.zig): the same digest as step 1, equal
//! to the golden in `m7_expected.zon`; and a `fetch` step with no network is refused.
//!
//! `zig build demo-m7 -Daccel=tcg` for software emulation.

const std = @import("std");
const Io = std.Io;
const accept = @import("accept_m4.zig");
const accept_m7 = @import("accept_m7.zig");
const agent = @import("agent_m7.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const hello = @import("hello_m7.zig");
const image = @import("image.zig");
const limits = @import("limits.zig");
const old_release = @import("old_release.zon");
const old_wrapper = @import("upgrade_m5.zig");
const session_mod = @import("session.zig");
const spec_m6b = @import("spec_m6b.zig");
const upgrade = @import("upgrade_m7.zig");
const result = @import("spec_m7_result.zig");
const spec = @import("spec_m7.zig");

const Session = session_mod.Session;
const H = harness;

pub fn main(init: std.process.Init) !u8 {
    harness.demo_name = "demo-m7";
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const options = H.parse_options(init) catch |err| {
        try out.print("demo-m7: bad arguments ({s})\n", .{@errorName(err)});
        return 2;
    };
    const started = session_mod.now_ms();
    const code = demo(init, out, options) catch |err| {
        if (err == error.NoKvm) return 1;
        try out.print("\ndemo-m7: FAILED ({s})\n", .{@errorName(err)});
        return 1;
    };
    try out.print("\ndemo-m7: PASSED in {d} s\n", .{(session_mod.now_ms() - started) / 1000});
    return code;
}

fn demo(init: std.process.Init, out: *Io.Writer, options: H.Options) !u8 {
    const io = init.io;
    const accel = harness.choose_accel(options.accel, H.kvm_usable(io)) catch |err| switch (err) {
        error.NoKvm => {
            try out.print("demo-m7: /dev/kvm is not usable here; for software emulation " ++
                "(slow) add -Daccel=tcg\n", .{});
            return error.NoKvm;
        },
        error.BadAccel => return error.BadAccel,
    };
    const binary = try H.check_binaries(init, out, options);
    if (options.old_zbx.len == 0) {
        try out.print("demo-m7: --old-zbx is missing: the upgrade test needs 0.2.0\n", .{});
        return error.MissingBinary;
    }
    const arena = init.arena.allocator();
    const old_binary = try Io.Dir.cwd().readFileAlloc(
        io,
        options.old_zbx,
        arena,
        .limited(limits.elf_bytes_max),
    );
    try out.print("demo-m7: upgrade test from {s}: {s}, {d} bytes\n", .{
        old_release.m7_commit, options.old_zbx, old_binary.len,
    });
    const base = try image.ensure(init, options.cache_dir, out);
    var ca_file: []const u8 = "";
    if (options.ca_file.len > 0) {
        const limit: Io.Limit = .limited(limits.http_body_bytes_max);
        ca_file = try Io.Dir.cwd().readFileAlloc(io, options.ca_file, arena, limit);
    }
    const context: Context = .{
        .init = init,
        .out = out,
        .options = options,
        .accel = accel,
        .base = base,
        .binary = binary,
        .old_binary = old_binary,
        .ca_file = ca_file,
    };
    try first_vm(context);
    try second_vm(context);
    return 0;
}

const Context = struct {
    init: std.process.Init,
    out: *Io.Writer,
    options: H.Options,
    accel: session_mod.Accel,
    base: []const u8,
    binary: []const u8,
    old_binary: []const u8,
    ca_file: []const u8,
};

/// Starts a VM on its own overlay of the base image; `name` tells the two apart.
fn start_vm(context: Context, session: *Session, name: []const u8, old: bool) !void {
    const arena = context.init.arena.allocator();
    const overlay_pattern = "{s}/overlay-demo-m7-{s}.qcow2";
    const overlay = try std.fmt.allocPrint(
        arena,
        overlay_pattern,
        .{ context.options.cache_dir, name },
    );
    if (!context.options.reuse_overlay) try image.make_overlay(context.init, context.base, overlay);
    try session_mod.start(session, context.init, context.out, overlay, context.accel, .{
        .binary = context.binary,
        .old_binary = if (old) context.old_binary else &.{},
        .ca_file = context.ca_file,
    });
}

fn first_vm(context: Context) !void {
    var session: Session = undefined;
    try start_vm(context, &session, "one", true);
    defer session.deinit();
    var timer = H.Timer.start();
    try H.provision(&session, context.out, &timer, context.options.reuse_overlay);
    try H.install_binary(&session, context.out, &timer);
    const with_ca = context.ca_file.len > 0;
    try accept.install_old(&session, context.out);
    try common.write_wrappers(&session, context.out, with_ca);
    try old_wrapper.write_old_wrapper(&session, context.out, with_ca);
    inline for (parts) |part| try part(&session, context.out, &timer);
    try session.shutdown();
}

/// The clean VM: a store nothing has touched, and the same project.
fn second_vm(context: Context) !void {
    var session: Session = undefined;
    try start_vm(context, &session, "two", false);
    defer session.deinit();
    var timer = H.Timer.start();
    try H.provision(&session, context.out, &timer, context.options.reuse_overlay);
    try H.install_binary(&session, context.out, &timer);
    try common.write_wrappers(&session, context.out, context.ca_file.len > 0);
    try hello.step_second(&session, context.out, &timer);
    try session.shutdown();
}

/// The parts, in order. A part is `fn (*Session, *Io.Writer, *H.Timer) !void`.
const parts = [_]*const fn (*Session, *Io.Writer, *H.Timer) anyerror!void{
    upgrade.step_upgrade,
    spec_m6b.step_spec,
    hello.step_first,
    accept_m7.step_accept,
    agent.run_agent,
    spec.step_build,
    result.step_result,
};

test {
    // The files this demo is made of carry their own unit tests; a test root reaches them here.
    _ = @import("checks_m7.zig");
    _ = @import("hello_m7.zig");
    _ = @import("upgrade_m7.zig");
    _ = @import("accept_m7.zig");
    _ = @import("agent_m7.zig");
    _ = @import("spec_m7.zig");
    _ = @import("spec_m7_result.zig");
}
