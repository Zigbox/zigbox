//! The M9 demo (`zbx import`), run in a real Ubuntu 24.04 VM (the harness of the M0 to M7
//! demos). It is a list of parts, run in order; each part is a function of `parts` below.
//!
//! Two VMs. The first runs these parts, in order:
//!
//! SPEC (spec_m6b.zig): the M6b spec part, still green with `zbx import` in the binary.
//! HELLO (hello_m9.zig): the brief's steps 1 to 4 and 6 on the Go hello-world's Dockerfile.
//! ACCEPT (accept_m9.zig): the fixtures through the binary, the graph, comments, the refusals,
//!   a clean store.
//! AGENT (agent_m9.zig): `zbx import`, `build` and `explain` by JSON only.
//!
//! The second VM is clean: HELLO's step 5 (hello_m9.zig): the same import bytes and the digest of
//! step 2, equal to the golden in `m9_expected.zon`.
//!
//! No upgrade test: M9 changes no store or record format (docs/demos/m9.md).
//!
//! `zig build demo-m9 -Daccel=tcg` for software emulation.

const std = @import("std");
const Io = std.Io;
const accept = @import("accept_m9.zig");
const agent = @import("agent_m9.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const hello = @import("hello_m9.zig");
const image = @import("image.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");
const spec_m6b = @import("spec_m6b.zig");

const Session = session_mod.Session;
const H = harness;

pub fn main(init: std.process.Init) !u8 {
    harness.demo_name = "demo-m9";
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const options = H.parse_options(init) catch |err| {
        try out.print("demo-m9: bad arguments ({s})\n", .{@errorName(err)});
        return 2;
    };
    const started = session_mod.now_ms();
    const code = demo(init, out, options) catch |err| {
        if (err == error.NoKvm) return 1;
        try out.print("\ndemo-m9: FAILED ({s})\n", .{@errorName(err)});
        return 1;
    };
    try out.print("\ndemo-m9: PASSED in {d} s\n", .{(session_mod.now_ms() - started) / 1000});
    return code;
}

fn demo(init: std.process.Init, out: *Io.Writer, options: H.Options) !u8 {
    const io = init.io;
    const accel = harness.choose_accel(options.accel, H.kvm_usable(io)) catch |err| switch (err) {
        error.NoKvm => {
            try out.print("demo-m9: /dev/kvm is not usable here; for software emulation " ++
                "(slow) add -Daccel=tcg\n", .{});
            return error.NoKvm;
        },
        error.BadAccel => return error.BadAccel,
    };
    const binary = try H.check_binaries(init, out, options);
    const arena = init.arena.allocator();
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
    ca_file: []const u8,
};

/// Starts a VM on its own overlay of the base image; `name` tells the two apart.
fn start_vm(context: Context, session: *Session, name: []const u8) !void {
    const arena = context.init.arena.allocator();
    const overlay_pattern = "{s}/overlay-demo-m9-{s}.qcow2";
    const overlay = try std.fmt.allocPrint(
        arena,
        overlay_pattern,
        .{ context.options.cache_dir, name },
    );
    if (!context.options.reuse_overlay) try image.make_overlay(context.init, context.base, overlay);
    try session_mod.start(session, context.init, context.out, overlay, context.accel, .{
        .binary = context.binary,
        .old_binary = &.{},
        .ca_file = context.ca_file,
    });
}

fn first_vm(context: Context) !void {
    var session: Session = undefined;
    try start_vm(context, &session, "one");
    defer session.deinit();
    var timer = H.Timer.start();
    try H.provision(&session, context.out, &timer, context.options.reuse_overlay);
    try H.install_binary(&session, context.out, &timer);
    const with_ca = context.ca_file.len > 0;
    try common.write_wrappers(&session, context.out, with_ca);
    inline for (parts) |part| try part(&session, context.out, &timer);
    try session.shutdown();
}

/// The clean VM: a store nothing has touched, and the same project.
fn second_vm(context: Context) !void {
    var session: Session = undefined;
    try start_vm(context, &session, "two");
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
    spec_m6b.step_spec,
    hello.step_first,
    accept.step_accept,
    agent.run_agent,
};

test {
    // The files this demo is made of carry their own unit tests; a test root reaches them here.
    _ = @import("checks_m9.zig");
    _ = @import("hello_m9.zig");
    _ = @import("accept_m9.zig");
    _ = @import("agent_m9.zig");
}
