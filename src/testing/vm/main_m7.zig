//! The M7 demo (`zbx build`), run in a real Ubuntu 24.04 VM (the harness of the M0 to M6b
//! demos). It is a list of parts, run in order; each part is a function of `parts` below.
//!
//! BUILD (spec_m7.zig): slice 2's check: one step, built (a miss), built again (a hit, no
//!   container), and a build killed mid-step whose leftover work directory the next build sweeps.
//!
//! M7 has no older release to upgrade from yet, so there is no `--old-zbx`.
//!
//! `zig build demo-m7 -Daccel=tcg` for software emulation.

const std = @import("std");
const Io = std.Io;
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const image = @import("image.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");
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
    const arena = init.arena.allocator();
    const base = try image.ensure(init, options.cache_dir, out);
    const overlay_pattern = "{s}/overlay-demo-m7.qcow2";
    const overlay = try std.fmt.allocPrint(arena, overlay_pattern, .{options.cache_dir});
    if (!options.reuse_overlay) try image.make_overlay(init, base, overlay);
    defer if (!options.keep_overlay) Io.Dir.cwd().deleteFile(io, overlay) catch {};
    var ca_file: []const u8 = "";
    if (options.ca_file.len > 0) {
        const limit: Io.Limit = .limited(limits.http_body_bytes_max);
        ca_file = try Io.Dir.cwd().readFileAlloc(io, options.ca_file, arena, limit);
    }
    var session: Session = undefined;
    try session_mod.start(&session, init, out, overlay, accel, .{
        .binary = binary,
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
    spec.step_build,
    result.step_result,
};

fn steps(session: *Session, out: *Io.Writer, timer: *H.Timer, with_ca: bool) !void {
    try common.write_wrappers(session, out, with_ca);
    inline for (parts) |part| try part(session, out, timer);
}

test {
    // The file this demo is made of carries its own unit tests; a test root reaches them here.
    _ = @import("spec_m7.zig");
    _ = @import("spec_m7_result.zig");
}
