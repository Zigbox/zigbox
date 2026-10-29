//! `zbx doctor` on macOS (milestone M4b, slice 5): run here, not forwarded. It looks at what the
//! virtual machine needs from this Mac and from this binary, one line per check:
//!
//!     ok   entitlement  signed with com.apple.security.virtualization
//!     ok   vm           stopped; it starts when a command needs it
//!     ok   version      this zbx carries image 0123456789abcdef
//!     ok   share        /Users/ada is shared with the machine
//!     ok   disk         412 GiB free on the Mac's volume; the disk image is 64 GiB, sparse
//!     warn rosetta      not installed ... [ZBX-E1016]
//!
//! A failing check has a coded diagnostic with a fix, as on Linux (stderr); `--output json` is the
//! `zbx.doctor/1` document with these ids. The exit code is 0, or 2 when a check fails; a warning
//! changes nothing. With the machine running, the guest's own doctor (the Linux one) is forwarded
//! and shown after the report: as text under a heading, as the `guest` member in JSON. Its result
//! is information about the guest and does not change this exit code.

const std = @import("std");
const assert = std.debug.assert;
const codes = @import("../diag/codes.zig");
const commands = @import("commands.zig");
const constants = @import("../constants.zig");
const diagnose = @import("diagnose.zig");
const files = @import("files.zig");
const forward = @import("forward.zig");
const image = @import("image.zig");
const render = @import("../diag/render.zig");
const settings_file = @import("settings_file.zig");
const vz = @import("vz.zig");
const Diag = @import("../diag/diag.zig").Diag;

extern "c" fn _NSGetExecutablePath(buffer: [*]u8, size: *u32) i32;

pub const Status = enum { ok, warn, fail };
pub const Id = enum { entitlement, vm, version, share, disk, rosetta };

const detail_bytes_max: usize = 240;

pub const Check = struct {
    id: Id,
    status: Status = .ok,
    detail: [detail_bytes_max]u8 = undefined,
    detail_length: usize = 0,
    diag: Diag = undefined,

    fn say(check: *Check, comptime format: []const u8, args: anytype) void {
        const written = std.fmt.bufPrint(&check.detail, format, args) catch check.detail[0..0];
        check.detail_length = written.len;
        assert(check.detail_length > 0);
    }

    pub fn text(check: *const Check) []const u8 {
        assert(check.detail_length > 0);
        return check.detail[0..check.detail_length];
    }
};

/// All checks, in the order of the report.
pub const Report = struct {
    checks: [6]Check = undefined,

    pub fn failed(report: *const Report) bool {
        for (&report.checks) |*check| {
            if (check.status == .fail) return true;
        }
        return false;
    }
};

/// What the entitlement listing of `codesign` says about the binary.
pub const Signature = enum { entitled, unsigned, not_entitled, unreadable };

const entitlement_key = "com.apple.security.virtualization";

/// Reads `codesign -d --entitlements -` output: the listing names the key when the binary has it.
pub fn signature_of(output: []const u8, exit_code: ?u8) Signature {
    assert(output.len <= 1 << 20);
    const code = exit_code orelse return .unreadable;
    if (std.mem.indexOf(u8, output, "not signed at all") != null) return .unsigned;
    if (code != 0) return .unreadable;
    if (std.mem.indexOf(u8, output, entitlement_key) != null) return .entitled;
    return .not_entitled;
}

fn executable_path(buffer: *[constants.vm_path_bytes_max:0]u8) ?[:0]const u8 {
    var size: u32 = constants.vm_path_bytes_max;
    if (_NSGetExecutablePath(buffer, &size) != 0) return null;
    return std.mem.sliceTo(buffer, 0);
}

fn check_entitlement(check: *Check) void {
    assert(check.id == .entitlement);
    var path_storage: [constants.vm_path_bytes_max:0]u8 = undefined;
    const path = executable_path(&path_storage) orelse {
        check.status = .warn;
        check.say("cannot find this binary's own path", .{});
        check.diag.reset();
        diagnose.not_allowed(&check.diag, null);
        return;
    };
    var output: [4096]u8 = undefined;
    var kept: usize = 0;
    const argv = [_:null]?[*:0]const u8{
        "/usr/bin/codesign", "-d", "--entitlements", "-", path.ptr,
    };
    const exit_code = files.run_program(&argv, &output, &kept);
    switch (signature_of(output[0..kept], exit_code)) {
        .entitled => check.say("signed with {s}", .{entitlement_key}),
        .unsigned => fail_entitlement(check, "this binary is not signed"),
        .not_entitled => fail_entitlement(check, "signed without " ++ entitlement_key),
        .unreadable => {
            check.status = .warn;
            check.say("codesign could not read this binary's signature", .{});
            check.diag.reset();
            diagnose.not_allowed(&check.diag, null);
        },
    }
    assert(check.detail_length > 0);
}

fn fail_entitlement(check: *Check, detail: []const u8) void {
    assert(detail.len > 0);
    check.status = .fail;
    check.say("{s}", .{detail});
    check.diag.reset();
    diagnose.not_allowed(&check.diag, null);
    assert(check.diag.code.? == .E1001);
}

fn check_vm(ctx: *const commands.Context, check: *Check, version: *Check) void {
    assert(check.id == .vm);
    assert(version.id == .version);
    version.say("this zbx carries image {s}", .{image.version});
    switch (commands.probe(ctx.paths, constants.vm_control_timeout_ms)) {
        .absent => check.say("stopped; it starts when a command needs it", .{}),
        .answering => |status| {
            check.say("{s}, pid {d}, {d} cpus, {d} MiB", .{
                @tagName(status.state), status.pid, status.cpus, status.memory_bytes >> 20,
            });
            if (!std.mem.eql(u8, &status.version, image.version)) {
                version.status = .warn;
                version.say("the machine runs image {s}, this zbx carries {s}", .{
                    &status.version, image.version,
                });
                version.diag.reset();
                diagnose.replacing(&version.diag, &status.version, image.version);
            }
        },
        .other_format => {
            check.say("running, from another release of zbx", .{});
            version.status = .warn;
            version.say("the machine runs another release's image", .{});
            version.diag.reset();
            diagnose.replacing(&version.diag, "another release", image.version);
        },
        .held => |pid| {
            check.status = .fail;
            check.say("another process holds the machine's lock and does not answer", .{});
            check.diag.reset();
            diagnose.host_locked(&check.diag, pid);
        },
    }
}

fn check_share(check: *Check) void {
    assert(check.id == .share);
    var storage: [constants.vm_path_bytes_max:0]u8 = undefined;
    if (files.shared_home(&storage)) |home| {
        check.say("{s} is shared with the machine at the same path", .{home});
        return;
    }
    check.status = .fail;
    check.say("$HOME is not an absolute directory that can be shared", .{});
    check.diag.reset();
    diagnose.directory(&check.diag, "finding the directory to share", "$HOME", "cannot be resolved");
}

fn check_disk(ctx: *const commands.Context, host_cpus: u32, check: *Check) void {
    assert(check.id == .disk);
    assert(host_cpus >= 1);
    const loaded = settings_file.load(ctx.paths, host_cpus, &check.diag) catch {
        check.status = .fail;
        check.say("the machine's settings cannot be read", .{});
        return;
    };
    const base = ctx.paths.base.slice();
    const free = files.free_bytes(base);
    const have = files.file_size(ctx.paths.store_disk.slice());
    if (free < constants.vm_disk_host_free_bytes_min) {
        check.status = .fail;
        check.say("{d} MiB free on the Mac's volume, less than the {d} MiB it needs", .{
            free >> 20, constants.vm_disk_host_free_bytes_min >> 20,
        });
        check.diag.reset();
        const needed = constants.vm_disk_host_free_bytes_min;
        diagnose.host_volume_full(&check.diag, ctx.paths.store_disk.slice(), free, needed);
        return;
    }
    check.say("{d} GiB free on the Mac's volume; the disk image is {d} MiB of {d} GiB", .{
        free >> 30, have >> 20, loaded.values.disk_bytes >> 30,
    });
}

fn check_rosetta(check: *Check) void {
    assert(check.id == .rosetta);
    const state = vz.rosetta_state();
    if (state == .installed) return check.say("installed: linux/amd64 images can run", .{});
    check.status = .warn;
    if (state == .not_installed) {
        check.say("not installed: only linux/amd64 images need it", .{});
    } else {
        check.say("not available on this Mac: linux/amd64 images cannot run", .{});
    }
    check.diag.reset();
    diagnose.rosetta_missing(&check.diag);
}

/// Runs every check.
pub fn inspect(ctx: *const commands.Context, host_cpus: u32, report: *Report) void {
    assert(host_cpus >= 1);
    for (&report.checks, 0..) |*check, index| {
        check.* = .{ .id = @fromBackingInt(@intCast(index)) };
        check.diag.reset();
    }
    check_entitlement(&report.checks[@backingInt(Id.entitlement)]);
    check_vm(ctx, &report.checks[@backingInt(Id.vm)], &report.checks[@backingInt(Id.version)]);
    check_share(&report.checks[@backingInt(Id.share)]);
    check_disk(ctx, host_cpus, &report.checks[@backingInt(Id.disk)]);
    check_rosetta(&report.checks[@backingInt(Id.rosetta)]);
    for (&report.checks) |*check| assert(check.detail_length > 0);
}

fn label_of(status: Status) []const u8 {
    return switch (status) {
        .ok => "ok  ",
        .warn => "warn",
        .fail => "FAIL",
    };
}

/// The text report: a line per check, the code of a warning or failure after it.
pub fn render_text(report: *const Report, buffer: []u8) []const u8 {
    assert(buffer.len >= constants.output_bytes_max);
    var writer: std.Io.Writer = .fixed(buffer);
    for (&report.checks) |*check| {
        // Cannot fail: six lines of at most 300 bytes fit the output buffer.
        writer.print("{s} {s}  {s}", .{ label_of(check.status), @tagName(check.id), check.text() }) catch unreachable;
        if (check.status != .ok) {
            const name = codes.full_name(check.diag.code.?);
            writer.print("  [{s}]", .{name}) catch unreachable; // Same.
        }
        writer.writeAll("\n") catch unreachable; // Same.
    }
    return writer.buffered();
}

fn json_string(writer: *std.Io.Writer, text: []const u8) !void {
    try writer.writeByte('"');
    for (text) |byte| {
        switch (byte) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            0...0x1f => try writer.print("\\u{x:0>4}", .{byte}),
            else => try writer.writeByte(byte),
        }
    }
    try writer.writeByte('"');
}

/// Where one diagnostic is rendered on its way into the document (a process makes one report).
var diag_buffer: [constants.output_bytes_max]u8 = undefined;

/// The `zbx.doctor/1` document; `guest` is the guest doctor's own JSON document, or null. Written
/// without the guest member when there is none.
pub fn render_json(report: *const Report, guest: ?[]const u8, buffer: []u8) []const u8 {
    assert(buffer.len >= constants.output_bytes_max);
    var writer: std.Io.Writer = .fixed(buffer);
    // Cannot fail: six checks with a detail and a diagnostic each fit the output buffer.
    writer.print("{{\"schema\":\"zbx.doctor/1\",\"ok\":{s},\"checks\":[", .{
        if (report.failed()) "false" else "true",
    }) catch unreachable;
    for (&report.checks, 0..) |*check, index| {
        if (index > 0) writer.writeAll(",") catch unreachable; // Same.
        writer.print("{{\"id\":\"{s}\",\"status\":\"{s}\",\"detail\":", .{
            @tagName(check.id), @tagName(check.status),
        }) catch unreachable; // Same.
        json_string(&writer, check.text()) catch unreachable; // Same.
        if (check.status != .ok) {
            const name = codes.full_name(check.diag.code.?);
            writer.print(",\"code\":\"{s}\",\"diagnostic\":", .{name}) catch unreachable; // Same.
            const line = render.render(&check.diag, .json, false, &diag_buffer);
            writer.writeAll(std.mem.trimEnd(u8, line, "\n")) catch unreachable; // Same.
        }
        writer.writeAll("}") catch unreachable; // Same.
    }
    writer.writeAll("]") catch unreachable; // Same.
    if (guest) |document| writer.print(",\"guest\":{s}", .{document}) catch unreachable; // Same.
    writer.writeAll("}\n") catch unreachable; // Same.
    return writer.buffered();
}

/// The guest's doctor, when the machine runs: its JSON document (kept in `buffer`), or null.
fn guest_json(ctx: *const commands.Context, buffer: []u8, diag: *Diag) ?[]const u8 {
    assert(buffer.len > 0);
    var path: [constants.vm_path_bytes_max + 1:0]u8 = @splat(0);
    const written = std.fmt.bufPrint(&path, "{s}/doctor-guest.tmp", .{ctx.paths.base.slice()}) catch {
        return null;
    };
    const name: [:0]const u8 = path[0..written.len :0];
    const flags: std.c.O = .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true };
    const descriptor = std.c.open(name.ptr, flags, @as(std.c.mode_t, 0o600));
    if (descriptor < 0) return null;
    forward.stdout_descriptor = descriptor;
    const words = [_][]const u8{ "--output", "json", "doctor" };
    const command: forward.Command = .{ .words = &words, .json = true, .is_run = false };
    _ = forward.run(ctx, &command, diag) catch {};
    forward.stdout_descriptor = 1;
    files.close(descriptor);
    defer _ = std.c.unlink(name.ptr);
    const text = files.read_file(name, buffer) catch return null;
    const trimmed = std.mem.trim(u8, text, " \n");
    if (trimmed.len == 0 or trimmed[0] != '{') return null;
    return trimmed;
}

const guest_heading =
    "\nguest: the Linux zbx's own doctor, in the machine. It does not change the exit code.\n" ++
    "  The machine has no systemd, so its cgroup check always fails: zbx runs there with a\n" ++
    "  delegated cgroup subtree of its own instead.\n";

/// Runs the doctor. The report goes to stdout, a diagnostic per failing or warning check to
/// stderr. Returns the exit code.
pub fn run(ctx: *const commands.Context, host_cpus: u32, diag: *Diag) u8 {
    assert(host_cpus >= 1);
    assert(diag.code == null);
    var report: Report = .{};
    inspect(ctx, host_cpus, &report);
    const running = report.checks[@backingInt(Id.vm)].status == .ok and
        !std.mem.startsWith(u8, report.checks[@backingInt(Id.vm)].text(), "stopped");
    var buffer: [constants.output_bytes_max]u8 = undefined;
    if (ctx.json) {
        var guest_storage: [constants.output_bytes_max / 2]u8 = undefined;
        const guest = if (running) guest_json(ctx, &guest_storage, diag) else null;
        diag.reset();
        commands.print(render_json(&report, guest, &buffer));
    } else {
        commands.print(render_text(&report, &buffer));
    }
    for (&report.checks) |*check| {
        if (check.status == .ok) continue;
        var rendered: [constants.output_bytes_max]u8 = undefined;
        const text = render.render(&check.diag, ctx.mode, false, &rendered);
        files.write_all(2, text) catch {};
    }
    if (running and !ctx.json) {
        commands.print(guest_heading);
        const words = [_][]const u8{"doctor"};
        const command: forward.Command = .{ .words = &words, .json = false, .is_run = false };
        _ = forward.run(ctx, &command, diag) catch {};
        diag.reset();
    }
    return if (report.failed()) constants.exit_environment else constants.exit_ok;
}

test "the entitlement listing is read for the key, an unsigned binary and a failure" {
    // Goal: the one decision the entitlement check makes. Method: the three outputs codesign
    // gives (taken from a signed build, an unsigned one and a missing file), and no output.
    const listing =
        "Executable=/x/zbx\n<?xml version=\"1.0\"?><plist><dict><key>" ++
        entitlement_key ++ "</key><true/></dict></plist>\n";
    try std.testing.expectEqual(Signature.entitled, signature_of(listing, 0));
    const other = "<plist><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>";
    try std.testing.expectEqual(Signature.not_entitled, signature_of(other, 0));
    const unsigned = "/x/zbx: code object is not signed at all\n";
    try std.testing.expectEqual(Signature.unsigned, signature_of(unsigned, 1));
    try std.testing.expectEqual(Signature.unreadable, signature_of("no such file", 1));
    try std.testing.expectEqual(Signature.unreadable, signature_of("", null));
}

/// A report that is healthy, or one with a failure and two warnings, with fixed details.
fn fixture(failing: bool) Report {
    var report: Report = .{};
    const details = [_][]const u8{
        "signed with com.apple.security.virtualization",
        "running, pid 4121, 4 cpus, 2048 MiB",
        "this zbx carries image 0123456789abcdef",
        "/Users/ada is shared with the machine at the same path",
        "412 GiB free on the Mac's volume; the disk image is 1203 MiB of 64 GiB",
        "installed: linux/amd64 images can run",
    };
    for (&report.checks, details, 0..) |*check, detail, index| {
        check.* = .{ .id = @fromBackingInt(@intCast(index)) };
        check.say("{s}", .{detail});
        check.diag.reset();
    }
    if (!failing) return report;
    const entitlement = &report.checks[@backingInt(Id.entitlement)];
    entitlement.status = .fail;
    entitlement.say("this binary is not signed", .{});
    diagnose.not_allowed(&entitlement.diag, null);
    const version = &report.checks[@backingInt(Id.version)];
    version.status = .warn;
    version.say("the machine runs image fedcba9876543210, this zbx carries 0123456789abcdef", .{});
    diagnose.replacing(&version.diag, "fedcba9876543210", "0123456789abcdef");
    const rosetta = &report.checks[@backingInt(Id.rosetta)];
    rosetta.status = .warn;
    rosetta.say("not installed: only linux/amd64 images need it", .{});
    diagnose.rosetta_missing(&rosetta.diag);
    return report;
}

const guest_sample = "{\"schema\":\"zbx.doctor/1\",\"ok\":true,\"checks\":[]}";

test "golden: the macOS doctor's report, healthy and failing, as text and as JSON" {
    // Goal: the text and the zbx.doctor/1 document are part of the product. Method: fixed
    // reports (all ok; a failure and two warnings, with a guest document) against the files in
    // src/testdata/doctor/.
    const test_util = @import("../test_util.zig");
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const healthy = fixture(false);
    const failing = fixture(true);
    const cases = [_]struct { report: *const Report, text: []const u8, json: []const u8, guest: ?[]const u8 }{
        .{
            .report = &healthy,
            .text = @embedFile("../testdata/doctor/mac_healthy.txt"),
            .json = @embedFile("../testdata/doctor/mac_healthy.json.txt"),
            .guest = guest_sample,
        },
        .{
            .report = &failing,
            .text = @embedFile("../testdata/doctor/mac_failing.txt"),
            .json = @embedFile("../testdata/doctor/mac_failing.json.txt"),
            .guest = null,
        },
    };
    for (cases) |case| {
        try std.testing.expectEqualStrings(case.text, render_text(case.report, &buffer));
        const json = render_json(case.report, case.guest, &buffer);
        try std.testing.expectEqualStrings(case.json, json);
        try std.testing.expect(try test_util.json_is_valid(std.mem.trimEnd(u8, json, "\n")));
    }
    try std.testing.expect(!healthy.failed());
    try std.testing.expect(failing.failed());
    try std.testing.expectEqual(Status.fail, failing.checks[0].status);
}
