//! The diagnostics of the macOS VM layer (`10xx`). Each function raises one code with its causes
//! and fixes. The framework's errors arrive here as plain text (domain, code, description): this
//! is where an `NSError` becomes a cause and a fix, and nothing below renders text for the user.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const settings = @import("settings.zig");
const Diag = @import("../diag/diag.zig").Diag;

/// What the framework reported, as text.
pub const Framework = struct {
    domain: []const u8,
    code: i64,
    description: []const u8,
};

/// The step of the start that failed, in words.
pub const Step = enum {
    configuring,
    validating,
    starting,
    connecting,
    stopping,

    pub fn words(step: Step) []const u8 {
        return switch (step) {
            .configuring => "configuring the virtual machine",
            .validating => "validating the virtual machine's configuration",
            .starting => "starting the virtual machine",
            .connecting => "connecting to the virtual machine",
            .stopping => "stopping the virtual machine",
        };
    }
};

/// `text` with the typographic quotes the framework uses (U+2018, U+2019, U+201C, U+201D) as
/// plain ones, in `buffer`, cut at its end. A diagnostic is ASCII-safe on every terminal.
pub fn plain_text(buffer: []u8, text: []const u8) []const u8 {
    assert(buffer.len > 0);
    var length: usize = 0;
    var index: usize = 0;
    while (index < text.len and length < buffer.len) {
        const curly = index + 2 < text.len and text[index] == 0xe2 and text[index + 1] == 0x80;
        if (curly and text[index + 2] >= 0x98 and text[index + 2] <= 0x9d) {
            buffer[length] = if (text[index + 2] <= 0x99) '\'' else '"';
            index += 3;
        } else {
            buffer[length] = text[index];
            index += 1;
        }
        length += 1;
    }
    assert(length <= text.len);
    return buffer[0..length];
}

test "typographic quotes become plain ones" {
    // Goal: the framework's quotes do not reach the user as bytes a terminal may not show.
    // Method: a sentence as the framework writes it, and one cut by a small buffer.
    var buffer: [64]u8 = undefined;
    const said = "The process doesn\xe2\x80\x99t have \xe2\x80\x9ccom.apple\xe2\x80\x9d.";
    const plain = "The process doesn't have \"com.apple\".";
    try std.testing.expectEqualStrings(plain, plain_text(&buffer, said));
    var small: [5]u8 = undefined;
    try std.testing.expectEqualStrings("The p", plain_text(&small, said));
}

/// True if the framework's words say the entitlement is what is missing.
pub fn is_entitlement_text(description: []const u8) bool {
    return std.mem.indexOf(u8, description, "entitlement") != null;
}

/// `framework` is what the framework said when the entitlement is missing; null when it says
/// virtual machines are not supported here at all. The two have different fixes: re-signing or
/// reinstalling cannot make an Intel Mac, or a Mac inside a virtual machine, able to virtualize.
pub fn not_allowed(diag: *Diag, framework: ?Framework) void {
    assert(diag.code == null);
    diag.raise(.E1001);
    diag.while_("checking that this Mac can run a virtual machine", .{});
    const said = framework orelse {
        diag.cause("Virtualization.framework says virtual machines are not supported here", .{});
        diag.fix(.{ .sentence = "run zbx on an Apple silicon Mac, not inside a virtual machine" });
        assert(diag.fixes.count == 1);
        return;
    };
    assert(said.description.len > 0);
    diag.cause("Virtualization.framework refused: {s}", .{said.description});
    // A source build and an installed release cannot be told apart reliably from inside the
    // binary, so both fixes are given, each saying who it is for.
    diag.fix(.{
        .sentence = "if you built zbx from source, sign it from the checkout:",
        .command = "codesign -f -s - --entitlements vm/zbx.entitlements $(which zbx)",
        .template = true,
    });
    diag.fix(.{
        .sentence = "if you installed zbx, reinstall it, which is signed:",
        .command = "brew reinstall zigbox",
        .template = true,
    });
    assert(diag.fixes.count == 2);
}

pub fn start_failed(diag: *Diag, step: Step, framework: ?Framework, console_log: []const u8) void {
    assert(diag.code == null);
    assert(console_log.len > 0);
    diag.raise(.E1002);
    diag.while_("{s}", .{step.words()});
    if (framework) |said| {
        diag.cause("Virtualization.framework said: {s} ({s} {d})", .{
            said.description, said.domain, said.code,
        });
    } else {
        diag.cause("Virtualization.framework gave no reason", .{});
    }
    diag.context("log", "{s}", .{console_log});
    diag.fix_with("read how far the guest got:", "tail -n 20 '{s}'", .{console_log});
    diag.fix(.{ .sentence = "or try a smaller size:", .command = "zbx vm config --memory 1G" });
    assert(diag.fixes.count == 2);
}

pub fn no_answer(diag: *Diag, console_log: []const u8, waited_ms: u32) void {
    assert(diag.code == null);
    assert(waited_ms > 0);
    diag.raise(.E1003);
    diag.while_("waiting for the virtual machine to boot", .{});
    diag.cause("the guest's init did not answer on vsock port {d} within {d} s", .{
        constants.vm_guest_port, @divFloor(waited_ms, 1000),
    });
    diag.context("log", "{s}", .{console_log});
    diag.fix(.{ .sentence = "stop what is left of it:", .command = "zbx vm stop" });
    diag.fix_with("read how far the guest got:", "tail -n 20 '{s}'", .{console_log});
    assert(diag.fixes.count == 2);
}

pub fn host_locked(diag: *Diag, pid: ?u32) void {
    assert(diag.code == null);
    diag.raise(.E1004);
    diag.while_("looking for the process that owns the virtual machine", .{});
    if (pid) |holder| {
        assert(holder > 0);
        diag.cause("process {d} holds the VM lock and does not answer on its socket", .{holder});
        diag.fix_with("end it, then run the command again:", "kill {d}", .{holder});
    } else {
        diag.cause("a process holds the VM lock and does not answer on its socket", .{});
        diag.fix(.{ .sentence = "find it:", .command = "pgrep -fl 'zbx vm serve'" });
    }
    assert(diag.fixes.count >= 1);
}

pub fn directory(diag: *Diag, doing: []const u8, path: []const u8, reason: []const u8) void {
    assert(diag.code == null);
    assert(path.len > 0);
    assert(reason.len > 0);
    diag.raise(.E1005);
    diag.while_("{s}", .{doing});
    diag.cause("{s}: {s}", .{ path, reason });
    diag.context("path", "{s}", .{path});
    diag.fix(.{ .sentence = "free space, or check that your user owns that directory" });
    diag.fix(.{ .sentence = "HOME decides where it is; it is now:", .command = "echo $HOME" });
    assert(diag.fixes.count == 2);
}

pub fn not_running(diag: *Diag) void {
    assert(diag.code == null);
    diag.raise(.E1006);
    diag.while_("stopping the virtual machine", .{});
    diag.cause("no virtual machine is running for this user", .{});
    diag.fix(.{ .sentence = "see what is running:", .command = "zbx vm status" });
    assert(diag.fixes.count == 1);
}

/// `option` is "--cpus" or "--memory"; `given` is what the user typed.
pub fn size_out_of_range(
    diag: *Diag,
    problem: ?settings.Problem,
    option: []const u8,
    given: []const u8,
    bounds: settings.Bounds,
) void {
    assert(diag.code == null);
    assert(option.len > 0);
    diag.raise(.E1007);
    diag.while_("setting the virtual machine's size", .{});
    const cpus_range = .{ bounds.cpus_min, bounds.cpus_max };
    const memory_range = .{ bounds.memory_bytes_min >> 20, bounds.memory_bytes_max >> 20 };
    switch (problem orelse .not_a_size) {
        .cpus_below, .cpus_above => diag.cause(
            "{s} {s} is outside what this Mac allows: {d} to {d} CPUs",
            .{ option, given, cpus_range[0], cpus_range[1] },
        ),
        .memory_below, .memory_above => diag.cause(
            "{s} {s} is outside what this Mac allows: {d} MiB to {d} MiB",
            .{ option, given, memory_range[0], memory_range[1] },
        ),
        .memory_unaligned => diag.cause(
            "{s} {s} is not a size in whole MiB, between {d} MiB and {d} MiB",
            .{ option, given, memory_range[0], memory_range[1] },
        ),
        .not_a_size => if (std.mem.eql(u8, option, "--cpus")) diag.cause(
            "--cpus {s} is not a whole number of CPUs, {d} to {d}",
            .{ given, cpus_range[0], cpus_range[1] },
        ) else diag.cause(
            "--memory {s} is not a size like 2G or 4096M, {d} MiB to {d} MiB",
            .{ given, memory_range[0], memory_range[1] },
        ),
    }
    diag.context("given", "{s}", .{given});
    diag.fix(.{
        .sentence = "give a size in range, for example:",
        .command = "zbx vm config --cpus 4 --memory 2G",
        .template = true,
    });
    diag.fix(.{ .sentence = "see the current values:", .command = "zbx vm config" });
    assert(diag.fixes.count == 2);
}

pub fn settings_unreadable(diag: *Diag, path: []const u8, newer: bool) void {
    assert(diag.code == null);
    assert(path.len > 0);
    diag.raise(.E1008);
    diag.while_("reading the virtual machine's settings", .{});
    if (newer) {
        diag.cause("{s} was written by a newer zbx", .{path});
    } else {
        diag.cause("{s} is damaged: it is not a settings record this zbx writes", .{path});
    }
    diag.context("path", "{s}", .{path});
    diag.fix(.{
        .sentence = "write the settings again:",
        .command = "zbx vm config --cpus 4 --memory 2G",
        .template = true,
    });
    assert(diag.fixes.count == 1);
}

pub fn replacing(diag: *Diag, running: []const u8, ours: []const u8) void {
    assert(diag.code == null);
    assert(running.len > 0);
    assert(ours.len > 0);
    diag.raise(.W1001);
    diag.while_("checking the running virtual machine's version", .{});
    diag.cause("it runs image {s}, this zbx carries {s}: zbx stops it and starts its own", .{
        running, ours,
    });
    diag.fix(.{ .sentence = "nothing to do; to stop it by hand:", .command = "zbx vm stop" });
    assert(diag.fixes.count == 1);
}

// ---- Tests: the text of each diagnostic is in vm_golden.zig ------------------------------------

test "every function raises its own code" {
    // Goal: the code each builder raises, so that a golden cannot pass on the wrong one.
    var diag: Diag = undefined;
    diag.reset();
    not_running(&diag);
    try std.testing.expectEqual(@as(@TypeOf(diag.code.?), .E1006), diag.code.?);
    diag.reset();
    host_locked(&diag, 77);
    try std.testing.expectEqual(@as(@TypeOf(diag.code.?), .E1004), diag.code.?);
    diag.reset();
    host_locked(&diag, null);
    try std.testing.expectEqual(@as(@TypeOf(diag.code.?), .E1004), diag.code.?);
    diag.reset();
    not_allowed(&diag, null);
    try std.testing.expectEqual(@as(u32, 1), diag.fixes.count);
    const command = diag.fixes.slice()[0].command.slice();
    try std.testing.expect(std.mem.indexOf(u8, command, "brew") == null);
    try std.testing.expect(is_entitlement_text("missing the entitlement"));
    try std.testing.expect(!is_entitlement_text("out of memory"));
}
