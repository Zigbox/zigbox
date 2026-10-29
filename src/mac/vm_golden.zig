//! Golden tests for the `10xx` diagnostics (DIAGNOSTICS.md, "Testing"): each code is built by the
//! function that raises it, with fixed arguments, and rendered in the default, verbose and JSON
//! modes; the text must equal the checked-in files in src/testdata/diag/. These diagnostics come
//! from the macOS zbx, which the Linux simulator cannot run, so they are built directly. The same
//! test runs on Linux CI, because nothing here touches macOS.
//!
//! Changing a message means updating the golden files in the same commit.

const std = @import("std");
const assert = std.debug.assert;
const codes = @import("../diag/codes.zig");
const constants = @import("../constants.zig");
const diagnose = @import("diagnose.zig");
const render = @import("../diag/render.zig");
const settings = @import("settings.zig");
const Diag = @import("../diag/diag.zig").Diag;

const Case = struct {
    code: codes.Code,
    build: *const fn (diag: *Diag) void,
};

const bounds: settings.Bounds = .{
    .cpus_min = 1,
    .cpus_max = 8,
    .memory_bytes_min = 512 << 20,
    .memory_bytes_max = 18 << 30,
};

fn entitlement(diag: *Diag) void {
    diagnose.not_allowed(diag, .{
        .domain = "VZErrorDomain",
        .code = 2,
        .description = "The process doesn't have the \"com.apple.security.virtualization\" " ++
            "entitlement.",
    });
}

fn start_failed(diag: *Diag) void {
    diagnose.start_failed(diag, .validating, .{
        .domain = "VZErrorDomain",
        .code = 1,
        .description = "Invalid virtual machine configuration.",
    }, "/Users/ada/Library/Application Support/zbx/vm/console.log");
}

fn no_answer(diag: *Diag) void {
    diagnose.no_answer(diag, "/Users/ada/Library/Application Support/zbx/vm/console.log", 30_000);
}

fn host_locked(diag: *Diag) void {
    diagnose.host_locked(diag, 4121);
}

fn directory(diag: *Diag) void {
    diagnose.directory(
        diag,
        "unpacking the VM image",
        "/Users/ada/Library/Application Support/zbx/vm/0123456789abcdef",
        "no space left on device",
    );
}

fn not_running(diag: *Diag) void {
    diagnose.not_running(diag);
}

fn out_of_range(diag: *Diag) void {
    diagnose.size_out_of_range(diag, .memory_above, "--memory", "64G", bounds);
}

fn unreadable(diag: *Diag) void {
    const path = "/Users/ada/Library/Application Support/zbx/vm-settings";
    diagnose.settings_unreadable(diag, path, false);
}

fn replacing(diag: *Diag) void {
    diagnose.replacing(diag, "fedcba9876543210", "0123456789abcdef");
}

fn lost(diag: *Diag) void {
    diagnose.connection_lost(diag, "the guest hung up");
}

fn silent(diag: *Diag) void {
    diagnose.service_silent(diag, "/Users/ada/Library/Application Support/zbx/vm/console.log");
}

fn setup_failed(diag: *Diag) void {
    const log = "/Users/ada/Library/Application Support/zbx/vm/console.log";
    diagnose.setup_failed(diag, "cgroup", log);
}

fn no_network(diag: *Diag) void {
    diagnose.no_network(diag);
}

fn disk_shrink(diag: *Diag) void {
    const path = "/Users/ada/Library/Application Support/zbx/store.img";
    diagnose.disk_shrink(diag, 32 << 30, 64 << 30, path);
}

fn not_shared(diag: *Diag) void {
    diagnose.directory_not_shared(diag, "/private/tmp/build", "/Users/ada");
}

fn disk_full(diag: *Diag) void {
    diagnose.store_disk_full(diag, 64 << 30, 12 << 20);
}

fn host_full(diag: *Diag) void {
    const path = "/Users/ada/Library/Application Support/zbx/store.img";
    diagnose.host_volume_full(diag, path, 700 << 20, 2 << 30);
}

fn rosetta_missing(diag: *Diag) void {
    diagnose.rosetta_missing(diag);
}

pub const cases = [_]Case{
    .{ .code = .E1001, .build = &entitlement },
    .{ .code = .E1002, .build = &start_failed },
    .{ .code = .E1003, .build = &no_answer },
    .{ .code = .E1004, .build = &host_locked },
    .{ .code = .E1005, .build = &directory },
    .{ .code = .E1006, .build = &not_running },
    .{ .code = .E1007, .build = &out_of_range },
    .{ .code = .E1008, .build = &unreadable },
    .{ .code = .W1001, .build = &replacing },
    .{ .code = .E1009, .build = &lost },
    .{ .code = .E1010, .build = &silent },
    .{ .code = .E1011, .build = &setup_failed },
    .{ .code = .W1002, .build = &no_network },
    .{ .code = .E1012, .build = &disk_shrink },
    .{ .code = .E1013, .build = &not_shared },
    .{ .code = .E1014, .build = &disk_full },
    .{ .code = .E1015, .build = &host_full },
    .{ .code = .E1016, .build = &rosetta_missing },
};

/// True if a golden case here covers `code` (the registry's "every code has a case" test asks).
pub fn covers(code: codes.Code) bool {
    for (cases) |case| {
        if (case.code == code) return true;
    }
    return false;
}

pub fn rendered(case: *const Case, mode: render.Mode, buffer: []u8) []const u8 {
    var diag: Diag = undefined;
    diag.reset();
    case.build(&diag);
    assert(diag.code.? == case.code);
    return render.render(&diag, mode, false, buffer);
}

test "golden: every 10xx code in default, verbose and JSON output" {
    // Goal: the text of each VM-layer diagnostic is part of the product. Method: build each with
    // fixed arguments and compare the three renderings byte for byte with the files; the JSON is
    // one valid object per line; no output shows a trace or a Zig error name.
    @setEvalBranchQuota(100_000);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    inline for (cases) |case| {
        const name = @tagName(case.code);
        const expected = [_][]const u8{
            @embedFile("../testdata/diag/" ++ name ++ ".txt"),
            @embedFile("../testdata/diag/" ++ name ++ ".verbose.txt"),
            @embedFile("../testdata/diag/" ++ name ++ ".json.txt"),
        };
        for ([_]render.Mode{ .text, .verbose, .json }, expected) |mode, golden| {
            const shown = rendered(&case, mode, &buffer);
            std.testing.expectEqualStrings(golden, shown) catch |err| {
                std.debug.print("GOLDEN {s} {s}\n", .{ name, @tagName(mode) });
                return err;
            };
            try std.testing.expect(!render.contains_raw_error(shown));
        }
        const test_util = @import("../test_util.zig");
        const json = rendered(&case, .json, &buffer);
        try std.testing.expect(try test_util.json_is_valid(std.mem.trimEnd(u8, json, "\n")));
    }
}

test "every 10xx code in the registry has a golden case" {
    // Goal: the registry cannot gain a VM-layer code without a golden test. Method: walk it.
    for (codes.registry) |item| {
        const tag = @tagName(item.code);
        if (tag[1] != '1' or tag[2] != '0') continue;
        try std.testing.expect(covers(item.code));
    }
}

test "the diagnostics blame who the registry says" {
    // Goal: blame and severity are what DIAGNOSTICS.md describes for each case. Method: read the
    // registry entry of every case.
    for (cases) |case| {
        const entry = codes.entry(case.code);
        const is_warning = entry.severity == .warning;
        const warns = case.code == .W1001 or case.code == .W1002;
        try std.testing.expectEqual(warns, is_warning);
        try std.testing.expect(entry.blame != .internal);
    }
    try std.testing.expectEqual(codes.Blame.user, codes.entry(.E1006).blame);
    try std.testing.expectEqual(codes.Blame.user, codes.entry(.E1007).blame);
    try std.testing.expectEqual(codes.Blame.environment, codes.entry(.E1001).blame);
}
