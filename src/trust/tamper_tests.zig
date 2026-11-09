//! Tests of the tamper check (`tamper.zig`) against the simulated host and store: damage to an
//! object's bytes, mode or owner is always found, with the record of earlier checks and without
//! it, and a change of an object's change time is always looked at again.

const std = @import("std");
const testing = std.testing;
const Diag = @import("../diag/diag.zig").Diag;
const constants = @import("../constants.zig");
const fs_sim = @import("../store/fs_sim.zig");
const host_sim = @import("../host_sim.zig");
const import = @import("../store/import.zig");
const layout = @import("../store/layout.zig");
const support = @import("../store/test_support.zig");
const verify = @import("../store/verify.zig");
const Digest = @import("../store/digest.zig").Digest;
const tamper = @import("tamper.zig");

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var store: layout.Store = undefined;
var import_work: import.Workspace = undefined;
var workspace: tamper.Workspace = undefined;
var scratch: verify.Scratch = undefined;
var tree_buffer: [constants.store_tree_bytes_max]u8 = undefined;
var stack: [constants.image_import_stack_max]Digest = undefined;
var tree: Digest = undefined;
var last_diag: Diag = undefined;

fn start() !void {
    sim.init(1, &.{});
    files.init(1);
    sim.store_fs = &files;
    support.make_user_store(&files, ".{\n    .format = 1,\n}\n");
    support.make_source(&files, 0);
    store.at(sim.interface(), support.user_store);
    var diag: Diag = undefined;
    diag.reset();
    var made: import.Result = undefined;
    const options: import.Options = .{ .squash_owner = false, .warn = null };
    try import.import(&store, &import_work, "/src", options, &made, &diag);
    tree = made.digest;
}

fn check_tree(always: bool) !void {
    last_diag.reset();
    const lent: tamper.Lent = .{ .scratch = &scratch, .tree_buffer = &tree_buffer, .stack = &stack };
    try tamper.check(&store, &workspace, lent, tree, always, &last_diag);
}

/// The path of the object whose bytes are `content`, in the store.
fn object_with(content: []const u8) []const u8 {
    var index: u32 = 0;
    while (index < files.count) : (index += 1) {
        const path = files.alive_path(index) orelse continue;
        if (files.kind_of(path) != .file) continue;
        if (std.mem.indexOf(u8, path, "/objects/") == null) continue;
        if (std.mem.endsWith(u8, path, ".chunks")) continue;
        if (std.mem.eql(u8, files.content_of(path).?, content)) return path;
    }
    unreachable;
}

fn record_path() []const u8 {
    var buffer: [256]u8 = undefined;
    const hex = tree.hex();
    const path = std.fmt.bufPrint(&buffer, "{s}/{s}/{s}", .{
        support.user_store, tamper.directory_name, &hex,
    }) catch unreachable;
    return keep(path);
}

var kept: [256]u8 = undefined;
fn keep(text: []const u8) []const u8 {
    @memcpy(kept[0..text.len], text);
    return kept[0..text.len];
}

fn cause_has(needle: []const u8) !void {
    const text = last_diag.last_cause().?;
    try testing.expect(std.mem.indexOf(u8, text, needle) != null);
}

test "an intact tree passes, and leaves a record that the next check believes" {
    // Goal: the clean path and the record. Method: check twice; the record exists after the
    // first, and a record that is not a record (garbage) is ignored and replaced.
    try start();
    try check_tree(false);
    try testing.expect(files.kind_of(record_path()) == .file);
    const first = files.content_of(record_path()).?;
    try testing.expect(std.mem.eql(u8, first[0..8], "zbxverif"));
    try check_tree(false);
    files.remove_path(record_path());
    files.put_file(record_path(), 0o644, "garbage");
    try check_tree(false);
    try testing.expect(std.mem.eql(u8, files.content_of(record_path()).?[0..8], "zbxverif"));
}

test "changed bytes, mode or owner are found, with the record and without it" {
    // Goal: damage of every kind is always found. Method: for each kind, check once (making the
    // record), damage the object, check again; and again with `always` after a fresh record.
    const kinds = [_]tamper_kind{ .bytes, .mode, .owner };
    for (kinds) |kind| {
        for ([_]bool{ false, true }) |always| {
            try start();
            try check_tree(false);
            const path = object_with("root:x:0:0\n");
            switch (kind) {
                .bytes => files.flip_byte(path, 0),
                .mode => files.set_mode_of(path, 0o600),
                .owner => files.set_owner_of(path, 77, 77),
            }
            try testing.expectError(error.Failed, check_tree(always));
            try testing.expect(last_diag.code.? == .E0907);
            try cause_has("/etc/passwd");
        }
    }
}

const tamper_kind = enum { bytes, mode, owner };

test "a change of an object's change time is looked at again" {
    // Goal: the record is only believed while inode, size and change time all agree. Method:
    // check, damage the bytes in place and restore the change time's *meaning* by touching only:
    // an object whose bytes are intact but whose ctime moved passes (it is hashed again); one
    // damaged and touched is found.
    try start();
    try check_tree(false);
    const path = object_with("root:x:0:0\n");
    files.touch_ctime_of(path);
    try check_tree(false);
    files.flip_byte(path, 0);
    try testing.expectError(error.Failed, check_tree(false));
}

test "a tree with no damaged object and no record is checked in full" {
    // Goal: with no record every object is hashed: a flipped byte is found at the first check.
    try start();
    files.flip_byte(object_with("setuid\n"), 1);
    try testing.expectError(error.Failed, check_tree(false));
    try cause_has("/bin/su");
}

test "a missing object is found" {
    try start();
    files.remove_path(object_with("root:!\n"));
    try testing.expectError(error.Failed, check_tree(false));
    try cause_has("missing");
}
