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
    const lent: tamper.Lent = .{
        .scratch = &scratch,
        .tree_buffer = &tree_buffer,
        .stack = &stack,
    };
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
    }) catch unreachable; // 256 bytes hold the store path and a 64-digit hex.
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

const materialize = @import("../store/materialize.zig");

var farm_work: materialize.Workspace = undefined;

fn make_farm() !void {
    var diag: Diag = undefined;
    diag.reset();
    try testing.expect(try materialize.ensure(&store, &farm_work, tree, &diag));
}

/// The path `name` has in the farm of the tree.
fn farm_file(name: []const u8) []const u8 {
    var buffer: [512]u8 = undefined;
    const hex = tree.hex();
    const path = std.fmt.bufPrint(&buffer, "{s}/cache/{s}{s}", .{
        support.user_store, &hex, name,
    }) catch unreachable; // 512 bytes hold the store path, the hex and a short name.
    return keep(path);
}

fn expect_farm_refused(path_in_image: []const u8) !void {
    try testing.expectError(error.Failed, check_tree(false));
    try testing.expect(last_diag.code.? == .E0907);
    try cause_has(path_in_image);
    try cause_has("materialized");
    // `always` finds it too, and a refusal leaves the farm as it was.
    try testing.expectError(error.Failed, check_tree(true));
}

test "an intact farm passes, with and without a record" {
    // Goal: the farm check has no false alarm. Method: build the farm from the objects, check.
    try start();
    try check_tree(false);
    try make_farm();
    try check_tree(false);
    try check_tree(true);
}

test "a file of the farm replaced by rename is found" {
    // Goal: the farm is a lower layer of its own: `sed -i` gives its file a new inode and leaves
    // the object intact. Method: replace the farm's /etc/passwd by a file of other content.
    try start();
    try check_tree(false);
    try make_farm();
    files.remove_path(farm_file("/etc/passwd"));
    files.put_file(farm_file("/etc/passwd"), 0o644, "root:x:0:0 evil\n");
    try expect_farm_refused("/etc/passwd");
}

test "an entry added to a farm directory is found" {
    try start();
    try check_tree(false);
    try make_farm();
    files.put_file(farm_file("/etc/extra"), 0o644, "more\n");
    try expect_farm_refused("/etc");
}

test "an entry removed from the farm is found" {
    try start();
    try check_tree(false);
    try make_farm();
    files.remove_path(farm_file("/bin/su"));
    try expect_farm_refused("/bin/su");
}

test "a changed symlink of the farm is found" {
    try start();
    try check_tree(false);
    try make_farm();
    files.remove_path(farm_file("/bin/busybox"));
    files.put_symlink(farm_file("/bin/busybox"), "/etc/passwd");
    try expect_farm_refused("/bin/busybox");
}

test "a farm directory with another mode is found" {
    try start();
    try check_tree(false);
    try make_farm();
    files.set_mode_of(farm_file("/etc"), 0o777);
    try expect_farm_refused("/etc");
}

test "the record is believed: a change that leaves the change time is not hashed again" {
    // Goal: the record is a cache that works, and `always` ignores it. Method: damage an object
    // without moving its inode, size or change time: with a record the check passes (that is
    // what a record is: it cannot see this, and the kernel's ctime does not allow it), with
    // `always` it fails.
    try start();
    try check_tree(false);
    files.flip_byte_quietly(object_with("root:x:0:0\n"), 0);
    try check_tree(false);
    try testing.expectError(error.Failed, check_tree(true));
    try testing.expect(last_diag.code.? == .E0907);
}

fn check_capped(cap: u32) !void {
    last_diag.reset();
    const lent: tamper.Lent = .{
        .scratch = &scratch,
        .tree_buffer = &tree_buffer,
        .stack = &stack,
    };
    try tamper.check_capped(&store, &workspace, lent, tree, false, cap, &last_diag);
}

const contents = [_][]const u8{ "#!shell\n", "setuid\n", "root:x:0:0\n", "root:!\n" };

test "a tree of exactly the id capacity is recorded, one past it is not" {
    // Goal: the bound of the record (`trust_verified_entries_max`, 65536 in real life; a
    // test-only cap of the same code path stands in, as 65537 files are too slow in the
    // simulation). The tree has 6 distinct objects: at a cap of 6 the record is written and
    // believed; at 5 nothing is written, every object is hashed, and damage past the cap is found.
    try start();
    try check_capped(6);
    try testing.expect(files.kind_of(record_path()) == .file);
    const passwd = object_with("root:x:0:0\n");
    files.flip_byte_quietly(passwd, 0);
    try check_capped(6); // Believed.
    files.flip_byte_quietly(passwd, 0);
    files.remove_path(record_path());
    try check_capped(5);
    try testing.expect(files.kind_of(record_path()) == null);
    for (contents) |content| {
        const path = object_with(content);
        files.flip_byte(path, 0);
        try testing.expectError(error.Failed, check_capped(5));
        try testing.expect(last_diag.code.? == .E0907);
        files.flip_byte(path, 0);
        try check_capped(5);
    }
    try testing.expect(files.kind_of(record_path()) == null);
}

test "once the id list is full and partial it is sorted no more" {
    // Goal: a tree past the cap does not sort the list for every further object. Method: with
    // room for 2 ids and 6 objects, the list is sorted once, at the third.
    try start();
    try check_capped(2);
    try testing.expectEqual(@as(u32, 1), workspace.compactions);
    try testing.expect(files.kind_of(record_path()) == null);
}
