//! Which containers use a volume now: the run records (version 5 lists the volumes a run
//! mounted) of the containers that are running. `zbx state ls` says it, and a refusal names the
//! holder with it. The lock is what decides whether a volume is free; this only names who has
//! it, so a record written a moment after its lock was taken is no harm: the lock file's own
//! text names the holder until then.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const lifecycle = @import("../runtime/lifecycle.zig");
const records = @import("../runtime/records.zig");
const diagnose = @import("diagnose.zig");
const lock = @import("lock.zig");

const Host = host_mod.Host;

/// The containers found, each with whether it mounted the volume read-only and the pid of the
/// process that holds its lock (the supervisor in its record).
pub const Found = struct {
    names: [constants.state_holders_max][constants.container_name_bytes_max]u8,
    lens: [constants.state_holders_max]u8,
    read_only: [constants.state_holders_max]bool,
    supervisors: [constants.state_holders_max]u32,
    count: u32,
    /// More were found than are kept.
    more: bool,

    pub fn name(found: *const Found, index: u32) []const u8 {
        assert(index < found.count);
        return found.names[index][0..found.lens[index]];
    }

    fn add(found: *Found, record: *const records.Parsed, read_only: bool) void {
        if (found.count == constants.state_holders_max) {
            found.more = true;
            return;
        }
        const text = record.name_slice();
        @memcpy(found.names[found.count][0..text.len], text);
        found.lens[found.count] = @intCast(text.len);
        found.read_only[found.count] = read_only;
        found.supervisors[found.count] = record.supervisor;
        found.count += 1;
    }
};

/// Fills `found` with the running containers whose record names `volume`. `scratch` holds one
/// record at a time. Records that cannot be read are skipped, as `zbx ps` skips them.
pub fn find(host: Host, volume: []const u8, scratch: *records.Parsed, found: *Found) void {
    assert(volume.len > 0);
    found.count = 0;
    found.more = false;
    var dir: records.Dir = undefined;
    if (!records.locate(host, &dir)) return;
    var listing: host_mod.DirListing = undefined;
    listing.reset();
    records.names(host, &dir, &listing) catch return;
    for (0..listing.count) |at| {
        const stem = records.name_of(listing.name(@intCast(at))) orelse continue;
        records.load(host, &dir, stem, scratch) catch continue;
        const read_only = mounts(scratch, volume) orelse continue;
        if (lifecycle.state_of(host, scratch) != .running) continue;
        found.add(scratch, read_only);
    }
    assert(found.count <= constants.state_holders_max);
}

/// Whether the record's run mounted `volume`, and if so whether read-only.
fn mounts(record: *const records.Parsed, volume: []const u8) ?bool {
    for (0..record.state_count) |index| {
        const mount = record.state_mount(@intCast(index));
        if (std.mem.eql(u8, mount.name, volume)) return mount.read_only;
    }
    return null;
}

/// What a refusal says about who holds a busy lock: how the lock is held (`lock.holder_of`),
/// and the names the records give. A writer is named by the record whose supervisor wrote the
/// lock's text, else by any running writer of it, else by the text itself.
pub fn describe(
    holder: lock.Holder,
    found: *const Found,
    out: *diagnose.Holders,
) void {
    out.count = 0;
    out.writer = holder != .readers;
    out.writer_text = "";
    out.writer_pid = 0;
    switch (holder) {
        .readers => {
            for (0..found.count) |index| {
                if (!found.read_only[index]) continue;
                out.names[out.count] = found.name(@intCast(index));
                out.count += 1;
            }
        },
        .writer => |writer| {
            out.writer_text = writer.who;
            out.writer_pid = writer.pid;
            if (pick_writer(found, writer.pid)) |index| {
                out.names[0] = found.name(index);
                out.count = 1;
            }
        },
        .unknown => {
            if (pick_writer(found, 0)) |index| {
                out.names[0] = found.name(index);
                out.count = 1;
            }
        },
    }
    assert(out.count <= constants.state_holders_max);
}

fn pick_writer(found: *const Found, pid: u32) ?u32 {
    var any: ?u32 = null;
    for (0..found.count) |index| {
        if (found.read_only[index]) continue;
        if (pid != 0 and found.supervisors[index] == pid) return @intCast(index);
        if (any == null) any = @intCast(index);
    }
    return any;
}

const testing = std.testing;

test "a writer is named by the record whose supervisor holds the lock, readers by theirs" {
    // Goal: the naming rules. Method: a `Found` filled by hand, each kind of holder.
    var found: Found = undefined;
    found.count = 0;
    found.more = false;
    var record: records.Parsed = undefined;
    record.name_len = 2;
    @memcpy(record.name[0..2], "r1");
    record.supervisor = 10;
    found.add(&record, true);
    @memcpy(record.name[0..2], "w1");
    record.supervisor = 20;
    found.add(&record, false);
    @memcpy(record.name[0..2], "w2");
    record.supervisor = 30;
    found.add(&record, false);
    var out: diagnose.Holders = undefined;
    describe(.{ .writer = .{ .pid = 30, .who = "w2" } }, &found, &out);
    try testing.expect(out.writer);
    try testing.expectEqualStrings("w2", out.names[0]);
    describe(.{ .writer = .{ .pid = 99, .who = "zbx state rm" } }, &found, &out);
    try testing.expectEqualStrings("w1", out.names[0]);
    describe(.readers, &found, &out);
    try testing.expect(!out.writer);
    try testing.expectEqual(@as(u32, 1), out.count);
    try testing.expectEqualStrings("r1", out.names[0]);
    found.count = 0;
    describe(.{ .writer = .{ .pid = 99, .who = "zbx state rm" } }, &found, &out);
    try testing.expectEqual(@as(u32, 0), out.count);
    try testing.expectEqualStrings("zbx state rm", out.writer_text);
}
