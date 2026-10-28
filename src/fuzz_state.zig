//! The state-volume record fuzzer: `zig build fuzz -- state`. Each iteration renders a random
//! record (`state/record.zig`), reads it back exactly, then damages the text (flips, inserts,
//! deletes, truncations, repeats, numbers pushed past their bound) and checks that the parser
//! never crashes and that whatever it accepts renders again and reads back the same (REVIEW.md:
//! parse accepts only what render can write). It also parses the names, mount values and trash
//! names of `volume.zig` from random bytes: anything accepted must satisfy the rules the rest
//! of zbx asserts.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const record_mod = @import("state/record.zig");
const volume = @import("state/volume.zig");

const names = [_][]const u8{ "pgdata", "0", "a.b-c_d", "web" };
const containers = [_][]const u8{ "pg", "zbx-1a2b3c", "a", "web-1" };
const targets = [_][]const u8{
    "/var/lib/postgresql/data", "/a\"b", "/\"q\"", "/caf\xc3\xa9", "/x",
};

fn random_record(random: std.Random, record: *record_mod.Record) void {
    const created = random.uintLessThan(u64, constants.state_time_max);
    record.init(names[random.uintLessThan(usize, names.len)], created);
    if (random.boolean()) return;
    const mount: volume.Mount = .{
        .name = record.name_slice(),
        .target = targets[random.uintLessThan(usize, targets.len)],
        .read_only = random.boolean(),
    };
    const used = random.intRangeLessThan(u64, created, constants.state_time_max);
    record.use(containers[random.uintLessThan(usize, containers.len)], &mount, used);
}

fn same(a: *const record_mod.Record, b: *const record_mod.Record) bool {
    return std.mem.eql(u8, a.name_slice(), b.name_slice()) and a.created == b.created and
        a.last_used == b.last_used and
        std.mem.eql(u8, a.container_slice(), b.container_slice()) and
        std.mem.eql(u8, a.target_slice(), b.target_slice()) and
        a.last_read_only == b.last_read_only;
}

/// Damages `text[0..length_in]` in place with one to four edits; returns the new length.
fn damage(random: std.Random, text: []u8, length_in: usize) usize {
    var length = length_in;
    for (0..random.intRangeAtMost(u8, 1, 4)) |_| {
        switch (random.uintLessThan(u8, 6)) {
            0 => if (length > 0) {
                text[random.uintLessThan(usize, length)] = random.int(u8);
            },
            1 => if (length + 1 < text.len) {
                const at = random.uintAtMost(usize, length);
                @memmove(text[at + 1 .. length + 1], text[at..length]);
                text[at] = "\"\\\n,{}. =x09"[random.uintLessThan(usize, 12)];
                length += 1;
            },
            2 => if (length > 0) {
                const at = random.uintLessThan(usize, length);
                @memmove(text[at .. length - 1], text[at + 1 .. length]);
                length -= 1;
            },
            3 => length = random.uintAtMost(usize, length),
            4 => if (length > 0 and length * 2 <= text.len) {
                @memcpy(text[length .. length * 2], text[0..length]);
                length *= 2;
            },
            else => if (length + 13 < text.len) {
                // A digit run before a comma grows by 13 digits: a time past its bound.
                const comma = std.mem.indexOfScalarPos(u8, text[0..length], random.uintAtMost(
                    usize,
                    length,
                ), ',') orelse continue;
                @memmove(text[comma + 13 .. length + 13], text[comma..length]);
                @memset(text[comma .. comma + 13], '9');
                length += 13;
            },
        }
    }
    return length;
}

fn check_damaged(random: std.Random, text: []const u8) void {
    var buffer: [constants.state_record_bytes_max * 2]u8 = undefined;
    @memcpy(buffer[0..text.len], text);
    const length = damage(random, &buffer, text.len);
    var parsed: record_mod.Record = undefined;
    record_mod.parse(buffer[0..length], &parsed) catch return;
    // Accepted: it renders (render asserts every bound) and reads back the same.
    var again_buffer: [constants.state_record_bytes_max]u8 = undefined;
    const again = record_mod.render(&parsed, &again_buffer);
    var back: record_mod.Record = undefined;
    record_mod.parse(again, &back) catch unreachable; // Rendered text always reads back.
    assert(same(&parsed, &back));
}

/// Random bytes as a name, a `--state` value and a trash name: what is accepted keeps the rules.
fn check_parsers(random: std.Random) void {
    var bytes: [80]u8 = undefined;
    const length = random.uintAtMost(usize, bytes.len);
    for (bytes[0..length]) |*byte| {
        byte.* = "ab0._-/:ro@19\x00\xff"[random.uintLessThan(usize, 15)];
    }
    const text = bytes[0..length];
    if (volume.name_problem(text) == null) {
        assert(text.len > 0);
        assert(std.mem.indexOfScalar(u8, text, '/') == null);
    }
    switch (volume.parse_mount(text)) {
        .ok => |mount| {
            assert(volume.name_problem(mount.name) == null);
            assert(volume.target_problem(mount.target) == null);
            var echo: [constants.state_value_bytes_max]u8 = undefined;
            const round = volume.parse_mount(volume.mount_text(&mount, &echo)).ok;
            assert(std.mem.eql(u8, round.target, mount.target));
            assert(round.read_only == mount.read_only);
        },
        .problem => {},
    }
    if (volume.parse_trash_name(text)) |entry| {
        var name: volume.TrashName = undefined;
        volume.trash_name_of(entry.name, entry.removed, &name);
        assert(std.mem.eql(u8, name.text(), text)); // One spelling per entry.
    }
}

pub fn fuzz_state(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    var record: record_mod.Record = undefined;
    random_record(random, &record);
    var buffer: [constants.state_record_bytes_max]u8 = undefined;
    const text = record_mod.render(&record, &buffer);
    var back: record_mod.Record = undefined;
    record_mod.parse(text, &back) catch unreachable; // A rendered record always reads back.
    assert(same(&record, &back));
    for (0..4) |_| check_damaged(random, text);
    check_damaged(random, record_mod.version_1_text);
    check_parsers(random);
}
