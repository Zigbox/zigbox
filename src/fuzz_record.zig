//! The run-record fuzzer: `zig build fuzz -- record`. Each iteration builds a random record
//! view, renders it, and checks that the parser reads back exactly what was written (the view is
//! the oracle, so no second reader is needed). It then damages the text (flips, inserts,
//! deletes, truncates, duplicates) and checks the parser still returns, never crashes, and
//! when it accepts the text hands back a record that satisfies the invariants a reader relies
//! on. A record with a newer version is refused as such, and one with no version reads as 0.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const codes = @import("diag/codes.zig");
const records = @import("runtime/records.zig");
const spec_mod = @import("runtime/spec.zig");

const text_bytes_max = constants.record_bytes_max;

const names = [_][]const u8{ "a", "web-1", "0", "zbx-123456", "name" };

fn random_text(random: std.Random, buffer: []u8) []const u8 {
    const length = random.uintAtMost(usize, buffer.len);
    for (buffer[0..length]) |*byte| {
        byte.* = switch (random.uintLessThan(u8, 5)) {
            0 => '"',
            1 => '\\',
            2 => '\n',
            else => random.int(u8),
        };
    }
    return buffer[0..length];
}

fn random_exit(random: std.Random) records.Exit {
    return switch (random.uintLessThan(u8, 5)) {
        0 => .running,
        1 => .lost,
        2 => .{ .exited = random.int(u8) },
        3 => .{ .signaled = random.intRangeAtMost(u8, 1, constants.signal_number_max - 1) },
        else => .{ .start_failed = std.enums.values(codes.Code)[
            random.uintLessThan(
                usize,
                std.enums.values(codes.Code).len,
            )
        ] },
    };
}

fn random_reason(random: std.Random) records.EndReason {
    const all = std.enums.values(records.EndReason);
    return all[random.uintLessThan(usize, all.len)];
}

fn same_exit(a: records.Exit, b: records.Exit) bool {
    return std.meta.eql(a, b);
}

/// Damages `text[0..length]` in place with one to four edits; returns the new length.
fn damage(random: std.Random, text: []u8, length_in: usize) usize {
    var length = length_in;
    for (0..random.intRangeAtMost(u8, 1, 4)) |_| {
        switch (random.uintLessThan(u8, 5)) {
            0 => if (length > 0) {
                text[random.uintLessThan(usize, length)] = random.int(u8);
            },
            1 => if (length + 1 < text.len) {
                const at = random.uintAtMost(usize, length);
                @memmove(text[at + 1 .. length + 1], text[at..length]);
                text[at] = "\"\\\n,{}. =x0"[random.uintLessThan(usize, 11)];
                length += 1;
            },
            2 => if (length > 0) {
                const at = random.uintLessThan(usize, length);
                @memmove(text[at .. length - 1], text[at + 1 .. length]);
                length -= 1;
            },
            3 => length = random.uintAtMost(usize, length),
            else => if (length > 0 and length * 2 <= text.len) {
                @memcpy(text[length .. length * 2], text[0..length]);
                length *= 2;
            },
        }
    }
    return length;
}

/// A random set of M6's fields: the network, forwards (only with `user`, host ports distinct)
/// and names of `-e` (POSIX, distinct), all in the caller's storage.
const Reach = struct {
    network: spec_mod.Network,
    publish: [constants.publish_count_max]spec_mod.Publish,
    publish_count: u32,
    names: [constants.run_env_count_max][]const u8,
    names_count: u32,
    storage: [constants.run_env_count_max][8]u8,
};

fn random_reach(random: std.Random, reach: *Reach) void {
    reach.network = random.enumValue(spec_mod.Network);
    reach.publish_count = 0;
    if (reach.network == .user) {
        const wanted = random.uintAtMost(u32, constants.publish_count_max);
        while (reach.publish_count < wanted) {
            const host = random.intRangeAtMost(u16, 1, 65535);
            const taken = for (reach.publish[0..reach.publish_count]) |earlier| {
                if (earlier.host == host) break true;
            } else false;
            if (taken) continue;
            const container = random.intRangeAtMost(u16, 1, 65535);
            reach.publish[reach.publish_count] = .{ .host = host, .container = container };
            reach.publish_count += 1;
        }
    }
    reach.names_count = random.uintAtMost(u32, constants.run_env_count_max);
    for (0..reach.names_count) |at| {
        // "V0" to "V15" and the letters of the alphabet: distinct, and valid.
        const text = std.fmt.bufPrint(&reach.storage[at], "V{d}", .{at}) catch
            unreachable; // "V" and at most two digits fit eight bytes.
        reach.names[at] = text;
    }
}

fn check_round_trip(random: std.Random) void {
    var rootfs_bytes: [constants.rootfs_bytes_max]u8 = undefined;
    const rootfs = random_text(random, &rootfs_bytes);
    var words_bytes: [4][64]u8 = undefined;
    var words: [4][]const u8 = undefined;
    const count = random.intRangeAtMost(usize, 1, 4);
    for (words[0..count], 0..) |*word, at| word.* = random_text(random, &words_bytes[at]);
    var reach: Reach = undefined;
    random_reach(random, &reach);
    const view: records.View = .{
        .name = names[random.uintLessThan(usize, names.len)],
        .rootfs = rootfs,
        .command = words[0..count],
        .labels = &.{},
        .started = random.int(u64),
        .ended = if (random.boolean()) random.int(u64) else null,
        .exit = random_exit(random),
        .ids = if (random.boolean()) .single else .full,
        .zbx_version = "0.0.0",
        .reason = random_reason(random),
        .limits = .{
            .memory_bytes = if (random.boolean()) random.int(u64) else null,
            .pids = if (random.boolean()) random.int(u32) else null,
            .cpu_millis = if (random.boolean()) random.int(u32) else null,
        },
        .scope = if (random.boolean()) "zbx-web-1.scope" else "",
        .detached = random.boolean(),
        .timed_out = random.boolean(),
        .network = reach.network,
        .publish = reach.publish[0..reach.publish_count],
        .env_names = reach.names[0..reach.names_count],
    };
    var buffer: [text_bytes_max]u8 = undefined;
    const text = records.render(&view, &buffer);
    var parsed: records.Parsed = undefined;
    records.parse(text, &parsed) catch unreachable; // A rendered record always reads back.
    assert(parsed.version == constants.record_version);
    assert(std.mem.eql(u8, parsed.name_slice(), view.name));
    assert(std.mem.eql(u8, parsed.rootfs_slice(), view.rootfs));
    assert(parsed.started == view.started);
    assert(parsed.ended == view.ended);
    assert(same_exit(parsed.exit, view.exit));
    assert(parsed.ids.? == view.ids);
    const reason = if (view.reason == .none) records.reason_of(view.exit) else view.reason;
    assert(parsed.reason == reason);
    assert(std.meta.eql(parsed.limits, view.limits));
    assert(std.mem.eql(u8, parsed.scope_slice(), view.scope));
    assert(parsed.detached == view.detached);
    assert(parsed.timed_out == view.timed_out);
    assert(parsed.network.? == view.network);
    assert(parsed.publish_count == view.publish.len);
    for (view.publish, parsed.publish_slice()) |wanted, found| assert(std.meta.eql(wanted, found));
    assert(parsed.env_names_count == view.env_names.len);
    for (view.env_names, 0..) |wanted, at| {
        assert(std.mem.eql(u8, wanted, parsed.env_name(@intCast(at))));
    }
    check_damaged(random, text);
}

fn check_damaged(random: std.Random, text: []const u8) void {
    var buffer: [text_bytes_max]u8 = undefined;
    @memcpy(buffer[0..text.len], text);
    const length = damage(random, &buffer, text.len);
    var parsed: records.Parsed = undefined;
    records.parse(buffer[0..length], &parsed) catch |err| {
        if (err == error.Newer) assert(parsed.version > constants.record_version);
        return;
    };
    // Accepted: a reader may rely on these.
    assert(parsed.version <= constants.record_version);
    assert(parsed.name_len > 0);
    assert(spec_mod.name_problem(parsed.name_slice()) == null);
    assert(parsed.rootfs_len <= constants.rootfs_bytes_max);
    check_reach_accepted(&parsed);
}

/// What `render` asserts about M6's fields, which `parse` must have refused to break.
fn check_reach_accepted(parsed: *const records.Parsed) void {
    assert(parsed.publish_count <= constants.publish_count_max);
    assert(parsed.env_names_count <= constants.run_env_count_max);
    if (parsed.publish_count > 0) assert(parsed.network.? == .user);
    if (parsed.network) |network| {
        assert(spec_mod.publish_problem(network, parsed.publish_slice()) == null);
    }
    var words: [constants.run_env_count_max][]const u8 = undefined;
    for (0..parsed.env_names_count) |at| words[at] = parsed.env_name(@intCast(at));
    assert(spec_mod.env_names_problem(words[0..parsed.env_names_count]) == null);
}

fn check_versions(random: std.Random, text: []const u8) void {
    var buffer: [text_bytes_max + 32]u8 = undefined;
    var parsed: records.Parsed = undefined;
    const marker = "    .version = 5,\n";
    const at = std.mem.indexOf(u8, text, marker).?;
    // Newer: refused as such. Absent: version 0, still read.
    const newer = random.intRangeAtMost(u32, constants.record_version + 1, 1 << 30);
    const format = "{s}    .version = {d},\n";
    // Cannot fail: the buffer has room for the text and a number.
    const head = std.fmt.bufPrint(&buffer, format, .{ text[0..at], newer }) catch unreachable;
    @memcpy(buffer[head.len .. head.len + text.len - at - marker.len], text[at + marker.len ..]);
    const end = head.len + text.len - at - marker.len;
    assert(records.parse(buffer[0..end], &parsed) == error.Newer);
    @memcpy(buffer[0..at], text[0..at]);
    @memcpy(buffer[at .. text.len - marker.len], text[at + marker.len ..]);
    records.parse(buffer[0 .. text.len - marker.len], &parsed) catch unreachable; // Older reads.
    assert(parsed.version == 0);
    assert(parsed.reason == records.reason_of(parsed.exit)); // The version 2 fields default.
}

pub fn fuzz_record(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    check_round_trip(random);
    const view: records.View = .{
        .name = "version-check",
        .rootfs = "/r",
        .command = &.{"sh"},
        .labels = &.{},
        .started = random.int(u64),
        .ended = null,
        .exit = .running,
        .ids = .single,
        .zbx_version = "0.0.0",
    };
    var buffer: [text_bytes_max]u8 = undefined;
    check_versions(random, records.render(&view, &buffer));
}
