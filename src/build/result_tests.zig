//! The build record (`result.zig`): config resolution from a base and a file, the bytes, and what
//! a damaged record is.

const std = @import("std");
const constants = @import("../constants.zig");
const digest_mod = @import("../store/digest.zig");
const file_mod = @import("file.zig");
const file_tests = @import("file_tests.zig");
const images = @import("../store/images.zig");
const result = @import("result.zig");

const testing = std.testing;
const Digest = digest_mod.Digest;

var file: file_mod.BuildFile = undefined;
var problem: file_mod.Problem = undefined;
var base: images.Settings = undefined;
var record: result.Record = undefined;
var again: result.Record = undefined;
var buffer: [constants.build_result_bytes_max]u8 = undefined;

fn resolved() !void {
    try testing.expect(file_mod.parse(file_tests.example, &file, &problem) == .parsed);
    base.clear();
    _ = base.add(.entrypoint, "/bin/sh");
    _ = base.add(.cmd, "-c");
    _ = base.add(.env, "PATH=/usr/bin");
    _ = base.add(.env, "GREETING_STYLE=loud");
    _ = base.set(.workdir, "/home");
    _ = base.set(.user, "5:5");
    try testing.expect(result.resolve(&base, &file, &record.config) == null);
    record.tree = Digest.of("tree");
}

test "a config is the base's under the file's, field by field" {
    // Goal: the resolution rule. Method: a base with every field and a file that sets some.
    try resolved();
    const settings = &record.config.settings;
    try testing.expectEqual(@as(u32, 1), settings.count(.entrypoint));
    try testing.expectEqualStrings("/usr/local/bin/hello", settings.word(.entrypoint, 0));
    try testing.expectEqual(@as(u32, 1), settings.count(.cmd)); // The base's, not given.
    try testing.expectEqualStrings("-c", settings.word(.cmd, 0));
    try testing.expectEqual(@as(u32, 2), settings.count(.env));
    try testing.expectEqualStrings("PATH=/usr/bin", settings.word(.env, 0));
    try testing.expectEqualStrings("GREETING_STYLE=plain", settings.word(.env, 1)); // Replaced.
    try testing.expectEqualStrings("/", settings.get(.workdir));
    try testing.expectEqualStrings("0:0", settings.get(.user));
    try testing.expectEqual(@as(u32, 1), record.config.labels_count);
}

test "a record round-trips, and its digest changes with the config" {
    // Goal: encode/parse agree and the digest covers the config. Method: encode, parse, re-encode;
    // then change the entrypoint.
    try resolved();
    const bytes = try result.encode(&record, &buffer);
    try testing.expect(result.parse(bytes, &again) == .ok);
    var second: [constants.build_result_bytes_max]u8 = undefined;
    try testing.expectEqualSlices(u8, bytes, try result.encode(&again, &second));
    const first = result.result_digest(bytes);
    var other = record;
    other.config.settings.entrypoint_count = 0;
    var third: [constants.build_result_bytes_max]u8 = undefined;
    const changed = result.result_digest(try result.encode(&other, &third));
    try testing.expect(!first.eql(changed));
}

test "a damaged record is malformed, never accepted" {
    // Goal: parse accepts exactly what encode writes. Method: every cut of a record, a trailing
    // byte, a wrong magic and a newer version.
    try resolved();
    const bytes = try result.encode(&record, &buffer);
    for (0..bytes.len) |length| {
        try testing.expect(result.parse(bytes[0..length], &again) == .malformed);
    }
    var longer: [constants.build_result_bytes_max + 1]u8 = undefined;
    @memcpy(longer[0..bytes.len], bytes);
    longer[bytes.len] = 0;
    try testing.expect(result.parse(longer[0 .. bytes.len + 1], &again) == .malformed);
    longer[0] ^= 1;
    try testing.expect(result.parse(longer[0..bytes.len], &again) == .malformed);
    longer[0] ^= 1;
    longer[result.magic.len] = result.record_version + 1;
    try testing.expect(result.parse(longer[0..bytes.len], &again) == .newer);
}

test "labels are kept in key order and a key twice is refused" {
    // Goal: the canonical order. Method: add out of order; a repeated key and a full list.
    record.config.clear();
    try testing.expect(record.config.add_label("b", "2") != null);
    try testing.expect(record.config.add_label("a", "1") != null);
    try testing.expectEqualStrings("a", record.config.label_key(0));
    try testing.expectEqualStrings("2", record.config.label_value(1));
    try testing.expect(record.config.add_label("a", "3") == null);
    var count: u32 = 2;
    while (count < constants.build_config_labels_max) : (count += 1) {
        var key: [8]u8 = undefined;
        const name = std.fmt.bufPrint(&key, "k{d:0>3}", .{count}) catch unreachable; // Four bytes.
        try testing.expect(record.config.add_label(name, "v") != null);
    }
    try testing.expect(record.config.add_label("zz", "v") == null);
}
