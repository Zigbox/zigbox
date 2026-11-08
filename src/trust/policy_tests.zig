//! Tests for `policy.zig`: a whole policy reads back, every defect is refused where it is, and
//! the bounds hold at and one past.

const std = @import("std");
const testing = std.testing;
const constants = @import("../constants.zig");
const key = @import("key.zig");
const policy = @import("policy.zig");

var parsed: policy.Policy = undefined;
var text_buffer: [constants.policy_bytes_max + 16]u8 = undefined;

fn public_line(seed: u8) [constants.key_public_text_bytes]u8 {
    const seed_bytes: [constants.key_seed_bytes]u8 = @splat(seed);
    return key.public_text(key.public_of_seed(seed_bytes));
}

fn expect_problem(text: []const u8, kind: policy.Kind, line: u32, column: u32) !void {
    const problem = policy.parse(text, &parsed) orelse return error.TestExpectedProblem;
    try testing.expectEqual(kind, problem.kind);
    try testing.expectEqual(line, problem.line);
    try testing.expectEqual(column, problem.column);
}

test "a whole policy reads back, and a minimal one is only a version" {
    // Goal: every field lands where it belongs. Method: parse a file with each field, then
    // the shortest file, and compare.
    const public = public_line(1);
    var buffer: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer,
        \\// Trust the release key.
        \\.{{
        \\    .version = 1,
        \\    .keys = .{{ .{{ .name = "release", .public = "{s}" }}, }},
        \\    .require_signature = true,
        \\    .verify = "always",
        \\}}
    , .{public});
    try testing.expectEqual(@as(?policy.Problem, null), policy.parse(text, &parsed));
    try testing.expectEqual(@as(u32, 1), parsed.key_count);
    try testing.expectEqualStrings("release", parsed.keys[0].name_text());
    try testing.expect(parsed.require_signature);
    try testing.expect(!parsed.require_provenance);
    try testing.expectEqual(policy.Verify.always, parsed.verify);
    try testing.expect(parsed.checks());
    const seed1: [constants.key_seed_bytes]u8 = @splat(1);
    const found = parsed.trusted(&key.public_of_seed(seed1));
    try testing.expect(found != null);
    const seed2: [constants.key_seed_bytes]u8 = @splat(2);
    try testing.expect(parsed.trusted(&key.public_of_seed(seed2)) == null);

    try testing.expectEqual(@as(?policy.Problem, null), policy.parse(".{ .version = 1 }", &parsed));
    try testing.expect(!parsed.checks());
    try testing.expectEqual(policy.Verify.cached, parsed.verify);
}

test "every defect is refused with its line and column" {
    // Goal: one refusal per kind, at the offending token. Method: a small file for each.
    try expect_problem("", .syntax, 1, 1);
    try expect_problem(".{ }", .missing_version, 1, 5);
    try expect_problem(".{ .version = 2 }", .newer_version, 1, 15);
    try expect_problem(".{ .version = 0 }", .bad_version, 1, 15);
    try expect_problem(".{ .version = 1, .extra = true }", .unknown_field, 1, 18);
    try expect_problem(".{ .version = 1, .version = 1 }", .duplicate_field, 1, 18);
    try expect_problem(".{ .version = 1 } .{", .syntax, 1, 19);
    try expect_problem(".{ .version = 1,\n .verify = \"never\" }", .bad_verify, 2, 12);
    try expect_problem(".{ .version = 1,\n .verify = \"a\\n\" }", .bad_string, 2, 12);
    try expect_problem(".{ .version = 1, .require_signature = 1 }", .syntax, 1, 39);
    try expect_problem(".{ .version = 1, .require_provenance = true }", .provenance_not_yet, 1, 40);
    try testing.expectEqual(
        @as(?policy.Problem, null),
        policy.parse(".{ .version = 1, .require_provenance = false }", &parsed),
    );
}

test "a key's name and public key are checked, and a key may be listed once" {
    // Goal: the key entries' defects. Method: a policy per defect, built around real keys.
    const one = public_line(1);
    const two = public_line(2);
    var buffer: [1024]u8 = undefined;
    const bad_name = try std.fmt.bufPrint(&buffer,
        ".{{ .version = 1, .keys = .{{ .{{ .name = \"Bad\", .public = \"{s}\" }} }} }}",
        .{one},
    );
    try expect_problem(bad_name, .bad_name, 1, 40);
    const bad_public = ".{ .version = 1, .keys = .{ .{ .name = \"a\", .public = \"nope\" } } }";
    try expect_problem(bad_public, .bad_public, 1, 55);
    const same_key = try std.fmt.bufPrint(&buffer,
        ".{{ .version = 1, .keys = .{{ .{{ .name = \"a\", .public = \"{s}\" }}, " ++
            ".{{ .name = \"b\", .public = \"{s}\" }} }} }}",
        .{ one, one },
    );
    const problem = policy.parse(same_key, &parsed) orelse return error.TestExpectedProblem;
    try testing.expectEqual(policy.Kind.key_twice, problem.kind);
    try testing.expectEqualStrings("b", problem.detail_text());
    const same_name = try std.fmt.bufPrint(&buffer,
        ".{{ .version = 1, .keys = .{{ .{{ .name = \"a\", .public = \"{s}\" }}, " ++
            ".{{ .name = \"a\", .public = \"{s}\" }} }} }}",
        .{ one, two },
    );
    try expect_problem(same_name, .key_twice, 1, 242);
    const half = ".{ .version = 1, .keys = .{ .{ .name = \"a\" } } }";
    try expect_problem(half, .syntax, 1, 29);
}

test "sixteen keys fit and a seventeenth is refused, and the file size is bounded" {
    // Goal: the bounds at and one past. Method: build a file of n distinct keys; then a file
    // of exactly `policy_bytes_max` bytes and one of one more.
    var at: usize = 0;
    at += (try std.fmt.bufPrint(text_buffer[at..], ".{{ .version = 1, .keys = .{{", .{})).len;
    var index: u8 = 0;
    while (index < constants.policy_keys_max + 1) : (index += 1) {
        const written = try std.fmt.bufPrint(
            text_buffer[at..],
            " .{{ .name = \"k{d}\", .public = \"{s}\" }},",
            .{ index, public_line(index + 1) },
        );
        at += written.len;
        const closed = try std.fmt.bufPrint(text_buffer[at..], " }} }}", .{});
        const result = policy.parse(text_buffer[0 .. at + closed.len], &parsed);
        if (index < constants.policy_keys_max) {
            try testing.expectEqual(@as(?policy.Problem, null), result);
            try testing.expectEqual(@as(u32, index) + 1, parsed.key_count);
        } else {
            try testing.expectEqual(policy.Kind.too_many_keys, result.?.kind);
        }
    }
    const head = ".{ .version = 1 }";
    @memset(&text_buffer, ' ');
    @memcpy(text_buffer[0..head.len], head);
    const full = text_buffer[0..constants.policy_bytes_max];
    try testing.expectEqual(@as(?policy.Problem, null), policy.parse(full, &parsed));
    const over = text_buffer[0 .. constants.policy_bytes_max + 1];
    try testing.expectEqual(policy.Kind.too_large, policy.parse(over, &parsed).?.kind);
}
