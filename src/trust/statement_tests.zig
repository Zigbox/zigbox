//! Tests for `statement.zig`: the golden statements, the payload changing with each field it
//! covers, every spelling parse refuses, the subject bound at the bound and one past, and the
//! time form.

const std = @import("std");
const testing = std.testing;
const constants = @import("../constants.zig");
const statement = @import("statement.zig");

const tree_hex = "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc";
const result_hex = "05101b26313c47525d68737e89949faab5c0cbd6e1ecf7020d18232e39444f5a";
const manifest_hex = "1111111111111111111111111111111111111111111111111111111111111111";
const signed_at: u64 = 1794132000; // 2026-11-08T10:00:00Z

fn digest(comptime hex: []const u8) statement.Digest {
    var out: statement.Digest = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable; // The tests pass 64 hex digits.
    return out;
}

const head = "{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[" ++
    "{\"name\":\"tree\",\"digest\":{\"zbxTree\":\"" ++ tree_hex ++ "\"}}";

const tail = "],\"predicateType\":\"" ++ constants.sign_predicate_type ++ "\"," ++
    "\"predicate\":{\"signedAt\":\"2026-11-08T10:00:00Z\"}}";

// The goldens read the type URI from the constant, never spelling it out (the brief).
const golden_tree = head ++ tail;
const golden_result = head ++ ",{\"name\":\"result\",\"digest\":{\"zbxResult\":\"" ++
    result_hex ++ "\"}}" ++ tail;
const golden_manifest = head ++ ",{\"name\":\"docker.io/library/alpine:3.20@sha256:" ++
    manifest_hex ++ "\",\"digest\":{\"sha256\":\"" ++ manifest_hex ++ "\"}}" ++ tail;

fn render_into(out: []u8, value: *const statement.Statement) []const u8 {
    return statement.render(out, value);
}

test "the golden statements render byte for byte and parse back" {
    // Goal: pin the three statement shapes. Method: render each, compare with the golden text,
    // parse the golden, and compare the fields.
    var out: [statement.render_bytes_max]u8 = undefined;
    const tree = statement.Statement.for_tree(digest(tree_hex), signed_at);
    try testing.expectEqualStrings(golden_tree, render_into(&out, &tree));
    const parsed_tree = try statement.parse(golden_tree);
    try testing.expectEqualSlices(u8, &digest(tree_hex), &parsed_tree.tree);
    try testing.expectEqual(statement.Binding.none, parsed_tree.binding);
    try testing.expectEqual(signed_at, parsed_tree.signed_at);

    const result = statement.Statement.for_result(digest(tree_hex), digest(result_hex), signed_at);
    try testing.expectEqualStrings(golden_result, render_into(&out, &result));
    const parsed_result = try statement.parse(golden_result);
    try testing.expectEqualSlices(u8, &digest(result_hex), &parsed_result.binding.result);
    try testing.expectEqual(@as(u32, 0), parsed_result.reference_length);

    const name = "docker.io/library/alpine:3.20@sha256:" ++ manifest_hex;
    const manifest = statement.Statement.for_manifest(
        digest(tree_hex),
        name,
        digest(manifest_hex),
        signed_at,
    );
    try testing.expectEqualStrings(golden_manifest, render_into(&out, &manifest));
    const parsed_manifest = try statement.parse(golden_manifest);
    try testing.expectEqualSlices(u8, &digest(manifest_hex), &parsed_manifest.binding.manifest);
    try testing.expectEqualStrings(name, parsed_manifest.reference());
}

test "the payload changes with each field it covers" {
    // Goal: a signature over the payload covers every field. Method: change one field at a
    // time from a base statement and check the bytes differ from the base and from each other.
    var base_out: [statement.render_bytes_max]u8 = undefined;
    var other_out: [statement.render_bytes_max]u8 = undefined;
    const base = statement.Statement.for_result(digest(tree_hex), digest(result_hex), signed_at);
    const base_text = render_into(&base_out, &base);

    var tree = base;
    tree.tree[31] ^= 1;
    var result = base;
    result.binding.result[0] ^= 1;
    var later = base;
    later.signed_at += 1;
    const unbound = statement.Statement.for_tree(digest(tree_hex), signed_at);
    const manifest = statement.Statement.for_manifest(
        digest(tree_hex),
        "a",
        digest(result_hex),
        signed_at,
    );
    for ([_]statement.Statement{ tree, result, later, unbound, manifest }) |changed| {
        try testing.expect(!std.mem.eql(u8, base_text, render_into(&other_out, &changed)));
    }
}

test "parse refuses every statement render does not write" {
    // Goal: the schema layer's checks that the JSON reader leaves out. Method: damage the
    // golden one way at a time and expect `Malformed`, or `UnknownPredicate` for a new type.
    const swapped = "{\"subject\":[],\"_type\":\"" ++ statement.statement_type ++ "\"}";
    // A wrong statement type, a missing subject, the tree not first, a wrong tree name.
    const wrong_type = try std.mem.replaceOwned(
        u8,
        testing.allocator,
        golden_tree,
        "Statement/v1",
        "Statement/v2",
    );
    defer testing.allocator.free(wrong_type);
    const refused = [_][]const u8{
        "",
        "{}",
        swapped,
        golden_tree ++ " ",
        golden_tree ++ "{}",
        wrong_type,
    };
    for (refused) |text| {
        try testing.expectError(error.Malformed, statement.parse(text));
    }

    const edits = [_]struct { from: []const u8, to: []const u8 }{
        .{ .from = "\"name\":\"tree\"", .to = "\"name\":\"trea\"" },
        .{ .from = "zbxTree", .to = "zbxTreE" },
        .{ .from = tree_hex, .to = tree_hex[1..] },
        .{ .from = tree_hex, .to = "0A" ++ tree_hex[2..] },
        .{ .from = "\"signedAt\"", .to = "\"signedat\"" },
        .{ .from = "2026-11-08T10:00:00Z", .to = "2026-11-08t10:00:00Z" },
        .{ .from = "2026-11-08T10:00:00Z", .to = "2026-11-08T10:00:00+00:00" },
        .{ .from = "2026-11-08T10:00:00Z", .to = "2026-02-30T10:00:00Z" },
        .{ .from = "2026-11-08T10:00:00Z", .to = "2026-11-08T24:00:00Z" },
        .{ .from = "\"predicate\":{", .to = "\"predicate\":{\"a\":1," },
        .{ .from = "\"subject\":[", .to = "\"subject\":[]," },
    };
    for (edits) |edit| {
        const text = try std.mem.replaceOwned(
            u8,
            testing.allocator,
            golden_tree,
            edit.from,
            edit.to,
        );
        defer testing.allocator.free(text);
        try testing.expect(!std.mem.eql(u8, text, golden_tree));
        try testing.expectError(error.Malformed, statement.parse(text));
    }

    const other_type = try std.mem.replaceOwned(
        u8,
        testing.allocator,
        golden_tree,
        constants.sign_predicate_type,
        "https://example.org/other/v1",
    );
    defer testing.allocator.free(other_type);
    try testing.expectError(error.UnknownPredicate, statement.parse(other_type));
}

test "the binding: its name and digest key must agree, and a name is never empty" {
    // Goal: a `zbxResult` digest is named `result`; a `sha256` digest has any non-empty name.
    // Method: three bad second subjects.
    const bad_second = [_][]const u8{
        ",{\"name\":\"other\",\"digest\":{\"zbxResult\":\"" ++ result_hex ++ "\"}}",
        ",{\"name\":\"\",\"digest\":{\"sha256\":\"" ++ manifest_hex ++ "\"}}",
        ",{\"name\":\"a\",\"digest\":{\"blake3\":\"" ++ manifest_hex ++ "\"}}",
        ",{\"name\":\"a\",\"digest\":{\"sha256\":\"" ++ manifest_hex ++ "\",\"x\":\"\"}}",
        ",{\"name\":\"a\",\"digest\":{}}",
    };
    inline for (bad_second) |second| {
        try testing.expectError(error.Malformed, statement.parse(head ++ second ++ tail));
    }
}

test "the subject bound: two parse, a third is refused" {
    // Goal: `statement_subjects_max` at the bound and one past. Method: the tree alone (one),
    // the tree and a binding (the bound), and a third subject.
    comptime std.debug.assert(constants.statement_subjects_max == 2);
    _ = try statement.parse(golden_tree);
    _ = try statement.parse(golden_result);
    const third = ",{\"name\":\"x\",\"digest\":{\"sha256\":\"" ++ manifest_hex ++ "\"}}";
    try testing.expectError(
        error.Malformed,
        statement.parse(head ++ third ++ third ++ tail),
    );
    // A tree-less statement (an empty subject array) is refused too.
    const no_subjects = "{\"_type\":\"" ++ statement.statement_type ++
        "\",\"subject\":[]," ++ tail[2..];
    try testing.expectError(error.Malformed, statement.parse(no_subjects));
}

test "the reference bound: 1024 bytes parse, 1025 do not" {
    // Goal: `reference_bytes_max` at the bound and one past, through render and parse.
    var out: [statement.render_bytes_max]u8 = undefined;
    var name: [constants.reference_bytes_max + 1]u8 = undefined;
    @memset(&name, 'r');
    const at = statement.Statement.for_manifest(
        digest(tree_hex),
        name[0..constants.reference_bytes_max],
        digest(manifest_hex),
        signed_at,
    );
    const text = render_into(&out, &at);
    const parsed = try statement.parse(text);
    try testing.expectEqual(constants.reference_bytes_max, parsed.reference_length);

    var past: [statement.render_bytes_max + 8]u8 = undefined;
    const longer = try std.fmt.bufPrint(
        &past,
        "{s},{{\"name\":\"{s}\",\"digest\":{{\"sha256\":\"{s}\"}}}}{s}",
        .{ head, name[0..], manifest_hex, tail },
    );
    try testing.expectError(error.Malformed, statement.parse(longer));
}

test "a reference with every escape renders within render_bytes_max and reads back" {
    // Goal: the worst case for `render_bytes_max` (six bytes out per byte in).
    var out: [statement.render_bytes_max]u8 = undefined;
    const name: [constants.reference_bytes_max]u8 = @splat(1);
    const value = statement.Statement.for_manifest(
        digest(tree_hex),
        &name,
        digest(manifest_hex),
        signed_at,
    );
    const text = render_into(&out, &value);
    const parsed = try statement.parse(text);
    try testing.expectEqualStrings(&name, parsed.reference());
}

test "times: the form is fixed, and only existing dates parse" {
    // Goal: `signedAt` is RFC 3339 UTC to the second and nothing else. Method: formats at the
    // edges, round trips, and spellings that do not re-render to themselves.
    try testing.expectEqualStrings("1970-01-01T00:00:00Z", &statement.format_time(0));
    try testing.expectEqualStrings("2026-11-08T10:00:00Z", &statement.format_time(signed_at));
    try testing.expectEqualStrings("2000-02-29T23:59:59Z", &statement.format_time(951868799));
    try testing.expectEqualStrings(
        "9999-12-31T23:59:59Z",
        &statement.format_time(constants.signed_at_seconds_max),
    );
    const instants = [_]u64{
        0, 1, 59, 86399, 86400, 951868799, signed_at, constants.signed_at_seconds_max,
    };
    for (instants) |seconds| {
        const text = statement.format_time(seconds);
        try testing.expectEqual(@as(?u64, seconds), statement.parse_time(&text));
    }
    for ([_][]const u8{
        "",
        "1969-12-31T23:59:59Z",
        "10000-01-01T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-00-01T00:00:00Z",
        "2026-11-00T00:00:00Z",
        "2026-11-31T00:00:00Z",
        "2023-02-29T00:00:00Z",
        "2026-11-08T10:60:00Z",
        "2026-11-08T10:00:60Z",
        "2026-11-08 10:00:00Z",
        "2026-11-08T10:00:00z",
        "2026-11-08T10:00:00",
        "+026-11-08T10:00:00Z",
        "2026-11-08T1:00:00ZZ",
    }) |text| {
        try testing.expectEqual(@as(?u64, null), statement.parse_time(text));
    }
}
