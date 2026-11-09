//! The configuration blob of an image (`application/vnd.oci.image.config.v1+json`, or Docker's
//! `...container.image.v1+json`): what an image runs by default. Only five members of its
//! `config` object matter to zbx: `Entrypoint`, `Cmd`, `Env`, `WorkingDir` and `User`. The
//! rest is ignored, and a member that is absent or null is empty.
//!
//! Read with `std.json` into a typed struct in the caller's arena, then copied into the bounded
//! `images.Settings`, so a hostile config can at worst fill the arena or the settings and be
//! refused with a reason.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const images = @import("../store/images.zig");

const Settings = images.Settings;

const ConfigObject = struct {
    Entrypoint: ?[]const []const u8 = null,
    Cmd: ?[]const []const u8 = null,
    Env: ?[]const []const u8 = null,
    WorkingDir: ?[]const u8 = null,
    User: ?[]const u8 = null,
};

const Document = struct {
    config: ?ConfigObject = null,
};

/// Why a configuration is refused.
pub const Problem = error{
    /// Not JSON, or not the shape of an image configuration.
    malformed,
    /// More than the arena holds.
    too_complex,
    /// More words, variables or bytes than `images.Settings` holds, or a word that is too long.
    too_big,
    /// An entry of `Env` without a `=`, or with an empty name.
    bad_variable,
};

/// Reads `body` into `settings` and `labels`. `arena` is scratch for the JSON. Labels that do
/// not fit `images.Labels`, or are not a JSON object of strings, are left unknown, never refused:
/// zbx only needs them to derive a result digest, and an image that cannot is still pulled.
pub fn parse(
    arena: []u8,
    body: []const u8,
    settings: *Settings,
    labels: *images.Labels,
) Problem!void {
    assert(arena.len > 0);
    assert(body.len <= constants.registry_manifest_bytes_max);
    settings.clear();
    labels.clear();
    read_labels(arena, body, labels);
    var fixed = std.heap.FixedBufferAllocator.init(arena);
    const options: std.json.ParseOptions = .{ .ignore_unknown_fields = true };
    const document = std.json.parseFromSliceLeaky(
        Document,
        fixed.allocator(),
        body,
        options,
    ) catch |err| {
        return switch (err) {
            error.OutOfMemory => error.too_complex,
            else => error.malformed,
        };
    };
    const config = document.config orelse return;
    try add_words(settings, .entrypoint, config.Entrypoint orelse &.{});
    try add_words(settings, .cmd, config.Cmd orelse &.{});
    for (config.Env orelse &.{}) |variable| {
        const equals = std.mem.indexOfScalar(u8, variable, '=') orelse return error.bad_variable;
        if (equals == 0) return error.bad_variable;
        settings.add(.env, variable) orelse return error.too_big;
    }
    settings.set(.workdir, config.WorkingDir orelse "") orelse return error.too_big;
    settings.set(.user, config.User orelse "") orelse return error.too_big;
}

/// Copies the `Labels` member of the `config` object in, by walking `body` with a scanner of
/// its own: labels take no part in the typed parse, so they cannot make it fail. Anything this
/// walk cannot hold (a repeated key, a value that is not a string, a string past
/// `image_labels_bytes_max`, too many labels, a document too deep for `arena`) leaves them
/// unknown. `body` is not checked here; the typed parse that follows refuses it if malformed.
fn read_labels(arena: []u8, body: []const u8, labels: *images.Labels) void {
    assert(labels.known);
    assert(labels.total == 0);
    assert(arena.len > 0);
    var fixed = std.heap.FixedBufferAllocator.init(arena);
    var scanner = std.json.Scanner.initCompleteInput(fixed.allocator(), body);
    const found = find_labels(&scanner, fixed.allocator(), labels) catch false;
    if (!found or !labels.known) labels.forget();
    if (!labels.known) assert(labels.total == 0);
}

const LabelsError = std.json.Scanner.NextError || std.json.Scanner.AllocError ||
    std.json.Scanner.SkipError || error{Unreadable};

/// Walks to `config`, then to its `Labels`. False if the walk cannot say what they are.
fn find_labels(
    scanner: *std.json.Scanner,
    allocator: std.mem.Allocator,
    labels: *images.Labels,
) LabelsError!bool {
    assert(labels.known);
    assert(labels.total == 0);
    assert(scanner.cursor == 0);
    if ((try scanner.next()) != .object_begin) return true;
    while (try next_key(scanner, allocator)) |name| {
        if (!std.mem.eql(u8, name, "config")) {
            try scanner.skipValue();
            continue;
        }
        if ((try scanner.peekNextTokenType()) != .object_begin) return true;
        _ = try scanner.next();
        return try find_in_config(scanner, allocator, labels);
    }
    return true;
}

fn find_in_config(
    scanner: *std.json.Scanner,
    allocator: std.mem.Allocator,
    labels: *images.Labels,
) LabelsError!bool {
    assert(labels.known);
    assert(labels.total == 0);
    var seen = false;
    while (try next_key(scanner, allocator)) |name| {
        if (!std.mem.eql(u8, name, "Labels")) {
            try scanner.skipValue();
            continue;
        }
        if (seen) return false;
        seen = true;
        switch (try scanner.peekNextTokenType()) {
            .null => _ = try scanner.next(),
            .object_begin => {
                _ = try scanner.next();
                if (!try read_pairs(scanner, allocator, labels)) return false;
            },
            else => return false,
        }
    }
    return true;
}

fn read_pairs(
    scanner: *std.json.Scanner,
    allocator: std.mem.Allocator,
    labels: *images.Labels,
) LabelsError!bool {
    assert(labels.known);
    assert(labels.total <= constants.image_labels_count_max);
    while (try next_key(scanner, allocator)) |name| {
        if ((try scanner.peekNextTokenType()) != .string) return false;
        const text = try next_string(scanner, allocator);
        labels.add(name, text) orelse return false;
        assert(labels.known);
    }
    assert(labels.known);
    return true;
}

/// The next member name of the object being walked, or null at its end.
fn next_key(scanner: *std.json.Scanner, allocator: std.mem.Allocator) LabelsError!?[]const u8 {
    assert(scanner.cursor <= scanner.input.len);
    assert(scanner.input.len > 0);
    if ((try scanner.peekNextTokenType()) == .object_end) {
        _ = try scanner.next();
        return null;
    }
    return try next_string(scanner, allocator);
}

fn next_string(scanner: *std.json.Scanner, allocator: std.mem.Allocator) LabelsError![]const u8 {
    const limit = constants.image_labels_bytes_max;
    assert(limit > 0);
    assert(scanner.cursor <= scanner.input.len);
    return switch (try scanner.nextAllocMax(allocator, .alloc_if_needed, limit)) {
        .string, .allocated_string => |text| text,
        else => error.Unreadable,
    };
}

fn add_words(settings: *Settings, list: Settings.List, words: []const []const u8) Problem!void {
    assert(list != .env);
    assert(words.len < 1 << 20);
    for (words) |word| settings.add(list, word) orelse return error.too_big;
}

const testing = std.testing;

fn parsed(body: []const u8, settings: *Settings) Problem!void {
    var labels: images.Labels = undefined;
    return parsed_labels(body, settings, &labels);
}

fn parsed_labels(body: []const u8, settings: *Settings, labels: *images.Labels) Problem!void {
    var arena: [64 * 1024]u8 = undefined;
    return parse(&arena, body, settings, labels);
}

test "the five members are read, and the rest is ignored" {
    // Goal: what python:3.12-slim's config looks like to zbx.
    var settings: Settings = undefined;
    try parsed(
        \\{"architecture":"amd64","os":"linux","config":{"Env":["PATH=/usr/local/bin:/usr/bin",
        \\"LANG=C.UTF-8"],"Cmd":["python3"],"Entrypoint":null,"WorkingDir":"","User":"",
        \\"Labels":{"a":"b"},"ExposedPorts":{"80/tcp":{}}},"history":[{"created_by":"x"}]}
    , &settings);
    try testing.expectEqual(@as(u32, 2), settings.count(.env));
    try testing.expectEqualStrings("PATH=/usr/local/bin:/usr/bin", settings.word(.env, 0));
    try testing.expectEqual(@as(u32, 1), settings.count(.cmd));
    try testing.expectEqualStrings("python3", settings.word(.cmd, 0));
    try testing.expectEqual(@as(u32, 0), settings.count(.entrypoint));
    try testing.expectEqualStrings("", settings.get(.workdir));
    try testing.expectEqualStrings("", settings.get(.user));
}

test "an entrypoint, a directory and a user" {
    // Goal: the members a service image sets.
    var settings: Settings = undefined;
    try parsed(
        \\{"config":{"Entrypoint":["/docker-entrypoint.sh"],"Cmd":["nginx","-g","daemon off;"],
        \\"WorkingDir":"/app","User":"nginx:nginx"}}
    , &settings);
    try testing.expectEqualStrings("/docker-entrypoint.sh", settings.word(.entrypoint, 0));
    try testing.expectEqual(@as(u32, 3), settings.count(.cmd));
    try testing.expectEqualStrings("daemon off;", settings.word(.cmd, 2));
    try testing.expectEqualStrings("/app", settings.get(.workdir));
    try testing.expectEqualStrings("nginx:nginx", settings.get(.user));
}

test "no config member is an image with nothing set; bad documents are refused" {
    // Goal: the refusals, each with its own reason.
    var settings: Settings = undefined;
    try parsed("{\"architecture\":\"arm64\"}", &settings);
    try testing.expectEqual(@as(u32, 0), settings.count(.cmd));
    try testing.expectError(error.malformed, parsed("[1,2]", &settings));
    try testing.expectError(error.malformed, parsed("", &settings));
    try testing.expectError(error.malformed, parsed("{\"config\":{\"Cmd\":\"sh\"}}", &settings));
    try testing.expectError(
        error.bad_variable,
        parsed("{\"config\":{\"Env\":[\"NOEQUALS\"]}}", &settings),
    );
    try testing.expectError(
        error.bad_variable,
        parsed("{\"config\":{\"Env\":[\"=x\"]}}", &settings),
    );
    var labels: images.Labels = undefined;
    var small: [64]u8 = undefined;
    const body = "{\"config\":{\"Cmd\":[\"a\",\"b\",\"c\",\"d\",\"e\",\"f\",\"g\",\"h\"]}}";
    try testing.expectError(error.too_complex, parse(&small, body, &settings, &labels));
}

test "more words than the settings hold is refused" {
    // Goal: the bound is exact.
    var settings: Settings = undefined;
    var text: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&text);
    try writer.writeAll("{\"config\":{\"Cmd\":[");
    for (0..constants.image_settings_words_max + 1) |index| {
        if (index > 0) try writer.writeAll(",");
        try writer.writeAll("\"w\"");
    }
    try writer.writeAll("]}}");
    try testing.expectError(error.too_big, parsed(writer.buffered(), &settings));
}

test "labels are read in key order, and what does not fit leaves them unknown" {
    // Goal: a labelled config keeps them; a non-string value, a long block or too many do not
    // refuse the pull but forget the labels.
    var settings: Settings = undefined;
    var labels: images.Labels = undefined;
    try parsed_labels("{\"config\":{\"Labels\":{\"b\":\"2\",\"a\":\"1\"}}}", &settings, &labels);
    try testing.expect(labels.known);
    try testing.expectEqual(@as(u32, 2), labels.count());
    try testing.expectEqualStrings("a", labels.key(0));
    try testing.expectEqualStrings("2", labels.value(1));
    try parsed_labels("{\"config\":{\"Labels\":null}}", &settings, &labels);
    try testing.expect(labels.known and labels.count() == 0);
    try parsed_labels("{\"config\":{\"Labels\":{\"a\":1}}}", &settings, &labels);
    try testing.expect(!labels.known);
    try parsed_labels("{\"config\":{\"Labels\":[]}}", &settings, &labels);
    try testing.expect(!labels.known);
    var text: [8192]u8 = undefined;
    var writer = std.Io.Writer.fixed(&text);
    try writer.writeAll("{\"config\":{\"Labels\":{\"k\":\"");
    try writer.splatByteAll('x', constants.image_labels_bytes_max);
    try writer.writeAll("\"}}}");
    try parsed_labels(writer.buffered(), &settings, &labels);
    try testing.expect(!labels.known);
}

test "labels never refuse a pull: a repeated key or a huge value only leaves them unknown" {
    // Goal: main accepted both (it skipped `Labels`); so must this, with the pull's own arena.
    var settings: Settings = undefined;
    var labels: images.Labels = undefined;
    const arena = try testing.allocator.alloc(u8, constants.registry_json_arena_bytes);
    defer testing.allocator.free(arena);
    const repeated = "{\"config\":{\"Cmd\":[\"sh\"],\"Labels\":{\"a\":\"1\",\"a\":\"2\"}}}";
    try parse(arena, repeated, &settings, &labels);
    try testing.expect(!labels.known);
    try testing.expectEqualStrings("sh", settings.word(.cmd, 0));

    const huge = 600 * 1024;
    const body = try testing.allocator.alloc(u8, huge + 100);
    defer testing.allocator.free(body);
    var writer = std.Io.Writer.fixed(body);
    try writer.writeAll("{\"config\":{\"Cmd\":[\"sh\"],\"Labels\":{\"k\":\"");
    try writer.splatByteAll('x', huge);
    try writer.writeAll("\"}}}");
    try parse(arena, writer.buffered(), &settings, &labels);
    try testing.expect(!labels.known);
    try testing.expectEqualStrings("sh", settings.word(.cmd, 0));

    // Other odd shapes: a repeated `Labels`, an escaped key, a long key elsewhere, deep nesting.
    const odd = [_][]const u8{
        "{\"config\":{\"Labels\":{\"a\":\"1\"},\"Labels\":{\"b\":\"2\"}}}",
        "{\"x\":{\"y\":[[[[1]]]]},\"config\":{\"Labels\":{\"a\":{\"b\":1}}}}",
    };
    for (odd) |text| {
        try parse(arena, text, &settings, &labels);
        try testing.expect(!labels.known);
    }
    const escaped = "{\"x\":[1,2],\"config\":{\"La\\u0062els\":{\"a\":\"1\"}}}";
    try parse(arena, escaped, &settings, &labels);
    try testing.expect(labels.known and labels.count() == 1);
    try parse(arena, "{\"config\":{\"Labels\":{\"a\":\"\\u0041\\n\"}}}", &settings, &labels);
    try testing.expect(labels.known and labels.count() == 1);
    try testing.expectEqualStrings("A\n", labels.value(0));
}

test "labels totalling exactly the byte bound are kept; one byte more forgets them" {
    // Goal: the bound is exact (REVIEW.md: a test at the bound and one past it).
    var settings: Settings = undefined;
    var labels: images.Labels = undefined;
    var text: [8192]u8 = undefined;
    const sizes = .{ constants.image_labels_bytes_max - 1, constants.image_labels_bytes_max };
    inline for (sizes) |size| {
        var writer = std.Io.Writer.fixed(&text);
        try writer.writeAll("{\"config\":{\"Labels\":{\"k\":\"");
        try writer.splatByteAll('x', size);
        try writer.writeAll("\"}}}");
        try parsed_labels(writer.buffered(), &settings, &labels);
        // "k" plus `size` bytes: the first is exactly the bound, the second one past it.
        try testing.expectEqual(size == constants.image_labels_bytes_max - 1, labels.known);
    }
    var writer = std.Io.Writer.fixed(&text);
    for (0..constants.image_labels_count_max + 1) |index| {
        try writer.writeAll(if (index == 0) "{\"config\":{\"Labels\":{" else ",");
        try writer.print("\"l{d:0>2}\":\"v\"", .{index});
    }
    try writer.writeAll("}}}");
    try parsed_labels(writer.buffered(), &settings, &labels);
    try testing.expect(!labels.known);
}
