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
    Labels: ?std.json.Value = null,
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
    read_labels(labels, config.Labels);
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

/// Copies a JSON `Labels` member in; anything `images.Labels` cannot hold leaves them unknown.
fn read_labels(labels: *images.Labels, member: ?std.json.Value) void {
    assert(labels.known);
    assert(labels.total == 0);
    const value = member orelse return;
    const object = switch (value) {
        .object => |found| found,
        .null => return,
        else => return labels.forget(),
    };
    for (object.keys(), object.values()) |name, text| {
        const word = switch (text) {
            .string => |found| found,
            else => return labels.forget(),
        };
        labels.add(name, word) orelse return labels.forget();
    }
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
