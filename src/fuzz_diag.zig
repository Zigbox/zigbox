//! Fuzzers for the diagnostics machinery: the `Diag` bounds under adversarial text, and the
//! properties every CLI run must have (exactly one diagnostic per failure, blame matching the
//! exit code, nothing unsafe on screen). Driven by `fuzz.zig`.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const codes = @import("diag/codes.zig");
const render = @import("diag/render.zig");
const test_util = @import("test_util.zig");
const text_util = @import("text.zig");
const Diag = @import("diag/diag.zig").Diag;

/// What a stderr holds, counted from its text: how many diagnostic headers and the last code.
pub const Found = struct {
    count: u32,
    code: ?codes.Code,
};

/// Counts diagnostics in text or JSON-lines output. An independent reading of the format, not
/// the renderer's own code, so a renderer bug cannot hide itself.
pub fn find_diagnostics(stderr: []const u8) Found {
    var found: Found = .{ .count = 0, .code = null };
    var lines = std.mem.splitScalar(u8, stderr, '\n');
    while (lines.next()) |line| {
        const tag: ?[]const u8 = header_code(line);
        if (tag == null) continue;
        found.count += 1;
        found.code = codes.parse(tag.?);
    }
    return found;
}

fn header_code(line: []const u8) ?[]const u8 {
    const json_start = "{\"code\":\"";
    if (std.mem.startsWith(u8, line, json_start)) {
        const rest = line[json_start.len..];
        const end = std.mem.indexOfScalar(u8, rest, '"') orelse return "";
        return rest[0..end];
    }
    for ([_][]const u8{ "error[", "bug[", "warning[" }) |prefix| {
        if (!std.mem.startsWith(u8, line, prefix)) continue;
        const rest = line[prefix.len..];
        const end = std.mem.indexOfScalar(u8, rest, ']') orelse return "";
        return rest[0..end];
    }
    return null;
}

/// Bytes a text rendering may contain: printable ASCII, newline, and the UTF-8 middle dot the
/// `more` line uses. Never an escape or any other control byte.
fn text_output_is_clean(output: []const u8) bool {
    var index: usize = 0;
    while (index < output.len) : (index += 1) {
        const byte = output[index];
        if (byte == '\n') continue;
        if (byte >= 0x20 and byte <= 0x7e) continue;
        const dot = index + 1 < output.len and byte == 0xc2 and output[index + 1] == 0xb7;
        if (!dot) return false;
        index += 1;
    }
    return true;
}

/// Adversarial text: random bytes of random length, sometimes printable, sometimes all spaces
/// or empty, sometimes at, one under or one over the field bound.
fn random_text(random: std.Random, storage: *[constants.diag_field_bytes_max + 64]u8) []const u8 {
    const bound = constants.diag_field_bytes_max;
    const length: u32 = switch (random.uintLessThan(u8, 6)) {
        0 => 0,
        1 => bound,
        2 => bound + 1,
        3 => bound - 1,
        else => random.uintAtMost(u32, bound + 63),
    };
    const text = storage[0..length];
    random.bytes(text);
    switch (random.uintLessThan(u8, 4)) {
        0 => for (text) |*byte| {
            byte.* = 0x20 + byte.* % 0x5f;
        },
        1 => @memset(text, ' '),
        2 => for (text) |*byte| {
            byte.* = "\"\\ {}%\n\x1b"[byte.* % 8];
        },
        else => {},
    }
    return text;
}

/// Property: whatever is put into a `Diag`, it stays within its bounds, counts what it could not
/// keep, stores only printable ASCII, and renders in every mode to output that fits the buffer,
/// has no escape or control byte, and (for JSON) is one valid object on one line.
pub fn fuzz_diag(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    var diag: Diag = undefined;
    diag.reset();
    diag.raise(random_code(random));

    var storage: [constants.diag_field_bytes_max + 64]u8 = undefined;
    var calls = [_]u32{ 0, 0, 0, 0 };
    var last_cause: []const u8 = "";
    var last_cause_storage: [constants.diag_field_bytes_max + 64]u8 = undefined;
    for (0..random.uintAtMost(u32, 40)) |_| {
        const text = random_text(random, &storage);
        const operation = random.uintLessThan(u8, 4);
        calls[operation] += 1;
        switch (operation) {
            0 => {
                diag.cause("{s}", .{text});
                @memcpy(last_cause_storage[0..text.len], text);
                last_cause = last_cause_storage[0..text.len];
            },
            1 => diag.while_("{s}", .{text}),
            2 => diag.context("key", "{s}", .{text}),
            else => diag.fix(.{ .sentence = if (text.len > 0) text else "x", .command = text }),
        }
    }
    check_bounds(&diag);
    // Every call either stored an item or was counted as omitted: nothing vanishes silently.
    assert(calls[0] == diag.causes.count + diag.causes.omitted);
    assert(calls[1] == diag.whiles.count + diag.whiles.omitted);
    assert(calls[2] == diag.pairs.count + diag.pairs.omitted);
    assert(calls[3] == diag.fixes.count + diag.fixes.omitted);
    if (last_cause.len > constants.diag_field_bytes_max) {
        assert(std.mem.endsWith(u8, diag.last_cause().?, "..."));
    }
    check_renderings(&diag);
}

fn random_code(random: std.Random) codes.Code {
    const all = std.enums.values(codes.Code);
    return all[random.uintLessThan(usize, all.len)];
}

fn check_bounds(diag: *const Diag) void {
    assert(diag.causes.count <= constants.diag_causes_count_max);
    assert(diag.whiles.count <= constants.diag_whiles_count_max);
    assert(diag.pairs.count <= constants.diag_context_count_max);
    assert(diag.fixes.count <= constants.diag_fixes_count_max);
    // A full list is the only way anything is omitted.
    if (diag.causes.omitted > 0) assert(diag.causes.count == constants.diag_causes_count_max);
    if (diag.fixes.omitted > 0) assert(diag.fixes.count == constants.diag_fixes_count_max);
    for (diag.causes.slice()) |*text| check_field(text.slice());
    for (diag.whiles.slice()) |*text| check_field(text.slice());
    for (diag.pairs.slice()) |*pair| check_field(pair.value.slice());
    for (diag.fixes.slice()) |*item| {
        check_field(item.sentence.slice());
        for (item.command.slice()) |byte| assert(text_util.is_printable(byte));
        assert(item.command.len <= constants.diag_command_bytes_max);
    }
}

fn check_field(text: []const u8) void {
    assert(text.len > 0);
    assert(text.len <= constants.diag_field_bytes_max);
    for (text) |byte| assert(text_util.is_printable(byte));
}

fn check_renderings(diag: *const Diag) void {
    var buffer: [constants.output_bytes_max]u8 = undefined;
    var plain: [constants.output_bytes_max]u8 = undefined;
    var stripped: [constants.output_bytes_max]u8 = undefined;
    for ([_]render.Mode{ .text, .verbose }) |mode| {
        const output = render.render(diag, mode, false, &buffer);
        assert(text_output_is_clean(output));
        const found = find_diagnostics(output);
        assert(found.count == 1);
        assert(found.code.? == diag.code.?);
        @memcpy(plain[0..output.len], output);
        const coloured = render.render(diag, mode, true, &buffer);
        assert(std.mem.eql(u8, render.strip_colour(&stripped, coloured), plain[0..output.len]));
    }
    const json = render.render(diag, .json, false, &buffer);
    assert(json[json.len - 1] == '\n');
    assert(std.mem.count(u8, json, "\n") == 1);
    assert(test_util.json_is_valid(json[0 .. json.len - 1]) catch false);
    assert(find_diagnostics(json).count == 1);
}
