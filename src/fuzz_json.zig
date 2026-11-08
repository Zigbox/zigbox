//! The `json` fuzzer: `zig build fuzz -- json`. The canonical JSON writer and reader
//! (`src/trust/json.zig`) sit under every signed statement, and the reader takes bytes from
//! files and registries anyone could have written. Each iteration writes a random valid value,
//! reads it back, then damages the text and reads that, and reads random bytes too.
//!
//! Properties, every iteration:
//!   1. Round trip: what the writer wrote reads to its end, and writing the tokens it read
//!      gives the same bytes (so the reader's tokens are exactly what was written).
//!   2. Canonical: damaged or random bytes never crash the reader. They are accepted (read to
//!      `.end`) only if re-writing their tokens gives exactly those bytes.
//!   3. Bounds: the reader's depth never passes `json_depth_max`, a string token never exceeds
//!      the buffer it was given, each token consumes at least one byte, and the position never
//!      passes the input. The writer refuses a container past the depth bound, and a buffer too
//!      short for a value, without writing outside the buffer.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const json = @import("trust/json.zig");

const text_bytes_max: u32 = 8192;
const string_bytes_max: u32 = 96;
const steps_max: u32 = 48;
const scratch_bytes: u32 = 256;

var text_buffer: [text_bytes_max]u8 = undefined;
var again_buffer: [text_bytes_max + 16]u8 = undefined;
var damaged_buffer: [text_bytes_max + 16]u8 = undefined;
var string_buffer: [string_bytes_max]u8 = undefined;
var scratch: [scratch_bytes]u8 = undefined;

/// A random valid UTF-8 string, biased toward the bytes the form escapes and toward multi-byte
/// characters.
fn random_string(random: std.Random) []const u8 {
    var length: usize = 0;
    const count = random.uintLessThan(u32, 25);
    var index: u32 = 0;
    while (index < count) : (index += 1) {
        const kind = random.uintLessThan(u32, 20);
        var bytes: [4]u8 = undefined;
        var size: usize = 1;
        if (kind < 11) {
            bytes[0] = random.intRangeAtMost(u8, 0x20, 0x7e);
        } else if (kind < 15) {
            bytes[0] = random.uintLessThan(u8, 0x20);
        } else if (kind < 17) {
            bytes[0] = if (random.boolean()) '"' else '\\';
        } else {
            const point = random_scalar(random);
            size = std.unicode.utf8Encode(point, &bytes) catch unreachable; // A valid scalar.
        }
        assert(length + size <= string_buffer.len);
        @memcpy(string_buffer[length..][0..size], bytes[0..size]);
        length += size;
    }
    assert(std.unicode.utf8ValidateSlice(string_buffer[0..length]));
    return string_buffer[0..length];
}

fn random_scalar(random: std.Random) u21 {
    while (true) {
        const point = random.intRangeAtMost(u21, 0x80, 0x10ffff);
        if (point < 0xd800 or point > 0xdfff) return point;
    }
}

fn expect_ok(result: json.WriteError!void) void {
    result catch |err| std.debug.panic("writer refused a valid step: {s}", .{@errorName(err)});
}

/// One random scalar value at the writer's current position.
fn write_scalar(random: std.Random, writer: *json.Writer) void {
    switch (random.uintLessThan(u32, 5)) {
        0 => expect_ok(writer.string(random_string(random))),
        1 => expect_ok(writer.unsigned(random.int(u64) >> random.uintLessThan(u6, 63))),
        2 => expect_ok(writer.integer(@as(i64, @bitCast(random.int(u64))) >>
            random.uintLessThan(u6, 63))),
        3 => expect_ok(writer.boolean(random.boolean())),
        else => expect_ok(writer.unsigned(random.uintLessThan(u64, 3))),
    }
}

/// One random step: open a container, write a scalar (after a key, in an object), or close.
fn write_step(random: std.Random, writer: *json.Writer, remaining: u32) void {
    if (writer.depth == 0) return write_value(random, writer, 80);
    const frame = &writer.frames[writer.depth - 1];
    if (frame.kind == .object) {
        if (frame.key_pending) return write_value(random, writer, 40);
        if (frame.count > 0) {
            if (remaining < writer.depth or random.uintLessThan(u32, 5) == 0) {
                return expect_ok(writer.end_object());
            }
        }
        return expect_ok(writer.key(random_string(random)));
    }
    if (remaining < writer.depth or random.uintLessThan(u32, 6) == 0) {
        return expect_ok(writer.end_array());
    }
    write_value(random, writer, 40);
}

/// A value: a container with probability `percent` (while depth allows), else a scalar.
fn write_value(random: std.Random, writer: *json.Writer, percent: u32) void {
    const room = writer.depth < constants.json_depth_max;
    if (room and random.uintLessThan(u32, 100) < percent) {
        if (random.boolean()) return expect_ok(writer.begin_object());
        return expect_ok(writer.begin_array());
    }
    write_scalar(random, writer);
}

/// Writes a random valid value into `text_buffer` and returns its bytes.
fn generate(random: std.Random) []const u8 {
    var writer = json.Writer.init(&text_buffer);
    var step: u32 = 0;
    while (step < steps_max) : (step += 1) {
        write_step(random, &writer, steps_max - step);
        if (writer.depth == 0) break;
    }
    while (writer.depth > 0) {
        // Close what is open; an object with a pending key takes a value first.
        const frame = &writer.frames[writer.depth - 1];
        if (frame.kind == .object) {
            if (frame.key_pending) write_scalar(random, &writer);
            expect_ok(writer.end_object());
        } else {
            expect_ok(writer.end_array());
        }
    }
    return writer.finish();
}

/// Reads `text` to its end, writing each token to `out`. Returns false if the reader refused;
/// asserts the bounds either way.
fn rewrite(text: []const u8, scratch_size: usize, out: *json.Writer) bool {
    var reader = json.Reader.init(text);
    var tokens: usize = 0;
    while (true) {
        const before = reader.position;
        const token = reader.next(scratch[0..scratch_size]) catch return false;
        assert(reader.depth <= constants.json_depth_max);
        assert(reader.position <= text.len);
        tokens += 1;
        switch (token) {
            .end => return true,
            .object_begin => expect_ok(out.begin_object()),
            .object_end => expect_ok(out.end_object()),
            .array_begin => expect_ok(out.begin_array()),
            .array_end => expect_ok(out.end_array()),
            .key => |name| {
                assert(name.len <= scratch_size);
                expect_ok(out.key(name));
            },
            .string => |value| {
                assert(value.len <= scratch_size);
                expect_ok(out.string(value));
            },
            .unsigned => |value| expect_ok(out.unsigned(value)),
            .negative => |value| {
                assert(value < 0);
                expect_ok(out.integer(value));
            },
            .boolean => |value| expect_ok(out.boolean(value)),
        }
        assert(reader.position > before); // Progress: every token consumes a byte.
        assert(tokens <= text.len + 1);
    }
}

/// Property 2 for any bytes. Returns whether they were accepted.
fn check_canonical(text: []const u8, scratch_size: usize) bool {
    assert(text.len <= text_bytes_max + 16);
    var out = json.Writer.init(&again_buffer);
    if (!rewrite(text, scratch_size, &out)) return false;
    assert(out.depth == 0);
    assert(std.mem.eql(u8, text, out.finish()));
    return true;
}

fn pick(random: std.Random, alphabet: []const u8) u8 {
    return alphabet[random.uintLessThan(usize, alphabet.len)];
}

fn flip(random: std.Random, length: usize) void {
    const at = random.uintLessThan(usize, length);
    damaged_buffer[at] ^= random.intRangeAtMost(u8, 1, 255);
}

/// Opens a gap at `at` in the first `length` bytes.
fn shift_up(at: usize, length: usize) void {
    const moved = damaged_buffer[at..length];
    std.mem.copyBackwards(u8, damaged_buffer[at + 1 ..][0..moved.len], moved);
}

/// Removes the byte at `at` from the first `length` bytes.
fn shift_down(at: usize, length: usize) void {
    const rest = damaged_buffer[at + 1 .. length];
    std.mem.copyForwards(u8, damaged_buffer[at..][0..rest.len], rest);
}

fn damage(random: std.Random, text: []const u8) []const u8 {
    assert(text.len > 0);
    assert(text.len <= text_bytes_max);
    @memcpy(damaged_buffer[0..text.len], text);
    var length = text.len;
    const alphabet = "{}[]\":,\\ 0123456789-+.eEtrufalsn\n\t\x00\x1f\x7f\xc3\xa9\xff";
    switch (random.uintLessThan(u32, 6)) {
        0 => length = random.uintLessThan(usize, length), // Cut.
        1 => flip(random, length),
        2 => damaged_buffer[random.uintLessThan(usize, length)] = pick(random, alphabet),
        3 => { // Insert a byte.
            const at = random.uintLessThan(usize, length + 1);
            shift_up(at, length);
            damaged_buffer[at] = pick(random, alphabet);
            length += 1;
        },
        4 => { // Delete a byte.
            const at = random.uintLessThan(usize, length);
            shift_down(at, length);
            length -= 1;
        },
        else => { // Append a byte.
            damaged_buffer[length] = pick(random, alphabet);
            length += 1;
        },
    }
    return damaged_buffer[0..length];
}

/// Bytes drawn from the characters that matter to the grammar, and a few that do not.
fn random_bytes(random: std.Random) []const u8 {
    const alphabet = "{}[]\"\":,,\\\\ 0123456789-ntruefalsu\n\t\x00\xc3\xa9\xff";
    const length = random.uintLessThan(usize, 48);
    for (damaged_buffer[0..length]) |*byte| {
        byte.* = alphabet[random.uintLessThan(usize, alphabet.len)];
    }
    return damaged_buffer[0..length];
}

/// Property 3 for the depth bound: containers nested `levels` deep.
fn check_depth(random: std.Random) void {
    const levels = random.intRangeAtMost(u32, 1, constants.json_depth_max + 4);
    var writer = json.Writer.init(&text_buffer);
    var opened: u32 = 0;
    while (opened < levels) : (opened += 1) {
        // An object needs a key before its next value.
        if (writer.depth > 0) {
            if (writer.frames[writer.depth - 1].kind == .object) expect_ok(writer.key("k"));
        }
        const before = writer.depth;
        const result = if (random.boolean()) writer.begin_array() else writer.begin_object();
        if (before == constants.json_depth_max) {
            assert(result == error.TooDeep);
            break;
        }
        expect_ok(result);
    }
    assert(writer.depth <= constants.json_depth_max);
    var reader = json.Reader.init(text_buffer[0..writer.length]);
    var tokens: u32 = 0;
    while (reader.next(&scratch)) |token| {
        assert(token != .end);
        tokens += 1;
        assert(reader.depth <= constants.json_depth_max);
    } else |err| {
        assert(err != error.TooLong); // The scratch buffer is large enough here.
    }
    assert(tokens <= writer.length);
}

/// The reader refuses nesting one past `json_depth_max` (raw text, not the writer's).
fn check_reader_depth() void {
    const levels = constants.json_depth_max + 1;
    const opening: [levels]u8 = @splat('[');
    var reader = json.Reader.init(&opening);
    var opened: u32 = 0;
    while (reader.next(&scratch)) |token| {
        assert(token == .array_begin);
        opened += 1;
    } else |err| assert(err == error.TooDeep);
    assert(opened == constants.json_depth_max);
}

/// A buffer shorter than the value refuses with Overflow and writes nothing past itself.
fn check_overflow(random: std.Random, text: []const u8) void {
    if (text.len < 2) return;
    const size = random.uintLessThan(usize, text.len);
    var small: [text_bytes_max + 1]u8 = undefined;
    @memset(&small, 0xa5);
    var out = json.Writer.init(small[0..size]);
    var reader = json.Reader.init(text);
    var overflowed = false;
    while (!overflowed) {
        const token = reader.next(&scratch) catch unreachable; // `text` is valid.
        const result = switch (token) {
            .end => break,
            .object_begin => out.begin_object(),
            .object_end => out.end_object(),
            .array_begin => out.begin_array(),
            .array_end => out.end_array(),
            .key => |name| out.key(name),
            .string => |value| out.string(value),
            .unsigned => |value| out.unsigned(value),
            .negative => |value| out.integer(value),
            .boolean => |value| out.boolean(value),
        };
        if (result) |_| {} else |err| {
            assert(err == error.Overflow);
            overflowed = true;
        }
    }
    assert(overflowed); // The value is longer than the buffer.
    for (small[size..]) |canary| assert(canary == 0xa5);
}

pub fn fuzz_json(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    const text = generate(random);
    assert(check_canonical(text, scratch_bytes)); // Property 1.
    check_overflow(random, text);
    var round: u32 = 0;
    while (round < 4) : (round += 1) {
        const size = random.intRangeAtMost(usize, 1, scratch_bytes);
        _ = check_canonical(damage(random, text), size); // Property 2.
        _ = check_canonical(random_bytes(random), size);
    }
    check_depth(random);
    check_reader_depth();
}

test "the fuzzer's round trip holds on a fixed seed" {
    // Goal: the fuzzer's own property 1 runs under `zig build test`. Method: a few seeds.
    var seed: u64 = 1;
    while (seed <= 64) : (seed += 1) fuzz_json(seed);
}
