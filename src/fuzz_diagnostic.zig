//! Fuzzer for `Diagnostic` and its JSON (src/diag/diagnostic.zig). Each iteration builds a random
//! diagnostic (a registered Zigbox code or a made-up product's, lists empty, full and past their
//! bounds, text with quotes, backslashes, control bytes and exactly-at-the-bound lengths), then:
//!
//!   1. writes it, parses it back and checks equality, the same bytes on a second write, and the
//!      same rendering in every mode;
//!   2. recomposes the line out of order, with unknown members of every JSON type injected (some
//!      nested past the depth limit, some past the byte limit) and sometimes a known member
//!      repeated, and checks the oracle: the parse equals the original, or it is `Malformed`
//!      exactly when the line has a repeated known member, an unknown value nested deeper than
//!      `diag_skip_depth_max`, more than `diag_skip_bytes_max` bytes of unknown members, or is
//!      longer than `diag_wire_bytes_max`;
//!   3. mutates the canonical and the recomposed line (edits, truncation, duplication) and parses
//!      that, and parses noise and prefixes of the valid line.
//!
//! For any input, the parser refuses and leaves `out` empty, or accepts, and then the value
//! writes a canonical line that parses back equal, the standard scanner agrees the input is JSON,
//! and it renders in every mode and for every list of products without tripping an assertion.
//! Driven by `fuzz.zig`; a failure is replayed by its seed.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const codes = @import("diag/codes.zig");
const diag_mod = @import("diag/diag.zig");
const diagnostic_mod = @import("diag/diagnostic.zig");
const product_mod = @import("diag/product.zig");
const render = @import("diag/render.zig");
const test_util = @import("test_util.zig");

const Diag = diag_mod.Diag;
const Diagnostic = diagnostic_mod.Diagnostic;
const Product = product_mod.Product;

const foreign_product: Product = .{
    .prefix = "ZC-",
    .command = "zcube",
    .bundle_hint = "zcube bundle --last",
    .report_url = "https://example.invalid/zigcube/issues/new",
    .docs_url_base = "https://example.invalid/zigcube/errors/",
};

const text_bytes_max = constants.diag_field_bytes_max + 8;
const input_bytes_max = constants.diag_wire_bytes_max + 64;
const interesting = "\"\\{}[],:0123456789 \x00\xff\x1bnull\n";

// ---- Building a random diagnostic ----------------------------------------------------------

/// Text of a random kind: words, random bytes, quotes and backslashes, exactly the bound of a
/// field, one over it, and nothing.
fn random_text(random: std.Random, storage: *[text_bytes_max]u8) []const u8 {
    const words = [_][]const u8{ "alpha", "web-1", "C:\\x", "say \"hi\"", "a  b", " lead", "~" };
    switch (random.uintLessThan(u8, 6)) {
        0 => return words[random.uintLessThan(usize, words.len)],
        1 => {
            const length = random.uintAtMost(u32, 40);
            random.bytes(storage[0..length]);
            return storage[0..length];
        },
        2 => {
            const length = random.uintAtMost(u32, 24);
            for (storage[0..length]) |*byte| byte.* = "\"\\ x"[random.uintLessThan(usize, 4)];
            return storage[0..length];
        },
        3 => {
            @memset(storage, 'x');
            return storage[0..constants.diag_field_bytes_max];
        },
        4 => {
            @memset(storage, 'y');
            return storage[0 .. constants.diag_field_bytes_max + random.uintAtMost(u32, 8)];
        },
        else => return "",
    }
}

fn fill_collector(random: std.Random, diag: *Diag) void {
    var storage: [text_bytes_max]u8 = undefined;
    diag.reset();
    const registry_index = random.uintLessThan(usize, codes.registry.len);
    diag.raise(codes.registry[registry_index].code);
    const extra = 3;
    for (0..random.uintAtMost(u32, constants.diag_causes_count_max + extra)) |_| {
        diag.cause("{s}", .{random_text(random, &storage)});
    }
    for (0..random.uintAtMost(u32, constants.diag_whiles_count_max + extra)) |_| {
        diag.while_("{s}", .{random_text(random, &storage)});
    }
    const keys = .{ "path", "node", "a", "zzzzzz", "uid" };
    for (0..random.uintAtMost(u32, constants.diag_context_count_max + extra)) |_| {
        const pick = random.uintLessThan(usize, keys.len);
        inline for (keys, 0..) |key, index| {
            if (index == pick) diag.context(key, "{s}", .{random_text(random, &storage)});
        }
    }
    for (0..random.uintAtMost(u32, constants.diag_fixes_count_max + extra)) |_| {
        const sentence = random_text(random, &storage);
        const command = if (random.boolean()) "sudo zbx doctor" else "";
        diag.fix(.{ .sentence = if (sentence.len == 0) "fix" else sentence, .command = command });
    }
    if (random.uintLessThan(u8, 4) == 0) diag.save_bundle("/state/zbx/bundles/b\"1\\");
}

/// The prefixes a made-up product might have, valid and not: what the parser does with a code
/// whose prefix it knows nothing about is part of the property.
fn random_code(random: std.Random, buffer: *[constants.diag_code_bytes]u8) []const u8 {
    const prefixes = [_][]const u8{ "ZC-", "QX-", "Q-", "ABC-" };
    const prefix = prefixes[random.uintLessThan(usize, prefixes.len)];
    const kinds = "EWB";
    const digits = random.uintLessThan(u32, 10_000);
    const kind = kinds[random.uintLessThan(usize, kinds.len)];
    const text = std.fmt.bufPrint(buffer, "{s}{c}{d:0>4}", .{ prefix, kind, digits }) catch
        unreachable; // At most four prefix bytes and five more: the buffer is nine.
    assert(diagnostic_mod.code_is_valid(text));
    return text;
}

fn build_diagnostic(random: std.Random, out: *Diagnostic) void {
    var collector: Diag = undefined;
    fill_collector(random, &collector);
    diagnostic_mod.from_diag(out, &collector);
    if (random.boolean()) return;
    var code_buffer: [constants.diag_code_bytes]u8 = undefined;
    const code = random_code(random, &code_buffer);
    out.code = .{};
    out.code.print("{s}", .{code});
    out.severity = random.enumValue(codes.Severity);
    out.blame = random.enumValue(codes.Blame);
    out.docs = .{};
    if (Product.find(&.{foreign_product}, code)) |owner| out.set_docs(owner);
}

// ---- Checking ------------------------------------------------------------------------------

fn write_to(buffer: []u8, diagnostic: *const Diagnostic) []const u8 {
    var writer = std.Io.Writer.fixed(buffer);
    // Cannot fail: the longest diagnostic as JSON is proved smaller than the buffer.
    diagnostic_mod.write_json(&writer, diagnostic) catch unreachable;
    return writer.buffered();
}

/// Renders in every mode, colour and product list; the renderer's own assertions are the check.
fn render_everywhere(diagnostic: *const Diagnostic) void {
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const lists = [_][]const Product{ &.{}, &.{Product.zbx}, &.{ foreign_product, Product.zbx } };
    for (lists) |products| {
        for ([_]render.Mode{ .text, .verbose, .json }) |mode| {
            for ([_]bool{ false, true }) |color| {
                const output = render.render_diagnostic(diagnostic, products, mode, color, &buffer);
                assert(output.len > 0);
                assert(output[output.len - 1] == '\n');
                assert(std.mem.indexOf(u8, output, diagnostic.code.slice()) != null);
            }
        }
    }
}

/// The text of a JSON line without its optional final newline.
fn without_newline(line: []const u8) []const u8 {
    if (line.len == 0) return line;
    if (line[line.len - 1] == '\n') return line[0 .. line.len - 1];
    return line;
}

/// Property of the parser on any input: it refuses and leaves `out` empty, or accepts, and then
/// the value writes a line that parses back equal (and, if `canonical`, is the input itself),
/// the standard scanner agrees the input is JSON, and the value renders.
fn check_parse(input: []const u8, canonical: bool) void {
    var parsed: Diagnostic = undefined;
    if (diagnostic_mod.parse_json(&parsed, input)) {
        var buffer: [constants.output_bytes_max]u8 = undefined;
        const again = write_to(&buffer, &parsed);
        if (canonical) assert(std.mem.eql(u8, without_newline(input), without_newline(again)));
        var reparsed: Diagnostic = undefined;
        diagnostic_mod.parse_json(&reparsed, again) catch unreachable; // Its own output.
        assert(parsed.equal(&reparsed));
        assert(test_util.json_is_valid(without_newline(input)) catch false);
        render_everywhere(&parsed);
    } else |err| {
        assert(err == error.Malformed);
        assert(parsed.code.len == 0);
        assert(parsed.causes.count == 0);
        assert(parsed.fixes.count == 0);
    }
}

const members_max = 16;
const compose_bytes_max = 2 * constants.diag_wire_bytes_max;

/// Splits a canonical line into its top-level members, by scanning strings and brackets: a
/// reading of the format that shares nothing with the parser.
fn split_members(json: []const u8, members: *[members_max][]const u8) u32 {
    assert(json[0] == '{');
    var count: u32 = 0;
    var depth: u32 = 0;
    var start: usize = 1;
    var in_string = false;
    var escaped = false;
    for (json, 0..) |byte, at| {
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (byte == '\\') {
                escaped = true;
            } else if (byte == '"') {
                in_string = false;
            }
            continue;
        }
        switch (byte) {
            '"' => in_string = true,
            '{', '[' => depth += 1,
            '}', ']' => {
                depth -= 1;
                if (depth == 0) {
                    members[count] = json[start..at];
                    return count + 1;
                }
            },
            ',' => if (depth == 1) {
                members[count] = json[start..at];
                count += 1;
                start = at + 1;
            },
            else => {},
        }
    }
    unreachable; // A canonical line closes its object.
}

// The writers below are fixed buffers that hold the largest line the fuzzer composes, so a write
// cannot fail; these are the only places that say so.

fn put(writer: *std.Io.Writer, bytes: []const u8) void {
    assert(writer.end + bytes.len <= writer.buffer.len);
    writer.writeAll(bytes) catch unreachable; // Cannot fail: the buffer holds the largest line.
}

fn put_byte(writer: *std.Io.Writer, byte: u8) void {
    assert(writer.end < writer.buffer.len);
    writer.writeByte(byte) catch unreachable; // Cannot fail: same.
}

fn put_run(writer: *std.Io.Writer, byte: u8, count: u32) void {
    assert(writer.end + count <= writer.buffer.len);
    writer.splatByteAll(byte, count) catch unreachable; // Cannot fail: same.
}

/// What the injected members add up to, for the oracle.
const Injected = struct { bytes: u32 = 0, depth_max: u32 = 0 };

/// One unknown member `"key":value` of a random JSON type, nested up to two levels past the
/// limit and sometimes long. Its depth and size go into `injected`.
fn write_unknown(random: std.Random, writer: *std.Io.Writer, injected: *Injected) void {
    const keys = [_][]const u8{ "v", "extra", "codes", "x-y", "a_long_unknown_member_name" };
    const start = writer.end;
    const key = keys[random.uintLessThan(usize, keys.len)];
    // Cannot fail: the storage holds three members of the largest kind.
    writer.print("\"{s}\":", .{key}) catch unreachable;
    var depth: u32 = 0;
    switch (random.uintLessThan(u8, 7)) {
        0 => put(writer, "\"s\\u00e9\\n\\/x\\\"\""),
        1 => put(writer, if (random.boolean()) "-1.5e+3" else "12"),
        2 => put(writer, "true"),
        3 => put(writer, "null"),
        4 => {
            const length = random.uintAtMost(u32, 2500);
            put_byte(writer, '"');
            put_run(writer, 'p', length);
            put_byte(writer, '"');
        },
        else => depth = write_nested(random, writer),
    }
    injected.depth_max = @max(injected.depth_max, depth);
    injected.bytes += @intCast(writer.end - start);
}

/// Nested containers `depth` deep around one scalar; returns the depth.
fn write_nested(random: std.Random, writer: *std.Io.Writer) u32 {
    var kinds: [constants.diag_skip_depth_max + 3]u8 = undefined;
    const depth = random.uintAtMost(u32, constants.diag_skip_depth_max + 2);
    for (kinds[0..depth]) |*kind| {
        kind.* = if (random.boolean()) '[' else '{';
        // Cannot fail: see `write_unknown`.
        if (kind.* == '[') put_byte(writer, '[');
        if (kind.* == '{') put(writer, "{\"k\":");
    }
    put(writer, if (random.boolean()) "1" else "\"s\"");
    var index = depth;
    while (index > 0) : (index -= 1) {
        put_byte(writer, if (kinds[index - 1] == '[') ']' else '}');
    }
    return depth;
}

/// Property: out of order, with unknown members injected and sometimes a known one repeated, the
/// line parses to `original`, or is Malformed exactly when it breaks a rule written here.
fn check_recomposed(random: std.Random, original: *const Diagnostic, canonical: []const u8) void {
    var members: [members_max][]const u8 = undefined;
    var count = split_members(canonical, &members);
    const known_count = count;
    var storage: [8192]u8 = undefined;
    var storage_writer = std.Io.Writer.fixed(&storage);
    var injected: Injected = .{};
    var malformed = false;
    var previous_end: usize = 0;
    for (0..random.uintAtMost(u8, 3)) |_| {
        write_unknown(random, &storage_writer, &injected);
        members[count] = storage[previous_end..storage_writer.end];
        previous_end = storage_writer.end;
        count += 1;
    }
    if (random.uintLessThan(u8, 8) == 0) {
        members[count] = members[random.uintLessThan(u32, known_count)];
        count += 1;
        malformed = true; // A known member twice.
    }
    random.shuffle([]const u8, members[0..count]);
    var line: [compose_bytes_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&line);
    put_byte(&writer, '{'); // The line buffer holds every member.
    for (members[0..count], 0..) |member, index| {
        if (index > 0) put_byte(&writer, ','); // Same.
        put(&writer, member); // Same.
    }
    put(&writer, if (random.boolean()) "}\n" else "}"); // Same.
    if (injected.depth_max > constants.diag_skip_depth_max) malformed = true;
    if (injected.bytes > constants.diag_skip_bytes_max) malformed = true;
    if (writer.end > constants.diag_wire_bytes_max) malformed = true;

    var parsed: Diagnostic = undefined;
    if (diagnostic_mod.parse_json(&parsed, writer.buffered())) {
        assert(!malformed);
        assert(original.equal(&parsed));
    } else |err| {
        assert(err == error.Malformed);
        assert(malformed);
    }
    check_parse(writer.buffered(), false);
}

fn mutate(random: std.Random, buffer: *[input_bytes_max]u8, length_in: usize) usize {
    var length = length_in;
    for (0..random.intRangeAtMost(u8, 1, 4)) |_| {
        switch (random.uintLessThan(u8, 6)) {
            0 => if (length > 0) {
                buffer[random.uintLessThan(usize, length)] = pick_interesting(random);
            },
            1 => if (length < input_bytes_max) {
                const at = random.uintAtMost(usize, length);
                @memmove(buffer[at + 1 .. length + 1], buffer[at..length]);
                buffer[at] = pick_interesting(random);
                length += 1;
            },
            2 => if (length > 0) {
                const at = random.uintLessThan(usize, length);
                @memmove(buffer[at .. length - 1], buffer[at + 1 .. length]);
                length -= 1;
            },
            3 => length = random.uintAtMost(usize, length),
            4 => if (length > 0 and length * 2 <= input_bytes_max) {
                @memcpy(buffer[length .. length * 2], buffer[0..length]);
                length *= 2;
            },
            else => if (length > 0) {
                buffer[random.uintLessThan(usize, length)] = random.int(u8);
            },
        }
    }
    assert(length <= input_bytes_max);
    return length;
}

fn pick_interesting(random: std.Random) u8 {
    return interesting[random.uintLessThan(usize, interesting.len)];
}

pub fn fuzz_diagnostic(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();

    var original: Diagnostic = undefined;
    build_diagnostic(random, &original);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const json = write_to(&buffer, &original);
    var parsed: Diagnostic = undefined;
    diagnostic_mod.parse_json(&parsed, json) catch unreachable; // The round trip is the property.
    assert(original.equal(&parsed));
    var second: [constants.output_bytes_max]u8 = undefined;
    assert(std.mem.eql(u8, json, write_to(&second, &parsed)));
    render_everywhere(&original);
    check_parse(json, true);

    for (0..4) |_| check_recomposed(random, &original, json);
    var mutated: [input_bytes_max]u8 = undefined;
    for (0..8) |_| {
        @memcpy(mutated[0..json.len], json);
        check_parse(mutated[0..mutate(random, &mutated, json.len)], false);
    }
    check_parse(json[0..random.uintAtMost(usize, json.len)], false);
    var noise: [64]u8 = undefined;
    random.bytes(&noise);
    check_parse(noise[0..random.uintAtMost(usize, noise.len)], false);
}
