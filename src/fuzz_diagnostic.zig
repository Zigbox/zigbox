//! Fuzzer for `Diagnostic` and its JSON (src/diag/diagnostic.zig). Each iteration builds a random
//! diagnostic (a registered Zigbox code or a made-up product's, lists empty, full and past their
//! bounds, text with quotes, backslashes, control bytes and exactly-at-the-bound lengths), then:
//!
//!   1. writes it, parses it back and checks equality, the same bytes on a second write, and the
//!      same rendering in every mode;
//!   2. mutates the JSON (edits, truncation, duplication, splices) and parses that: the parser
//!      either refuses and leaves `out` empty, or accepts, and then the accepted value writes
//!      back to exactly the input, is valid JSON for the standard scanner (an independent reader),
//!      and renders in every mode and for every list of products without tripping an assertion;
//!   3. parses noise, and prefixes of the valid line.
//!
//! The property is the one parse_json documents: it accepts exactly what write_json writes.
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
/// the value writes back to the input, the standard scanner agrees it is JSON, and it renders.
fn check_parse(input: []const u8) void {
    var parsed: Diagnostic = undefined;
    if (diagnostic_mod.parse_json(&parsed, input)) {
        var buffer: [constants.output_bytes_max]u8 = undefined;
        const again = write_to(&buffer, &parsed);
        assert(std.mem.eql(u8, without_newline(input), without_newline(again)));
        assert(test_util.json_is_valid(without_newline(input)) catch false);
        render_everywhere(&parsed);
    } else |err| {
        assert(err == error.Malformed);
        assert(parsed.code.len == 0);
        assert(parsed.causes.count == 0);
        assert(parsed.fixes.count == 0);
    }
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

    var mutated: [input_bytes_max]u8 = undefined;
    for (0..8) |_| {
        @memcpy(mutated[0..json.len], json);
        check_parse(mutated[0..mutate(random, &mutated, json.len)]);
    }
    check_parse(json[0..random.uintAtMost(usize, json.len)]);
    var noise: [64]u8 = undefined;
    random.bytes(&noise);
    check_parse(noise[0..random.uintAtMost(usize, noise.len)]);
}
