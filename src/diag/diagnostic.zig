//! `Diagnostic`: a finished diagnostic as plain data (DIAGNOSTICS.md, "Same model everywhere").
//!
//! A `Diag` is the collector of one product: its code is a tag of that product's registry, so
//! it cannot name another product's code. A `Diagnostic` is what the collector produces, with the
//! code as text. It is what travels (node, API, CLI) as JSON, and what the renderer renders, so
//! a second product's diagnostics and Zigbox's are one type, one renderer and one wire form.
//!
//!   - `from_diag` copies a collector.
//!   - `write_json` writes the one-line JSON object that `zbx --output json` has always written.
//!   - `parse_json` reads it back. It accepts exactly what `write_json` writes, and nothing
//!     else: a field over its bound, an unknown severity or blame, a list over its capacity or a
//!     key out of place is `error.Malformed`, never a truncation. So whatever it accepts,
//!     `write_json` writes back byte for byte (the fuzzer checks that), and the renderer's
//!     assertions (no empty text, printable ASCII, counts within the bounds) hold for it.
//!
//! The wire form does not carry `command_missing` (it is not in today's JSON, which must not
//! change): a parsed diagnostic has it false. It only matters for the exit code of a container
//! run, which the process that ran the container decides before the diagnostic leaves it.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const codes = @import("codes.zig");
const diag_mod = @import("diag.zig");
const product_mod = @import("product.zig");
const text_util = @import("../text.zig");

const Diag = diag_mod.Diag;
const Product = product_mod.Product;

pub const Code = text_util.Bounded(constants.diag_code_bytes);
pub const Summary = text_util.Bounded(constants.diag_summary_bytes_max);
pub const Docs = text_util.Bounded(constants.docs_url_bytes_max);

pub const Diagnostic = struct {
    /// "ZBX-E0501", "ZC-E0201": text, not an enum, so any product's codes fit.
    code: Code,
    severity: codes.Severity,
    blame: codes.Blame,
    summary: Summary,
    causes: diag_mod.Causes,
    whiles: diag_mod.Whiles,
    pairs: diag_mod.Pairs,
    fixes: diag_mod.Fixes,
    /// The path of the bundle written for a bug; empty for none.
    saved: diag_mod.Saved,
    /// The code's page, as the product that raised it knows it; empty for none (a product whose
    /// docs this program does not know). `set_docs` fills it.
    docs: Docs,
    /// As in `Diag`. Not on the wire.
    command_missing: bool,

    /// Initialises in place: the struct is several kilobytes. Leaves a valid but empty value;
    /// the caller fills the code, the severity, the blame and the summary.
    pub fn reset(diagnostic: *Diagnostic) void {
        diagnostic.code = .{};
        diagnostic.severity = .@"error";
        diagnostic.blame = .user;
        diagnostic.summary = .{};
        diagnostic.causes = .{};
        diagnostic.whiles = .{};
        diagnostic.pairs = .{};
        diagnostic.fixes = .{};
        diagnostic.saved = .{};
        diagnostic.docs = .{};
        diagnostic.command_missing = false;
        assert(diagnostic.code.len == 0);
        assert(diagnostic.causes.count == 0);
    }

    /// Points `docs` at the code's page under `product`'s base. The code must start with the
    /// product's prefix.
    pub fn set_docs(diagnostic: *Diagnostic, product: *const Product) void {
        assert(code_is_valid(diagnostic.code.slice()));
        product.validate();
        var url: [constants.docs_url_bytes_max]u8 = undefined;
        diagnostic.docs = .{};
        diagnostic.docs.print("{s}", .{product.docs_url(&url, diagnostic.code.slice())});
        assert(diagnostic.docs.len > 0);
        assert(!diagnostic.docs.truncated);
    }

    /// The process exit code in the standard scope: the blame decides, as for a `Diag`. A
    /// container run needs `command_missing` and the code's registry, which only its product has.
    pub fn exit_code(diagnostic: *const Diagnostic) u8 {
        assert(diagnostic.code.len > 0);
        return codes.exit_code(diagnostic.blame);
    }

    /// The newest cause: the one default output shows. Null if none was added.
    pub fn last_cause(diagnostic: *const Diagnostic) ?[]const u8 {
        assert(diagnostic.causes.count <= constants.diag_causes_count_max);
        if (diagnostic.causes.count == 0) return null;
        const text = diagnostic.causes.items[diagnostic.causes.count - 1].slice();
        assert(text.len > 0);
        return text;
    }

    /// True if two diagnostics say the same, field by field. Bytes past a text's length are not
    /// compared (they are undefined). For tests, and for a product's own.
    pub fn equal(first: *const Diagnostic, second: *const Diagnostic) bool {
        assert(first.code.len <= constants.diag_code_bytes);
        assert(second.code.len <= constants.diag_code_bytes);
        if (!std.mem.eql(u8, first.code.slice(), second.code.slice())) return false;
        if (first.severity != second.severity) return false;
        if (first.blame != second.blame) return false;
        if (!std.mem.eql(u8, first.summary.slice(), second.summary.slice())) return false;
        if (!std.mem.eql(u8, first.saved.slice(), second.saved.slice())) return false;
        if (!std.mem.eql(u8, first.docs.slice(), second.docs.slice())) return false;
        if (first.command_missing != second.command_missing) return false;
        if (!lists_equal(&first.causes, &second.causes)) return false;
        if (!lists_equal(&first.whiles, &second.whiles)) return false;
        if (!lists_equal(&first.pairs, &second.pairs)) return false;
        return lists_equal(&first.fixes, &second.fixes);
    }
};

fn lists_equal(first: anytype, second: anytype) bool {
    assert(first.count <= first.items.len);
    assert(second.count <= second.items.len);
    if (first.count != second.count) return false;
    if (first.omitted != second.omitted) return false;
    for (first.slice(), second.slice()) |*left, *right| {
        if (!item_equal(left, right)) return false;
    }
    return true;
}

fn item_equal(first: anytype, second: anytype) bool {
    const Item = @TypeOf(first.*);
    if (Item == diag_mod.Text) return std.mem.eql(u8, first.slice(), second.slice());
    if (Item == diag_mod.Pair) {
        if (!std.mem.eql(u8, first.key_slice(), second.key_slice())) return false;
        return std.mem.eql(u8, first.value.slice(), second.value.slice());
    }
    comptime assert(Item == diag_mod.Fix);
    if (!std.mem.eql(u8, first.sentence.slice(), second.sentence.slice())) return false;
    return std.mem.eql(u8, first.command.slice(), second.command.slice());
}

/// Copies a finished collector. Initialises `out` in place (it is several kilobytes). The docs
/// are Zigbox's: a product other than Zigbox calls `set_docs` with its own after filling `out`.
pub fn from_diag(out: *Diagnostic, source: *const Diag) void {
    assert(source.code != null);
    const entry = source.entry();
    out.reset();
    out.code.print("{s}", .{codes.full_name(entry.code)});
    out.severity = entry.severity;
    out.blame = entry.blame;
    out.summary.print("{s}", .{entry.summary});
    assert(!out.summary.truncated); // The registry's comptime check bounds every summary.
    copy_list(&out.causes, &source.causes);
    copy_list(&out.whiles, &source.whiles);
    copy_list(&out.pairs, &source.pairs);
    copy_list(&out.fixes, &source.fixes);
    out.saved.print("{s}", .{source.saved.slice()});
    out.command_missing = source.command_missing;
    out.set_docs(&Product.zbx);
    assert(out.code.len == constants.diag_code_bytes);
}

/// Copies the used items only, so no byte that was never written is read.
fn copy_list(target: anytype, source: anytype) void {
    assert(source.count <= source.items.len);
    target.* = .{ .count = source.count, .omitted = source.omitted };
    @memcpy(target.items[0..source.count], source.items[0..source.count]);
    assert(target.slice().len == source.slice().len);
}

/// Whether `text` has the shape of a code: a prefix of capital letters and a dash (at most
/// `product_prefix_bytes_max`), a capital letter and four digits.
pub fn code_is_valid(text: []const u8) bool {
    const tag_bytes = 5;
    if (text.len < 2 + tag_bytes) return false;
    if (text.len > constants.diag_code_bytes) return false;
    const prefix = text[0 .. text.len - tag_bytes];
    assert(prefix.len <= constants.product_prefix_bytes_max);
    if (prefix[prefix.len - 1] != '-') return false;
    for (prefix[0 .. prefix.len - 1]) |byte| {
        if (!std.ascii.isUpper(byte)) return false;
    }
    const tag = text[text.len - tag_bytes ..];
    if (!std.ascii.isUpper(tag[0])) return false;
    for (tag[1..]) |byte| {
        if (!std.ascii.isDigit(byte)) return false;
    }
    return true;
}

fn key_is_valid(key: []const u8) bool {
    assert(key.len <= constants.diag_key_bytes_max);
    if (key.len == 0) return false;
    for (key) |byte| {
        if (!std.ascii.isLower(byte)) return false;
    }
    for (diag_mod.reserved_keys) |word| {
        if (std.mem.eql(u8, key, word)) return false;
    }
    return true;
}

// ---- Writing -------------------------------------------------------------------------------

const Writer = std.Io.Writer;

fn write_string(writer: *Writer, text: []const u8) Writer.Error!void {
    try writer.writeByte('"');
    for (text) |byte| {
        assert(byte >= 0x20); // Free text is printable ASCII only: Diag and parse_json see to it.
        assert(byte <= 0x7e);
        if (byte == '"' or byte == '\\') try writer.writeByte('\\');
        try writer.writeByte(byte);
    }
    try writer.writeByte('"');
}

fn write_key(writer: *Writer, key: []const u8) Writer.Error!void {
    assert(key.len > 0);
    assert(std.mem.indexOfAny(u8, key, "\"\\") == null); // Keys are ours and need no escape.
    try write_string(writer, key);
    try writer.writeByte(':');
}

fn write_texts(writer: *Writer, key: []const u8, list: anytype) Writer.Error!void {
    assert(list.count <= list.items.len);
    try write_key(writer, key);
    try writer.writeByte('[');
    for (list.slice(), 0..) |*text, index| {
        if (index > 0) try writer.writeByte(',');
        try write_string(writer, text.slice());
    }
    try writer.writeAll("],");
}

fn write_context(writer: *Writer, diagnostic: *const Diagnostic) Writer.Error!void {
    assert(diagnostic.pairs.count <= constants.diag_context_count_max);
    try write_key(writer, "context");
    try writer.writeByte('{');
    for (diagnostic.pairs.slice(), 0..) |*pair, index| {
        if (index > 0) try writer.writeByte(',');
        try write_key(writer, pair.key_slice());
        try write_string(writer, pair.value.slice());
    }
    try writer.writeAll("},");
}

fn write_fixes(writer: *Writer, diagnostic: *const Diagnostic) Writer.Error!void {
    assert(diagnostic.fixes.count <= constants.diag_fixes_count_max);
    try write_key(writer, "fixes");
    try writer.writeByte('[');
    for (diagnostic.fixes.slice(), 0..) |*item, index| {
        if (index > 0) try writer.writeByte(',');
        try writer.writeByte('{');
        try write_key(writer, "sentence");
        try write_string(writer, item.sentence.slice());
        try writer.writeByte(',');
        try write_key(writer, "command");
        if (item.command.len > 0) {
            try write_string(writer, item.command.slice());
        } else {
            try writer.writeAll("null");
        }
        try writer.writeByte('}');
    }
    try writer.writeAll("],");
}

/// One JSON object on one line, ending in a newline. The standard's field table, plus `while`
/// (the standard's verbose rendering shows those lines but its table has no field for them) and
/// `omitted`, the counts past the bounds.
pub fn write_json(writer: *Writer, diagnostic: *const Diagnostic) Writer.Error!void {
    assert(diagnostic.code.len > 0);
    assert(diagnostic.summary.len > 0);
    try writer.writeByte('{');
    try write_key(writer, "code");
    try write_string(writer, diagnostic.code.slice());
    try writer.writeByte(',');
    try write_key(writer, "severity");
    try write_string(writer, @tagName(diagnostic.severity));
    try writer.writeByte(',');
    try write_key(writer, "blame");
    try write_string(writer, @tagName(diagnostic.blame));
    try writer.writeByte(',');
    try write_key(writer, "summary");
    try write_string(writer, diagnostic.summary.slice());
    try writer.writeByte(',');
    try write_texts(writer, "causes", &diagnostic.causes);
    try write_texts(writer, "while", &diagnostic.whiles);
    try write_context(writer, diagnostic);
    try write_fixes(writer, diagnostic);
    if (diagnostic.saved.len > 0) {
        try write_key(writer, "saved");
        try write_string(writer, diagnostic.saved.slice());
        try writer.writeByte(',');
    }
    if (diagnostic.docs.len > 0) {
        try write_key(writer, "docs");
        try write_string(writer, diagnostic.docs.slice());
        try writer.writeByte(',');
    }
    const omitted = "\"omitted\":{{\"causes\":{d},\"while\":{d}," ++
        "\"context\":{d},\"fixes\":{d}}}}}\n";
    try writer.print(omitted, .{
        diagnostic.causes.omitted, diagnostic.whiles.omitted,
        diagnostic.pairs.omitted,  diagnostic.fixes.omitted,
    });
}

// ---- Parsing -------------------------------------------------------------------------------

const Malformed = error{Malformed};

/// A position in the input. Every operation either consumes input or fails, so every loop over a
/// cursor ends within the input's length, which `parse_json` has bounded.
const Cursor = struct {
    bytes: []const u8,
    at: u32,

    fn next(cursor: *Cursor) ?u8 {
        assert(cursor.at <= cursor.bytes.len);
        if (cursor.at == cursor.bytes.len) return null;
        const byte = cursor.bytes[cursor.at];
        cursor.at += 1;
        return byte;
    }

    /// Consumes `byte` if it is next.
    fn accept(cursor: *Cursor, byte: u8) bool {
        assert(cursor.at <= cursor.bytes.len);
        if (cursor.at == cursor.bytes.len) return false;
        if (cursor.bytes[cursor.at] != byte) return false;
        cursor.at += 1;
        return true;
    }

    fn take(cursor: *Cursor, byte: u8) Malformed!void {
        assert(cursor.at <= cursor.bytes.len);
        if (!cursor.accept(byte)) return error.Malformed;
        assert(cursor.at > 0);
    }

    /// Consumes `literal` if it is next, whole.
    fn accept_literal(cursor: *Cursor, literal: []const u8) bool {
        assert(literal.len > 0);
        assert(cursor.at <= cursor.bytes.len);
        const rest = cursor.bytes[cursor.at..];
        if (!std.mem.startsWith(u8, rest, literal)) return false;
        cursor.at += @intCast(literal.len);
        return true;
    }

    fn take_literal(cursor: *Cursor, literal: []const u8) Malformed!void {
        assert(literal.len > 0);
        if (!cursor.accept_literal(literal)) return error.Malformed;
        assert(cursor.at >= literal.len);
    }
};

/// Reads a JSON string into `storage` and returns its length. Only what `write_string` writes:
/// printable ASCII, with `\"` and `\\` the only escapes. Longer than `storage` is Malformed.
fn read_string(cursor: *Cursor, storage: []u8) Malformed!u32 {
    assert(storage.len > 0);
    assert(storage.len <= constants.diag_wire_bytes_max);
    try cursor.take('"');
    var length: u32 = 0;
    while (cursor.next()) |byte| {
        if (byte == '"') return length;
        var value = byte;
        if (byte == '\\') {
            value = cursor.next() orelse return error.Malformed;
            if (value != '"') {
                if (value != '\\') return error.Malformed;
            }
        }
        if (!text_util.is_printable(value)) return error.Malformed;
        if (length == storage.len) return error.Malformed;
        storage[length] = value;
        length += 1;
    }
    return error.Malformed; // The input ended inside the string.
}

/// Reads a non-empty string into a bounded text, which is never empty anywhere else either.
fn read_text(cursor: *Cursor, field: anytype) Malformed!void {
    const length = try read_string(cursor, &field.bytes);
    assert(length <= field.bytes.len);
    if (length == 0) return error.Malformed;
    field.len = length;
    field.truncated = false;
    assert(field.len <= field.bytes.len);
}

fn read_enum(cursor: *Cursor, comptime Enum: type) Malformed!Enum {
    var storage: [16]u8 = undefined;
    const length = try read_string(cursor, &storage);
    assert(length <= storage.len);
    const found = std.meta.stringToEnum(Enum, storage[0..length]) orelse return error.Malformed;
    assert(std.mem.eql(u8, @tagName(found), storage[0..length]));
    return found;
}

/// A count as written by `{d}`: digits, no leading zero, within what the renderer can show.
fn read_count(cursor: *Cursor) Malformed!u32 {
    const start = cursor.at;
    var value: u32 = 0;
    while (cursor.at < cursor.bytes.len) {
        const byte = cursor.bytes[cursor.at];
        if (!std.ascii.isDigit(byte)) break;
        if (cursor.at - start == 5) return error.Malformed; // More digits than a u16 has.
        value = value * 10 + (byte - '0');
        cursor.at += 1;
    }
    const digits = cursor.at - start;
    assert(digits <= 5);
    if (digits == 0) return error.Malformed;
    if (digits > 1) {
        if (cursor.bytes[start] == '0') return error.Malformed;
    }
    if (value > std.math.maxInt(u16)) return error.Malformed;
    assert(value < 100_000);
    return value;
}

fn parse_texts(cursor: *Cursor, list: anytype) Malformed!void {
    const capacity: u32 = @intCast(list.items.len);
    assert(list.count == 0);
    assert(capacity > 0);
    try cursor.take('[');
    if (cursor.accept(']')) return;
    while (list.count < capacity) {
        try read_text(cursor, &list.items[list.count]);
        list.count += 1;
        if (cursor.accept(']')) return;
        try cursor.take(',');
    }
    assert(list.count == capacity);
    return error.Malformed; // Another item after a full list.
}

fn parse_pair(cursor: *Cursor, pair: *diag_mod.Pair) Malformed!void {
    pair.key = @splat(0);
    const length = try read_string(cursor, &pair.key);
    assert(length <= pair.key.len);
    if (!key_is_valid(pair.key[0..length])) return error.Malformed;
    pair.key_len = @intCast(length);
    try cursor.take(':');
    pair.value = .{};
    try read_text(cursor, &pair.value);
    assert(pair.key_slice().len == length);
}

fn parse_context(cursor: *Cursor, list: *diag_mod.Pairs) Malformed!void {
    assert(list.count == 0);
    assert(list.omitted == 0);
    try cursor.take('{');
    if (cursor.accept('}')) return;
    while (list.count < constants.diag_context_count_max) {
        try parse_pair(cursor, &list.items[list.count]);
        list.count += 1;
        if (cursor.accept('}')) return;
        try cursor.take(',');
    }
    assert(list.count == constants.diag_context_count_max);
    return error.Malformed;
}

fn parse_fix(cursor: *Cursor, item: *diag_mod.Fix) Malformed!void {
    item.sentence = .{};
    item.command = .{};
    try cursor.take_literal("{\"sentence\":");
    try read_text(cursor, &item.sentence);
    try cursor.take_literal(",\"command\":");
    if (!cursor.accept_literal("null")) try read_text(cursor, &item.command);
    try cursor.take('}');
    assert(item.sentence.len > 0);
    assert(item.command.len <= constants.diag_command_bytes_max);
}

fn parse_fixes(cursor: *Cursor, list: *diag_mod.Fixes) Malformed!void {
    assert(list.count == 0);
    assert(list.omitted == 0);
    try cursor.take('[');
    if (cursor.accept(']')) return;
    while (list.count < constants.diag_fixes_count_max) {
        try parse_fix(cursor, &list.items[list.count]);
        list.count += 1;
        if (cursor.accept(']')) return;
        try cursor.take(',');
    }
    assert(list.count == constants.diag_fixes_count_max);
    return error.Malformed;
}

/// A list that has dropped items is full: the collector drops only past its capacity.
fn set_omitted(list: anytype, omitted: u32) Malformed!void {
    assert(list.omitted == 0);
    assert(list.count <= list.items.len);
    if (omitted > 0) {
        if (list.count != list.items.len) return error.Malformed;
    }
    list.omitted = omitted;
    if (list.omitted > 0) assert(list.slice().len == list.items.len);
}

fn parse_omitted(cursor: *Cursor, out: *Diagnostic) Malformed!void {
    assert(out.causes.omitted == 0);
    assert(out.fixes.omitted == 0);
    try cursor.take_literal("\"omitted\":{\"causes\":");
    try set_omitted(&out.causes, try read_count(cursor));
    try cursor.take_literal(",\"while\":");
    try set_omitted(&out.whiles, try read_count(cursor));
    try cursor.take_literal(",\"context\":");
    try set_omitted(&out.pairs, try read_count(cursor));
    try cursor.take_literal(",\"fixes\":");
    try set_omitted(&out.fixes, try read_count(cursor));
    try cursor.take_literal("}}");
    assert(out.pairs.omitted <= std.math.maxInt(u16));
}

fn parse_head(cursor: *Cursor, out: *Diagnostic) Malformed!void {
    assert(cursor.at == 0);
    assert(out.code.len == 0);
    try cursor.take_literal("{\"code\":");
    try read_text(cursor, &out.code);
    if (!code_is_valid(out.code.slice())) return error.Malformed;
    try cursor.take_literal(",\"severity\":");
    out.severity = try read_enum(cursor, codes.Severity);
    try cursor.take_literal(",\"blame\":");
    out.blame = try read_enum(cursor, codes.Blame);
    try cursor.take_literal(",\"summary\":");
    try read_text(cursor, &out.summary);
    try cursor.take(',');
    assert(out.summary.len > 0);
}

fn parse_body(cursor: *Cursor, out: *Diagnostic) Malformed!void {
    assert(cursor.at > 0);
    assert(out.causes.count == 0);
    try cursor.take_literal("\"causes\":");
    try parse_texts(cursor, &out.causes);
    try cursor.take_literal(",\"while\":");
    try parse_texts(cursor, &out.whiles);
    try cursor.take_literal(",\"context\":");
    try parse_context(cursor, &out.pairs);
    try cursor.take_literal(",\"fixes\":");
    try parse_fixes(cursor, &out.fixes);
    try cursor.take(',');
    if (cursor.accept_literal("\"saved\":")) {
        try read_text(cursor, &out.saved);
        try cursor.take(',');
    }
    if (cursor.accept_literal("\"docs\":")) {
        try read_text(cursor, &out.docs);
        try cursor.take(',');
    }
    assert(out.fixes.count <= constants.diag_fixes_count_max);
}

/// The inverse of `write_json`. Initialises `out` in place; after an error it is empty. See the
/// top of this file for what it accepts. Allocation free and bounded: input over
/// `diag_wire_bytes_max` is refused unread.
pub fn parse_json(out: *Diagnostic, bytes: []const u8) Malformed!void {
    out.reset();
    errdefer out.reset();
    if (bytes.len > constants.diag_wire_bytes_max) return error.Malformed;
    var cursor: Cursor = .{ .bytes = bytes, .at = 0 };
    try parse_head(&cursor, out);
    try parse_body(&cursor, out);
    try parse_omitted(&cursor, out);
    _ = cursor.accept('\n'); // The newline `write_json` ends with is optional.
    if (cursor.at != bytes.len) return error.Malformed;
    assert(code_is_valid(out.code.slice()));
    assert(out.summary.len > 0);
}

// ---- Tests ---------------------------------------------------------------------------------

const testing = std.testing;
const test_util = @import("../test_util.zig");

fn json_of(buffer: []u8, diagnostic: *const Diagnostic) ![]const u8 {
    var writer = Writer.fixed(buffer);
    try write_json(&writer, diagnostic);
    return writer.buffered();
}

/// A diagnostic with every kind of content: escapes, a fix without a command, a context pair,
/// a saved path.
fn fill_sample(diag: *Diag, code: codes.Code) void {
    diag.reset();
    diag.raise(code);
    diag.while_("starting container \"web-1\"", .{});
    diag.cause("clone3 returned EACCES", .{});
    diag.cause("a path C:\\x and a ' ' and ~", .{});
    diag.context("path", "{s}", .{"C:\\x"});
    diag.fix(.{ .sentence = "allow zbx only:", .command = "sudo zbx doctor --fix apparmor" });
    diag.fix(.{ .sentence = "or read the docs" });
}

test "every registered code round-trips through write_json and parse_json" {
    // Goal: the acceptance test of the wire form. For each code in the registry, a collector
    // with every kind of content becomes a Diagnostic, is written, parsed, and equals itself;
    // and writing the parsed one gives the same bytes. Also with the newline removed.
    var diag: Diag = undefined;
    var original: Diagnostic = undefined;
    var parsed: Diagnostic = undefined;
    var buffer: [constants.output_bytes_max]u8 = undefined;
    var again: [constants.output_bytes_max]u8 = undefined;
    for (codes.registry) |item| {
        fill_sample(&diag, item.code);
        if (item.severity == .bug) diag.save_bundle("/state/zbx/bundles/x");
        from_diag(&original, &diag);
        const json = try json_of(&buffer, &original);
        try parse_json(&parsed, json);
        try testing.expect(original.equal(&parsed));
        try testing.expectEqualStrings(json, try json_of(&again, &parsed));
        try parse_json(&parsed, json[0 .. json.len - 1]);
        try testing.expect(original.equal(&parsed));
    }
}

test "from_diag copies the collector and write_json is what render wrote before" {
    // Goal: the Diagnostic says what the Diag says, with the registry's severity, blame and
    // summary, Zigbox's docs, and the exit code of the blame.
    var diag: Diag = undefined;
    fill_sample(&diag, .E0001);
    var diagnostic: Diagnostic = undefined;
    from_diag(&diagnostic, &diag);
    try testing.expectEqualStrings("ZBX-E0001", diagnostic.code.slice());
    try testing.expectEqualStrings("unknown command", diagnostic.summary.slice());
    try testing.expectEqualStrings("a path C:\\x and a ' ' and ~", diagnostic.last_cause().?);
    try testing.expectEqual(diag.exit_code(), diagnostic.exit_code());
    try testing.expectEqualStrings(
        "https://zigbox.github.io/zigbox/errors/E0001.html",
        diagnostic.docs.slice(),
    );
    var buffer: [constants.output_bytes_max]u8 = undefined;
    try testing.expect(try test_util.json_is_valid(try json_of(&buffer, &diagnostic)));
}

test "lists past their bounds round-trip with their omitted counts" {
    // Goal: the overflow state survives the wire. A full list with omitted items parses; the
    // same count on a list that is not full does not.
    var diag: Diag = undefined;
    diag.reset();
    diag.raise(.E0001);
    for (0..constants.diag_causes_count_max + 3) |index| diag.cause("cause {d}", .{index});
    for (0..constants.diag_fixes_count_max + 2) |_| diag.fix(.{ .sentence = "fix" });
    for (0..constants.diag_context_count_max + 1) |_| diag.context("k", "v", .{});
    var original: Diagnostic = undefined;
    from_diag(&original, &diag);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const json = try json_of(&buffer, &original);
    var parsed: Diagnostic = undefined;
    try parse_json(&parsed, json);
    try testing.expect(original.equal(&parsed));
    try testing.expectEqual(@as(u32, 3), parsed.causes.omitted);

    fill_sample(&diag, .E0001);
    from_diag(&original, &diag);
    const short = try json_of(&buffer, &original);
    var forged: [constants.output_bytes_max]u8 = undefined;
    const needle = "\"causes\":0,";
    const at = std.mem.indexOf(u8, short, needle).?;
    @memcpy(forged[0..short.len], short);
    forged[at + needle.len - 2] = '2';
    try testing.expectError(error.Malformed, parse_json(&parsed, forged[0..short.len]));
}

test "parse_json refuses what write_json never writes, and never truncates" {
    // Goal: the negative space, one case per rule. Each input is a valid line with one change.
    var diag: Diag = undefined;
    fill_sample(&diag, .E0001);
    var original: Diagnostic = undefined;
    from_diag(&original, &diag);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const good = try json_of(&buffer, &original);
    var parsed: Diagnostic = undefined;
    try parse_json(&parsed, good);

    const bad = [_]struct { from: []const u8, to: []const u8 }{
        .{ .from = "\"error\"", .to = "\"fatal\"" }, // Unknown severity.
        .{ .from = "\"user\"", .to = "\"nobody\"" }, // Unknown blame.
        .{ .from = "ZBX-E0001", .to = "ZBX-E001" }, // Code shape.
        .{ .from = "ZBX-E0001", .to = "zbx-E0001" },
        .{ .from = "ZBX-E0001", .to = "ZBXQX-E0001" },
        .{ .from = "\"unknown command\"", .to = "\"\"" }, // Empty text.
        .{ .from = "\"clone3 returned EACCES\"", .to = "\"a\\nb\"" }, // Another escape.
        .{ .from = "\"clone3 returned EACCES\"", .to = "\"a\x01b\"" }, // Control byte.
        .{ .from = "\"clone3 returned EACCES\"", .to = "\"a\xffb\"" }, // Not ASCII.
        .{ .from = "\"path\"", .to = "\"while\"" }, // A reserved key.
        .{ .from = "\"path\"", .to = "\"Path\"" },
        .{ .from = "\"path\"", .to = "\"toolong\"" },
        .{ .from = "\"path\"", .to = "\"\"" },
        .{ .from = "\"causes\"", .to = "\"cause\"" }, // A key out of place.
        .{ .from = "\"fixes\":[", .to = "\"extra\":1,\"fixes\":[" }, // An unknown key.
        .{ .from = "\"context\":0", .to = "\"context\":00" }, // Not canonical.
        .{ .from = "\"context\":0", .to = "\"context\":65536" }, // Over what is shown.
        .{ .from = "\"context\":0", .to = "\"context\":" }, // No count.
        .{ .from = "{\"code\"", .to = " {\"code\"" }, // Whitespace.
        .{ .from = ",\"omitted\"", .to = ", \"omitted\"" },
    };
    for (bad) |case| {
        var changed: [constants.output_bytes_max]u8 = undefined;
        const line = try replace_once(&changed, good, case.from, case.to);
        try testing.expectError(error.Malformed, parse_json(&parsed, line));
        try testing.expectEqual(@as(u32, 0), parsed.causes.count); // Left empty.
    }
    try testing.expectError(error.Malformed, parse_json(&parsed, ""));
    try testing.expectError(error.Malformed, parse_json(&parsed, good[0 .. good.len - 2]));
    var joined: [constants.output_bytes_max]u8 = undefined;
    const trailing = try replace_once(&joined, good, "}}\n", "}}\nx");
    try testing.expectError(error.Malformed, parse_json(&parsed, trailing));
}

/// `text` with the one occurrence of `from` replaced by `to`, in `buffer`.
fn replace_once(buffer: []u8, text: []const u8, from: []const u8, to: []const u8) ![]const u8 {
    const at = std.mem.indexOf(u8, text, from) orelse return error.TestUnexpectedResult;
    const rest = text[at + from.len ..];
    @memcpy(buffer[0..at], text[0..at]);
    @memcpy(buffer[at..][0..to.len], to);
    @memcpy(buffer[at + to.len ..][0..rest.len], rest);
    return buffer[0 .. at + to.len + rest.len];
}

test "a field one byte over its bound is refused and one at the bound is kept whole" {
    // Goal: the boundary between valid and invalid. Texts of exactly the bound parse and equal;
    // one more byte is Malformed; and so is a list one item over its capacity.
    var buffer: [constants.output_bytes_max]u8 = undefined;
    var parsed: Diagnostic = undefined;
    const exact = test_util.repeat('x', constants.diag_field_bytes_max);
    const head = "{\"code\":\"ZBX-E0001\",\"severity\":\"error\",\"blame\":\"user\"," ++
        "\"summary\":\"s\",\"causes\":[\"";
    const tail = "\"],\"while\":[],\"context\":{},\"fixes\":[]," ++
        "\"omitted\":{\"causes\":0,\"while\":0,\"context\":0,\"fixes\":0}}\n";
    var writer = Writer.fixed(&buffer);
    try writer.print("{s}{s}{s}", .{ head, exact, tail });
    try parse_json(&parsed, writer.buffered());
    try testing.expectEqualStrings(exact, parsed.causes.slice()[0].slice());
    writer = Writer.fixed(&buffer);
    try writer.print("{s}{s}y{s}", .{ head, exact, tail });
    try testing.expectError(error.Malformed, parse_json(&parsed, writer.buffered()));

    var many: [constants.output_bytes_max]u8 = undefined;
    writer = Writer.fixed(&many);
    try writer.writeAll(head);
    for (0..constants.diag_causes_count_max + 1) |index| {
        if (index > 0) try writer.writeAll("\",\"");
        try writer.writeAll("a");
    }
    try writer.writeAll(tail);
    try testing.expectError(error.Malformed, parse_json(&parsed, writer.buffered()));
}

test "input over the wire bound is refused unread" {
    var parsed: Diagnostic = undefined;
    const big = test_util.repeat('{', constants.diag_wire_bytes_max + 1);
    try testing.expectError(error.Malformed, parse_json(&parsed, big));
}
