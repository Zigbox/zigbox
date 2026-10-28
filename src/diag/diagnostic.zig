//! `Diagnostic`: a finished diagnostic as plain data (DIAGNOSTICS.md, "Same model everywhere").
//!
//! A `Diag` is the collector of one product: its code is a tag of that product's registry, so
//! it cannot name another product's code. A `Diagnostic` is what the collector produces, with the
//! code as text. It is what travels (node, API, CLI) as JSON, and what the renderer renders, so
//! a second product's diagnostics and Zigbox's are one type, one renderer and one wire form.
//!
//!   - `from_diag` copies a collector.
//!   - `write_json` writes the one-line JSON object that `zbx --output json` has always written.
//!   - `parse_json` reads it back. It is forward tolerant and strict on what it knows: members
//!     may come in any order and a member it does not know is skipped (a newer writer added it;
//!     the skipping is bounded by `diag_skip_depth_max` and `diag_skip_bytes_max`), but a known
//!     member twice, a missing one, a field over its bound, an unknown severity or blame, or a
//!     list over its capacity is `error.Malformed`, never a truncation. There is no version
//!     member. Whitespace is not accepted. Whatever it accepts is a value `write_json` writes
//!     in its own canonical form and `parse_json` reads back equal (the fuzzer checks that),
//!     and the renderer's assertions (no empty text, printable ASCII, counts within the bounds)
//!     hold for it.
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
    if (first.needs_root != second.needs_root) return false;
    if (first.template != second.template) return false;
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
        // Added in M6, only when true, so every older document is byte for byte what it was.
        if (item.needs_root) {
            try writer.writeByte(',');
            try write_key(writer, "needs_root");
            try writer.writeAll("true");
        }
        if (item.template) {
            try writer.writeByte(',');
            try write_key(writer, "template");
            try writer.writeAll("true");
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
    /// Bytes of unknown members skipped so far, against `diag_skip_bytes_max`.
    skipped: u32,

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

// Unknown members. A newer writer may add members; they are skipped, not refused, so a rolling
// upgrade does not turn every diagnostic from a newer node into `Malformed`. Skipping checks the
// value is JSON of the shape `write_json` writes (printable ASCII, no whitespace), bounded in
// depth and in bytes, and keeps no explicit recursion: the open containers are a small stack.

fn skip_hex4(cursor: *Cursor) Malformed!void {
    assert(cursor.at > 0); // After the `u`.
    for (0..4) |_| {
        const byte = cursor.next() orelse return error.Malformed;
        if (!std.ascii.isHex(byte)) return error.Malformed;
    }
    assert(cursor.at <= cursor.bytes.len);
}

/// Skips a JSON string: printable ASCII, with the escapes JSON has.
fn skip_string(cursor: *Cursor) Malformed!void {
    assert(cursor.at <= cursor.bytes.len);
    try cursor.take('"');
    while (cursor.next()) |byte| {
        if (byte == '"') return;
        if (!text_util.is_printable(byte)) return error.Malformed;
        if (byte != '\\') continue;
        const escaped = cursor.next() orelse return error.Malformed;
        if (escaped == 'u') {
            try skip_hex4(cursor);
        } else if (std.mem.indexOfScalar(u8, "\"\\/bfnrt", escaped) == null) {
            return error.Malformed;
        }
    }
    return error.Malformed; // The input ended inside the string.
}

fn skip_digits(cursor: *Cursor) u32 {
    assert(cursor.at <= cursor.bytes.len);
    const start = cursor.at;
    while (cursor.at < cursor.bytes.len) {
        if (!std.ascii.isDigit(cursor.bytes[cursor.at])) break;
        cursor.at += 1;
    }
    assert(cursor.at >= start);
    return cursor.at - start;
}

/// Skips a JSON number: -?(0|[1-9][0-9]*)(.[0-9]+)?([eE][+-]?[0-9]+)?
fn skip_number(cursor: *Cursor) Malformed!void {
    assert(cursor.at <= cursor.bytes.len);
    const start = cursor.at;
    _ = cursor.accept('-');
    if (cursor.accept('0')) {
        // A leading zero stands alone.
    } else if (skip_digits(cursor) == 0) {
        return error.Malformed;
    }
    if (cursor.accept('.')) {
        if (skip_digits(cursor) == 0) return error.Malformed;
    }
    if (cursor.accept('e')) {
        try skip_exponent(cursor);
    } else if (cursor.accept('E')) {
        try skip_exponent(cursor);
    }
    assert(cursor.at > start); // A number is at least one byte.
    assert(cursor.at <= cursor.bytes.len);
}

/// The part of a number after its `e`.
fn skip_exponent(cursor: *Cursor) Malformed!void {
    assert(cursor.at > 0);
    if (!cursor.accept('+')) _ = cursor.accept('-');
    if (skip_digits(cursor) == 0) return error.Malformed;
    assert(cursor.at <= cursor.bytes.len);
}

const Started = enum { scalar, opened };

/// Skips a scalar, or opens a container and pushes it on `stack`.
fn skip_start(
    cursor: *Cursor,
    stack: *[constants.diag_skip_depth_max]u8,
    depth: *u32,
) Malformed!Started {
    assert(depth.* <= constants.diag_skip_depth_max);
    if (cursor.at == cursor.bytes.len) return error.Malformed;
    const byte = cursor.bytes[cursor.at];
    switch (byte) {
        '"' => try skip_string(cursor),
        '[', '{' => {
            if (depth.* == constants.diag_skip_depth_max) return error.Malformed;
            stack[depth.*] = byte;
            depth.* += 1;
            cursor.at += 1;
            return .opened;
        },
        't' => try cursor.take_literal("true"),
        'f' => try cursor.take_literal("false"),
        'n' => try cursor.take_literal("null"),
        else => try skip_number(cursor),
    }
    assert(cursor.at > 0);
    assert(depth.* <= constants.diag_skip_depth_max);
    return .scalar;
}

/// Skips one JSON value of any type.
fn skip_value(cursor: *Cursor) Malformed!void {
    const start = cursor.at;
    var stack: [constants.diag_skip_depth_max]u8 = undefined;
    var depth: u32 = 0;
    var state = try skip_start(cursor, &stack, &depth);
    // Every pass consumes at least one byte or fails, and the budget below ends a long one.
    while (depth > 0) {
        if (cursor.at - start > constants.diag_skip_bytes_max) return error.Malformed;
        const top = stack[depth - 1];
        assert(top != 0);
        if (top != '[') assert(top == '{');
        if (cursor.accept(if (top == '[') ']' else '}')) {
            depth -= 1;
            state = .scalar; // A container is a finished value like a scalar.
            continue;
        }
        if (state == .scalar) try cursor.take(',');
        if (top == '{') {
            try skip_string(cursor);
            try cursor.take(':');
        }
        state = try skip_start(cursor, &stack, &depth);
    }
    assert(depth == 0);
}

/// The members of an object this parser knows. `read_member` returns the known one whose value
/// is next, or null for an unknown one that it has skipped whole.
fn read_member(cursor: *Cursor, comptime Field: type, seen: *u32) Malformed!?Field {
    comptime assert(std.meta.fieldNames(Field).len <= 32); // One bit each in `seen`.
    const start = cursor.at;
    assert(cursor.skipped <= constants.diag_skip_bytes_max);
    inline for (comptime std.meta.fieldNames(Field)) |name| {
        if (cursor.accept_literal("\"" ++ name ++ "\":")) {
            const bit = @as(u32, 1) << @backingInt(@field(Field, name));
            if (seen.* & bit != 0) return error.Malformed; // A known member twice.
            seen.* |= bit;
            return @field(Field, name);
        }
    }
    try skip_string(cursor);
    try cursor.take(':');
    try skip_value(cursor);
    assert(cursor.at > start);
    cursor.skipped += cursor.at - start;
    if (cursor.skipped > constants.diag_skip_bytes_max) return error.Malformed;
    return null;
}

/// After a member: true if the object ended, false if another follows.
fn object_ended(cursor: *Cursor) Malformed!bool {
    assert(cursor.at > 0); // A member was read.
    assert(cursor.at <= cursor.bytes.len);
    if (cursor.accept('}')) return true;
    try cursor.take(',');
    return false;
}

fn all_seen(comptime Field: type, seen: u32) bool {
    const fields = comptime std.meta.fieldNames(Field);
    assert(seen >> fields.len == 0); // No bit past the last field.
    return seen == (@as(u32, 1) << fields.len) - 1;
}

const FixField = enum(u5) { sentence, command, needs_root, template };
/// The members every fix has; the last two appear only when true.
const fix_required_mask: u32 = 0b11;

fn parse_fix(cursor: *Cursor, item: *diag_mod.Fix) Malformed!void {
    item.sentence = .{};
    item.command = .{};
    item.needs_root = false;
    item.template = false;
    try cursor.take('{');
    var seen: u32 = 0;
    var ended = false; // Every pass reads a member, which consumes input or fails.
    while (!ended) {
        const field = try read_member(cursor, FixField, &seen);
        if (field == .sentence) try read_text(cursor, &item.sentence);
        if (field == .command) {
            if (!cursor.accept_literal("null")) try read_text(cursor, &item.command);
        }
        // Only `true` is read: `false` is never written, so it is not canonical.
        if (field == .needs_root) try cursor.take_literal("true");
        if (field == .template) try cursor.take_literal("true");
        if (field == .needs_root) item.needs_root = true;
        if (field == .template) item.template = true;
        ended = try object_ended(cursor);
    }
    if (seen & fix_required_mask != fix_required_mask) return error.Malformed;
    // A flag describes a command, so a fix without one cannot carry it.
    if (item.command.len == 0) {
        if (item.needs_root or item.template) return error.Malformed;
    }
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

const OmittedField = enum(u5) { causes, @"while", context, fixes };

/// The four counts, in the order of `OmittedField`.
fn parse_omitted(cursor: *Cursor) Malformed![4]u32 {
    var counts: [4]u32 = @splat(0);
    try cursor.take('{');
    var seen: u32 = 0;
    var ended = false; // Every pass reads a member, which consumes input or fails.
    while (!ended) {
        const field = try read_member(cursor, OmittedField, &seen);
        if (field) |known| counts[@backingInt(known)] = try read_count(cursor);
        ended = try object_ended(cursor);
    }
    if (!all_seen(OmittedField, seen)) return error.Malformed;
    assert(counts[0] <= std.math.maxInt(u16));
    return counts;
}

const Member = enum(u5) {
    code,
    severity,
    blame,
    summary,
    causes,
    @"while",
    context,
    fixes,
    saved,
    docs,
    omitted,
};

/// Every member `write_json` always writes. `saved` and `docs` are written when there is one.
const required_fields: u32 = blk: {
    const all: u32 = (@as(u32, 1) << std.meta.fieldNames(Member).len) - 1;
    const saved = @as(u32, 1) << @backingInt(Member.saved);
    const docs = @as(u32, 1) << @backingInt(Member.docs);
    break :blk all & ~(saved | docs);
};

/// Reads the value of a known member into `out`. The counts of omitted items wait for the end,
/// when the lists they refer to are known.
fn parse_field(cursor: *Cursor, out: *Diagnostic, field: Member, counts: *[4]u32) Malformed!void {
    assert(cursor.at > 0);
    assert(out.code.len <= constants.diag_code_bytes);
    switch (field) {
        .code => {
            try read_text(cursor, &out.code);
            if (!code_is_valid(out.code.slice())) return error.Malformed;
        },
        .severity => out.severity = try read_enum(cursor, codes.Severity),
        .blame => out.blame = try read_enum(cursor, codes.Blame),
        .summary => try read_text(cursor, &out.summary),
        .causes => try parse_texts(cursor, &out.causes),
        .@"while" => try parse_texts(cursor, &out.whiles),
        .context => try parse_context(cursor, &out.pairs),
        .fixes => try parse_fixes(cursor, &out.fixes),
        .saved => try read_text(cursor, &out.saved),
        .docs => try read_text(cursor, &out.docs),
        .omitted => counts.* = try parse_omitted(cursor),
    }
}

/// The inverse of `write_json`. Initialises `out` in place; after an error it is empty. See the
/// top of this file for what it accepts. Allocation free and bounded: input over
/// `diag_wire_bytes_max` is refused unread.
pub fn parse_json(out: *Diagnostic, bytes: []const u8) Malformed!void {
    out.reset();
    errdefer out.reset();
    if (bytes.len > constants.diag_wire_bytes_max) return error.Malformed;
    assert(bytes.len < std.math.maxInt(u32)); // Positions are u32; the bound above is far lower.
    var cursor: Cursor = .{ .bytes = bytes, .at = 0, .skipped = 0 };
    try cursor.take('{');
    var seen: u32 = 0;
    var counts: [4]u32 = @splat(0);
    var ended = false; // Every pass reads a member, which consumes input or fails.
    while (!ended) {
        const field = try read_member(&cursor, Member, &seen);
        if (field) |known| try parse_field(&cursor, out, known, &counts);
        ended = try object_ended(&cursor);
    }
    if (seen & required_fields != required_fields) return error.Malformed;
    try set_omitted(&out.causes, counts[@backingInt(OmittedField.causes)]);
    try set_omitted(&out.whiles, counts[@backingInt(OmittedField.@"while")]);
    try set_omitted(&out.pairs, counts[@backingInt(OmittedField.context)]);
    try set_omitted(&out.fixes, counts[@backingInt(OmittedField.fixes)]);
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

fn fill_flags(diag: *Diag, group: u32) void {
    diag.reset();
    diag.raise(.E0001);
    diag.cause("c", .{});
    switch (group) {
        0 => {
            diag.fix(.{ .sentence = "plain", .command = "zbx doctor" });
            diag.fix(.{ .sentence = "root", .command = "sudo apt install passt" });
            diag.fix(.{ .sentence = "piped", .command = "echo x | sudo tee /etc/y" });
        },
        1 => {
            diag.fix(.{ .sentence = "example", .command = "zbx run x", .template = true });
            diag.fix(.{ .sentence = "both", .command = "sudo sysctl a=1", .template = true });
            diag.fix(.{ .sentence = "prose only" });
        },
        else => {
            diag.fix_with("formatted", "sudo ls {s}", .{"/x"});
            diag.fix_with("placeholder", "zbx run <{s}>", .{"command"});
            diag.mark_last_fix_template();
        },
    }
}

test "a fix's needs_root and template are written only when true, and read back" {
    // Goal: M6's two flags are additive: a fix without them writes what it always wrote, a
    // sudo command is marked by itself, a template by its maker, and a damaged flag is refused.
    const flagged = [3][]const []const u8{
        &.{
            "{\"sentence\":\"plain\",\"command\":\"zbx doctor\"}",
            "\"command\":\"sudo apt install passt\",\"needs_root\":true}",
            "\"command\":\"echo x | sudo tee /etc/y\",\"needs_root\":true}",
        },
        &.{
            "\"command\":\"zbx run x\",\"template\":true}",
            "\"command\":\"sudo sysctl a=1\",\"needs_root\":true,\"template\":true}",
            "{\"sentence\":\"prose only\",\"command\":null}",
        },
        &.{
            "\"command\":\"sudo ls /x\",\"needs_root\":true}",
            "\"command\":\"zbx run <command>\",\"template\":true}",
        },
    };
    var diag: Diag = undefined;
    var original: Diagnostic = undefined;
    var parsed: Diagnostic = undefined;
    var buffer: [constants.output_bytes_max]u8 = undefined;
    for (flagged, 0..) |parts, group| {
        fill_flags(&diag, @intCast(group));
        from_diag(&original, &diag);
        const json = try json_of(&buffer, &original);
        for (parts) |part| try testing.expect(std.mem.indexOf(u8, json, part) != null);
        try parse_json(&parsed, json);
        try testing.expect(original.equal(&parsed));
        // A flag a later zbx does not know is skipped, as every unknown member is.
        var future: [constants.output_bytes_max]u8 = undefined;
        const mark = std.mem.indexOf(u8, json, "\"fixes\":[{").?;
        const extra = ",\"later\":[1]";
        const close = std.mem.indexOfPos(u8, json, mark, "}").?;
        @memcpy(future[0..close], json[0..close]);
        @memcpy(future[close..][0..extra.len], extra);
        @memcpy(future[close + extra.len ..][0 .. json.len - close], json[close..]);
        try parse_json(&parsed, future[0 .. json.len + extra.len]);
        try testing.expect(original.equal(&parsed));
    }
    fill_flags(&diag, 0);
    from_diag(&original, &diag);
    try testing.expect(original.fixes.items[1].needs_root);
    try testing.expect(!original.fixes.items[1].template);
    fill_flags(&diag, 1);
    from_diag(&original, &diag);
    try testing.expect(original.fixes.items[0].template);
    const json = try json_of(&buffer, &original);

    const damages = [_]struct { from: []const u8, to: []const u8 }{
        .{ .from = "\"needs_root\":true", .to = "\"needs_root\":false" }, // Not canonical.
        .{ .from = "\"needs_root\":true", .to = "\"needs_root\":1" },
        .{ .from = "\"needs_root\":true", .to = "\"needs_root\":true,\"needs_root\":true" },
        .{ .from = "\"template\":true", .to = "\"template\":\"true\"" },
        .{
            .from = "\"sentence\":\"prose only\",\"command\":null",
            .to = "\"sentence\":\"p\",\"command\":null,\"template\":true",
        },
    };
    for (damages) |damage| {
        var copy: [constants.output_bytes_max]u8 = undefined;
        const size = std.mem.replacementSize(u8, json, damage.from, damage.to);
        _ = std.mem.replace(u8, json, damage.from, damage.to, &copy);
        try testing.expectError(error.Malformed, parse_json(&parsed, copy[0..size]));
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

/// Parses `good` with the one occurrence of `from` replaced by `to`; `parsed` is the result.
fn parse_changed(parsed: *Diagnostic, good: []const u8, from: []const u8, to: []const u8) !void {
    var changed: [constants.output_bytes_max]u8 = undefined;
    try parse_json(parsed, try replace_once(&changed, good, from, to));
}

fn sample_json(buffer: []u8, original: *Diagnostic) ![]const u8 {
    var diag: Diag = undefined;
    fill_sample(&diag, .E0001);
    from_diag(original, &diag);
    return json_of(buffer, original);
}

test "an unknown member is skipped wherever it is and whatever its value" {
    // Goal: forward tolerance. A newer writer adds members at the top, inside a fix and inside
    // the omitted counts, of any JSON type; the result equals the diagnostic without them and
    // writes back the canonical line.
    var original: Diagnostic = undefined;
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const good = try sample_json(&buffer, &original);
    const values = [_][]const u8{
        "1",
        "-1.5e+3",
        "0",
        "\"s\\u00e9\\n\\/x\\\"\"",
        "true",
        "false",
        "null",
        "[]",
        "{}",
        "[1,[2,{\"a\":[]}]]",
        "{\"a\":{\"b\":\"c\"},\"d\":[null]}",
    };
    const places = [_]struct { from: []const u8, key: []const u8, after: []const u8 }{
        .{ .from = "{\"code\":", .key = "{\"v\":", .after = ",\"code\":" },
        .{ .from = ",\"docs\":", .key = ",\"zz\":", .after = ",\"docs\":" },
        .{ .from = "{\"sentence\":", .key = "{\"id\":", .after = ",\"sentence\":" },
        .{ .from = "\"omitted\":{", .key = "\"omitted\":{\"extra\":", .after = "," },
    };
    var parsed: Diagnostic = undefined;
    var line: [constants.output_bytes_max]u8 = undefined;
    var again: [constants.output_bytes_max]u8 = undefined;
    for (places) |place| {
        for (values) |value| {
            var writer = Writer.fixed(&line);
            try writer.print("{s}{s}{s}", .{ place.key, value, place.after });
            try parse_changed(&parsed, good, place.from, writer.buffered());
            try testing.expect(original.equal(&parsed));
            try testing.expectEqualStrings(good, try json_of(&again, &parsed));
        }
    }
}

test "members in any order parse; a missing member or a repeated known one is refused" {
    // Goal: order is free, completeness and uniqueness are not.
    var parsed: Diagnostic = undefined;
    const reversed = "{\"omitted\":{\"fixes\":0,\"context\":0,\"while\":0,\"causes\":0}," ++
        "\"fixes\":[],\"context\":{},\"while\":[],\"causes\":[\"c\"],\"summary\":\"s\"," ++
        "\"blame\":\"user\",\"severity\":\"error\",\"code\":\"ZBX-E0001\"}\n";
    try parse_json(&parsed, reversed);
    try testing.expectEqualStrings("ZBX-E0001", parsed.code.slice());
    try testing.expectEqualStrings("c", parsed.last_cause().?);
    try testing.expectEqual(@as(u32, 0), parsed.fixes.count);

    var original: Diagnostic = undefined;
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const good = try sample_json(&buffer, &original);
    const code = "{\"code\":\"ZBX-E0001\",";
    const refused = [_]struct { from: []const u8, to: []const u8 }{
        .{ .from = code, .to = code ++ "\"code\":\"ZBX-E0001\"," }, // A known member twice.
        .{ .from = "{\"sentence\":", .to = "{\"sentence\":\"a\",\"sentence\":" },
        .{ .from = "\"omitted\":{", .to = "\"omitted\":{\"causes\":0," },
        .{ .from = "\"summary\":\"unknown command\",", .to = "" }, // A missing one.
        .{ .from = ",\"command\":null", .to = "" },
        .{ .from = "\"fixes\":[", .to = "\"fixez\":[" },
        .{ .from = ",\"fixes\":0}", .to = "}" },
    };
    for (refused) |case| {
        const result = parse_changed(&parsed, good, case.from, case.to);
        try testing.expectError(error.Malformed, result);
        try testing.expectEqual(@as(u32, 0), parsed.causes.count);
    }
}

/// `{"x":<payload>` placed first in a valid line; `payload` is built by `fill`.
fn parse_with_unknown(parsed: *Diagnostic, good: []const u8, member: []const u8) !void {
    var line: [constants.output_bytes_max]u8 = undefined;
    var writer = Writer.fixed(&line);
    try writer.print("{s},\"code\":", .{member});
    try parse_changed(parsed, good, "\"code\":", writer.buffered());
}

test "skipping is bounded in depth and in bytes, and checks what it skips" {
    // Goal: the two limits are exact (at the limit parses, one over is Malformed), they hold
    // over all unknown members together, and a skipped value must still be well-formed JSON.
    var original: Diagnostic = undefined;
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const good = try sample_json(&buffer, &original);
    var parsed: Diagnostic = undefined;
    var member: [constants.diag_skip_bytes_max * 3]u8 = undefined;

    const depth_max = constants.diag_skip_depth_max;
    for ([_]u32{ depth_max, depth_max + 1 }) |depth| {
        var writer = Writer.fixed(&member);
        try writer.writeAll("\"x\":");
        for (0..depth) |_| try writer.writeByte('[');
        for (0..depth) |_| try writer.writeByte(']');
        const result = parse_with_unknown(&parsed, good, writer.buffered());
        if (depth <= depth_max) try result else try testing.expectError(error.Malformed, result);
    }

    const bytes_max = constants.diag_skip_bytes_max;
    for ([_]u32{ bytes_max, bytes_max + 1 }) |bytes| {
        var writer = Writer.fixed(&member);
        try writer.writeAll("\"x\":\"");
        try writer.splatByteAll('p', bytes - 6);
        try writer.writeByte('"');
        try testing.expectEqual(bytes, writer.buffered().len);
        const result = parse_with_unknown(&parsed, good, writer.buffered());
        if (bytes <= bytes_max) try result else try testing.expectError(error.Malformed, result);
    }
    // Two members that are each within the limit and together over it.
    var writer = Writer.fixed(&member);
    try writer.writeAll("\"x\":\"");
    try writer.splatByteAll('p', bytes_max / 2);
    try writer.writeAll("\",\"y\":\"");
    try writer.splatByteAll('p', bytes_max / 2);
    try writer.writeByte('"');
    try testing.expectError(error.Malformed, parse_with_unknown(&parsed, good, writer.buffered()));

    const bad_values = [_][]const u8{
        "[1,]",
        "{\"a\"}",
        "tru",
        "01",
        "\"a\x01\"",
        "\"\\q\"",
        "-",
        "1.",
        "1e",
        "[1 2]",
        "[",
        "{\"a\":1,}",
        "\"\\u12g4\"",
        "+1",
        ".5",
        "\"\xff\"",
    };
    for (bad_values) |value| {
        writer = Writer.fixed(&member);
        try writer.print("\"x\":{s}", .{value});
        const result = parse_with_unknown(&parsed, good, writer.buffered());
        try testing.expectError(error.Malformed, result);
    }
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
