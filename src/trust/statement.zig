//! The in-toto Statement v1 that a signature covers (docs/briefs/M8-trust.md, "What is
//! signed"), written by the canonical JSON writer and read back only in that form:
//!
//!   {"_type":"https://in-toto.io/Statement/v1",
//!    "subject":[{"name":"tree","digest":{"zbxTree":"<64 hex>"}},
//!               {"name":"result","digest":{"zbxResult":"<64 hex>"}}],
//!    "predicateType":"https://zigbox.org/attestation/sign/v1",
//!    "predicate":{"signedAt":"2026-11-08T10:00:00Z"}}
//!
//! (Shown with whitespace; the payload has none.) The first subject is always the tree. The
//! second is optional: a result (`zbxResult`) or an image manifest (`<reference>` with a
//! `sha256` digest). At most `statement_subjects_max` subjects. The only predicate this slice
//! knows is our sign predicate; a statement of another predicate type is refused as unknown
//! (the provenance predicate arrives with slice 4, and the type URI comes from `constants`).
//!
//! The reader checks the grammar only, so this layer compares each member name with the one the
//! writer writes next, refuses any other, and requires `.end` after the root. Parse accepts only
//! what `render` writes, and a time must re-render to its own text.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const json = @import("json.zig");
const dsse = @import("dsse.zig");

pub const statement_type = "https://in-toto.io/Statement/v1";
pub const tree_name = "tree";
pub const result_name = "result";
pub const tree_digest_key = "zbxTree";
pub const result_digest_key = "zbxResult";
pub const manifest_digest_key = "sha256";

pub const Digest = [32]u8;

pub const ParseError = error{
    /// Not a statement in the form `render` writes.
    Malformed,
    /// A well-formed statement whose predicate type this release does not know.
    UnknownPredicate,
};

/// The second subject: what the signature binds the tree to.
pub const Binding = union(enum) {
    none,
    /// An M7 result, which commits to the tree and its config.
    result: Digest,
    /// An image manifest, which commits to the OCI config.
    manifest: Digest,
};

pub const Statement = struct {
    tree: Digest,
    binding: Binding,
    /// A manifest binding's subject name (the image reference); empty for the other bindings.
    reference_text: [constants.reference_bytes_max]u8,
    reference_length: u32,
    /// Seconds since the epoch, at most `signed_at_seconds_max`.
    signed_at: u64,

    pub fn reference(self: *const Statement) []const u8 {
        return self.reference_text[0..self.reference_length];
    }

    /// A statement for `tree` alone.
    pub fn for_tree(tree: Digest, signed_at: u64) Statement {
        return make(tree, .none, "", signed_at);
    }

    pub fn for_result(tree: Digest, result: Digest, signed_at: u64) Statement {
        return make(tree, .{ .result = result }, "", signed_at);
    }

    /// `name` is the image reference as the operand spelled it: 1 to `reference_bytes_max`
    /// bytes of valid UTF-8.
    pub fn for_manifest(tree: Digest, name: []const u8, manifest: Digest, at: u64) Statement {
        assert(name.len > 0);
        return make(tree, .{ .manifest = manifest }, name, at);
    }

    /// True when both statements are about the same subjects: the same tree and binding, and for
    /// a manifest the same subject name. `signed_at` is not compared, so signing again later
    /// says the same thing (docs/decisions/2026-11-08-sign-idempotence.md).
    pub fn same_subjects(self: *const Statement, other: *const Statement) bool {
        if (!std.mem.eql(u8, &self.tree, &other.tree)) return false;
        const same_binding = switch (self.binding) {
            .none => other.binding == .none,
            .result => |digest| other.binding == .result and
                std.mem.eql(u8, &digest, &other.binding.result),
            .manifest => |digest| other.binding == .manifest and
                std.mem.eql(u8, &digest, &other.binding.manifest),
        };
        if (!same_binding) return false;
        return std.mem.eql(u8, self.reference(), other.reference());
    }

    fn make(tree: Digest, binding: Binding, name: []const u8, signed_at: u64) Statement {
        assert(name.len <= constants.reference_bytes_max);
        assert(std.unicode.utf8ValidateSlice(name));
        assert(signed_at <= constants.signed_at_seconds_max);
        var statement: Statement = .{
            .tree = tree,
            .binding = binding,
            .reference_text = @splat(0),
            .reference_length = @intCast(name.len),
            .signed_at = signed_at,
        };
        @memcpy(statement.reference_text[0..name.len], name);
        return statement;
    }
};

/// Most bytes `render` can write: the fixed text, plus a reference that escapes at its worst
/// (six bytes per byte, `\u00xx`), plus two digests.
pub const render_bytes_max: u32 = 512 + 6 * constants.reference_bytes_max;

comptime {
    assert(render_bytes_max <= constants.statement_bytes_max);
    assert(constants.statement_subjects_max == 2);
    assert(constants.sign_predicate_type.len > constants.type_uri_base.len);
}

/// The payload bytes of `statement`, into `out` (at least `render_bytes_max`).
pub fn render(out: []u8, statement: *const Statement) []const u8 {
    assert(out.len >= render_bytes_max);
    assert(statement.signed_at <= constants.signed_at_seconds_max);
    var writer = json.Writer.init(out[0..render_bytes_max]);
    // Every step fits: `render_bytes_max` bounds the longest statement, and the reference is
    // valid UTF-8 (`Statement.make` asserted it).
    write_statement(&writer, statement) catch unreachable;
    const text = writer.finish();
    assert(text.len <= constants.statement_bytes_max);
    return text;
}

fn write_statement(writer: *json.Writer, statement: *const Statement) json.WriteError!void {
    try writer.begin_object();
    try writer.member_string("_type", statement_type);
    try writer.member_array("subject");
    try write_subject(writer, tree_name, tree_digest_key, &statement.tree);
    switch (statement.binding) {
        .none => {},
        .result => |digest| try write_subject(writer, result_name, result_digest_key, &digest),
        .manifest => |digest| {
            try write_subject(writer, statement.reference(), manifest_digest_key, &digest);
        },
    }
    try writer.end_array();
    try writer.member_string("predicateType", constants.sign_predicate_type);
    try writer.member_object("predicate");
    const when = format_time(statement.signed_at);
    try writer.member_string("signedAt", &when);
    try writer.end_object();
    try writer.end_object();
}

fn write_subject(
    writer: *json.Writer,
    name: []const u8,
    digest_key: []const u8,
    digest: *const Digest,
) json.WriteError!void {
    try writer.begin_object();
    try writer.member_string("name", name);
    try writer.member_object("digest");
    const hex = std.fmt.bytesToHex(digest.*, .lower);
    try writer.member_string(digest_key, &hex);
    try writer.end_object();
    try writer.end_object();
}

// ---- Parse ----

/// The statement in `payload`. Call it only on bytes whose envelope has been verified (or on a
/// record being listed for people), never to decide trust on its own.
pub fn parse(payload: []const u8) ParseError!Statement {
    if (payload.len > constants.statement_bytes_max) return error.Malformed;
    var scratch: [constants.reference_bytes_max]u8 = undefined;
    var reader = json.Reader.init(payload);
    try dsse_expect(&reader, &scratch, .object_begin);
    try expect_key(&reader, &scratch, "_type");
    if (!std.mem.eql(u8, try read_string(&reader, &scratch), statement_type)) {
        return error.Malformed;
    }
    try expect_key(&reader, &scratch, "subject");
    var statement = try parse_subjects(&reader, &scratch);
    try expect_key(&reader, &scratch, "predicateType");
    const kind = try read_string(&reader, &scratch);
    if (!std.mem.eql(u8, kind, constants.sign_predicate_type)) return error.UnknownPredicate;
    try expect_key(&reader, &scratch, "predicate");
    try dsse_expect(&reader, &scratch, .object_begin);
    try expect_key(&reader, &scratch, "signedAt");
    statement.signed_at = parse_time(try read_string(&reader, &scratch)) orelse
        return error.Malformed;
    try dsse_expect(&reader, &scratch, .object_end);
    try dsse_expect(&reader, &scratch, .object_end);
    try dsse_expect(&reader, &scratch, .end);
    return statement;
}

fn parse_subjects(reader: *json.Reader, scratch: []u8) ParseError!Statement {
    try dsse_expect(reader, scratch, .array_begin);
    var statement = Statement.for_tree(@splat(0), 0);
    var index: u32 = 0;
    while (index < constants.statement_subjects_max) : (index += 1) {
        const token = reader.next(scratch) catch return error.Malformed;
        switch (token) {
            .object_begin => {},
            .array_end => {
                if (index == 0) return error.Malformed; // The tree is always there.
                return statement;
            },
            else => return error.Malformed,
        }
        if (index == 0) {
            statement.tree = try parse_tree_subject(reader, scratch);
        } else {
            try parse_binding(reader, scratch, &statement);
        }
    }
    // Two subjects read; anything but the end of the array is a third, which is refused.
    try dsse_expect(reader, scratch, .array_end);
    assert(index == constants.statement_subjects_max);
    return statement;
}

/// The rest of the tree's subject object, whose `{` was read: its name and digest are fixed.
fn parse_tree_subject(reader: *json.Reader, scratch: []u8) ParseError!Digest {
    try expect_key(reader, scratch, "name");
    if (!std.mem.eql(u8, try read_string(reader, scratch), tree_name)) return error.Malformed;
    try expect_key(reader, scratch, "digest");
    try dsse_expect(reader, scratch, .object_begin);
    try expect_key(reader, scratch, tree_digest_key);
    const digest = try read_digest(reader, scratch);
    try dsse_expect(reader, scratch, .object_end);
    try dsse_expect(reader, scratch, .object_end);
    return digest;
}

fn parse_binding(reader: *json.Reader, scratch: []u8, out: *Statement) ParseError!void {
    try expect_key(reader, scratch, "name");
    const name = try read_string(reader, scratch);
    if (name.len == 0) return error.Malformed;
    // The name comes before the digest key that says what it names, so keep it in the
    // statement's own buffer meanwhile.
    @memcpy(out.reference_text[0..name.len], name);
    out.reference_length = @intCast(name.len);
    try expect_key(reader, scratch, "digest");
    try dsse_expect(reader, scratch, .object_begin);
    const token = reader.next(scratch) catch return error.Malformed;
    const digest_key = switch (token) {
        .key => |found| found,
        else => return error.Malformed,
    };
    if (std.mem.eql(u8, digest_key, result_digest_key)) {
        if (!std.mem.eql(u8, out.reference(), result_name)) return error.Malformed;
        out.reference_length = 0;
        out.binding = .{ .result = try read_digest(reader, scratch) };
    } else if (std.mem.eql(u8, digest_key, manifest_digest_key)) {
        out.binding = .{ .manifest = try read_digest(reader, scratch) };
    } else {
        return error.Malformed;
    }
    try dsse_expect(reader, scratch, .object_end);
    try dsse_expect(reader, scratch, .object_end);
}

fn read_digest(reader: *json.Reader, scratch: []u8) ParseError!Digest {
    const text = try read_string(reader, scratch);
    if (text.len != 64) return error.Malformed;
    var digest: Digest = undefined;
    for (&digest, 0..) |*byte, index| {
        const high = hex_value(text[2 * index]) orelse return error.Malformed;
        const low = hex_value(text[2 * index + 1]) orelse return error.Malformed;
        byte.* = high << 4 | low;
    }
    return digest;
}

fn hex_value(char: u8) ?u8 {
    if (char >= '0' and char <= '9') return char - '0';
    if (char >= 'a' and char <= 'f') return char - 'a' + 10;
    return null;
}

fn dsse_expect(
    reader: *json.Reader,
    scratch: []u8,
    want: std.meta.Tag(json.Token),
) ParseError!void {
    dsse.expect(reader, scratch, want) catch return error.Malformed;
}

fn expect_key(reader: *json.Reader, scratch: []u8, name: []const u8) ParseError!void {
    dsse.expect_key(reader, scratch, name) catch return error.Malformed;
}

fn read_string(reader: *json.Reader, scratch: []u8) ParseError![]const u8 {
    return dsse.read_string(reader, scratch) catch return error.Malformed;
}

// ---- Time ----

pub const TimeText = [constants.signed_at_text_bytes]u8;

/// `2026-11-08T10:00:00Z` for `seconds` since the epoch.
pub fn format_time(seconds: u64) TimeText {
    assert(seconds <= constants.signed_at_seconds_max);
    const epoch: std.time.epoch.EpochSeconds = .{ .secs = seconds };
    const year_day = epoch.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch.getDaySeconds();
    var text: TimeText = undefined;
    const written = std.fmt.bufPrint(&text, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
    }) catch unreachable; // The year is at most 9999, so the text is always 20 bytes.
    assert(written.len == constants.signed_at_text_bytes);
    return text;
}

/// The seconds `text` names, or null unless it is exactly what `format_time` writes for them:
/// a date that does not exist, a lowercase `t`, a missing `Z` and an offset all fail the
/// re-render comparison.
pub fn parse_time(text: []const u8) ?u64 {
    if (text.len != constants.signed_at_text_bytes) return null;
    const year = digits(text[0..4]) orelse return null;
    const month = digits(text[5..7]) orelse return null;
    const day = digits(text[8..10]) orelse return null;
    const hour = digits(text[11..13]) orelse return null;
    const minute = digits(text[14..16]) orelse return null;
    const second = digits(text[17..19]) orelse return null;
    if (month < 1 or month > 12) return null;
    if (day < 1 or day > 31) return null;
    if (hour > 23 or minute > 59 or second > 59) return null;
    const days = days_from_civil(year, month, day);
    const seconds = days * 86400 + hour * 3600 + minute * 60 + second;
    if (seconds > constants.signed_at_seconds_max) return null;
    const again = format_time(seconds);
    if (!std.mem.eql(u8, &again, text)) return null;
    return seconds;
}

fn digits(text: []const u8) ?u64 {
    var value: u64 = 0;
    for (text) |char| {
        if (char < '0' or char > '9') return null;
        value = value * 10 + (char - '0');
    }
    return value;
}

/// Days from 1970-01-01 to the civil date (proleptic Gregorian), for years 1970 and later;
/// earlier years give a result that fails the re-render comparison in `parse_time`.
fn days_from_civil(year: u64, month: u64, day: u64) u64 {
    if (year < 1970) return 0;
    const shifted_year = if (month <= 2) year - 1 else year;
    const era = shifted_year / 400;
    const year_of_era = shifted_year - era * 400;
    const month_index = if (month > 2) month - 3 else month + 9;
    const day_of_year = (153 * month_index + 2) / 5 + day - 1;
    const day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    return era * 146097 + day_of_era - 719468;
}
