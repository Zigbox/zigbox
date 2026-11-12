//! Tests for `provenance.zig` and `provenance_view.zig`: the golden record, the round trip, the
//! record being a function of its inputs and times only, a worst-case record fitting every
//! buffer that holds one, and every kind of damage parse refuses.

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const digest_mod = @import("../store/digest.zig");
const provenance = @import("provenance.zig");
const view = @import("provenance_view.zig");
const key = @import("key.zig");

const Record = provenance.Record;

var record: Record = undefined;
var parsed: Record = undefined;
var out: [constants.statement_bytes_max]u8 = undefined;
var again: [constants.statement_bytes_max]u8 = undefined;
var second: [constants.statement_bytes_max]u8 = undefined;
var shown: [constants.inspect_provenance_bytes_max]u8 = undefined;

fn filled(byte: u8) provenance.Digest {
    return @splat(byte);
}

/// Two steps, the second needing the first, one base, a lock: the golden's record.
fn sample(into: *Record) void {
    into.clear();
    into.tree = filled(0x11);
    into.result = filled(0x22);
    into.set_build_file("/home/alice/project/zbx.build.zon");
    into.build_file_digest = filled(0x33);
    into.lock = filled(0x44);
    const base = into.add_base("docker.io/library/alpine:3.20", filled(0x55), filled(0x66));
    const compile = into.add_step("compile");
    compile.base = base;
    compile.key = filled(0x71);
    compile.input = filled(0x72);
    compile.output = filled(0x73);
    compile.network = true;
    const notice = into.add_step("notice");
    notice.base = base;
    notice.key = filled(0x81);
    notice.input = filled(0x82);
    notice.output = filled(0x83);
    notice.network = false;
    Record.add_need(notice, "compile", filled(0x73));
    into.image_key = filled(0x91);
    into.image_base = base;
    into.set_version("0.4.0", "linux/amd64");
    into.zbx = filled(0xa1);
    into.started = 1794132000; // 2026-11-08T10:00:00Z
    into.finished = 1794132042;
}

test "the golden record renders byte for byte and parses back" {
    // Goal: pin the record's bytes. Method: render the sample, compare with the golden file
    // (`testdata/provenance_golden.json`, checked once against the SLSA v1 provenance schema, see
    // docs/demos/m8.md), parse the golden and render what was read.
    sample(&record);
    const text = provenance.render(&out, &record);
    const golden = std.mem.trimEnd(u8, @embedFile("../testdata/provenance_golden.json"), "\n");
    try testing.expectEqualStrings(golden, text);
    try provenance.parse(golden, &parsed, &again);
    try testing.expectEqualStrings(golden, provenance.render(&second, &parsed));
    try testing.expectEqual(@as(u32, 2), parsed.steps_count);
    try testing.expectEqualStrings("notice", parsed.steps_slice()[1].text());
    try testing.expectEqualStrings("compile", parsed.steps_slice()[1].needs_slice()[0].text());
}

test "a record is a function of its inputs and its two times, and of nothing else" {
    // Goal: the same build gives the same bytes but for `startedOn` and `finishedOn`. Method:
    // render one record with two sets of times; the bytes differ only in the two time fields,
    // and they are equal once both are read back and set to the same times.
    sample(&record);
    const first = provenance.render(&out, &record);
    record.started += 3600;
    record.finished += 3601;
    const later = provenance.render(&second, &record);
    try testing.expectEqual(first.len, later.len);
    var differing: usize = 0;
    for (first, later) |a, b| differing += @intFromBool(a != b);
    try testing.expect(differing > 0 and differing <= 2 * "2026-11-08T10:00:00Z".len);
    try provenance.parse(first, &parsed, &again);
    parsed.started = record.started;
    parsed.finished = record.finished;
    try testing.expectEqualStrings(later, provenance.render(&again, &parsed));
}

/// The longest record the bounds allow: every step, each with every need and a base of its own,
/// names and references at their bounds, and a build file whose bytes each need six to write.
/// `value` as four decimal digits, so names stay distinct and valid UTF-8.
fn digits(target: *[4]u8, value: usize) void {
    assert(value < 10_000);
    var rest = value;
    for (0..4) |at| {
        target[3 - at] = '0' + @as(u8, @intCast(rest % 10));
        rest /= 10;
    }
}

fn worst(into: *Record) void {
    into.clear();
    into.tree = filled(0xff);
    into.result = filled(0xfe);
    var path: [constants.path_bytes_max]u8 = @splat(0x01); // Written as \u0001.
    into.set_build_file(&path);
    into.build_file_digest = filled(0xfd);
    into.lock = filled(0xfc);
    var name: [constants.build_step_name_bytes_max]u8 = undefined;
    var reference: [constants.reference_bytes_max]u8 = undefined;
    @memset(&reference, 'r');
    for (0..constants.provenance_steps_max) |at| {
        @memset(&name, 'a' + @as(u8, @intCast(at % 26)));
        digits(name[0..4], at);
        digits(reference[0..4], at);
        // The image's base takes the last of the bases; later steps share the first.
        const base = if (at + 1 < constants.provenance_bases_max)
            into.add_base(&reference, filled(@intCast(at)), filled(0x10))
        else
            0;
        const step = into.add_step(&name);
        step.base = base;
        step.key = filled(0xf0);
        step.input = filled(0xf1);
        step.output = filled(0xf2);
        step.network = true;
        for (0..constants.build_step_needs_max) |need_at| {
            @memset(&name, 'n');
            digits(name[0..4], need_at);
            Record.add_need(step, &name, filled(0xf3));
        }
    }
    digits(reference[0..4], 9999);
    into.image_base = into.add_base(&reference, filled(0xf4), filled(0xf5));
    into.image_key = filled(0xf6);
    const version: [constants.provenance_version_bytes_max]u8 = @splat('v');
    into.set_version(&version, "linux/aarch64");
    into.zbx = filled(0xf7);
    into.started = constants.signed_at_seconds_max;
    into.finished = constants.signed_at_seconds_max;
}

test "a worst-case record fits the statement bound, and its view fits the inspect bound" {
    // Goal: no buffer that holds a record is too small for one. Method: the longest record
    // renders into `statement_bytes_max`, parses back to itself, and, with eight signers, shows
    // in text and in JSON within `inspect_provenance_bytes_max`.
    comptime std.debug.assert(constants.provenance_bytes_max <= constants.statement_bytes_max);
    worst(&record);
    const text = provenance.render(&out, &record);
    try testing.expect(text.len <= constants.provenance_bytes_max);
    try provenance.parse(text, &parsed, &again);
    try testing.expectEqualStrings(text, provenance.render(&second, &parsed));
    var signers: [constants.signatures_per_tree_max]view.Signer = undefined;
    for (&signers, 0..) |*signer, at| {
        signer.* = .{ .public = @splat(@intCast(at)), .current = at % 2 == 0 };
    }
    const shown_view: view.View = .{
        .result = .{ .bytes = record.result },
        .record_digest = digest_mod.Digest.of(text),
        .record = &record,
        .signers = &signers,
    };
    var writer = std.Io.Writer.fixed(&shown);
    try view.render_json(&writer, &shown_view);
    try testing.expect(writer.buffered().len <= constants.inspect_provenance_bytes_max);
    writer = std.Io.Writer.fixed(&shown);
    try view.render_text(&writer, &shown_view);
    try testing.expect(writer.buffered().len <= constants.inspect_provenance_bytes_max);
}

test "parse refuses every damage to the golden and every other spelling" {
    // Goal: input is accepted only if it re-renders to itself. Method: change each byte of the
    // golden in turn (a few values each) and cut it at every length; whatever parses renders
    // to the bytes that were read.
    sample(&record);
    const text = provenance.render(&out, &record);
    var damaged: [constants.statement_bytes_max]u8 = undefined;
    for (0..text.len) |at| {
        try testing.expectError(error.Malformed, provenance.parse(text[0..at], &parsed, &again));
        for ([_]u8{ 0, '0', '"', 'z', 0xff }) |byte| {
            if (text[at] == byte) continue;
            @memcpy(damaged[0..text.len], text);
            damaged[at] = byte;
            provenance.parse(damaged[0..text.len], &parsed, &again) catch continue;
            const rendered = provenance.render(&second, &parsed);
            try testing.expectEqualSlices(u8, damaged[0..text.len], rendered);
        }
    }
    try testing.expectError(error.Malformed, provenance.parse("", &parsed, &again));
}

test "the key id is shown the way keys are everywhere" {
    // Goal: the view names a signer by `key_id`, 64 hex digits. Method: render one signer.
    sample(&record);
    const text = provenance.render(&out, &record);
    const signers = [_]view.Signer{.{ .public = @splat(7), .current = false }};
    const shown_view: view.View = .{
        .result = .{ .bytes = record.result },
        .record_digest = digest_mod.Digest.of(text),
        .record = &record,
        .signers = &signers,
    };
    var writer = std.Io.Writer.fixed(&shown);
    try view.render_text(&writer, &shown_view);
    const id = key.key_id(signers[0].public);
    try testing.expect(std.mem.indexOf(u8, writer.buffered(), &id) != null);
    try testing.expect(std.mem.indexOf(u8, writer.buffered(), "an earlier build") != null);
}
