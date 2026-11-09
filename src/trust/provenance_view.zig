//! `zbx inspect --provenance` (docs/briefs/M8-trust.md, "Provenance"): a stored provenance
//! record as labelled text, or as the `zbx.provenance/1` document. Pure: it writes what it is
//! given into a fixed writer of `inspect_provenance_bytes_max` bytes.
//!
//! The view says what the record says and which keys have signed a provenance statement of the
//! result's tree, and whether each signed these very bytes ("this record") or the record of an
//! earlier build of the same result ("an earlier build"): a later build replaces the stored
//! record, and a signature made before that vouches for the old one.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const bundle = @import("../bundle.zig");
const digest_mod = @import("../store/digest.zig");
const oci_digest = @import("../registry/digest.zig");
const text_util = @import("../text.zig");
const key = @import("key.zig");
const provenance = @import("provenance.zig");

const Digest = digest_mod.Digest;

/// One signature of the tree that is a provenance statement.
pub const Signer = struct {
    public: [constants.key_public_bytes]u8,
    /// The envelope's payload is the stored record's bytes.
    current: bool,
};

pub const View = struct {
    result: Digest,
    /// The digest of the record's bytes.
    record_digest: Digest,
    record: *const provenance.Record,
    signers: []const Signer,
};

pub const schema = "zbx.provenance/1";

fn digest_text(bytes: [32]u8) [constants.store_digest_text_bytes]u8 {
    return (Digest{ .bytes = bytes }).text();
}

fn manifest_text(bytes: [32]u8) [constants.oci_digest_text_bytes]u8 {
    return (oci_digest.Sha256{ .bytes = bytes }).text();
}

fn word(writer: *std.Io.Writer, text: []const u8) !void {
    try bundle.write_json_string(writer, text);
}

fn current_word(signer: Signer) []const u8 {
    return if (signer.current) "this record" else "an earlier build";
}

/// The `zbx.provenance/1` document, one line.
pub fn render_json(writer: *std.Io.Writer, view: *const View) !void {
    assert(writer.buffer.len >= constants.inspect_provenance_bytes_max);
    const record = view.record;
    try writer.print("{{\"schema\":\"{s}\",\"result\":\"{s}\",\"tree\":\"{s}\"," ++
        "\"record\":\"{s}\",\"build_file\":{{\"name\":", .{
        schema,
        &view.result.text(),
        &digest_text(record.tree),
        &view.record_digest.text(),
    });
    try word(writer, record.build_file_text());
    try writer.print(",\"digest\":\"{s}\"}},\"lock\":", .{&digest_text(record.build_file_digest)});
    if (record.lock) |lock| {
        try writer.print("\"{s}\"", .{&digest_text(lock)});
    } else try writer.writeAll("null");
    try writer.writeAll(",\"builder\":{\"version\":");
    try word(writer, record.version_text());
    try writer.writeAll(",\"platform\":");
    try word(writer, record.platform_text());
    try writer.print(",\"zbx\":\"{s}\"}},\"started\":{d},\"finished\":{d},\"bases\":[", .{
        &digest_text(record.zbx), record.started, record.finished,
    });
    try json_bases(writer, record);
    try writer.writeAll("],\"steps\":[");
    try json_steps(writer, record);
    try writer.print("],\"image\":{{\"key\":\"{s}\",\"base\":", .{&digest_text(record.image_key)});
    if (record.image_base) |at| {
        try writer.print("{d}", .{at});
    } else try writer.writeAll("null");
    try writer.writeAll("},\"signatures\":[");
    for (view.signers, 0..) |signer, at| {
        if (at > 0) try writer.writeByte(',');
        try writer.print("{{\"key\":\"{s}\",\"id\":\"{s}\",\"signed\":\"{s}\"}}", .{
            &key.public_text(signer.public), &key.key_id(signer.public), current_word(signer),
        });
    }
    try writer.writeAll("]}\n");
}

fn json_bases(writer: *std.Io.Writer, record: *const provenance.Record) !void {
    for (record.bases_slice(), 0..) |base, at| {
        if (at > 0) try writer.writeByte(',');
        try writer.writeAll("{\"reference\":");
        try word(writer, base.text());
        try writer.print(",\"manifest\":\"{s}\",\"tree\":\"{s}\"}}", .{
            &manifest_text(base.manifest), &digest_text(base.tree),
        });
    }
}

fn json_steps(writer: *std.Io.Writer, record: *const provenance.Record) !void {
    for (record.steps_slice(), 0..) |step, at| {
        if (at > 0) try writer.writeByte(',');
        try writer.writeAll("{\"name\":");
        try word(writer, step.text());
        try writer.print(",\"key\":\"{s}\",\"base\":{d},\"input\":\"{s}\",\"needs\":{{", .{
            &digest_text(step.key), step.base, &digest_text(step.input),
        });
        for (step.needs_slice(), 0..) |need, number| {
            if (number > 0) try writer.writeByte(',');
            try word(writer, need.text());
            try writer.print(":\"{s}\"", .{&digest_text(need.output)});
        }
        try writer.print("}},\"output\":\"{s}\",\"network\":{}}}", .{
            &digest_text(step.output), step.network,
        });
    }
}

fn line(writer: *std.Io.Writer, name: []const u8, value: []const u8) !void {
    var storage: [1024]u8 = undefined;
    try writer.print("{s: <12}{s}\n", .{ name, text_util.sanitise(&storage, value) });
}

/// The labelled lines.
pub fn render_text(writer: *std.Io.Writer, view: *const View) !void {
    assert(writer.buffer.len >= constants.inspect_provenance_bytes_max);
    const record = view.record;
    try line(writer, "result", &view.result.text());
    try line(writer, "tree", &digest_text(record.tree));
    try line(writer, "record", &view.record_digest.text());
    try line(writer, "build file", record.build_file_text());
    try line(writer, "", &digest_text(record.build_file_digest));
    try line(writer, "lock", if (record.lock) |lock| &digest_text(lock) else "none");
    var storage: [192]u8 = undefined;
    const builder = std.fmt.bufPrint(&storage, "zbx {s}  {s}  {s}", .{
        record.version_text(), record.platform_text(), &digest_text(record.zbx),
    }) catch unreachable; // 4 + 64 + 2 + 16 + 2 + 67 fits.
    try line(writer, "builder", builder);
    try writer.print("{s: <12}{d}\n{s: <12}{d}\n", .{
        "started", record.started, "finished", record.finished,
    });
    for (record.bases_slice(), 0..) |base, at| try text_base(writer, at, &base);
    for (record.steps_slice()) |*step| try text_step(writer, step);
    try text_image(writer, record);
    for (view.signers) |signer| {
        var named: [128]u8 = undefined;
        const text = std.fmt.bufPrint(&named, "{s}  {s}", .{
            &key.key_id(signer.public), current_word(signer),
        }) catch unreachable; // A 64-byte id and a short phrase fit.
        try line(writer, "signed", text);
    }
}

fn text_base(writer: *std.Io.Writer, at: usize, base: *const provenance.Base) !void {
    var storage: [1024 + 8]u8 = undefined;
    const text = std.fmt.bufPrint(&storage, "{d}  {s}", .{ at, base.text() }) catch
        unreachable; // A number and a reference fit.
    try line(writer, "base", text); // `text` holds a number and a reference, which fit.
    try line(writer, "", &manifest_text(base.manifest));
    try line(writer, "", &digest_text(base.tree));
}

fn text_step(writer: *std.Io.Writer, step: *const provenance.Step) !void {
    const net = if (step.network) "  network" else "";
    var storage: [128]u8 = undefined;
    const head = std.fmt.bufPrint(&storage, "{s}  base {d}{s}", .{
        step.text(), step.base, net,
    }) catch unreachable; // A step name, a number and a word fit.
    try line(writer, "step", head);
    try line(writer, "  key", &digest_text(step.key));
    try line(writer, "  input", &digest_text(step.input));
    for (step.needs_slice()) |need| {
        var named: [128]u8 = undefined;
        const text = std.fmt.bufPrint(&named, "{s}  {s}", .{
            need.text(), &digest_text(need.output),
        }) catch unreachable; // A name and a digest fit.
        try line(writer, "  needs", text);
    }
    try line(writer, "  output", &digest_text(step.output));
}

fn text_image(writer: *std.Io.Writer, record: *const provenance.Record) !void {
    try line(writer, "image key", &digest_text(record.image_key));
    var storage: [16]u8 = undefined;
    const base = if (record.image_base) |at|
        std.fmt.bufPrint(&storage, "{d}", .{at}) catch unreachable // A number fits.
    else
        "none";
    try line(writer, "image base", base);
}
