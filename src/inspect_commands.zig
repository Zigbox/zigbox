//! `zbx inspect <result digest>`: what a build produced (`build/result.zig`), read from the
//! record under `build/results`: the digest of the record, the tree it names and the config the
//! image runs with. Text is a few labelled lines; `--output json` is the `zbx.build_result/1`
//! document (`zbx schema inspect`). It only reads.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const bundle = @import("bundle.zig");
const build_diagnose = @import("build/diagnose.zig");
const errors = @import("diag/errors.zig");
const host_mod = @import("host.zig");
const open = @import("store/open.zig");
const result = @import("build/result.zig");
const store_diagnose = @import("store/diagnose.zig");
const text_util = @import("text.zig");
const Diag = @import("diag/diag.zig").Diag;
const Digest = @import("store/digest.zig").Digest;
const Host = host_mod.Host;
const Store = @import("store/layout.zig").Store;

pub const Error = error{ Failed, OutputFailed };

pub const Workspace = struct {
    record: result.Record,
    bytes: [constants.build_result_bytes_max + 1]u8,
    out: [constants.inspect_output_bytes_max]u8,
};

/// One word of the text form is shown cut to this many bytes.
const shown_bytes_max = 1024;

/// Prints the record named `operand`, a full digest.
pub fn run(host: Host, ws: *Workspace, operand: []const u8, json: bool, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(operand.len <= constants.arg_bytes_max);
    const digest = Digest.parse(operand) orelse {
        build_diagnose.result_operand(diag, operand, false);
        return error.Failed;
    };
    var store: Store = undefined;
    if (!store.locate(host)) {
        store_diagnose.no_data_directory(diag);
        return error.Failed;
    }
    const present = open.check(&store, .existing, diag) catch return error.Failed;
    var errno: u16 = 0;
    const loaded = if (present)
        result.load(&store, digest, &ws.record, &ws.bytes, &errno)
    else
        error.NotFound;
    loaded catch |err| switch (err) {
        error.NotFound => {
            build_diagnose.result_operand(diag, operand, true);
            return error.Failed;
        },
        error.Damaged, error.Newer => {
            build_diagnose.result_unusable(diag, digest, err == error.Newer);
            return error.Failed;
        },
        error.Unreadable => {
            const failed = error.IoFailed;
            store_diagnose.cannot_read(diag, &store, "reading the build result", failed, errno);
            return error.Failed;
        },
    };
    var writer = std.Io.Writer.fixed(&ws.out);
    const rendered = if (json)
        render_json(&writer, digest, &ws.record)
    else
        render_text(&writer, digest, &ws.record);
    // Cannot fail: `inspect_output_bytes_max` holds the largest record, escaped.
    rendered catch unreachable;
    host.write_all(.stdout, writer.buffered()) catch |err| {
        errors.output_failed(diag, .stdout, err, host.last_errno());
        return error.OutputFailed;
    };
}

fn json_list(writer: *std.Io.Writer, config: *const result.Config, list: anytype) !void {
    const settings = &config.settings;
    try writer.writeByte('[');
    for (0..settings.count(list)) |at| {
        if (at > 0) try writer.writeByte(',');
        try bundle.write_json_string(writer, settings.word(list, @intCast(at)));
    }
    try writer.writeByte(']');
}

/// The `zbx.build_result/1` document, one line.
pub fn render_json(writer: *std.Io.Writer, digest: Digest, record: *const result.Record) !void {
    assert(writer.buffer.len >= constants.inspect_output_bytes_max);
    const config = &record.config;
    try writer.print("{{\"schema\":\"zbx.build_result/1\",\"digest\":\"{s}\",\"tree\":\"{s}\"," ++
        "\"config\":{{", .{ &digest.text(), &record.tree.text() });
    inline for (.{ "entrypoint", "cmd", "env" }) |name| {
        try writer.print("\"{s}\":", .{name});
        try json_list(writer, config, @field(@TypeOf(config.settings).List, name));
        try writer.writeByte(',');
    }
    try writer.writeAll("\"workdir\":");
    try bundle.write_json_string(writer, config.settings.get(.workdir));
    try writer.writeAll(",\"user\":");
    try bundle.write_json_string(writer, config.settings.get(.user));
    try writer.writeAll(",\"labels\":{");
    for (0..config.labels_count) |at| {
        if (at > 0) try writer.writeByte(',');
        try bundle.write_json_string(writer, config.label_key(@intCast(at)));
        try writer.writeByte(':');
        try bundle.write_json_string(writer, config.label_value(@intCast(at)));
    }
    try writer.writeAll("}}}\n");
}

fn text_line(writer: *std.Io.Writer, name: []const u8, value: []const u8) !void {
    var storage: [shown_bytes_max]u8 = undefined;
    try writer.print("{s: <11}{s}\n", .{ name, text_util.sanitise(&storage, value) });
}

fn text_list(writer: *std.Io.Writer, config: *const result.Config, list: anytype) !void {
    const settings = &config.settings;
    for (0..settings.count(list)) |at| {
        const name = if (at == 0) @tagName(list) else "";
        try text_line(writer, name, settings.word(list, @intCast(at)));
    }
}

/// The labelled lines: the result, the tree, then each list one word to a line.
pub fn render_text(writer: *std.Io.Writer, digest: Digest, record: *const result.Record) !void {
    assert(writer.buffer.len >= constants.inspect_output_bytes_max);
    const config = &record.config;
    try text_line(writer, "result", &digest.text());
    try text_line(writer, "tree", &record.tree.text());
    try text_list(writer, config, .entrypoint);
    try text_list(writer, config, .cmd);
    try text_list(writer, config, .env);
    try text_line(writer, "workdir", config.settings.get(.workdir));
    try text_line(writer, "user", config.settings.get(.user));
    for (0..config.labels_count) |at| {
        const name = if (at == 0) "labels" else "";
        var storage: [shown_bytes_max]u8 = undefined;
        var line: [shown_bytes_max * 2 + 1]u8 = undefined;
        const key = text_util.sanitise(&storage, config.label_key(@intCast(at)));
        const joined = std.fmt.bufPrint(&line, "{s}=", .{key}) catch unreachable; // Fits.
        try writer.print("{s: <11}{s}", .{ name, joined });
        const value = text_util.sanitise(&storage, config.label_value(@intCast(at)));
        try writer.print("{s}\n", .{value});
    }
}
