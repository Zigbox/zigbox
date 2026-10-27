//! `zbx pull`. In this slice of M4 the command resolves: `zbx pull --resolve-only <reference>`
//! asks the registry what the reference names for this machine's platform and prints the digest
//! of that image's manifest (the digest a lock file records), without fetching any layer. Text is
//! the digest on a line; `--output json` is one object (`zbx schema pull-resolve`).
//!
//! The network work runs here, in the parent, before and outside any namespace child.

const std = @import("std");
const assert = std.debug.assert;
const client_mod = @import("registry/client.zig");
const constants = @import("constants.zig");
const diagnose = @import("registry/diagnose.zig");
const errors = @import("diag/errors.zig");
const host_mod = @import("host.zig");
const manifest = @import("registry/manifest.zig");
const reference_mod = @import("registry/reference.zig");
const Diag = @import("diag/diag.zig").Diag;

const Host = host_mod.Host;

pub const Error = error{ Failed, OutputFailed };

/// What resolving works in: the client's memory, the result, and the text of the JSON result.
pub const Workspace = struct {
    client: client_mod.Workspace,
    resolved: manifest.Resolved,
    output: [constants.pull_output_bytes_max]u8,
};

pub const Args = struct {
    reference: []const u8,
    json: bool,
};

pub fn run_resolve(host: Host, args: Args, workspace: *Workspace, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(args.reference.len <= constants.arg_bytes_max);
    var reference: reference_mod.Reference = undefined;
    reference_mod.parse(args.reference, &reference) catch |err| {
        diagnose.bad_reference(diag, args.reference, err);
        return error.Failed;
    };
    // A host that cannot say its machine type gets an empty one, which has no image platform:
    // the refusal says so. `uname` does not fail on a real kernel.
    const uname = host.uname() catch host_mod.Uname{
        .release = host_mod.Text.from_slice(""),
        .machine = host_mod.Text.from_slice(""),
    };
    var machine = uname.machine;
    var client = client_mod.Client.init(host.network(), &workspace.client, machine.slice());
    client_mod.resolve(&client, &reference, &workspace.resolved, diag) catch return error.Failed;
    const text = render(args.json, &reference, &workspace.resolved, &workspace.output);
    host.write_all(.stdout, text) catch |err| {
        errors.output_failed(diag, .stdout, err, host.last_errno());
        return error.OutputFailed;
    };
}

fn render(
    json: bool,
    reference: *const reference_mod.Reference,
    resolved: *const manifest.Resolved,
    buffer: *[constants.pull_output_bytes_max]u8,
) []const u8 {
    var writer = std.Io.Writer.fixed(buffer);
    // Cannot fail: the buffer holds the largest result (128 layers, the constants assert it).
    if (json) write_json(&writer, reference, resolved) catch unreachable else {
        writer.print("{s}\n", .{&resolved.manifest_digest.text()}) catch unreachable; // Same.
    }
    const text = writer.buffered();
    assert(text.len > 0);
    assert(text[text.len - 1] == '\n');
    return text;
}

fn write_json(
    writer: *std.Io.Writer,
    reference: *const reference_mod.Reference,
    resolved: *const manifest.Resolved,
) std.Io.Writer.Error!void {
    var formatted: reference_mod.Formatted = undefined;
    try writer.print("{{\"schema\":\"zbx.pull.resolve/1\",\"reference\":\"{s}\",", .{reference.format(&formatted)});
    try writer.print("\"registry\":\"{s}\",\"repository\":\"{s}\",", .{ reference.registry(), reference.repository() });
    try writer.writeAll("\"index_digest\":");
    if (resolved.index_digest) |digest| {
        try writer.print("\"{s}\",", .{&digest.text()});
    } else {
        try writer.writeAll("null,");
    }
    try writer.print("\"manifest_digest\":\"{s}\",\"manifest_size\":{d},", .{ &resolved.manifest_digest.text(), resolved.manifest_size });
    try writer.print("\"platform\":\"linux/{s}\",", .{resolved.architecture.name()});
    try writer.print("\"config_digest\":\"{s}\",\"config_size\":{d},\"layers\":[", .{ &resolved.config_digest.text(), resolved.config_size });
    for (resolved.layers[0..resolved.layer_count], 0..) |layer, index| {
        if (index > 0) try writer.writeAll(",");
        try writer.print("{{\"digest\":\"{s}\",\"size\":{d},\"kind\":\"{s}\"}}", .{ &layer.digest.text(), layer.size, @tagName(layer.kind) });
    }
    try writer.writeAll("]}\n");
}
