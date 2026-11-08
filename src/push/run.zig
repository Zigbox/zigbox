//! The packing steps the commands share: find the source, pack it, and write the layout.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;
const diagnose = @import("diagnose.zig");
const export_mod = @import("export.zig");
const json = @import("../trust/json.zig");
const layout = @import("../store/layout.zig");
const pack = @import("pack.zig");
const source_mod = @import("source.zig");

const Store = layout.Store;

pub const Error = error{Failed};

/// About 9 MiB; keep it in static or heap storage.
pub const Workspace = struct {
    source_memory: source_mod.Workspace,
    source: source_mod.Source,
    pack: pack.Workspace,
};

/// Packs what `operand` names into the store's blob cache. A refusal is on `diag`.
pub fn pack_operand(
    store: *Store,
    ws: *Workspace,
    operand: []const u8,
    out: *pack.Packed,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    assert(operand.len > 0);
    source_mod.resolve(store, &ws.source_memory, operand, &ws.source) catch |err| {
        const why = switch (err) {
            error.NotFound => "the store has no build result, image or tree by that name",
            error.Unusable => "a record of the store is damaged or cannot be read",
        };
        diagnose.cannot_pack(diag, operand, why);
        return error.Failed;
    };
    const input: pack.Input = .{
        .tree = ws.source.tree,
        .settings = &ws.source.settings,
        .labels = ws.source.labels(),
    };
    var failure: pack.Failure = undefined;
    pack.pack(store, &ws.pack, input, out, &failure) catch {
        diagnose.pack_stopped(diag, operand, &failure);
        return error.Failed;
    };
    // The image record lets `zbx run` and `zbx sign` find the manifest on this host.
    var fail: @import("../store/fs.zig").Failure = undefined;
    pack.record_image(store, out, input, "", &fail) catch {
        diagnose.pack_stopped(diag, operand, &.{
            .stop = .write,
            .errno = fail.errno,
            .digest = out.tree,
        });
        return error.Failed;
    };
}

/// Packs `operand` and writes its layout to `dir`.
pub fn export_operand(
    store: *Store,
    ws: *Workspace,
    operand: []const u8,
    dir: []const u8,
    out: *export_mod.Exported,
    diag: *Diag,
) Error!void {
    var failure: export_mod.Failure = undefined;
    export_mod.check_target(store.fs, dir, &failure) catch {
        diagnose.export_stopped(diag, dir, &failure);
        return error.Failed;
    };
    var made: pack.Packed = undefined;
    try pack_operand(store, ws, operand, &made, diag);
    export_mod.export_layout(store, &made, dir, &ws.pack.io, out, &failure) catch {
        diagnose.export_stopped(diag, dir, &failure);
        return error.Failed;
    };
}

/// The result line of `--output json`: `zbx.export/1`.
pub fn export_json(
    out: *const export_mod.Exported,
    dir: []const u8,
    buffer: []u8,
) json.WriteError![]const u8 {
    var writer = json.Writer.init(buffer);
    try writer.begin_object();
    try writer.member_string("config", &out.config.text());
    try writer.member_string("dir", dir);
    try writer.member_string("layer", &out.layer.text());
    try writer.member_string("manifest", &out.manifest.text());
    try writer.member_string("schema", "zbx.export/1");
    try writer.member_unsigned("size", out.total_size);
    try writer.end_object();
    return writer.finish();
}
