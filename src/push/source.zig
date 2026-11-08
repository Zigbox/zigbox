//! What a pack is made from: a build result (a tree and the config the build resolved), a
//! reference of a pulled or pushed image, or a tree digest (a tree with an image record keeps its
//! image's settings; a bare tree has none).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const result_mod = @import("../build/result.zig");
const digest_mod = @import("../store/digest.zig");
const image_find = @import("../store/image_find.zig");
const images = @import("../store/images.zig");
const layout = @import("../store/layout.zig");

const Digest = digest_mod.Digest;
const Store = layout.Store;

pub const Error = error{ NotFound, Unusable };

/// The memory a resolution needs.
pub const Workspace = struct {
    result_bytes: [constants.build_result_bytes_max + 1]u8,
    memory: image_find.Memory,
    image: images.Image,
};

pub const Source = struct {
    tree: Digest,
    settings: images.Settings,
    /// A build result's labels are the image's; null for any other source.
    record: result_mod.Record,
    from_result: bool,

    pub fn labels(source: *const Source) ?*const result_mod.Config {
        return if (source.from_result) &source.record.config else null;
    }
};

/// Finds `operand`. `NotFound`: nothing of the store is named so. `Unusable`: a record that is
/// damaged, newer, or cannot be read.
pub fn resolve(store: *const Store, ws: *Workspace, operand: []const u8, out: *Source) Error!void {
    assert(operand.len > 0);
    assert(store.root_len > 1);
    out.from_result = false;
    out.settings.clear();
    if (Digest.parse(operand)) |digest| {
        var errno: u16 = 0;
        if (result_mod.load(store, digest, &out.record, &ws.result_bytes, &errno)) |_| {
            out.tree = out.record.tree;
            out.settings = out.record.config.settings;
            out.from_result = true;
            return;
        } else |err| if (err != error.NotFound) return error.Unusable;
        out.tree = digest;
        var by: image_find.ByTree = .{ .tree = digest };
        image_find.scan(store, &ws.memory, &ws.image, &by) catch return error.Unusable;
        if (by.count > 0) try take_settings(store, ws, by.manifest, out);
        return;
    }
    var by: image_find.ByReference = .{ .text = operand };
    image_find.scan(store, &ws.memory, &ws.image, &by) catch return error.Unusable;
    if (!by.found) return error.NotFound;
    out.tree = by.tree;
    try take_settings(store, ws, by.manifest, out);
}

fn take_settings(store: *const Store, ws: *Workspace, manifest: anytype, out: *Source) Error!void {
    var errno: u16 = 0;
    images.load(store, manifest, &ws.image, &errno) catch return error.Unusable;
    out.settings = ws.image.settings;
}
