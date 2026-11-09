//! The packing steps the commands share: find the source, pack it, and write the layout.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;
const diagnose = @import("diagnose.zig");
const credentials_mod = @import("credentials.zig");
const fs_mod = @import("../store/fs.zig");
const export_mod = @import("export.zig");
const json = @import("../trust/json.zig");
const layout = @import("../store/layout.zig");
const images = @import("../store/images.zig");
const net = @import("../registry/net.zig");
const pack = @import("pack.zig");
const reference_mod = @import("../registry/reference.zig");
const upload = @import("upload.zig");
const source_mod = @import("source.zig");

const Store = layout.Store;

pub const Error = error{Failed};

/// About 9 MiB; keep it in static or heap storage.
pub const Workspace = struct {
    source_memory: source_mod.Workspace,
    source: source_mod.Source,
    pack: pack.Workspace,
    upload: upload.Workspace,
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

/// What a push needs besides the source: where it goes.
pub const Pushed = struct {
    report: upload.Report,
    /// The destination as parsed and written: "registry.example/team/app:1.0".
    destination: reference_mod.Formatted,
    destination_len: u16,
    /// Set when the registry holds the image and this host's store could not record the tag.
    record_failure: ?fs_mod.Failure,

    pub fn destination_text(pushed: *const Pushed) []const u8 {
        assert(pushed.destination_len <= pushed.destination.len);
        return pushed.destination[0..pushed.destination_len];
    }
};

/// Checks that `operand` is a reference that names a tag and nothing else.
pub fn parse_destination(
    operand: []const u8,
    out: *reference_mod.Reference,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    assert(operand.len > 0);
    reference_mod.parse(operand, out) catch {
        diagnose.destination_refused(diag, operand, "it is not a registry reference");
        return error.Failed;
    };
    if (out.digest != null) {
        diagnose.destination_refused(diag, operand, "a push goes to a tag, not to a digest");
        return error.Failed;
    }
    // The parser fills in `latest`; a push names its tag.
    const last = std.mem.lastIndexOfScalar(u8, operand, '/') orelse 0;
    if (std.mem.indexOfScalar(u8, operand[last..], ':') == null) {
        diagnose.destination_refused(diag, operand, "it names no tag");
        return error.Failed;
    }
}

/// Another repository on the destination's registry that already holds this image's blobs,
/// by the tags the store's record of it carries; empty for none.
fn mount_holder(
    store: *const Store,
    made: *const pack.Packed,
    destination: *const reference_mod.Reference,
    out: *reference_mod.Reference,
) []const u8 {
    var image: images.Image = undefined;
    var errno: u16 = 0;
    images.load(store, made.manifest, &image, &errno) catch return "";
    for (0..image.tag_count) |index| {
        reference_mod.parse(image.tag_text(@intCast(index)), out) catch continue;
        if (!std.mem.eql(u8, out.registry(), destination.registry())) continue;
        if (std.mem.eql(u8, out.repository(), destination.repository())) continue;
        return out.repository();
    }
    return "";
}

/// Packs `operand` and pushes it to `destination` (a reference with a tag). The tag is recorded
/// on the image in the store once the registry holds the manifest.
pub fn push_operand(
    store: *Store,
    ws: *Workspace,
    wire: net.Net,
    operand: []const u8,
    destination: *const reference_mod.Reference,
    credentials: ?*const credentials_mod.Credentials,
    out: *Pushed,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    assert(destination.tag() != null);
    var made: pack.Packed = undefined;
    try pack_operand(store, ws, operand, &made, diag);
    var holder: reference_mod.Reference = undefined;
    const from = mount_holder(store, &made, destination, &holder);
    const options: upload.Options = .{ .mount_from = from, .credentials = credentials };
    const target = upload.Destination.of(destination);
    upload.push(store, &ws.upload, wire, target, &made, options, &out.report, diag) catch
        return error.Failed;
    out.destination_len = @intCast(destination.format(&out.destination).len);
    const input: pack.Input = .{
        .tree = ws.source.tree,
        .settings = &ws.source.settings,
        .labels = ws.source.labels(),
    };
    var fail: fs_mod.Failure = undefined;
    out.record_failure = null;
    // The push is done and the registry holds it; a record that cannot be written costs the tag
    // on this host only, so it is not a failure of the push: the caller warns (W0552).
    pack.record_image(store, &made, input, out.destination_text(), &fail) catch {
        out.record_failure = fail;
    };
}

fn outcome_word(outcome: upload.Outcome) []const u8 {
    return @tagName(outcome);
}

/// The result line of `--output json`: `zbx.push/1`.
pub fn push_json(pushed: *const Pushed, buffer: []u8) json.WriteError![]const u8 {
    var writer = json.Writer.init(buffer);
    try writer.begin_object();
    try writer.member_array("blobs");
    for (pushed.report.blobs()) |sent| {
        try writer.begin_object();
        try writer.member_string("digest", &sent.digest.text());
        try writer.member_string("outcome", outcome_word(sent.outcome));
        try writer.member_unsigned("size", sent.size);
        try writer.end_object();
    }
    try writer.end_array();
    try writer.member_string("destination", pushed.destination_text());
    try writer.member_string("manifest", &pushed.report.manifest.text());
    try writer.member_string("schema", "zbx.push/1");
    try writer.end_object();
    return writer.finish();
}
