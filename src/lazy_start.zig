//! `zbx run --lazy` of an image the store does not have (S2 slice 5): resolves the reference,
//! reads the layer's `org.zigbox.lazy-index` anchor, fetches the index by `Range`, inflates and
//! verifies it against the manifest's `org.zigbox.tree` (`E1202` when it fails, before anything
//! is written), stores the tree's directories with `trees.put_checked`, and writes the image's
//! record with `partial = true` (version 4, `store/images.zig`), as a pull writes its record: it
//! roots the tree and keeps the config blob for gc, and `zbx images` shows the image. The run
//! composes from the same record in memory. The registry client stays resolved for the run's
//! chunk fetches (`RegistryRange`).
//!
//! An image without an anchor is `W1201`: the caller pulls it whole, as without `--lazy`.

const std = @import("std");
const assert = std.debug.assert;
const flate = std.compress.flate;
const constants = @import("constants.zig");
const client_mod = @import("registry/client.zig");
const host_mod = @import("host.zig");
const images = @import("store/images.zig");
const index_mod = @import("lazy/index.zig");
const lazy_diagnose = @import("fuse/diagnose.zig");
const namespace = @import("store/namespace.zig");
const object = @import("store/object.zig");
const pull_commands = @import("pull_commands.zig");
const pull_lib = @import("pull.zig");
const pull_unpack = @import("pull_unpack.zig");
const registry_range = @import("lazy/registry_range.zig");
const store_diagnose = @import("store/diagnose.zig");
const trees = @import("store/trees.zig");
const verify_mod = @import("lazy/verify.zig");
const Diag = @import("diag/diag.zig").Diag;
const Digest = @import("store/digest.zig").Digest;
const Host = host_mod.Host;
const Sha256 = @import("registry/digest.zig").Sha256;
const Store = @import("store/layout.zig").Store;

pub const Error = error{
    /// The reason is in the diagnostic.
    Failed,
};

/// About 160 MiB, nearly all of it untouched unless an index that large comes: keep it in static
/// storage. It lives for the run: `index` points into `index_bytes`, and `range` uses `client`.
pub const Workspace = struct {
    client: client_mod.Client,
    checking: verify_mod.Workspace,
    compressed: [index_mod.compressed_bytes_max + index_mod.range_trailer.len]u8,
    window: [flate.max_window_len]u8,
    index_bytes: [constants.lazy_index_bytes_max]u8,
    index: index_mod.Index,
    /// The layer blob the index and the chunks are in.
    layer: Sha256,
    /// The index's compressed bytes fetched from the layer: the progress line's "index 2.1 MiB".
    index_fetched: u64,
    range: registry_range.RegistryRange,
};

pub const Outcome = enum {
    /// The index is verified and the trees are in the store: run lazily.
    lazy,
    /// No anchor, or more than one layer (`W1201` was given to `warn`): pull the image whole.
    whole,
    /// The store holds the image whole already: run it from there, as without `--lazy`. Its
    /// record is left as it is (never rewritten as partial), and nothing was said.
    local,
};

/// Resolves `text` (a tag or a digest reference) and readies its lazy start, or says it has no
/// index. On `lazy`, `image` holds the manifest, the config, the tree and the settings, and
/// `ws.index` the verified index; the caller attaches them to the server, and wipes the client
/// when the run ends (`finish`).
pub fn start(
    host: Host,
    pull: *pull_commands.Workspace,
    ws: *Workspace,
    store: *Store,
    text: []const u8,
    warn: ?namespace.Warn,
    image: *images.Image,
    diag: *Diag,
) Error!Outcome {
    assert(diag.code == null);
    assert(text.len > 0);
    const library = &pull.library;
    pull_lib.parse_reference(library, text, diag) catch return error.Failed;
    errdefer client_mod.Workspace.wipe(&library.client);
    {
        defer pull.aws.wipe();
        defer pull.google.wipe();
        const request = pull_commands.request_of(host, text, pull, diag) catch {
            return error.Failed;
        };
        pull_lib.resolve_with(host, &request, library, &ws.client, diag) catch {
            return error.Failed;
        };
        // The fallback's storage is wiped here; the ranges re-ask with what the client holds.
        ws.client.realm_fallback = null;
    }
    const resolved = &library.resolved;
    if (held_whole(store, resolved.manifest_digest, image)) {
        client_mod.Workspace.wipe(&library.client);
        return .local;
    }
    if (resolved.layer_count != 1) {
        client_mod.Workspace.wipe(&library.client);
        warn_layers(warn, text, resolved.layer_count);
        return .whole;
    }
    const anchor = resolved.lazy_index orelse {
        client_mod.Workspace.wipe(&library.client);
        warn_no_index(warn, text);
        return .whole;
    };
    const note = resolved.tree_note orelse {
        lazy_diagnose.index_refused(diag, text, .no_tree);
        return error.Failed;
    };
    const tree: Digest = .{ .bytes = note };
    pull_lib.fetch_settings(&ws.client, library, store, diag) catch return error.Failed;
    ws.layer = resolved.layers[0].digest;
    try fetch_index(host, ws, &library.reference, &anchor, tree, text, diag);
    try put_trees(store, &ws.index, diag);
    fill_image(host, store, image, library, tree, text);
    try save_image(store, image, diag);
    return .lazy;
}

/// Wipes the client's token and state; the run that used `ws.range` has ended.
pub fn finish(pull: *pull_commands.Workspace, lazy: ?*Workspace) void {
    assert(pull.library.reference.registry_len > 0);
    wipe(pull, lazy);
}

/// Wipes the client's secrets whether or not a lazy start resolved anything: the `defer` of a
/// lazy run, so an exit between the start and the run's own `finish` (a refusal by the gate, a
/// bad flag, a failed compose) leaves no token behind. Wiping twice is harmless.
/// `lazy` is the start's workspace, whose client holds the token's length: zeroed with the
/// bytes, so no client reads a wiped token as a live one.
pub fn wipe(pull: *pull_commands.Workspace, lazy: ?*Workspace) void {
    client_mod.Workspace.wipe(&pull.library.client);
    assert(pull.library.client.token[0] == 0);
    const ws = lazy orelse return;
    ws.client.token_len = 0;
    ws.client.basic_len = 0;
    ws.client.credential = .none;
    ws.client.realm_fallback = null;
    assert(ws.client.basic_len == 0);
}

/// Whether the store has a whole record of `manifest`: a pulled image, which a lazy start must
/// not turn into a partial one. `image` is only scratch here; the caller loads it again.
fn held_whole(store: *Store, manifest: Sha256, image: *images.Image) bool {
    assert(manifest.bytes.len == constants.oci_digest_bytes);
    assert(@intFromPtr(image) != 0);
    var errno: u16 = 0;
    images.load(store, manifest, image, &errno) catch return false;
    return !image.partial;
}

/// A lazy index covers one layer: an image of more than one is pulled whole (`W1201`).
fn warn_layers(warn: ?namespace.Warn, text: []const u8, count: u32) void {
    assert(text.len > 0);
    assert(count != 1);
    const to = warn orelse return;
    var warning: Diag = undefined;
    warning.reset();
    lazy_diagnose.many_layers(&warning, text, count);
    to.call(to.context, &warning);
}

fn warn_no_index(warn: ?namespace.Warn, text: []const u8) void {
    assert(text.len > 0);
    const to = warn orelse return;
    var warning: Diag = undefined;
    warning.reset();
    lazy_diagnose.no_index(&warning, text);
    to.call(to.context, &warning);
}

/// Fetches the anchor's range of the layer, inflates it, and verifies it into `ws.index`.
fn fetch_index(
    host: Host,
    ws: *Workspace,
    reference: *const @import("registry/reference.zig").Reference,
    anchor: *const index_mod.Anchor,
    tree: Digest,
    text: []const u8,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    anchor.check() catch |err| return refuse(diag, tree, text, err, .hash);
    const length: usize = @intCast(anchor.length);
    const size: usize = @intCast(anchor.size);
    assert(length <= index_mod.compressed_bytes_max);
    assert(size <= ws.index_bytes.len);
    const clock: client_mod.Clock = .{ .context = &host, .now_ms = host_now_ms };
    const out = ws.compressed[0..length];
    const fetched = registry_range.fetch_whole(
        &ws.client,
        reference,
        ws.layer,
        anchor.offset,
        out,
        clock,
        diag,
    );
    fetched catch |err| switch (err) {
        error.Short => return refuse(diag, tree, text, error.Malformed, .inflate),
        error.Failed => {
            diag.while_("fetching the lazy index of '{s}' ({d} seconds in all)", .{
                text,
                constants.net_request_timeout_ms / 1000,
            });
            return error.Failed;
        },
    };
    ws.index_fetched = length;
    const bytes = ws.index_bytes[0..size];
    index_mod.inflate_range(&ws.compressed, length, bytes, &ws.window) catch |err| {
        return refuse(diag, tree, text, err, .inflate);
    };
    host.random_bytes(&ws.checking.key) catch {
        ws.checking.key = @splat(0x5a); // The key keeps the walk fast, not safe; any one works.
    };
    if (!Digest.of(bytes).eql(anchor.digest)) {
        return refuse(diag, tree, text, error.Malformed, .hash);
    }
    ws.index = verify_mod.verify(&ws.checking, bytes, anchor, tree) catch |err| {
        return refuse(diag, tree, text, err, .tree);
    };
    assert(ws.index.header.complete);
}

/// The host's monotonic clock, for `client_mod.Deadline`.
fn host_now_ms(context: *const anyopaque) u64 {
    const host: *const Host = @ptrCast(@alignCast(context));
    return host.monotonic_ms();
}

/// `TooLarge` is the image past a bound of lazy start (E1207); anything else is E1202.
fn refuse(
    diag: *Diag,
    tree: Digest,
    text: []const u8,
    err: index_mod.Refusal,
    why: lazy_diagnose.Refused,
) Error {
    assert(diag.code == null);
    assert(text.len > 0);
    switch (err) {
        error.TooLarge => lazy_diagnose.too_large(diag, tree, lazy_diagnose.bound(.index)),
        error.Malformed => lazy_diagnose.index_refused(diag, text, why),
    }
    return error.Failed;
}

/// Stores every directory of the verified index, each checked again by its digest.
fn put_trees(store: *Store, index: *const index_mod.Index, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(index.header.complete);
    var records = index.tree_records();
    while (records.next()) |record| {
        var failure: object.Failure = undefined;
        _ = trees.put_checked(store, record.digest, record.bytes, &failure) catch |err| {
            const operation = "storing the image's directories from its lazy index";
            switch (err) {
                // `verify` walked these same bytes from the tree digest.
                error.TooLarge, error.DigestMismatch, error.Malformed => unreachable,
                error.Busy => store_diagnose.store_busy(diag, operation, ""),
                error.StoreFailed => store_diagnose.write_failed(
                    diag,
                    store,
                    operation,
                    failure.err,
                    failure.errno,
                ),
            }
            return error.Failed;
        };
    }
}

/// The image's record, partial, as a pull would write it: what `compose` reads. A record already
/// kept for the manifest keeps its tags, and a start by tag adds the tag, as a pull does.
fn fill_image(
    host: Host,
    store: *const Store,
    image: *images.Image,
    library: *const pull_lib.Workspace,
    tree: Digest,
    text: []const u8,
) void {
    const resolved = &library.resolved;
    assert(resolved.layer_count >= 1);
    assert(resolved.layer_count <= constants.registry_layers_max);
    images.carry_tags(store, resolved.manifest_digest, image);
    const written = text[0..@min(text.len, constants.reference_bytes_max)];
    if (library.reference.digest == null) image.add_tag(written);
    image.manifest = resolved.manifest_digest;
    var platform_buffer: [16]u8 = undefined;
    const platform = pull_unpack.platform_text(&platform_buffer, resolved.architecture);
    @memcpy(image.platform[0..platform.len], platform);
    image.platform_len = @intCast(platform.len);
    image.config = resolved.config_digest;
    image.tree = tree;
    image.time = host.time_now();
    image.layer_count = resolved.layer_count;
    for (resolved.layers[0..resolved.layer_count], 0..) |layer, at| image.layers[at] = layer.digest;
    image.settings = library.settings;
    image.labels = library.labels;
    image.partial = true;
}

/// Writes the partial image's record, before the run: it keeps the tree's directories (stored
/// just now) for gc while the run fetches the files.
fn save_image(store: *Store, image: *const images.Image, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(image.partial);
    var failure: @import("store/fs.zig").Failure = undefined;
    images.save(store, image, &failure) catch {
        const step = "writing the image record";
        store_diagnose.write_failed(diag, store, step, failure.err, failure.errno);
        return error.Failed;
    };
}
