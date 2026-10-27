//! The part of `zbx pull` that runs in the store's child (`store/namespace.zig`): unpack the
//! layers into a staging directory, import it as one tree, write the image's record, and remove
//! the staging directory. It runs in the user namespace so that a tar entry's owner lands as
//! the container id it names, and so that the staging directory, whose files belong to
//! subordinate ids, can be removed.
//!
//! The simplest correct method, as the brief asks: extract, then run the existing import. The
//! staging directory is `tmp/<pid>-<n>` in the store, so a pull that is killed leaves it where
//! `gc` already removes the leftovers of dead processes.
//!
//! The child prints the result itself (stdout) and its diagnostics (stderr), and its exit code
//! is the command's, as for every store command.

const std = @import("std");
const assert = std.debug.assert;
const apply = @import("layer/apply.zig");
const client_mod = @import("registry/client.zig");
const blobs_mod = @import("registry/blobs.zig");
const constants = @import("constants.zig");
const host_mod = @import("host.zig");
const import = @import("store/import.zig");
const images = @import("store/images.zig");
const layer_diagnose = @import("layer/diagnose.zig");
const layout = @import("store/layout.zig");
const manifest = @import("registry/manifest.zig");
const open = @import("store/open.zig");
const reader_mod = @import("layer/reader.zig");
const reference_mod = @import("registry/reference.zig");
const registry_diagnose = @import("registry/diagnose.zig");
const remove = @import("store/remove.zig");
const render = @import("diag/render.zig");
const store_diagnose = @import("store/diagnose.zig");
const fs_mod = @import("store/fs.zig");
const Diag = @import("diag/diag.zig").Diag;

const Host = host_mod.Host;
const PathBuf = fs_mod.PathBuf;
const Store = layout.Store;

pub const Error = error{Failed};

/// How results and diagnostics are written (the same three facts as a store command's).
pub const Output = struct {
    mode: render.Mode,
    color: bool,
    json: bool,
};

/// The caller's memory for unpacking, about 14 MiB: keep it in static storage.
pub const Workspace = struct {
    applier: apply.Applier,
    layer: reader_mod.Layer,
    output: [constants.pull_output_bytes_max]u8,
};

/// What the parent did before the child started: how each blob came, for the result.
pub const Fetched = struct {
    config: client_mod.BlobOutcome,
    layers: [constants.registry_layers_max]client_mod.BlobOutcome,
};

pub const Job = struct {
    host: Host,
    output: Output,
    /// The reference as the user wrote it.
    written: []const u8,
    reference: *const reference_mod.Reference,
    resolved: *const manifest.Resolved,
    fetched: *const Fetched,
    workspace: *Workspace,
    import_workspace: *import.Workspace,
};

pub fn work_call(context: *anyopaque, squash_owner: bool) u8 {
    assert(@intFromPtr(context) != 0);
    const job: *Job = @ptrCast(@alignCast(context));
    var diag: Diag = undefined;
    diag.reset();
    execute(job, squash_owner, &diag) catch {
        if (diag.code == null) {
            diag.raise(.B0001);
            diag.cause("a pull failed with no diagnostic", .{});
        }
        write_diag(job, &diag);
        return diag.exit_code();
    };
    return constants.exit_ok;
}

fn write_diag(job: *const Job, diag: *const Diag) void {
    assert(@intFromPtr(job) != 0);
    assert(diag.code != null);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const text = render.render(diag, job.output.mode, job.output.color, &buffer);
    // A diagnostic that cannot be written is lost; the exit code still says the pull failed.
    job.host.write_all(.stderr, text) catch return;
}

fn report_warning(context: *anyopaque, diag: *const Diag) void {
    assert(diag.code != null);
    assert(@intFromPtr(context) != 0);
    const job: *const Job = @ptrCast(@alignCast(context));
    write_diag(job, diag);
}

fn execute(job: *Job, squash_owner: bool, diag: *Diag) Error!void {
    assert(job.resolved.layer_count <= constants.registry_layers_max);
    assert(diag.code == null);
    var store: Store = undefined;
    _ = open.open(job.host, &store, .create, diag) catch return error.Failed;
    var staging: PathBuf = undefined;
    const stage = store.tmp_path(&staging);
    store.fs.make_directory(stage, false) catch |err| {
        const step = "making the staging directory";
        store_diagnose.write_failed(diag, &store, step, err, store.fs.last_errno());
        return error.Failed;
    };
    var result: import.Result = undefined;
    const outcome = unpack(job, &store, stage, squash_owner, &result, diag);
    // The staging directory goes whatever happened. The unpack's own failure is the one to say.
    var cleanup_diag: Diag = undefined;
    cleanup_diag.reset();
    const cleaned = cleanup(job, stage, &store, &cleanup_diag);
    try outcome;
    cleaned catch {
        diag.* = cleanup_diag;
        return error.Failed;
    };
    try finish(job, &store, &result, diag);
}

/// Removes the staging directory. If that fails it stays in `tmp/`, where gc removes the
/// leftovers of dead processes, and the pull says so: it has not finished.
fn cleanup(job: *Job, stage: [:0]const u8, store: *const Store, diag: *Diag) Error!void {
    assert(stage.len > 0);
    assert(store.root_len > 1);
    const applier = &job.workspace.applier;
    var failure: remove.Failure = undefined;
    remove.tree(store.fs, &applier.removal, &applier.removal_arena, stage, &failure) catch {
        const step = "removing the staging directory";
        store_diagnose.write_failed(diag, store, step, failure.err, failure.errno);
        return error.Failed;
    };
}

fn unpack(
    job: *Job,
    store: *Store,
    stage: [:0]const u8,
    squash_owner: bool,
    result: *import.Result,
    diag: *Diag,
) Error!void {
    assert(stage.len > store.root_len);
    assert(job.resolved.layer_count > 0);
    const workspace = job.workspace;
    workspace.applier.start(store.fs, stage, squash_owner);
    const resolved = job.resolved;
    const blobs: blobs_mod.Blobs = .{ .fs = store.fs, .root = store.root_text() };
    for (resolved.layers[0..resolved.layer_count], 0..) |blob, index| {
        const place: layer_diagnose.Place = .{
            .layer = @intCast(index + 1),
            .layers = resolved.layer_count,
            .root = store.root_text(),
        };
        try unpack_layer(workspace, blobs, blob.digest, place, diag);
    }
    report_skipped(job, &workspace.applier);
    var reporter: Reporter = .{ .job = job };
    const options: import.Options = .{
        .squash_owner = squash_owner,
        .warn = .{ .context = &reporter, .call = reporter_call },
        .label = job.written,
    };
    import.import(store, job.import_workspace, stage, options, result, diag) catch {
        return error.Failed;
    };
}

const Reporter = struct { job: *const Job };

fn reporter_call(context: *anyopaque, diag: *const Diag) void {
    assert(diag.code != null);
    assert(@intFromPtr(context) != 0);
    const reporter: *const Reporter = @ptrCast(@alignCast(context));
    report_warning(@constCast(reporter.job), diag);
}

fn unpack_layer(
    workspace: *Workspace,
    blobs: blobs_mod.Blobs,
    digest: @import("registry/digest.zig").Sha256,
    place: layer_diagnose.Place,
    diag: *Diag,
) Error!void {
    assert(place.layer >= 1);
    assert(place.layer <= place.layers);
    var path: PathBuf = undefined;
    const blob_path = blobs.final_path(&path, digest);
    const layer = &workspace.layer;
    const applier = &workspace.applier;
    layer.start(blobs.fs, blob_path) catch {
        applier.failure.reason = .unreadable;
        applier.failure.path_len = 0;
        layer_diagnose.layer_refused(diag, &applier.failure, layer, place);
        return error.Failed;
    };
    defer layer.close();
    applier.apply_layer(layer) catch {
        layer_diagnose.layer_refused(diag, &applier.failure, layer, place);
        return error.Failed;
    };
    const actual = layer.finish() catch {
        applier.failure.reason = .unreadable;
        applier.failure.path_len = 0;
        layer_diagnose.layer_refused(diag, &applier.failure, layer, place);
        return error.Failed;
    };
    if (!actual.eql(digest)) {
        registry_diagnose.blob_damaged(diag, place.root, digest, actual);
        return error.Failed;
    }
}

fn report_skipped(job: *const Job, applier: *const apply.Applier) void {
    assert(applier.root_len > 1);
    assert(applier.counts.layers <= constants.registry_layers_max);
    const counts = applier.counts;
    if (counts.special_skipped > 0) {
        var warning: Diag = undefined;
        warning.reset();
        const first = applier.first_special_path();
        layer_diagnose.special_skipped(&warning, counts.special_skipped, first);
        write_diag(job, &warning);
    }
    if (counts.xattrs_skipped > 0) {
        var warning: Diag = undefined;
        warning.reset();
        layer_diagnose.xattrs_skipped(&warning, counts.xattrs_skipped, applier.first_xattr_path());
        write_diag(job, &warning);
    }
}

/// The image's record, then the result on stdout.
fn finish(job: *Job, store: *Store, result: *const import.Result, diag: *Diag) Error!void {
    assert(result.directories > 0);
    assert(diag.code == null);
    const resolved = job.resolved;
    var image: images.Image = undefined;
    const written = job.written[0..@min(job.written.len, constants.reference_bytes_max)];
    @memcpy(image.reference[0..written.len], written);
    image.reference_len = @intCast(written.len);
    image.manifest = resolved.manifest_digest;
    var platform_buffer: [16]u8 = undefined;
    const platform = std.fmt.bufPrint(&platform_buffer, "linux/{s}", .{
        resolved.architecture.name(),
    }) catch unreachable; // Sized: "linux/" and a name under eight bytes.
    @memcpy(image.platform[0..platform.len], platform);
    image.platform_len = @intCast(platform.len);
    image.config = resolved.config_digest;
    image.tree = result.digest;
    image.time = job.host.time_now();
    image.layer_count = resolved.layer_count;
    for (resolved.layers[0..resolved.layer_count], 0..) |blob, index| {
        image.layers[index] = blob.digest;
    }
    var failure: fs_mod.Failure = undefined;
    images.save(store, &image, &failure) catch {
        const step = "writing the image record";
        store_diagnose.write_failed(diag, store, step, failure.err, failure.errno);
        return error.Failed;
    };
    const text = render_result(job, result, &platform_buffer);
    job.host.write_all(.stdout, text) catch |err| {
        @import("diag/errors.zig").output_failed(diag, .stdout, err, job.host.last_errno());
        return error.Failed;
    };
}

fn render_result(job: *Job, result: *const import.Result, platform: []const u8) []const u8 {
    assert(job.workspace.output.len == constants.pull_output_bytes_max);
    assert(platform.len > 0);
    const buffer = &job.workspace.output;
    var writer = std.Io.Writer.fixed(buffer);
    const resolved = job.resolved;
    // Cannot fail: the buffer holds the largest result (128 layers, the constants assert it).
    if (!job.output.json) {
        writer.print("{s}\n", .{&resolved.manifest_digest.text()}) catch unreachable; // Sized.
        return writer.buffered();
    }
    write_json(&writer, job, result) catch unreachable; // Same bound.
    return writer.buffered();
}

fn write_json(
    writer: *std.Io.Writer,
    job: *const Job,
    result: *const import.Result,
) std.Io.Writer.Error!void {
    assert(job.resolved.layer_count <= constants.registry_layers_max);
    assert(result.directories > 0);
    const resolved = job.resolved;
    const reference = job.reference;
    try writer.writeAll("{\"schema\":\"zbx.pull/1\",\"reference\":");
    try @import("bundle.zig").write_json_string(writer, job.written);
    try writer.print(",\"registry\":\"{s}\",\"repository\":\"{s}\",", .{
        reference.registry(), reference.repository(),
    });
    try writer.print("\"manifest_digest\":\"{s}\",\"platform\":\"linux/{s}\",", .{
        &resolved.manifest_digest.text(), resolved.architecture.name(),
    });
    try writer.print("\"tree\":\"{s}\",\"config\":{{\"digest\":\"{s}\",\"cache\":\"{s}\"}},", .{
        result.digest.text(), &resolved.config_digest.text(), @tagName(job.fetched.config),
    });
    try writer.writeAll("\"layers\":[");
    for (resolved.layers[0..resolved.layer_count], 0..) |blob, index| {
        if (index > 0) try writer.writeAll(",");
        try writer.print("{{\"digest\":\"{s}\",\"size\":{d},\"cache\":\"{s}\"}}", .{
            &blob.digest.text(), blob.size, @tagName(job.fetched.layers[index]),
        });
    }
    const counts = job.workspace.applier.counts;
    try writer.print("],\"files\":{d},\"directories\":{d},\"symlinks\":{d},\"bytes\":{d},", .{
        result.files, result.directories, result.symlinks, result.bytes,
    });
    try writer.print("\"special_skipped\":{d},\"xattrs_skipped\":{d}}}\n", .{
        counts.special_skipped, counts.xattrs_skipped,
    });
}
