//! `zbx pull`. `zbx pull --resolve-only <reference>` asks the registry what the reference names
//! for this machine's platform and prints the digest of that image's manifest (the digest a lock
//! file records), without fetching any layer. Text is the digest on a line; `--output json` is
//! one object (`zbx schema pull-resolve`).
//!
//! `zbx pull <reference>` goes on: it downloads the config and the layers into the store's blob
//! cache (a cut download resumes), then the store's child (`pull_unpack.zig`) unpacks the layers
//! into one tree, imports it, and records the image. It prints the manifest digest (the same
//! line as the resolve), or with `--output json` the object `zbx.pull/1`.
//!
//! The network work runs here, in the parent, before and outside any namespace child.

const std = @import("std");
const assert = std.debug.assert;
const blobs_mod = @import("registry/blobs.zig");
const config_mod = @import("registry/config.zig");
const image_diagnose = @import("image_diagnose.zig");
const images = @import("store/images.zig");
const lock_file = @import("lock_file.zig");
const client_mod = @import("registry/client.zig");
const constants = @import("constants.zig");
const diagnose = @import("registry/diagnose.zig");
const errors = @import("diag/errors.zig");
const host_mod = @import("host.zig");
const manifest = @import("registry/manifest.zig");
const reference_mod = @import("registry/reference.zig");
const doctor = @import("doctor.zig");
const import = @import("store/import.zig");
const lock = @import("store/lock.zig");
const namespace = @import("store/namespace.zig");
const open = @import("store/open.zig");
const render_diag = @import("diag/render.zig");
const store_diagnose = @import("store/diagnose.zig");
const unpack = @import("pull_unpack.zig");
const fs_mod = @import("store/fs.zig");
const Diag = @import("diag/diag.zig").Diag;
const Store = @import("store/layout.zig").Store;

const Host = host_mod.Host;

pub const Error = error{ Failed, OutputFailed };

/// What a pull works in: the client's memory, the result, the text of the JSON result, the
/// blob being downloaded, and what the child unpacks in.
pub const Workspace = struct {
    client: client_mod.Workspace,
    resolved: manifest.Resolved,
    output: [constants.pull_output_bytes_max]u8,
    fetched: unpack.Fetched,
    download: blobs_mod.Download,
    unpack: unpack.Workspace,
    reference: reference_mod.Reference,
    /// What the image runs by default, read from its configuration blob.
    settings: images.Settings,
};

pub const Args = struct {
    reference: []const u8,
    json: bool,
};

/// Parses the reference and resolves it for this machine into `workspace.resolved`.
fn resolve_reference(
    host: Host,
    text: []const u8,
    workspace: *Workspace,
    client: *client_mod.Client,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    assert(text.len <= constants.arg_bytes_max);
    reference_mod.parse(text, &workspace.reference) catch |err| {
        diagnose.bad_reference(diag, text, err);
        return error.Failed;
    };
    // A host that cannot say its machine type gets an empty one, which has no image platform:
    // the refusal says so. `uname` does not fail on a real kernel.
    const uname = host.uname() catch host_mod.Uname{
        .release = host_mod.Text.from_slice(""),
        .machine = host_mod.Text.from_slice(""),
    };
    var machine = uname.machine;
    client.* = client_mod.Client.init(host.network(), &workspace.client, machine.slice());
    const mirrors = host.environment("ZBX_REGISTRY_MIRRORS", constants.registry_mirrors_bytes_max);
    client.mirrors = mirrors orelse "";
    client_mod.resolve(client, &workspace.reference, &workspace.resolved, diag) catch {
        return error.Failed;
    };
    assert(diag.code == null);
    assert(workspace.resolved.layer_count <= constants.registry_layers_max);
}

pub fn run_resolve(host: Host, args: Args, workspace: *Workspace, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(args.reference.len <= constants.arg_bytes_max);
    assert(@sizeOf(Workspace) > constants.pull_output_bytes_max);
    var client: client_mod.Client = undefined;
    try resolve_reference(host, args.reference, workspace, &client, diag);
    const text = render(args.json, &workspace.reference, &workspace.resolved, &workspace.output);
    host.write_all(.stdout, text) catch |err| {
        errors.output_failed(diag, .stdout, err, host.last_errno());
        return error.OutputFailed;
    };
}

/// How the child's output is written, and the one thing the parent needs to say about the map.
pub const Output = unpack.Output;

/// `zbx pull <reference>`: resolve, download what the cache lacks, and have the store's child
/// unpack, import and record. The result is the exit code (the child's).
pub fn run_pull(
    host: Host,
    args: Args,
    output: Output,
    facts: *doctor.Facts,
    workspace: *Workspace,
    import_workspace: *import.Workspace,
    diag: *Diag,
) Error!u8 {
    assert(diag.code == null);
    assert(args.reference.len <= constants.arg_bytes_max);
    var client: client_mod.Client = undefined;
    try resolve_reference(host, args.reference, workspace, &client, diag);
    var store: Store = undefined;
    if (!store.locate(host)) {
        store_diagnose.no_data_directory(diag);
        return error.Failed;
    }
    _ = open.check(&store, .create, diag) catch return error.Failed;
    // The blobs are in the cache from the first byte to the record of the image that names them,
    // and a gc in that time would take them: hold the lock for the whole pull.
    store_diagnose.hold(diag, &store, .shared, "pull", "pulling an image") catch {
        return error.Failed;
    };
    defer lock.release(&store);
    // A lock that is damaged is found now, not after the layers are unpacked.
    try check_lock(host, &store, workspace, diag);
    try fetch_all(&client, workspace, &store, diag);
    try read_settings(workspace, &store, diag);
    var job: unpack.Job = .{
        .host = host,
        .output = output,
        .written = args.reference,
        .reference = &workspace.reference,
        .resolved = &workspace.resolved,
        .fetched = &workspace.fetched,
        .workspace = &workspace.unpack,
        .import_workspace = import_workspace,
        .settings = &workspace.settings,
    };
    var reporter: Reporter = .{ .host = host, .output = output };
    const work: namespace.Work = .{ .context = &job, .call = unpack.work_call };
    const warn: namespace.Warn = .{ .context = &reporter, .call = report_warning };
    return namespace.run(host, facts, work, warn, diag) catch return error.Failed;
}

const Reporter = struct {
    host: Host,
    output: Output,
};

/// Reads zbx.lock before any work, if the pull is going to record in it (a digest reference
/// needs no lock): a lock that can not be read ends the pull now.
fn check_lock(host: Host, store: *const Store, workspace: *Workspace, diag: *Diag) Error!void {
    assert(workspace.reference.registry_len > 0);
    assert(diag.code == null);
    if (workspace.reference.digest != null) return;
    const locking = &workspace.unpack.locking;
    var failure: lock_file.Failure = undefined;
    lock_file.open_project(host, store.fs, locking, &failure) catch {
        const path = if (locking.located.len > 0) locking.located.text() else lock_file.file_name;
        image_diagnose.lock_failure(diag, path, failure);
        return error.Failed;
    };
}

/// Reads the image's configuration blob (checked by its digest when it arrived) into
/// `workspace.settings`.
fn read_settings(workspace: *Workspace, store: *const Store, diag: *Diag) Error!void {
    assert(workspace.resolved.layer_count > 0);
    assert(diag.code == null);
    const config = workspace.resolved.config_digest;
    const blobs: blobs_mod.Blobs = .{ .fs = store.fs, .root = store.root_text() };
    var path: fs_mod.PathBuf = undefined;
    const where = blobs.final_path(&path, config);
    const body = store.fs.read_whole(where, &workspace.client.body) catch {
        image_diagnose.config_refused(diag, config, "could not be read back from the blob cache");
        return error.Failed;
    };
    config_mod.parse(&workspace.client.arena, body, &workspace.settings) catch |problem| {
        const words = switch (problem) {
            error.malformed => "is not the JSON of an image configuration",
            error.too_complex => "is more complex than zbx reads",
            error.too_big => "has more words or bytes than zbx keeps",
            error.bad_variable => "has an environment entry that is not NAME=value",
        };
        image_diagnose.config_refused(diag, config, words);
        return error.Failed;
    };
}

fn report_warning(context: *anyopaque, diag: *const Diag) void {
    const reporter: *const Reporter = @ptrCast(@alignCast(context));
    assert(diag.code != null);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const text = render_diag.render(diag, reporter.output.mode, reporter.output.color, &buffer);
    // A warning that cannot be written is lost, and the pull goes on: it is only a warning.
    reporter.host.write_all(.stderr, text) catch return;
}

/// Downloads the config and every layer the cache lacks, in manifest order.
fn fetch_all(
    client: *client_mod.Client,
    workspace: *Workspace,
    store: *const Store,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    assert(workspace.resolved.layer_count > 0);
    const resolved = &workspace.resolved;
    const blobs: blobs_mod.Blobs = .{ .fs = store.fs, .root = store.root_text() };
    var failure: blobs_mod.Failure = undefined;
    blobs.ensure_directories(&failure) catch {
        diagnose.cache_failed(diag, blobs.root, &failure);
        return error.Failed;
    };
    const reference = &workspace.reference;
    const download = &workspace.download;
    const config = resolved.config_digest;
    workspace.fetched.config = client_mod.fetch_blob(
        client,
        reference,
        config,
        resolved.config_size,
        blobs,
        download,
        diag,
    ) catch return error.Failed;
    for (resolved.layers[0..resolved.layer_count], 0..) |layer, index| {
        workspace.fetched.layers[index] = client_mod.fetch_blob(
            client,
            reference,
            layer.digest,
            layer.size,
            blobs,
            download,
            diag,
        ) catch return error.Failed;
    }
}

fn render(
    json: bool,
    reference: *const reference_mod.Reference,
    resolved: *const manifest.Resolved,
    buffer: *[constants.pull_output_bytes_max]u8,
) []const u8 {
    assert(resolved.layer_count <= constants.registry_layers_max);
    assert(buffer.len == constants.pull_output_bytes_max);
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
    assert(resolved.manifest_size > 0);
    assert(resolved.layer_count <= constants.registry_layers_max);
    var formatted: reference_mod.Formatted = undefined;

    const shown = reference.format(&formatted);
    try writer.print("{{\"schema\":\"zbx.pull.resolve/1\",\"reference\":\"{s}\",", .{shown});
    try writer.print("\"registry\":\"{s}\",", .{reference.registry()});
    try writer.print("\"repository\":\"{s}\",", .{reference.repository()});
    try writer.writeAll("\"index_digest\":");
    if (resolved.index_digest) |digest| {
        try writer.print("\"{s}\",", .{&digest.text()});
    } else {
        try writer.writeAll("null,");
    }
    const manifest_text = resolved.manifest_digest.text();
    try writer.print("\"manifest_digest\":\"{s}\",", .{&manifest_text});
    try writer.print("\"manifest_size\":{d},", .{resolved.manifest_size});
    try writer.print("\"platform\":\"linux/{s}\",", .{resolved.architecture.name()});
    const config_text = resolved.config_digest.text();
    try writer.print("\"config_digest\":\"{s}\",", .{&config_text});
    try writer.print("\"config_size\":{d},\"layers\":[", .{resolved.config_size});
    for (resolved.layers[0..resolved.layer_count], 0..) |layer, index| {
        if (index > 0) try writer.writeAll(",");
        const digest_text = layer.digest.text();
        const kind = @tagName(layer.kind);
        try writer.print("{{\"digest\":\"{s}\",\"size\":{d},", .{ &digest_text, layer.size });
        try writer.print("\"kind\":\"{s}\"}}", .{kind});
    }
    try writer.writeAll("]}\n");
}
