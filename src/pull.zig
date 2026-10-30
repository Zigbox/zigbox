//! Pull as a library call (M6b, slice 4): `pull` resolves a reference for a platform, fetches and
//! verifies the image's blobs into the store's cache, flattens its layers into one tree in the
//! store, and writes the image's record, exactly as `zbx pull` does. It returns the manifest
//! digest, the tree digest, the platform, the image's settings and the counts of the unpack.
//! Zigcube's agent calls it as `ensure_image`.
//!
//! What it takes, and from whom:
//!   - the `Request`: the reference (a tag or a digest), the platform to ask for, and the
//!     registry mirrors for docker.io. The caller reads `ZBX_REGISTRY_MIRRORS`,
//!     `ZBX_PLATFORM` and `ZBX_PLATFORM_FALLBACK` (the command line does, in
//!     `pull_commands.zig`); this file reads none of them.
//!   - the caller's store: the one `host` locates (`XDG_DATA_HOME`, else `HOME`), as for every
//!     function of the library.
//!   - the caller's memory: a `Workspace` (about 15 MiB: static storage or the heap), the
//!     store's `import.Workspace` and the doctor's `Facts`. Nothing is module-level.
//!   - the network of `host`. The real one reads `HTTPS_PROXY`, `NO_PROXY` and `SSL_CERT_FILE`
//!     from `host`'s environment, as it did, and keeps its buffers and parsed CA certificates in
//!     the `HostReal.network_memory` the caller gave it, so two callers on two threads with two
//!     hosts share nothing.
//!   - a progress callback, which may be null.
//!
//! It never touches a `zbx.lock`: that is a project's file. It prints nothing: warnings, from
//! the parent and from the store's child (which reports them through a pipe,
//! `pull_report.zig`), go to the callback as they are known, the child's after it has ended. A
//! failure is a coded `Diag`, the same as the command's.
//!
//! The network work runs here, in the parent, outside any namespace; the unpack runs in the
//! store's single-threaded child (`store/namespace.zig`, `pull_unpack.zig`). The store's shared
//! lock is held from the first byte downloaded to the image's record, so a gc cannot take the
//! blobs in between.

const std = @import("std");
const assert = std.debug.assert;
const blobs_mod = @import("registry/blobs.zig");
const client_mod = @import("registry/client.zig");
const config_mod = @import("registry/config.zig");
const constants = @import("constants.zig");
const diagnose = @import("registry/diagnose.zig");
const doctor = @import("doctor.zig");
const fs_mod = @import("store/fs.zig");
const host_mod = @import("host.zig");
const image_diagnose = @import("image_diagnose.zig");
const images = @import("store/images.zig");
const import = @import("store/import.zig");
const lock = @import("store/lock.zig");
const manifest = @import("registry/manifest.zig");
const namespace = @import("store/namespace.zig");
const open = @import("store/open.zig");
const reference_mod = @import("registry/reference.zig");
const report_mod = @import("pull_report.zig");
const store_diagnose = @import("store/diagnose.zig");
const store_digest = @import("store/digest.zig");
const unpack = @import("pull_unpack.zig");
const Diag = @import("diag/diag.zig").Diag;
const Sha256 = @import("registry/digest.zig").Sha256;
const Store = @import("store/layout.zig").Store;

const Host = host_mod.Host;

/// The failure is in the `Diag`.
pub const Error = error{Failed};

pub const Counts = report_mod.Counts;
pub const BlobOutcome = client_mod.BlobOutcome;
pub const Fetched = unpack.Fetched;

/// Which images the registry may give: this machine's architecture (from `uname`) unless
/// `architecture` replaces it, and `fallback` for an image that has none for it.
pub const Platform = struct {
    architecture: ?manifest.Architecture = null,
    fallback: ?manifest.Architecture = null,
};

pub const Request = struct {
    /// A tag or a digest reference, as a person writes it (`alpine:3.20`, `ghcr.io/o/r@sha256:..`).
    reference: []const u8,
    platform: Platform,
    /// Mirrors for docker.io, comma separated; empty for none.
    mirrors: []const u8,
};

pub const Event = union(enum) {
    /// The registry answered: the manifest this platform gets. Valid during the call.
    resolved: *const manifest.Resolved,
    /// A blob is in the cache. Index 0 is the configuration, 1 and up the layers, `of` the count.
    blob: struct { index: u32, of: u32, outcome: BlobOutcome },
    /// A warning. Valid during the call.
    warning: *const Diag,
};

/// Tells the caller what a pull is doing. Called on the calling thread, never from the child.
pub const Progress = struct {
    context: *anyopaque,
    call: *const fn (context: *anyopaque, event: Event) void,
};

/// What a pull works in: the client's memory, what the registry resolved to, how each blob came,
/// the blob being downloaded and what the child unpacks in. Keep it in static storage or on the
/// heap.
pub const Workspace = struct {
    client: client_mod.Workspace,
    resolved: manifest.Resolved,
    fetched: unpack.Fetched,
    download: blobs_mod.Download,
    unpack: unpack.Workspace,
    reference: reference_mod.Reference,
    /// What the image runs by default, read from its configuration blob.
    settings: images.Settings,
    /// The machine type the client quotes in its refusals; it must outlive the resolve.
    machine: host_mod.Text,
};

/// What a pull gives back. `settings`, and what `Workspace` holds of the image (the layers in
/// `resolved`, how each blob came in `fetched`), are the workspace's and valid until its next
/// pull.
pub const Result = struct {
    /// The image's manifest digest: what a lock records and an image record is named by.
    manifest_digest: Sha256,
    config_digest: Sha256,
    /// The tree the layers flatten to, in the store.
    tree: store_digest.Digest,
    platform_bytes: [16]u8,
    platform_len: u8,
    layer_count: u32,
    counts: Counts,
    /// Warnings the child raised that its report had no room for.
    warnings_dropped: u32,
    /// What the image runs by default: entrypoint, cmd, env, working directory, user.
    settings: *const images.Settings,

    /// "linux/amd64" or "linux/arm64".
    pub fn platform(result: *const Result) []const u8 {
        assert(result.platform_len > 0);
        return result.platform_bytes[0..result.platform_len];
    }
};

/// Parses the reference into `workspace.reference`; a bad one is a diagnostic.
pub fn parse_reference(workspace: *Workspace, text: []const u8, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(text.len <= constants.arg_bytes_max);
    reference_mod.parse(text, &workspace.reference) catch |err| {
        diagnose.bad_reference(diag, text, err);
        return error.Failed;
    };
    assert(workspace.reference.registry_len > 0);
}

/// Parses the reference and resolves it for the platform into `workspace.resolved`.
fn resolve_with(
    host: Host,
    request: *const Request,
    workspace: *Workspace,
    client: *client_mod.Client,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    assert(request.mirrors.len <= constants.registry_mirrors_bytes_max);
    try parse_reference(workspace, request.reference, diag);
    // A host that cannot say its machine type gets an empty one, which has no image platform:
    // the refusal says so. `uname` does not fail on a real kernel.
    const uname = host.uname() catch host_mod.Uname{
        .release = host_mod.Text.from_slice(""),
        .machine = host_mod.Text.from_slice(""),
    };
    workspace.machine = uname.machine;
    client.* = client_mod.Client.init(host.network(), &workspace.client, workspace.machine.slice());
    client.mirrors = request.mirrors;
    if (request.platform.architecture) |architecture| client.architecture = architecture;
    client.fallback = request.platform.fallback;
    client_mod.resolve(client, &workspace.reference, &workspace.resolved, diag) catch {
        return error.Failed;
    };
    assert(diag.code == null);
    assert(workspace.resolved.layer_count <= constants.registry_layers_max);
}

/// Asks the registry what the reference names for the platform, and fetches no layer: the result
/// is in `workspace.resolved` and `workspace.reference`.
pub fn resolve(host: Host, request: *const Request, workspace: *Workspace, diag: *Diag) Error!void {
    var client: client_mod.Client = undefined;
    try resolve_with(host, request, workspace, &client, diag);
}

/// What the callback of `namespace.run` and the report's warnings go through.
const Sink = struct {
    progress: ?Progress,

    fn warn(sink: *const Sink, diag: *const Diag) void {
        assert(diag.code != null);
        const progress = sink.progress orelse return;
        progress.call(progress.context, .{ .warning = diag });
    }
};

fn namespace_warning(context: *anyopaque, diag: *const Diag) void {
    const sink: *const Sink = @ptrCast(@alignCast(context));
    sink.warn(diag);
}

/// Pulls the image into the store; see the module comment. The thread that calls it must be the
/// only one using `host` and the only one in the process while the store's child is made, as
/// for every call that makes a namespace.
pub fn pull(
    host: Host,
    facts: *doctor.Facts,
    request: *const Request,
    progress: ?Progress,
    workspace: *Workspace,
    import_workspace: *import.Workspace,
    result: *Result,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    var client: client_mod.Client = undefined;
    try resolve_with(host, request, workspace, &client, diag);
    const sink: Sink = .{ .progress = progress };
    if (progress) |watcher| watcher.call(watcher.context, .{ .resolved = &workspace.resolved });
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
    try fetch_all(&client, workspace, &store, progress, diag);
    try read_settings(workspace, &store, diag);
    var done: report_mod.Done = undefined;
    try unpack_in_child(host, facts, request, &sink, workspace, import_workspace, &done, diag);
    fill_result(result, workspace, &done);
}

fn fill_result(result: *Result, workspace: *const Workspace, done: *const report_mod.Done) void {
    const resolved = &workspace.resolved;
    var buffer: [16]u8 = undefined;
    const platform = unpack.platform_text(&buffer, resolved.architecture);
    result.* = .{
        .manifest_digest = resolved.manifest_digest,
        .config_digest = resolved.config_digest,
        .tree = done.tree,
        .platform_bytes = buffer,
        .platform_len = @intCast(platform.len),
        .layer_count = resolved.layer_count,
        .counts = done.counts,
        .warnings_dropped = done.warnings_dropped,
        .settings = &workspace.settings,
    };
    assert(result.layer_count > 0);
}

/// Makes the store's child do the unpack and the record, and reads its report.
fn unpack_in_child(
    host: Host,
    facts: *doctor.Facts,
    request: *const Request,
    sink: *const Sink,
    workspace: *Workspace,
    import_workspace: *import.Workspace,
    done: *report_mod.Done,
    diag: *Diag,
) Error!void {
    const pipe = host.pipe() catch |err| {
        store_worker_failed(host, diag, "pipe", err);
        return error.Failed;
    };
    var writer: report_mod.Writer = undefined;
    writer.init(host, pipe.write);
    var job: unpack.Job = .{
        .host = host,
        .report = &writer,
        .written = request.reference,
        .reference = &workspace.reference,
        .resolved = &workspace.resolved,
        .fetched = &workspace.fetched,
        .workspace = &workspace.unpack,
        .import_workspace = import_workspace,
        .settings = &workspace.settings,
    };
    const work: namespace.Work = .{ .context = &job, .call = unpack.work_call };
    const warn: namespace.Warn = .{
        .context = @constCast(sink),
        .call = namespace_warning,
    };
    const code = namespace.run(host, facts, work, warn, diag) catch {
        host.close(pipe.read);
        host.close(pipe.write);
        return error.Failed;
    };
    host.close(pipe.write);
    defer host.close(pipe.read);
    var bytes: [constants.pull_report_bytes_max]u8 = undefined;
    var length: usize = 0;
    while (length < bytes.len) {
        const count = host.read_some(pipe.read, bytes[length..]) catch break;
        if (count == 0) break;
        length += count;
    }
    return read_report(host, code, bytes[0..length], sink, done, diag);
}

/// Hands the warnings on and turns the last record into the result or the failure.
fn read_report(
    host: Host,
    code: u8,
    bytes: []const u8,
    sink: *const Sink,
    done: *report_mod.Done,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    var reader = report_mod.Reader.init(bytes);
    var finished = false;
    while (reader.next() catch null) |record| switch (record) {
        .warning => |payload| {
            var warning: Diag = undefined;
            warning.reset();
            // A warning that does not read back is lost; the pull goes on.
            if (warning.decode(payload)) sink.warn(&warning);
        },
        .failure => |payload| {
            // A failure with an exit code of 0 is a child that contradicts itself: not believed.
            if (code != constants.exit_ok and diag.decode(payload)) return error.Failed;
            diag.reset();
        },
        .result => |found| {
            done.* = found;
            finished = true;
        },
    };
    if (code == constants.exit_ok and finished) return;
    diag.reset();
    store_worker_failed(host, diag, "unpacking the image", error.IoFailed);
    return error.Failed;
}

fn store_worker_failed(host: Host, diag: *Diag, step: []const u8, err: host_mod.Error) void {
    assert(diag.code == null);
    assert(step.len > 0);
    @import("store/diagnose.zig").worker_ended(diag, .{ .step = .{
        .name = step,
        .err = err,
        .errno = host.last_errno(),
    } });
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

/// Downloads the config and every layer the cache lacks, in manifest order.
fn fetch_all(
    client: *client_mod.Client,
    workspace: *Workspace,
    store: *const Store,
    progress: ?Progress,
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
    const of = resolved.layer_count + 1;
    workspace.fetched.config = client_mod.fetch_blob(
        client,
        reference,
        resolved.config_digest,
        resolved.config_size,
        blobs,
        download,
        diag,
    ) catch return error.Failed;
    if (progress) |watcher| {
        const outcome = workspace.fetched.config;
        const event: Event = .{ .blob = .{ .index = 0, .of = of, .outcome = outcome } };
        watcher.call(watcher.context, event);
    }
    for (resolved.layers[0..resolved.layer_count], 0..) |layer, index| {
        const outcome = client_mod.fetch_blob(
            client,
            reference,
            layer.digest,
            layer.size,
            blobs,
            download,
            diag,
        ) catch return error.Failed;
        workspace.fetched.layers[index] = outcome;
        if (progress) |watcher| {
            const event: Event = .{ .blob = .{
                .index = @intCast(index + 1),
                .of = of,
                .outcome = outcome,
            } };
            watcher.call(watcher.context, event);
        }
    }
}
