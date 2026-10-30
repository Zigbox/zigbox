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
const codes = @import("diag/codes.zig");
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
    /// At most `constants.reference_bytes_max` bytes; a longer or empty one is refused (E0501).
    reference: []const u8,
    platform: Platform,
    /// Mirrors for docker.io, comma separated; empty for none. At most
    /// `constants.registry_mirrors_bytes_max` bytes and `registry_mirrors_max` entries; more is
    /// refused (E0514).
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
    // Any length is the caller's to give, so a long one is a refusal here, before the parser.
    if (text.len > constants.reference_bytes_max) {
        const shown = text[0..@min(text.len, constants.arg_bytes_max)];
        diagnose.bad_reference(diag, shown, error.TooLong);
        return error.Failed;
    }
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
pub const Sink = struct {
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
///
/// The report goes through a pipe that the parent reads only after the child has ended, so the
/// pipe must hold the whole report or the child would wait for a reader that waits for it. The
/// kernel gives a user over `fs.pipe-user-pages-soft` a pipe of one or two pages, so the parent
/// asks for `pull_report_bytes_max` and checks what it got (`ensure_pipe_capacity`), and refuses
/// the pull with a diagnostic if the pipe is smaller; draining while the child runs would need
/// the wait for the child (`namespace.run`) to poll a pipe too, for a case that is rare. The read
/// does not wait for end of file either: another thread's child that was made while the pipe was
/// open may hold its write end, so everything buffered is read and the first empty poll ends it.
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
        store_pipe_failed(host, diag, err);
        return error.Failed;
    };
    host.ensure_pipe_capacity(pipe.write, constants.pull_report_bytes_max) catch |err| {
        host.close(pipe.read);
        host.close(pipe.write);
        if (err == error.NoSpace) {
            report_failed(diag, .small_pipe, 0);
        } else store_pipe_failed(host, diag, err);
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
    const length = read_buffered(host, pipe.read, &bytes) orelse {
        report_failed(diag, .unreadable, code);
        return error.Failed;
    };
    return read_report(code, bytes[0..length], sink, done, diag);
}

/// Everything the pipe holds, without waiting for end of file: null if it cannot be read.
fn read_buffered(
    host: Host,
    handle: host_mod.Handle,
    bytes: *[constants.pull_report_bytes_max]u8,
) ?usize {
    assert(bytes.len == constants.pull_report_bytes_max);
    var length: usize = 0;
    // The child has ended, so its writes are all in the pipe: each read gives some, and the
    // loop ends when it gives none, when nothing more is ready, or when the report is as big
    // as a report can be.
    for (0..constants.pull_report_bytes_max) |_| {
        if (length == bytes.len) break;
        const wait_ms = constants.pull_report_drain_wait_ms;
        const count = host.read_timeout(handle, bytes[length..], wait_ms) catch |err| {
            if (err == error.TimedOut) break;
            return null;
        };
        if (count == 0) break;
        length += count;
    }
    assert(length <= bytes.len);
    assert(length <= constants.pull_report_bytes_max);
    return length;
}

/// Why a pull's worker is not believed. Each is one sentence in the diagnostic.
const ReportCause = enum {
    /// The pipe could not be made big enough for the report.
    small_pipe,
    /// The pipe could not be read.
    unreadable,
    /// The report is not what the worker's writer writes.
    damaged,
    /// A failure record whose diagnostic does not decode.
    failure_unreadable,
    /// The worker ended with a non-zero status and no failure record.
    silent,
    /// The worker ended with status 0 and no result record.
    no_result,
    /// The worker reported a failure and ended with status 0, or a result and a failing status.
    contradiction,
};

/// Hands the warnings on and turns the report's last record into the result or the failure.
/// `code` is the child's exit code and `bytes` what it wrote: the report is believed only if it
/// is whole, ends in one record (a failure with a non-zero code or a result with 0), and the two
/// agree.
pub fn read_report(
    code: u8,
    bytes: []const u8,
    sink: *const Sink,
    done: *report_mod.Done,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    var reader = report_mod.Reader.init(bytes);
    var finished = false;
    var failed = false;
    while (true) {
        const found = reader.next() catch {
            report_failed(diag, .damaged, code);
            return error.Failed;
        };
        const record = found orelse break;
        switch (record) {
            .warning => |payload| {
                var warning: Diag = undefined;
                warning.reset();
                // The writer encoded it, so a warning that does not read back is a damaged report.
                if (!warning.decode(payload)) {
                    report_failed(diag, .damaged, code);
                    return error.Failed;
                }
                sink.warn(&warning);
            },
            .failure => |payload| {
                failed = true;
                if (code == constants.exit_ok) break;
                // Nothing may follow a failure: bytes after it are a damaged report, as after a
                // result, and the child's word is not taken from such a report.
                _ = reader.next() catch {
                    report_failed(diag, .damaged, code);
                    return error.Failed;
                };
                if (diag.decode(payload)) {
                    // The writer sends the diagnostic that ended the child, never a warning or a
                    // note; one that is not an error is damage that happens to decode.
                    const severity = codes.entry(diag.code.?).severity;
                    if (severity == .@"error" or severity == .bug) return error.Failed;
                }
                diag.reset();
                report_failed(diag, .failure_unreadable, code);
                return error.Failed;
            },
            .result => |found_done| {
                done.* = found_done;
                finished = true;
            },
        }
    }
    if (failed) {
        report_failed(diag, .contradiction, code);
        return error.Failed;
    }
    if (code != constants.exit_ok) {
        const cause: ReportCause = if (finished) .contradiction else .silent;
        report_failed(diag, cause, code);
        return error.Failed;
    }
    if (finished) return;
    report_failed(diag, .no_result, code);
    return error.Failed;
}

/// E0419 with the sentence for `cause`: what the parent saw of the store's worker.
fn report_failed(diag: *Diag, cause: ReportCause, code: u8) void {
    if (cause == .no_result) assert(code == constants.exit_ok);
    if (cause == .silent) assert(code != constants.exit_ok);
    diag.reset();
    var storage: [192]u8 = undefined;
    const sentence = switch (cause) {
        .small_pipe => std.fmt.bufPrint(
            &storage,
            "the pipe for the store worker's report holds less than {d} bytes, which the " ++
                "kernel allows a user over its pipe memory limits",
            .{constants.pull_report_bytes_max},
        ),
        .unreadable => std.fmt.bufPrint(
            &storage,
            "the store's worker ended with status {d} and its report could not be read",
            .{code},
        ),
        .damaged => std.fmt.bufPrint(
            &storage,
            "the store's worker sent a damaged report (it ended with status {d})",
            .{code},
        ),
        .failure_unreadable => std.fmt.bufPrint(
            &storage,
            "the store's worker ended with status {d} and sent a failure that cannot be read",
            .{code},
        ),
        .silent => std.fmt.bufPrint(
            &storage,
            "the store's worker ended with status {d} and did not say why",
            .{code},
        ),
        .no_result => std.fmt.bufPrint(
            &storage,
            "the store's worker ended with status 0 without reporting a result",
            .{},
        ),
        .contradiction => std.fmt.bufPrint(
            &storage,
            "the store's worker contradicted itself: its report and its status {d} disagree",
            .{code},
        ),
    } catch unreachable; // The longest sentence is under 160 bytes, and the buffer is 192.
    assert(sentence.len > 0);
    store_diagnose.worker_ended(diag, .{ .report = sentence });
    assert(diag.code.? == .E0419);
}

/// The pipe for the report could not be made: the kernel's reason is fresh, from the call.
fn store_pipe_failed(host: Host, diag: *Diag, err: host_mod.Error) void {
    assert(diag.code == null);
    assert(err != error.Interrupted); // Neither pipe2 nor fcntl is interruptible.
    store_diagnose.worker_ended(diag, .{ .step = .{
        .name = "making the pipe for the store worker's report",
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

// ---- Tests ---------------------------------------------------------------------------------

const testing = std.testing;

const Seen = struct {
    warnings: u32 = 0,

    fn on_event(context: *anyopaque, event: Event) void {
        const seen: *Seen = @ptrCast(@alignCast(context));
        switch (event) {
            .warning => seen.warnings += 1,
            .resolved, .blob => {},
        }
    }
};

/// A report built with the real writer: `warnings` warnings, then the last record as `ending`
/// says. Returns the bytes in `out`.
const Ending = enum { none, result, failure };

fn build_report(
    out: *[constants.pull_report_bytes_max]u8,
    warnings: u32,
    ending: Ending,
) []const u8 {
    var rig: report_mod.Rig = undefined;
    rig.setup();
    const warning = report_mod.warning_of(.W0501, "a device node was left out");
    for (0..warnings) |_| rig.writer.warning(&warning);
    switch (ending) {
        .none => {},
        .result => {
            var tree: store_digest.Digest = undefined;
            @memset(&tree.bytes, 0x42);
            var counts = std.mem.zeroes(Counts);
            counts.files = 9;
            rig.writer.result(tree, counts);
        },
        .failure => {
            var failing = report_mod.warning_of(.E0515, "an entry would leave the root");
            failing.fix(.{ .sentence = "pull another image:", .command = "zbx pull alpine:3.20" });
            rig.writer.failure(&failing);
        },
    }
    return rig.report(out);
}

/// Runs `read_report` on `bytes` and `code`; the result is the error or null, with the warnings
/// seen and the diagnostic.
fn read_for_test(
    code: u8,
    bytes: []const u8,
    seen: *Seen,
    diag: *Diag,
    done: *report_mod.Done,
) ?Error {
    const progress: Progress = .{ .context = seen, .call = Seen.on_event };
    const sink: Sink = .{ .progress = progress };
    diag.reset();
    read_report(code, bytes, &sink, done, diag) catch |err| return err;
    return null;
}

fn expect_worker_refused(code: u8, bytes: []const u8, words: []const u8) !void {
    var seen: Seen = .{};
    var diag: Diag = undefined;
    var done: report_mod.Done = undefined;
    const err = read_for_test(code, bytes, &seen, &diag, &done);
    try testing.expectEqual(@as(?Error, error.Failed), err);
    try testing.expectEqual(@as(?codes.Code, .E0419), diag.code);
    const cause = diag.last_cause() orelse "";
    testing.expect(std.mem.indexOf(u8, cause, words) != null) catch |failed| {
        std.debug.print("cause was '{s}', wanted '{s}'\n", .{ cause, words });
        return failed;
    };
}

test "read_report: a report with a result and exit 0 is the result, and its warnings come first" {
    // Goal: the one good ending. Method: two warnings and a result built by the writer.
    var buffer: [constants.pull_report_bytes_max]u8 = @splat(0x55);
    const bytes = build_report(&buffer, 2, .result);
    var seen: Seen = .{};
    var diag: Diag = undefined;
    var done: report_mod.Done = undefined;
    try testing.expectEqual(@as(?Error, null), read_for_test(0, bytes, &seen, &diag, &done));
    try testing.expectEqual(@as(u32, 2), seen.warnings);
    try testing.expectEqual(@as(u64, 9), done.counts.files);
    try testing.expectEqual(@as(?codes.Code, null), diag.code);
}

test "read_report: a failure with a non-zero exit is the child's own diagnostic" {
    // Goal: a failure travels whole. Method: a failure record and exit 2.
    var buffer: [constants.pull_report_bytes_max]u8 = @splat(0x55);
    const bytes = build_report(&buffer, 1, .failure);
    var seen: Seen = .{};
    var diag: Diag = undefined;
    var done: report_mod.Done = undefined;
    const err = read_for_test(2, bytes, &seen, &diag, &done);
    try testing.expectEqual(@as(?Error, error.Failed), err);
    try testing.expectEqual(@as(?codes.Code, .E0515), diag.code);
    try testing.expectEqual(@as(u32, 1), seen.warnings);
}

test "read_report: a failure is believed only when it is an error and ends the report" {
    // Goal: the first record of a report whose kind byte was damaged from warning to failure is
    // not taken for the child's word (found by the pull_report fuzzer, seed
    // 12862358659054011226). Method: a real warning report with its kind byte set to failure and
    // records after it; the same cut after that record, a failure that is only a warning; and a
    // real failure with a byte after it. All are refused as E0419 with a cause.
    var buffer: [constants.pull_report_bytes_max]u8 = @splat(0x55);
    const whole = build_report(&buffer, 2, .result);
    var altered: [constants.pull_report_bytes_max]u8 = @splat(0x55);
    @memcpy(altered[0..whole.len], whole);
    altered[0] = @backingInt(report_mod.Kind.failure);
    try expect_worker_refused(15, altered[0..whole.len], "damaged report");
    const first_end = constants.pull_report_header_bytes + (whole[1] | @as(usize, whole[2]) << 8);
    try expect_worker_refused(15, altered[0..first_end], "cannot be read");
    var failing: [constants.pull_report_bytes_max]u8 = @splat(0x55);
    const failure = build_report(&failing, 0, .failure);
    failing[failure.len] = 1;
    try expect_worker_refused(15, failing[0 .. failure.len + 1], "damaged report");
}

test "read_report: every other ending is a specific refusal of the worker" {
    // Goal: every exit path of the report reader. Method: reports from the real writer, and
    // hand-damaged copies, each against the exit code that makes it wrong: a non-zero exit with
    // no failure, exit 0 with no result, exit 0 with a failure, a result with a failing exit, a
    // failure whose payload does not decode, a tail after the last record, and every cut.
    var buffer: [constants.pull_report_bytes_max]u8 = @splat(0x55);
    try expect_worker_refused(3, build_report(&buffer, 0, .none), "did not say why");
    try expect_worker_refused(3, build_report(&buffer, 2, .none), "did not say why");
    try expect_worker_refused(0, build_report(&buffer, 2, .none), "without reporting a result");
    try expect_worker_refused(0, build_report(&buffer, 0, .none), "without reporting a result");
    try expect_worker_refused(0, build_report(&buffer, 1, .failure), "contradicted itself");
    try expect_worker_refused(1, build_report(&buffer, 1, .result), "contradicted itself");
    var junk = [_]u8{ 2, 2, 0, 'x', 'y' }; // A failure whose payload is not a diagnostic.
    try expect_worker_refused(1, &junk, "failure that cannot be read");
    var tail: [constants.pull_report_bytes_max]u8 = undefined;
    const whole = build_report(&buffer, 1, .result);
    @memcpy(tail[0..whole.len], whole);
    tail[whole.len] = 7;
    try expect_worker_refused(0, tail[0 .. whole.len + 1], "damaged report");
    var junk_warning = [_]u8{ 1, 2, 0, 'x', 'y' }; // A warning that is not a diagnostic.
    try expect_worker_refused(0, &junk_warning, "damaged report");
    for (1..whole.len) |cut| {
        const first_length = whole[1] | @as(usize, whole[2]) << 8;
        const first_end = constants.pull_report_header_bytes + first_length;
        // A cut at the end of the first record is a whole report of one warning: no result.
        const words = if (cut == first_end) "without reporting a result" else "damaged report";
        try expect_worker_refused(0, whole[0..cut], words);
    }
}
