//! Running a tree from the store: everything that happens before the plan, to give a container a
//! root filesystem made of a tree digest (docs/briefs/M3-store.md, "Materialize and run").
//!
//!   1. The digest (or a unique prefix of at least 12 hex digits) names a tree in the user's
//!      store: no store, no such tree and an ambiguous prefix are the store's diagnostics
//!      (E0410, E0411, E0412), which end the run before anything is created.
//!   2. In the store's child (`store/namespace.zig`, the user's namespace with the same id map
//!      the container will have) the tree is materialized if it is not yet (`materialize.zig`),
//!      and the container's directory is made: `$XDG_STATE_HOME/zbx/containers/<name>/` with
//!      `merged` (where the overlay is mounted), and `upper` and `work` (or, for a read-only run,
//!      `empty`). An earlier run's directory of the same name is removed first. The upper layer's
//!      root gets the tree root's own mode, owner and attributes: with an upper layer the
//!      overlay shows the upper's root, so it must say what the tree's root says.
//!   3. The plan mounts the overlay (`plan.zig`): lower is the farm, upper and work are the
//!      container's, `userxattr`, inside the container's user and mount namespaces.
//!
//! A failure in the child comes back through a pipe as the child's own diagnostic.
//!
//! The upper layer is kept while the container's run record is kept (`records.runs_max`), so
//! that `commit` works after the container exits. It is removed when the record is pruned, or
//! when a new run takes the name (`remove_container`).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const doctor = @import("../doctor.zig");
const host_mod = @import("../host.zig");
const Diag = @import("../diag/diag.zig").Diag;
const diagnose = @import("../store/diagnose.zig");
const image_diagnose = @import("../image_diagnose.zig");
const image_find = @import("../store/image_find.zig");
const images = @import("../store/images.zig");
const reference_mod = @import("../registry/reference.zig");
const digest_mod = @import("../store/digest.zig");
const layout = @import("../store/layout.zig");
const materialize = @import("../store/materialize.zig");
const namespace = @import("../store/namespace.zig");
const open = @import("../store/open.zig");
const remove = @import("../store/remove.zig");
const trees = @import("../store/trees.zig");
const spec = @import("spec.zig");

const Digest = digest_mod.Digest;
const Host = host_mod.Host;
const Store = layout.Store;

pub const Error = error{Failed};

/// The caller's memory for preparing a run, about 17 MiB; keep it in static or heap storage.
pub const Workspace = struct {
    materialize: materialize.Workspace,
    blob: [constants.store_xattr_blob_bytes_max]u8,
    /// A name that is not a digest is looked for among the image records.
    find: image_find.Memory,
    record: images.Image,
};

/// A path with its own room.
pub const Path = struct {
    bytes: [constants.containers_path_bytes_max + 1]u8,
    len: u16,

    pub fn text(path: *const Path) [:0]const u8 {
        assert(path.len > 0);
        assert(path.bytes[path.len] == 0);
        return path.bytes[0..path.len :0];
    }

    fn set(path: *Path, parts: []const []const u8) bool {
        var length: usize = 0;
        for (parts) |part| {
            if (length + part.len >= path.bytes.len) return false;
            @memcpy(path.bytes[length..][0..part.len], part);
            length += part.len;
        }
        path.bytes[length] = 0;
        path.len = @intCast(length);
        return length > 0;
    }
};

/// What a prepared run needs from the image: the tree and the layers, as paths.
pub const Prepared = struct {
    digest: Digest,
    digest_text: [constants.store_digest_text_bytes]u8,
    /// The farm of the tree (the lower layer).
    lower: Path,
    /// The mount point of the overlay, which becomes the container's root.
    merged: Path,
    /// The writable layer and its work directory; unused for a read-only run.
    upper: Path,
    work: Path,
    /// A read-only run's second lower layer: an empty directory.
    empty: Path,
    read_only: bool,

    pub fn tree_text(prepared: *const Prepared) []const u8 {
        return &prepared.digest_text;
    }

    pub fn overlay(prepared: *const Prepared) @import("plan.zig").Overlay {
        return .{
            .lower = prepared.lower.text(),
            .upper = if (prepared.read_only) null else prepared.upper.text(),
            .work = if (prepared.read_only) null else prepared.work.text(),
            .empty = if (prepared.read_only) prepared.empty.text() else null,
        };
    }
};

/// The base of the containers' directories: `<state>/zbx/containers`, with the part that must
/// already exist (HOME, or the state base). False if the environment gives none.
fn containers_base(host: Host, base: *Path, existing: *u32) bool {
    const suffix = "/zbx/containers";
    const limit: u32 = constants.state_path_bytes_max - suffix.len;
    var state: []const u8 = "";
    if (host.environment("XDG_STATE_HOME", limit)) |found| {
        if (found.len > 0 and found[0] == '/') state = found;
    }
    if (state.len > 0) {
        const trimmed = std.mem.trimEnd(u8, state, "/");
        if (!base.set(&.{ trimmed, suffix })) return false;
        existing.* = @intCast(trimmed.len);
        return true;
    }
    const home = host.environment("HOME", limit - "/.local/state".len) orelse return false;
    if (home.len == 0 or home[0] != '/') return false;
    const trimmed = std.mem.trimEnd(u8, home, "/");
    if (!base.set(&.{ trimmed, "/.local/state", suffix })) return false;
    existing.* = @intCast(trimmed.len);
    return true;
}

/// The directory of the container called `name`.
pub fn container_directory(host: Host, name: []const u8, out: *Path, existing: *u32) bool {
    assert(spec.name_problem(name) == null);
    var base: Path = undefined;
    if (!containers_base(host, &base, existing)) return false;
    return out.set(&.{ base.text(), "/", name });
}

/// Resolves the image, builds what it needs in the store's child, and fills `prepared`.
pub fn prepare(
    host: Host,
    facts: *doctor.Facts,
    workspace: *Workspace,
    image: []const u8,
    name: []const u8,
    read_only: bool,
    warn: ?namespace.Warn,
    prepared: *Prepared,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    var store: Store = undefined;
    if (!store.locate(host)) {
        diagnose.no_data_directory(diag);
        return error.Failed;
    }
    const digest = try resolve(&store, workspace, image, diag);
    var existing: u32 = 0;
    var base: Path = undefined;
    if (!container_directory(host, name, &base, &existing)) {
        diagnose.no_state_directory(diag);
        return error.Failed;
    }
    var farm_storage: @import("../store/fs.zig").PathBuf = undefined;
    const farm = materialize.farm_path(&store, &farm_storage, digest);
    prepared.digest = digest;
    prepared.digest_text = digest.text();
    prepared.read_only = read_only;
    const ok = prepared.lower.set(&.{farm}) and
        prepared.merged.set(&.{ base.text(), "/merged" }) and
        prepared.upper.set(&.{ base.text(), "/upper" }) and
        prepared.work.set(&.{ base.text(), "/work" }) and
        prepared.empty.set(&.{ base.text(), "/empty" });
    if (!ok) {
        diagnose.overlay_path(diag, farm, 0);
        return error.Failed;
    }
    const layers = [_]*const Path{
        &prepared.lower, &prepared.upper, &prepared.work, &prepared.empty,
    };
    for (layers) |layer| {
        if (spec.overlay_path_problem(layer.text())) |byte| {
            diagnose.overlay_path(diag, layer.text(), byte);
            return error.Failed;
        }
    }
    try build(host, facts, workspace, prepared, base.text(), existing, warn, diag);
}

/// The digest `image` names, or the store's diagnostic.
fn resolve(store: *Store, workspace: *Workspace, image: []const u8, diag: *Diag) Error!Digest {
    assert(diag.code == null);
    const prefix = digest_mod.Prefix.parse(image) orelse {
        return resolve_name(store, workspace, image, diag);
    };
    const present = open.check(store, .existing, diag) catch return error.Failed;
    if (!present) {
        diagnose.unknown_digest(diag, image);
        return error.Failed;
    }
    const found = trees.find(store, &prefix) catch |err| {
        diagnose.cannot_read(diag, store, "looking for the tree", err, store.fs.last_errno());
        return error.Failed;
    };
    switch (found) {
        .none => {
            diagnose.unknown_digest(diag, image);
            return error.Failed;
        },
        .many => |two| {
            diagnose.ambiguous_digest(diag, image, two[0], two[1]);
            return error.Failed;
        },
        .one => |digest| return digest,
    }
}

/// A name that is not a digest: the tree of the newest image record that was pulled as it. A
/// library caller that wants the project's lock to decide uses the cli's way (`run_image.zig`);
/// this is the store's own answer, for a caller that has pulled and only names.
fn resolve_name(store: *Store, workspace: *Workspace, name: []const u8, diag: *Diag) Error!Digest {
    assert(diag.code == null);
    var reference: reference_mod.Reference = undefined;
    reference_mod.parse(name, &reference) catch {
        diagnose.bad_digest(diag, name);
        return error.Failed;
    };
    const present = open.check(store, .existing, diag) catch return error.Failed;
    if (!present) {
        image_diagnose.not_locked(diag, name, null);
        return error.Failed;
    }
    var wanted: image_find.ByReference = .{ .text = name };
    if (reference.digest) |manifest| {
        var errno: u16 = 0;
        images.load(store, manifest, &workspace.record, &errno) catch {
            image_diagnose.not_locked(diag, name, null);
            return error.Failed;
        };
        return workspace.record.tree;
    }
    image_find.scan(store, &workspace.find, &workspace.record, &wanted) catch {
        diagnose.cannot_read(
            diag,
            store,
            "looking through the images",
            error.IoFailed,
            store.fs.last_errno(),
        );
        return error.Failed;
    };
    if (!wanted.found) {
        image_diagnose.not_locked(diag, name, null);
        return error.Failed;
    }
    return wanted.tree;
}

// ---- The store's child ---------------------------------------------------------------------

const Job = struct {
    host: Host,
    workspace: *Workspace,
    prepared: *const Prepared,
    base: [:0]const u8,
    existing: u32,
    /// The write end of the pipe the child reports a failure through.
    report: host_mod.Pipe,
};

fn build(
    host: Host,
    facts: *doctor.Facts,
    workspace: *Workspace,
    prepared: *const Prepared,
    base: [:0]const u8,
    existing: u32,
    warn: ?namespace.Warn,
    diag: *Diag,
) Error!void {
    const pipe = host.pipe() catch |err| {
        diagnose.worker_ended(diag, .{ .step = .{
            .name = "pipe",
            .err = err,
            .errno = host.last_errno(),
        } });
        return error.Failed;
    };
    var job: Job = .{
        .host = host,
        .workspace = workspace,
        .prepared = prepared,
        .base = base,
        .existing = existing,
        .report = pipe,
    };
    const work: namespace.Work = .{ .context = &job, .call = work_call };
    const code = namespace.run(host, facts, work, warn, diag) catch {
        host.close(pipe.read);
        host.close(pipe.write);
        return error.Failed;
    };
    host.close(pipe.write);
    defer host.close(pipe.read);
    if (code == constants.exit_ok) return;
    // The child said why, if it could.
    var bytes: [constants.diag_carry_bytes_max]u8 = undefined;
    var length: usize = 0;
    while (length < bytes.len) {
        const count = host.read_some(pipe.read, bytes[length..]) catch break;
        if (count == 0) break;
        length += count;
    }
    if (length > 0 and diag.decode(bytes[0..length])) return error.Failed;
    diag.reset();
    diagnose.worker_ended(diag, .{ .step = .{
        .name = "preparing the tree",
        .err = error.IoFailed,
        .errno = 0,
    } });
    return error.Failed;
}

fn work_call(context: *anyopaque, squash_owner: bool) u8 {
    _ = squash_owner; // A tree imported under the other map fails at its first chown.
    const job: *Job = @ptrCast(@alignCast(context));
    var diag: Diag = undefined;
    diag.reset();
    execute(job, &diag) catch {
        if (diag.code == null) {
            diag.raise(.B0001);
            diag.cause("preparing a tree failed with no diagnostic", .{});
        }
        var bytes: [constants.diag_carry_bytes_max]u8 = undefined;
        const text = diag.encode(&bytes);
        // If this write fails the parent says only that the worker failed.
        job.host.write_handle_all(job.report.write, text) catch {};
        return diag.exit_code();
    };
    return constants.exit_ok;
}

fn execute(job: *Job, diag: *Diag) Error!void {
    const prepared = job.prepared;
    var store: Store = undefined;
    if (!store.locate(job.host)) {
        diagnose.no_data_directory(diag);
        return error.Failed;
    }
    const present = open.check(&store, .existing, diag) catch return error.Failed;
    assert(present); // The caller found the tree in it.
    const ws = &job.workspace.materialize;
    _ = materialize.ensure(&store, ws, prepared.digest, diag) catch return error.Failed;
    // The container's directory, new: whatever an earlier run of the name left is removed.
    try make_container(&store, job, diag);
}

fn make_container(store: *Store, job: *Job, diag: *Diag) Error!void {
    const prepared = job.prepared;
    const fs = store.fs;
    const ws = &job.workspace.materialize;
    var failure: remove.Failure = undefined;
    remove.tree(fs, &ws.removal, &ws.arena, job.base, &failure) catch {
        const operation = "removing the earlier container's directory";
        diagnose.write_failed(diag, store, operation, failure.err, failure.errno);
        return error.Failed;
    };
    try make_path(store, job.base, job.existing, diag);
    const directories = [_]*const Path{
        &prepared.merged,
        if (prepared.read_only) &prepared.empty else &prepared.upper,
        &prepared.work,
    };
    const count: usize = if (prepared.read_only) 2 else 3;
    for (directories[0..count]) |directory| {
        fs.make_directory(directory.text(), false) catch |err| {
            diagnose.write_failed(
                diag,
                store,
                "making the container's directories",
                err,
                fs.last_errno(),
            );
            return error.Failed;
        };
    }
    if (prepared.read_only) return;
    try give_upper_the_root(store, job, diag);
}

/// The upper layer's root says what the tree's root says: the overlay shows the upper's.
fn give_upper_the_root(store: *Store, job: *Job, diag: *Diag) Error!void {
    const prepared = job.prepared;
    const fs = store.fs;
    const ws = &job.workspace.materialize;
    var errno: u16 = 0;
    const own = materialize.root_own(
        store,
        prepared.digest,
        &ws.arena,
        &job.workspace.blob,
        &errno,
    ) catch {
        diagnose.tree_damaged(diag, prepared.digest, "cannot be read for its root directory");
        return error.Failed;
    };
    fs.set_path_attributes(prepared.upper.text(), .{
        .mode = own.mode,
        .uid = own.uid,
        .gid = own.gid,
        .mtime = constants.store_mtime_seconds,
    }) catch |err| {
        diagnose.write_failed(
            diag,
            store,
            "giving the upper layer the tree's root owner",
            err,
            fs.last_errno(),
        );
        return error.Failed;
    };
    var iterator = @import("../store/xattrs.zig").Iterator.init(own.xattrs);
    var name_buffer: [constants.store_xattr_name_bytes_max + 1]u8 = undefined;
    while (iterator.next()) |item| {
        @memcpy(name_buffer[0..item.name.len], item.name);
        name_buffer[item.name.len] = 0;
        fs.set_path_xattr(
            prepared.upper.text(),
            name_buffer[0..item.name.len :0],
            item.value,
        ) catch |err| {
            diagnose.write_failed(
                diag,
                store,
                "giving the upper layer the root's attributes",
                err,
                fs.last_errno(),
            );
            return error.Failed;
        };
    }
}

/// Makes every directory from the first below `existing` bytes of `path` to `path` itself.
fn make_path(store: *Store, path: [:0]const u8, existing: u32, diag: *Diag) Error!void {
    assert(existing < path.len);
    var at: usize = existing;
    var prefix: [constants.containers_path_bytes_max + 1]u8 = undefined;
    while (at < path.len) {
        const next = std.mem.indexOfScalarPos(u8, path, at + 1, '/') orelse path.len;
        @memcpy(prefix[0..next], path[0..next]);
        prefix[next] = 0;
        store.fs.make_directory(prefix[0..next :0], true) catch |err| {
            diagnose.write_failed(
                diag,
                store,
                "making the containers directory",
                err,
                store.fs.last_errno(),
            );
            return error.Failed;
        };
        at = next;
    }
}

// ---- Removing a container's directory -------------------------------------------------------

/// Removes the directory of the container `name`, in the store's child. Nothing to do is not a
/// failure. `failure` says what stayed when it could not be removed.
pub fn remove_container(
    host: Host,
    facts: *doctor.Facts,
    workspace: *Workspace,
    name: []const u8,
    diag: *Diag,
) Error!void {
    var base: Path = undefined;
    var existing: u32 = 0;
    if (!container_directory(host, name, &base, &existing)) return;
    // A look first: most records never had a directory, and a namespace is not free.
    var store: Store = undefined;
    if (!store.locate(host)) return;
    // Anything but "it is there" (not found, or a store that cannot be looked at) is nothing
    // to remove.
    _ = store.fs.lstat(base.text()) catch return;
    var prepared: Prepared = undefined;
    prepared.read_only = false;
    var job: Job = .{
        .host = host,
        .workspace = workspace,
        .prepared = &prepared,
        .base = base.text(),
        .existing = existing,
        .report = host.pipe() catch return error.Failed,
    };
    defer host.close(job.report.read);
    const work: namespace.Work = .{ .context = &job, .call = remove_call };
    const code = namespace.run(host, facts, work, null, diag) catch {
        host.close(job.report.write);
        return error.Failed;
    };
    host.close(job.report.write);
    if (code == constants.exit_ok) return;
    var bytes: [constants.diag_carry_bytes_max]u8 = undefined;
    const count = host.read_some(job.report.read, &bytes) catch 0;
    diag.reset();
    if (count > 0 and diag.decode(bytes[0..count])) return error.Failed;
    diag.reset();
    diagnose.container_not_removed_unknown(diag, base.text());
    return error.Failed;
}

fn remove_call(context: *anyopaque, squash_owner: bool) u8 {
    _ = squash_owner;
    const job: *Job = @ptrCast(@alignCast(context));
    var diag: Diag = undefined;
    diag.reset();
    var store: Store = undefined;
    if (!store.locate(job.host)) {
        diagnose.no_data_directory(&diag);
    } else {
        const ws = &job.workspace.materialize;
        var failure: remove.Failure = undefined;
        remove.tree(store.fs, &ws.removal, &ws.arena, job.base, &failure) catch {
            diagnose.container_not_removed(&diag, &failure);
        };
    }
    if (diag.code == null) return constants.exit_ok;
    var bytes: [constants.diag_carry_bytes_max]u8 = undefined;
    const text = diag.encode(&bytes);
    job.host.write_handle_all(job.report.write, text) catch {};
    return diag.exit_code();
}
