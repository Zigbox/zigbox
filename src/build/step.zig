//! One build step (docs/briefs/M7-build.md, "What a step is"): from its resolved key spec to its
//! output tree. `run_step` is what the scheduler (slice 3) and a library caller call.
//!
//! - **Before**, in the store's namespace (`store/namespace.zig`): the input tree's farm and each
//!   needed step's output farm are made if they are not yet (`materialize.ensure`), and the
//!   step's work directory, `build/work/<container name>/out`, is made empty.
//! - **The container** is an ordinary run (`runtime/run.zig`, M2-hardened: seccomp,
//!   capabilities, `no_new_privs`, the step limits below), on the base tree, as the container's
//!   root, with network none unless the step asks, hostname `build`, umask 022, `/src` the input
//!   farm (read-only, the working directory), `/in/<name>` each need's farm (read-only) and
//!   `/out` the work directory (writable). The run's project directory is the work directory, so
//!   the writable mount's rule ("inside the project") holds without being widened. Its
//!   environment is the base's, then the file's, then the fixed one (`key.fixed_env`).
//! - **After**, on every path: the run's log is copied as plain text to
//!   `build/logs/<group>/<step>.log`, where the group is a digest of the build file's absolute
//!   path (`log_group`), so two projects' steps of one name keep apart (the last line is kept
//!   for the diagnostic), and the run leaves nothing (`run.discard`). Then,
//!   in the store's namespace again: after a zero exit `/out` is imported (owners 0:0, no
//!   attributes, a root labelled `build:<step>` until the parent writes the cache entry, which
//!   then roots it (N8); a device, FIFO or socket is E0806),
//!   and the work directory is removed. A non-zero end is E0805.
//! - **M9 additions** (docs/briefs/M9-dockerfile-import.md): a step may run as `.user` (a name is
//!   looked up in the base tree's /etc/passwd, E0817 if absent; its home is `HOME`) in `.workdir`.
//!   A step with `.output = .root` has no `/src` and no `/out`: it runs in the base as the
//!   container's root, and its output is the run's upper layer, committed before `run.discard`
//!   removes the layers, so a later step can take it as its `step:` base. A `.copy` step runs no
//!   container at all: `compose.zig` makes its output in the parent from the sources' selection
//!   (`copy.zig`).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const doctor = @import("../doctor.zig");
const Diag = @import("../diag/diag.zig").Diag;
const run = @import("../runtime/run.zig");
const spec_mod = @import("../runtime/spec.zig");
const mounts_mod = @import("../runtime/mounts.zig");
const logfile = @import("../runtime/logfile.zig");
const image = @import("../runtime/image.zig");
const layout = @import("../store/layout.zig");
const fs_mod = @import("../store/fs.zig");
const namespace = @import("../store/namespace.zig");
const materialize = @import("../store/materialize.zig");
const import_mod = @import("../store/import.zig");
const image_user = @import("../image_user.zig");
const remove = @import("../store/remove.zig");
const open = @import("../store/open.zig");
const store_diagnose = @import("../store/diagnose.zig");
const lock = @import("../store/lock.zig");
const digest_mod = @import("../store/digest.zig");
const key_mod = @import("key.zig");
const diagnose = @import("diagnose.zig");

const Host = host_mod.Host;
const Digest = digest_mod.Digest;
const Store = layout.Store;
const PathBuf = fs_mod.PathBuf;

pub const Error = error{Failed};

// What a step means is fixed by the constants below, the mount layout in `build_mounts`, the
// environment in `key.fixed_env` and the limits in `start_and_wait`. Changing any of them
// changes what a cached output means: bump `constants.build_step_format_version` with it.
pub const hostname = "build";
pub const umask: u16 = 0o022;
/// A step's container name: this, the step's name, `-`, and random hex.
pub const name_prefix = "build-";
const name_hex_digits = 16;
const env_count_max = constants.env_vars_count_max + constants.build_step_env_max +
    key_mod.fixed_env.len + 1;
const mounts_count = constants.mounts_max;

comptime {
    assert(mounts_count <= constants.mounts_max);
    assert(name_prefix.len + constants.build_step_name_bytes_max + 1 + name_hex_digits <=
        constants.container_name_bytes_max);
    assert(umask <= 0o777);
}

pub const Request = struct {
    host: Host,
    facts: *doctor.Facts,
    spec: *const key_mod.Spec,
    /// The build file as the project sees it, for the diagnostic's fix (`zbx.build.zon`).
    file: []const u8,
    /// Where the logs of this build file's steps are kept (`log_group`), `log_group_bytes`.
    group: []const u8,
    warn: ?run.Warn = null,
    /// Stream the step's output to standard error as it runs, each line after `<step> | `
    /// (`zbx build --verbose`). The log is kept either way.
    stream: bool = false,
};

pub const log_group_bytes = 16;

/// The log directory's name for a build file: a digest of its absolute path.
pub fn log_group(out: *[log_group_bytes]u8, absolute_file: []const u8) []const u8 {
    assert(absolute_file.len > 0);
    assert(absolute_file[0] == '/');
    // The hex alone: the group names directories that are mounted (`build/caches/<group>`),
    // and a mount's host path may not hold the `:` of `b3:` (volume.path_problem).
    const hex = Digest.of(absolute_file).hex();
    @memcpy(out, hex[0..log_group_bytes]);
    assert(std.mem.indexOfScalar(u8, out, ':') == null);
    return out;
}

pub const Result = struct {
    output: Digest,
    files: u64,
};

/// The caller's memory for a step, about 35 MiB: keep it in static storage or on the heap. One
/// step at a time per workspace.
pub const Workspace = struct {
    handle: run.Handle,
    image: image.Workspace,
    import: import_mod.Workspace,
    reader: logfile.Reader,
    paths: Paths,
    env: [env_count_max]spec_mod.Label,
    mounts: [mounts_count]mounts_mod.Mount,
    targets: [constants.build_step_needs_max][4 + constants.build_step_name_bytes_max]u8,
    last_line: [constants.diag_field_bytes_max]u8,
    last_line_len: u32,
    import_result: import_mod.Result,
    /// The `.user` resolved against the base tree (`resolve_identity`), and its home.
    user_ws: image_user.Workspace,
    user: ?spec_mod.User,
    home: [image_user.home_bytes_max]u8,
    home_len: u8,
    /// How many of `mounts` the container has; a root step's commit leaves them out.
    mount_count: u32,
};

const Paths = struct {
    name: [constants.container_name_bytes_max]u8,
    name_len: u8,
    image: [constants.store_digest_text_bytes]u8,
    work: PathBuf,
    out: PathBuf,
    log: PathBuf,
    src: PathBuf,
    needs: [constants.build_step_needs_max]PathBuf,
    /// The farms of the step's `.binds` trees, and the directory of each of its caches.
    binds: [constants.build_step_binds_max]PathBuf,
    caches_root: PathBuf,
    caches: [constants.build_step_caches_max]PathBuf,

    fn name_slice(paths: *const Paths) []const u8 {
        assert(paths.name_len > 0);
        assert(paths.name_len <= paths.name.len);
        return paths.name[0..paths.name_len];
    }

    fn work_text(paths: *const Paths) [:0]const u8 {
        assert(paths.work.len > 0);
        assert(paths.out.len > paths.work.len);
        return paths.work.text();
    }

    fn out_text(paths: *const Paths) [:0]const u8 {
        assert(paths.out.len > paths.work.len);
        assert(std.mem.endsWith(u8, paths.out.text(), "/out"));
        return paths.out.text();
    }

    fn log_text(paths: *const Paths) [:0]const u8 {
        assert(paths.log.len > 0);
        assert(std.mem.endsWith(u8, paths.log.text(), ".log"));
        return paths.log.text();
    }
};

/// Runs one step and imports its output. On `Failed`, `diag` says why (E0805, E0806, or the
/// store's and the run's own codes).
pub fn run_step(request: *const Request, ws: *Workspace, result: *Result, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(request.spec.name.len > 0);
    assert(request.spec.needs.len <= constants.build_step_needs_max);
    var store: Store = undefined;
    if (!store.locate(request.host)) {
        store_diagnose.no_data_directory(diag);
        return error.Failed;
    }
    try name_paths(request, &store, ws);
    try check_env(request, ws, diag);
    // A sweep of the work directories (`sweep`) takes the lock exclusively, so a step in flight
    // keeps its own directory.
    try store_diagnose.hold(diag, &store, .shared, "build", "running a build step");
    defer lock.release(&store);
    try resolve_identity(request, &store, ws, diag);
    try in_store(request, ws, .prepare, diag);
    defer cleanup(request, ws);
    const reason = try start_and_wait(request, ws, diag);
    copy_log(request, &store, ws);
    const end = step_end(&ws.handle, reason);
    // A root step's output is its upper layer, which `run.discard` removes: commit it first.
    var committed = true;
    if (end == null and request.spec.root_output) {
        in_store(request, ws, .commit, diag) catch {
            committed = false;
        };
    }
    run.discard(&ws.handle);
    if (!committed) return error.Failed;
    if (end) |end_reason| {
        const failure: diagnose.StepFailure = .{
            .step = request.spec.name,
            .file = request.file,
            .end = end_reason,
            .network = request.spec.network,
            .last_line = ws.last_line[0..ws.last_line_len],
            .log = ws.paths.log_text(),
        };
        diagnose.step_failed(diag, &failure);
        return error.Failed;
    }
    if (!request.spec.root_output) try in_store(request, ws, .import, diag);
    result.* = .{ .output = ws.import_result.digest, .files = ws.import_result.files };
}

/// The step's `.user`, resolved against its base tree: the ids it runs as and its home. A name
/// the base's files lack is E0817, mid-build, because a `step:` base exists only after the
/// steps before it ran.
fn resolve_identity(
    request: *const Request,
    store: *const Store,
    ws: *Workspace,
    diag: *Diag,
) Error!void {
    const spec = request.spec;
    assert(diag.code == null);
    ws.user = null;
    ws.home_len = 0;
    const text = spec.user orelse return;
    assert(text.len > 0);
    const found = image_user.resolve(store, &ws.user_ws, spec.base_tree, text, diag) catch {
        // The image's own `User` is E0521; here the build file named it.
        diag.reset();
        var where: [constants.build_step_name_bytes_max + 8]u8 = undefined;
        // The buffer holds the name at its bound plus `step ""`.
        const named = std.fmt.bufPrint(&where, "step \"{s}\"", .{spec.name}) catch unreachable;
        diagnose.user_not_found(diag, named, text, ws.user_ws.too_large);
        return error.Failed;
    };
    ws.user = found.user;
    const home = found.home_text();
    @memcpy(ws.home[0..home.len], home);
    ws.home_len = @intCast(home.len);
    assert(ws.home_len > 0);
}

// ---- Names and paths ----------------------------------------------------------------------------

fn name_paths(request: *const Request, store: *const Store, ws: *Workspace) Error!void {
    const spec = request.spec;
    assert(spec.name.len <= constants.build_step_name_bytes_max);
    const paths = &ws.paths;
    var random: [name_hex_digits / 2]u8 = undefined;
    // A name only has to be apart from a concurrent step's; zeroes are a name too.
    request.host.random_bytes(&random) catch @memset(&random, 0);
    const hex = std.fmt.bytesToHex(random, .lower);
    const name = std.fmt.bufPrint(&paths.name, name_prefix ++ "{s}-{s}", .{ spec.name, &hex }) catch
        unreachable; // The comptime check above bounds it.
    paths.name_len = @intCast(name.len);
    assert(spec_mod.name_problem(name) == null);
    paths.image = spec.base_tree.text();
    _ = store.path(&paths.work, &.{ "/build/work/", name });
    _ = store.path(&paths.out, &.{ "/build/work/", name, "/out" });
    assert(request.group.len == log_group_bytes);
    _ = store.path(&paths.log, &.{ "/build/logs/", request.group, "/", spec.name, ".log" });
    _ = materialize.farm_path(store, &paths.src, spec.input_tree);
    for (spec.needs, 0..) |need, index| {
        _ = materialize.farm_path(store, &paths.needs[index], need.output);
        const target = std.fmt.bufPrint(&ws.targets[index], "/in/{s}", .{need.name}) catch
            unreachable; // A need is a step's name, at most 32 bytes.
        assert(target.len > 4);
    }
    for (spec.binds, 0..) |found, index| {
        _ = materialize.farm_path(store, &paths.binds[index], found.source);
    }
    _ = store.path(&paths.caches_root, &.{ "/build/caches/", request.group });
    for (spec.caches, 0..) |cache, index| {
        var dir_name: [cache_dir_bytes_max]u8 = undefined;
        const dir = cache_dir_name(&dir_name, cache.id);
        const parts = [_][]const u8{ paths.caches_root.text(), "/", dir };
        paths.caches[index].set(&parts) catch unreachable; // Sized for the longest.
    }
}

const cache_dir_bytes_max = constants.build_label_key_bytes_max + 1;

/// The directory name of a cache id: a `/` is `%` (an id has no `%`), and a name that starts with
/// a `.` gets a `~` in front (an id has no `~`), so no id is `.` or `..` and two ids never meet.
pub fn cache_dir_name(out: *[cache_dir_bytes_max]u8, id: []const u8) []const u8 {
    assert(id.len > 0);
    assert(id.len < out.len);
    var length: usize = 0;
    if (id[0] == '.') {
        out[0] = '~';
        length = 1;
    }
    for (id) |byte| {
        out[length] = if (byte == '/') '%' else byte;
        length += 1;
    }
    return out[0..length];
}

// ---- The container ------------------------------------------------------------------------------

fn start_and_wait(request: *const Request, ws: *Workspace, diag: *Diag) Error!run.ExitReason {
    const spec = request.spec;
    const paths = &ws.paths;
    assert(spec.argv.len > 0);
    const env_count = build_env(spec, ws.home[0..ws.home_len], &ws.env);
    const mount_count = build_mounts(spec, ws);
    ws.mount_count = mount_count;
    const container: spec_mod.Spec = .{
        .image = &paths.image,
        .name = paths.name_slice(),
        .command = spec.argv,
        .env = ws.env[0..env_count],
        .workdir = spec.workdir orelse if (spec.root_output) "/" else "/src",
        .user = ws.user,
        .user_text = spec.user orelse "",
        .network = if (spec.network) .user else .none,
        .mounts = ws.mounts[0..mount_count],
        .project = paths.work_text(),
        .caches_root = paths.caches_root.text(),
        .hostname = hostname,
        .umask = umask,
        .limits = .{
            .memory_bytes = constants.build_step_memory_bytes,
            .pids = constants.build_step_pids,
        },
    };
    var prefix_storage: [run.stream_prefix_bytes_max]u8 = undefined;
    const prefix = if (request.stream) stream_prefix(&prefix_storage, spec.name) else "";
    const options: run.StartOptions = .{
        .warn = request.warn,
        .stream_prefix = prefix,
        .timeout_ms = constants.build_step_timeout_ms,
        .image_workspace = &ws.image,
        .keep_log = true,
        .mirror = false,
        .stdin_null = true,
        .build_step = true,
    };
    run.start(request.host, &container, options, &ws.handle, diag) catch {
        // A start that fails after the record began has saved a `start_failed` record; the
        // step leaves none. The log of a start that never ran is of no use.
        if (ws.handle.status == .stopped) run.discard(&ws.handle);
        return error.Failed;
    };
    const reason = run.wait(&ws.handle);
    assert(ws.handle.status == .stopped);
    return reason;
}

/// `<step> | `, the start of each streamed line.
fn stream_prefix(out: *[run.stream_prefix_bytes_max]u8, name: []const u8) []const u8 {
    assert(name.len > 0);
    assert(name.len <= constants.build_step_name_bytes_max);
    return std.fmt.bufPrint(out, "{s} | ", .{name}) catch unreachable; // `name` is bounded.
}

/// Refuses, naming the step and the file, an environment the run would refuse with no step in
/// sight (`spec.env_problem`: more than `env_vars_count_max` merged variables, or too many
/// bytes with the command). An argv the run will refuse itself is left to it.
fn check_env(request: *const Request, ws: *Workspace, diag: *Diag) Error!void {
    const spec = request.spec;
    assert(diag.code == null);
    if (spec_mod.command_problem(spec.argv) != null) return;
    const count = build_env(spec, "", &ws.env);
    const problem = spec_mod.env_problem(ws.env[0..count], spec.argv) orelse return;
    const key = if (problem < count) ws.env[problem].key else "";
    diagnose.step_env_refused(diag, spec.name, request.file, count, key);
    return error.Failed;
}

/// The base's environment, then the file's, then the fixed one: a later key replaces an
/// earlier one in place, so each key is there once.
fn build_env(
    spec: *const key_mod.Spec,
    home: []const u8,
    out: *[env_count_max]spec_mod.Label,
) u32 {
    assert(spec.base_env.len <= constants.env_vars_count_max);
    assert(spec.env.len <= constants.build_step_env_max);
    var count: u32 = 0;
    for (spec.base_env) |entry| add_env(out, &count, entry);
    for (spec.env) |entry| add_env(out, &count, entry);
    for (key_mod.fixed_env) |entry| add_env(out, &count, entry);
    // A step that names a user has that user's home, not root's.
    if (home.len > 0) add_label(out, &count, .{ .key = "HOME", .value = home });
    const step_key = key_mod.step_variable[0 .. key_mod.step_variable.len - 1];
    add_label(out, &count, .{ .key = step_key, .value = spec.name });
    assert(count <= env_count_max);
    return count;
}

fn add_env(out: *[env_count_max]spec_mod.Label, count: *u32, entry: []const u8) void {
    assert(count.* <= out.len);
    // An entry without `=` was refused when the image or the file was read.
    const at = std.mem.indexOfScalar(u8, entry, '=') orelse return;
    assert(at > 0);
    add_label(out, count, .{ .key = entry[0..at], .value = entry[at + 1 ..] });
}

fn add_label(out: *[env_count_max]spec_mod.Label, count: *u32, label: spec_mod.Label) void {
    assert(label.key.len > 0);
    for (out[0..count.*]) |*slot| {
        if (std.mem.eql(u8, slot.key, label.key)) {
            slot.value = label.value;
            return;
        }
    }
    assert(count.* < out.len);
    out[count.*] = label;
    count.* += 1;
}

fn build_mounts(spec: *const key_mod.Spec, ws: *Workspace) u32 {
    const paths = &ws.paths;
    assert(spec.needs.len <= constants.build_step_needs_max);
    var count: u32 = 0;
    // A root step's output is its root: it has no `/src` and no `/out`.
    if (!spec.root_output) {
        ws.mounts[count] = bind(.bind, paths.src.text(), "/src");
        count += 1;
    }
    for (spec.needs, 0..) |need, index| {
        const target = ws.targets[index][0 .. 4 + need.name.len];
        ws.mounts[count] = bind(.bind, paths.needs[index].text(), target);
        count += 1;
    }
    if (!spec.root_output) {
        ws.mounts[count] = bind(.mount, paths.out_text(), "/out");
        count += 1;
    }
    for (spec.binds, 0..) |found, index| {
        ws.mounts[count] = bind(.bind, paths.binds[index].text(), found.to);
        count += 1;
    }
    for (spec.caches, 0..) |cache, index| {
        const kind: mounts_mod.Kind = if (cache.ro) .bind else .cache;
        ws.mounts[count] = bind(kind, paths.caches[index].text(), cache.path);
        count += 1;
    }
    assert(count <= mounts_count);
    return count;
}

fn bind(kind: mounts_mod.Kind, source: []const u8, target: []const u8) mounts_mod.Mount {
    assert(source.len > 0);
    assert(target[0] == '/');
    return .{ .kind = kind, .source = source, .target = target, .size_bytes = 0 };
}

/// How the step ended, when it did not exit 0; null when it did.
fn step_end(handle: *const run.Handle, reason: run.ExitReason) ?diagnose.StepEnd {
    assert(handle.status == .stopped);
    if (run.timed_out(handle)) return .{ .timed_out = constants.build_step_timeout_ms };
    const end: diagnose.StepEnd = switch (reason) {
        .exited => |code| if (code == 0) return null else .{ .exited = code },
        .signaled => |number| .{ .signaled = number },
        .oom => |hit| .{ .oom = hit.limit_bytes },
        .pid_limit => |hit| .{ .pid_limit = hit.limit },
        .start_failed, .lost => .lost,
    };
    assert(std.meta.activeTag(end) != .timed_out);
    return end;
}

// ---- The log ------------------------------------------------------------------------------------

/// Copies the run's log, both streams in order, to `build/logs/<group>/<step>.log` as plain
/// text, and keeps its last line. It is written inside the work directory first, so that what a
/// crash leaves is swept with it. Best effort: a step whose log cannot be kept still has its
/// output.
fn copy_log(request: *const Request, store: *const Store, ws: *Workspace) void {
    assert(ws.handle.status == .stopped);
    ws.last_line_len = 0;
    const fs = store.fs;
    var dir: PathBuf = undefined;
    fs.make_directory(store.path(&dir, &.{"/build"}), true) catch return;
    fs.make_directory(store.path(&dir, &.{"/build/logs"}), true) catch return;
    fs.make_directory(store.path(&dir, &.{ "/build/logs/", request.group }), true) catch return;
    var temporary: PathBuf = undefined;
    temporary.set(&.{ ws.paths.work_text(), "/log" }) catch return;
    const temporary_path = temporary.text();
    const fd = fs.create(temporary_path, 0o644) catch return;
    var written = true;
    logfile.open_log(&ws.reader, request.host, ws.paths.name_slice()) catch {
        written = false;
    };
    if (written) {
        written = copy_records(fs, fd, ws);
        ws.reader.close();
    }
    fs.close(fd);
    if (written) fs.rename(temporary_path, ws.paths.log_text()) catch {
        written = false;
    };
    if (!written) fs.unlink(temporary_path) catch {};
}

fn copy_records(fs: fs_mod.Fs, fd: fs_mod.Fd, ws: *Workspace) bool {
    assert(ws.last_line_len == 0);
    var records_left: u64 = constants.log_bytes_max;
    while (records_left > 0) : (records_left -= 1) {
        switch (ws.reader.next()) {
            .record => |record| {
                fs.write_all(fd, record.payload) catch return false;
                keep_last_line(ws, record.payload);
            },
            .end => return true,
            .damaged, .failed => return false,
        }
    }
    return true; // Every record holds a byte at least, so the log's bound ends the loop first.
}

/// The last non-empty line of what has been copied so far, cut to a diagnostic field.
fn keep_last_line(ws: *Workspace, payload: []const u8) void {
    assert(ws.last_line_len <= ws.last_line.len);
    const trimmed = std.mem.trimEnd(u8, payload, "\r\n");
    if (trimmed.len == 0) return;
    const start = if (std.mem.lastIndexOfScalar(u8, trimmed, '\n')) |at| at + 1 else 0;
    const line = trimmed[start..];
    const length: u32 = @intCast(@min(line.len, ws.last_line.len));
    // A record that ends without a line end continues the line the next record ends.
    @memcpy(ws.last_line[0..length], line[0..length]);
    ws.last_line_len = length;
    assert(ws.last_line_len <= ws.last_line.len);
}

// ---- In the store's namespace -------------------------------------------------------------------

const Action = enum { prepare, import, commit, remove, sweep, clear_caches };

/// The actions that work on a directory of the store and not on one step's work directory.
fn is_store_wide(action: Action) bool {
    return action == .sweep or action == .clear_caches;
}

/// What the child gets. It has its own copy of memory, so what it learns comes back through
/// `report`: a diagnostic on failure, the import's digest and file count on success.
const Job = struct {
    request: *const Request,
    ws: *Workspace,
    action: Action,
    report: host_mod.Pipe,
    /// Set by `job_call`: whether the namespace maps only the caller's own id (a commit's owners).
    squash_owner: bool = true,
};

/// The import's answer on the pipe: the digest, then the file count, little-endian.
const answer_bytes = constants.store_digest_bytes + 8;

comptime {
    assert(answer_bytes < constants.diag_carry_bytes_max);
    assert(@typeInfo(Action).@"enum".field_names.len == 6);
}

fn in_store(request: *const Request, ws: *Workspace, action: Action, diag: *Diag) Error!void {
    assert(diag.code == null);
    if (!is_store_wide(action)) assert(ws.paths.work.len > 0);
    const host = request.host;
    var job: Job = .{
        .request = request,
        .ws = ws,
        .action = action,
        .report = host.pipe() catch |err| {
            store_diagnose.worker_ended(diag, .{ .step = .{
                .name = "pipe",
                .err = err,
                .errno = host.last_errno(),
            } });
            return error.Failed;
        },
    };
    defer host.close(job.report.read);
    const work: namespace.Work = .{ .context = &job, .call = job_call };
    const code = namespace.run(host, request.facts, work, null, diag) catch {
        host.close(job.report.write);
        return error.Failed;
    };
    host.close(job.report.write);
    var bytes: [constants.diag_carry_bytes_max]u8 = undefined;
    var length: usize = 0;
    while (length < bytes.len) {
        const count = host.read_some(job.report.read, bytes[length..]) catch break;
        if (count == 0) break;
        length += count;
    }
    if (code == constants.exit_ok) return take_answer(ws, action, bytes[0..length], diag);
    if (length > 0 and diag.decode(bytes[0..length])) return error.Failed;
    diag.reset();
    store_diagnose.worker_ended(diag, .{ .step = .{
        .name = @tagName(action),
        .err = error.IoFailed,
        .errno = 0,
    } });
    return error.Failed;
}

fn take_answer(ws: *Workspace, action: Action, answer: []const u8, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(answer.len <= constants.diag_carry_bytes_max);
    if (action != .import and action != .commit) return;
    if (answer.len != answer_bytes) {
        store_diagnose.worker_ended(diag, .{ .step = .{
            .name = "importing the step's output",
            .err = error.IoFailed,
            .errno = 0,
        } });
        return error.Failed;
    }
    const digest_bytes = constants.store_digest_bytes;
    ws.import_result = std.mem.zeroes(import_mod.Result);
    @memcpy(&ws.import_result.digest.bytes, answer[0..digest_bytes]);
    ws.import_result.files = std.mem.readInt(u64, answer[digest_bytes..][0..8], .little);
}

fn job_call(context: *anyopaque, squash_owner: bool) u8 {
    const job: *Job = @ptrCast(@alignCast(context));
    // An import squashes owners to 0:0 either way; a commit keeps the container's ids.
    job.squash_owner = squash_owner;
    if (!is_store_wide(job.action)) assert(job.ws.paths.work.len > 0);
    var diag: Diag = undefined;
    diag.reset();
    var answer: [answer_bytes]u8 = undefined;
    var answer_len: usize = 0;
    var store: Store = undefined;
    if (!store.locate(job.request.host)) {
        store_diagnose.no_data_directory(&diag);
    } else if (execute(&store, job, &diag)) {
        if (job.action == .import or job.action == .commit) {
            const result = &job.ws.import_result;
            @memcpy(answer[0..constants.store_digest_bytes], &result.digest.bytes);
            const count = answer[constants.store_digest_bytes..][0..8];
            std.mem.writeInt(u64, count, result.files, .little);
            answer_len = answer.len;
        }
    } else |_| {
        if (diag.code == null) {
            diag.raise(.B0001);
            diag.cause("a build step's store work failed with no diagnostic", .{});
        }
    }
    const host = job.request.host;
    if (diag.code == null) {
        // If this write fails the parent says the worker ended without an answer.
        // Only an import has an answer; the host refuses to write nothing.
        if (answer_len > 0) {
            host.write_handle_all(job.report.write, answer[0..answer_len]) catch {};
        }
        return constants.exit_ok;
    }
    var bytes: [constants.diag_carry_bytes_max]u8 = undefined;
    host.write_handle_all(job.report.write, diag.encode(&bytes)) catch {};
    return diag.exit_code();
}

fn execute(store: *Store, job: *Job, diag: *Diag) Error!void {
    assert(diag.code == null);
    if (!is_store_wide(job.action)) assert(job.ws.paths.out.len > job.ws.paths.work.len);
    switch (job.action) {
        .prepare => try prepare(store, job, diag),
        .import => try import_output(store, job, diag),
        .commit => try commit_output(store, job, diag),
        .remove => try remove_work(store, job, job.ws.paths.work_text(), diag),
        .sweep => {
            // Under the exclusive lock the parent holds: nothing here may take the lock.
            var dir: PathBuf = undefined;
            try remove_work(store, job, store.path(&dir, &.{"/build/work"}), diag);
        },
        .clear_caches => try remove_caches(store, job, diag),
    }
}

/// Empties this build file's cache directories (`--clear-caches`): their files belong to
/// subordinate ids, which only the namespace's root may remove. The next step that mounts a
/// cache makes its directory again.
fn remove_caches(store: *Store, job: *Job, diag: *Diag) Error!void {
    assert(diag.code == null);
    const group = job.request.group;
    assert(group.len == log_group_bytes);
    var dir: PathBuf = undefined;
    const path = store.path(&dir, &.{ "/build/caches/", group });
    assert(std.mem.indexOf(u8, path, "/build/caches/") != null);
    const ws = &job.ws.image.materialize;
    var failure: remove.Failure = undefined;
    remove.tree(store.fs, &ws.removal, &ws.arena, path, &failure) catch {
        const operation = "emptying the build's cache directories";
        store_diagnose.write_failed(diag, store, operation, failure.err, failure.errno);
        return error.Failed;
    };
}

fn remove_work(store: *Store, job: *Job, path: [:0]const u8, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(std.mem.indexOf(u8, path, "/build/work") != null);
    const ws = &job.ws.image.materialize;
    var failure: remove.Failure = undefined;
    remove.tree(store.fs, &ws.removal, &ws.arena, path, &failure) catch {
        const operation = "removing a build step's work directory";
        store_diagnose.write_failed(diag, store, operation, failure.err, failure.errno);
        return error.Failed;
    };
}

/// The farms the container mounts, and an empty work directory with its `out`.
fn prepare(store: *Store, job: *Job, diag: *Diag) Error!void {
    const spec = job.request.spec;
    assert(diag.code == null);
    const present = open.check(store, .existing, diag) catch return error.Failed;
    if (!present) {
        store_diagnose.no_data_directory(diag);
        return error.Failed;
    }
    const ws = &job.ws.image.materialize;
    _ = materialize.ensure(store, ws, spec.input_tree, diag) catch return error.Failed;
    for (spec.needs) |need| {
        _ = materialize.ensure(store, ws, need.output, diag) catch return error.Failed;
    }
    for (spec.binds) |found| {
        _ = materialize.ensure(store, ws, found.source, diag) catch return error.Failed;
    }
    const fs = store.fs;
    var dir: PathBuf = undefined;
    const steps = [_]struct { parts: []const []const u8, exist_ok: bool }{
        .{ .parts = &.{"/build"}, .exist_ok = true },
        .{ .parts = &.{"/build/work"}, .exist_ok = true },
    };
    for (steps) |step| {
        fs.make_directory(store.path(&dir, step.parts), step.exist_ok) catch |err| {
            return made_nothing(store, diag, err);
        };
    }
    // A name is new, so the work directory is too.
    fs.make_directory(job.ws.paths.work_text(), false) catch |err| {
        return made_nothing(store, diag, err);
    };
    fs.make_directory(job.ws.paths.out_text(), false) catch |err| {
        return made_nothing(store, diag, err);
    };
    try make_caches(store, job, diag);
    if (spec.user != null) {
        // A step that runs as someone else must be able to write its `/out`; the import
        // squashes the owners and the output's modes are what it makes of them.
        const open_mode: fs_mod.PathAttributes = .{
            .mode = 0o777,
            .uid = 0,
            .gid = 0,
            .mtime = 0,
            .set_owner = false,
        };
        fs.set_path_attributes(job.ws.paths.out_text(), open_mode) catch |err| {
            return made_nothing(store, diag, err);
        };
    }
}

/// The step's cache directories, kept between builds: made if they are not there, with the mode
/// the entry asks for (only when first made), and given to the ids the entry names, else to the
/// step's user, as the container sees them. A host with the one-id map leaves the owner as it is.
fn make_caches(store: *Store, job: *Job, diag: *Diag) Error!void {
    const spec = job.request.spec;
    if (spec.caches.len == 0) return;
    const fs = store.fs;
    const paths = &job.ws.paths;
    var dir: PathBuf = undefined;
    fs.make_directory(store.path(&dir, &.{"/build/caches"}), true) catch |err| {
        return made_caches_nothing(store, diag, err);
    };
    fs.make_directory(paths.caches_root.text(), true) catch |err| {
        return made_caches_nothing(store, diag, err);
    };
    const user = job.ws.user;
    for (spec.caches, 0..) |cache, index| {
        const path = paths.caches[index].text();
        const fresh = if (fs.lstat(path)) |_| false else |_| true;
        fs.make_directory(path, true) catch |err| return made_caches_nothing(store, diag, err);
        const attributes: fs_mod.PathAttributes = .{
            .mode = if (fresh) cache.mode orelse 0o755 else null,
            .uid = cache.uid orelse if (user) |found| found.uid else 0,
            .gid = cache.gid orelse if (user) |found| found.gid else 0,
            .mtime = 0,
            .set_owner = !job.squash_owner,
        };
        fs.set_path_attributes(path, attributes) catch |err| {
            return made_caches_nothing(store, diag, err);
        };
    }
}

fn made_caches_nothing(store: *const Store, diag: *Diag, err: fs_mod.Error) Error {
    assert(diag.code == null);
    const operation = "making a build step's cache directory";
    store_diagnose.write_failed(diag, store, operation, err, store.fs.last_errno());
    return error.Failed;
}

fn made_nothing(store: *const Store, diag: *Diag, err: fs_mod.Error) Error {
    assert(diag.code == null);
    assert(@errorName(err).len > 0);
    const operation = "making a build step's work directory";
    store_diagnose.write_failed(diag, store, operation, err, store.fs.last_errno());
    return error.Failed;
}

/// The source of the root a step's import leaves until the cache entry holds the output.
pub const output_root_prefix = "build:";

fn import_output(store: *Store, job: *Job, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(job.action == .import);
    var refusal: Refusal = .{ .step = job.request.spec.name };
    // The output is rooted until the parent has written the cache entry, which then holds it
    // (N8): `compose.zig` removes a root whose source starts with `output_root_prefix`.
    var label: [output_root_prefix.len + constants.build_step_name_bytes_max]u8 = undefined;
    const labelled = std.fmt.bufPrint(&label, output_root_prefix ++ "{s}", .{
        job.request.spec.name,
    }) catch unreachable; // The buffer holds the prefix and the longest name.
    const options: import_mod.Options = .{
        .squash_owner = true,
        .warn = null,
        .drop_xattrs = true,
        .refuse_special = .{ .context = &refusal, .call = Refusal.call },
        .save_root = true,
        .keep_existing_root = true,
        .label = labelled,
    };
    const ws = job.ws;
    const out = ws.paths.out_text();
    import_mod.import(store, &ws.import, out, options, &ws.import_result, diag) catch
        return error.Failed;
}

/// A root step's output: its upper layer committed onto the base tree, deletions applied and no
/// whiteouts kept, owners in the container's ids. The mounts' targets are mount points zbx made,
/// not changes.
fn commit_output(store: *Store, job: *Job, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(job.action == .commit);
    const ws = job.ws;
    var refusal: Refusal = .{ .step = job.request.spec.name };
    var label: [output_root_prefix.len + constants.build_step_name_bytes_max]u8 = undefined;
    const labelled = std.fmt.bufPrint(&label, output_root_prefix ++ "{s}", .{
        job.request.spec.name,
    }) catch unreachable; // The buffer holds the prefix and the longest name.
    var excluded: [constants.mounts_max][]const u8 = undefined;
    assert(ws.mount_count <= excluded.len);
    for (ws.mounts[0..ws.mount_count], 0..) |mount, at| excluded[at] = mount.target;
    const options: import_mod.Options = .{
        .squash_owner = job.squash_owner,
        .warn = null,
        .parent = job.request.spec.base_tree,
        .exclude = excluded[0..ws.mount_count],
        .refuse_special = .{ .context = &refusal, .call = Refusal.call },
        .save_root = true,
        .keep_existing_root = true,
        .label = labelled,
    };
    const upper = ws.handle.image.upper.text();
    import_mod.commit(store, &ws.import, upper, options, &ws.import_result, diag) catch
        return error.Failed;
}

/// Turns a device, FIFO or socket under `/out` into E0806.
const Refusal = struct {
    step: []const u8,

    fn call(context: *anyopaque, diag: *Diag, relative: []const u8, kind: []const u8) void {
        const refusal: *const Refusal = @ptrCast(@alignCast(context));
        assert(relative.len > 0);
        assert(relative[0] == '/');
        diagnose.output_refused(diag, refusal.step, relative, kind);
    }
};

/// The work directory goes on every path, best effort: a step that cannot remove it has its
/// result anyway, and the next `zbx gc` finds what is left.
fn cleanup(request: *const Request, ws: *Workspace) void {
    assert(ws.paths.work.len > 0);
    assert(request.spec.name.len > 0);
    var diag: Diag = undefined;
    diag.reset();
    in_store(request, ws, .remove, &diag) catch {};
}

/// Clears `build/work`, which a crashed or killed step leaves its directory in, with the log
/// temporary inside it. Call it before a build starts steps. It takes the store lock
/// exclusively, so no step is in flight; if the lock is busy a build is running, and its
/// directories are not leftovers, so nothing is done and nothing is said. A store that does not
/// exist yet (a clean machine's first build) has nothing to sweep, and is not an error.
pub fn sweep(request: *const Request, ws: *Workspace, diag: *Diag) Error!void {
    assert(diag.code == null);
    var store: Store = undefined;
    if (!store.locate(request.host)) {
        store_diagnose.no_data_directory(diag);
        return error.Failed;
    }
    lock.hold(&store, .exclusive, "build sweep") catch |err| {
        if (err == error.Busy) return;
        // A machine that has never written the store has no lock file and no leftovers.
        if (store.lock_error == error.NotFound) return;
        const operation = "taking the store lock";
        store_diagnose.write_failed(diag, &store, operation, store.lock_error, store.lock_errno);
        return error.Failed;
    };
    defer lock.release(&store);
    try in_store(request, ws, .sweep, diag);
}

/// Empties the cache directories of `request.group` (`zbx build --clear-caches`), under the
/// exclusive lock: a build that holds a cache has the lock shared, so this refuses (E0436)
/// instead of pulling a directory out from under a running step. A store that does not exist
/// has no caches.
pub fn clear_caches(request: *const Request, ws: *Workspace, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(request.group.len == log_group_bytes);
    var store: Store = undefined;
    if (!store.locate(request.host)) {
        store_diagnose.no_data_directory(diag);
        return error.Failed;
    }
    lock.hold(&store, .exclusive, "build clear-caches") catch |err| {
        if (err == error.Busy) {
            store_diagnose.store_busy(diag, "emptying the build's caches", lock.holder(&store));
            return error.Failed;
        }
        if (store.lock_error == error.NotFound) return;
        const operation = "taking the store lock";
        store_diagnose.write_failed(diag, &store, operation, store.lock_error, store.lock_errno);
        return error.Failed;
    };
    defer lock.release(&store);
    try in_store(request, ws, .clear_caches, diag);
}

// ---- Tests ----------------------------------------------------------------------------------

const testing = std.testing;

fn test_spec() key_mod.Spec {
    return .{
        .platform = "linux/amd64",
        .base_tree = Digest.of("base"),
        .base_env = &.{ "PATH=/usr/bin:/bin", "HOME=/root", "LANG=C.UTF-8" },
        .input_tree = Digest.of("input"),
        .needs = &.{},
        .argv = &.{ "make", "all" },
        .env = &.{ "CC=cc", "HOME=/src" },
        .network = false,
        .name = "fetch",
    };
}

fn find_env(env: []const spec_mod.Label, name: []const u8) ?[]const u8 {
    for (env) |label| {
        if (std.mem.eql(u8, label.key, name)) return label.value;
    }
    return null;
}

test "a step's environment: the base's, then the file's, then the fixed one, each key once" {
    // Goal: a later layer replaces an earlier key in place, and the fixed variables always win.
    const spec = test_spec();
    var env: [env_count_max]spec_mod.Label = undefined;
    const count = build_env(&spec, "", &env);
    const labels = env[0..count];
    try testing.expectEqualStrings("/root", find_env(labels, "HOME").?);
    try testing.expectEqualStrings("cc", find_env(labels, "CC").?);
    try testing.expectEqualStrings("fetch", find_env(labels, "ZBX_BUILD_STEP").?);
    for (key_mod.fixed_env) |entry| {
        const at = std.mem.indexOfScalar(u8, entry, '=').?;
        try testing.expectEqualStrings(entry[at + 1 ..], find_env(labels, entry[0..at]).?);
    }
    for (labels, 0..) |label, index| {
        for (labels[index + 1 ..]) |other| {
            try testing.expect(!std.mem.eql(u8, label.key, other.key));
        }
    }
    // HOME stays where the base put it.
    try testing.expectEqualStrings("HOME", labels[1].key);
}

test "a step's mounts: /src, each need at /in/<name>, and /out last as the project's" {
    // Goal: the mount list is what the brief names, in order, and only `/out` is writable.
    const needs = [_]key_mod.Need{
        .{ .name = "deps", .output = Digest.of("deps") },
        .{ .name = "gen", .output = Digest.of("gen") },
    };
    var spec = test_spec();
    spec.needs = &needs;
    const ws = try testing.allocator.create(Workspace);
    defer testing.allocator.destroy(ws);
    var store: Store = undefined;
    @memcpy(store.root[0.."/data/zbx".len], "/data/zbx");
    store.root[9] = 0;
    store.root_len = 9;
    _ = store.path(&ws.paths.work, &.{"/build/work/build-x"});
    _ = store.path(&ws.paths.out, &.{"/build/work/build-x/out"});
    _ = materialize.farm_path(&store, &ws.paths.src, spec.input_tree);
    for (needs, 0..) |need, index| {
        _ = materialize.farm_path(&store, &ws.paths.needs[index], need.output);
        _ = try std.fmt.bufPrint(&ws.targets[index], "/in/{s}", .{need.name});
    }
    const count = build_mounts(&spec, ws);
    const mounts = ws.mounts[0..count];
    try testing.expectEqual(@as(u32, 4), count);
    try testing.expectEqualStrings("/src", mounts[0].target);
    try testing.expectEqualStrings("/in/deps", mounts[1].target);
    try testing.expectEqualStrings("/in/gen", mounts[2].target);
    try testing.expectEqualStrings("/out", mounts[3].target);
    try testing.expectEqualStrings("/data/zbx/build/work/build-x/out", mounts[3].source);
    try testing.expect(std.mem.startsWith(u8, mounts[0].source, "/data/zbx/cache/"));
    for (mounts[0..3]) |mount| try testing.expect(mount.kind == .bind);
    try testing.expect(mounts[3].kind == .mount);
}

test "the stream prefix is the step name, a bar and a space" {
    // Goal: `--verbose` lines read `<step> | <line>`, as the brief says. Method: format the
    // longest name and a short one.
    var out: [run.stream_prefix_bytes_max]u8 = undefined;
    try std.testing.expectEqualStrings("compile | ", stream_prefix(&out, "compile"));
    const longest: [constants.build_step_name_bytes_max]u8 = @splat('n');
    const expected = longest ++ " | ".*;
    try std.testing.expectEqualStrings(&expected, stream_prefix(&out, &longest));
}
