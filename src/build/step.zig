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
//! - **After**, on every path: the run's log is copied as plain text to `build/logs/<step>.log`
//!   (the last line kept for the diagnostic), and the run leaves nothing (`run.discard`). Then,
//!   in the store's namespace again: after a zero exit `/out` is imported (owners 0:0, no
//!   attributes, no root record: the cache entry roots it; a device, FIFO or socket is E0806),
//!   and the work directory is removed. A non-zero end is E0805.

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
const remove = @import("../store/remove.zig");
const open = @import("../store/open.zig");
const store_diagnose = @import("../store/diagnose.zig");
const digest_mod = @import("../store/digest.zig");
const key_mod = @import("key.zig");
const diagnose = @import("diagnose.zig");

const Host = host_mod.Host;
const Digest = digest_mod.Digest;
const Store = layout.Store;
const PathBuf = fs_mod.PathBuf;

pub const Error = error{Failed};

pub const hostname = "build";
pub const umask: u16 = 0o022;
/// A step's container name: this, the step's name, `-`, and random hex.
pub const name_prefix = "build-";
const name_hex_digits = 16;
const env_count_max = constants.env_vars_count_max + constants.build_step_env_max +
    key_mod.fixed_env.len + 1;
const mounts_count = constants.build_step_needs_max + 2;

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
    warn: ?run.Warn = null,
};

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
    try in_store(request, ws, .prepare, diag);
    defer cleanup(request, ws);
    const reason = try start_and_wait(request, ws, diag);
    copy_log(request, &store, ws);
    run.discard(&ws.handle);
    if (step_end(&ws.handle, reason)) |end| {
        const failure: diagnose.StepFailure = .{
            .step = request.spec.name,
            .file = request.file,
            .end = end,
            .network = request.spec.network,
            .last_line = ws.last_line[0..ws.last_line_len],
            .log = ws.paths.log_text(),
        };
        diagnose.step_failed(diag, &failure);
        return error.Failed;
    }
    try in_store(request, ws, .import, diag);
    result.* = .{ .output = ws.import_result.digest, .files = ws.import_result.files };
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
    _ = store.path(&paths.log, &.{ "/build/logs/", spec.name, ".log" });
    _ = materialize.farm_path(store, &paths.src, spec.input_tree);
    for (spec.needs, 0..) |need, index| {
        _ = materialize.farm_path(store, &paths.needs[index], need.output);
        const target = std.fmt.bufPrint(&ws.targets[index], "/in/{s}", .{need.name}) catch
            unreachable; // A need is a step's name, at most 32 bytes.
        assert(target.len > 4);
    }
}

// ---- The container ------------------------------------------------------------------------------

fn start_and_wait(request: *const Request, ws: *Workspace, diag: *Diag) Error!run.ExitReason {
    const spec = request.spec;
    const paths = &ws.paths;
    assert(spec.argv.len > 0);
    const env_count = build_env(spec, &ws.env);
    const mount_count = build_mounts(spec, ws);
    const container: spec_mod.Spec = .{
        .image = &paths.image,
        .name = paths.name_slice(),
        .command = spec.argv,
        .env = ws.env[0..env_count],
        .workdir = "/src",
        .network = if (spec.network) .user else .none,
        .mounts = ws.mounts[0..mount_count],
        .project = paths.work_text(),
        .hostname = hostname,
        .umask = umask,
        .limits = .{
            .memory_bytes = constants.build_step_memory_bytes,
            .pids = constants.build_step_pids,
        },
    };
    const options: run.StartOptions = .{
        .warn = request.warn,
        .timeout_ms = constants.build_step_timeout_ms,
        .image_workspace = &ws.image,
        .keep_log = true,
        .mirror = false,
    };
    run.start(request.host, &container, options, &ws.handle, diag) catch return error.Failed;
    const reason = run.wait(&ws.handle);
    assert(ws.handle.status == .stopped);
    return reason;
}

/// The base's environment, then the file's, then the fixed one: a later key replaces an
/// earlier one in place, so each key is there once.
fn build_env(spec: *const key_mod.Spec, out: *[env_count_max]spec_mod.Label) u32 {
    assert(spec.base_env.len <= constants.env_vars_count_max);
    assert(spec.env.len <= constants.build_step_env_max);
    var count: u32 = 0;
    for (spec.base_env) |entry| add_env(out, &count, entry);
    for (spec.env) |entry| add_env(out, &count, entry);
    for (key_mod.fixed_env) |entry| add_env(out, &count, entry);
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
    ws.mounts[count] = bind(.bind, paths.src.text(), "/src");
    count += 1;
    for (spec.needs, 0..) |need, index| {
        const target = ws.targets[index][0 .. 4 + need.name.len];
        ws.mounts[count] = bind(.bind, paths.needs[index].text(), target);
        count += 1;
    }
    ws.mounts[count] = bind(.mount, paths.out_text(), "/out");
    count += 1;
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

/// Copies the run's log, both streams in order, to `build/logs/<step>.log` as plain text, and
/// keeps its last line. Best effort: a step whose log cannot be kept still has its output.
fn copy_log(request: *const Request, store: *const Store, ws: *Workspace) void {
    assert(ws.handle.status == .stopped);
    ws.last_line_len = 0;
    const fs = store.fs;
    var dir: PathBuf = undefined;
    fs.make_directory(store.path(&dir, &.{"/build"}), true) catch return;
    fs.make_directory(store.path(&dir, &.{"/build/logs"}), true) catch return;
    var temporary: PathBuf = undefined;
    temporary.set(&.{ ws.paths.log_text(), ".", ws.paths.name_slice() }) catch return;
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

const Action = enum { prepare, import, remove };

/// What the child gets. It has its own copy of memory, so what it learns comes back through
/// `report`: a diagnostic on failure, the import's digest and file count on success.
const Job = struct {
    request: *const Request,
    ws: *Workspace,
    action: Action,
    report: host_mod.Pipe,
};

/// The import's answer on the pipe: the digest, then the file count, little-endian.
const answer_bytes = constants.store_digest_bytes + 8;

comptime {
    assert(answer_bytes < constants.diag_carry_bytes_max);
    assert(@typeInfo(Action).@"enum".field_names.len == 3);
}

fn in_store(request: *const Request, ws: *Workspace, action: Action, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(ws.paths.work.len > 0);
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
    if (action != .import) return;
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
    _ = squash_owner; // The output is imported with owners 0:0 either way.
    const job: *Job = @ptrCast(@alignCast(context));
    assert(job.ws.paths.work.len > 0);
    var diag: Diag = undefined;
    diag.reset();
    var answer: [answer_bytes]u8 = undefined;
    var answer_len: usize = 0;
    var store: Store = undefined;
    if (!store.locate(job.request.host)) {
        store_diagnose.no_data_directory(&diag);
    } else if (execute(&store, job, &diag)) {
        if (job.action == .import) {
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
    assert(job.ws.paths.out.len > job.ws.paths.work.len);
    switch (job.action) {
        .prepare => try prepare(store, job, diag),
        .import => try import_output(store, job, diag),
        .remove => {
            const ws = &job.ws.image.materialize;
            var failure: remove.Failure = undefined;
            const work = job.ws.paths.work_text();
            remove.tree(store.fs, &ws.removal, &ws.arena, work, &failure) catch {
                store_diagnose.write_failed(
                    diag,
                    store,
                    "removing a build step's work directory",
                    failure.err,
                    failure.errno,
                );
                return error.Failed;
            };
        },
    }
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
}

fn made_nothing(store: *const Store, diag: *Diag, err: fs_mod.Error) Error {
    assert(diag.code == null);
    assert(@errorName(err).len > 0);
    const operation = "making a build step's work directory";
    store_diagnose.write_failed(diag, store, operation, err, store.fs.last_errno());
    return error.Failed;
}

fn import_output(store: *Store, job: *Job, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(job.action == .import);
    var refusal: Refusal = .{ .step = job.request.spec.name };
    const options: import_mod.Options = .{
        .squash_owner = true,
        .warn = null,
        .drop_xattrs = true,
        .refuse_special = .{ .context = &refusal, .call = Refusal.call },
        .save_root = false,
    };
    const ws = job.ws;
    const out = ws.paths.out_text();
    import_mod.import(store, &ws.import, out, options, &ws.import_result, diag) catch
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
    const count = build_env(&spec, &env);
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
