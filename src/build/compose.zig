//! `zbx build`, the thin composition of slice 2: for each step of the build file in graph order,
//! the lock gives the base image, the image record its tree, platform and environment, the
//! inputs are imported (`input_tree.zig`), the key is computed (`key.zig`), and the cache
//! (`cache.zig`) either has the output (a hit starts no container) or `step.run_step` makes it
//! and the cache records it. One line per step says which: `<step>  hit|built  <output digest>`.
//!
//! Steps run through `schedule.zig`: hits are found here, a miss runs in a worker process, a
//! failure starts nothing new. A base that the lock names but the store lacks is refused with the
//! pull that fixes it (the pull by locked digest is still to do), and there is no image output
//! yet.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const doctor = @import("../doctor.zig");
const errors = @import("../diag/errors.zig");
const lock_file = @import("../lock_file.zig");
const image_diagnose = @import("../image_diagnose.zig");
const Diag = @import("../diag/diag.zig").Diag;
const layout = @import("../store/layout.zig");
const images = @import("../store/images.zig");
const lock = @import("../store/lock.zig");
const store_diagnose = @import("../store/diagnose.zig");
const digest_mod = @import("../store/digest.zig");
const load_mod = @import("load.zig");
const file_mod = @import("file.zig");
const key_mod = @import("key.zig");
const cache = @import("cache.zig");
const step_mod = @import("step.zig");
const input_tree = @import("input_tree.zig");
const inputs_mod = @import("inputs.zig");
const diagnose = @import("diagnose.zig");
const schedule = @import("schedule.zig");
const pull_lib = @import("../pull.zig");
const import_mod = @import("../store/import.zig");

const Host = host_mod.Host;
const Digest = digest_mod.Digest;
const Store = layout.Store;

pub const Error = error{ Failed, OutputFailed };

/// The caller's memory for a build: large, so static or heap storage.
pub const Workspace = struct {
    locking: lock_file.Workspace,
    image: images.Image,
    input: input_tree.Workspace,
    input_problem: inputs_mod.Problem,
    step: step_mod.Workspace,
    cache: cache.Workspace,
    result: step_mod.Result,
    outputs: [constants.build_steps_max]Digest,
    base_env: [constants.env_vars_count_max][]const u8,
    env: [constants.build_step_env_max][]const u8,
    argv: [constants.build_step_argv_max][]const u8,
    needs: [constants.build_step_needs_max]key_mod.Need,
    key: key_mod.Key,
    row: [row_bytes]u8,
    slots: [constants.build_parallel_max]Slot,
    plan: schedule.Plan,
    side_diag: Diag,
};

const row_bytes = constants.build_step_name_bytes_max + 400;

/// Builds every step of the loaded build file with the scheduler (`schedule.zig`): hits are
/// found here, in this process; a miss runs in a worker process (`worker_entry`) that this process
/// waits for with pidfds. A row is written as each step ends.
pub fn run_steps(
    host: Host,
    facts: *doctor.Facts,
    loaded: *const load_mod.Workspace,
    ws: *Workspace,
    pull_ws: *pull_lib.Workspace,
    import_ws: *import_mod.Workspace,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    assert(loaded.graph.count == loaded.file.steps_count);
    var failure: lock_file.Failure = undefined;
    lock_file.open_project(host, host.filesystem(), &ws.locking, &failure) catch {
        image_diagnose.lock_failure(diag, lock_file.file_name, failure);
        return error.Failed;
    };
    var store: Store = undefined;
    if (!store.locate(host)) {
        store_diagnose.no_data_directory(diag);
        return error.Failed;
    }
    var group_storage: [step_mod.log_group_bytes]u8 = undefined;
    const group = step_mod.log_group(&group_storage, loaded.path.text());
    var context: Context = .{
        .host = host,
        .facts = facts,
        .loaded = loaded,
        .ws = ws,
        .diag = diag,
        .store = &store,
        .group = group,
        .pull = pull_ws,
        .import = import_ws,
        .row_failed = null,
    };
    for (&ws.slots) |*slot| slot.active = false;
    try context.sweep();
    make_plan(loaded, &ws.plan);
    const executor: schedule.Executor = .{
        .context = &context,
        .begin = Context.begin_step,
        .wait = Context.wait_step,
        .abort = Context.abort_step,
    };
    const outcome = schedule.run(&ws.plan, parallel_bound(host), executor);
    if (outcome.failed != null or outcome.aborted) {
        if (diag.code == null) {
            diag.raise(.B0001);
            diag.cause("a build step failed with no diagnostic", .{});
        }
        return error.Failed;
    }
    if (context.row_failed) |err| return err;
}

/// How many steps may run at once: the constant (a cut: the CPUs online are not counted).
fn parallel_bound(host: Host) u8 {
    _ = host;
    return constants.build_parallel_max;
}

fn make_plan(loaded: *const load_mod.Workspace, plan: *schedule.Plan) void {
    const graph = &loaded.graph;
    plan.count = graph.count;
    for (graph.order_slice(), 0..) |index, at| plan.order[at] = index;
    for (0..graph.count) |index| {
        const needs = graph.needs_slice(&loaded.file, @intCast(index));
        for (needs, 0..) |need, at| plan.needs[index][at] = need;
        plan.needs_count[index] = @intCast(needs.len);
    }
    assert(plan.valid());
}

/// A miss that is running in a worker process.
pub const Slot = struct {
    active: bool,
    index: u8,
    pid: host_mod.Pid,
    report: host_mod.Pipe,
    key: key_mod.Key,
};

/// What the worker needs: it runs on a copy of this process's memory.
const Job = struct {
    request: *const step_mod.Request,
    ws: *step_mod.Workspace,
    write: host_mod.Handle,
    host: Host,
};

/// The worker: runs the step as a container and answers on the pipe, the output's digest and its
/// file count, or the encoded diagnostic. The exit code is 0 only with an answer.
fn worker_entry(raw: *anyopaque) u8 {
    const job: *Job = @ptrCast(@alignCast(raw));
    // A killed build takes its workers with it, as it took its one step before.
    job.host.die_with_parent() catch return 1;
    var diag: Diag = undefined;
    diag.reset();
    var result: step_mod.Result = undefined;
    step_mod.run_step(job.request, job.ws, &result, &diag) catch {
        var bytes: [constants.diag_carry_bytes_max]u8 = undefined;
        const encoded = diag.encode(&bytes);
        job.host.write_handle_all(job.write, encoded) catch {};
        return diag.exit_code();
    };
    var answer: [answer_bytes]u8 = undefined;
    @memcpy(answer[0..constants.store_digest_bytes], &result.output.bytes);
    std.mem.writeInt(u64, answer[constants.store_digest_bytes..][0..8], result.files, .little);
    job.host.write_handle_all(job.write, &answer) catch return 1;
    return 0;
}

/// The answer on the pipe: the output's digest, then its file count.
pub const answer_bytes = constants.store_digest_bytes + 8;

pub const Answer = union(enum) { output: Digest, failed };

/// What a worker's end and the bytes it wrote mean. Only a clean exit with exactly an answer is
/// an output; otherwise the bytes are the worker's diagnostic if they decode as one, else the
/// worker is blamed (a signal, or an exit with no answer). `diag` is set on `.failed`.
pub fn decode_answer(status: host_mod.ExitStatus, bytes: []const u8, diag: *Diag) Answer {
    const clean = status == .exited and status.exited == 0;
    if (clean and bytes.len == answer_bytes) {
        var output: Digest = undefined;
        @memcpy(&output.bytes, bytes[0..constants.store_digest_bytes]);
        return .{ .output = output };
    }
    if (bytes.len > 0 and diag.decode(bytes)) return .failed;
    diag.reset();
    const fault: store_diagnose.WorkerFault = switch (status) {
        .signaled => |number| .{ .signaled = number },
        .exited => .{ .report = "a build step's worker ended with no answer" },
    };
    store_diagnose.worker_ended(diag, fault);
    assert(diag.code != null);
    return .failed;
}

pub const Context = struct {
    host: Host,
    facts: *doctor.Facts,
    loaded: *const load_mod.Workspace,
    ws: *Workspace,
    diag: *Diag,
    store: *Store,
    group: []const u8,
    pull: *pull_lib.Workspace,
    import: *import_mod.Workspace,
    row_failed: ?Error,

    fn request(context: *const Context, spec: *const key_mod.Spec) step_mod.Request {
        return .{
            .host = context.host,
            .facts = context.facts,
            .spec = spec,
            .file = context.loaded.shown(),
            .group = context.group,
        };
    }

    fn begin_step(raw: *anyopaque, index: u8) schedule.Error!schedule.Begin {
        const context: *Context = @ptrCast(@alignCast(raw));
        return context.begin(index) catch error.Failed;
    }

    fn wait_step(raw: *anyopaque) schedule.Error!schedule.Ended {
        const context: *Context = @ptrCast(@alignCast(raw));
        return context.wait() catch error.Failed;
    }

    /// Clears what a killed build left in `build/work`, before this one starts steps.
    fn sweep(context: *Context) Error!void {
        const spec: key_mod.Spec = .{
            .platform = "linux/amd64",
            .base_tree = Digest.of("sweep"),
            .base_env = &.{},
            .input_tree = Digest.of("sweep"),
            .needs = &.{},
            .argv = &.{},
            .env = &.{},
            .network = false,
            .name = "sweep",
        };
        const sweep_request = context.request(&spec);
        step_mod.sweep(&sweep_request, &context.ws.step, context.diag) catch return error.Failed;
    }

    /// Resolves the step's key; a cached output is a hit, anything else starts a worker.
    fn begin(context: *Context, index: u8) Error!schedule.Begin {
        const loaded = context.loaded;
        const ws = context.ws;
        const file = &loaded.file;
        assert(index < file.steps_count);
        const step = &file.steps[index];
        const name = file.text(step.name);
        var spec: key_mod.Spec = undefined;
        spec.name = name;
        spec.network = step.network;
        try context.resolve_base(file.text(step.base), &spec);
        spec.input_tree = try context.import_inputs(index);
        fill_lists(file, step, ws, &spec);
        spec.needs = fill_needs(loaded, index, ws);
        key_mod.compute(&spec, &ws.key) catch {
            diagnose.step_env_refused(context.diag, name, loaded.shown(), step.env.count, "");
            return error.Failed;
        };
        var failure: cache.Failure = undefined;
        const found = cache.lookup(context.store, &ws.cache, &ws.key, &failure) catch {
            return context.cache_failed(&failure);
        };
        switch (found) {
            .hit => |output| {
                ws.outputs[index] = output;
                try context.row(index, "hit", output);
                return .hit;
            },
            .miss => {},
        }
        try context.fork_worker(index, &spec);
        return .running;
    }

    fn fork_worker(
        context: *Context,
        index: u8,
        spec: *const key_mod.Spec,
    ) Error!void {
        const ws = context.ws;
        const slot = for (&ws.slots) |*candidate| {
            if (!candidate.active) break candidate;
        } else unreachable; // The bound never exceeds the slots.
        const host = context.host;
        const report = host.pipe() catch |err| {
            store_diagnose.worker_ended(context.diag, .{ .step = .{
                .name = "pipe",
                .err = err,
                .errno = host.last_errno(),
            } });
            return error.Failed;
        };
        const run_request = context.request(spec);
        var job: Job = .{
            .request = &run_request,
            .ws = &ws.step,
            .write = report.write,
            .host = host,
        };
        const pid = host.fork_child(false, worker_entry, &job) catch |err| {
            host.close(report.read);
            host.close(report.write);
            store_diagnose.worker_ended(context.diag, .{ .step = .{
                .name = "starting a build step's worker",
                .err = err,
                .errno = host.last_errno(),
            } });
            return error.Failed;
        };
        host.close(report.write);
        slot.* = .{
            .active = true,
            .index = index,
            .pid = pid,
            .report = report,
            .key = ws.key,
        };
    }

    /// Waits for the first worker to end and settles its step.
    pub fn wait(context: *Context) Error!schedule.Ended {
        const ws = context.ws;
        const host = context.host;
        var pids: [constants.build_parallel_max]host_mod.Pid = undefined;
        var which: [constants.build_parallel_max]u8 = undefined;
        var count: u8 = 0;
        for (&ws.slots, 0..) |*slot, at| {
            if (!slot.active) continue;
            pids[count] = slot.pid;
            which[count] = @intCast(at);
            count += 1;
        }
        assert(count > 0);
        const reaped = host.wait_any(pids[0..count], 0) catch |err| {
            store_diagnose.worker_ended(context.diag, .{ .step = .{
                .name = "waiting for a build step",
                .err = err,
                .errno = host.last_errno(),
            } });
            return error.Failed;
        } orelse unreachable; // A wait with no time does not time out.
        return context.settle(&ws.slots[which[reaped.index]], reaped.status);
    }

    /// Ends every worker still running: SIGKILL, reap, close its pipe. Best effort: a worker
    /// that is already gone is not an error here.
    pub fn abort_step(raw: *anyopaque) void {
        const context: *Context = @ptrCast(@alignCast(raw));
        const host = context.host;
        var ended: u8 = 0;
        for (&context.ws.slots) |*slot| {
            if (!slot.active) continue;
            host.signal(slot.pid, constants.signal_kill) catch {};
            _ = host.wait_for(slot.pid) catch {};
            host.close(slot.report.read);
            slot.active = false;
            ended += 1;
        }
        assert(ended > 0);
    }

    /// Reads the answer of the worker that ended with `status`, and settles its step: the output
    /// is recorded and its row written, or the step failed with a diagnostic.
    pub fn settle(context: *Context, slot: *Slot, status: host_mod.ExitStatus) schedule.Ended {
        const ws = context.ws;
        const host = context.host;
        assert(slot.active);
        slot.active = false;
        defer host.close(slot.report.read);
        var bytes: [constants.diag_carry_bytes_max]u8 = undefined;
        var length: usize = 0;
        while (length < bytes.len) {
            const got = host.read_some(slot.report.read, bytes[length..]) catch break;
            if (got == 0) break;
            length += got;
        }
        // A second failure is told to nobody: the first diagnostic is the build's.
        const outer = context.diag;
        if (outer.code != null) {
            ws.side_diag.reset();
            context.diag = &ws.side_diag;
        }
        defer context.diag = outer;
        const output = switch (decode_answer(status, bytes[0..length], context.diag)) {
            .failed => return .{ .index = slot.index, .ok = false },
            .output => |digest| digest,
        };
        ws.key = slot.key;
        const kept = context.record(output) catch return .{ .index = slot.index, .ok = false };
        ws.outputs[slot.index] = kept;
        context.row(slot.index, "built", kept) catch |err| {
            context.row_failed = err;
            return .{ .index = slot.index, .ok = false };
        };
        return .{ .index = slot.index, .ok = true };
    }

    /// The base's image, from the lock: its platform, tree and environment.
    fn resolve_base(context: *Context, reference: []const u8, spec: *key_mod.Spec) Error!void {
        const ws = context.ws;
        const name = spec.name;
        const at = ws.locking.lock.find(reference) orelse {
            diagnose.base_not_locked(context.diag, name, reference, false);
            return error.Failed;
        };
        const entry = &ws.locking.lock.entries[at];
        var errno: u16 = 0;
        images.load(context.store, entry.manifest, &ws.image, &errno) catch |err| {
            if (err == error.NotFound) {
                diagnose.base_not_locked(context.diag, name, reference, true);
            } else {
                const operation = "reading the base image's record";
                const failed = error.IoFailed;
                store_diagnose.write_failed(context.diag, context.store, operation, failed, errno);
            }
            return error.Failed;
        };
        spec.platform = entry.platform_text();
        spec.base_tree = ws.image.tree;
        const count = ws.image.settings.count(.env);
        assert(count <= ws.base_env.len);
        for (0..count) |word| ws.base_env[word] = ws.image.settings.word(.env, @intCast(word));
        spec.base_env = ws.base_env[0..count];
    }

    fn import_inputs(context: *Context, index: u8) Error!Digest {
        const loaded = context.loaded;
        const fs = context.host.filesystem();
        const project = fs.open_directory(loaded.project.text()) catch |err| {
            const operation = "opening the project directory";
            const errno = fs.last_errno();
            store_diagnose.write_failed(context.diag, context.store, operation, err, errno);
            return error.Failed;
        };
        defer fs.close(project);
        const import: input_tree.Request = .{
            .store = context.store,
            .project = project,
            .file = &loaded.file,
            .step = index,
        };
        const ws = context.ws;
        return input_tree.import(import, &ws.input, &ws.input_problem, context.diag) catch |err| {
            if (err == error.Refused) {
                diagnose.input_problem(
                    context.diag,
                    loaded.project.text(),
                    &loaded.file,
                    &ws.input_problem,
                );
            }
            return error.Failed;
        };
    }

    /// Writes the entry under the shared lock, and returns the tree it names.
    fn record(context: *Context, output: Digest) Error!Digest {
        const store = context.store;
        try store_diagnose.hold(context.diag, store, .shared, "build", "recording a build step");
        defer lock.release(store);
        var failure: cache.Failure = undefined;
        return cache.record(store, &context.ws.cache, &context.ws.key, output, &failure) catch {
            return context.cache_failed(&failure);
        };
    }

    fn cache_failed(context: *Context, failure: *const cache.Failure) Error {
        const operation = "reading the build cache";
        switch (failure.*) {
            .io => |io| {
                store_diagnose.write_failed(context.diag, context.store, io.step, io.err, io.errno);
            },
            .tree => store_diagnose.write_failed(
                context.diag,
                context.store,
                operation,
                error.IoFailed,
                0,
            ),
        }
        return error.Failed;
    }

    fn row(
        context: *Context,
        index: u8,
        what: []const u8,
        output: Digest,
    ) Error!void {
        const name = context.loaded.file.text(context.loaded.file.steps[index].name);
        const text = output.text();
        const format = "{s}  {s}  {s}\n";
        const line = std.fmt.bufPrint(&context.ws.row, format, .{ name, what, &text }) catch
            unreachable; // `row_bytes` holds a name, a word and a digest.
        context.host.write_all(.stdout, line) catch |err| {
            errors.output_failed(context.diag, .stdout, err, context.host.last_errno());
            return error.OutputFailed;
        };
    }
};

fn fill_lists(
    file: *const file_mod.BuildFile,
    step: *const file_mod.Step,
    ws: *Workspace,
    spec: *key_mod.Spec,
) void {
    for (step.run.slice(), 0..) |word, at| ws.argv[at] = file.text(word);
    for (step.env.slice(), 0..) |word, at| ws.env[at] = file.text(word);
    spec.argv = ws.argv[0..step.run.count];
    spec.env = ws.env[0..step.env.count];
}

fn fill_needs(loaded: *const load_mod.Workspace, index: u8, ws: *Workspace) []const key_mod.Need {
    const file = &loaded.file;
    const wanted = loaded.graph.needs_slice(file, index);
    for (wanted, 0..) |need, at| {
        ws.needs[at] = .{ .name = file.text(file.steps[need].name), .output = ws.outputs[need] };
    }
    return ws.needs[0..wanted.len];
}

comptime {
    assert(row_bytes > constants.store_digest_text_bytes);
}
