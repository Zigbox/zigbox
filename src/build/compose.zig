//! `zbx build`, the thin composition of slice 2: for each step of the build file in graph order,
//! the lock gives the base image, the image record its tree, platform and environment, the
//! inputs are imported (`input_tree.zig`), the key is computed (`key.zig`), and the cache
//! (`cache.zig`) either has the output (a hit starts no container) or `step.run_step` makes it
//! and the cache records it.
//!
//! Steps run through `schedule.zig`: hits are found here, a miss runs in a worker process, a
//! failure starts nothing new. A base that the lock names but the store lacks is pulled by the
//! locked manifest digest (`pull.zig`, the library call). When every step is done the image
//! step runs here, in this process: the base, the adds and the config become the image tree
//! (`assemble.zig`, cached under the image key) and the build record (`result.zig`), whose digest
//! is the build's result.
//!
//! The report is a header, one row per step as it ends (`  compile   miss   9.81 s`) and a
//! footer with the result digest; with `json` it is one `zbx.build/1` line per step as it ends
//! and a last `build_result` line (`zbx schema build`).

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
const provenance_job = @import("provenance_job.zig");
const file_mod = @import("file.zig");
const key_mod = @import("key.zig");
const cache = @import("cache.zig");
const step_mod = @import("step.zig");
const input_tree = @import("input_tree.zig");
const input_job = @import("input_job.zig");
const inputs_mod = @import("inputs.zig");
const diagnose = @import("diagnose.zig");
const render = @import("../diag/render.zig");
const schedule = @import("schedule.zig");
const assemble = @import("assemble.zig");
const result_mod = @import("result.zig");
const roots = @import("../store/roots.zig");
const pull_lib = @import("../pull.zig");
const reference_mod = @import("../registry/reference.zig");
const manifest = @import("../registry/manifest.zig");
const digest_sha = @import("../registry/digest.zig");
const trust_gate = @import("../trust/gate.zig");
const trust_record = @import("../trust/record.zig");

const Host = host_mod.Host;
const Digest = digest_mod.Digest;
const Store = layout.Store;

pub const Error = error{ Failed, OutputFailed };

/// The caller's memory for a build: large, so static or heap storage.
pub const Workspace = struct {
    /// The policy gate before a step starts: the files, and the base's signatures.
    gate: trust_gate.Memory,
    signatures: trust_record.Record,
    record_work: trust_record.Work,
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
    /// When each step began and ended (milliseconds into the build), by step index; the image
    /// is `image_slot`.
    timings: [constants.build_steps_max + 1]Timing,
    /// The library pull of a base the lock names and the store lacks.
    pull: pull_lib.Workspace,
    /// The image step: the assembly's memory and failure, the record and its bytes.
    assembly: assemble.Workspace,
    assembly_failure: assemble.Failure,
    record: result_mod.Record,
    empty_settings: images.Settings,
    record_bytes: [constants.build_result_bytes_max]u8,
    adds: [constants.build_image_adds_max]assemble.Add,
    image_adds: [constants.build_image_adds_max]key_mod.ImageAdd,
    /// By step index: the input tree each step was keyed with, and its key, for the provenance.
    step_inputs: [constants.build_steps_max]Digest,
    step_keys: [constants.build_steps_max]Digest,
    provenance: provenance_job.Workspace,
};

/// The timings slot of the image step.
const image_slot = constants.build_steps_max;

pub const Timing = struct {
    start_ms: u64,
    end_ms: u64,
    key: Digest,
    output: Digest,
    hit: bool,
    network: bool,
};

/// What the caller asks of the build besides the file.
pub const Options = struct {
    /// `--output json`: one `zbx.build/1` record per line on stdout.
    json: bool,
    /// `--verbose`: stream each step's output to stderr, a `<step> | ` before each line, and
    /// render a warning with its whole cause chain.
    verbose: bool,
};

/// The most a report line holds: a JSON step record (two digests, a name, numbers) is the
/// longest, with room to spare.
const row_bytes = 640;
const name_gap = "   ";

/// Builds every step of the loaded build file with the scheduler (`schedule.zig`): hits are
/// found here, in this process; a miss runs in a worker process (`worker_entry`) that this process
/// waits for with pidfds. A row is written as each step ends.
pub fn run_steps(
    host: Host,
    facts: *doctor.Facts,
    loaded: *const load_mod.Workspace,
    ws: *Workspace,
    options: Options,
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
        .row_failed = null,
        .json = options.json,
        .verbose = options.verbose,
        .started_ms = host.monotonic_ms(),
        .started_s = host.time_now(),
        .name_width = name_width(&loaded.file),
        .hits = 0,
        .misses = 0,
        .gate_loaded = false,
        .records_max = constants.trust_records_max,
    };
    for (&ws.slots) |*slot| slot.active = false;
    try context.sweep();
    try context.header();
    context.warn_network();
    make_plan(loaded, &ws.plan);
    const executor: schedule.Executor = .{
        .context = &context,
        .begin = Context.begin_step,
        .wait = Context.wait_step,
        .abort = Context.abort_step,
    };
    const outcome = schedule.run(&ws.plan, parallel_bound(host), executor);
    try context.finish(outcome);
    try context.build_image();
}

/// The width of the name column: the longest step name, or `image`.
fn name_width(file: *const file_mod.BuildFile) u8 {
    var width: usize = "image".len;
    for (file.steps_slice()) |step| width = @max(width, file.text(step.name).len);
    assert(width <= constants.build_step_name_bytes_max);
    return @intCast(width);
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

/// The worker: runs the step as a container and answers on the pipe, the output's digest or the
/// encoded diagnostic, each behind a tag byte. The exit code is 0 only with an answer.
fn worker_entry(raw: *anyopaque) u8 {
    const job: *Job = @ptrCast(@alignCast(raw));
    // A killed build takes its workers with it, as it took its one step before.
    job.host.die_with_parent() catch return 1;
    var diag: Diag = undefined;
    diag.reset();
    var result: step_mod.Result = undefined;
    step_mod.run_step(job.request, job.ws, &result, &diag) catch {
        var bytes: [failure_bytes_max]u8 = undefined;
        bytes[0] = tag_failure;
        const encoded = diag.encode(bytes[1..][0..constants.diag_carry_bytes_max]);
        job.host.write_handle_all(job.write, bytes[0 .. 1 + encoded.len]) catch {};
        return diag.exit_code();
    };
    var answer: [answer_bytes]u8 = undefined;
    answer[0] = tag_output;
    @memcpy(answer[1..], &result.output.bytes);
    job.host.write_handle_all(job.write, &answer) catch return 1;
    return 0;
}

/// The first byte of what a worker writes: an output's digest follows, or an encoded diagnostic.
/// A tag, not a length, tells them apart, so no diagnostic can pass for an output or the reverse.
pub const tag_output: u8 = 1;
pub const tag_failure: u8 = 2;

/// The answer on the pipe: the tag, then the output's digest.
pub const answer_bytes = 1 + constants.store_digest_bytes;

/// The most a worker writes: the tag and a diagnostic.
pub const failure_bytes_max = 1 + constants.diag_carry_bytes_max;

pub const Answer = union(enum) { output: Digest, failed };

/// What a worker's end and the bytes it wrote mean. Only a clean exit with exactly a tagged
/// answer is an output; a tagged diagnostic that decodes is the worker's; anything else blames
/// the worker (a signal, or an exit with no answer). `diag` is set on `.failed`.
pub fn decode_answer(status: host_mod.ExitStatus, bytes: []const u8, diag: *Diag) Answer {
    const clean = status == .exited and status.exited == 0;
    if (clean and bytes.len == answer_bytes and bytes[0] == tag_output) {
        var output: Digest = undefined;
        @memcpy(&output.bytes, bytes[1..]);
        return .{ .output = output };
    }
    if (bytes.len > 1 and bytes[0] == tag_failure and diag.decode(bytes[1..])) return .failed;
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
    row_failed: ?Error,
    json: bool,
    verbose: bool,
    started_ms: u64,
    /// The wall clock at the start, in the seconds a root record keeps (`unroot`).
    started_s: u64,
    name_width: u8,
    hits: u32,
    misses: u32,
    /// The policy files have been read (once per build).
    gate_loaded: bool,
    /// `trust_records_max`; a test lowers it.
    records_max: u32,

    pub fn request(context: *const Context, spec: *const key_mod.Spec) step_mod.Request {
        return .{
            .host = context.host,
            .facts = context.facts,
            .spec = spec,
            .file = context.loaded.shown(),
            .group = context.group,
            .stream = context.verbose,
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

    /// The build's answer once the scheduler is done. A row that could not be written fails its
    /// step; only the returned error value is then the output's (`OutputFailed`), not the
    /// step's. What the user reads is `diag`, which keeps the first failure (a later row failure
    /// goes to `side_diag`). A failed `hit` row never sets `row_failed`: `begin_step` turns its
    /// error into `Failed`, so the ordering covers `built` rows only.
    pub fn finish(context: *Context, outcome: schedule.Outcome) Error!void {
        if (context.row_failed) |err| return err;
        if (outcome.failed == null and !outcome.aborted) return;
        if (context.diag.code == null) {
            context.diag.raise(.B0001);
            context.diag.cause("a build step failed with no diagnostic", .{});
        }
        return error.Failed;
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
        ws.step_inputs[index] = spec.input_tree;
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
                try context.report(index, true, output);
                return .hit;
            },
            .miss => {},
        }
        try context.check_base(file.text(step.base), &spec);
        try context.fork_worker(index, &spec);
        return .running;
    }

    /// The policy gate on a step that is about to run (a hit runs nothing and is not checked):
    /// the base is judged like a run's tree, bound to the manifest the lock names.
    pub fn check_base(
        context: *Context,
        reference: []const u8,
        spec: *const key_mod.Spec,
    ) Error!void {
        assert(spec.name.len > 0);
        const ws = context.ws;
        const diag = context.diag;
        if (!context.gate_loaded) {
            trust_gate.load(context.host, &ws.gate, diag) catch return error.Failed;
            context.gate_loaded = true;
        }
        if (!trust_gate.any_checks(&ws.gate)) return;
        const entry = ws.locking.lock.entries[ws.locking.lock.find(reference).?];
        var text: [constants.oci_digest_text_bytes + 129]u8 = undefined;
        const shown = base_text(&text, reference, entry.manifest);
        // A base derives nothing (M8 slice 14 cut): its labels are not in the base's record, so
        // only a tree-only or manifest-bound statement can count for it.
        const subject: trust_gate.Subject = .{
            .tree = spec.base_tree,
            .binding = .{ .manifest = entry.manifest.bytes },
            .text = shown,
            .step = spec.name,
        };
        const host = context.host;
        trust_gate.judge_all(host, &ws.gate, &ws.signatures, &ws.record_work, subject, diag) catch
            return error.Failed;
    }

    pub fn fork_worker(
        context: *Context,
        index: u8,
        spec: *const key_mod.Spec,
    ) Error!void {
        const ws = context.ws;
        const slot = for (&ws.slots) |*candidate| {
            if (!candidate.active) break candidate;
        } else unreachable; // The bound never exceeds the slots.
        const host = context.host;
        const pipe = host.pipe() catch |err| {
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
            .write = pipe.write,
            .host = host,
        };
        const pid = host.fork_child(false, worker_entry, &job) catch |err| {
            host.close(pipe.read);
            host.close(pipe.write);
            store_diagnose.worker_ended(context.diag, .{ .step = .{
                .name = "starting a build step's worker",
                .err = err,
                .errno = host.last_errno(),
            } });
            return error.Failed;
        };
        host.close(pipe.write);
        ws.timings[index].start_ms = context.elapsed();
        slot.* = .{
            .active = true,
            .index = index,
            .pid = pid,
            .report = pipe,
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
        var bytes: [failure_bytes_max]u8 = undefined;
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
        context.report(slot.index, false, kept) catch |err| {
            context.row_failed = err;
            return .{ .index = slot.index, .ok = false };
        };
        return .{ .index = slot.index, .ok = true };
    }

    /// The base's image, from the lock: its platform, tree and environment.
    fn resolve_base(context: *Context, reference: []const u8, spec: *key_mod.Spec) Error!void {
        const ws = context.ws;
        const entry = try context.load_base(reference, spec.name);
        spec.platform = entry.platform_text();
        spec.base_tree = ws.image.tree;
        const count = ws.image.settings.count(.env);
        assert(count <= ws.base_env.len);
        for (0..count) |word| ws.base_env[word] = ws.image.settings.word(.env, @intCast(word));
        spec.base_env = ws.base_env[0..count];
    }

    /// Reads the locked base's image record into `ws.image`. An image the lock names and the
    /// store lacks is pulled by the locked manifest digest; one the lock does not name is
    /// refused (E0804), because a build never resolves a tag itself.
    pub fn load_base(
        context: *Context,
        reference: []const u8,
        name: ?[]const u8,
    ) Error!*const lock_file.Entry {
        const ws = context.ws;
        const at = ws.locking.lock.find(reference) orelse {
            diagnose.base_not_locked(context.diag, name, reference, false);
            return error.Failed;
        };
        const entry = &ws.locking.lock.entries[at];
        var errno: u16 = 0;
        images.load(context.store, entry.manifest, &ws.image, &errno) catch |first| {
            if (first != error.NotFound) return context.image_unreadable(errno);
            try context.pull_locked(reference, name, entry);
            images.load(context.store, entry.manifest, &ws.image, &errno) catch |err| {
                if (err != error.NotFound) return context.image_unreadable(errno);
                diagnose.base_not_locked(context.diag, name, reference, true);
                return error.Failed;
            };
        };
        return entry;
    }

    /// A lock entry that cannot be pulled by digest (its reference does not parse again).
    fn stale_lock(context: *Context, name: ?[]const u8, reference: []const u8) Error {
        diagnose.base_not_locked(context.diag, name, reference, true);
        return error.Failed;
    }

    fn image_unreadable(context: *Context, errno: u16) Error {
        const operation = "reading the base image's record";
        const failed = error.IoFailed;
        store_diagnose.write_failed(context.diag, context.store, operation, failed, errno);
        return error.Failed;
    }

    /// Pulls the image the lock names by its manifest digest, for the lock's platform.
    fn pull_locked(
        context: *Context,
        reference: []const u8,
        name: ?[]const u8,
        entry: *const lock_file.Entry,
    ) Error!void {
        const ws = context.ws;
        reference_mod.parse(reference, &ws.pull.reference) catch
            return context.stale_lock(name, reference);
        var text: [constants.reference_bytes_max]u8 = undefined;
        const by_digest = std.fmt.bufPrint(&text, "{s}/{s}@{s}", .{
            ws.pull.reference.registry(),
            ws.pull.reference.repository(),
            &entry.manifest.text(),
        }) catch return context.stale_lock(name, reference);
        const mirrors = context.host.environment(
            "ZBX_REGISTRY_MIRRORS",
            constants.registry_mirrors_bytes_max,
        );
        const architecture = manifest.architecture_of_platform(entry.platform_text());
        const pulling: pull_lib.Request = .{
            .reference = by_digest,
            .platform = .{ .architecture = architecture },
            .mirrors = mirrors orelse "",
        };
        try context.say_pulling(by_digest);
        var pulled: pull_lib.Result = undefined;
        const import_ws = &ws.step.import;
        const host = context.host;
        const facts = context.facts;
        const diag = context.diag;
        pull_lib.pull(host, facts, &pulling, null, &ws.pull, import_ws, &pulled, diag) catch {
            return error.Failed;
        };
        if (!pulled.manifest_digest.eql(entry.manifest)) {
            const returned = pulled.manifest_digest.text();
            const locked = entry.manifest.text();
            diagnose.locked_manifest_mismatch(context.diag, reference, &returned, &locked);
            return error.Failed;
        }
    }

    /// `pulling <base>@<digest>`: a pull can take a while, and the report has no row for it. On
    /// stderr under `--output json`, so stdout stays one record per line.
    fn say_pulling(context: *Context, by_digest: []const u8) Error!void {
        var line: [constants.reference_bytes_max + 16]u8 = undefined;
        const format = "pulling {s}\n";
        const text = std.fmt.bufPrint(&line, format, .{by_digest}) catch unreachable; // Fits.
        if (!context.json) return context.emit(text);
        context.host.write_all(.stderr, text) catch |err| {
            errors.output_failed(context.diag, .stderr, err, context.host.last_errno());
            return error.OutputFailed;
        };
    }

    fn import_inputs(context: *Context, index: u8) Error!Digest {
        const ws = context.ws;
        const job: input_job.Request = .{
            .host = context.host,
            .facts = context.facts,
            .store = context.store,
            .loaded = context.loaded,
            .step = index,
            .ws = &ws.input,
            .problem = &ws.input_problem,
        };
        return input_job.import(&job, context.diag) catch return error.Failed;
    }

    /// Writes the entry under the shared lock, and returns the tree it names.
    fn record(context: *Context, output: Digest) Error!Digest {
        const store = context.store;
        try store_diagnose.hold(context.diag, store, .shared, "build", "recording a build step");
        defer lock.release(store);
        var failure: cache.Failure = undefined;
        const ws = context.ws;
        const kept = cache.record(store, &ws.cache, &ws.key, output, &failure) catch {
            return context.cache_failed(&failure);
        };
        context.unroot(output);
        return kept;
    }

    /// The entry roots the output now: drops the root the step's import left (N8). Only a root
    /// this build made goes: its source starts with `build:` and it was written at or after the
    /// build's start; a root the user made earlier (the import left it as it was) stays. A
    /// failure to drop it is no failure of the build: the next `store gc` shows the root and the
    /// user may remove it.
    fn unroot(context: *Context, output: Digest) void {
        const store = context.store;
        var root: roots.Root = undefined;
        var errno: u16 = 0;
        roots.load(store, output, &root, &errno) catch return;
        if (!std.mem.startsWith(u8, root.source_text(), step_mod.output_root_prefix)) return;
        if (root.time < context.started_s) return;
        roots.remove(store, output) catch {};
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
    fn elapsed(context: *const Context) u64 {
        const now = context.host.monotonic_ms();
        assert(now >= context.started_ms);
        return now - context.started_ms;
    }

    /// `build: <file>, <n> steps` (the steps and the image), in text mode only.
    fn header(context: *Context) Error!void {
        if (context.json) return;
        const file = &context.loaded.file;
        const line = std.fmt.bufPrint(&context.ws.row, "build: {s}, {d} steps\n", .{
            context.loaded.shown(), file.steps_count + 1,
        }) catch unreachable; // `row_bytes` holds a shown path and a count.
        return context.emit(line);
    }

    /// `W0801` once, on stderr, before any step runs, when the build file has steps with
    /// `network = true`. Only a warning: a stderr that cannot be written loses it and the build
    /// goes on.
    pub fn warn_network(context: *Context) void {
        const file = &context.loaded.file;
        var names: [constants.build_steps_max][]const u8 = undefined;
        var count: u32 = 0;
        for (file.steps_slice()) |*step| {
            if (!step.network) continue;
            names[count] = file.text(step.name);
            count += 1;
        }
        if (count == 0) return;
        comptime assert(constants.diag_field_bytes_max >= diagnose.network_label.len + 8);
        var joined: [constants.diag_field_bytes_max - diagnose.network_label.len]u8 = undefined;
        var warning: Diag = undefined;
        warning.reset();
        diagnose.network_steps(&warning, diagnose.network_names(&joined, names[0..count]), count);
        const mode: render.Mode = if (context.json)
            .json
        else if (context.verbose)
            .verbose
        else
            .text;
        const color = mode != .json and context.host.color_enabled(.stderr);
        var buffer: [constants.output_bytes_max]u8 = undefined;
        const text = render.render(&warning, mode, color, &buffer);
        context.host.write_all(.stderr, text) catch return;
    }

    fn emit(context: *Context, line: []const u8) Error!void {
        context.host.write_all(.stdout, line) catch |err| {
            errors.output_failed(context.diag, .stdout, err, context.host.last_errno());
            return error.OutputFailed;
        };
    }

    /// Tells that step `index` (or the image, `image_slot`) ended: a row, or a `zbx.build/1`
    /// line. A hit starts and ends when it is found.
    fn report(context: *Context, index: u32, hit: bool, output: Digest) Error!void {
        const ws = context.ws;
        const file = &context.loaded.file;
        assert(index <= image_slot);
        if (index != image_slot) assert(index < file.steps_count);
        const timing = &ws.timings[index];
        timing.end_ms = context.elapsed();
        if (hit) timing.start_ms = timing.end_ms;
        timing.hit = hit;
        timing.output = output;
        timing.key = ws.key.digest;
        const name = if (index == image_slot) "image" else file.text(file.steps[index].name);
        timing.network = index != image_slot and file.steps[index].network;
        if (hit) context.hits += 1 else context.misses += 1;
        var writer = std.Io.Writer.fixed(&ws.row);
        const word = if (hit) "hit" else "miss";
        if (context.json) {
            writer.print("{{\"schema\":\"zbx.build/1\",\"step\":\"{s}\",\"cache\":\"{s}\"," ++
                "\"key\":\"{s}\",\"output\":\"{s}\",\"start_ms\":{d},\"end_ms\":{d}," ++
                "\"network\":{s}}}\n", .{
                name,
                word,
                &timing.key.text(),
                &output.text(),
                timing.start_ms,
                timing.end_ms,
                if (timing.network) "true" else "false",
            }) catch unreachable; // `row_bytes` holds the longest record.
        } else {
            const took = timing.end_ms - timing.start_ms;
            writer.print("  {s}", .{name}) catch unreachable; // Fits `row_bytes`.
            writer.splatByteAll(' ', context.name_width - name.len) catch unreachable; // Fits.
            writer.print("{s}{s: <4}{s}{d}.{d:0>2} s", .{
                name_gap, word, name_gap, took / 1000, took % 1000 / 10,
            }) catch unreachable; // Fits.
            if (timing.network) writer.print("{s}net", .{name_gap}) catch unreachable; // Fits.
            writer.writeByte('\n') catch unreachable; // Fits.
        }
        return context.emit(writer.buffered());
    }

    /// The image step: the base, the adds and the config become the image tree and the build
    /// record. Runs after every step has an output, in this process, under one shared lock so
    /// that a gc cannot take the trees assembled before the cache entry roots them.
    pub fn build_image(context: *Context) Error!void {
        const ws = context.ws;
        const file = &context.loaded.file;
        ws.timings[image_slot].start_ms = context.elapsed();
        var base_tree: ?Digest = null;
        var base: *const images.Settings = &ws.empty_settings;
        ws.empty_settings.clear();
        if (file.image.base) |text| {
            _ = try context.load_base(file.text(text), null);
            base_tree = ws.image.tree;
            base = &ws.image.settings;
        }
        if (result_mod.resolve(base, file, &ws.record.config)) |refusal| {
            diagnose.config_too_large(context.diag, refusal);
            return error.Failed;
        }
        const adds = try context.fill_adds();
        ws.record.tree = std.mem.zeroes(Digest);
        var overflowed: result_mod.Refusal = undefined;
        const encoded = result_mod.encode_field(&ws.record, &ws.record_bytes, &overflowed);
        const config_bytes = encoded catch {
            diagnose.config_too_large(context.diag, overflowed);
            return error.Failed;
        };
        const spec: key_mod.ImageSpec = .{
            .base_tree = base_tree orelse std.mem.zeroes(Digest),
            .adds = ws.image_adds[0..adds.len],
            .config = Digest.of(config_bytes),
        };
        key_mod.compute_image(&spec, &ws.key) catch unreachable; // Adds and paths are bounded.
        const store = context.store;
        try store_diagnose.hold(context.diag, store, .shared, "build", "assembling the image");
        defer lock.release(store);
        var hit = true;
        var failure: cache.Failure = undefined;
        const found = cache.lookup(store, &ws.cache, &ws.key, &failure) catch
            return context.cache_failed(&failure);
        const tree = switch (found) {
            .hit => |existing| existing,
            .miss => blk: {
                hit = false;
                const made = try context.assemble_image(base_tree, adds);
                break :blk cache.record(store, &ws.cache, &ws.key, made, &failure) catch
                    return context.cache_failed(&failure);
            },
        };
        ws.record.tree = tree;
        var saved: result_mod.Failure = undefined;
        const digest = result_mod.save(store, &ws.record, &ws.record_bytes, &saved) catch {
            const err = saved.err;
            store_diagnose.write_failed(context.diag, store, saved.step, err, saved.errno);
            return error.Failed;
        };
        try context.write_provenance(tree, digest);
        try context.report(image_slot, hit, tree);
        try context.footer(digest);
    }

    /// The provenance record of the result just saved (the store lock is held).
    fn write_provenance(context: *Context, tree: Digest, result: Digest) Error!void {
        const ws = context.ws;
        const count = context.loaded.file.steps_count;
        for (ws.timings[0..count], 0..) |timing, index| ws.step_keys[index] = timing.key;
        const asked: provenance_job.Request = .{
            .host = context.host,
            .store = context.store,
            .loaded = context.loaded,
            .locking = &ws.locking,
            .keys = ws.step_keys[0..count],
            .inputs = ws.step_inputs[0..count],
            .outputs = ws.outputs[0..count],
            .image_key = ws.key.digest,
            .tree = tree,
            .result = result,
            .started = context.started_s,
            .records_max = context.records_max,
        };
        const outcome = provenance_job.write(&asked, &ws.provenance, context.diag) catch {
            return error.Failed;
        };
        if (outcome == .written) return;
        // The result is built and usable; only its provenance record is missing, so a run under
        // `require_provenance` will be refused until room is made.
        const text = std.fmt.comptimePrint(
            "zbx: the store holds {d} provenance records, the most it keeps " ++
                "(trust_records_max), so this result has none and require_provenance refuses it\n",
            .{constants.trust_records_max},
        );
        context.host.write_all(.stderr, text) catch {};
    }

    /// The adds as the assembly and the key take them: each source is its step's output.
    fn fill_adds(context: *Context) Error![]const assemble.Add {
        const ws = context.ws;
        const file = &context.loaded.file;
        const given = file.adds_slice();
        assert(given.len <= ws.adds.len);
        for (given, 0..) |add, at| {
            const from = file.text(add.from);
            const source = for (file.steps_slice(), 0..) |step, index| {
                if (std.mem.eql(u8, file.text(step.name), from)) break ws.outputs[index];
            } else unreachable; // The graph check refused an add from no step.
            ws.adds[at] = .{ .source = source, .to = file.text(add.to) };
            ws.image_adds[at] = .{ .source = source, .to = file.text(add.to) };
        }
        return ws.adds[0..given.len];
    }

    fn assemble_image(
        context: *Context,
        base: ?Digest,
        adds: []const assemble.Add,
    ) Error!Digest {
        const ws = context.ws;
        const assembling: assemble.Context = .{
            .store = context.store,
            .ws = &ws.assembly,
            .failure = &ws.assembly_failure,
        };
        return assemble.assemble(assembling, base, adds) catch {
            const store = context.store;
            switch (ws.assembly_failure) {
                .io => |io| {
                    store_diagnose.write_failed(context.diag, store, io.step, io.err, io.errno);
                },
                .damaged => {
                    const operation = "reading an image tree";
                    store_diagnose.write_failed(context.diag, store, operation, error.IoFailed, 0);
                },
                else => {
                    const file = &context.loaded.file;
                    const failed = ws.assembly.failed_add;
                    const add = file.adds_slice()[failed];
                    var earlier: ?diagnose.AddText = null;
                    if (ws.assembly_failure == .conflict) {
                        const conflict = &ws.assembly_failure.conflict;
                        const path = conflict.path[0..conflict.path_len];
                        const found = assemble.earlier_source(assembling, adds, failed, path);
                        if (found) |at| {
                            const before = file.adds_slice()[at];
                            earlier = .{
                                .from = file.text(before.from),
                                .to = file.text(before.to),
                            };
                        }
                    }
                    diagnose.assembly_refused(
                        context.diag,
                        &ws.assembly_failure,
                        failed,
                        file.text(add.from),
                        file.text(add.to),
                        earlier,
                    );
                },
            }
            return error.Failed;
        };
    }

    /// `built <result digest> (<hits> hits, <misses> misses, <s> s)`, or the `build_result` line.
    fn footer(context: *Context, digest: Digest) Error!void {
        const total = context.elapsed();
        var writer = std.Io.Writer.fixed(&context.ws.row);
        if (context.json) {
            writer.print("{{\"schema\":\"zbx.build/1\",\"build_result\":{{\"digest\":\"{s}\"," ++
                "\"hits\":{d},\"misses\":{d},\"elapsed_ms\":{d}}}}}\n", .{
                &digest.text(), context.hits, context.misses, total,
            }) catch unreachable; // `row_bytes` holds it.
        } else {
            var hits: [16]u8 = undefined;
            var misses: [16]u8 = undefined;
            writer.print("built {s}  ({s}, {s}, {d}.{d} s)\n", .{
                &digest.text(),
                count_text(&hits, context.hits, "hit", "hits"),
                count_text(&misses, context.misses, "miss", "misses"),
                total / 1000,
                total % 1000 / 100,
            }) catch unreachable; // `row_bytes` holds it.
        }
        return context.emit(writer.buffered());
    }
};

/// `1 hit`, `2 hits`: the count and its noun, the singular only for one.
fn count_text(buffer: *[16]u8, count: u32, one: []const u8, many: []const u8) []const u8 {
    assert(one.len < many.len);
    const word = if (count == 1) one else many;
    return std.fmt.bufPrint(buffer, "{d} {s}", .{ count, word }) catch unreachable; // Fits.
}

test "the footer counts say hit once and hits otherwise" {
    // Goal: the grammar of the footer's counts. Method: 0, 1 and 2 of each noun.
    var buffer: [16]u8 = undefined;
    try std.testing.expectEqualStrings("0 hits", count_text(&buffer, 0, "hit", "hits"));
    try std.testing.expectEqualStrings("1 hit", count_text(&buffer, 1, "hit", "hits"));
    try std.testing.expectEqualStrings("2 hits", count_text(&buffer, 2, "hit", "hits"));
    try std.testing.expectEqualStrings("1 miss", count_text(&buffer, 1, "miss", "misses"));
    try std.testing.expectEqualStrings("2 misses", count_text(&buffer, 2, "miss", "misses"));
    try std.testing.expectEqualStrings("0 misses", count_text(&buffer, 0, "miss", "misses"));
}

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
    assert(row_bytes > 2 * constants.store_digest_text_bytes + constants.build_step_name_bytes_max +
        200);
    assert(answer_bytes == 1 + constants.store_digest_bytes);
}

/// What `zbx sign` takes for a base: the reference's name and the manifest the lock names,
/// `alpine@sha256:<hex>`. A name too long for `out` is cut (the digest is what is signed).
fn base_text(out: []u8, reference: []const u8, manifest_digest: digest_sha.Sha256) []const u8 {
    assert(out.len >= constants.oci_digest_text_bytes + 1);
    var name = reference;
    if (std.mem.indexOfScalar(u8, name, '@')) |at| name = name[0..at];
    const slash = std.mem.lastIndexOfScalar(u8, name, '/') orelse 0;
    if (std.mem.indexOfScalarPos(u8, name, slash, ':')) |colon| name = name[0..colon];
    const room = out.len - constants.oci_digest_text_bytes - 1;
    name = name[0..@min(name.len, room)];
    const digest = manifest_digest.text();
    return std.fmt.bufPrint(out, "{s}@{s}", .{ name, &digest }) catch unreachable; // Room made.
}
