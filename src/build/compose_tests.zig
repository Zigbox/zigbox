//! The real executor of `zbx build` (`compose.zig`) on the simulated host: how a worker's end and
//! its answer on the pipe are read (a clean answer, garbage, a short answer, a signal, a
//! diagnostic from the worker), that a second failure does not replace the first diagnostic,
//! that a step recorded after another failed still is, a failed row, and that `abort_step`
//! leaves no worker and no pipe behind. The sim's `wait_any` ends a worker only as a test says
//! (`reaped_next`); the real fork, pidfd and pipe are the VM demo's.

const std = @import("std");
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;
const host_sim = @import("../host_sim.zig");
const host_mod = @import("../host.zig");
const doctor = @import("../doctor.zig");
const compose = @import("compose.zig");
const file_mod = @import("file.zig");
const file_tests = @import("file_tests.zig");
const fs_sim = @import("../store/fs_sim.zig");
const import = @import("../store/import.zig");
const key_mod = @import("key.zig");
const layout = @import("../store/layout.zig");
const load_mod = @import("load.zig");
const support = @import("../store/test_support.zig");
const digest_mod = @import("../store/digest.zig");

const testing = std.testing;
const Digest = digest_mod.Digest;

const root_path = "/data/store";

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var store: layout.Store = undefined;
var import_workspace: import.Workspace = undefined;
var loaded: load_mod.Workspace = undefined;
var composed: compose.Workspace = undefined;
var facts: doctor.Facts = undefined;
var diag: Diag = undefined;
var context: compose.Context = undefined;

fn noop_child(raw: *anyopaque) u8 {
    _ = raw;
    return 0;
}

/// A world with a store, the brief's example build file parsed (step 0 is "compile"), and a
/// context over them whose workers are the test's.
fn start() void {
    sim.init(1, &.{});
    files.init(1);
    sim.store_fs = &files;
    files.put_dir("/data", 0o755);
    support.make_store_directories(&files, root_path);
    store.at(sim.interface(), root_path);
    sim.world.now = 1_800_000_000;
    diag.reset();
    var problem: file_mod.Problem = undefined;
    const parsed = file_mod.parse(file_tests.example, &loaded.file, &problem);
    testing.expectEqual(file_mod.ParseResult.parsed, parsed) catch unreachable; // The brief's file.
    for (&composed.slots) |*slot| slot.active = false;
    composed.outputs = @splat(Digest.of("unset"));
    context = .{
        .host = sim.interface(),
        .facts = &facts,
        .loaded = &loaded,
        .ws = &composed,
        .diag = &diag,
        .store = &store,
        .group = "g",
        .row_failed = null,
    };
    key_mod.compute(&.{
        .platform = "linux/amd64",
        .base_tree = Digest.of("base"),
        .base_env = &.{},
        .input_tree = Digest.of("input"),
        .needs = &.{},
        .argv = &.{"true"},
        .env = &.{},
        .network = false,
        .name = "compile",
    }, &composed.key) catch unreachable; // A small spec.
}

/// A real tree in the store: the cache entry that records an output names it.
fn made_output() Digest {
    support.make_source(&files, 0);
    var result: import.Result = undefined;
    const options: import.Options = .{ .squash_owner = false, .warn = null };
    import.import(&store, &import_workspace, "/src", options, &result, &diag) catch {
        unreachable; // The sample tree imports.
    };
    diag.reset();
    return result.digest;
}

/// Activates slot `at` for step 0 with a pipe that already holds `bytes` and is closed for
/// writing, as a worker that ended leaves it.
fn worker_ended(at: usize, pid: host_mod.Pid, bytes: []const u8) *compose.Slot {
    const host = sim.interface();
    const report = host.pipe() catch unreachable; // The sim has pipes to spare.
    if (bytes.len > 0) host.write_handle_all(report.write, bytes) catch unreachable; // Room.
    host.close(report.write);
    const slot = &composed.slots[at];
    slot.* = .{ .active = true, .index = 0, .pid = pid, .report = report, .key = composed.key };
    return slot;
}

fn answer_of(output: Digest) [compose.answer_bytes]u8 {
    var bytes: [compose.answer_bytes]u8 = @splat(0);
    bytes[0] = compose.tag_output;
    @memcpy(bytes[1..], &output.bytes);
    return bytes;
}

/// What a failing worker writes: the failure tag, then the encoded diagnostic.
fn encoded_failure(bytes: *[compose.failure_bytes_max]u8) []const u8 {
    var made: Diag = undefined;
    made.reset();
    made.raise(.E0805);
    made.cause("the step said so", .{});
    bytes[0] = compose.tag_failure;
    const encoded = made.encode(bytes[1..][0..constants.diag_carry_bytes_max]);
    return bytes[0 .. 1 + encoded.len];
}

fn settle(slot: *compose.Slot, status: host_mod.ExitStatus) @import("schedule.zig").Ended {
    return context.settle(slot, status);
}

test "a clean exit with a whole answer is recorded and its row written" {
    // Goal: the success path of a worker. Method: the answer of a real imported tree on the
    // pipe; the cache entry names it, the output is kept and the row is on stdout.
    start();
    const output = made_output();
    const answer = answer_of(output);
    const slot = worker_ended(0, 7, &answer);
    const ended = settle(slot, .{ .exited = 0 });
    try testing.expect(ended.ok);
    try testing.expectEqual(@as(u8, 0), ended.index);
    try testing.expect(composed.outputs[0].eql(output));
    try testing.expect(!slot.active);
    try testing.expect(diag.code == null);
    const format = "compile  built  {s}\n";
    const want = try std.fmt.allocPrint(testing.allocator, format, .{output.text()});
    defer testing.allocator.free(want);
    try testing.expectEqualStrings(want, sim.stdout());
}

test "garbage, a short answer, no answer and a signal each fail the step with E0419" {
    // Goal: nothing but a whole answer after a clean exit is an output. Method: each shape of
    // bytes and status, fresh; the step fails, one diagnostic says why, nothing is printed.
    const garbage = "not a diagnostic at all, and not an answer";
    const almost = garbage[0 .. compose.answer_bytes - 1];
    const Case = struct { status: host_mod.ExitStatus, bytes: []const u8, cause: []const u8 };
    const cases = [_]Case{
        .{ .status = .{ .exited = 0 }, .bytes = "", .cause = "no answer" },
        .{ .status = .{ .exited = 0 }, .bytes = "short", .cause = "no answer" },
        .{ .status = .{ .exited = 0 }, .bytes = almost, .cause = "no answer" },
        .{ .status = .{ .exited = 0 }, .bytes = garbage, .cause = "no answer" },
        .{ .status = .{ .exited = 3 }, .bytes = garbage, .cause = "no answer" },
        .{ .status = .{ .signaled = 9 }, .bytes = "", .cause = "signal 9" },
    };
    for (cases) |case| {
        start();
        const slot = worker_ended(0, 7, case.bytes);
        const ended = settle(slot, case.status);
        try testing.expect(!ended.ok);
        try testing.expect(diag.code.? == .E0419);
        try testing.expect(std.mem.indexOf(u8, diag.last_cause().?, case.cause) != null);
        try testing.expectEqual(@as(usize, 0), sim.stdout().len);
        try testing.expect(!slot.active);
    }
}

test "a diagnostic the worker wrote is the step's, whatever its length" {
    // Goal: a worker that failed on its own says why. Method: an encoded E0805 and a non-zero
    // exit; a clean exit with the same bytes is no output either.
    var bytes: [compose.failure_bytes_max]u8 = undefined;
    const encoded = encoded_failure(&bytes);
    for ([_]u8{ 1, 0 }) |code| {
        start();
        const slot = worker_ended(0, 7, encoded);
        try testing.expect(!settle(slot, .{ .exited = code }).ok);
        try testing.expect(diag.code.? == .E0805);
    }
}

test "a second failure keeps the first diagnostic; a later success is still recorded" {
    // Goal: the first failure is the build's, but a step that finished well stays cached.
    // Method: a diagnostic already in place; a failing worker, then a good one.
    start();
    const output = made_output();
    diag.raise(.E0803);
    const slot = worker_ended(0, 7, "");
    try testing.expect(!settle(slot, .{ .signaled = 9 }).ok);
    try testing.expect(diag.code.? == .E0803);
    try testing.expect(composed.side_diag.code.? == .E0419);
    try testing.expect(context.diag == &diag);
    const answer = answer_of(output);
    const good = worker_ended(1, 8, &answer);
    try testing.expect(settle(good, .{ .exited = 0 }).ok);
    try testing.expect(diag.code.? == .E0803);
    try testing.expect(composed.outputs[0].eql(output));
    try testing.expect(std.mem.endsWith(u8, sim.stdout(), "\n"));
}

test "a row that cannot be written fails the step and says why once" {
    // Goal: a closed stdout is an output failure, not a lost row. Method: stdout writes fail;
    // the output is recorded, the step is not ok and `row_failed` carries the error.
    start();
    const output = made_output();
    const answer = answer_of(output);
    const slot = worker_ended(0, 7, &answer);
    sim.faults.write_error_per_mille = 1000;
    sim.faults.write_fault_stream = .stdout;
    try testing.expect(!settle(slot, .{ .exited = 0 }).ok);
    try testing.expectEqual(@as(?compose.Error, error.OutputFailed), context.row_failed);
    try testing.expect(composed.outputs[0].eql(output));
    try testing.expect(diag.code != null);
}

test "wait reaps the worker wait_any names, and a failed wait is one diagnostic" {
    // Goal: the real `wait`. Method: two workers; the second is the one the host reaps; then a
    // wait_any that fails leaves both workers active for the scheduler to abort.
    start();
    const output = made_output();
    const answer = answer_of(output);
    _ = worker_ended(0, 7, "");
    _ = worker_ended(2, 9, &answer);
    sim.reaped_next = .{ .index = 1, .status = .{ .exited = 0 } };
    const ended = try context.wait();
    try testing.expect(ended.ok);
    try testing.expect(composed.slots[0].active);
    try testing.expect(!composed.slots[2].active);
    try testing.expectError(error.Failed, context.wait());
    try testing.expect(diag.code.? == .E0419);
    try testing.expect(composed.slots[0].active);
}

test "abort ends every worker, reaps it and closes its pipe" {
    // Goal: after a failed wait nothing outlives the build. Method: two real sim children with
    // pipes; abort; no slot is active and the pipes have lost their readers.
    start();
    var unused: u8 = 0;
    var reports: [2]host_mod.Pipe = undefined;
    for (0..2) |at| {
        const host = sim.interface();
        const pid = host.fork_child(false, noop_child, &unused) catch unreachable; // Room.
        const slot = worker_ended(at, pid, "");
        reports[at] = slot.report;
    }
    try testing.expect(sim.interface().pipe_has_reader(reports[0].write));
    compose.Context.abort_step(&context);
    for (composed.slots[0..2]) |slot| try testing.expect(!slot.active);
    try testing.expect(!sim.interface().pipe_has_reader(reports[0].write));
    try testing.expect(!sim.interface().pipe_has_reader(reports[1].write));
}

test "a tag, not a length, tells an output from a diagnostic" {
    // Goal: no diagnostic passes for an output, and none is lost for its length. Method: a clean
    // exit with an answer-sized tagged failure still decodes as the worker's; an answer-sized
    // message without the output tag is no output; a valid diagnostic without the failure tag
    // is not the worker's.
    start();
    var made: Diag = undefined;
    made.reset();
    made.raise(.E0805);
    made.cause("x", .{});
    var raw: [constants.diag_carry_bytes_max]u8 = undefined;
    const short = made.encode(&raw);
    var exact: [compose.answer_bytes]u8 = @splat('\n');
    exact[0] = compose.tag_failure;
    @memcpy(exact[1..][0..short.len], short);
    const slot = worker_ended(0, 7, &exact);
    try testing.expect(!settle(slot, .{ .exited = 0 }).ok);
    try testing.expect(diag.code.? == .E0805);
    start();
    var untagged = answer_of(Digest.of("x"));
    untagged[0] = 0;
    const other = worker_ended(0, 7, &untagged);
    try testing.expect(!settle(other, .{ .exited = 0 }).ok);
    try testing.expect(diag.code.? == .E0419);
    start();
    var bare: [compose.failure_bytes_max]u8 = undefined;
    bare[0] = 0; // Not the failure tag; a valid diagnostic follows.
    @memcpy(bare[1..][0..short.len], short);
    const no_tag = worker_ended(0, 7, bare[0 .. 1 + short.len]);
    try testing.expect(!settle(no_tag, .{ .exited = 1 }).ok);
    try testing.expect(diag.code.? == .E0419);
}

fn set_path(path: *@TypeOf(loaded.project), text: []const u8) void {
    @memset(&path.bytes, 0);
    @memcpy(path.bytes[0..text.len], text);
    path.len = @intCast(text.len);
}

test "a failing step reaches the user as the step's own diagnostic" {
    // Goal: the worker writes its failure behind the failure tag, so a real step failure is not
    // E0419 "worker ended with no answer". Method: run `worker_entry` itself, through
    // `fork_worker` and the sim's `fork_child`, on a step that fails (no data directory is
    // found, E0421); the child's exit and bytes settle in the parent.
    start();
    set_path(&loaded.project, "/p");
    set_path(&loaded.path, "/p/zbx.build.zon");
    const spec: key_mod.Spec = .{
        .platform = "linux/amd64",
        .base_tree = Digest.of("base"),
        .base_env = &.{},
        .input_tree = Digest.of("input"),
        .needs = &.{},
        .argv = &.{"true"},
        .env = &.{},
        .network = false,
        .name = "compile",
    };
    try context.fork_worker(0, &spec);
    const slot = &composed.slots[0];
    const status = try sim.interface().wait_for(slot.pid);
    try testing.expect(status == .exited and status.exited != 0);
    try testing.expect(!settle(slot, status).ok);
    try testing.expect(diag.code.? == .E0421);
}

test "a failed row changes the error value `finish` returns, not the diagnostic" {
    // Goal: pin what the row ordering does. Method: a failed step and a failed row; `finish`
    // answers OutputFailed (the value `run_slice` discards; the user reads `diag`, which keeps
    // the first failure). Without the row, Failed. A failed `hit` row never sets `row_failed`.
    start();
    const failed: @import("schedule.zig").Outcome = .{
        .failed = 0,
        .aborted = false,
        .hits = 0,
        .built = 0,
    };
    context.row_failed = error.OutputFailed;
    try testing.expectError(error.OutputFailed, context.finish(failed));
    context.row_failed = null;
    try testing.expectError(error.Failed, context.finish(failed));
    try testing.expect(diag.code != null);
}
