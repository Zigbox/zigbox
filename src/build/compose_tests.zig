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
const input_job = @import("input_job.zig");
const input_tree = @import("input_tree.zig");
const inputs_mod = @import("inputs.zig");
const codes = @import("../diag/codes.zig");
const key_mod = @import("key.zig");
const layout = @import("../store/layout.zig");
const load_mod = @import("load.zig");
const support = @import("../store/test_support.zig");
const digest_mod = @import("../store/digest.zig");
const cache = @import("cache.zig");
const schedule = @import("schedule.zig");
const verify = @import("../store/verify.zig");

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
        .json = false,
        .verbose = false,
        .started_ms = sim.interface().monotonic_ms(),
        .started_s = sim.interface().time_now(),
        .name_width = 7,
        .hits = 0,
        .misses = 0,
        .gate_loaded = false,
        .records_max = constants.trust_records_max,
    };
    composed.timings = @splat(std.mem.zeroes(compose.Timing));
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
    try testing.expectEqualStrings("  compile   miss   0.00 s\n", sim.stdout());
    try testing.expectEqual(@as(u32, 1), context.misses);
    try testing.expect(composed.timings[0].output.eql(output));
}

test "with json the step ends as one zbx.build/1 line with its times and key" {
    // Goal: the machine report. Method: the same settle in json mode; one line, whole fields.
    start();
    context.json = true;
    composed.timings[0].start_ms = 0;
    const output = made_output();
    const answer = answer_of(output);
    const slot = worker_ended(0, 7, &answer);
    try testing.expect(settle(slot, .{ .exited = 0 }).ok);
    const line = sim.stdout();
    const head = "{\"schema\":\"zbx.build/1\",\"step\":\"compile\",\"cache\":\"miss\"," ++
        "\"key\":\"b3:";
    try testing.expect(std.mem.startsWith(u8, line, head));
    const tail = "\"start_ms\":0,\"end_ms\":0,\"network\":false}\n";
    try testing.expect(std.mem.indexOf(u8, line, tail) != null);
    try testing.expect(std.mem.indexOf(u8, line, &output.text()) != null);
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

const roots = @import("../store/roots.zig");
const result_mod = @import("result.zig");
const provenance_store = @import("../trust/provenance_store.zig");
const provenance = @import("../trust/provenance.zig");

/// A step's output imported as the worker does: rooted `build:compile`, unless a root exists.
fn imported_as_step(fresh: bool) Digest {
    if (fresh) support.make_source(&files, 0);
    var result: import.Result = undefined;
    const options: import.Options = .{
        .squash_owner = false,
        .warn = null,
        .save_root = true,
        .keep_existing_root = true,
        .label = "build:compile",
    };
    import.import(&store, &import_workspace, "/src", options, &result, &diag) catch {
        unreachable; // The sample tree imports.
    };
    diag.reset();
    return result.digest;
}

fn root_source(output: Digest, text: *[constants.store_source_bytes_max]u8) ?[]const u8 {
    var root: roots.Root = undefined;
    var errno: u16 = 0;
    roots.load(&store, output, &root, &errno) catch return null;
    @memcpy(text[0..root.source_len], root.source_text());
    return text[0..root.source_len];
}

fn recorded(output: Digest) !void {
    const answer = answer_of(output);
    const slot = worker_ended(0, 7, &answer);
    try testing.expect(settle(slot, .{ .exited = 0 }).ok);
}

test "N8: a root the user made of the output survives the step and its record" {
    // Goal: the build never replaces or deletes the user's root of the same tree. Method: root
    // /src as the user, import it as the step does (keeps the record), record the step.
    start();
    const output = made_output();
    try testing.expect(imported_as_step(false).eql(output));
    var text: [constants.store_source_bytes_max]u8 = undefined;
    try testing.expectEqualStrings("/src", root_source(output, &text).?);
    try recorded(output);
    try testing.expectEqualStrings("/src", root_source(output, &text).?);
}

test "N8: the root the build made is removed once the entry holds the output" {
    // Goal: the build's own root goes. Method: import as the step with no earlier root; it is
    // `build:compile`; recording the step removes it.
    start();
    const output = imported_as_step(true);
    var text: [constants.store_source_bytes_max]u8 = undefined;
    try testing.expectEqualStrings("build:compile", root_source(output, &text).?);
    try recorded(output);
    try testing.expect(root_source(output, &text) == null);
}

test "N8: a build: root older than this build is left alone" {
    // Goal: only a root this build made is removed. Method: the same root, made before the
    // build's start (a user's, or a crashed build's); recording leaves it.
    start();
    const output = imported_as_step(true);
    context.started_s += 100;
    try recorded(output);
    var text: [constants.store_source_bytes_max]u8 = undefined;
    try testing.expectEqualStrings("build:compile", root_source(output, &text).?);
}

const image_only =
    \\.{
    \\    .version = 1,
    \\    .steps = .{
    \\        .{ .name = "compile", .base = "alpine:3.20", .inputs = .{"a"}, .run = .{"true"} },
    \\        .{ .name = "notice", .base = "alpine:3.20", .inputs = .{"a"}, .run = .{"true"} },
    \\    },
    \\    .image = .{
    \\        .add = .{
    \\            .{ .from = "compile", .to = "/usr/bin" },
    \\            .{ .from = "notice", .to = DEST },
    \\        },
    \\    },
    \\}
    \\
;

/// The build file with the second add's destination `dest`; the first step's output is the sample
/// tree, the second's a tree whose `bin` is a file.
fn image_started(dest: []const u8) void {
    start();
    var replaced: [1024]u8 = undefined;
    const at = std.mem.indexOf(u8, image_only, "DEST").?;
    const out = std.fmt.bufPrint(&replaced, "{s}\"{s}\"{s}", .{
        image_only[0..at], dest, image_only[at + 4 ..],
    }) catch unreachable; // Fits.
    var problem: file_mod.Problem = undefined;
    const parsed = file_mod.parse(out, &loaded.file, &problem);
    testing.expectEqual(file_mod.ParseResult.parsed, parsed) catch unreachable; // A valid file.
    composed.outputs[0] = made_output();
    composed.locking.lock.clear();
    const manifest = oci_digest.Sha256{ .bytes = @splat(3) };
    composed.locking.lock.put("alpine:3.20", manifest, "linux/amd64", Digest.of("t")) catch {
        unreachable; // One entry fits.
    };
    // A tree with a file `bin`: under /usr/bin it clashes with the sample tree's directory.
    files.put_dir("/other", 0o755);
    files.put("/other/bin", .file, 0o644, .{ 0, 0 }, "x");
    var result: import.Result = undefined;
    const options: import.Options = .{ .squash_owner = false, .warn = null };
    import.import(&store, &import_workspace, "/other", options, &result, &diag) catch {
        unreachable; // The small tree imports.
    };
    diag.reset();
    composed.outputs[1] = result.digest;
    sim.stdout_len = 0;
}

test "build_image: a miss, then a hit, the footer, and the result record saved" {
    // Goal: the image step end to end on the simulated store. Method: build it twice; the first
    // is a miss and says `1 miss`, the second a hit and says `1 hit`, with the same digest; the
    // record under that digest loads and names the assembled tree.
    image_started("/etc");
    try context.build_image();
    const first = sim.stdout();
    try testing.expect(std.mem.indexOf(u8, first, "  image") != null);
    try testing.expect(std.mem.indexOf(u8, first, "miss") != null);
    const footer = "built b3:";
    const at = std.mem.indexOf(u8, first, footer).?;
    const digest = Digest.parse(first[at + 6 ..][0..constants.store_digest_text_bytes]).?;
    try testing.expect(std.mem.indexOf(u8, first[at..], "  (0 hits, 1 miss, ") != null);
    var record: result_mod.Record = undefined;
    var bytes: [constants.build_result_bytes_max + 1]u8 = undefined;
    var errno: u16 = 0;
    try result_mod.load(&store, digest, &record, &bytes, &errno);
    try testing.expectEqual(@as(u32, 1), context.misses);
    sim.stdout_len = 0;
    context.hits = 0;
    context.misses = 0;
    try context.build_image();
    const second = sim.stdout();
    try testing.expect(std.mem.indexOf(u8, second, "hit") != null);
    try testing.expect(std.mem.indexOf(u8, second, &digest.text()) != null);
    try testing.expect(std.mem.indexOf(u8, second, "  (1 hit, 0 misses, ") != null);
}

var provenance_work: provenance_store.Work = undefined;
var first_record: provenance.Record = undefined;

/// The stored record of `digest`, copied into `into`.
fn stored_record(digest: Digest, into: *provenance.Record) !void {
    var errno: u16 = 0;
    _ = try provenance_store.load(&store, &provenance_work, digest, &errno);
    into.* = provenance_work.parsed;
}

test "build_image: a hit writes the same record but for its times, and a cache with none gets one" {
    // Goal: a record is a function of the build inputs and its times; an all-hit rebuild of an
    // unchanged project writes the same record apart from its times; a record from a cache a
    // release without provenance wrote (no record in the store) is complete. Method: build
    // (miss), read the record, build again (hit), read it, compare with the times set equal;
    // delete the record, build once more (a hit), and compare again.
    image_started("/etc");
    try context.build_image();
    const first = sim.stdout();
    const at = std.mem.indexOf(u8, first, "built b3:").?;
    const digest = Digest.parse(first[at + 6 ..][0..constants.store_digest_text_bytes]).?;
    try stored_record(digest, &first_record);
    try testing.expectEqual(@as(u32, 2), first_record.steps_count);
    try testing.expectEqual(@as(u32, 1), first_record.bases_count);
    try testing.expectEqualSlices(u8, &digest.bytes, &first_record.result);
    try testing.expect(first_record.finished >= first_record.started);
    sim.stdout_len = 0;
    try context.build_image();
    try stored_record(digest, &provenance_work.parsed);
    var again: provenance.Record = first_record;
    again.started = provenance_work.parsed.started;
    again.finished = provenance_work.parsed.finished;
    var left: [constants.statement_bytes_max]u8 = undefined;
    var right: [constants.statement_bytes_max]u8 = undefined;
    const kept = provenance.render(&left, &again);
    try testing.expectEqualStrings(kept, provenance.render(&right, &provenance_work.parsed));
    var path: @import("../store/fs.zig").PathBuf = undefined;
    try store.fs.unlink(provenance_store.record_path(&store, &path, digest));
    try testing.expect(!provenance_store.exists(&store, digest));
    try context.build_image();
    try stored_record(digest, &provenance_work.parsed);
    again.started = provenance_work.parsed.started;
    again.finished = provenance_work.parsed.finished;
    const rebuilt = provenance.render(&left, &again);
    try testing.expectEqualStrings(rebuilt, provenance.render(&right, &provenance_work.parsed));
}

test "build_image: a store full of provenance records skips the new one, and keeps replacing" {
    // Goal: the bound `trust_records_max` on provenance records, at the bound and one past it.
    // Method: build (one record), lower the bound to three and fill the directory to it: a
    // rebuild still replaces its record and says nothing. Delete the record and add one more
    // other record: the store is full, the rebuild succeeds, writes no record and prints the bound.
    image_started("/etc");
    try context.build_image();
    const first = sim.stdout();
    const at = std.mem.indexOf(u8, first, "built b3:").?;
    const digest = Digest.parse(first[at + 6 ..][0..constants.store_digest_text_bytes]).?;
    // The simulated disk cannot hold 4096 files, so the bound is lowered to three records.
    context.records_max = 3;
    defer context.records_max = constants.trust_records_max;
    var failure: @import("../store/fs.zig").Failure = undefined;
    var filler: Digest = .{ .bytes = @splat(0xee) };
    for (1..context.records_max) |number| {
        std.mem.writeInt(u32, filler.bytes[0..4], @intCast(number), .little);
        try provenance_store.save(&store, filler, "x", &failure);
    }
    var errno: u16 = 0;
    try testing.expectEqual(context.records_max, try provenance_store.count(&store, &errno));
    sim.stdout_len = 0;
    sim.stderr_len = 0;
    try context.build_image();
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    var path: @import("../store/fs.zig").PathBuf = undefined;
    try store.fs.unlink(provenance_store.record_path(&store, &path, digest));
    std.mem.writeInt(u32, filler.bytes[0..4], context.records_max, .little);
    try provenance_store.save(&store, filler, "x", &failure);
    sim.stdout_len = 0;
    try context.build_image();
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "built b3:") != null);
    try testing.expect(!provenance_store.exists(&store, digest));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-W0901") != null);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "trust_records_max") != null);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "require_provenance") != null);
}

test "build_image: adds that clash are E0807 naming both, reached through compose" {
    // Goal: the conflict's text from the whole path, not only from `assemble`. Method: both
    // steps' outputs added at /usr/bin; the second add refuses, naming the first.
    image_started("/usr/bin");
    try testing.expectError(error.Failed, context.build_image());
    try testing.expectEqual(.E0807, diag.code.?);
    const cause = diag.last_cause().?;
    try testing.expect(std.mem.indexOf(u8, cause, ".image.add compile -> /usr/bin has a") != null);
    const second = ".image.add notice -> /usr/bin brings a";
    try testing.expect(std.mem.indexOf(u8, cause, second) != null);
}

const images = @import("../store/images.zig");
const net_sim = @import("../registry/net_sim.zig");
const oci_digest = @import("../registry/digest.zig");
const test_registry = @import("../registry/test_registry.zig");

var registry: test_registry.TestRegistry = undefined;
var wire: net_sim.SimNet = undefined;

const locked_reference = test_registry.TestRegistry.reference(.open);

const registry_environment = [_]host_sim.EnvironmentVariable{
    .{ .name = "XDG_DATA_HOME", .value = "/data" },
};

/// A world whose network is the test registry, and whose lock names `locked_reference` as
/// `manifest` (an item of the fixture), with the store empty of it.
fn registry_started(manifest: []const u8) void {
    start();
    // The pull finds its store by the environment, so the store lives where the environment says.
    sim.environment_variables = &registry_environment;
    files.put_dir("/data/zbx", 0o755);
    support.make_store_directories(&files, "/data/zbx/store");
    store.at(sim.interface(), "/data/zbx/store");
    registry.init();
    wire.init(1, registry.responder());
    sim.wire = &wire;
    const parsed = oci_digest.Sha256.parse(manifest).?;
    composed.locking.lock.clear();
    composed.locking.lock.put(locked_reference, parsed, "linux/amd64", Digest.of("t")) catch {
        unreachable; // One entry fits.
    };
}

test "a locked base the store lacks is pulled by its manifest digest, and said so" {
    // Goal: `pull_locked` end to end on the simulated registry. Method: the lock names the
    // fixture's amd64 manifest; the store is empty; the base loads, the image record is there,
    // and one line names the base and the digest (on stdout in text, stderr under json).
    registry_started(&registry.fixture.oci.amd64.digest);
    const entry = try context.load_base(locked_reference, "compile");
    const want = oci_digest.Sha256.parse(&registry.fixture.oci.amd64.digest).?;
    try testing.expect(entry.manifest.eql(want));
    try testing.expect(composed.image.tree.bytes.len > 0);
    const line = sim.stdout();
    try testing.expect(std.mem.startsWith(u8, line, "pulling registry.test/fixture/open@sha256:"));
    try testing.expect(std.mem.indexOf(u8, line, &registry.fixture.oci.amd64.digest) != null);
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    // The record is in the store now: a second load pulls nothing.
    sim.stdout_len = 0;
    _ = try context.load_base(locked_reference, "compile");
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);

    registry_started(&registry.fixture.oci.amd64.digest);
    context.json = true;
    _ = try context.load_base(locked_reference, "compile");
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "pulling registry.test/fixture/open@"));
}

test "begin computes the key of an M7 step: the M9 fields are defaults, not garbage" {
    // Goal: `begin` fills every field of the key's spec. `var spec: Spec = undefined` applies no
    // defaults, so a missed M9 field is 0xAA and `compute` refuses it as too long (E0805 with an
    // empty variable name, which broke every M7 build). Method: begin a step with a run and one
    // input on a pulled base; it passes the key, misses the cache and starts a worker.
    registry_started(&registry.fixture.oci.amd64.digest);
    var buffer: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer, "{s}{s}{s}", .{
        ".{ .version = 1, .image = .{}, .steps = .{ .{ .name = \"compile\", .base = \"",
        locked_reference,
        "\", .inputs = .{\"a.txt\"}, .run = .{\"true\"} } } }\n",
    });
    var problem: file_mod.Problem = undefined;
    const parsed = file_mod.parse(text, &loaded.file, &problem);
    try testing.expectEqual(file_mod.ParseResult.parsed, parsed);
    files.put_dir("/p", 0o755);
    files.put_file("/p/a.txt", 0o644, "a\n");
    set_path(&loaded.project, "/p");
    set_path(&loaded.path, "/p/zbx.build.zon");
    const began = try context.begin(0);
    try testing.expect(began == .running);
    try testing.expect(diag.code == null);
}

test "a lock holding an index digest is E0804 naming both manifests, never an assertion" {
    // Goal: external input (zbx.lock) cannot panic a ReleaseSafe build. Method: the lock names
    // the fixture's index; the registry answers the pull with the platform's manifest, which
    // differs; the build is refused with the one-line cause.
    registry_started(&registry.fixture.oci.index.digest);
    try testing.expectError(error.Failed, context.load_base(locked_reference, "compile"));
    try testing.expectEqual(.E0804, diag.code.?);
    var expected: [256]u8 = undefined;
    const format = "locked base {s}: registry returned manifest {s}, lock says {s}";
    const head = std.fmt.bufPrint(&expected, format, .{
        locked_reference,
        registry.fixture.oci.amd64.digest[0..19],
        registry.fixture.oci.index.digest[0..19],
    }) catch unreachable; // Fits.
    try testing.expectEqualStrings(head, diag.last_cause().?);
}

test "a damaged result record is E0422 and a newer one E0423 that says to upgrade" {
    // Goal: finding 7, neither case is the "file too large" of a read that never happened.
    // Method: raise both and read the code, the cause and the fix.
    const digest = Digest.of("a result");
    const diagnose = @import("diagnose.zig");
    diag.reset();
    diagnose.result_unusable(&diag, digest, false);
    try testing.expectEqual(.E0422, diag.code.?);
    try testing.expect(std.mem.endsWith(u8, diag.last_cause().?, " is damaged"));
    diag.reset();
    diagnose.result_unusable(&diag, digest, true);
    try testing.expectEqual(.E0423, diag.code.?);
    try testing.expect(std.mem.endsWith(u8, diag.last_cause().?, "was written by a newer zbx"));
}

test "a network step's row ends with net, and a step without network has no marker" {
    // Goal: the report marks a step that ran with the network (the brief's `net`). Method: the
    // same settle as the clean exit, with the step's `network` set.
    start();
    loaded.file.steps[0].network = true;
    const answer = answer_of(made_output());
    try testing.expect(settle(worker_ended(0, 7, &answer), .{ .exited = 0 }).ok);
    try testing.expectEqualStrings("  compile   miss   0.00 s   net\n", sim.stdout());
    try testing.expect(composed.timings[0].network);
}

test "W0801 is printed once on stderr, naming the network steps, and never on stdout" {
    // Goal: a build with network steps warns before it runs them, once, in the mode asked; one
    // without says nothing. Method: set `network` on the steps of the example and render.
    start();
    context.warn_network();
    try testing.expectEqualStrings("", sim.stderr());
    loaded.file.steps[0].network = true;
    loaded.file.steps[1].network = true;
    context.warn_network();
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "warning[ZBX-W0801]: "));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "compile, notice") != null);
    try testing.expectEqualStrings("", sim.stdout());
    sim.stderr_len = 0;
    context.json = true;
    context.warn_network();
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "{\"code\":\"ZBX-W0801\""));
    try testing.expectEqualStrings("", sim.stdout());
}

test "a step with cache mounts ends its row with cache, and its JSON line says so" {
    // Goal: the report marks a step that has `.caches` (the brief's `cache`); additive in JSON.
    // Method: the same settle as the network marker, with the span's count set.
    start();
    loaded.file.steps[0].caches.count = 1;
    const answer = answer_of(made_output());
    try testing.expect(settle(worker_ended(0, 7, &answer), .{ .exited = 0 }).ok);
    try testing.expectEqualStrings("  compile   miss   0.00 s   cache\n", sim.stdout());
    try testing.expect(composed.timings[0].caches);
    start();
    loaded.file.steps[0].caches.count = 1;
    context.json = true;
    try testing.expect(settle(worker_ended(0, 7, &answer), .{ .exited = 0 }).ok);
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), ",\"caches\":true}") != null);
}

test "W0802 is printed once on stderr, naming the steps with caches, never on stdout" {
    // Goal: a build with cache mounts warns once; one without says nothing. Method: set the
    // count on a step of the example and render in both modes.
    start();
    context.warn_caches();
    try testing.expectEqualStrings("", sim.stderr());
    loaded.file.steps[1].caches.count = 1;
    context.warn_caches();
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "warning[ZBX-W0802]: "));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "notice") != null);
    try testing.expectEqualStrings("", sim.stdout());
    sim.stderr_len = 0;
    context.json = true;
    context.warn_caches();
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "{\"code\":\"ZBX-W0802\""));
    try testing.expectEqualStrings("", sim.stdout());
}

test "a bind from a step's output is selected from that output, and nothing matched is E0803" {
    // Goal: the bind's key part is the selection of `.source` in the earlier step's output.
    // Method: step "a"'s output is the sample tree; "b" binds a directory, then another, then
    // a path that is not there.
    start();
    const text =
        \\.{ .version = 1, .image = .{}, .steps = .{
        \\  .{ .name = "a", .base = "alpine:3.20", .run = .{"true"} },
        \\  .{ .name = "b", .base = "alpine:3.20", .run = .{"true"},
        \\    .binds = .{ .{ .from = "step:a", .source = "/etc", .to = "/t" } } },
        \\} }
    ;
    var problem: file_mod.Problem = undefined;
    const parsed = file_mod.parse(text, &loaded.file, &problem);
    try testing.expectEqual(file_mod.ParseResult.parsed, parsed);
    composed.outputs[0] = made_output();
    var spec: key_mod.Spec = undefined;
    try context.resolve_binds(1, &spec);
    try testing.expectEqual(@as(usize, 1), spec.binds.len);
    try testing.expectEqualStrings("/t", spec.binds[0].to);
    const first = spec.binds[0].source;
    try context.resolve_binds(1, &spec);
    try testing.expect(first.eql(spec.binds[0].source));
    const other = ".binds = .{ .{ .from = \"step:a\", .source = \"/bin\", .to = \"/t\" } }";
    const nothing = ".binds = .{ .{ .from = \"step:a\", .source = \"/nope\", .to = \"/t\" } }";
    inline for (.{ other, nothing }, 0..) |field, at| {
        var buffer: [512]u8 = undefined;
        const edited = try std.fmt.bufPrint(&buffer, "{s}{s}{s}", .{
            ".{ .version = 1, .image = .{}, .steps = .{ " ++
                ".{ .name = \"a\", .base = \"alpine:3.20\", .run = .{\"true\"} }, " ++
                ".{ .name = \"b\", .base = \"alpine:3.20\", .run = .{\"true\"}, ",
            field,
            " } } }",
        });
        const parsed = file_mod.parse(edited, &loaded.file, &problem);
        try testing.expectEqual(file_mod.ParseResult.parsed, parsed);
        if (at == 0) {
            try context.resolve_binds(1, &spec);
            try testing.expect(!first.eql(spec.binds[0].source));
        } else {
            try testing.expectError(error.Failed, context.resolve_binds(1, &spec));
            try testing.expectEqual(.E0803, diag.code.?);
        }
    }
}

var verify_workspace: verify.Workspace = undefined;

/// One step from its import to its cache entry, as the worker and then the parent do them, on the
/// simulated store. False when a crash (or any failure) stopped it somewhere on the way.
fn step_to_entry() bool {
    var result: import.Result = undefined;
    const options: import.Options = .{
        .squash_owner = false,
        .warn = null,
        .save_root = true,
        .keep_existing_root = true,
        .label = "build:compile",
    };
    import.import(&store, &import_workspace, "/src", options, &result, &diag) catch {
        diag.reset();
        return false;
    };
    diag.reset();
    const answer = answer_of(result.digest);
    const slot = worker_ended(0, 7, &answer);
    const ended = settle(slot, .{ .exited = 0 });
    diag.reset();
    context.row_failed = null;
    return ended.ok;
}

test "a step that dies at any write point, built again, gives the output of a clean build" {
    // Goal: the result digest depends on the inputs only, whatever crashed on the way (the
    // brief's "worker crashes"). Method: a clean step (import of /out, root, cache entry) counts
    // its write points; then for each point the machine dies there, the process starts again on
    // what the disk kept, and the step runs again on the same store. The entry must name the
    // clean build's tree, that tree must be whole, and `store verify` must find no damage.
    start();
    support.make_source(&files, 0);
    try testing.expect(step_to_entry());
    const clean = composed.outputs[0];
    const points = files.mutations;
    try testing.expect(points > 10);
    var crashed_runs: u32 = 0;
    for (0..points) |at| {
        start();
        support.make_source(&files, 0);
        files.faults.crash_mutation = @intCast(at);
        // A crash in the last, best-effort write (dropping the build's root) still ends the step
        // as done; every other one fails it. Either way the machine died.
        _ = step_to_entry();
        try testing.expect(files.crashed);
        crashed_runs += 1;
        // The process that starts again is another process: its temporary names (`tmp/<pid>-<n>`)
        // do not collide with what the dead one left.
        files.restart();
        sim.world.processes[0].pid += 1;
        store.at(sim.interface(), root_path);
        try testing.expect(step_to_entry());
        try testing.expect(composed.outputs[0].eql(clean));
        var failure: cache.Failure = undefined;
        const found = try cache.lookup(&store, &composed.cache, &composed.key, &failure);
        try testing.expect(found == .hit);
        try testing.expect(found.hit.eql(clean));
        var totals: verify.Totals = undefined;
        var verify_failure: verify.Failure = undefined;
        const arena = &import_workspace.arena;
        try verify.verify(&store, &verify_workspace, arena, &totals, &verify_failure);
        try testing.expectEqual(@as(u32, 0), totals.damaged);
    }
    try testing.expectEqual(@as(u32, @intCast(points)), crashed_runs);
}

test "a full disk during a step's output import is E0416, with no cache entry written" {
    // Goal: the demo document's claim for a full disk: the import of /out fails as ZBX-E0416
    // (no space), not as a generic write failure, and the step leaves no cache entry. Method:
    // the sim disk holds a few bytes only, the step's import runs, and the key is looked up.
    start();
    support.make_source(&files, 0);
    files.faults.bytes_max = files.bytes_live + 4;
    try testing.expect(!step_to_entry_keeping_diag());
    try testing.expectEqual(@as(?codes.Code, .E0416), diag.code);
    var failure: cache.Failure = undefined;
    const found = try cache.lookup(&store, &composed.cache, &composed.key, &failure);
    try testing.expect(found == .miss);
    diag.reset();
}

fn step_to_entry_keeping_diag() bool {
    var result: import.Result = undefined;
    const options: import.Options = .{
        .squash_owner = false,
        .warn = null,
        .save_root = true,
        .keep_existing_root = true,
        .label = "build:compile",
    };
    import.import(&store, &import_workspace, "/src", options, &result, &diag) catch return false;
    return true;
}

fn in_new_user_namespace(raw: *anyopaque) bool {
    const world: *host_sim.HostSim = @ptrCast(@alignCast(raw));
    return world.world.processes[world.world.current].new_user;
}

test "a step's inputs are imported inside the new user namespace, where chown to 0:0 is allowed" {
    // Goal: regression for the first live demo-m7 run, where the parent imported the inputs and
    // the real kernel refused `fchown(0, 0)` (EPERM) for an ordinary user. Method: the sim file
    // system refuses a change of owner from a process with no new user namespace; the inputs
    // of step 0 are imported through `input_job.import`. It fails if the import runs in the
    // parent (the old code), and passes when the namespace's child does it.
    start();
    files.put_dir("/p", 0o755);
    files.put_file("/p/go.mod", 0o644, "module x\n");
    files.put_file("/p/main.go", 0o644, "package main\n");
    set_path(&loaded.project, "/p");
    files.faults.owner_gate = .{ .context = &sim, .in_new_user_namespace = in_new_user_namespace };
    try testing.expect(!in_new_user_namespace(&sim)); // The parent has none.
    var input: input_tree.Workspace = undefined;
    var problem: inputs_mod.Problem = undefined;
    const request: input_job.Request = .{
        .host = sim.interface(),
        .facts = &facts,
        .store = &store,
        .loaded = &loaded,
        .step = 0,
        .ws = &input,
        .problem = &problem,
    };
    const first = try input_job.import(&request, &diag);
    try testing.expect(diag.code == null);
    // Each import is its own child: a second one gives the same tree.
    try testing.expect(first.eql(try input_job.import(&request, &diag)));
    try testing.expectEqual(@as(u32, 0), files.open_count());
}

test "--verbose reaches the step's request: verbose asks to stream, and nothing else does" {
    // Goal: the wiring from the flag to the step. The step's own streaming is tested in
    // step_tests.zig; this fails if `request` stops passing `verbose` on. Method: the request a
    // context makes with `verbose` set and cleared.
    start();
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
    context.verbose = true;
    try testing.expect(context.request(&spec).stream);
    context.verbose = false;
    try testing.expect(!context.request(&spec).stream);
}

test "a step whose base no policy trusts is refused before it starts, naming the step" {
    // Goal: the build gate. Method: with no policy file the base passes; a policy that requires
    // a signature refuses the unsigned base with E0905 naming the step and the base as
    // `zbx sign` takes it; a policy that asks nothing passes.
    registry_started(&registry.fixture.oci.amd64.digest);
    const config = [_]host_sim.EnvironmentVariable{
        .{ .name = "XDG_DATA_HOME", .value = "/data" },
        .{ .name = "XDG_CONFIG_HOME", .value = "/cfg" },
    };
    sim.environment_variables = &config;
    _ = try context.load_base(locked_reference, "compile");
    var spec: key_mod.Spec = undefined;
    spec.name = "compile";
    spec.binds = &.{};
    spec.copies = &.{};
    spec.base_tree = composed.image.tree;
    try context.check_base(locked_reference, &spec);
    files.put_dir("/cfg", 0o755);
    files.put_dir("/cfg/zbx", 0o755);
    files.put_file("/cfg/zbx/policy.zon", 0o644, ".{ .version = 1 }");
    context.gate_loaded = false;
    try context.check_base(locked_reference, &spec);
    files.remove_path("/cfg/zbx/policy.zon");
    files.put_file("/cfg/zbx/policy.zon", 0o644, ".{ .version = 1, .require_signature = true }");
    context.gate_loaded = false;
    try testing.expectError(error.Failed, context.check_base(locked_reference, &spec));
    try testing.expectEqual(.E0905, diag.code.?);
    const text = diag.whiles.slice()[0].slice();
    try testing.expect(std.mem.indexOf(u8, text, "base of step 'compile'") != null);
    const sign = "registry.test/fixture/open@sha256:";
    try testing.expect(std.mem.indexOf(u8, text, sign) != null);
    // The one-line form shows only the last cause, so that names the step too.
    const cause = diag.causes.slice()[diag.causes.count - 1].slice();
    try testing.expect(std.mem.indexOf(u8, cause, "the base of step 'compile'") != null);
}

test "a copy step makes its output with no worker, and an unmatched file never moves the key" {
    // Goal: `.copy` is built in the parent: a miss is recorded and reported as one, the same
    // step again is a hit, and a project file that no `.src` takes changes nothing. Method: copy
    // `a.txt` and begin; edit `other.txt` and begin again; edit `a.txt` and begin again.
    registry_started(&registry.fixture.oci.amd64.digest);
    var buffer: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer, "{s}{s}{s}", .{
        ".{ .version = 1, .image = .{}, .steps = .{ .{ .name = \"put\", .base = \"",
        locked_reference,
        "\", .copy = .{ .{ .src = .{\"a.txt\"}, .to = \"/opt/\" } } } } }\n",
    });
    var problem: file_mod.Problem = undefined;
    const parsed = file_mod.parse(text, &loaded.file, &problem);
    try testing.expectEqual(file_mod.ParseResult.parsed, parsed);
    files.put_dir("/p", 0o755);
    files.put_file("/p/a.txt", 0o644, "a\n");
    files.put_file("/p/other.txt", 0o644, "o\n");
    set_path(&loaded.project, "/p");
    set_path(&loaded.path, "/p/zbx.build.zon");
    try testing.expect(try context.begin(0) == .hit);
    try testing.expect(diag.code == null);
    try testing.expectEqual(@as(u32, 1), context.misses);
    const first = composed.outputs[0];
    files.remove_path("/p/other.txt");
    files.put_file("/p/other.txt", 0o644, "changed\n");
    try testing.expect(try context.begin(0) == .hit);
    try testing.expectEqual(@as(u32, 1), context.hits);
    try testing.expect(first.eql(composed.outputs[0]));
    files.remove_path("/p/a.txt");
    files.put_file("/p/a.txt", 0o644, "edited\n");
    try testing.expect(try context.begin(0) == .hit);
    try testing.expectEqual(@as(u32, 2), context.misses);
    try testing.expect(!first.eql(composed.outputs[0]));
}

test "a config user written as a name becomes its numbers, and an unknown name is E0817" {
    // Goal: the record of a result holds `uid:gid` only. Method: the sample tree's passwd names
    // root; `root` becomes `0:0`, a numeric user is left as written, `nobody` is refused.
    start();
    composed.record.tree = made_output();
    composed.record.config.clear();
    _ = composed.record.config.settings.set(.user, "root");
    try context.numeric_user();
    try testing.expectEqualStrings("0:0", composed.record.config.settings.get(.user));
    _ = composed.record.config.settings.set(.user, "5:6");
    try context.numeric_user();
    try testing.expectEqualStrings("5:6", composed.record.config.settings.get(.user));
    _ = composed.record.config.settings.set(.user, "nobody");
    try testing.expectError(error.Failed, context.numeric_user());
    try testing.expectEqual(codes.Code.E0817, diag.code.?);
}

fn copy_project_loaded() !void {
    registry_started(&registry.fixture.oci.amd64.digest);
    var buffer: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer, "{s}{s}{s}", .{
        ".{ .version = 1, .image = .{}, .steps = .{ .{ .name = \"put\", .base = \"",
        locked_reference,
        "\", .copy = .{ .{ .src = .{\"a.txt\"}, .to = \"/opt/\" } } } } }\n",
    });
    var problem: file_mod.Problem = undefined;
    const parsed = file_mod.parse(text, &loaded.file, &problem);
    try testing.expectEqual(file_mod.ParseResult.parsed, parsed);
    files.put_dir("/p", 0o755);
    files.put_file("/p/a.txt", 0o644, "a\n");
    set_path(&loaded.project, "/p");
    set_path(&loaded.path, "/p/zbx.build.zon");
}

fn import_entry(entry: ?u32) !Digest {
    var input: input_tree.Workspace = undefined;
    var problem: inputs_mod.Problem = undefined;
    const request: input_job.Request = .{
        .host = sim.interface(),
        .facts = &facts,
        .store = &store,
        .loaded = &loaded,
        .step = 0,
        .entry = entry,
        .ws = &input,
        .problem = &problem,
    };
    return input_job.import(&request, &diag);
}

test "a copy's project source is a root between the import and the selection" {
    // Goal: a concurrent `store gc` cannot remove the source tree a copy selects from. Method:
    // import entry 0 as `begin_copy` does and read the root record (named for the step, as a
    // step's output root is); an import that is no copy entry's makes none; a root the user
    // made first is kept as it was; a build that selects drops only the root it made.
    try copy_project_loaded();
    var text: [constants.store_source_bytes_max]u8 = undefined;
    const rootless = try import_entry(null);
    try testing.expect(root_source(rootless, &text) == null);
    const source = try import_entry(0);
    try testing.expect(!source.eql(rootless)); // The entry selects part of the project.
    try testing.expectEqualStrings("build:put", root_source(source, &text).?);
    var kept: roots.Root = undefined;
    var errno: u16 = 0;
    try roots.load(&store, source, &kept, &errno);
    kept.set_source("mine");
    var failure: @import("../store/fs.zig").Failure = undefined;
    try roots.save(&store, &kept, &failure);
    _ = try import_entry(0);
    try testing.expectEqualStrings("mine", root_source(source, &text).?);
    try testing.expect(diag.code == null);
}

test "a copy step leaves no root of its project source behind" {
    // Goal: the root is for the window only. Method: build the copy step as the test above's
    // file has it, then look for the source's root.
    try copy_project_loaded();
    try testing.expect(try context.begin(0) == .hit);
    try testing.expect(diag.code == null);
    var text: [constants.store_source_bytes_max]u8 = undefined;
    try testing.expect(root_source(try import_entry(null), &text) == null);
}

test "a copy source's root that cannot be written is one diagnostic, not a crash" {
    // Goal: the failure path of the root. Method: a full disk after the import's own writes is
    // hard to aim at, so the tree is imported once, and then the next write of the model fails:
    // the second import finds the tree and its first write is the root record's.
    try copy_project_loaded();
    _ = try import_entry(0);
    const source = try import_entry(0);
    var path: @import("../store/fs.zig").PathBuf = undefined;
    files.remove_path(store.root_record_path(&path, source));
    files.faults.fail_mutation = files.mutations;
    try testing.expectError(error.Failed, import_entry(0));
    try testing.expect(diag.code != null);
}

test "steps that share a cache id come one after another, each after the nearest holder" {
    // Goal: `sharing=locked`. Method: four steps in file order, three holding the id `go` (one
    // with a second id too) and one none; the plan gets an edge from each holder to the nearest
    // holder before it, none from the step without caches, and stays a valid order.
    const text =
        ".{ .version = 1, .image = .{}, .steps = .{\n" ++
        " .{ .name = \"a\", .base = \"b\", .run = .{\"x\"},\n" ++
        "   .caches = .{ .{ .id = \"go\", .path = \"/c\" } } },\n" ++
        " .{ .name = \"m\", .base = \"b\", .run = .{\"x\"} },\n" ++
        " .{ .name = \"b\", .base = \"b\", .run = .{\"x\"}, .caches = .{\n" ++
        "   .{ .id = \"go\", .path = \"/c\" }, .{ .id = \"npm\", .path = \"/n\" } } },\n" ++
        " .{ .name = \"c\", .base = \"b\", .run = .{\"x\"}, .caches = .{\n" ++
        "   .{ .id = \"npm\", .path = \"/n\" }, .{ .id = \"go\", .path = \"/c\" } } },\n" ++
        "} }\n";
    var problem: file_mod.Problem = undefined;
    const parsed = file_mod.parse(text, &loaded.file, &problem);
    try testing.expectEqual(file_mod.ParseResult.parsed, parsed);
    var plan: schedule.Plan = std.mem.zeroes(schedule.Plan);
    plan.count = 4;
    for (0..4) |at| plan.order[at] = @intCast(at);
    compose.cache_edges(&loaded.file, &plan);
    try testing.expectEqual(@as(usize, 0), plan.needs_of(0).len);
    try testing.expectEqual(@as(usize, 0), plan.needs_of(1).len);
    try testing.expectEqualSlices(u8, &.{0}, plan.needs_of(2));
    // `c` holds `npm` (last held by `b`) and `go` (also `b`): one edge, not two.
    try testing.expectEqualSlices(u8, &.{2}, plan.needs_of(3));
    try testing.expect(plan.valid());
}
