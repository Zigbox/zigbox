//! Tests of the trust library (`peer.zig`) against the simulated store: the export and import
//! pair, and `prune_records` with its scan.

const std = @import("std");
const testing = std.testing;
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;
const host_sim = @import("../host_sim.zig");
const import = @import("../store/import.zig");
const layout = @import("../store/layout.zig");
const fs_sim = @import("../store/fs_sim.zig");
const support = @import("../store/test_support.zig");
const result = @import("../build/result.zig");
const sim_run = @import("../runtime/sim_run.zig");
const fs_mod = @import("../store/fs.zig");
const peer = @import("peer.zig");
const provenance = @import("provenance.zig");
const provenance_store = @import("provenance_store.zig");
const record = @import("record.zig");
const sign_commands = @import("sign_commands.zig");
const store_api = @import("../store/store.zig");
const Digest = @import("../store/digest.zig").Digest;

const home = [_]host_sim.EnvironmentVariable{.{ .name = "HOME", .value = "/home/alice" }};

var sim: *host_sim.HostSim = undefined;
var files: *fs_sim.SimFs = undefined;
var store: layout.Store = undefined;
// The two big workspaces live on the heap: the test binary's static data is near its limit.
var import_work: *import.Workspace = undefined;
var workspace: *sign_commands.Workspace = undefined;
var allocated = false;
var memory: *peer.Memory = undefined;
var prune_memory: *peer.PruneMemory = undefined;
var report: peer.Report = undefined;
var failure: peer.Failure = undefined;
var save_buffer: []u8 = undefined;
var bundle: []u8 = undefined;
var tree: Digest = undefined;

/// A store holding the sample tree `/src`, signed once by the key `ci`; the bundle is copied
/// to `bundle`, whose length is returned.
fn start() !usize {
    const heap = std.heap.page_allocator;
    import_work = heap.create(import.Workspace) catch return error.OutOfMemory;
    workspace = heap.create(sign_commands.Workspace) catch return error.OutOfMemory;
    defer heap.destroy(import_work);
    defer heap.destroy(workspace);
    if (!allocated) {
        sim = heap.create(host_sim.HostSim) catch return error.OutOfMemory;
        files = heap.create(fs_sim.SimFs) catch return error.OutOfMemory;
        memory = heap.create(peer.Memory) catch return error.OutOfMemory;
        prune_memory = heap.create(peer.PruneMemory) catch return error.OutOfMemory;
        const result_bytes = constants.build_result_bytes_max;
        save_buffer = heap.alloc(u8, result_bytes) catch return error.OutOfMemory;
        const bundle_bytes = constants.signature_record_bytes_max;
        bundle = heap.alloc(u8, bundle_bytes) catch return error.OutOfMemory;
        allocated = true;
    }
    sim.init(1, &.{});
    files.init(1);
    sim.store_fs = files;
    sim.environment_variables = &home;
    support.make_user_store(files, ".{\n    .format = 1,\n}\n");
    support.make_source(files, 0);
    store.at(sim.interface(), support.user_store);
    var diag: Diag = undefined;
    diag.reset();
    var made: import.Result = undefined;
    const options: import.Options = .{ .squash_owner = false, .warn = null };
    try import.import(&store, import_work, "/src", options, &made, &diag);
    tree = made.digest;
    const made_key = [_][:0]const u8{ "zbx", "key", "new", "ci", "--no-passphrase" };
    try testing.expectEqual(@as(u8, 0), sim_run.run_cli(sim, &made_key));
    const text = tree.text();
    const args: sign_commands.Args = .{ .operand = &text };
    const code = try sign_commands.run(sim.interface(), workspace, args, .{ .json = false }, &diag);
    try testing.expectEqual(@as(u8, 0), code);
    const bytes = try store_api.export_trust(&store, memory, tree, &failure);
    @memcpy(bundle[0..bytes.len], bytes);
    return bytes.len;
}

fn path_of(kind: peer.Kind, digest: Digest) [:0]const u8 {
    var path: fs_mod.PathBuf = undefined;
    const found = switch (kind) {
        .signature => record.record_path(&store, &path, digest),
        .provenance => provenance_store.record_path(&store, &path, digest),
    };
    return keep(found);
}

var kept_path: [constants.store_path_bytes_max + 1:0]u8 = undefined;

fn keep(text: [:0]const u8) [:0]const u8 {
    @memcpy(kept_path[0..text.len], text);
    kept_path[text.len] = 0;
    return kept_path[0..text.len :0];
}

fn stray(seed: u8) Digest {
    return Digest.of(&.{ seed, 0x5a });
}

/// A record file that holds nothing a parser would accept, named for `digest`.
fn put_junk(kind: peer.Kind, digest: Digest) void {
    if (kind == .provenance) {
        var directory: fs_mod.PathBuf = undefined;
        const made = store.directory_path(&directory, provenance_store.directory_name);
        if (files.kind_of(made) == null) files.put_dir(made, 0o755);
    }
    files.put_file(path_of(kind, digest), 0o644, "junk\n");
}

fn exists(kind: peer.Kind, digest: Digest) bool {
    return files.kind_of(path_of(kind, digest)) != null;
}

test "export then import into a store without the record gives the same bundle" {
    // Goal: the pair is inverse, and importing twice changes nothing. Method: sign, export,
    // delete the record, import the bundle, export again and compare; import once more.
    const length = try start();
    const exported = bundle[0..length];
    files.remove_path(path_of(.signature, tree));
    const first = try store_api.import_trust(&store, memory, exported, tree, &failure);
    try testing.expectEqual(@as(u32, 1), first.added);
    try testing.expectEqual(@as(u32, 1), first.total);
    const again = try store_api.export_trust(&store, memory, tree, &failure);
    try testing.expectEqualStrings(exported, again);
    const second = try store_api.import_trust(&store, memory, exported, tree, &failure);
    try testing.expectEqual(@as(u32, 0), second.added);
    try testing.expectEqual(@as(u32, 1), second.present);
}

test "an import of a bundle with any byte changed is refused whole and writes nothing" {
    // Goal: the peer property. Method: flip every byte in turn, with the record deleted; each
    // import is refused and the record stays absent.
    const length = try start();
    files.remove_path(path_of(.signature, tree));
    var flipped: [constants.signature_record_bytes_max]u8 = undefined;
    for (0..length) |at| {
        @memcpy(flipped[0..length], bundle[0..length]);
        flipped[at] ^= 1;
        const refused = store_api.import_trust(&store, memory, flipped[0..length], tree, &failure);
        try testing.expectError(error.Failed, refused);
        try testing.expect(failure.refusal == .malformed or failure.refusal == .newer);
        try testing.expect(!exists(.signature, tree));
    }
}

test "an import names the refusal: another tree, too long, none to export" {
    // Goal: each refusal reason of the pair. Method: one call each.
    const length = try start();
    const wrong = stray(1);
    const other = store_api.import_trust(&store, memory, bundle[0..length], wrong, &failure);
    try testing.expectError(error.Failed, other);
    try testing.expect(failure.refusal == .malformed);
    var long: [constants.signature_record_bytes_max + 1]u8 = undefined;
    @memset(&long, 'x');
    const refused = store_api.import_trust(&store, memory, &long, tree, &failure);
    try testing.expectError(error.Failed, refused);
    try testing.expect(failure.refusal == .too_large);
    try testing.expectEqual(@as(u64, long.len), failure.size);
    try testing.expectError(error.Failed, store_api.export_trust(&store, memory, wrong, &failure));
    try testing.expect(failure.refusal == .no_record);
}

test "a bundle's tree is its first statement's" {
    // Goal: `bundle_tree` finds the tree without a store. Method: the exported bundle.
    const length = try start();
    const found = try peer.bundle_tree(&memory.work, bundle[0..length]);
    try testing.expect(found.eql(tree));
    try testing.expectError(error.Malformed, peer.bundle_tree(&memory.work, "no newline"));
}

/// A result record committing to `committed` (which need not be in the store).
fn save_result(committed: Digest) !Digest {
    var saved: result.Record = undefined;
    saved.config.clear();
    saved.tree = committed;
    var made: result.Failure = undefined;
    return try result.save(&store, &saved, save_buffer, &made);
}

fn prune(apply: bool) !void {
    try store_api.prune_trust(&store, prune_memory, apply, &report, &failure);
}

test "prune lists orphans and removes nothing without apply; apply removes exactly them" {
    // Goal: the rules of "What is an orphan". Method: the signed tree's record (present), a
    // signature of an absent tree, a provenance of an absent result, one of a result whose tree
    // is absent, and one of a result whose tree is present (damaged: kept and reported).
    _ = try start();
    const gone_tree = stray(2);
    const gone_result = stray(3);
    const tree_gone_result = try save_result(stray(4));
    const live_result = try save_result(tree);
    put_junk(.signature, gone_tree);
    put_junk(.provenance, gone_result);
    put_junk(.provenance, tree_gone_result);
    put_junk(.provenance, live_result);
    const before = files.live_count();
    try prune(false);
    try testing.expectEqual(before, files.live_count());
    try testing.expectEqual(@as(u32, 3), report.orphans);
    try testing.expectEqual(@as(u32, 1), report.damaged);
    try testing.expectEqual(@as(u32, 1), report.kept);
    try testing.expectEqual(@as(u32, 0), report.removed);
    try prune(true);
    try testing.expectEqual(@as(u32, 3), report.removed);
    try testing.expect(!exists(.signature, gone_tree));
    try testing.expect(!exists(.provenance, gone_result));
    try testing.expect(!exists(.provenance, tree_gone_result));
    try testing.expect(exists(.provenance, live_result));
    try testing.expect(exists(.signature, tree));
    try prune(true);
    try testing.expectEqual(@as(u32, 0), report.orphans);
    try testing.expectEqual(@as(u32, 1), report.damaged);
}

test "prune keeps a damaged record of a present tree and removes a damaged one of an absent tree" {
    // Goal: the W0902 rule. Method: damage the signed tree's record, and add junk for a tree
    // that is not there.
    _ = try start();
    files.flip_byte(path_of(.signature, tree), 3);
    const absent = stray(5);
    put_junk(.signature, absent);
    try prune(true);
    try testing.expectEqual(@as(u32, 1), report.damaged);
    try testing.expectEqual(@as(u32, 1), report.removed);
    try testing.expect(exists(.signature, tree));
    try testing.expect(!exists(.signature, absent));
    const entry = report.list()[0];
    try testing.expect(entry.fate == .damaged and entry.kind == .signature);
}

/// The records a fresh run of the crash scenario holds: orphans and one present record.
const crash_orphans = 4;

fn crash_setup() !void {
    _ = try start();
    for (0..crash_orphans) |index| put_junk(.signature, stray(@intCast(10 + index)));
    for (0..crash_orphans) |index| put_junk(.provenance, stray(@intCast(20 + index)));
}

test "a crash at every prune unlink leaves each record present or gone, and a second run finishes" {
    // Goal: crash safety. Method: for each write point of an applied prune, crash there,
    // restart, prune again; then only the present tree's record is left.
    var point: u32 = 0;
    while (point < 64) : (point += 1) {
        try crash_setup();
        files.mutations = 0;
        files.faults.crash_mutation = point;
        const finished = !std.meta.isError(store_api.prune_trust(
            &store,
            prune_memory,
            true,
            &report,
            &failure,
        ));
        files.faults = .{};
        if (finished) {
            // The fault did not fire: every write point has been tried.
            try testing.expect(point >= crash_orphans * 2);
            return;
        }
        files.restart();
        try prune(true);
        try testing.expectEqual(report.orphans, report.removed);
        try prune(false);
        try testing.expectEqual(@as(u32, 0), report.orphans);
        for (0..crash_orphans) |index| {
            try testing.expect(!exists(.signature, stray(@intCast(10 + index))));
            try testing.expect(!exists(.provenance, stray(@intCast(20 + index))));
        }
        try testing.expect(exists(.signature, tree));
    }
    return error.TestUnexpectedResult;
}

test "prune reads at most the bound per directory and says so" {
    // Goal: the bound. Method: a lowered limit. With exactly `limit` names (the signed tree's
    // record and the rest orphans) every one is seen; one more is cut, and the report says so.
    _ = try start();
    const limit: u32 = 50;
    for (1..limit) |index| put_junk(.signature, Digest.of(std.mem.asBytes(&index)));
    var scanned: peer.ScanMemory = undefined;
    try peer.scan_limited(&store, &scanned, null, &report, limit, &failure);
    try testing.expect(!report.truncated);
    try testing.expectEqual(limit - 1, report.orphans);
    try testing.expectEqual(@as(u32, 1), report.kept);
    put_junk(.signature, Digest.of("one name too many"));
    try peer.scan_limited(&store, &scanned, null, &report, limit, &failure);
    try testing.expect(report.truncated);
    try testing.expectEqual(limit, report.orphans + report.kept);
}

var provenance_record: provenance.Record = undefined;
var provenance_bytes: [constants.statement_bytes_max]u8 = undefined;

/// A result of `committed`, told from the others of it by `index`.
fn save_labeled_result(committed: Digest, index: u32) !Digest {
    var saved: result.Record = undefined;
    saved.config.clear();
    var label: [16]u8 = undefined;
    const text = std.fmt.bufPrint(&label, "r{d}", .{index}) catch unreachable; // Short.
    _ = saved.config.add_label("label", text).?;
    saved.tree = committed;
    var made: result.Failure = undefined;
    return try result.save(&store, &saved, save_buffer, &made);
}

/// A provenance record a reader accepts, stored under `digest`.
fn put_sound_provenance(digest: Digest, committed: Digest) !void {
    const filled: provenance.Digest = @splat(0x5a);
    const made = &provenance_record;
    made.clear();
    made.tree = committed.bytes;
    made.result = digest.bytes;
    made.set_build_file("zbx.build.zon");
    made.build_file_digest = filled;
    made.set_version("0.4.0", "linux/amd64");
    made.image_key = filled;
    made.zbx = filled;
    const bytes = provenance.render(&provenance_bytes, made);
    var saving: fs_mod.Failure = undefined;
    try provenance_store.save(&store, digest, bytes, &saving);
}

/// One record of a random store, and whether the rules keep it.
const Planned = struct { kind: peer.Kind, digest: Digest, keeps: bool };

test "over random stores, prune removes exactly the records whose tree is gone, and only with apply" {
    // Goal: the brief's property. Method: 48 seeds; each store gets signature records of present
    // and absent trees, and provenance records (sound or damaged) of results that are present with
    // a present tree, present with an absent tree, or not there. Prune without apply changes
    // nothing and counts the orphans the rules name; with apply it removes exactly those.
    var seed: u64 = 0;
    while (seed < 48) : (seed += 1) {
        _ = try start();
        var prng = std.Random.DefaultPrng.init(seed);
        const random = prng.random();
        var plan: [16]Planned = undefined;
        var count: u32 = 0;
        var orphans: u32 = 0;
        const total = 1 + random.uintLessThan(u32, 12);
        while (count < total) : (count += 1) {
            const at: u8 = @intCast(count);
            if (random.boolean()) {
                // A signature record of an absent tree: a sound one needs the tree, so junk.
                const digest = stray(100 + at);
                put_junk(.signature, digest);
                plan[count] = .{ .kind = .signature, .digest = digest, .keeps = false };
                orphans += 1;
                continue;
            }
            const where = random.uintLessThan(u32, 3);
            const committed = if (where == 0) tree else stray(150 + at);
            const digest = if (where == 2) stray(200 + at) else try save_labeled_result(committed, at);
            const keeps = where == 0;
            if (random.boolean()) {
                try put_sound_provenance(digest, committed);
            } else {
                put_junk(.provenance, digest);
            }
            plan[count] = .{ .kind = .provenance, .digest = digest, .keeps = keeps };
            if (!keeps) orphans += 1;
        }
        const before = files.live_count();
        try prune(false);
        try testing.expectEqual(before, files.live_count());
        try testing.expectEqual(orphans, report.orphans);
        try testing.expectEqual(@as(u32, 0), report.removed);
        try prune(true);
        try testing.expectEqual(orphans, report.removed);
        for (plan[0..count]) |planned| {
            try testing.expectEqual(planned.keeps, exists(planned.kind, planned.digest));
        }
        try testing.expect(exists(.signature, tree));
        try prune(true);
        try testing.expectEqual(@as(u32, 0), report.orphans);
    }
}
