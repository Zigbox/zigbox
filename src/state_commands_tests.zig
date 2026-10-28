//! Tests of the `zbx state` commands through the command line, against the simulated host: what
//! `ls` shows (text and JSON, checked against the schema's required keys), `rm` to the trash
//! and `restore` back, and each refusal. The diagnostics' own text is in the golden tests.

const std = @import("std");
const cli = @import("cli.zig");
const constants = @import("constants.zig");
const host_sim = @import("host_sim.zig");
const schemas = @import("schemas.zig");
const sim_run = @import("runtime/sim_run.zig");
const fs_sim = @import("store/fs_sim.zig");
const run = @import("runtime/run.zig");
const volume = @import("state/volume.zig");
const lock = @import("state/lock.zig");
const Diag = @import("diag/diag.zig").Diag;

const testing = std.testing;

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var handle: run.Handle = undefined;

const root = sim_run.state_root;

fn start(seed: u64) void {
    sim_run.init(&sim, seed);
    sim_run.prepare_state(&sim, &files, &.{ "pgdata", "cache" });
}

/// Runs `zbx <args>` and returns the exit code; the output is in the simulator.
fn command(args: []const [:0]const u8) u8 {
    var items: [24][:0]const u8 = undefined;
    items[0] = "zbx";
    @memcpy(items[1 .. 1 + args.len], args);
    sim.stdout_len = 0;
    sim.stderr_len = 0;
    return sim_run.run_cli(&sim, items[0 .. 1 + args.len]);
}

fn contains(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}

fn parse_stdout() !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, testing.allocator, sim.stdout(), .{});
}

fn has_keys(object: std.json.ObjectMap, schema: []const u8, keys: []const []const u8) !void {
    for (keys) |key| {
        try testing.expect(contains(schema, key));
        if (object.get(key) == null) {
            std.debug.print("missing key {s}\n", .{key});
            return error.TestUnexpectedResult;
        }
    }
}

/// The container model starts again (it does not model a fresh /dev per run, so two runs need two
/// models); the state directory's file tree stays.
fn fresh_world(seed: u64) void {
    sim_run.init(&sim, seed);
    sim.store_fs = &files;
    sim.world.add_node(root ++ "/pgdata", .dir);
    sim.world.add_node(root ++ "/cache", .dir);
}

/// A run of `pg` that mounted `pgdata`, ended; the volume's files put in its data directory
/// (the container model and the file tree are separate in the simulator).
fn ran_pg() !void {
    const args = [_][:0]const u8{
        "run",     "--rootfs",                        sim_run.rootfs_path, "--name",  "pg",
        "--state", "pgdata:/var/lib/postgresql/data", "--",                "/bin/sh",
    };
    const code = command(&args);
    if (code != 0) std.debug.print("ran_pg: {s}\n", .{sim.stderr()});
    try testing.expectEqual(@as(u8, 0), code);
    files.put_dir(root ++ "/pgdata/data", 0o700);
    files.put_dir(root ++ "/pgdata/data/base", 0o700);
    files.set_owner_of(root ++ "/pgdata/data/base", 999, 999);
    const rows = @import("test_util.zig").repeat('r', 5000);
    files.put_file(root ++ "/pgdata/data/base/1", 0o600, rows);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "ls shows each volume: size, times, last container, and who uses it now" {
    // Goal: the listing the demo reads. Method: a run of pg ends, one of web holds `cache`;
    // `ls` in text and in JSON, the JSON against the schema.
    start(1);
    try ran_pg();
    fresh_world(11);
    sim.world.command_runs_ms = 3_600_000;
    var diag: Diag = undefined;
    diag.reset();
    const mounts = [_]volume.Mount{.{ .name = "cache", .target = "/cache", .read_only = true }};
    const container: run.Spec = .{
        .rootfs = sim_run.rootfs_path,
        .name = "web",
        .command = &.{"/bin/sh"},
        .state = &mounts,
    };
    run.start(sim.interface(), &container, .{ .detached = true }, &handle, &diag) catch |err| {
        var buffer: [constants.output_bytes_max]u8 = undefined;
        const render = @import("diag/render.zig");
        std.debug.print("{s}\n", .{render.render(&diag, .verbose, false, &buffer)});
        return err;
    };
    try testing.expectEqual(@as(u8, 0), command(&.{ "state", "ls" }));
    const out = sim.stdout();
    try testing.expect(contains(out, "NAME"));
    try testing.expect(contains(out, "pgdata"));
    try testing.expect(contains(out, "16.0 KiB")); // Two 4 KiB directories, an 8 KiB file.
    try testing.expect(contains(out, " pg "));
    try testing.expect(contains(out, "web (ro)"));
    try testing.expectEqual(@as(u8, 0), command(&.{ "--output", "json", "state", "ls" }));
    const parsed = try parse_stdout();
    defer parsed.deinit();
    const top = parsed.value.object;
    const schema = schemas.of("state-ls").?;
    try has_keys(top, schema, &.{ "schema", "directory", "volumes", "trash", "truncated" });
    try testing.expectEqualStrings("zbx.state.ls/1", top.get("schema").?.string);
    const volumes = top.get("volumes").?.array.items;
    try testing.expectEqual(@as(usize, 2), volumes.len);
    const cache = volumes[0].object;
    const pg = volumes[1].object;
    const keys = [_][]const u8{
        "name",      "bytes",          "disk_bytes", "files",          "record", "created",
        "last_used", "last_container", "last_path",  "last_read_only", "in_use", "used_by",
    };
    try has_keys(pg, schema, &keys);
    try testing.expectEqualStrings("pgdata", pg.get("name").?.string);
    try testing.expectEqual(@as(i64, 5000), pg.get("bytes").?.integer);
    try testing.expectEqual(@as(i64, 1), pg.get("files").?.integer);
    try testing.expectEqualStrings("pg", pg.get("last_container").?.string);
    try testing.expectEqualStrings("/var/lib/postgresql/data", pg.get("last_path").?.string);
    try testing.expect(!pg.get("in_use").?.bool);
    try testing.expect(cache.get("in_use").?.bool);
    const user = cache.get("used_by").?.array.items[0].object;
    try testing.expectEqualStrings("web", user.get("container").?.string);
    try testing.expect(user.get("read_only").?.bool);
    _ = run.wait(&handle);
}

test "rm moves a volume to the trash, ls lists it, and restore brings it back whole" {
    // Goal: nothing a user removes is lost at once. Method: rm, ls, restore, in JSON; the files
    // are the same afterwards, and the lock went with the volume and back.
    start(2);
    try ran_pg();
    try testing.expectEqual(@as(u8, 0), command(&.{ "--output", "json", "state", "rm", "pgdata" }));
    {
        const parsed = try parse_stdout();
        defer parsed.deinit();
        const keys = [_][]const u8{ "schema", "name", "entry", "removed", "expires", "emptied" };
        try has_keys(parsed.value.object, schemas.of("state-rm").?, &keys);
    }
    try testing.expect(files.kind_of(root ++ "/pgdata") == null);
    const entry = root ++ "/.trash/pgdata@1760000000";
    try testing.expect(files.kind_of(entry ++ "/data/base/1") != null);
    try testing.expectEqual(@as(u8, 0), command(&.{ "state", "ls" }));
    try testing.expect(contains(sim.stdout(), "trash: pgdata removed"));
    try testing.expect(contains(sim.stdout(), "restorable"));
    const restore = [_][:0]const u8{ "--output", "json", "state", "restore", "pgdata" };
    try testing.expectEqual(@as(u8, 0), command(&restore));
    {
        const parsed = try parse_stdout();
        defer parsed.deinit();
        const keys = [_][]const u8{ "schema", "name", "entry", "removed" };
        try has_keys(parsed.value.object, schemas.of("state-restore").?, &keys);
    }
    try testing.expect(files.kind_of(entry) == null);
    const back = files.content_of(root ++ "/pgdata/data/base/1").?;
    try testing.expectEqual(@as(usize, 5000), back.len);
    try testing.expectEqual(@as(u8, 0), command(&.{ "state", "rm", "pgdata" }));
    try testing.expect(contains(sim.stdout(), "zbx state restore pgdata brings it back"));
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "rm is refused while a run holds the volume, and a run is refused while rm holds it" {
    // Goal: a volume in use is never moved. Method: the lock held as a run holds it, then rm;
    // and a run started while rm holds it waits its half second and is refused.
    start(3);
    try ran_pg();
    var text: lock.HolderText = undefined;
    lock.holder_text(77, "pg", &text);
    const held = try lock.take(sim.interface(), root ++ "/pgdata/lock", .shared, &text, 0);
    try testing.expectEqual(@as(u8, 1), command(&.{ "state", "rm", "pgdata" }));
    try testing.expect(contains(sim.stderr(), "ZBX-E0706"));
    try testing.expect(files.kind_of(root ++ "/pgdata/data/base/1") != null);
    lock.release(sim.interface(), held);
    lock.holder_text(77, "zbx state rm", &text);
    const rm = try lock.take(sim.interface(), root ++ "/pgdata/lock", .exclusive, &text, 0);
    const args = [_][:0]const u8{
        "run", "--rootfs", sim_run.rootfs_path, "--state", "pgdata:/data", "--", "/bin/sh",
    };
    const before = sim.world.now_ms;
    try testing.expectEqual(@as(u8, 125), command(&args));
    try testing.expect(contains(sim.stderr(), "zbx state rm (process 77) holds the volume"));
    try testing.expectEqual(before + constants.state_lock_wait_ms, sim.world.now_ms);
    lock.release(sim.interface(), rm);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "rm and restore refuse a name that is not there, and restore one made again" {
    // Goal: the refusals, each with its code and nothing changed. Method: each case.
    start(4);
    try testing.expectEqual(@as(u8, 1), command(&.{ "state", "rm", "pgdata" }));
    try testing.expect(contains(sim.stderr(), "ZBX-E0707"));
    try testing.expectEqual(@as(u8, 1), command(&.{ "state", "rm", "Bad" }));
    try testing.expect(contains(sim.stderr(), "ZBX-E0705"));
    try testing.expectEqual(@as(u8, 1), command(&.{ "state", "restore", "pgdata" }));
    try testing.expect(contains(sim.stderr(), "ZBX-E0709"));
    try ran_pg();
    try testing.expectEqual(@as(u8, 0), command(&.{ "state", "rm", "pgdata" }));
    fresh_world(14);
    try ran_pg(); // The name made again.
    try testing.expectEqual(@as(u8, 1), command(&.{ "state", "restore", "pgdata" }));
    try testing.expect(contains(sim.stderr(), "ZBX-E0708"));
    try testing.expect(contains(sim.stderr(), "pgdata@1760000000"));
    try testing.expectEqual(@as(u8, 1), command(&.{ "state", "restore", "pgdata", "x" }));
    try testing.expect(contains(sim.stderr(), "ZBX-E0003"));
    try testing.expectEqual(@as(u8, 1), command(&.{ "state", "rm" }));
    try testing.expect(contains(sim.stderr(), "ZBX-E0006"));
    try testing.expectEqual(@as(u8, 1), command(&.{ "state", "drop", "pgdata" }));
    try testing.expect(contains(sim.stderr(), "ZBX-E0001"));
}

test "an expired trash is refused by restore and emptied by the next rm" {
    // Goal: the store's expiry, and nothing removed implicitly before it. Method: rm, the clock
    // moved past seven days, restore refused; another volume's rm empties the old entry.
    start(5);
    try ran_pg();
    try testing.expectEqual(@as(u8, 0), command(&.{ "state", "rm", "pgdata" }));
    sim.world.now += constants.store_trash_seconds - 1;
    try testing.expectEqual(@as(u8, 0), command(&.{ "state", "ls" }));
    try testing.expect(contains(sim.stdout(), "restorable"));
    sim.world.now += 1;
    try testing.expectEqual(@as(u8, 1), command(&.{ "state", "restore", "pgdata" }));
    try testing.expect(contains(sim.stderr(), "ZBX-E0710"));
    const entry = root ++ "/.trash/pgdata@1760000000";
    try testing.expect(files.kind_of(entry ++ "/data/base/1") != null);
    files.put_dir(root ++ "/cache", 0o755);
    try testing.expectEqual(@as(u8, 0), command(&.{ "--output", "json", "state", "rm", "cache" }));
    try testing.expect(contains(sim.stdout(), "\"emptied\":1"));
    try testing.expect(files.kind_of(entry) == null);
}

fn gunzip_member(gz: []const u8, name: []const u8, owner: u32) !?[]const u8 {
    const flate = std.compress.flate;
    const plain = try testing.allocator.alloc(u8, 1 << 20);
    defer testing.allocator.free(plain);
    var input: std.Io.Reader = .fixed(gz);
    var window: [flate.max_window_len]u8 = undefined;
    var decompress: flate.Decompress = .init(&input, .gzip, &window);
    var output = std.Io.Writer.fixed(plain);
    _ = try decompress.reader.streamRemaining(&output);
    const tar = output.buffered();
    var at: usize = 0;
    while (at + 512 <= tar.len) {
        const header = tar[at..][0..512];
        if (std.mem.allEqual(u8, header, 0)) break;
        const size_text = std.mem.trim(u8, header[124..136], " \x00");
        const size = try std.fmt.parseInt(usize, size_text, 8);
        const path = std.mem.sliceTo(header[0..100], 0);
        if (std.mem.eql(u8, path, name)) {
            // The owner as `tar -tzv` shows it, and the first bytes of the content.
            const uid = try std.fmt.parseInt(u32, std.mem.trim(u8, header[108..116], " \x00"), 8);
            try testing.expectEqual(owner, uid);
            const head = tar[at + 512 ..][0..@min(size, 8)];
            const copy: []const u8 = try testing.allocator.dupe(u8, head);
            return copy;
        }
        at += 512 + std.mem.alignForward(usize, size, 512);
    }
    return null;
}

test "export writes a gzip tar of the volume with the container's owners, to a file or stdout" {
    // Goal: the archive the demo lists with `tar -tzvf`. Method: a volume with a file owned by
    // 999; export to a file (text and JSON summary) and to stdout; read the archive back.
    start(7);
    try ran_pg();
    const out = "/home/alice/pgdata.tar.gz";
    try testing.expectEqual(@as(u8, 0), command(&.{ "state", "export", "pgdata", "-o", out }));
    try testing.expect(contains(sim.stdout(), "pgdata: exported 1 files"));
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    try testing.expect(files.kind_of(out ++ ".zbx-part") == null);
    const archive = files.content_of(out).?;
    try testing.expectEqual(@as(u8, 0x1f), archive[0]);
    const first = (try gunzip_member(archive, "./base/1", 0)).?;
    defer testing.allocator.free(first);
    try testing.expectEqualStrings("rrrrrrrr", first);
    const directory = (try gunzip_member(archive, "./base/", 999)).?;
    testing.allocator.free(directory);
    // JSON: the summary on stdout, the object checked against the schema.
    try testing.expectEqual(@as(u8, 0), command(&.{
        "--output", "json", "state", "export", "pgdata", "-o", out,
    }));
    var parsed = try parse_stdout();
    defer parsed.deinit();
    const keys = [_][]const u8{ "schema", "name", "file", "files", "bytes", "archive_bytes" };
    try has_keys(parsed.value.object, schemas.of("state-export").?, &keys);
    const schema = parsed.value.object.get("schema").?.string;
    try testing.expectEqualStrings("zbx.state.export/1", schema);
    // Standard output (not a terminal): only the archive.
    try testing.expectEqual(@as(u8, 0), command(&.{ "state", "export", "pgdata" }));
    try testing.expectEqual(@as(u8, 0x1f), sim.stdout()[0]);
    try testing.expectEqual(@as(u8, 0x8b), sim.stdout()[1]);
    try testing.expectEqualSlices(u8, archive[0..4], sim.stdout()[0..4]);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "export is refused while a run writes the volume, and shares it with readers" {
    // Goal: a consistent read. Method: the lock held exclusive, as a run holds it, then shared;
    // nothing is written when refused, the volume is as it was.
    start(8);
    try ran_pg();
    var text: lock.HolderText = undefined;
    lock.holder_text(77, "pg", &text);
    const writer = try lock.take(sim.interface(), root ++ "/pgdata/lock", .exclusive, &text, 0);
    const out = "/home/alice/pgdata.tar.gz";
    try testing.expectEqual(@as(u8, 1), command(&.{ "state", "export", "pgdata", "-o", out }));
    try testing.expect(contains(sim.stderr(), "ZBX-E0706"));
    try testing.expect(files.kind_of(out) == null);
    try testing.expect(files.kind_of(out ++ ".zbx-part") == null);
    lock.release(sim.interface(), writer);
    const reader = try lock.take(sim.interface(), root ++ "/pgdata/lock", .shared, &text, 0);
    try testing.expectEqual(@as(u8, 0), command(&.{ "state", "export", "pgdata", "-o", out }));
    lock.release(sim.interface(), reader);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "export refuses a missing volume, a full disk and bad words, leaving no file" {
    // Goal: each refusal is coded and leaves nothing. Method: a name that is not there (E0707),
    // a disk that takes no more (E0715, the part removed), `-o` on another command, a missing
    // name, and an extra one.
    start(9);
    try ran_pg();
    const out = "/home/alice/pgdata.tar.gz";
    try testing.expectEqual(@as(u8, 1), command(&.{ "state", "export", "nothing", "-o", out }));
    try testing.expect(contains(sim.stderr(), "ZBX-E0707"));
    try testing.expect(contains(sim.stderr(), "no state volume called nothing"));
    files.faults.bytes_max = 200;
    try testing.expectEqual(@as(u8, 2), command(&.{ "state", "export", "pgdata", "-o", out }));
    try testing.expect(contains(sim.stderr(), "ZBX-E0715"));
    files.faults.bytes_max = null;
    try testing.expect(files.kind_of(out) == null);
    try testing.expect(files.kind_of(out ++ ".zbx-part") == null);
    try testing.expectEqual(@as(u8, 1), command(&.{ "state", "ls", "-o", out }));
    try testing.expect(contains(sim.stderr(), "ZBX-E0004"));
    try testing.expectEqual(@as(u8, 1), command(&.{ "state", "export" }));
    try testing.expect(contains(sim.stderr(), "needs the name of the volume to export"));
    try testing.expectEqual(@as(u8, 1), command(&.{ "state", "export", "a", "b" }));
    try testing.expectEqual(@as(u8, 1), command(&.{ "state", "export", "a", "-o" }));
    const twice = [_][:0]const u8{ "state", "export", "a", "-o", "x", "-o", "y" };
    try testing.expectEqual(@as(u8, 1), command(&twice));
}
