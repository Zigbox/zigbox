//! The archive of `zbx state export` against the simulated file system: the tar inside the gzip
//! is read back with a reader written here, apart from the writer, and compared with the tree
//! that was exported: owners, modes, times, symlinks, hard links, long names, files left out,
//! and every way the export stops.

const std = @import("std");
const constants = @import("../constants.zig");
const host_sim = @import("../host_sim.zig");
const export_mod = @import("export.zig");
const fs_mod = @import("../store/fs.zig");
const fs_sim = @import("../store/fs_sim.zig");

const HostSim = host_sim.HostSim;
const SimFs = fs_sim.SimFs;
const testing = std.testing;
const flate = std.compress.flate;
const repeat = @import("../test_util.zig").repeat;

var workspace: export_mod.Workspace = undefined;
var files: SimFs = undefined;
var sim: HostSim = undefined;

const root = "/vol/data";
const mtime: u64 = 1_700_000_123;

const Entry = struct {
    name: []const u8,
    link: []const u8,
    kind: u8,
    uid: u32,
    gid: u32,
    mode: u32,
    mtime: u64,
    body: []const u8,
};

var name_storage: [64][300]u8 = undefined;

/// The name of the entry: the ustar prefix, a slash, and the name, or a GNU long name.
fn name_of(header: *const [512]u8, long: ?[]const u8, slot: usize) []const u8 {
    if (long) |text| return text;
    const prefix = std.mem.sliceTo(header[345..500], 0);
    const base = std.mem.sliceTo(header[0..100], 0);
    if (prefix.len == 0) return base;
    const format = "{s}/{s}";
    return std.fmt.bufPrint(&name_storage[slot], format, .{ prefix, base }) catch {
        unreachable; // A prefix of at most 155 bytes, a slash and a name of 100 fit 300.
    };
}

/// The entries of a tar in memory, with GNU long names and links applied. At most 64.
fn read_tar(tar: []const u8, out: []Entry) !usize {
    var at: usize = 0;
    var count: usize = 0;
    var long_name: ?[]const u8 = null;
    var long_link: ?[]const u8 = null;
    while (at + 512 <= tar.len) {
        const header = tar[at..][0..512];
        if (std.mem.allEqual(u8, header, 0)) break;
        const size = try std.fmt.parseInt(usize, std.mem.trim(u8, header[124..136], " \x00"), 8);
        const body = tar[at + 512 ..][0..size];
        at += 512 + std.mem.alignForward(usize, size, 512);
        var sum: usize = 0;
        for (header, 0..) |byte, index| sum += if (index >= 148 and index < 156) ' ' else byte;
        const stored = try std.fmt.parseInt(usize, std.mem.trim(u8, header[148..156], " \x00"), 8);
        try testing.expectEqual(sum, stored);
        switch (header[156]) {
            'L' => {
                long_name = body;
                continue;
            },
            'K' => {
                long_link = body;
                continue;
            },
            else => {},
        }
        const octal = struct {
            fn of(field: []const u8) !u64 {
                return std.fmt.parseInt(u64, std.mem.trim(u8, field, " \x00"), 8);
            }
        }.of;
        out[count] = .{
            .name = name_of(header, long_name, count),
            .link = long_link orelse std.mem.sliceTo(header[157..257], 0),
            .kind = header[156],
            .uid = @intCast(try octal(header[108..116])),
            .gid = @intCast(try octal(header[116..124])),
            .mode = @intCast(try octal(header[100..108])),
            .mtime = try octal(header[136..148]),
            .body = body,
        };
        long_name = null;
        long_link = null;
        count += 1;
    }
    return count;
}

fn gunzip(gz: []const u8, plain: []u8) ![]const u8 {
    var input: std.Io.Reader = .fixed(gz);
    var window: [flate.max_window_len]u8 = undefined;
    var decompress: flate.Decompress = .init(&input, .gzip, &window);
    var output = std.Io.Writer.fixed(plain);
    _ = try decompress.reader.streamRemaining(&output);
    return output.buffered();
}

fn owned(path: [:0]const u8, uid: u32, gid: u32, mode: u16) void {
    const attributes: fs_mod.PathAttributes = .{
        .mode = mode,
        .uid = uid,
        .gid = gid,
        .mtime = mtime,
    };
    files.interface().set_path_attributes(path, attributes) catch {
        unreachable; // The path was just made.
    };
}

const Counter = struct {
    seen: u32 = 0,
    fn call(context: *anyopaque, path: []const u8, kind: fs_mod.FileKind) void {
        const counter: *Counter = @ptrCast(@alignCast(context));
        counter.seen += 1;
        std.debug.assert(path.len > 0);
        std.debug.assert(kind == .fifo);
    }
};

fn build_volume() void {
    files.init(1);
    sim.init(1, &.{});
    sim.store_fs = &files;
    files.put_dir("/vol", 0o755);
    files.put_dir(root, 0o700);
    files.put_dir(root ++ "/base", 0o700);
    files.put_file(root ++ "/base/PG_VERSION", 0o600, "16\n");
    files.put_file(root ++ "/empty", 0o644, "");
    files.put_symlink(root ++ "/current", "base/PG_VERSION");
    files.put(root ++ "/pipe", .fifo, 0o600, .{ 0, 0 }, "");
    // A file of several blocks, and a path that does not fit a ustar header's name.
    var big: [70_000]u8 = undefined;
    for (&big, 0..) |*byte, index| byte.* = "abcdefghij\n"[index % 11];
    files.put_file(root ++ "/big", 0o640, &big);
    const deep = root ++ "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    files.put_dir(deep, 0o755);
    const middle = deep ++ "/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    files.put_dir(middle, 0o755);
    files.put_dir(middle ++ "/cccccccccccccccccccccccccccccccccccccccc", 0o755);
    files.put_file(middle ++ "/cccccccccccccccccccccccccccccccccccccccc/f", 0o644, "x");
    owned(root, 999, 999, 0o700);
    owned(root ++ "/base", 999, 999, 0o700);
    owned(root ++ "/base/PG_VERSION", 999, 999, 0o600);
    owned(root ++ "/big", 999, 998, 0o640);
    owned(root ++ "/current", 999, 999, 0o777);
}

fn export_to_stdout(
    counter: *Counter,
    totals: *export_mod.Totals,
    failure: *export_mod.Failure,
) !void {
    const skip: export_mod.Skip = .{ .context = counter, .call = Counter.call };
    sim.stdout_len = 0;
    try export_mod.write(
        files.interface(),
        &workspace,
        root,
        .{ .stdout = sim.interface() },
        skip,
        totals,
        failure,
    );
}

test "the archive holds the tree with its owners, modes, times, links and long names" {
    // Goal: what `tar -tzvf` shows is what the container sees. Method: a volume owned by 999
    // (as postgres has it) with a directory, a file, an empty file, a symlink, a hard link, a
    // file of several blocks, a path too long for a ustar name, and a fifo; export it, unzip
    // with std's decompressor, read the tar back, and compare entry by entry.
    build_volume();
    // Mark `PG_VERSION` and a second name for the same inode.
    files.interface().link(root ++ "/base/PG_VERSION", root ++ "/hard") catch {
        unreachable; // Both paths are the volume's own.
    };
    var counter: Counter = .{};
    var totals: export_mod.Totals = undefined;
    var failure: export_mod.Failure = undefined;
    try export_to_stdout(&counter, &totals, &failure);
    try testing.expectEqual(@as(u32, 1), counter.seen);
    try testing.expectEqual(@as(u64, 1), totals.skipped);
    try testing.expectEqual(@as(u64, 1), totals.symlinks);
    try testing.expectEqual(@as(u64, 1), totals.hard_links);
    // PG_VERSION (or its second name, which is a link), empty, big and f; and five directories.
    try testing.expectEqual(@as(u64, 4), totals.files);
    try testing.expectEqual(@as(u64, 5), totals.directories);
    const plain = try testing.allocator.alloc(u8, 4 * 1024 * 1024);
    defer testing.allocator.free(plain);
    const tar = try gunzip(sim.stdout(), plain);
    try testing.expect(tar.len % 512 == 0);
    try testing.expect(sim.stdout().len < tar.len / 4); // It is compressed.
    try testing.expectEqual(totals.archive_bytes, sim.stdout().len);
    var entries: [64]Entry = undefined;
    const count = try read_tar(tar, &entries);
    const list = entries[0..count];
    // The root first, as "./", with its owner and mode.
    try testing.expectEqualStrings("./", list[0].name);
    try testing.expectEqual(@as(u8, '5'), list[0].kind);
    try testing.expectEqual(@as(u32, 999), list[0].uid);
    try testing.expectEqual(@as(u32, 0o700), list[0].mode);
    try check_entries(list);
}

fn check_entries(list: []const Entry) !void {
    var seen_link = false;
    var seen_long = false;
    var names_of_inode: u32 = 0;
    var link_kinds: u32 = 0;
    var first_name: []const u8 = "";
    for (list) |entry| {
        const is_inode = std.mem.eql(u8, entry.name, "./base/PG_VERSION") or
            std.mem.eql(u8, entry.name, "./hard");
        if (is_inode) {
            names_of_inode += 1;
            if (entry.kind == '1') {
                link_kinds += 1;
                try testing.expectEqual(@as(usize, 0), entry.body.len);
            } else {
                first_name = entry.name;
                try testing.expectEqual(@as(u8, '0'), entry.kind);
                try testing.expectEqualStrings("16\n", entry.body);
            }
            try testing.expectEqual(@as(u32, 999), entry.uid);
            try testing.expectEqual(@as(u32, 999), entry.gid);
            try testing.expectEqual(@as(u32, 0o600), entry.mode);
            try testing.expectEqual(mtime, entry.mtime);
        }
        if (std.mem.eql(u8, entry.name, "./current")) {
            seen_link = true;
            try testing.expectEqual(@as(u8, '2'), entry.kind);
            try testing.expectEqualStrings("base/PG_VERSION", entry.link);
            try testing.expectEqual(@as(u32, 0o777), entry.mode);
        }
        if (std.mem.eql(u8, entry.name, "./big")) {
            try testing.expectEqual(@as(usize, 70_000), entry.body.len);
            try testing.expectEqual(@as(u32, 998), entry.gid);
            try testing.expectEqualStrings("abcdefghij\n", entry.body[0..11]);
        }
        if (entry.name.len > 100 and entry.kind == '0') {
            seen_long = true;
            try testing.expect(std.mem.endsWith(u8, entry.name, "/f"));
        }
        try testing.expect(!std.mem.endsWith(u8, entry.name, "pipe"));
    }
    // One name carries the bytes, the other links to it.
    try testing.expectEqual(@as(u32, 2), names_of_inode);
    try testing.expectEqual(@as(u32, 1), link_kinds);
    for (list) |entry| {
        if (entry.kind == '1') try testing.expectEqualStrings(first_name, entry.link);
    }
    try testing.expect(seen_link);
    try testing.expect(seen_long);
}

test "an export stops at an unreadable directory, a file that grows and a full output" {
    // Goal: every way an export ends early is a stop with a reason and no cut archive. Method:
    // a directory that cannot be read, a file that grows while it is read, a stdout that
    // fails; the stop and the path it names are checked.
    build_volume();
    files.set_unreadable(root ++ "/base");
    var counter: Counter = .{};
    var totals: export_mod.Totals = undefined;
    var failure: export_mod.Failure = undefined;
    try testing.expectError(error.Stopped, export_to_stdout(&counter, &totals, &failure));
    try testing.expectEqual(export_mod.Stop.unreadable, failure.stop);
    try testing.expectEqualStrings(root ++ "/base", failure.path);

    build_volume();
    files.faults.grow_on_open = true;
    try testing.expectError(error.Stopped, export_to_stdout(&counter, &totals, &failure));
    try testing.expectEqual(export_mod.Stop.changed, failure.stop);

    build_volume();
    sim.faults.write_error_per_mille = 1000;
    sim.faults.write_fault_stream = .stdout;
    try testing.expectError(error.Stopped, export_to_stdout(&counter, &totals, &failure));
    try testing.expectEqual(export_mod.Stop.write, failure.stop);
    try testing.expectEqual(@as(usize, 0), failure.path.len);
}

test "an owner a tar header cannot hold stops the export; the largest it holds is written" {
    // Goal: the bound of seven octal digits, at and past it. Method: one file owned by the
    // largest id, then one past.
    build_volume();
    owned(root ++ "/big", constants.state_export_id_max, 0, 0o640);
    var counter: Counter = .{};
    var totals: export_mod.Totals = undefined;
    var failure: export_mod.Failure = undefined;
    try export_to_stdout(&counter, &totals, &failure);
    const plain = try testing.allocator.alloc(u8, 4 * 1024 * 1024);
    defer testing.allocator.free(plain);
    var entries: [64]Entry = undefined;
    const count = try read_tar(try gunzip(sim.stdout(), plain), &entries);
    for (entries[0..count]) |entry| {
        if (std.mem.eql(u8, entry.name, "./big")) {
            try testing.expectEqual(constants.state_export_id_max, entry.uid);
        }
    }
    owned(root ++ "/big", constants.state_export_id_max + 1, 0, 0o640);
    try testing.expectError(error.Stopped, export_to_stdout(&counter, &totals, &failure));
    try testing.expectEqual(export_mod.Stop.owner_too_big, failure.stop);
}

test "a name or a link too long for a header is a GNU long record, read back whole" {
    // Goal: the paths a ustar name and prefix cannot hold (past 255 bytes) and a link target
    // past 100. Method: write the headers of a file, a hard link and a symlink with such
    // names into memory, and read them back.
    const long = "./" ++ repeat('d', 150) ++ "/" ++ repeat('e', 150) ++ "/file";
    const target = "./" ++ repeat('t', 130);
    var buffer: [16384]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    const stat: fs_mod.Stat = .{
        .kind = .file,
        .mode = 0o640,
        .uid = 7,
        .gid = 8,
        .size = 0,
        .inode = 5,
        .links = 2,
        .mtime = mtime,
    };
    try export_mod.write_header(&writer, .regular, long, "", &stat);
    try export_mod.write_header(&writer, .hard_link, long ++ "2", target, &stat);
    try export_mod.write_header(&writer, .symlink, "./s", target, &stat);
    try writer.splatByteAll(0, 1024);
    var entries: [8]Entry = undefined;
    const count = try read_tar(writer.buffered(), &entries);
    try testing.expectEqual(@as(usize, 3), count);
    try testing.expectEqualStrings(long, entries[0].name);
    try testing.expectEqual(@as(u8, '0'), entries[0].kind);
    try testing.expectEqualStrings(long ++ "2", entries[1].name);
    try testing.expectEqual(@as(u8, '1'), entries[1].kind);
    try testing.expectEqualStrings(target, entries[1].link);
    try testing.expectEqual(@as(u8, '2'), entries[2].kind);
    try testing.expectEqualStrings(target, entries[2].link);
    try testing.expectEqual(@as(u32, 7), entries[2].uid);
}
