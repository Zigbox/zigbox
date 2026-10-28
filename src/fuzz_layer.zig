//! The `layer` fuzzer: `zig build fuzz -- layer`. A layer is an archive from a registry, which
//! is untrusted, and the applier writes files from it. Each iteration builds one or two layers
//! from a small alphabet of names, so that entries collide and replace one another: files,
//! directories, symlinks (to absolute paths and to `..`), hard links, whiteouts, opaque
//! directories, devices, and names that are absolute or climb with `..`. The layers may be
//! wrapped in gzip or zstd, and the bytes may be cut or flipped. Then the applier runs them on
//! the simulated file system and the properties are checked:
//!
//!   1. It never crashes, and a failure always names a reason.
//!   2. Nothing is created anywhere but the staging directory: the only other nodes are the ones
//!      the iteration made (`/outside` and the blob).
//!   3. Nothing is written through a symlink: the simulator takes a path as text, so it panics
//!      when asked about a path with a link above its last part (`forbid_link_above`), as a real
//!      file system would have followed the link.
//!   4. Success means the archive had no entry with an absolute name, a `..` in a name, or a
//!      hard link to an absolute or `..` path: those can never be applied.
//!   5. `/outside/secret` is unchanged.

const std = @import("std");
const assert = std.debug.assert;
const apply = @import("layer/apply.zig");
const builder = @import("testing/vm/layer_fixture.zig");
const fs_sim = @import("store/fs_sim.zig");
const reader_mod = @import("layer/reader.zig");

var files: fs_sim.SimFs = undefined;
var applier: apply.Applier = undefined;
var layer: reader_mod.Layer = undefined;
var tar_storage: [48 * 1024]u8 = undefined;
var wrapped: [64 * 1024]u8 = undefined;
var damaged: [64 * 1024]u8 = undefined;
var names: [24][160]u8 = undefined;
var links: [24][160]u8 = undefined;

const parts = [_][]const u8{
    "a",     "b",     "c",            "d",  "a", "b",
    ".wh.a", ".wh.b", ".wh..wh..opq", "..", ".", "evil",
};

/// A name of one to four parts. `hostile` allows `..` and a leading slash.
fn make_name(random: std.Random, out: *[160]u8, hostile: bool) []const u8 {
    var length: usize = 0;
    if (hostile and random.uintLessThan(u8, 8) == 0) {
        out[0] = '/';
        length = 1;
    }
    const count = random.intRangeAtMost(u8, 1, 4);
    for (0..count) |index| {
        var part = parts[random.uintLessThan(usize, parts.len)];
        if (!hostile and std.mem.eql(u8, part, "..")) part = "a";
        if (index > 0) {
            out[length] = '/';
            length += 1;
        }
        @memcpy(out[length..][0..part.len], part);
        length += part.len;
    }
    return out[0..length];
}

/// Whether a name has a part that climbs, or starts at the root.
fn is_hostile_name(name: []const u8) bool {
    if (name.len > 0 and name[0] == '/') return true;
    var split = std.mem.splitScalar(u8, name, '/');
    while (split.next()) |part| {
        if (std.mem.eql(u8, part, "..")) return true;
    }
    return false;
}

/// The last part of a name as the applier reads it, which skips empty and `.` parts: the last
/// part of `.wh.b/.wh.b/.` is `.wh.b`, so that entry is a whiteout.
fn last_part(name: []const u8) []const u8 {
    var last: []const u8 = "";
    var split = std.mem.splitScalar(u8, name, '/');
    while (split.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".")) continue;
        last = part;
    }
    return last;
}

const Made = struct { hostile: bool };

fn make_layer(random: std.Random, tar: *builder.Tar) Made {
    var made: Made = .{ .hostile = false };
    const hostile_allowed = random.uintLessThan(u8, 3) == 0;
    const count = random.intRangeAtMost(u8, 1, 12);
    for (0..count) |index| {
        const name = make_name(random, &names[index], hostile_allowed);
        const link = make_name(random, &links[index], hostile_allowed);
        const kind: builder.Kind = switch (random.uintLessThan(u8, 10)) {
            0, 1, 2, 3 => .file,
            4, 5 => .directory,
            6 => .symlink,
            7 => .hardlink,
            8 => .char_device,
            else => .fifo,
        };
        var entry: builder.Entry = .{
            .name = name,
            .kind = kind,
            .mode = random.intRangeAtMost(u32, 0, 0o7777),
            .uid = random.uintLessThan(u32, 3),
            .gid = random.uintLessThan(u32, 3),
            .data = if (kind == .file) "data" else "",
            .link = link,
        };
        if (kind == .symlink and random.boolean()) entry.link = "/outside";
        if (kind == .file and random.uintLessThan(u8, 6) == 0) {
            entry.xattrs = &.{.{ .name = "user.x", .value = "v" }};
        }
        if (is_hostile_name(name)) made.hostile = true;
        // A whiteout entry is never made, whatever its kind and link say.
        const whiteout = std.mem.startsWith(u8, last_part(name), ".wh.");
        if (kind == .hardlink and is_hostile_name(link) and !whiteout) made.hostile = true;
        tar.add(entry);
    }
    tar.finish();
    return made;
}

fn check_tree() void {
    var index: u32 = 0;
    while (files.alive_path(index)) |path| : (index += 1) {
        const ours = std.mem.startsWith(u8, path, "/stage") or
            std.mem.startsWith(u8, path, "/outside") or std.mem.eql(u8, path, "/layer");
        assert(ours);
        var slash: usize = 1;
        while (std.mem.indexOfScalarPos(u8, path, slash, '/')) |at| : (slash = at + 1) {
            const kind = files.kind_of(path[0..at]) orelse continue;
            assert(kind != .symlink);
        }
    }
    assert(std.mem.eql(u8, files.content_of("/outside/secret").?, "secret"));
}

pub fn fuzz_layer(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    files.init(seed);
    files.faults.forbid_link_above = true;
    files.put_dir("/stage", 0o755);
    files.put_dir("/outside", 0o755);
    files.put_file("/outside/secret", 0o600, "secret");
    applier.start(files.interface(), "/stage", random.uintLessThan(u8, 4) == 0);
    var hostile = false;
    var failed = false;
    var damaged_any = false;
    const layers = random.intRangeAtMost(u8, 1, 2);
    for (0..layers) |_| {
        var tar = builder.Tar.init(&tar_storage);
        hostile = make_layer(random, &tar).hostile or hostile;
        var blob: []const u8 = tar.bytes();
        switch (random.uintLessThan(u8, 3)) {
            0 => {},
            1 => blob = builder.gzip(&wrapped, blob),
            else => blob = builder.zstd(&wrapped, blob),
        }
        if (random.uintLessThan(u8, 5) == 0 and blob.len > 8) {
            @memcpy(damaged[0..blob.len], blob);
            damaged_any = true;
            damaged[random.uintLessThan(usize, blob.len)] ^= random.int(u8) | 1;
            const kept = if (random.boolean()) blob.len else random.uintLessThan(usize, blob.len);
            blob = damaged[0..kept];
        }
        if (files.kind_of("/layer") != null) files.remove_path("/layer");
        files.put_file("/layer", 0o644, blob);
        layer.start(files.interface(), "/layer") catch {
            failed = true;
            continue;
        };
        defer layer.close();
        applier.apply_layer(&layer) catch {
            assert(applier.failure.path_len <= apply.path_show_bytes);
            failed = true;
            break;
        };
    }
    check_tree();
    // A cut archive may end before its hostile entry; an intact one may not apply it.
    if (!failed and !damaged_any) assert(!hostile);
}

test "the layer fuzzer runs a few hundred seeds without a failed property" {
    // Goal: the properties hold on a spread of archives; `zig build fuzz -- layer` runs more.
    for (1..300) |seed| fuzz_layer(seed);
}
