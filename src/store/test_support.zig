//! What the store's tests and fuzzers share: a check that a simulated store is whole, and a few
//! builders for source trees. Not part of `zbx`; the unit tests, the golden tests and the
//! `store` fuzzer import it.
//!
//! `check_whole` is the invariant the brief names: after any failure or crash, everything under
//! an id is what the id says it is. An object's name is the hash of its header, which holds its
//! content hash and its attributes, so it can be recomputed from the file and its stat. A
//! tree's name is the hash of its bytes. A chunk list matches its object. A root's tree exists.
//! Files in `tmp/` are not checked: they are not under an id.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const digest_mod = @import("digest.zig");
const fs_sim = @import("fs_sim.zig");
const object = @import("object.zig");
const roots = @import("roots.zig");
const tree = @import("tree.zig");
const xattrs = @import("xattrs.zig");

const Digest = digest_mod.Digest;
const SimFs = fs_sim.SimFs;

pub const Broken = error{Broken};

fn broken(comptime what: []const u8, path: []const u8) Broken {
    std.debug.print("store is not whole: {s}: {s}\n", .{ what, path });
    return error.Broken;
}

/// `name` is under `directory` (and not in a deeper one): the part after the slash, or null.
fn under(path: []const u8, directory: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, path, directory)) return null;
    if (path.len == directory.len) return null;
    if (path[directory.len] != '/') return null;
    return path[directory.len + 1 ..];
}

/// Every object, chunk list, tree and root under `root` is whole. `chunk_bytes` is the store's.
pub fn check_whole(sim: *const SimFs, root: []const u8, chunk_bytes: u32) Broken!void {
    var objects: [128]u8 = undefined;
    var trees_dir: [128]u8 = undefined;
    var roots_dir: [128]u8 = undefined;
    const objects_path = std.fmt.bufPrint(&objects, "{s}/objects", .{root}) catch
        unreachable; // Short.
    const trees_path = std.fmt.bufPrint(&trees_dir, "{s}/trees", .{root}) catch
        unreachable; // Short.
    const roots_path = std.fmt.bufPrint(&roots_dir, "{s}/roots", .{root}) catch
        unreachable; // Short.
    var index: u32 = 0;
    while (index < sim.count) : (index += 1) {
        const path = sim.alive_path(index) orelse continue;
        if (sim.kind_of(path).? != .file) continue;
        if (under(path, objects_path)) |rest| try check_object(sim, path, rest, chunk_bytes);
        if (under(path, trees_path)) |rest| try check_tree(sim, path, rest);
        if (under(path, roots_path)) |rest| try check_root(sim, path, rest, root);
    }
}

fn shard_name(rest: []const u8, suffix: []const u8) ?[64]u8 {
    // "ab/<62 hex>" plus the suffix.
    if (rest.len != 2 + 1 + 62 + suffix.len) return null;
    if (rest[2] != '/') return null;
    if (!std.mem.endsWith(u8, rest, suffix)) return null;
    var hex: [64]u8 = undefined;
    @memcpy(hex[0..2], rest[0..2]);
    @memcpy(hex[2..], rest[3..][0..62]);
    return hex;
}

fn check_object(
    sim: *const SimFs,
    path: []const u8,
    rest: []const u8,
    chunk_bytes: u32,
) Broken!void {
    if (std.mem.endsWith(u8, rest, ".chunks")) return check_chunks(sim, path, rest, chunk_bytes);
    const hex = shard_name(rest, "") orelse return broken("odd name", path);
    const named = Digest.from_hex(&hex) orelse return broken("not hex", path);
    const content = sim.content_of(path).?;
    const stat = sim.stat_of(path).?;
    const attrs: object.Attrs = .{
        .mode = stat.mode,
        .uid = stat.uid,
        .gid = stat.gid,
        .xattrs = sim.xattrs_of(path) orelse &xattrs.empty,
    };
    const id = object.object_id(Digest.of(content), attrs);
    if (!id.eql(named)) return broken("object does not hash to its name", path);
    if (sim.mtime_of(path).? != constants.store_mtime_seconds) return broken("mtime", path);
}

fn check_chunks(
    sim: *const SimFs,
    path: []const u8,
    rest: []const u8,
    chunk_bytes: u32,
) Broken!void {
    const hex = shard_name(rest, ".chunks") orelse return broken("odd name", path);
    var sibling: [constants.sim_fs_path_bytes_max]u8 = undefined;
    @memcpy(sibling[0 .. path.len - 7], path[0 .. path.len - 7]);
    const object_path = sibling[0 .. path.len - 7];
    _ = hex;
    const content = sim.content_of(object_path) orelse return; // The object may not exist yet.
    var chunks: [constants.store_chunks_max]Digest = undefined;
    var reader = object.Reader.init(chunk_bytes);
    if (content.len > 0) _ = reader.update(content, &chunks);
    _ = reader.finish(&chunks);
    const listed = sim.content_of(path).?;
    if (listed.len != reader.count * 32) return broken("chunk list length", path);
    for (0..reader.count) |at| {
        if (!std.mem.eql(u8, listed[at * 32 ..][0..32], &chunks[at].bytes)) {
            return broken("chunk hash", path);
        }
    }
}

fn check_tree(sim: *const SimFs, path: []const u8, rest: []const u8) Broken!void {
    const hex = shard_name(rest, "") orelse return broken("odd name", path);
    const named = Digest.from_hex(&hex) orelse return broken("not hex", path);
    const bytes = sim.content_of(path).?;
    if (!Digest.of(bytes).eql(named)) return broken("tree does not hash to its name", path);
    var decoder: tree.Decoder = undefined;
    decoder.init(bytes) catch return broken("tree does not decode", path);
    var entry: tree.Entry = undefined;
    while (decoder.next(&entry) catch return broken("tree does not decode", path)) {}
}

fn check_root(sim: *const SimFs, path: []const u8, rest: []const u8, root: []const u8) Broken!void {
    const named = Digest.from_hex(rest) orelse return broken("root name is not a digest", path);
    var record: roots.Root = undefined;
    if (roots.parse(sim.content_of(path).?, &record) != .ok) return broken("root record", path);
    var tree_path: [constants.sim_fs_path_bytes_max]u8 = undefined;
    const hex = named.hex();
    const where = std.fmt.bufPrint(
        &tree_path,
        "{s}/trees/{s}/{s}",
        .{ root, hex[0..2], hex[2..] },
    ) catch
        unreachable; // Short.
    if (sim.kind_of(where) == null) return broken("root without its tree", path);
}

/// How many files there are under `directory`, at any depth.
pub fn count_files(sim: *const SimFs, directory: []const u8) u32 {
    var count: u32 = 0;
    var index: u32 = 0;
    while (index < sim.count) : (index += 1) {
        const path = sim.alive_path(index) orelse continue;
        if (under(path, directory) == null) continue;
        if (sim.kind_of(path).? == .file) count += 1;
    }
    return count;
}

/// The bytes held by the files under `directory`.
pub fn bytes_under(sim: *const SimFs, directory: []const u8) u64 {
    var total: u64 = 0;
    var index: u32 = 0;
    while (index < sim.count) : (index += 1) {
        const path = sim.alive_path(index) orelse continue;
        if (under(path, directory) == null) continue;
        if (sim.kind_of(path).? == .file) total += sim.content_of(path).?.len;
    }
    return total;
}

/// The directories of a store, ready for an import (what `ensure_layout` makes).
pub fn make_store_directories(sim: *SimFs, root: []const u8) void {
    var path: [constants.sim_fs_path_bytes_max]u8 = undefined;
    sim.put_dir(root, 0o755);
    const names = [_][]const u8{ "objects", "trees", "roots", "cache", "trash", "tmp" };
    for (names) |name| {
        const where = std.fmt.bufPrint(&path, "{s}/{s}", .{ root, name }) catch
            unreachable; // Short.
        sim.put_dir(where, 0o755);
    }
}

/// A small root filesystem under `/src`: directories, files of several modes and owners, a
/// file with attributes, a symlink, an empty file and an empty directory. The order the nodes
/// are created in is `order`, which a test varies to show that it does not matter.
pub fn make_source(sim: *SimFs, order: u32) void {
    const Item = struct { path: []const u8, kind: u8, mode: u16, uid: u32, content: []const u8 };
    const items = [_]Item{
        .{ .path = "/src", .kind = 'd', .mode = 0o755, .uid = 0, .content = "" },
        .{ .path = "/src/bin", .kind = 'd', .mode = 0o755, .uid = 0, .content = "" },
        .{ .path = "/src/etc", .kind = 'd', .mode = 0o755, .uid = 0, .content = "" },
        .{ .path = "/src/empty", .kind = 'd', .mode = 0o700, .uid = 0, .content = "" },
        .{ .path = "/src/bin/sh", .kind = 'f', .mode = 0o755, .uid = 0, .content = "#!shell\n" },
        .{ .path = "/src/bin/ls", .kind = 'f', .mode = 0o755, .uid = 0, .content = "#!shell\n" },
        .{ .path = "/src/bin/su", .kind = 'f', .mode = 0o4755, .uid = 0, .content = "setuid\n" },
        .{
            .path = "/src/etc/passwd",
            .kind = 'f',
            .mode = 0o644,
            .uid = 0,
            .content = "root:x:0:0\n",
        },
        .{ .path = "/src/etc/shadow", .kind = 'f', .mode = 0o600, .uid = 5, .content = "root:!\n" },
        .{ .path = "/src/etc/empty", .kind = 'f', .mode = 0o644, .uid = 0, .content = "" },
        .{ .path = "/src/bin/busybox", .kind = 'l', .mode = 0o777, .uid = 0, .content = "sh" },
    };
    // Directories first, in an order that makes parents exist; then the rest in a rotation
    // that depends on `order`.
    for (items) |item| {
        if (item.kind == 'd') sim.put(item.path, .dir, item.mode, .{ item.uid, item.uid }, "");
    }
    var at: u32 = 0;
    while (at < items.len) : (at += 1) {
        const item = items[(at + order) % items.len];
        switch (item.kind) {
            'd' => {},
            'f' => sim.put(item.path, .file, item.mode, .{ item.uid, item.uid }, item.content),
            else => sim.put_symlink(item.path, item.content),
        }
    }
    sim.put_xattr("/src/bin/ls", "user.note", "listing");
    sim.put_xattr("/src/bin/su", "security.capability", "\x01\x00\x00\x02");
}

/// Makes `/deep` and `levels` directories below it, one inside the other.
pub fn make_chain(sim: *SimFs, levels: u32) void {
    var buffer: [constants.sim_fs_path_bytes_max]u8 = undefined;
    const base = "/deep";
    @memcpy(buffer[0..base.len], base);
    var length: usize = base.len;
    sim.put_dir(buffer[0..length], 0o755);
    for (0..levels) |_| {
        @memcpy(buffer[length..][0..2], "/d");
        length += 2;
        sim.put_dir(buffer[0..length], 0o755);
    }
}

/// The directories above a store at `/home/alice/.local/share/zbx/store`, the store's own
/// layout, and its `store.zon` with `format` as its text (null for none).
pub fn make_user_store(sim: *SimFs, format: ?[]const u8) void {
    const parents = [_][]const u8{
        "/home",
        "/home/alice",
        "/home/alice/.local",
        "/home/alice/.local/share",
        "/home/alice/.local/share/zbx",
    };
    for (parents) |parent| {
        if (sim.kind_of(parent) == null) sim.put_dir(parent, 0o755);
    }
    make_store_directories(sim, user_store);
    if (format) |text| sim.put_file(user_store ++ "/store.zon", 0o644, text);
}

pub const user_store = "/home/alice/.local/share/zbx/store";

/// Writes a tree object into a store made by `make_user_store`, under its digest.
pub fn put_tree_object(sim: *SimFs, bytes: []const u8) Digest {
    const digest = Digest.of(bytes);
    const hex = digest.hex();
    var path: [constants.sim_fs_path_bytes_max]u8 = undefined;
    const shard = std.fmt.bufPrint(&path, user_store ++ "/trees/{s}", .{hex[0..2]}) catch
        unreachable; // Short.
    if (sim.kind_of(shard) == null) sim.put_dir(shard, 0o755);
    const where = std.fmt.bufPrint(
        &path,
        user_store ++ "/trees/{s}/{s}",
        .{ hex[0..2], hex[2..] },
    ) catch
        unreachable; // Short.
    sim.put_file(where, 0o644, bytes);
    return digest;
}
