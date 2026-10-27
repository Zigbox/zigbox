//! The simulated file system the store is tested against: an in-memory tree of directories,
//! files, symlinks and device nodes, with the faults a disk has and the one a machine has.
//!
//! What it models, because the store's rules depend on exactly these:
//!   - A parent directory must exist; `create` fails on an existing path; `rename` replaces its
//!     target; `unlink` and `remove_directory` are what they say; a directory lists in a random
//!     order, different on every call (a real file system's order is not sorted either).
//!   - A file's bytes are `data_len` long and `synced_len` of them are on the disk: `fsync`
//!     makes the two equal.
//!   - Every call that changes anything is a numbered write point. A crash at write point N
//!     applies nothing from N on and tears every file that has unsynced bytes: it keeps a
//!     random prefix of them, between `synced_len` and `data_len`. After a crash every call fails
//!     with `EIO` until `restart`, which is the process starting again on what is left. This is
//!     the store's version of TigerBeetle's VOPR: a test crashes at every write point and then
//!     checks that the store is unchanged or validly updated.
//!   - Faults without a crash: a call fails with an errno (`fail_mutation`), interrupted calls,
//!     short reads and writes, a read error, a disk that holds only so many bytes (ENOSPC).
//!
//! What it does not model: permissions (an `unreadable` flag stands for EACCES), time, and
//! directory entries that are lost in a crash (an entry is durable when its call returned; the
//! store flushes directories anyway, and a test of that would need a model of the file
//! system's journal).
//!
//! No allocation: every table is a fixed array, and the struct is large, so it is initialised in
//! place and kept in static storage by the tests.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host = @import("../host.zig");
const fs_mod = @import("fs.zig");
const xattrs = @import("xattrs.zig");

const Error = fs_mod.Error;
const Fd = fs_mod.Fd;
const FileKind = fs_mod.FileKind;

pub const errno_io: u16 = 5;
pub const errno_intr: u16 = 4;
pub const errno_acces: u16 = 13;
pub const errno_exist: u16 = 17;
pub const errno_noent: u16 = 2;
pub const errno_notdir: u16 = 20;
pub const errno_isdir: u16 = 21;
pub const errno_notempty: u16 = 39;
pub const errno_nospc: u16 = 28;
pub const errno_loop: u16 = 40;
pub const errno_inval: u16 = 22;
pub const errno_nodata: u16 = 61;
pub const errno_mlink: u16 = 31;

pub const Faults = struct {
    /// The call at this write point (zero-based) fails with `fail_errno`, and is not applied.
    fail_mutation: ?u32 = null,
    fail_errno: u16 = errno_io,
    /// The machine dies at this write point: it and everything after are not applied.
    crash_mutation: ?u32 = null,
    interrupt_per_mille: u16 = 0,
    short_write_per_mille: u16 = 0,
    short_read_per_mille: u16 = 0,
    read_error_per_mille: u16 = 0,
    /// The most bytes all files together may hold; null for no limit.
    bytes_max: ?u64 = null,
    /// A writer appends a byte to every file right after it is opened for reading: what a file
    /// that is being written to looks like to a program that read its size a moment before.
    grow_on_open: bool = false,
    /// The most names one inode may have; a `link` past it is `EMLINK` (ext4 allows 65000).
    link_max: ?u32 = null,
};

const Node = struct {
    path: [constants.sim_fs_path_bytes_max]u8,
    path_len: u16,
    alive: bool,
    kind: FileKind,
    mode: u16,
    uid: u32,
    gid: u32,
    /// Where the bytes are in the pool, how many, and how many are on the disk. A symlink's
    /// target is its data.
    data_at: u32,
    data_len: u32,
    synced_len: u32,
    xattr_at: u32,
    xattr_len: u32,
    mtime: u64,
    inode: u64,
    unreadable: bool,
    rdev_major: u32,
    rdev_minor: u32,

    fn text(node: *const Node) []const u8 {
        return node.path[0..node.path_len];
    }
};

const Open = struct {
    used: bool,
    node: u32,
    offset: u32,
    writable: bool,
};

pub const SimFs = struct {
    nodes: [constants.sim_fs_nodes_max]Node,
    count: u32,
    pool: [constants.sim_fs_pool_bytes_max]u8,
    pool_len: u32,
    opens: [constants.sim_fs_handles_max]Open,
    prng: std.Random.Xoshiro256,
    faults: Faults,
    /// Write points passed so far (the next one's index).
    mutations: u32,
    crashed: bool,
    errno_last: u16,
    next_inode: u64,
    /// Bytes held by live files now.
    bytes_live: u64,
    builder: xattrs.Builder,
    blob: [constants.store_xattr_blob_bytes_max]u8,

    /// Initialises in place. The tree is empty (the root exists and cannot be removed).
    pub fn init(sim: *SimFs, seed: u64) void {
        sim.count = 0;
        sim.pool_len = 0;
        sim.opens = @splat(.{ .used = false, .node = 0, .offset = 0, .writable = false });
        sim.prng = std.Random.Xoshiro256.init(seed);
        sim.faults = .{};
        sim.mutations = 0;
        sim.crashed = false;
        sim.errno_last = 0;
        sim.next_inode = 100;
        sim.bytes_live = 0;
        assert(sim.open_count() == 0);
        assert(sim.live_count() == 0);
    }

    pub fn interface(sim: *SimFs) fs_mod.Fs {
        return .{ .context = sim, .vtable = &vtable };
    }

    const vtable: fs_mod.VTable = .{
        .lstat = lstat,
        .read_dir = read_dir,
        .read_link = read_link,
        .list_xattrs = list_xattrs,
        .get_xattr = get_xattr,
        .open_read = open_read,
        .read = read,
        .create = create,
        .write = write,
        .fsync = fsync,
        .close = close,
        .set_owner = set_owner,
        .set_mode = set_mode,
        .set_xattr = set_xattr,
        .set_mtime = set_mtime,
        .rename = rename,
        .unlink = unlink,
        .make_directory = make_directory,
        .remove_directory = remove_directory,
        .sync_directory = sync_directory,
        .link = link,
        .symlink = symlink,
        .set_path_attributes = set_path_attributes,
        .set_path_xattr = set_path_xattr,
        .last_errno = last_errno,
    };

    // ---- Setting up a tree, and looking at it (tests only; no faults, no write points) ------

    pub fn open_count(sim: *const SimFs) u32 {
        var used: u32 = 0;
        for (sim.opens) |slot| {
            if (slot.used) used += 1;
        }
        return used;
    }

    pub fn live_count(sim: *const SimFs) u32 {
        var live: u32 = 0;
        for (sim.nodes[0..sim.count]) |*node| {
            if (node.alive) live += 1;
        }
        return live;
    }

    fn find(sim: *const SimFs, path: []const u8) ?u32 {
        for (sim.nodes[0..sim.count], 0..) |*node, index| {
            if (node.alive and std.mem.eql(u8, node.text(), path)) return @intCast(index);
        }
        return null;
    }

    /// The path of the node in slot `index`, or null if the slot is empty or dead. Tests walk the
    /// whole tree with it, from 0 to `count`.
    pub fn alive_path(sim: *const SimFs, index: u32) ?[]const u8 {
        if (index >= sim.count) return null;
        if (!sim.nodes[index].alive) return null;
        return sim.nodes[index].text();
    }

    /// The kind of the thing at `path`, or null.
    pub fn kind_of(sim: *const SimFs, path: []const u8) ?FileKind {
        const index = sim.find(path) orelse return null;
        return sim.nodes[index].kind;
    }

    /// The bytes of a file (or a symlink's target), or null if there is none.
    pub fn content_of(sim: *const SimFs, path: []const u8) ?[]const u8 {
        const index = sim.find(path) orelse return null;
        const node = &sim.nodes[index];
        return sim.pool[node.data_at..][0..node.data_len];
    }

    pub fn stat_of(sim: *const SimFs, path: []const u8) ?fs_mod.Stat {
        const index = sim.find(path) orelse return null;
        return sim.stat_node(index);
    }

    /// The canonical attribute section of a file (`xattrs.zig`), or null if it has none.
    pub fn xattrs_of(sim: *const SimFs, path: []const u8) ?[]const u8 {
        const index = sim.find(path) orelse return null;
        const node = &sim.nodes[index];
        if (node.xattr_len == 0) return null;
        return sim.pool[node.xattr_at..][0..node.xattr_len];
    }

    fn stat_node(sim: *const SimFs, index: u32) fs_mod.Stat {
        const node = &sim.nodes[index];
        return .{
            .kind = node.kind,
            .mode = node.mode,
            .uid = node.uid,
            .gid = node.gid,
            .size = if (node.kind == .dir) 0 else node.data_len,
            .inode = node.inode,
            .links = sim.links_of(node.inode),
            .rdev_major = node.rdev_major,
            .rdev_minor = node.rdev_minor,
        };
    }

    /// How many live names the inode has. A `link` makes a second node with the same inode and
    /// the same bytes; an object is never written after it is made, so the two cannot diverge.
    fn links_of(sim: *const SimFs, inode: u64) u32 {
        var count: u32 = 0;
        for (sim.nodes[0..sim.count]) |*node| {
            if (node.alive and node.inode == inode) count += 1;
        }
        assert(count > 0);
        return count;
    }

    /// Adds a node without a fault, creating nothing above it (the parent must exist). Panics on
    /// a programming error in the test: a duplicate, a missing parent, a full table.
    pub fn put(
        sim: *SimFs,
        path: []const u8,
        kind: FileKind,
        mode: u16,
        owner: [2]u32,
        content: []const u8,
    ) void {
        assert(path.len > 1);
        assert(sim.find(path) == null);
        assert(sim.parent_exists(path));
        const index = sim.allocate_node(path);
        const node = &sim.nodes[index];
        node.kind = kind;
        node.mode = mode;
        node.uid = owner[0];
        node.gid = owner[1];
        node.data_len = 0;
        node.synced_len = 0;
        node.data_at = sim.pool_len;
        sim.append(node, content);
        node.synced_len = node.data_len;
    }

    pub fn put_dir(sim: *SimFs, path: []const u8, mode: u16) void {
        sim.put(path, .dir, mode, .{ 0, 0 }, "");
    }

    pub fn put_file(sim: *SimFs, path: []const u8, mode: u16, content: []const u8) void {
        sim.put(path, .file, mode, .{ 0, 0 }, content);
    }

    pub fn put_symlink(sim: *SimFs, path: []const u8, target: []const u8) void {
        sim.put(path, .symlink, 0o777, .{ 0, 0 }, target);
    }

    /// Sets an attribute without a fault.
    pub fn put_xattr(sim: *SimFs, path: []const u8, name: []const u8, value: []const u8) void {
        const index = sim.find(path).?;
        sim.store_xattr(index, name, value) catch unreachable; // A test's attribute fits.
    }

    /// Gives a device node its numbers (a new one is 0/0).
    pub fn set_rdev(sim: *SimFs, path: []const u8, major: u32, minor: u32) void {
        const node = &sim.nodes[sim.find(path).?];
        node.rdev_major = major;
        node.rdev_minor = minor;
    }

    pub fn set_unreadable(sim: *SimFs, path: []const u8) void {
        sim.nodes[sim.find(path).?].unreadable = true;
    }

    pub fn set_owner_of(sim: *SimFs, path: []const u8, uid: u32, gid: u32) void {
        const node = &sim.nodes[sim.find(path).?];
        node.uid = uid;
        node.gid = gid;
    }

    pub fn remove_xattrs_of(sim: *SimFs, path: []const u8) void {
        sim.nodes[sim.find(path).?].xattr_len = 0;
    }

    /// Removes a node outright, as a test breaks the store on purpose.
    pub fn remove_path(sim: *SimFs, path: []const u8) void {
        sim.kill(sim.find(path).?);
    }

    pub fn set_mode_of(sim: *SimFs, path: []const u8, mode: u16) void {
        sim.nodes[sim.find(path).?].mode = mode;
    }

    pub fn set_mtime_of(sim: *SimFs, path: []const u8, seconds: u64) void {
        sim.nodes[sim.find(path).?].mtime = seconds;
    }

    pub fn mtime_of(sim: *const SimFs, path: []const u8) ?u64 {
        const index = sim.find(path) orelse return null;
        return sim.nodes[index].mtime;
    }

    fn parent_exists(sim: *const SimFs, path: []const u8) bool {
        const slash = std.mem.lastIndexOfScalar(u8, path, '/').?;
        if (slash == 0) return true;
        const index = sim.find(path[0..slash]) orelse return false;
        return sim.nodes[index].kind == .dir;
    }

    fn allocate_node(sim: *SimFs, path: []const u8) u32 {
        assert(path.len <= constants.sim_fs_path_bytes_max);
        var index: u32 = 0;
        while (index < sim.count and sim.nodes[index].alive) index += 1;
        if (index == sim.count) {
            assert(sim.count < constants.sim_fs_nodes_max); // The test outgrew the model.
            sim.count += 1;
        }
        const node = &sim.nodes[index];
        node.alive = true;
        @memcpy(node.path[0..path.len], path);
        node.path_len = @intCast(path.len);
        node.xattr_at = 0;
        node.xattr_len = 0;
        node.mtime = 0;
        node.unreadable = false;
        node.rdev_major = 0;
        node.rdev_minor = 0;
        node.uid = 0;
        node.gid = 0;
        node.mode = 0;
        node.data_at = sim.pool_len;
        node.data_len = 0;
        node.synced_len = 0;
        node.inode = sim.next_inode;
        sim.next_inode += 1;
        return index;
    }

    /// Appends to a node's data, moving it to the end of the pool first if it is not there.
    fn append(sim: *SimFs, node: *Node, bytes: []const u8) void {
        if (bytes.len == 0) return;
        const at_end = node.data_at + node.data_len == sim.pool_len;
        if (!at_end) {
            assert(sim.pool_len + node.data_len + bytes.len <= sim.pool.len);
            std.mem.copyForwards(
                u8,
                sim.pool[sim.pool_len..][0..node.data_len],
                sim.pool[node.data_at..][0..node.data_len],
            );
            node.data_at = sim.pool_len;
            sim.pool_len += node.data_len;
        }
        assert(sim.pool_len + bytes.len <= sim.pool.len); // The test outgrew the pool.
        @memcpy(sim.pool[sim.pool_len..][0..bytes.len], bytes);
        sim.pool_len += @intCast(bytes.len);
        node.data_len += @intCast(bytes.len);
        sim.bytes_live += bytes.len;
    }

    fn store_xattr(sim: *SimFs, index: u32, name: []const u8, value: []const u8) Error!void {
        try sim.rewrite_xattrs(index, name, .{ .name = name, .value = value });
    }

    /// Replaces the node's attribute section with its attributes but `drop`, and `add`.
    fn rewrite_xattrs(sim: *SimFs, index: u32, drop: []const u8, add: ?xattrs.Xattr) Error!void {
        const node = &sim.nodes[index];
        sim.builder.reset();
        if (node.xattr_len > 0) {
            var iterator = xattrs.Iterator.init(sim.pool[node.xattr_at..][0..node.xattr_len]);
            while (iterator.next()) |item| {
                if (std.mem.eql(u8, item.name, drop)) continue;
                sim.builder.add(item.name, item.value) catch return error.NoSpace;
            }
        }
        if (add) |item| sim.builder.add(item.name, item.value) catch return error.NoSpace;
        if (sim.builder.count == 0) {
            node.xattr_len = 0;
            return;
        }
        const section = sim.builder.finish(&sim.blob);
        if (sim.pool_len + section.len > sim.pool.len) return error.NoSpace;
        @memcpy(sim.pool[sim.pool_len..][0..section.len], section);
        node.xattr_at = sim.pool_len;
        node.xattr_len = @intCast(section.len);
        sim.pool_len += @intCast(section.len);
    }

    // ---- Faults ------------------------------------------------------------------------------

    fn fail(sim: *SimFs, errno: u16) Error {
        assert(errno != 0);
        sim.errno_last = errno;
        return host.error_for_errno(errno);
    }

    fn roll(sim: *SimFs, per_mille: u16) bool {
        if (per_mille == 0) return false;
        return sim.prng.random().uintLessThan(u16, 1000) < per_mille;
    }

    /// The start of every call: a dead machine answers nothing, and an interrupt may come.
    fn begin_call(sim: *SimFs) Error!void {
        sim.errno_last = 0;
        if (sim.crashed) return sim.fail(errno_io);
        if (sim.roll(sim.faults.interrupt_per_mille)) return sim.fail(errno_intr);
    }

    /// The start of a call that changes something: the numbered write point.
    fn begin_mutation(sim: *SimFs) Error!void {
        try sim.begin_call();
        const index = sim.mutations;
        sim.mutations += 1;
        if (sim.faults.crash_mutation) |at| {
            if (at == index) {
                sim.crash();
                return sim.fail(errno_io);
            }
        }
        if (sim.faults.fail_mutation) |at| {
            if (at == index) return sim.fail(sim.faults.fail_errno);
        }
    }

    /// The machine dies now: unsynced bytes are torn, and every open file is gone.
    fn crash(sim: *SimFs) void {
        sim.crashed = true;
        for (sim.nodes[0..sim.count]) |*node| {
            if (!node.alive or node.kind != .file) continue;
            if (node.data_len == node.synced_len) continue;
            const extra = node.data_len - node.synced_len;
            const kept = sim.prng.random().uintAtMost(u32, extra);
            sim.bytes_live -= extra - kept;
            node.data_len = node.synced_len + kept;
        }
    }

    /// The process starts again on what the disk kept.
    pub fn restart(sim: *SimFs) void {
        sim.crashed = false;
        sim.opens = @splat(.{ .used = false, .node = 0, .offset = 0, .writable = false });
        sim.errno_last = 0;
        sim.mutations = 0;
        sim.faults.crash_mutation = null;
        sim.faults.fail_mutation = null;
    }

    // ---- The vtable --------------------------------------------------------------------------

    fn from_context(context: *anyopaque) *SimFs {
        const sim: *SimFs = @ptrCast(@alignCast(context));
        assert(sim.count <= constants.sim_fs_nodes_max);
        return sim;
    }

    fn last_errno(context: *anyopaque) u16 {
        return from_context(context).errno_last;
    }

    fn lstat(context: *anyopaque, path: [:0]const u8) Error!fs_mod.Stat {
        const sim = from_context(context);
        try sim.begin_call();
        if (std.mem.eql(u8, path, "/")) {
            return .{
                .kind = .dir,
                .mode = 0o755,
                .uid = 0,
                .gid = 0,
                .size = 0,
                .inode = 2,
                .links = 1,
            };
        }
        const index = sim.find(path) orelse return sim.fail(errno_noent);
        return sim.stat_node(index);
    }

    fn read_dir(context: *anyopaque, path: [:0]const u8, visitor: fs_mod.Visitor) Error!void {
        const sim = from_context(context);
        try sim.begin_call();
        const is_root = std.mem.eql(u8, path, "/");
        if (!is_root) {
            const index = sim.find(path) orelse return sim.fail(errno_noent);
            if (sim.nodes[index].kind != .dir) return sim.fail(errno_notdir);
            if (sim.nodes[index].unreadable) return sim.fail(errno_acces);
        }
        var order: [constants.sim_fs_nodes_max]u32 = undefined;
        var count: u32 = 0;
        for (sim.nodes[0..sim.count], 0..) |*node, index| {
            if (!node.alive) continue;
            if (child_name(node.text(), path) == null) continue;
            order[count] = @intCast(index);
            count += 1;
        }
        sim.prng.random().shuffle(u32, order[0..count]);
        for (order[0..count]) |index| {
            const name = child_name(sim.nodes[index].text(), path).?;
            visitor.call(visitor.context, name);
        }
    }

    /// The name of `candidate` if it is directly inside `directory`, else null.
    fn child_name(candidate: []const u8, directory: []const u8) ?[]const u8 {
        assert(directory.len > 0);
        const base = if (std.mem.eql(u8, directory, "/")) "" else directory;
        if (candidate.len <= base.len + 1) return null;
        if (!std.mem.startsWith(u8, candidate, base)) return null;
        if (candidate[base.len] != '/') return null;
        const name = candidate[base.len + 1 ..];
        if (std.mem.indexOfScalar(u8, name, '/') != null) return null;
        return name;
    }

    fn read_link(context: *anyopaque, path: [:0]const u8, buffer: []u8) Error!u32 {
        const sim = from_context(context);
        try sim.begin_call();
        const index = sim.find(path) orelse return sim.fail(errno_noent);
        const node = &sim.nodes[index];
        if (node.kind != .symlink) return sim.fail(errno_inval);
        const length = @min(node.data_len, buffer.len);
        @memcpy(buffer[0..length], sim.pool[node.data_at..][0..length]);
        return length;
    }

    fn list_xattrs(context: *anyopaque, path: [:0]const u8, buffer: []u8) Error!u32 {
        const sim = from_context(context);
        try sim.begin_call();
        const index = sim.find(path) orelse return sim.fail(errno_noent);
        const node = &sim.nodes[index];
        if (node.xattr_len == 0) return 0;
        var iterator = xattrs.Iterator.init(sim.pool[node.xattr_at..][0..node.xattr_len]);
        var used: usize = 0;
        while (iterator.next()) |item| {
            if (used + item.name.len + 1 > buffer.len) return sim.fail(errno_range);
            @memcpy(buffer[used..][0..item.name.len], item.name);
            buffer[used + item.name.len] = 0;
            used += item.name.len + 1;
        }
        return @intCast(used);
    }

    const errno_range: u16 = 34;

    fn get_xattr(
        context: *anyopaque,
        path: [:0]const u8,
        name: [:0]const u8,
        buffer: []u8,
    ) Error!u32 {
        const sim = from_context(context);
        try sim.begin_call();
        const index = sim.find(path) orelse return sim.fail(errno_noent);
        const node = &sim.nodes[index];
        if (node.xattr_len == 0) return sim.fail(errno_nodata);
        var iterator = xattrs.Iterator.init(sim.pool[node.xattr_at..][0..node.xattr_len]);
        while (iterator.next()) |item| {
            if (!std.mem.eql(u8, item.name, name)) continue;
            if (item.value.len > buffer.len) return sim.fail(errno_range);
            @memcpy(buffer[0..item.value.len], item.value);
            return @intCast(item.value.len);
        }
        return sim.fail(errno_nodata);
    }

    fn take_slot(sim: *SimFs, node: u32, writable: bool) Error!Fd {
        for (&sim.opens, 0..) |*slot, index| {
            if (slot.used) continue;
            slot.* = .{ .used = true, .node = node, .offset = 0, .writable = writable };
            return @intCast(index);
        }
        return sim.fail(24); // EMFILE: the test leaks descriptors.
    }

    fn open_read(context: *anyopaque, path: [:0]const u8) Error!Fd {
        const sim = from_context(context);
        try sim.begin_call();
        const index = sim.find(path) orelse return sim.fail(errno_noent);
        const node = &sim.nodes[index];
        if (node.kind == .symlink) return sim.fail(errno_loop);
        if (node.kind == .dir) return sim.fail(errno_isdir);
        if (node.unreadable) return sim.fail(errno_acces);
        if (sim.faults.grow_on_open and node.kind == .file) sim.append(node, "+");
        return sim.take_slot(index, false);
    }

    fn slot_of(sim: *SimFs, fd: Fd) *Open {
        assert(fd < sim.opens.len);
        assert(sim.opens[fd].used);
        return &sim.opens[fd];
    }

    fn read(context: *anyopaque, fd: Fd, buffer: []u8) Error!u32 {
        const sim = from_context(context);
        try sim.begin_call();
        const slot = sim.slot_of(fd);
        const node = &sim.nodes[slot.node];
        if (sim.roll(sim.faults.read_error_per_mille)) return sim.fail(errno_io);
        const left = node.data_len - @min(slot.offset, node.data_len);
        var length: u32 = @intCast(@min(left, buffer.len));
        if (length > 1 and sim.roll(sim.faults.short_read_per_mille)) {
            length = sim.prng.random().intRangeAtMost(u32, 1, length - 1);
        }
        @memcpy(buffer[0..length], sim.pool[node.data_at + slot.offset ..][0..length]);
        slot.offset += length;
        return length;
    }

    fn create(context: *anyopaque, path: [:0]const u8, mode: u16) Error!Fd {
        const sim = from_context(context);
        try sim.begin_mutation();
        if (sim.find(path) != null) return sim.fail(errno_exist);
        if (!sim.parent_exists(path)) return sim.fail(errno_noent);
        if (path.len > constants.sim_fs_path_bytes_max) return sim.fail(36);
        const index = sim.allocate_node(path);
        const node = &sim.nodes[index];
        node.kind = .file;
        node.mode = mode;
        return sim.take_slot(index, true) catch |err| {
            node.alive = false;
            return err;
        };
    }

    fn write(context: *anyopaque, fd: Fd, bytes: []const u8) Error!u32 {
        const sim = from_context(context);
        try sim.begin_mutation();
        const slot = sim.slot_of(fd);
        assert(slot.writable);
        const node = &sim.nodes[slot.node];
        var length: usize = bytes.len;
        if (length > 1 and sim.roll(sim.faults.short_write_per_mille)) {
            length = sim.prng.random().intRangeAtMost(usize, 1, length - 1);
        }
        if (sim.faults.bytes_max) |limit| {
            const room = limit -| sim.bytes_live;
            if (room == 0) return sim.fail(errno_nospc);
            length = @min(length, room);
        }
        if (sim.pool_len + node.data_len + length > sim.pool.len) return sim.fail(errno_nospc);
        sim.append(node, bytes[0..length]);
        return @intCast(length);
    }

    fn fsync(context: *anyopaque, fd: Fd) Error!void {
        const sim = from_context(context);
        try sim.begin_mutation();
        const node = &sim.nodes[sim.slot_of(fd).node];
        node.synced_len = node.data_len;
    }

    fn close(context: *anyopaque, fd: Fd) void {
        const sim = from_context(context);
        sim.slot_of(fd).used = false;
    }

    fn set_owner(context: *anyopaque, fd: Fd, uid: u32, gid: u32) Error!void {
        const sim = from_context(context);
        try sim.begin_mutation();
        const node = &sim.nodes[sim.slot_of(fd).node];
        node.uid = uid;
        node.gid = gid;
        // A change of owner clears the file capability and the setuid and setgid bits, as the
        // kernel does; the other attributes stay.
        node.mode &= 0o1777;
        try sim.rewrite_xattrs(sim.slot_of(fd).node, "security.capability", null);
    }

    fn set_mode(context: *anyopaque, fd: Fd, mode: u16) Error!void {
        const sim = from_context(context);
        try sim.begin_mutation();
        sim.nodes[sim.slot_of(fd).node].mode = mode;
    }

    fn set_xattr(context: *anyopaque, fd: Fd, name: [:0]const u8, value: []const u8) Error!void {
        const sim = from_context(context);
        try sim.begin_mutation();
        try sim.store_xattr(sim.slot_of(fd).node, name, value);
    }

    fn set_mtime(context: *anyopaque, fd: Fd, seconds: u64) Error!void {
        const sim = from_context(context);
        try sim.begin_mutation();
        sim.nodes[sim.slot_of(fd).node].mtime = seconds;
    }

    fn rename(context: *anyopaque, from: [:0]const u8, to: [:0]const u8) Error!void {
        const sim = from_context(context);
        try sim.begin_mutation();
        const index = sim.find(from) orelse return sim.fail(errno_noent);
        if (!sim.parent_exists(to)) return sim.fail(errno_noent);
        if (to.len > constants.sim_fs_path_bytes_max) return sim.fail(36);
        if (sim.nodes[index].kind == .dir) return try sim.rename_directory(index, to);
        if (sim.find(to)) |target| {
            if (sim.nodes[target].kind == .dir) return sim.fail(errno_isdir);
            sim.kill(target);
        }
        const node = &sim.nodes[index];
        @memcpy(node.path[0..to.len], to);
        node.path_len = @intCast(to.len);
    }

    /// A directory moves with everything below it. The target must not exist: `rename(2)` would
    /// replace an empty directory, which the store never asks for.
    fn rename_directory(sim: *SimFs, index: u32, to: []const u8) Error!void {
        const from = sim.nodes[index].text();
        var old_path: [constants.sim_fs_path_bytes_max]u8 = undefined;
        @memcpy(old_path[0..from.len], from);
        const old = old_path[0..from.len];
        if (sim.find(to) != null) return sim.fail(errno_exist);
        if (std.mem.startsWith(u8, to, old) and to.len > old.len and to[old.len] == '/') {
            return sim.fail(errno_inval); // Into itself.
        }
        for (sim.nodes[0..sim.count]) |*node| {
            if (!node.alive) continue;
            if (!deeper(node.text(), old) and !std.mem.eql(u8, node.text(), old)) continue;
            const suffix = node.text()[old.len..];
            if (to.len + suffix.len > constants.sim_fs_path_bytes_max) return sim.fail(36);
            var moved: [constants.sim_fs_path_bytes_max]u8 = undefined;
            @memcpy(moved[0..to.len], to);
            @memcpy(moved[to.len..][0..suffix.len], suffix);
            @memcpy(node.path[0 .. to.len + suffix.len], moved[0 .. to.len + suffix.len]);
            node.path_len = @intCast(to.len + suffix.len);
        }
    }

    fn deeper(path: []const u8, directory: []const u8) bool {
        return path.len > directory.len and std.mem.startsWith(u8, path, directory) and
            path[directory.len] == '/';
    }

    fn kill(sim: *SimFs, index: u32) void {
        const node = &sim.nodes[index];
        assert(node.alive);
        node.alive = false;
        // The bytes go with the last name of the inode.
        var shared = false;
        for (sim.nodes[0..sim.count]) |*other| {
            if (other.alive and other.inode == node.inode) shared = true;
        }
        if (!shared) sim.bytes_live -= node.data_len;
    }

    fn unlink(context: *anyopaque, path: [:0]const u8) Error!void {
        const sim = from_context(context);
        try sim.begin_mutation();
        const index = sim.find(path) orelse return sim.fail(errno_noent);
        if (sim.nodes[index].kind == .dir) return sim.fail(errno_isdir);
        sim.kill(index);
    }

    fn make_directory(context: *anyopaque, path: [:0]const u8, exist_ok: bool) Error!void {
        const sim = from_context(context);
        try sim.begin_mutation();
        if (sim.find(path)) |existing| {
            if (exist_ok and sim.nodes[existing].kind == .dir) return;
            return sim.fail(errno_exist);
        }
        if (!sim.parent_exists(path)) return sim.fail(errno_noent);
        if (path.len > constants.sim_fs_path_bytes_max) return sim.fail(36);
        const index = sim.allocate_node(path);
        sim.nodes[index].kind = .dir;
        sim.nodes[index].mode = 0o755;
    }

    fn remove_directory(context: *anyopaque, path: [:0]const u8) Error!void {
        const sim = from_context(context);
        try sim.begin_mutation();
        const index = sim.find(path) orelse return sim.fail(errno_noent);
        if (sim.nodes[index].kind != .dir) return sim.fail(errno_notdir);
        for (sim.nodes[0..sim.count]) |*node| {
            if (node.alive and child_name(node.text(), path) != null) {
                return sim.fail(errno_notempty);
            }
        }
        sim.kill(index);
    }

    fn link(context: *anyopaque, from: [:0]const u8, to: [:0]const u8) Error!void {
        const sim = from_context(context);
        try sim.begin_mutation();
        const index = sim.find(from) orelse return sim.fail(errno_noent);
        const is_dir = sim.nodes[index].kind == .dir;
        if (is_dir) return sim.fail(1); // EPERM: no hard link to a directory.
        if (sim.find(to) != null) return sim.fail(errno_exist);
        if (!sim.parent_exists(to)) return sim.fail(errno_noent);
        if (to.len > constants.sim_fs_path_bytes_max) return sim.fail(36);
        if (sim.faults.link_max) |limit| {
            if (sim.links_of(sim.nodes[index].inode) >= limit) return sim.fail(errno_mlink);
        }
        const source = sim.nodes[index];
        const made = sim.allocate_node(to);
        const node = &sim.nodes[made];
        const path_len = node.path_len;
        var path: [constants.sim_fs_path_bytes_max]u8 = undefined;
        @memcpy(path[0..path_len], node.path[0..path_len]);
        node.* = source; // The same inode, bytes, owner, mode and attributes.
        @memcpy(node.path[0..path_len], path[0..path_len]);
        node.path_len = path_len;
    }

    fn symlink(context: *anyopaque, target: [:0]const u8, path: [:0]const u8) Error!void {
        const sim = from_context(context);
        try sim.begin_mutation();
        if (sim.find(path) != null) return sim.fail(errno_exist);
        if (!sim.parent_exists(path)) return sim.fail(errno_noent);
        if (path.len > constants.sim_fs_path_bytes_max) return sim.fail(36);
        const index = sim.allocate_node(path);
        const node = &sim.nodes[index];
        node.kind = .symlink;
        node.mode = 0o777;
        sim.append(node, target);
        node.synced_len = node.data_len;
    }

    fn set_path_attributes(
        context: *anyopaque,
        path: [:0]const u8,
        attributes: fs_mod.PathAttributes,
    ) Error!void {
        const sim = from_context(context);
        try sim.begin_mutation();
        const index = sim.find(path) orelse return sim.fail(errno_noent);
        const inode = sim.nodes[index].inode;
        // Every name of the inode shows the change, as in a real file system.
        for (sim.nodes[0..sim.count]) |*node| {
            if (!node.alive or node.inode != inode) continue;
            node.uid = attributes.uid;
            node.gid = attributes.gid;
            if (attributes.mode) |mode| node.mode = mode;
            node.mtime = attributes.mtime;
        }
    }

    fn set_path_xattr(
        context: *anyopaque,
        path: [:0]const u8,
        name: [:0]const u8,
        value: []const u8,
    ) Error!void {
        const sim = from_context(context);
        try sim.begin_mutation();
        const index = sim.find(path) orelse return sim.fail(errno_noent);
        try sim.store_xattr(index, name, value);
    }

    fn sync_directory(context: *anyopaque, path: [:0]const u8) Error!void {
        const sim = from_context(context);
        try sim.begin_mutation();
        if (std.mem.eql(u8, path, "/")) return;
        const index = sim.find(path) orelse return sim.fail(errno_noent);
        if (sim.nodes[index].kind != .dir) return sim.fail(errno_notdir);
    }
};

const testing = std.testing;

var test_sim: SimFs = undefined;

const Collector = struct {
    names: [16][32]u8 = undefined,
    lens: [16]u8 = undefined,
    count: u32 = 0,

    fn visit(context: *anyopaque, entry: []const u8) void {
        const collector: *Collector = @ptrCast(@alignCast(context));
        @memcpy(collector.names[collector.count][0..entry.len], entry);
        collector.lens[collector.count] = @intCast(entry.len);
        collector.count += 1;
    }

    fn visitor(collector: *Collector) fs_mod.Visitor {
        return .{ .context = collector, .call = visit };
    }

    fn name(collector: *const Collector, index: u32) []const u8 {
        return collector.names[index][0..collector.lens[index]];
    }

    fn has(collector: *const Collector, wanted: []const u8) bool {
        for (0..collector.count) |index| {
            if (std.mem.eql(u8, collector.name(@intCast(index)), wanted)) return true;
        }
        return false;
    }
};

test "a file written and renamed is there, with its bytes, and the old name is not" {
    // Goal: the model's basic rules. Method: create, write, flush, rename; stat both names.
    const sim = &test_sim;
    sim.init(1);
    sim.put_dir("/d", 0o755);
    const fs = sim.interface();
    const fd = try fs.create("/d/a.tmp", 0o600);
    try fs.write_all(fd, "hello");
    try fs.fsync(fd);
    fs.close(fd);
    try fs.rename("/d/a.tmp", "/d/a");
    try testing.expectEqual(error.NotFound, fs.lstat("/d/a.tmp") catch |err| err);
    try testing.expectEqual(@as(u64, 5), (try fs.lstat("/d/a")).size);
    var buffer: [8]u8 = undefined;
    const bytes = try fs.read_whole("/d/a", &buffer);
    try testing.expectEqualStrings("hello", bytes);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
    try testing.expectError(error.IoFailed, fs.create("/d/a", 0o600));
    try testing.expectEqual(errno_exist, fs.last_errno());
}

test "a directory lists in a different order on different calls" {
    // Goal: nothing above the file system may depend on its order. Method: ten names listed
    // repeatedly; the set is always the same and more than one order is seen.
    const sim = &test_sim;
    sim.init(7);
    sim.put_dir("/d", 0o755);
    const names = [_][]const u8{ "a", "b", "c", "d", "e", "f", "g", "h", "i", "j" };
    for (names) |name| {
        var path: [8]u8 = undefined;
        sim.put_file(try std.fmt.bufPrint(&path, "/d/{s}", .{name}), 0o644, "");
    }
    var first: Collector = .{};
    try sim.interface().read_dir("/d", first.visitor());
    var differs = false;
    for (0..8) |_| {
        var again: Collector = .{};
        try sim.interface().read_dir("/d", again.visitor());
        try testing.expectEqual(@as(u32, 10), again.count);
        for (names) |name| try testing.expect(again.has(name));
        for (0..10) |index| {
            if (!std.mem.eql(u8, first.name(@intCast(index)), again.name(@intCast(index)))) {
                differs = true;
            }
        }
    }
    try testing.expect(differs);
}

test "a crash tears unsynced bytes and keeps synced ones, and nothing works until restart" {
    // Goal: the crash model. Method: write 8 bytes, flush, write 8 more, crash at the next write
    // point; the file keeps between 8 and 16 bytes, calls fail, and restart brings it back.
    const sim = &test_sim;
    sim.init(3);
    sim.put_dir("/d", 0o755);
    const fs = sim.interface();
    const fd = try fs.create("/d/f", 0o600);
    try fs.write_all(fd, "01234567");
    try fs.fsync(fd);
    try fs.write_all(fd, "89abcdef");
    sim.faults.crash_mutation = sim.mutations;
    try testing.expectError(error.IoFailed, fs.fsync(fd));
    try testing.expect(sim.crashed);
    try testing.expectError(error.IoFailed, fs.lstat("/d/f"));
    sim.restart();
    const kept = (try fs.lstat("/d/f")).size;
    try testing.expect(kept >= 8 and kept <= 16);
    try testing.expectEqualStrings("01234567", sim.content_of("/d/f").?[0..8]);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "a full disk lets part of a write through, then refuses" {
    // Goal: ENOSPC arrives after a short write, as on a real disk. Method: room for 6 bytes.
    const sim = &test_sim;
    sim.init(3);
    sim.put_dir("/d", 0o755);
    sim.faults.bytes_max = 6;
    const fs = sim.interface();
    const fd = try fs.create("/d/f", 0o600);
    defer fs.close(fd);
    try testing.expectError(error.NoSpace, fs.write_all(fd, "0123456789"));
    try testing.expectEqual(@as(u16, errno_nospc), fs.last_errno());
    try testing.expectEqual(@as(u64, 6), (try fs.lstat("/d/f")).size);
}

test "attributes: listed, read, and cleared by a change of owner as the kernel does" {
    // Goal: xattrs round-trip through the model and chown drops the capability.
    const sim = &test_sim;
    sim.init(3);
    sim.put_dir("/d", 0o755);
    sim.put_file("/d/f", 0o755, "x");
    sim.put_xattr("/d/f", "user.b", "2");
    sim.put_xattr("/d/f", "user.a", "1");
    const fs = sim.interface();
    var names: [64]u8 = undefined;
    const listed = try fs.list_xattrs("/d/f", &names);
    try testing.expectEqualStrings("user.a\x00user.b\x00", listed);
    var value: [8]u8 = undefined;
    try testing.expectEqualStrings("2", try fs.get_xattr("/d/f", "user.b", &value));
    try testing.expectError(error.NoData, fs.get_xattr("/d/f", "user.c", &value));
    const fd = try fs.create("/d/g", 0o4755);
    defer fs.close(fd);
    try fs.set_xattr(fd, "security.capability", "\x01");
    try fs.set_xattr(fd, "user.keep", "k");
    try fs.set_owner(fd, 5, 6);
    var kept = xattrs.Iterator.init(sim.xattrs_of("/d/g").?);
    try testing.expectEqualStrings("user.keep", kept.next().?.name);
    try testing.expect(kept.next() == null);
    try testing.expectEqual(@as(u16, 0o755), sim.stat_of("/d/g").?.mode);
}
