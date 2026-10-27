//! Where things are in the store, and the store itself as a value: `Store` holds the host, the
//! file system, the store's directory and a few counters. The caller owns it (no module-level
//! state), so two stores in one process share nothing.
//!
//!   <root>/store.zon                  the format version
//!   <root>/objects/ab/<62 hex>        a file object (the file itself, with its real attributes)
//!   <root>/objects/ab/<62 hex>.chunks the hashes of its chunks, only for a file longer than one
//!   <root>/trees/ab/<62 hex>          a tree object (the encoding of `tree.zig`)
//!   <root>/roots/<64 hex>             a root record: why the tree is kept
//!   <root>/cache/                     materialized trees (slice 2)
//!   <root>/trash/                     what gc removed, until it expires (slice 4)
//!   <root>/tmp/<pid>-<n>              files being written; a crash leaves them here
//!
//! The root is `$XDG_DATA_HOME/zbx/store`, or `~/.local/share/zbx/store`. `ab` is the first byte
//! of the id in hex, so no directory holds more than a 256th of the objects. Everything in it is
//! written by zbx, from inside the user's namespace (`namespace.zig`).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const digest_mod = @import("digest.zig");
const fs_mod = @import("fs.zig");

const Digest = digest_mod.Digest;
const Fs = fs_mod.Fs;
const Host = host_mod.Host;
const PathBuf = fs_mod.PathBuf;

pub const store_suffix = "/zbx/store";
pub const subdirectories = [_][]const u8{ "objects", "trees", "roots", "cache", "trash", "tmp" };
pub const format_file = "store.zon";
pub const chunks_suffix = ".chunks";

pub const Store = struct {
    host: Host,
    fs: Fs,
    /// The store's directory, NUL-terminated at `root_len`.
    root: [constants.store_data_base_bytes_max + store_suffix.len + 1]u8,
    root_len: u32,
    /// Bytes of `root` that must already exist (the data directory's parent: HOME or
    /// XDG_DATA_HOME); directories are made from there on.
    existing_len: u32,
    /// The bytes a chunk covers. Always `constants.store_chunk_bytes` in a program; a test sets
    /// a small one to have multi-chunk objects without megabytes.
    chunk_bytes: u32,
    tmp_counter: u32,
    /// What this process has written, for the message of a write that fails halfway.
    objects_written: u64,
    bytes_written: u64,

    /// Fills `store` from the environment. False if neither XDG_DATA_HOME nor HOME gives an
    /// absolute directory that fits.
    pub fn locate(store: *Store, host: Host) bool {
        assert(constants.store_data_base_bytes_max + store_suffix.len < store.root.len);
        assert(@intFromPtr(host.vtable) != 0);
        const limit: u32 = constants.store_data_base_bytes_max;
        var base: []const u8 = "";
        var from_home = false;
        if (host.environment("XDG_DATA_HOME", limit)) |data| {
            if (data.len > 0 and data[0] == '/') base = data;
        }
        var home: []const u8 = "";
        if (base.len == 0) {
            const found = host.environment("HOME", limit - "/.local/share".len) orelse
                return false;
            if (found.len == 0 or found[0] != '/') return false;
            home = std.mem.trimEnd(u8, found, "/");
            from_home = true;
        }
        const joined = if (from_home)
            std.fmt.bufPrint(&store.root, "{s}/.local/share{s}", .{ home, store_suffix })
        else
            std.fmt.bufPrint(
                &store.root,
                "{s}{s}",
                .{ std.mem.trimEnd(u8, base, "/"), store_suffix },
            );
        const text = joined catch return false;
        store.root_len = @intCast(text.len);
        store.root[store.root_len] = 0;
        store.existing_len = if (from_home)
            @intCast(home.len)
        else
            @intCast(text.len - store_suffix.len);
        store.start(host);
        return true;
    }

    /// A store at exactly `root` (absolute, without a trailing slash), whose parent exists.
    pub fn at(store: *Store, host: Host, root: []const u8) void {
        assert(root.len > 1);
        assert(root[0] == '/');
        assert(root.len < store.root.len);
        @memcpy(store.root[0..root.len], root);
        store.root[root.len] = 0;
        store.root_len = @intCast(root.len);
        store.existing_len = @intCast(std.mem.lastIndexOfScalar(u8, root, '/').?);
        store.start(host);
    }

    fn start(store: *Store, host: Host) void {
        assert(store.root_len > 1);
        store.host = host;
        store.fs = host.filesystem();
        store.chunk_bytes = constants.store_chunk_bytes;
        store.tmp_counter = 0;
        store.objects_written = 0;
        store.bytes_written = 0;
        assert(store.root[store.root_len] == 0);
    }

    pub fn root_text(store: *const Store) [:0]const u8 {
        assert(store.root_len > 1);
        assert(store.root[store.root_len] == 0);
        return store.root[0..store.root_len :0];
    }

    /// A path inside the store: the root and the parts. The longest is far below the buffer.
    pub fn path(store: *const Store, buffer: *PathBuf, parts: []const []const u8) [:0]const u8 {
        assert(store.root_len > 1);
        var all: [12][]const u8 = undefined;
        assert(parts.len < all.len);
        all[0] = store.root_text();
        @memcpy(all[1..][0..parts.len], parts);
        // Cannot fail: the root is at most 400 + 10 bytes and the parts at most 100 more.
        buffer.set(all[0 .. parts.len + 1]) catch unreachable;
        return buffer.text();
    }

    pub fn directory_path(store: *const Store, buffer: *PathBuf, name: []const u8) [:0]const u8 {
        assert(store.root_len > 1);
        assert(name.len > 0);
        return store.path(buffer, &.{ "/", name });
    }

    /// `objects/ab/<rest>` (or `trees`), with `suffix` after the id.
    pub fn id_path(
        store: *const Store,
        buffer: *PathBuf,
        directory: []const u8,
        id: Digest,
        suffix: []const u8,
    ) [:0]const u8 {
        assert(directory.len > 0);
        assert(suffix.len < 16);
        const hex = id.hex();
        return store.path(buffer, &.{ "/", directory, "/", hex[0..2], "/", hex[2..], suffix });
    }

    pub fn shard_path(
        store: *const Store,
        buffer: *PathBuf,
        directory: []const u8,
        id: Digest,
    ) [:0]const u8 {
        assert(directory.len > 0);
        assert(store.root_len > 1);
        const hex = id.hex();
        return store.path(buffer, &.{ "/", directory, "/", hex[0..2] });
    }

    pub fn object_path(store: *const Store, buffer: *PathBuf, id: Digest) [:0]const u8 {
        assert(store.root_len > 1);
        assert(id.bytes.len == constants.store_digest_bytes);
        return store.id_path(buffer, "objects", id, "");
    }

    pub fn chunks_path(store: *const Store, buffer: *PathBuf, id: Digest) [:0]const u8 {
        assert(store.root_len > 1);
        assert(id.bytes.len == constants.store_digest_bytes);
        return store.id_path(buffer, "objects", id, chunks_suffix);
    }

    pub fn tree_path(store: *const Store, buffer: *PathBuf, id: Digest) [:0]const u8 {
        assert(store.root_len > 1);
        assert(id.bytes.len == constants.store_digest_bytes);
        return store.id_path(buffer, "trees", id, "");
    }

    pub fn root_record_path(store: *const Store, buffer: *PathBuf, id: Digest) [:0]const u8 {
        assert(store.root_len > 1);
        assert(id.bytes.len == constants.store_digest_bytes);
        const hex = id.hex();
        return store.path(buffer, &.{ "/roots/", &hex });
    }

    /// A fresh name for a file being written: `tmp/<pid>-<n>`.
    pub fn tmp_path(store: *Store, buffer: *PathBuf) [:0]const u8 {
        assert(store.root_len > 1);
        assert(store.tmp_counter < constants.store_tmp_attempts_max);
        var name: [32]u8 = undefined;
        // Cannot fail: "/tmp/" and two numbers of at most ten digits fit 32 bytes.
        const text = std.fmt.bufPrint(&name, "/tmp/{d}-{d}", .{
            store.host.own_pid(),
            store.tmp_counter,
        }) catch unreachable; // Same bound.
        store.tmp_counter += 1;
        return store.path(buffer, &.{text});
    }
};

/// What `store.zon` says about the store.
pub const Format = union(enum) {
    /// There is no store here yet.
    absent,
    ok,
    /// Written by a newer zbx: the version it carries.
    too_new: u32,
    /// Cannot be read, or is not a store.zon; the errno of the read, 0 if the file is malformed.
    unreadable: u16,
};

/// The format file's text.
pub fn format_text(buffer: *[64]u8) []const u8 {
    assert(constants.store_format_version > 0);
    assert(constants.store_format_version < 1 << 20);
    // Cannot fail: a few words and a number fit 64 bytes.
    return std.fmt.bufPrint(buffer, ".{{\n    .format = {d},\n}}\n", .{
        constants.store_format_version,
    }) catch unreachable; // Same bound.
}

/// The version in a `store.zon`, or null if the text is not one.
pub fn parse_format(text: []const u8) ?u32 {
    assert(text.len <= constants.file_bytes_max);
    assert(constants.store_format_version > 0);
    const key = ".format = ";
    const at = std.mem.indexOf(u8, text, key) orelse return null;
    const rest = text[at + key.len ..];
    const end = std.mem.indexOfAny(u8, rest, ",\n") orelse return null;
    const version = std.fmt.parseInt(u32, rest[0..end], 10) catch return null;
    if (version == 0) return null;
    return version;
}

/// Reads `store.zon`.
pub fn read_format(store: *const Store) Format {
    assert(store.root_len > 1);
    assert(store.root[store.root_len] == 0);
    var buffer: PathBuf = undefined;
    const path = store.path(&buffer, &.{ "/", format_file });
    var bytes: [256]u8 = undefined;
    const text = store.fs.read_whole(path, &bytes) catch |err| switch (err) {
        error.NotFound => return .absent,
        error.FileTooLarge => return .{ .unreadable = 0 },
        else => return .{ .unreadable = store.fs.last_errno() },
    };
    const version = parse_format(text) orelse return .{ .unreadable = 0 };
    if (version > constants.store_format_version) return .{ .too_new = version };
    return .ok;
}

const testing = std.testing;
const host_sim = @import("../host_sim.zig");
const HostSim = host_sim.HostSim;

test "the format file round-trips, and anything else is not one" {
    // Goal: the version is read back exactly; near misses are refused, not guessed at.
    var buffer: [64]u8 = undefined;
    const text = format_text(&buffer);
    try testing.expectEqual(@as(?u32, constants.store_format_version), parse_format(text));
    try testing.expectEqual(@as(?u32, 7), parse_format(".{ .format = 7, }"));
    try testing.expect(parse_format("") == null);
    try testing.expect(parse_format(".{ .format = x, }") == null);
    try testing.expect(parse_format(".{ .format = 0, }") == null);
    try testing.expect(parse_format(".{ .format = 5") == null);
    try testing.expect(parse_format(".{ .format = 99999999999, }") == null);
}

test "the store's directory comes from XDG_DATA_HOME, else HOME, and must be absolute" {
    // Goal: the location rules of the brief. Method: four environments.
    var sim: HostSim = undefined;
    var store: Store = undefined;
    const cases = [_]struct { env: []const host_sim.EnvironmentVariable, want: ?[]const u8 }{
        .{
            .env = &.{.{ .name = "HOME", .value = "/home/u" }},
            .want = "/home/u/.local/share/zbx/store",
        },
        .{ .env = &.{
            .{ .name = "HOME", .value = "/home/u/" },
            .{ .name = "XDG_DATA_HOME", .value = "/data/" },
        }, .want = "/data/zbx/store" },
        .{ .env = &.{
            .{ .name = "HOME", .value = "/home/u" },
            .{ .name = "XDG_DATA_HOME", .value = "relative" },
        }, .want = "/home/u/.local/share/zbx/store" },
        .{ .env = &.{.{ .name = "HOME", .value = "home" }}, .want = null },
        .{ .env = &.{}, .want = null },
    };
    for (cases) |case| {
        sim.init(1, &.{});
        sim.environment_variables = case.env;
        const found = store.locate(sim.interface());
        try testing.expectEqual(case.want != null, found);
        if (case.want) |want| try testing.expectEqualStrings(want, store.root_text());
    }
}

test "an object lives under its first byte, and a tree under trees" {
    // Goal: the sharding rule and the suffixes. Method: one id, every path builder.
    var sim: HostSim = undefined;
    sim.init(1, &.{});
    var store: Store = undefined;
    store.at(sim.interface(), "/s");
    const id = Digest.of("x");
    const hex = id.hex();
    var buffer: PathBuf = undefined;
    var expect: [200]u8 = undefined;
    const object = try std.fmt.bufPrint(&expect, "/s/objects/{s}/{s}", .{ hex[0..2], hex[2..] });
    try testing.expectEqualStrings(object, store.object_path(&buffer, id));
    const chunks = try std.fmt.bufPrint(
        &expect,
        "/s/objects/{s}/{s}.chunks",
        .{ hex[0..2], hex[2..] },
    );
    try testing.expectEqualStrings(chunks, store.chunks_path(&buffer, id));
    const tree = try std.fmt.bufPrint(&expect, "/s/trees/{s}/{s}", .{ hex[0..2], hex[2..] });
    try testing.expectEqualStrings(tree, store.tree_path(&buffer, id));
    const root = try std.fmt.bufPrint(&expect, "/s/roots/{s}", .{hex});
    try testing.expectEqualStrings(root, store.root_record_path(&buffer, id));
    const first = store.tmp_path(&buffer);
    try testing.expect(std.mem.startsWith(u8, first, "/s/tmp/"));
    var again: PathBuf = undefined;
    try testing.expect(!std.mem.eql(u8, first, store.tmp_path(&again)));
}
