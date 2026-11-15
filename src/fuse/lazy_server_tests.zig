//! `lazy_server.Server` without a kernel: the node table built at its real bounds (exactly the
//! room builds, one more is E1207 with its cause), a tree the store cannot give (E0422), and the
//! serving side over a socket pair standing in for `/dev/fuse` (the handshake, its refusals, and
//! `finish` stopping threads whose connection never ends).

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const testing = std.testing;
const constants = @import("../constants.zig");
const object = @import("../store/object.zig");
const tree = @import("../store/tree.zig");
const xattrs = @import("../store/xattrs.zig");
const Digest = @import("../store/digest.zig").Digest;
const Diag = @import("../diag/diag.zig").Diag;
const host_mod = @import("../host.zig");
const host_real = @import("../host_real.zig");
const abi = @import("abi.zig");
const nodes = @import("nodes.zig");
const diagnose = @import("diagnose.zig");
const fixture_mod = @import("fixture.zig");
const lazy_server = @import("lazy_server.zig");
const run_mod = @import("../runtime/run.zig");

const Server = lazy_server.Server;

var diag: Diag = undefined;
var small_fixture: fixture_mod.Fixture = undefined;

/// The generated trees a test holds: enough for the entries test's 256 directories and roots.
const generated_trees_max = 300;
/// The entries test's shape: `entries_dirs` directories of `entries_files` distinct files, which
/// with the directories themselves is exactly `lazy_nodes_max` entries.
const entries_dirs = 256;
const entries_files = constants.lazy_nodes_max / entries_dirs - 1;
/// The index test's shape: `index_trees` distinct directories that, with the root, fill
/// `lazy_index_bytes_max` to the byte.
const index_trees = 16;
/// A file entry's bytes besides its name: kind, mode, uid, gid, name length, the empty attribute
/// section, and the size, content digest and object id.
const file_entry_fixed = 1 + 2 + 4 + 4 + 1 + 1 + 8 + 32 + 32;
/// The index test's names: a nine-digit prefix that orders them, padded to the length wanted.
const name_prefix_bytes = 9;
const name_bytes_usual = 200;
const store_root = "/nonexistent/zbx-lazy-server-tests";

comptime {
    assert(constants.lazy_nodes_max % entries_dirs == 0);
    assert(entries_files <= constants.store_dir_entries_max);
    assert(constants.lazy_index_bytes_max / index_trees <= constants.store_tree_bytes_max);
    assert(name_bytes_usual <= constants.store_name_bytes_max);
}

/// A `nodes.TreeSource` over trees generated on the heap, keyed by digest.
const Generated = struct {
    digests: [generated_trees_max]Digest,
    held: [generated_trees_max][]u8,
    count: u32,
    buffer: []u8,

    fn init(generated: *Generated) !void {
        generated.count = 0;
        generated.buffer = try testing.allocator.alloc(u8, constants.store_tree_bytes_max);
        assert(generated.buffer.len == constants.store_tree_bytes_max);
        assert(generated.count == 0);
    }

    fn deinit(generated: *Generated) void {
        assert(generated.count <= generated_trees_max);
        for (generated.held[0..generated.count]) |bytes| testing.allocator.free(bytes);
        testing.allocator.free(generated.buffer);
        generated.count = 0;
    }

    fn writer(generated: *Generated) tree.Writer {
        assert(generated.buffer.len == constants.store_tree_bytes_max);
        assert(generated.count < generated_trees_max);
        return tree.Writer.init(generated.buffer);
    }

    fn keep(generated: *Generated, bytes: []const u8) !Digest {
        assert(generated.count < generated_trees_max);
        assert(bytes.len >= tree.header_bytes);
        const digest = Digest.of(bytes);
        generated.held[generated.count] = try testing.allocator.dupe(u8, bytes);
        generated.digests[generated.count] = digest;
        generated.count += 1;
        return digest;
    }

    fn source(generated: *Generated) nodes.TreeSource {
        return .{ .context = generated, .load = load };
    }

    fn load(context: *anyopaque, digest: Digest, out: []u8) nodes.LoadError![]const u8 {
        const generated: *Generated = @ptrCast(@alignCast(context));
        assert(generated.count <= generated_trees_max);
        for (generated.digests[0..generated.count], 0..) |held, index| {
            if (!held.eql(digest)) continue;
            const bytes = generated.held[index];
            if (bytes.len > out.len) return error.Damaged;
            @memcpy(out[0..bytes.len], bytes);
            return out[0..bytes.len];
        }
        return error.NotFound;
    }
};

const root_own: tree.Own = .{ .mode = 0o755, .uid = 0, .gid = 0, .xattrs = &xattrs.empty };

/// A file entry for the object made from `serial`: each serial is its own object.
fn file_entry(writer: *tree.Writer, name: []const u8, serial: u32) !void {
    assert(name.len > 0);
    assert(name.len <= constants.store_name_bytes_max);
    var seed: [4]u8 = undefined;
    std.mem.writeInt(u32, &seed, serial, .little);
    const content = Digest.of(&seed);
    const attrs: object.Attrs = .{ .mode = 0o644, .uid = 0, .gid = 0, .xattrs = &xattrs.empty };
    try writer.begin(name, .file, 0o644, 0, 0, &xattrs.empty);
    try writer.end_file(1, content, object.object_id(content, attrs));
}

fn dir_entry(writer: *tree.Writer, name: []const u8, subtree: Digest) !void {
    assert(name.len > 0);
    assert(name.len <= constants.store_name_bytes_max);
    try writer.begin(name, .dir, 0o755, 0, 0, &xattrs.empty);
    try writer.end_dir(subtree);
}

/// A heap `Server` on the real host, its store's root a path that does not exist (nothing here
/// reads a chunk from it).
fn server_create(real: *host_real.HostReal) !*Server {
    const server = try testing.allocator.create(Server);
    server.init(real.interface());
    server.store.at(real.interface(), store_root);
    server.store.chunk_bytes = 64 * 1024;
    assert(server.state == .idle);
    assert(server.fd == -1);
    return server;
}

/// The roots of the entries test: one with exactly `lazy_nodes_max` entries, one with one more.
fn entries_roots(generated: *Generated) ![2]Digest {
    var subtrees: [entries_dirs]Digest = undefined;
    var serial: u32 = 0;
    var name_buffer: [16]u8 = undefined;
    for (&subtrees) |*subtree| {
        var writer = generated.writer();
        for (0..entries_files) |index| {
            const name = try std.fmt.bufPrint(&name_buffer, "f{d:0>7}", .{index});
            try file_entry(&writer, name, serial);
            serial += 1;
        }
        subtree.* = try generated.keep(writer.finish());
    }
    var roots: [2]Digest = undefined;
    for (&roots, 0..) |*root, extra| {
        var writer = generated.writer();
        for (subtrees, 0..) |subtree, index| {
            const name = try std.fmt.bufPrint(&name_buffer, "d{d:0>4}", .{index});
            try dir_entry(&writer, name, subtree);
        }
        if (extra == 1) try file_entry(&writer, "z", serial);
        root.* = try generated.keep(try writer.finish_with(root_own));
    }
    assert(serial == entries_dirs * entries_files);
    assert(!roots[0].eql(roots[1]));
    return roots;
}

test "E1207 entries: a tree of exactly lazy_nodes_max entries builds, one more is refused" {
    // Goal: the entries bound is reached at `lazy_nodes_max`, not before, through the server's
    // own `prepare`, and its refusal is E1207 with the bound in its cause. Method: generate 256
    // directories of 1023 distinct files (262144 entries, every one its own node, so the table
    // holds 262145 with the root); prepare it, then a root with one more file.
    var real: host_real.HostReal = .{};
    const server = try server_create(&real);
    defer testing.allocator.destroy(server);
    var generated: Generated = undefined;
    try generated.init();
    defer generated.deinit();
    const roots = try entries_roots(&generated);

    diag.reset();
    try testing.expect(server.prepare_from(generated.source(), roots[0], &diag));
    try testing.expectEqual(null, diag.code);
    try testing.expectEqual(constants.lazy_nodes_max + 1, server.table.node_count);
    try testing.expectEqual(constants.lazy_nodes_max, server.table.child_count);
    server.finish();

    diag.reset();
    try testing.expect(!server.prepare_from(generated.source(), roots[1], &diag));
    try testing.expectEqual(.E1207, diag.code.?);
    try testing.expectEqualStrings("the image has more than 262144 entries", diag.last_cause().?);
    try testing.expectEqualStrings("has more than 262144 entries", diagnose.bound(.entries));
    try testing.expectEqual(.idle, server.state);
}

/// A directory of `bytes` bytes, every entry a link of one object, names starting with `tag`.
fn index_subtree(generated: *Generated, tag: u32, bytes: u32) !Digest {
    assert(bytes > tree.header_bytes + tree.own_bytes_min);
    assert(bytes <= constants.store_tree_bytes_max);
    var writer = generated.writer();
    var left: u32 = bytes - tree.header_bytes - tree.own_bytes_min;
    var name_buffer: [constants.store_name_bytes_max]u8 = undefined;
    var index: u32 = 0;
    const entry_min = file_entry_fixed + name_prefix_bytes;
    while (left > 0) : (index += 1) {
        // A usual entry while what is left after it can still take one; else the rest in one or
        // two, each at least `entry_min` and at most the longest name's.
        const take: u32 = if (left >= file_entry_fixed + name_bytes_usual + entry_min)
            file_entry_fixed + name_bytes_usual
        else if (left <= file_entry_fixed + constants.store_name_bytes_max)
            left
        else
            left - 100;
        assert(take >= entry_min);
        const name = name_buffer[0 .. take - file_entry_fixed];
        _ = try std.fmt.bufPrint(name[0..name_prefix_bytes], "{d:0>2}{d:0>7}", .{ tag, index });
        @memset(name[name_prefix_bytes..], 'x');
        try file_entry(&writer, name, 0);
        left -= take;
    }
    const finished = writer.finish();
    assert(finished.len == bytes);
    return generated.keep(finished);
}

/// The roots of the index test: directories of exactly `lazy_index_bytes_max` bytes in all, and
/// the same with one byte more.
fn index_roots(generated: *Generated) ![2]Digest {
    var name_buffer: [8]u8 = undefined;
    // The root's length does not depend on its subtrees' digests: measure it on zeros.
    var measure = generated.writer();
    for (0..index_trees) |index| {
        const name = try std.fmt.bufPrint(&name_buffer, "d{d:0>2}", .{index});
        try dir_entry(&measure, name, tree.zero_digest);
    }
    const root_bytes: u32 = @intCast((try measure.finish_with(root_own)).len);
    const rest = constants.lazy_index_bytes_max - root_bytes;
    var subtrees: [index_trees + 1]Digest = undefined;
    for (subtrees[0..index_trees], 0..) |*subtree, index| {
        const share = rest / index_trees + if (index == index_trees - 1) rest % index_trees else 0;
        subtree.* = try index_subtree(generated, @intCast(index), share);
    }
    const last = rest / index_trees + rest % index_trees;
    subtrees[index_trees] = try index_subtree(generated, index_trees - 1, last + 1);
    var roots: [2]Digest = undefined;
    for (&roots, 0..) |*root, extra| {
        var writer = generated.writer();
        for (0..index_trees) |index| {
            const name = try std.fmt.bufPrint(&name_buffer, "d{d:0>2}", .{index});
            const which = if (index == index_trees - 1 and extra == 1) index_trees else index;
            try dir_entry(&writer, name, subtrees[which]);
        }
        const finished = try writer.finish_with(root_own);
        assert(finished.len == root_bytes);
        root.* = try generated.keep(finished);
    }
    return roots;
}

test "E1207 index: directories of exactly lazy_index_bytes_max bytes build, one more is refused" {
    // Goal: the directory-listing bound is reached at `lazy_index_bytes_max`, not before, through
    // `prepare`, and its refusal is E1207 with the bound in its cause. Method: sixteen distinct
    // directories of about 4 MiB whose lengths, with the root's, sum to 64 MiB exactly (the last
    // entry's name takes up the difference); prepare it, then the same with one byte more.
    var real: host_real.HostReal = .{};
    const server = try server_create(&real);
    defer testing.allocator.destroy(server);
    var generated: Generated = undefined;
    try generated.init();
    defer generated.deinit();
    const roots = try index_roots(&generated);

    diag.reset();
    try testing.expect(server.prepare_from(generated.source(), roots[0], &diag));
    try testing.expectEqual(null, diag.code);
    try testing.expectEqual(constants.lazy_index_bytes_max, server.table.arena_len);
    server.finish();

    diag.reset();
    try testing.expect(!server.prepare_from(generated.source(), roots[1], &diag));
    try testing.expectEqual(.E1207, diag.code.?);
    try testing.expectEqualStrings(
        "the image has more than 64 MiB of directory listings",
        diag.last_cause().?,
    );
    try testing.expectEqual(.idle, server.state);
}

test "E0422: a tree the store does not hold is a damaged store, not a bound" {
    // Goal: a build failure that is not a bound maps to E0422 with the reason, never E1207.
    // Method: prepare a root digest the source does not hold.
    var real: host_real.HostReal = .{};
    const server = try server_create(&real);
    defer testing.allocator.destroy(server);
    var generated: Generated = undefined;
    try generated.init();
    defer generated.deinit();
    const missing = Digest.of("not a tree");

    diag.reset();
    try testing.expect(!server.prepare_from(generated.source(), missing, &diag));
    try testing.expectEqual(.E0422, diag.code.?);
    var expected_buffer: [256]u8 = undefined;
    const expected = try std.fmt.bufPrint(
        &expected_buffer,
        "tree {s} cannot be served lazily: a directory of it is not in the store",
        .{missing.text()},
    );
    try testing.expectEqualStrings(expected, diag.last_cause().?);
}

/// A small prepared server and a socket pair: `[0]` is the server's end, counted by the host as
/// a received descriptor is; `[1]` plays the kernel.
const Paired = struct {
    server: *Server,
    /// Taken before the server was prepared, as the run takes it.
    lazy: run_mod.Lazy,
    peer: linux.fd_t,
    device: host_mod.Handle,
};

fn paired_create(real: *host_real.HostReal) !Paired {
    const server = try server_create(real);
    errdefer testing.allocator.destroy(server);
    const lazy = server.lazy();
    const fixture = &small_fixture;
    fixture.init(64 * 1024);
    _ = fixture.begin();
    _ = try fixture.file("a", "hello\n", 0o644, &xattrs.empty);
    const root = try fixture.finish_root(root_own);
    diag.reset();
    try testing.expect(server.prepare_from(fixture.source(), root, &diag));
    var pair: [2]i32 = undefined;
    const kind = linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC;
    try testing.expectEqual(0, linux.socketpair(linux.AF.UNIX, kind, 0, &pair));
    real.open_count += 1; // The server's end, which `serve` owns and closes through the host.
    assert(pair[0] >= 0);
    assert(pair[1] >= 0);
    return .{ .server = server, .lazy = lazy, .peer = pair[1], .device = @intCast(pair[0]) };
}

fn peer_send(
    peer: linux.fd_t,
    opcode: abi.Opcode,
    nodeid: u64,
    unique: u64,
    body: []const u8,
) !void {
    var buffer: [256]u8 = undefined;
    const bytes = fixture_mod.request(&buffer, opcode, nodeid, unique, &.{body});
    const sent = linux.write(peer, bytes.ptr, bytes.len);
    try testing.expectEqual(bytes.len, sent);
}

/// The next reply's header, or null once the server's end is closed.
fn peer_reply(peer: linux.fd_t) !?abi.OutHeader {
    var buffer: [4096]u8 = undefined;
    const got = linux.read(peer, &buffer, buffer.len);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(got));
    if (got == 0) return null;
    return fixture_mod.reply_header(buffer[0..got]);
}

const init_in: abi.InitIn = .{
    .major = abi.major_version,
    .minor = abi.minor_version,
    .max_readahead = 128 * 1024,
    .flags = 0,
};

test "serve over a socket pair: INIT answered, requests served, finish stops and closes" {
    // Goal: `finish` returns while the connection is still open (nothing ends it from the
    // kernel's side), joins every thread, closes the descriptor, and leaves no file open.
    // Method: the peer sends INIT, `serve` answers it and starts the threads; the peer gets a
    // GETATTR answered by a thread; then `finish`, and the peer reads end-of-file.
    var real: host_real.HostReal = .{};
    const paired = try paired_create(&real);
    defer testing.allocator.destroy(paired.server);
    defer _ = linux.close(paired.peer);
    const lazy = paired.lazy;

    try peer_send(paired.peer, .init, 0, 1, std.mem.asBytes(&init_in));
    try lazy.serve(lazy.context, paired.device);
    const init_reply = (try peer_reply(paired.peer)).?;
    try testing.expectEqual(0, init_reply.@"error");
    try testing.expectEqual(1, init_reply.unique);
    try testing.expectEqual(.serving, paired.server.state);
    try testing.expectEqual(constants.lazy_fuse_threads, paired.server.serving.started);

    const getattr_in = std.mem.zeroes(abi.GetattrIn);
    try peer_send(paired.peer, .getattr, abi.root_id, 2, std.mem.asBytes(&getattr_in));
    const attr_reply = (try peer_reply(paired.peer)).?;
    try testing.expectEqual(0, attr_reply.@"error");
    try testing.expectEqual(2, attr_reply.unique);

    paired.server.finish();
    try testing.expectEqual(.idle, paired.server.state);
    try testing.expectEqual(0, paired.server.serving.started);
    try testing.expectEqual(0, real.open_count);
    try testing.expectEqual(null, try peer_reply(paired.peer));
}

test "a lazy run served from the store alone records its image 100% local" {
    // Goal: the review's SHOULD 5 for S2 slice 5: a lazy run of an image whole in the store (no
    // `attach`, so no resolver) shows `local_percent` 100 in its run record and in `ps`, not 0.
    // Method: a prepared server with nothing attached; its record hook, the run's source of
    // both, answers 100% local with nothing fetched, before and while it serves.
    var real: host_real.HostReal = .{};
    const paired = try paired_create(&real);
    defer testing.allocator.destroy(paired.server);
    defer _ = linux.close(paired.peer);
    const lazy = paired.lazy;
    const before = lazy.record.?(lazy.context).?;
    try testing.expectEqual(100, before.local_percent);
    try testing.expectEqual(0, before.sources);
    try peer_send(paired.peer, .init, 0, 1, std.mem.asBytes(&init_in));
    try lazy.serve(lazy.context, paired.device);
    try testing.expectEqual(0, (try peer_reply(paired.peer)).?.@"error");
    const serving = lazy.record.?(lazy.context).?;
    try testing.expectEqual(100, serving.local_percent);
    try testing.expectEqual(0, serving.demand_bytes + serving.fill_bytes + serving.errors);
    paired.server.finish();
    try testing.expectEqual(0, real.open_count);
}

test "serve over a socket pair: a first request that is not INIT is refused, its end closed" {
    // Goal: a refused handshake closes the descriptor (so the kernel ends the connection) and
    // leaves the server idle, with the refusal the run reports. Method: the peer sends GETATTR
    // first; `serve` fails with `Unsupported`, the host holds nothing, the peer reads end-of-file.
    var real: host_real.HostReal = .{};
    const paired = try paired_create(&real);
    defer testing.allocator.destroy(paired.server);
    defer _ = linux.close(paired.peer);
    const lazy = paired.lazy;

    const getattr_in = std.mem.zeroes(abi.GetattrIn);
    try peer_send(paired.peer, .getattr, abi.root_id, 1, std.mem.asBytes(&getattr_in));
    try testing.expectError(error.Unsupported, lazy.serve(lazy.context, paired.device));
    try testing.expectEqual(.idle, paired.server.state);
    try testing.expectEqual(-1, paired.server.fd);
    try testing.expectEqual(0, real.open_count);
    try testing.expectEqual(null, try peer_reply(paired.peer));
    paired.server.finish();
}

test "serve over a socket pair: a connection that ends before INIT is an I/O failure" {
    // Goal: the kernel side going away before INIT fails the run at once, not after the INIT
    // deadline, and closes the descriptor. Method: close the peer, then `serve`.
    var real: host_real.HostReal = .{};
    const paired = try paired_create(&real);
    defer testing.allocator.destroy(paired.server);
    const lazy = paired.lazy;

    try testing.expectEqual(0, linux.close(paired.peer));
    try testing.expectError(error.IoFailed, lazy.serve(lazy.context, paired.device));
    try testing.expectEqual(.idle, paired.server.state);
    try testing.expectEqual(0, real.open_count);
}
