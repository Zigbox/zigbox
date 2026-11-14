//! The parent's side of `zbx run --lazy` (S2 slice 4): the FUSE server over the store's own
//! objects. `prepare` builds the node table from the image's trees before the container starts;
//! `serve` takes the descriptor the setup child mounted, answers `INIT` and starts the serving
//! threads; `finish`, after the run, joins them and closes the descriptor.
//!
//! The memory is static (the caller's one `Server`, in bss): the table at `lazy_nodes_max`
//! nodes and `lazy_index_bytes_max` bytes of directories, the chunk cache, and each serving
//! thread's buffers. A thread reads chunks through its own `HostReal` and `Store`, so nothing a
//! read changes (the open count, the store's scratch) is shared between threads. The store is
//! read from outside its namespace, so its owners are the host's map (`outside_owners`).
//!
//! Only the real host serves: `serve` uses real descriptors and threads. A simulated run uses
//! another `run.Lazy`.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const host_real = @import("../host_real.zig");
const host_real_fuse = @import("../host_real_fuse.zig");
const doctor = @import("../doctor.zig");
const Diag = @import("../diag/diag.zig").Diag;
const store_diagnose = @import("../store/diagnose.zig");
const diagnose = @import("diagnose.zig");
const store_namespace = @import("../store/namespace.zig");
const layout = @import("../store/layout.zig");
const xattrs = @import("../store/xattrs.zig");
const Digest = @import("../store/digest.zig").Digest;
const run = @import("../runtime/run.zig");
const nodes = @import("nodes.zig");
const ops = @import("ops.zig");
const cache_mod = @import("cache.zig");
const serve_mod = @import("serve.zig");
const resolver = @import("resolver.zig");

const Host = host_mod.Host;
const Store = layout.Store;
const threads_count = constants.lazy_fuse_threads;

const table_bytes = nodes.memory_bytes(constants.lazy_nodes_max, constants.lazy_index_bytes_max);
const cache_bytes = cache_mod.memory_bytes(constants.store_chunk_bytes);

/// One serving thread's own way into the store.
const Thread = struct {
    real: host_real.HostReal,
    store: Store,
    scratch: xattrs.Scratch,
    io: [constants.store_chunks_max * constants.store_digest_bytes]u8,
    chunks: resolver.StoreChunks,
};

const State = enum { idle, prepared, serving };

pub const Server = struct {
    table_region: [table_bytes]u8 align(8),
    cache_memory: [cache_bytes]u8 align(8),
    thread_memory: [threads_count * serve_mod.thread_memory_bytes]u8 align(8),
    threads: [threads_count]Thread,
    sources: [threads_count]ops.Chunks,
    facts: doctor.Facts,
    threaded: std.Io.Threaded,
    host: Host,
    store: Store,
    owners: @import("../store/owners.zig").Map,
    table: nodes.Table,
    cache: cache_mod.Cache,
    server: ops.Server,
    serving: serve_mod.Serving,
    fd: linux.fd_t,
    state: State,

    /// Readies `server` for one run on `host` (the real host).
    pub fn init(server: *Server, host: Host) void {
        server.host = host;
        server.threaded = .init_single_threaded;
        server.fd = -1;
        server.state = .idle;
    }

    pub fn lazy(server: *Server) run.Lazy {
        assert(server.state == .idle);
        assert(server.fd == -1);
        return .{ .context = server, .prepare = prepare, .serve = serve };
    }

    /// After the run (or a start that failed): joins the serving threads, which return once the
    /// container's mount namespace is gone, and closes the descriptor.
    pub fn finish(server: *Server) void {
        switch (server.state) {
            .idle, .prepared => {},
            .serving => {
                server.serving.wait();
                // Through the host, which counted the descriptor when it was received.
                server.host.close(@intCast(server.fd));
                server.fd = -1;
            },
        }
        server.state = .idle;
        assert(server.fd == -1);
    }

    fn prepare(context: *anyopaque, tree: Digest, diag: *Diag) bool {
        const server: *Server = @ptrCast(@alignCast(context));
        assert(server.state == .idle);
        assert(server.fd == -1);
        assert(diag.code == null);
        const store = &server.store;
        if (!store.locate(server.host)) {
            store_diagnose.tree_damaged(diag, tree, "cannot be read: the store is not found");
            return false;
        }
        server.owners = store_namespace.outside_owners(server.host, &server.facts).map;
        store.owners = .{ .outside = server.owners };
        const memory = nodes.carve(
            &server.table_region,
            constants.lazy_nodes_max,
            constants.lazy_index_bytes_max,
        );
        server.table.init(memory);
        var trees: resolver.StoreTrees = .{ .store = store, .errno = 0 };
        server.table.build(trees.source(), tree) catch |err| {
            switch (err) {
                error.TooManyNodes, error.TooLarge => diagnose.too_large(diag, tree, bound(err)),
                else => store_diagnose.tree_damaged(diag, tree, build_failure(err)),
            }
            return false;
        };
        assert(store.chunk_bytes > 0);
        assert(store.chunk_bytes <= constants.store_chunk_bytes);
        server.cache.init(server.threaded.io(), &server.cache_memory, store.chunk_bytes);
        server.server = .{
            .table = &server.table,
            .cache = &server.cache,
            .chunk_bytes = store.chunk_bytes,
        };
        server.state = .prepared;
        return true;
    }

    fn build_failure(err: nodes.BuildError) []const u8 {
        return switch (err) {
            error.NotFound => "cannot be served lazily: a directory of it is not in the store",
            error.Damaged => "cannot be served lazily: a directory of it does not hash to its id",
            error.Unreadable => "cannot be served lazily: a directory of it cannot be read",
            error.Malformed => "cannot be served lazily: a directory of it does not decode",
            error.TooManyNodes, error.TooLarge => unreachable, // E1207, `bound`.
        };
    }

    /// The bound of the node table that a tree too large for it passed (E1207).
    fn bound(err: nodes.BuildError) []const u8 {
        return switch (err) {
            error.TooManyNodes => std.fmt.comptimePrint(
                "has more than {d} entries",
                .{constants.lazy_nodes_max},
            ),
            error.TooLarge => std.fmt.comptimePrint(
                "has more than {d} MiB of directory listings",
                .{constants.lazy_index_bytes_max / (1024 * 1024)},
            ),
            else => unreachable, // E0422, `build_failure`.
        };
    }

    /// `Session.Fuse.serve`: owns `device` whatever the outcome.
    fn serve(context: *anyopaque, device: host_mod.Handle) host_mod.Error!void {
        const server: *Server = @ptrCast(@alignCast(context));
        assert(server.state == .prepared);
        assert(server.fd == -1);
        server.fd = @intCast(device);
        assert(server.fd >= 0);
        assert(server.store.chunk_bytes > 0);
        for (&server.threads, &server.sources) |*thread, *source| {
            thread.real = .{};
            thread.store.at(thread.real.interface(), server.store.root_text());
            thread.store.chunk_bytes = server.store.chunk_bytes;
            thread.store.owners = .{ .outside = server.owners };
            thread.chunks = resolver.StoreChunks.init(&thread.store, &thread.io, &thread.scratch);
            source.* = thread.chunks.chunks();
            assert(thread.store.chunk_bytes == server.server.chunk_bytes);
        }
        server.serving = serve_mod.Serving.init(
            &server.server,
            host_real_fuse.device(&server.fd),
            &server.sources,
            &server.thread_memory,
        );
        server.serving.handshake() catch |err| {
            server.host.close(@intCast(server.fd));
            server.fd = -1;
            server.state = .idle;
            return switch (err) {
                error.Ended => error.IoFailed,
                error.Refused => error.Unsupported,
            };
        };
        server.state = .serving;
        // Threads already started go on serving, and `finish` joins them.
        server.serving.start() catch return error.OutOfMemory;
    }
};

comptime {
    assert(table_bytes <= std.math.maxInt(usize));
    assert(cache_bytes <= std.math.maxInt(usize));
}
