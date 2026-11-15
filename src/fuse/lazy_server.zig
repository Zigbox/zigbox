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
const records = @import("../runtime/records.zig");
const nodes = @import("nodes.zig");
const ops = @import("ops.zig");
const cache_mod = @import("cache.zig");
const serve_mod = @import("serve.zig");
const resolver = @import("resolver.zig");
const lazy_mod = @import("../lazy/lazy.zig");
const index_mod = @import("../lazy/index.zig");

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

/// An image that is not all local: its verified lazy index (whose trees are in the store), and
/// where the chunks the store lacks come from. `attach` gives it to the server before the run.
pub const Remote = struct {
    index: index_mod.Index,
    /// The layer blob by `Range`; null serves only what the store holds (or peers give).
    registry: ?lazy_mod.Range,
    /// A library caller's peer sources (`StartOptions.lazy_sources`), asked before the registry.
    peers: []const lazy_mod.Source = &.{},
    log: lazy_mod.Log,
    free: lazy_mod.FreeBytes,
    /// Called once, when the resolver has started, with its first report: the progress line.
    started: ?Started = null,
};

pub const Started = struct {
    context: *anyopaque,
    call: *const fn (context: *anyopaque, report: *const lazy_mod.Report) void,
};

/// The resolver's catalog and its fetch threads, for a `Remote` image. Allocated in `prepare`
/// (sized by the index), freed in `finish`.
const Resolving = struct {
    remote: Remote,
    memory: resolver.CatalogMemory,
    resolver: lazy_mod.Resolver,
    started: bool,
    chunks: [threads_count]resolver.ResolverChunks,
};

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
    /// Set by `attach` for an image that is not all local; null serves the store's own objects.
    remote: ?Remote,
    resolving: ?Resolving,

    /// Readies `server` for one run on `host` (the real host).
    pub fn init(server: *Server, host: Host) void {
        server.host = host;
        server.threaded = .init_single_threaded;
        server.fd = -1;
        server.state = .idle;
        server.remote = null;
        server.resolving = null;
    }

    /// Serves the run's chunks through the chunk resolver, from the store or `remote`'s sources,
    /// rather than from the store alone. Before `lazy`'s `prepare`.
    pub fn attach(server: *Server, remote: Remote) void {
        assert(server.state == .idle);
        assert(server.remote == null);
        assert(server.resolving == null);
        assert(remote.index.header.complete);
        server.remote = remote;
    }

    /// What the resolver did, for the summary line; null when the run served the store alone or
    /// its resolver never started.
    pub fn report(server: *Server) ?lazy_mod.Report {
        const resolving = &(server.resolving orelse return null);
        if (!resolving.started) return null;
        return resolving.resolver.report();
    }

    /// The sources' names, indexed as `Report.source_bytes`; empty when `report` is null.
    pub fn source_names(server: *const Server) []const []const u8 {
        const resolving = &(server.resolving orelse return &.{});
        if (!resolving.started) return &.{};
        const count = resolving.resolver.source_count();
        return resolving.resolver.names[0..count];
    }

    pub fn lazy(server: *Server) run.Lazy {
        assert(server.state == .idle);
        assert(server.fd == -1);
        return .{
            .context = server,
            .prepare = prepare,
            .serve = serve,
            .record = record,
            .peers = peers,
        };
    }

    /// The run's peer sources, kept for the resolver. A run with nothing to fetch (no `attach`)
    /// asks no source, so it keeps none.
    fn peers(context: *anyopaque, sources: []const lazy_mod.Source) void {
        const server: *Server = @ptrCast(@alignCast(context));
        assert(server.state == .idle);
        assert(sources.len < constants.lazy_sources_max); // `run.start` checked it.
        const remote = &(server.remote orelse return);
        remote.peers = sources;
    }

    /// The run record's `.lazy`, from the resolver's report; null before it started. A run that
    /// serves the store alone (no `attach`: the image is whole in the store) is 100% local,
    /// with nothing fetched and no resolver.
    fn record(context: *anyopaque) ?records.Lazy {
        const server: *Server = @ptrCast(@alignCast(context));
        if (server.remote == null) {
            assert(server.resolving == null);
            return .{
                .sources = 0,
                .demand_bytes = 0,
                .fill_bytes = 0,
                .errors = 0,
                .local_percent = 100,
            };
        }
        const found = server.report() orelse return null;
        return record_of(&found, server.source_names().len);
    }

    /// After the run (or a start that failed): stops the serving threads, joins them, and
    /// closes the descriptor. Bounded whatever holds the mount: each thread sees the stop within
    /// a poll (`fuse_poll_ms`) and its request in hand, and once the descriptor is closed the
    /// kernel ends the connection, so a holder outside gets `ENOTCONN`
    /// (docs/decisions/2026-11-14-s2-lazy-teardown.md).
    pub fn finish(server: *Server) void {
        switch (server.state) {
            .idle, .prepared => {},
            .serving => {
                server.serving.stop();
                // A serving thread waiting in `Resolver.read` (up to `lazy_read_deadline_ms`)
                // returns at once with `Stopped`.
                if (server.resolving) |*resolving| resolving.resolver.stop();
                server.serving.wait();
                // Each thread closed every chunk file it opened.
                for (&server.threads) |*thread| assert(thread.real.open_count == 0);
                // Through the host, which counted the descriptor when it was received.
                server.host.close(@intCast(server.fd));
                server.fd = -1;
            },
        }
        server.release_resolving();
        server.remote = null;
        server.state = .idle;
        assert(server.fd == -1);
    }

    fn release_resolving(server: *Server) void {
        const resolving = &(server.resolving orelse return);
        if (resolving.started and server.state != .serving) resolving.resolver.stop();
        resolving.resolver.deinit(gpa);
        free_catalog(resolving.memory);
        server.resolving = null;
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
        var trees: resolver.StoreTrees = .{ .store = store, .errno = 0 };
        return server.prepare_from(trees.source(), tree, diag);
    }

    /// `prepare`'s table and cache, with the trees read from `source` (the store's, or a test's).
    pub fn prepare_from(server: *Server, source: nodes.TreeSource, tree: Digest, diag: *Diag) bool {
        assert(server.state == .idle);
        assert(diag.code == null);
        const store = &server.store;
        const memory = nodes.carve(
            &server.table_region,
            constants.lazy_nodes_max,
            constants.lazy_index_bytes_max,
        );
        server.table.init(memory);
        server.table.build(source, tree) catch |err| {
            switch (err) {
                error.TooManyNodes, error.TooLarge => diagnose.too_large(diag, tree, bound_of(err)),
                else => store_diagnose.tree_damaged(diag, tree, build_failure(err)),
            }
            assert(diag.code != null);
            return false;
        };
        assert(store.chunk_bytes > 0);
        assert(store.chunk_bytes <= constants.store_chunk_bytes);
        const cache_used = cache_mod.memory_bytes(store.chunk_bytes);
        assert(cache_used <= server.cache_memory.len);
        const cache_memory = server.cache_memory[0..@intCast(cache_used)];
        server.cache.init(server.threaded.io(), cache_memory, store.chunk_bytes);
        server.server = .{
            .table = &server.table,
            .cache = &server.cache,
            .chunk_bytes = store.chunk_bytes,
        };
        if (server.remote) |*remote| {
            if (!server.prepare_resolving(remote, tree, diag)) return false;
        }
        server.state = .prepared;
        return true;
    }

    /// The catalog of `remote`'s index, checked against the table, and a resolver over it.
    fn prepare_resolving(server: *Server, remote: *const Remote, tree: Digest, diag: *Diag) bool {
        assert(server.resolving == null);
        assert(remote.index.header.tree.eql(tree));
        const memory = alloc_catalog(&remote.index.header) catch {
            diagnose.out_of_memory(diag, tree);
            return false;
        };
        const catalog = resolver.catalog_of(&server.table, &remote.index, memory) catch {
            free_catalog(memory);
            diagnose.index_disagrees(diag, tree);
            return false;
        };
        server.resolving = .{
            .remote = remote.*,
            .memory = memory,
            .resolver = undefined,
            .started = false,
            .chunks = undefined,
        };
        const resolving = &server.resolving.?;
        resolving.resolver.init(gpa, .{
            .store = &server.store,
            .catalog = catalog,
            .peers = remote.peers,
            .registry = remote.registry,
            .log = remote.log,
            .free = remote.free,
            .fill = false,
        }) catch |err| {
            // `run.start` left room for the registry under `lazy_sources_max`.
            assert(err == error.OutOfMemory);
            free_catalog(memory);
            server.resolving = null;
            diagnose.out_of_memory(diag, tree);
            return false;
        };
        return true;
    }

    fn bound_of(err: nodes.BuildError) []const u8 {
        return switch (err) {
            error.TooManyNodes => diagnose.bound(.entries),
            error.TooLarge => diagnose.bound(.index),
            else => unreachable, // E0422, `build_failure`.
        };
    }

    fn build_failure(err: nodes.BuildError) []const u8 {
        return switch (err) {
            error.NotFound => "cannot be served lazily: a directory of it is not in the store",
            error.Damaged => "cannot be served lazily: a directory of it does not hash to its id",
            error.Unreadable => "cannot be served lazily: a directory of it cannot be read",
            error.Malformed => "cannot be served lazily: a directory of it does not decode",
            error.TooManyNodes, error.TooLarge => unreachable, // E1207, `bound_of`.
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
        const device_fuse = host_real_fuse.device(&server.fd) catch {
            server.host.close(@intCast(server.fd));
            server.fd = -1;
            server.state = .idle;
            return error.IoFailed;
        };
        server.serving = serve_mod.Serving.init(
            &server.server,
            device_fuse,
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
                error.TimedOut => error.TimedOut,
            };
        };
        if (server.resolving) |*resolving| {
            for (&resolving.chunks, &server.sources) |*chunks, *source| {
                const chunk_bytes = server.store.chunk_bytes;
                chunks.* = resolver.ResolverChunks.init(&resolving.resolver, chunk_bytes);
                source.* = chunks.chunks();
            }
            resolving.resolver.start(server.threaded.io()) catch {
                server.host.close(@intCast(server.fd));
                server.fd = -1;
                server.state = .idle;
                return error.OutOfMemory;
            };
            resolving.started = true;
            if (resolving.remote.started) |started| {
                const first = resolving.resolver.report();
                started.call(started.context, &first);
            }
        }
        server.state = .serving;
        // Threads already started go on serving, and `finish` stops and joins them.
        server.serving.start() catch return error.OutOfMemory;
        assert(server.serving.started == threads_count);
    }
};

/// The resolver's and the catalog's allocator: a lazy run's only heap, sized by the index at
/// start and freed after the run.
const gpa = std.heap.page_allocator;

fn alloc_catalog(header: *const index_mod.Header) error{OutOfMemory}!resolver.CatalogMemory {
    const objects = try gpa.alloc(lazy_mod.Object, header.objects);
    errdefer gpa.free(objects);
    const hashes = try gpa.alloc(Digest, header.chunks);
    errdefer gpa.free(hashes);
    const chaining = try gpa.alloc(Digest, header.chunks);
    errdefer gpa.free(chaining);
    const locations = try gpa.alloc(lazy_mod.Location, header.chunks);
    return .{ .objects = objects, .hashes = hashes, .chaining = chaining, .locations = locations };
}

fn free_catalog(memory: resolver.CatalogMemory) void {
    gpa.free(memory.objects);
    gpa.free(memory.hashes);
    gpa.free(memory.chaining);
    gpa.free(memory.locations);
}

comptime {
    assert(table_bytes <= std.math.maxInt(usize));
    assert(cache_bytes <= std.math.maxInt(usize));
}

/// A report as the run record keeps it: the percent local by bytes, as the summary line says it.
pub fn record_of(report: *const lazy_mod.Report, sources: usize) records.Lazy {
    assert(report.bytes_local <= report.bytes_total);
    assert(sources <= constants.lazy_sources_max);
    const percent = if (report.bytes_total == 0) 100 else report.bytes_local * 100 /
        report.bytes_total;
    return .{
        .sources = @intCast(sources),
        .demand_bytes = report.fetched_on_demand_bytes,
        .fill_bytes = report.fetched_fill_bytes,
        .errors = report.errors,
        .local_percent = @intCast(percent),
    };
}
