//! Tests of the upload (`upload.zig`) against the test registry in the simulator: each named fault
//! of `push_fixture.zig` gives the code it should, a push that meets random faults ends whole or
//! with a code, the manifest is never put before its blobs are there, and a second push sends no
//! blob bytes.

const std = @import("std");
const codes = @import("../diag/codes.zig");
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;
const fs_sim = @import("../store/fs_sim.zig");
const host_sim = @import("../host_sim.zig");
const images = @import("../store/images.zig");
const import = @import("../store/import.zig");
const layout = @import("../store/layout.zig");
const net = @import("../registry/net.zig");
const net_sim = @import("../registry/net_sim.zig");
const oci = @import("../registry/digest.zig");
const pack = @import("pack.zig");
const push_registry = @import("../registry/push_registry.zig");
const support = @import("../store/test_support.zig");
const upload = @import("upload.zig");

const testing = std.testing;
const store_root = "/data/store";

/// Everything one test owns: the store with a packed image, and the registry. On the heap.
const Rig = struct {
    host: host_sim.HostSim,
    files: fs_sim.SimFs,
    store: layout.Store,
    imports: import.Workspace,
    packing: pack.Workspace,
    wire: net_sim.SimNet,
    registry: push_registry.PushRegistry,
    ws: upload.Workspace,
    diag: Diag,
    settings: images.Settings,
    made: pack.Packed,
    report: upload.Report,

    fn create(seed: u64) !*Rig {
        const rig = try std.heap.page_allocator.create(Rig);
        rig.host.init(seed, &.{});
        rig.files.init(seed);
        rig.host.store_fs = &rig.files;
        rig.files.put_dir("/data", 0o755);
        support.make_store_directories(&rig.files, store_root);
        rig.store.at(rig.host.interface(), store_root);
        support.make_source(&rig.files, 0);
        rig.settings.clear();
        rig.wire.init(seed, rig.registry.responder());
        rig.registry.init(&rig.wire);
        rig.diag.reset();
        var result: import.Result = undefined;
        try import.import(
            &rig.store,
            &rig.imports,
            "/src",
            .{ .squash_owner = false, .warn = null },
            &result,
            &rig.diag,
        );
        const input: pack.Input = .{
            .tree = result.digest,
            .settings = &rig.settings,
            .labels = null,
        };
        var failure: pack.Failure = undefined;
        rig.packing.piece = 4096;
        try pack.pack(&rig.store, &rig.packing, input, &rig.made, &failure);
        return rig;
    }

    fn destroy(rig: *Rig) void {
        std.heap.page_allocator.destroy(rig);
    }

    fn holds(rig: *const Rig, repository: []const u8, digest: oci.Sha256) bool {
        return rig.registry.fixture.has_blob(repository, &digest.text());
    }

    fn push(rig: *Rig, repository: []const u8, options: upload.Options) upload.Error!void {
        rig.diag.reset();
        const destination: upload.Destination = .{
            .origin = .{ .scheme = .https, .host = push_registry.registry_host, .port = 443 },
            .repository = repository,
            .tag = "v1",
        };
        return upload.push(
            &rig.store,
            &rig.ws,
            rig.wire.interface(),
            destination,
            &rig.made,
            options,
            &rig.report,
            &rig.diag,
        );
    }
};

const pieces: upload.Options = .{ .chunk_bytes = 64 };

fn expect_code(rig: *Rig, code: codes.Code) !void {
    try testing.expect(rig.diag.code != null);
    try testing.expectEqual(code, rig.diag.code.?);
}

test "a push to a plain registry puts both blobs and the manifest" {
    // Goal: the happy path. Method: push to a registry with no fault, in one request per blob
    // and again in pieces; both end with the manifest and the digests of the packed image.
    const rig = try Rig.create(1);
    defer rig.destroy();
    try rig.push("push/ok", .{});
    try testing.expectEqual(upload.Outcome.uploaded, rig.report.layer.outcome);
    try testing.expectEqual(upload.Outcome.uploaded, rig.report.config.outcome);
    try testing.expect(rig.report.manifest.eql(rig.made.manifest));
    try testing.expect(rig.holds("push/ok", rig.made.layer));
    try testing.expectEqual(@as(u32, 0), rig.registry.fixture.unknown_refusals);
    try rig.push("push/ok-pieces", pieces);
    try testing.expect(rig.holds("push/ok-pieces", rig.made.layer));
    try testing.expectEqual(@as(u32, 0), rig.registry.fixture.unknown_refusals);
}

test "a repeat push finds every blob and sends no blob bytes" {
    // Goal: the repeat push is cheap. Method: push twice; the second sees `exists` for both and
    // the registry received no further body bytes except the manifest.
    const rig = try Rig.create(2);
    defer rig.destroy();
    try rig.push("push/ok", .{});
    const before = rig.registry.fixture.received_bytes;
    try rig.push("push/ok", .{});
    try testing.expectEqual(upload.Outcome.exists, rig.report.layer.outcome);
    try testing.expectEqual(upload.Outcome.exists, rig.report.config.outcome);
    try testing.expectEqual(@as(u64, 0), rig.report.bytes_sent);
    try testing.expectEqual(before, rig.registry.fixture.received_bytes);
}

test "a mount takes the blobs from another repository, and a declined mount uploads them" {
    // Goal: the cross-repository mount, and the fall back when the registry declines it.
    // Method: push to one repository, then to another naming the first as the holder.
    const rig = try Rig.create(3);
    defer rig.destroy();
    try rig.push("push/ok-src", .{});
    try rig.push("push/ok", .{ .mount_from = "push/ok-src" });
    try testing.expectEqual(upload.Outcome.mounted, rig.report.layer.outcome);
    try testing.expectEqual(@as(u64, 0), rig.report.bytes_sent);
    try rig.push("push/nomount", .{ .mount_from = "push/ok-src" });
    try testing.expectEqual(upload.Outcome.uploaded, rig.report.layer.outcome);
    try testing.expect(rig.holds("push/nomount", rig.made.layer));
}

test "each fault of the test registry gives its answer" {
    // Goal: the refusals of the protocol. Method: push in pieces to each named fault and check
    // the code (or success, for the faults a client should ride out).
    const Case = struct { repository: []const u8, code: ?codes.Code };
    const cases = [_]Case{
        .{ .repository = "push/absolute", .code = null },
        .{ .repository = "push/norange", .code = null },
        .{ .repository = "push/shortrange", .code = .E0555 },
        .{ .repository = "push/refusechunk", .code = .E0555 },
        .{ .repository = "push/badclose", .code = .E0555 },
        .{ .repository = "push/invalidmanifest", .code = .E0556 },
        .{ .repository = "push/wrongdigest", .code = .E0556 },
        .{ .repository = "push/throttle", .code = .E0555 },
        .{ .repository = "push/farlocation", .code = null },
        .{ .repository = "push/nodigest", .code = null },
        .{ .repository = "push/nodigestwrong", .code = .E0556 },
    };
    const rig = try Rig.create(4);
    defer rig.destroy();
    for (cases) |case| {
        errdefer std.debug.print("fault {s}: {s}\n", .{
            case.repository,
            rig.diag.last_cause() orelse "",
        });
        rig.registry.init(&rig.wire); // The registry's blob slots are few: start empty.
        const result = rig.push(case.repository, pieces);
        if (case.code) |code| {
            try testing.expectError(error.Failed, result);
            try expect_code(rig, code);
        } else {
            try result;
        }
        try testing.expectEqual(@as(u32, 0), rig.registry.fixture.unknown_refusals);
    }
}

test "a Location on another origin is followed, with no credential" {
    // Goal: the brief's "each Location is followed, relative or absolute", for an upload host
    // other than the registry. Method: push to the `farlocation` repository in one piece; the
    // closing request goes to the other host, and no request carries a bearer.
    const rig = try Rig.create(6);
    defer rig.destroy();
    try rig.push("push/farlocation", .{});
    try testing.expect(rig.holds("push/farlocation", rig.made.layer));
    var elsewhere: u32 = 0;
    var index: u32 = 0;
    while (rig.wire.logged(index)) |entry| : (index += 1) {
        if (index >= rig.wire.requests) break;
        try testing.expectEqual(@as(u32, 0), entry.bearer_len);
        if (std.mem.eql(u8, entry.host_text(), push_registry.other_host)) {
            elsewhere += 1;
            try testing.expectEqual(net.Method.put, entry.method);
        }
    }
    try testing.expectEqual(@as(u32, 2), elsewhere); // The closing PUT of each blob.
}

/// A responder that changes the answers to one method of what the test registry says.
const Rewrite = struct {
    inner: net_sim.Responder,
    when: net.Method,
    change: *const fn (served: *net_sim.Served) void,

    fn responder(rewrite: *Rewrite) net_sim.Responder {
        return .{ .context = rewrite, .answer = answer };
    }

    fn answer(
        context: *anyopaque,
        request: *const net.Request,
        received: []const u8,
        served: *net_sim.Served,
    ) void {
        const rewrite: *Rewrite = @ptrCast(@alignCast(context));
        rewrite.inner.answer(rewrite.inner.context, request, received, served);
        if (request.method == rewrite.when) rewrite.change(served);
    }
};

const bulk_json = "{\"errors\":[{\"code\":\"UNAVAILABLE\"}]}";
var bulk: [constants.push_error_body_bytes + 1]u8 = undefined;

fn refuse_with_bulk(served: *net_sim.Served, length: usize) void {
    @memset(&bulk, ' ');
    @memcpy(bulk[0..bulk_json.len], bulk_json);
    served.* = .{ .status = 503, .content_type = "text/html", .body = bulk[0..length] };
}

fn bulk_at_bound(served: *net_sim.Served) void {
    refuse_with_bulk(served, constants.push_error_body_bytes);
}

fn bulk_past_bound(served: *net_sim.Served) void {
    refuse_with_bulk(served, constants.push_error_body_bytes + 1);
}

fn context_of(rig: *const Rig, key: []const u8) ?[]const u8 {
    for (rig.diag.pairs.slice()) |*pair| {
        if (std.mem.eql(u8, pair.key_slice(), key)) return pair.value.slice();
    }
    return null;
}

test "a refusal's body at the bound gives its code, and one byte past it still gives its status" {
    // Goal: `push_error_body_bytes` at the bound and one past. Method: a registry that refuses
    // opening an upload with a 503 page of exactly the bound, and of one byte more. Both are
    // E0555 with the status; only the first can say the registry's own code.
    const rig = try Rig.create(7);
    defer rig.destroy();
    const changes = [_]*const fn (served: *net_sim.Served) void{ bulk_at_bound, bulk_past_bound };
    for (changes, 0..) |change, index| {
        var rewrite: Rewrite = .{
            .inner = rig.registry.responder(),
            .when = .post,
            .change = change,
        };
        rig.wire.init(7, rewrite.responder());
        rig.wire.received = &rig.registry.drained;
        try testing.expectError(error.Failed, rig.push("push/ok", .{}));
        try expect_code(rig, .E0555);
        try testing.expectEqualStrings("503", context_of(rig, "status").?);
        if (index == 0) {
            try testing.expectEqualStrings("UNAVAILABLE", context_of(rig, "code").?);
        } else {
            try testing.expect(context_of(rig, "code") == null);
        }
    }
}

fn range_from_one(served: *net_sim.Served) void {
    if (served.status == 202) served.range = "1-63";
}

test "a Range that does not start at 0 stops the upload at the piece" {
    // Goal: check_range reads the start. Method: the registry answers a piece with "1-63" after
    // 64 bytes were sent; the refusal names the piece, not the closing request.
    const rig = try Rig.create(8);
    defer rig.destroy();
    var rewrite: Rewrite = .{
        .inner = rig.registry.responder(),
        .when = .patch,
        .change = range_from_one,
    };
    rig.wire.init(8, rewrite.responder());
    rig.wire.received = &rig.registry.drained;
    try testing.expectError(error.Failed, rig.push("push/ok", pieces));
    try expect_code(rig, .E0555);
    const cause = rig.diag.last_cause().?;
    try testing.expect(std.mem.indexOf(u8, cause, "the Range is odd") != null);
}

test "a blob of exactly the most pieces is sent, and one more piece is refused before any request" {
    // Goal: `push_chunks_max` at the bound and one past. Method: the check on the size of the
    // packed layer (the layer is a few kilobytes, so only the count is checked at the bound, and
    // the push of the made-up size starts and then fails to read the file); one past is refused
    // with E0555 before the registry is asked anything.
    const chunk: u32 = 16;
    const bound: u64 = @as(u64, chunk) * constants.push_chunks_max;
    try testing.expectEqual(@as(u64, constants.push_chunks_max), upload.pieces_of(bound, chunk));
    const at_bound: u64 = constants.push_chunks_max;
    try testing.expectEqual(at_bound, upload.pieces_of(bound - 15, chunk));
    try testing.expectEqual(at_bound + 1, upload.pieces_of(bound + 1, chunk));
    const rig = try Rig.create(9);
    defer rig.destroy();
    rig.made.layer_size = bound;
    try testing.expectError(error.Failed, rig.push("push/ok", .{ .chunk_bytes = chunk }));
    try testing.expect(rig.wire.requests > 0); // The bound passes the check.
    rig.wire.init(9, rig.registry.responder());
    rig.wire.received = &rig.registry.drained;
    rig.made.layer_size = bound + 1;
    try testing.expectError(error.Failed, rig.push("push/ok", .{ .chunk_bytes = chunk }));
    try expect_code(rig, .E0555);
    try testing.expectEqual(@as(u32, 0), rig.wire.requests);
    try testing.expectEqualStrings(
        "16",
        context_of(rig, "chunk").?,
    );
    rig.made.layer_size = bound + 1;
    rig.made.config_size = bound + 1;
    try testing.expectError(error.Failed, rig.push("push/ok", .{ .chunk_bytes = chunk }));
    try expect_code(rig, .E0555);
}

const fault_names = [_][]const u8{
    "ok",          "absolute", "norange",         "shortrange",  "refusechunk",
    "badclose",    "nomount",  "invalidmanifest", "wrongdigest", "throttle",
    "farlocation", "nodigest", "nodigestwrong",
};

test "random faults end with the image whole or with a code, never a manifest ahead of a blob" {
    // Goal: no half-image is ever named. Method: many seeds; each picks a registry fault, a
    // chunk size, a mount from a repository that holds the blobs (or none), and random network
    // failures and cut bodies. Each push either ends whole (manifest and both blobs held) or with
    // a diagnostic, and the registry never had to refuse a manifest for a missing blob.
    const rig = try Rig.create(5);
    defer rig.destroy();
    var seed: u64 = 0;
    while (seed < 300) : (seed += 1) {
        var prng = std.Random.Xoshiro256.init(seed);
        const random = prng.random();
        rig.wire.init(seed, rig.registry.responder());
        rig.registry.init(&rig.wire);
        try rig.push("push/ok-src", .{}); // Holds both blobs, for a mount to come from.
        rig.wire.faults = .{
            .fail_per_mille = random.uintLessThan(u16, 60),
            .cut_per_mille = random.uintLessThan(u16, 60),
        };
        var name: [48]u8 = undefined;
        const fault = fault_names[random.uintLessThan(usize, fault_names.len)];
        const repository = std.fmt.bufPrint(&name, "push/{s}", .{fault}) catch
            unreachable; // `name` holds "push/" and the longest fault name
        const options: upload.Options = .{
            .chunk_bytes = random.intRangeAtMost(u32, 16, 4096),
            .mount_from = if (random.boolean()) "push/ok-src" else "",
        };
        const result = rig.push(repository, options);
        if (result) |_| {
            try testing.expect(rig.holds(repository, rig.made.layer));
            try testing.expect(rig.holds(repository, rig.made.config));
            try testing.expect(rig.registry.fixture.tag_digest(repository, "v1") != null);
        } else |_| {
            try testing.expect(rig.diag.code != null);
        }
        try testing.expectEqual(@as(u32, 0), rig.registry.fixture.unknown_refusals);
    }
}
