//! Tests of the upload (`upload.zig`) against the test registry in the simulator: each named fault
//! of `push_fixture.zig` gives the code it should, a push that meets random faults ends whole or
//! with a code, the manifest is never put before its blobs are there, and a second push sends no
//! blob bytes.

const std = @import("std");
const codes = @import("../diag/codes.zig");
const Diag = @import("../diag/diag.zig").Diag;
const fs_sim = @import("../store/fs_sim.zig");
const host_sim = @import("../host_sim.zig");
const images = @import("../store/images.zig");
const import = @import("../store/import.zig");
const layout = @import("../store/layout.zig");
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
        .{ .repository = "push/farlocation", .code = .E0555 },
    };
    const rig = try Rig.create(4);
    defer rig.destroy();
    for (cases) |case| {
        errdefer std.debug.print("fault {s}\n", .{case.repository});
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

test "random faults end with the image whole or with a code, never a manifest ahead of a blob" {
    // Goal: no half-image is ever named. Method: many seeds of random network failures; each
    // push either ends whole (manifest and both blobs held) or with a diagnostic, and the
    // registry never had to refuse a manifest for a missing blob.
    const rig = try Rig.create(5);
    defer rig.destroy();
    var seed: u64 = 0;
    while (seed < 200) : (seed += 1) {
        rig.wire.init(seed, rig.registry.responder());
        rig.wire.received = &rig.registry.drained;
        rig.wire.faults = .{ .fail_per_mille = 40 };
        const result = rig.push("push/ok", .{ .chunk_bytes = 1500 });
        if (result) |_| {
            try testing.expect(rig.holds("push/ok", rig.made.layer));
            try testing.expect(rig.holds("push/ok", rig.made.config));
            try testing.expect(rig.registry.fixture.tag_digest("push/ok", "v1") != null);
        } else |_| {
            try testing.expect(rig.diag.code != null);
        }
        try testing.expectEqual(@as(u32, 0), rig.registry.fixture.unknown_refusals);
    }
}
