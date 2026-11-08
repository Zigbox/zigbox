//! Tests of `zigbox.push`, the library call, from callers other than the command line: each
//! caller brings its own memory, simulated host and store and shares nothing with the other. The
//! same tree, imported in a different order into another caller's store, packs to the same
//! digests, and the exported layout is whole (the CLI's own tests are in
//! `store_commands_tests.zig`).

const std = @import("std");
const zigbox = @import("zigbox.zig");
const Diag = @import("diag/diag.zig").Diag;
const fs_sim = @import("store/fs_sim.zig");
const host_sim = @import("host_sim.zig");
const images = @import("store/images.zig");
const import = @import("store/import.zig");
const support = @import("store/test_support.zig");
const Store = @import("store/layout.zig").Store;

const testing = std.testing;
const store_root = "/data/store";

/// Everything one caller of the library owns. About 12 MiB, made on the heap.
const Caller = struct {
    sim: host_sim.HostSim,
    files: fs_sim.SimFs,
    store: Store,
    imports: import.Workspace,
    packing: zigbox.push.Workspace,
    diag: Diag,
    settings: images.Settings,

    fn create(seed: u64, order: u32) !*Caller {
        const caller = try std.heap.page_allocator.create(Caller);
        caller.sim.init(seed, &.{});
        caller.files.init(seed);
        caller.sim.store_fs = &caller.files;
        caller.files.put_dir("/data", 0o755);
        support.make_store_directories(&caller.files, store_root);
        caller.store.at(caller.sim.interface(), store_root);
        support.make_source(&caller.files, order);
        caller.diag.reset();
        caller.settings.clear();
        return caller;
    }

    fn destroy(caller: *Caller) void {
        std.heap.page_allocator.destroy(caller);
    }

    /// Imports `/src`, packs it and writes the layout to `/layout`.
    fn pack_and_export(caller: *Caller) !zigbox.push.Packed {
        var result: import.Result = undefined;
        try import.import(
            &caller.store,
            &caller.imports,
            "/src",
            .{ .squash_owner = false, .warn = null },
            &result,
            &caller.diag,
        );
        const input: zigbox.push.Input = .{
            .tree = result.digest,
            .settings = &caller.settings,
            .labels = null,
        };
        var made: zigbox.push.Packed = undefined;
        var failure: zigbox.push.pack.Failure = undefined;
        try zigbox.push.pack.pack(&caller.store, &caller.packing, input, &made, &failure);
        var exported: zigbox.push.Exported = undefined;
        var export_failure: zigbox.push.export_mod.Failure = undefined;
        try zigbox.push.export_layout(
            &caller.store,
            &made,
            "/layout",
            &caller.packing.io,
            &exported,
            &export_failure,
        );
        try testing.expect(exported.manifest.eql(made.manifest));
        return made;
    }
};

test "two callers of zigbox.push, with stores of their own, make the same image" {
    // Goal: the library promise: no shared state, and one tree gives one image whoever packs
    // it. Method: two callers import the same files in different directory orders and pack
    // them; their digests are equal, and each one's layout holds its manifest.
    const first = try Caller.create(1, 0);
    defer first.destroy();
    const second = try Caller.create(2, 1);
    defer second.destroy();
    const one = try first.pack_and_export();
    const two = try second.pack_and_export();
    try testing.expectEqualSlices(u8, &one.manifest.bytes, &two.manifest.bytes);
    try testing.expectEqualSlices(u8, &one.layer.bytes, &two.layer.bytes);
    try testing.expectEqualSlices(u8, &one.config.bytes, &two.config.bytes);
    try testing.expect(first.files.kind_of("/layout/oci-layout") != null);
    try testing.expect(second.files.kind_of("/layout/index.json") != null);
    // A second pack by the first caller finds its own pack record, and nothing of the other's.
    const input: zigbox.push.Input = .{
        .tree = one.tree,
        .settings = &first.settings,
        .labels = null,
    };
    var again: zigbox.push.Packed = undefined;
    var failure: zigbox.push.pack.Failure = undefined;
    try zigbox.push.pack.pack(&first.store, &first.packing, input, &again, &failure);
    try testing.expect(again.cached);
    try testing.expectEqualSlices(u8, &one.manifest.bytes, &again.manifest.bytes);
}
