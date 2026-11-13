//! Tests of `zigbox.dockerfile`, the library surface, from callers other than the command line:
//! two callers on two threads each bring their own workspace and resolver, translate the same
//! Dockerfile and agree on every byte; a refusal is a code and a line, not a crash, and the
//! workspace is reusable after it. Only names `zigbox.zig` exports are used.

const std = @import("std");
const assert = std.debug.assert;
const zigbox = @import("zigbox.zig");

const testing = std.testing;
const dockerfile = zigbox.dockerfile;

const source =
    \\FROM alpine:3.20 AS base
    \\ARG VERSION=1
    \\ENV APP=/srv
    \\WORKDIR /srv
    \\COPY . /srv
    \\RUN echo $VERSION > /srv/version
    \\CMD ["/bin/sh"]
    \\
;

/// A caller's resolver: every image has Docker's default `PATH` and no workdir of its own.
const Resolver = struct {
    asked: u32 = 0,

    fn resolve(context: *anyopaque, reference: []const u8) error{Unresolved}!dockerfile.ImageFacts {
        const resolver: *Resolver = @ptrCast(@alignCast(context));
        assert(reference.len > 0);
        resolver.asked += 1;
        return .{ .env = &.{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}, .workdir = "" };
    }
};

fn options_of(text: []const u8, resolver: *Resolver) dockerfile.Options {
    assert(text.len > 0);
    return .{
        .dockerfile = text,
        .dockerfile_name = "Dockerfile",
        .dockerignore = "",
        .build_args = &.{},
        .target = null,
        .platform = .{ .os = "linux", .architecture = "amd64", .variant = "" },
        .network = .detect,
        .hermetic = false,
        .resolver = .{ .context = resolver, .resolve = Resolver.resolve },
    };
}

/// What one caller got: its own copy of the bytes (the workspace is freed with the caller).
const Result = struct {
    bytes: [8192]u8 = undefined,
    len: usize = 0,
    references: u32 = 0,
    failed: bool = false,
};

fn work(result: *Result) void {
    const ws = std.heap.page_allocator.create(dockerfile.Workspace) catch {
        result.failed = true;
        return;
    };
    defer std.heap.page_allocator.destroy(ws);
    var resolver: Resolver = .{};
    const options = options_of(source, &resolver);
    const built = dockerfile.translate(ws, &options) catch {
        result.failed = true;
        return;
    };
    if (built.len > result.bytes.len) {
        result.failed = true;
        return;
    }
    @memcpy(result.bytes[0..built.len], built);
    result.len = built.len;
    result.references = @intCast(ws.references_slice().len);
}

test "two callers on two threads translate one Dockerfile to the same bytes" {
    // Goal: the translator shares nothing between callers. Method: two threads, each with its
    // own heap workspace and resolver, translate the same text; the bytes and the references
    // reached are identical, and the resolver was asked once for the one base image.
    var results: [2]Result = .{ .{}, .{} };
    var threads: [2]std.Thread = undefined;
    for (&threads, &results) |*thread, *result| {
        thread.* = try std.Thread.spawn(.{}, work, .{result});
    }
    for (threads) |thread| thread.join();
    try testing.expect(!results[0].failed);
    try testing.expect(!results[1].failed);
    try testing.expect(results[0].len > 0);
    try testing.expectEqualStrings(results[0].bytes[0..results[0].len], results[1].bytes[0..results[1].len]);
    try testing.expectEqual(@as(u32, 1), results[0].references);
    try testing.expect(std.mem.indexOf(u8, results[0].bytes[0..results[0].len], "alpine:3.20") != null);
}

test "a refusal is a code and a line, and the workspace is reusable after it" {
    // Goal: a caller can tell a Dockerfile zbx cannot honour from a bug, and goes on. Method:
    // an instruction the translator refuses, then the good text again in the same workspace.
    const ws = try testing.allocator.create(dockerfile.Workspace);
    defer testing.allocator.destroy(ws);
    var resolver: Resolver = .{};
    const bad = "FROM alpine:3.20\nHEALTHCHECK CMD true\nBOGUS x\n";
    const refused = options_of(bad, &resolver);
    try testing.expectError(error.Refused, dockerfile.translate(ws, &refused));
    try testing.expect(ws.refusal.line > 0);
    const good = options_of(source, &resolver);
    const built = try dockerfile.translate(ws, &good);
    try testing.expect(built.len > 0);
}

test "a reference the resolver cannot find is Unresolved, not a refusal" {
    // Goal: the two errors are told apart. Method: a resolver that refuses every reference.
    const Missing = struct {
        fn resolve(context: *anyopaque, reference: []const u8) error{Unresolved}!dockerfile.ImageFacts {
            _ = context;
            assert(reference.len > 0);
            return error.Unresolved;
        }
    };
    const ws = try testing.allocator.create(dockerfile.Workspace);
    defer testing.allocator.destroy(ws);
    var resolver: Resolver = .{};
    var options = options_of(source, &resolver);
    options.resolver = .{ .context = &resolver, .resolve = Missing.resolve };
    try testing.expectError(error.Unresolved, dockerfile.translate(ws, &options));
}
