//! The lazy start's diagnostics that slice 4 raises (docs/briefs/S2-lazy-start.md,
//! "Diagnostics"): an image too large for the server's table (E1207) and `--lazy` with an
//! option it does not take (E1208); and slice 5's: the start from a registry (W1201, E1202)
//! and the reads it serves (W1202, E1203, E1206).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;
const Digest = @import("../store/digest.zig").Digest;
const errors = @import("../diag/errors.zig");
const host_mod = @import("../host.zig");

/// What is wrong with a library caller's lazy sources (`StartOptions.lazy_sources`).
pub const SourcesProblem = enum { no_lazy, no_peers_hook, too_many };

/// ZBX-E1208 for a library caller: peer sources a lazy run cannot take. `zbx` passes none.
pub fn sources_refused(diag: *Diag, problem: SourcesProblem, count: usize) void {
    assert(count > 0);
    assert(diag.code == null);
    diag.raise(.E1208);
    diag.while_("checking the run's lazy sources", .{});
    switch (problem) {
        .no_lazy => diag.cause("{d} peer sources were given to a run that is not lazy", .{count}),
        .no_peers_hook => diag.cause("{d} peer sources were given, and the run's lazy " ++
            "server takes none (its peers hook is null)", .{count}),
        .too_many => diag.cause("{d} peer sources were given, and a lazy run takes at most " ++
            "{d} beside the registry", .{ count, constants.lazy_sources_max - 1 }),
    }
    diag.fix(.{ .sentence = "give peer sources only to a lazy run whose server takes them" });
}

/// Which bound of the node table a tree too large for it passed.
pub const Bound = enum { entries, index };

/// The bound's words in E1207's cause, after "the image".
pub fn bound(which: Bound) []const u8 {
    const text = switch (which) {
        .entries => std.fmt.comptimePrint(
            "has more than {d} entries",
            .{constants.lazy_nodes_max},
        ),
        .index => std.fmt.comptimePrint(
            "has more than {d} MiB of directory listings",
            .{constants.lazy_index_bytes_max / (1024 * 1024)},
        ),
    };
    assert(text.len > 0);
    assert(std.mem.startsWith(u8, text, "has more than "));
    return text;
}

/// ZBX-E1207: the image's tree `tree` does not fit the node table; `what` says which bound.
pub fn too_large(diag: *Diag, tree: Digest, what: []const u8) void {
    assert(what.len > 0);
    assert(diag.code == null);
    diag.raise(.E1207);
    diag.while_("reading the image's directories to serve them lazily", .{});
    diag.cause("the image {s}", .{what});
    diag.context("tree", "{s}", .{tree.text()});
    diag.fix(.{ .sentence = "run it without --lazy, which reads the whole image first" });
}

/// ZBX-E1208: `--lazy` with `flag`, which it does not take.
pub fn flag_refused(diag: *Diag, flag: []const u8) void {
    assert(flag.len > 0);
    assert(diag.code == null);
    diag.raise(.E1208);
    diag.while_("reading the command line", .{});
    diag.cause("'--lazy' serves an image's files as the container reads them, and does not " ++
        "take '{s}'", .{flag});
    diag.context("cmd", "run", .{});
    diag.context("arg", "{s}", .{flag});
    diag.fix(.{ .sentence = "leave out --lazy, or the other option" });
}

/// ZBX-E1202: the index the registry sent for `tree` does not describe it (`catalog_of` found an
/// object whose attributes or content do not give its id).
pub fn index_disagrees(diag: *Diag, tree: Digest) void {
    assert(diag.code == null);
    diag.raise(.E1202);
    diag.while_("checking the image's lazy index against its tree", .{});
    diag.cause("the index lists a file whose content and attributes are not the tree's", .{});
    diag.context("tree", "{s}", .{tree.text()});
    diag.fix(.{ .sentence = "run it without --lazy, which pulls the whole image" });
}

/// ZBX-E1201: no memory for the chunk resolver of `tree`'s lazy run.
pub fn out_of_memory(diag: *Diag, tree: Digest) void {
    assert(diag.code == null);
    diag.raise(.E1201);
    diag.while_("setting up the chunk fetcher for the lazy run", .{});
    diag.cause("this host has too little free memory for its chunk buffers and tables", .{});
    diag.context("tree", "{s}", .{tree.text()});
    diag.fix(.{ .sentence = "run it without --lazy, which reads the whole image first" });
}

/// Why a lazy run cannot use FUSE on this host: E1201's cause names which.
pub const FuseProblem = enum {
    /// `/dev/fuse` does not exist, or no driver is behind it.
    missing,
    /// `/dev/fuse` exists, and this user may not open it.
    denied,
    /// The device opened, and the kernel refused the FUSE mount in the user namespace.
    mount_refused,
    /// The device did not open, for a reason that says nothing about the host's setup.
    failed,
};

/// What the failed open of `/dev/fuse` says about the host, by its errno.
pub fn open_problem(errno: u16) FuseProblem {
    assert(errno < 4096);
    if (errno == 0) return .failed;
    const problem: FuseProblem = switch (@as(std.os.linux.E, @fromBackingInt(errno))) {
        .NOENT, .NODEV, .NXIO => .missing,
        .ACCES, .PERM => .denied,
        else => .failed,
    };
    assert(problem != .mount_refused);
    return problem;
}

/// ZBX-E1201, asked before anything of the run starts: `/dev/fuse` did not open read-write
/// (`Host.open_fuse_device` failed with `err` and `errno`).
pub fn device_refused(diag: *Diag, err: host_mod.Error, errno: u16) void {
    assert(errno < 4096);
    assert(diag.code == null);
    diag.raise(.E1201);
    diag.while_("checking that this user can open /dev/fuse for the lazy run", .{});
    errors.cause_host_error(diag, "opening /dev/fuse read-write", err, errno);
    fuse_cause(diag, open_problem(errno));
    diag.context("device", "/dev/fuse", .{});
    assert(diag.code.? == .E1201);
}

/// ZBX-E1201 from the container's setup child: its step `operation` (the FUSE mount, which
/// opens `/dev/fuse` first) failed with `err` and `errno`. The child reports one errno for the
/// two calls: a missing device and EACCES are the open's; EPERM, the kernel's answer to a
/// mount a user namespace may not make, and everything else are the mount's.
pub fn mount_refused(diag: *Diag, operation: []const u8, err: host_mod.Error, errno: u16) void {
    assert(operation.len > 0);
    assert(errno < 4096);
    assert(diag.code == null);
    diag.raise(.E1201);
    errors.cause_host_error(diag, operation, err, errno);
    const problem: FuseProblem = switch (open_problem(errno)) {
        .missing => .missing,
        .denied => if (errno == @backingInt(std.os.linux.E.PERM)) .mount_refused else .denied,
        .failed, .mount_refused => .mount_refused,
    };
    fuse_cause(diag, problem);
    assert(diag.code.? == .E1201);
}

/// The newest cause of E1201 (the one the default output shows) and its fixes, by `problem`.
fn fuse_cause(diag: *Diag, problem: FuseProblem) void {
    assert(diag.code.? == .E1201);
    assert(diag.causes.count > 0);
    switch (problem) {
        .missing => {
            diag.cause("/dev/fuse is missing: the fuse module is not loaded", .{});
            diag.fix(.{ .sentence = "load it:", .command = "sudo modprobe fuse" });
        },
        .denied => {
            diag.cause("/dev/fuse is not openable: this user may not open it", .{});
            diag.fix(.{ .sentence = "give users read and write on /dev/fuse (the fuse udev " ++
                "rule, mode 0666)" });
        },
        .mount_refused => {
            diag.cause("the kernel refused the FUSE mount in the user namespace", .{});
            diag.fix(.{ .sentence = "see what this host allows:", .command = "zbx doctor" });
        },
        .failed => diag.cause("/dev/fuse could not be opened", .{}),
    }
    diag.fix(.{ .sentence = "or run it without --lazy, which reads the whole image first" });
}

/// ZBX-W1201: `reference` names an image without a lazy index: the run pulls it whole.
pub fn no_index(diag: *Diag, reference: []const u8) void {
    assert(reference.len > 0);
    assert(diag.code == null);
    diag.raise(.W1201);
    diag.while_("starting {s} lazily", .{reference});
    diag.cause("its manifest has no lazy index: no zbx with layer writer 2 pushed it", .{});
    diag.context("image", "{s}", .{reference});
    diag.fix(.{ .sentence = "nothing to do: the image is pulled whole, then run" });
}

/// W1201 for an image of more than one layer: a lazy index covers one layer only.
pub fn many_layers(diag: *Diag, reference: []const u8, count: u32) void {
    assert(reference.len > 0);
    assert(diag.code == null);
    diag.raise(.W1201);
    diag.while_("starting {s} lazily", .{reference});
    diag.cause("it has {d} layers, and a lazy start serves an image of one layer only", .{count});
    diag.context("image", "{s}", .{reference});
    diag.fix(.{ .sentence = "nothing to do: the image is pulled whole, then run" });
}

/// Why `index_refused` refused an index.
pub const Refused = enum { no_tree, hash, tree, inflate };

/// ZBX-E1202: the index the registry sent for `reference` was refused before anything was
/// written.
pub fn index_refused(diag: *Diag, reference: []const u8, why: Refused) void {
    assert(reference.len > 0);
    assert(diag.code == null);
    diag.raise(.E1202);
    diag.while_("checking the lazy index of {s}", .{reference});
    const cause = switch (why) {
        .no_tree => "the manifest has a lazy index but names no tree for it to describe",
        .hash => "the index's bytes do not hash to the manifest's value",
        .tree => "the index's trees do not check against the manifest's org.zigbox.tree",
        .inflate => "the index's range in the layer is not one whole compressed stream",
    };
    diag.cause("{s}", .{cause});
    diag.context("image", "{s}", .{reference});
    diag.fix(.{ .sentence = "run it without --lazy, which pulls the whole image" });
}

/// ZBX-W1202: `source` sent bytes for chunk `chunk` of the object `object` that do not match
/// the chunk's hash; another source was asked, and this one is not asked for the object again.
pub fn chunk_lied(diag: *Diag, source: []const u8, object: Digest, chunk: u32) void {
    assert(source.len > 0);
    assert(diag.code == null);
    diag.raise(.W1202);
    diag.while_("fetching a chunk of a lazily started image", .{});
    // The object is in the cause, not only in the context: the plain rendering shows no
    // context, and the cause is what tells a reader which file to suspect. At most 192 bytes
    // with a 52-byte source name, so it fits `diag_field_bytes_max`.
    diag.cause("{s} sent bytes for {s} that do not match chunk {d}'s hash; none were used", .{
        source,
        object.text(),
        chunk,
    });
    diag.context("object", "{s}", .{object.text()});
    diag.context("source", "{s}", .{source});
    diag.fix(.{ .sentence = "nothing to do here: the next source is asked; tell its owner" });
}

/// Why no source gave a chunk, for `E1203`'s cause.
pub const Unavailable = enum {
    /// None gave it within `lazy_read_deadline_ms` (or `lazy_down_fail_ms` while all are down).
    deadline,
    /// Every source sent bytes that do not match its hash, for this read or an earlier one,
    /// and is not asked for the file again: the read failed at once, no deadline passed.
    lied,
};

/// ZBX-E1203: no source gave chunk `chunk` of `object`: the reading process got `EIO`. `tried`
/// is what each source did, already rendered.
pub fn chunk_unavailable(
    diag: *Diag,
    object: Digest,
    chunk: u32,
    why: Unavailable,
    tried: []const u8,
) void {
    assert(tried.len > 0);
    assert(diag.code == null);
    diag.raise(.E1203);
    diag.while_("fetching a chunk of a lazily started image", .{});
    switch (why) {
        .deadline => diag.cause(
            "chunk {d} could not be fetched within {d} s; the reading process got EIO ({s})",
            .{ chunk, constants.lazy_read_deadline_ms / 1000, tried },
        ),
        .lied => diag.cause(
            "no source sent bytes that match chunk {d}'s hash; the reading process got EIO ({s})",
            .{ chunk, tried },
        ),
    }
    diag.context("object", "{s}", .{object.text()});
    switch (why) {
        .deadline => diag.fix(.{
            .sentence = "check the network and the registry, then read the file again",
        }),
        // Reading again does not help: this run asks no source that lied about the file.
        .lied => diag.fix(.{ .sentence = "tell the owner of the source that sent wrong bytes" }),
    }
    assert(diag.code == .E1203);
}

/// ZBX-E1206: the store's disk is too full to keep fetched chunks: the read got `EIO`.
pub fn store_full(diag: *Diag, object: Digest, chunk: u32) void {
    assert(diag.code == null);
    assert(constants.lazy_store_free_bytes_min > 0);
    diag.raise(.E1206);
    diag.while_("keeping a fetched chunk of a lazily started image", .{});
    diag.cause(
        "the store's disk has less than {d} MiB free; chunk {d} was not kept, the read got EIO",
        .{ constants.lazy_store_free_bytes_min / 4 / (1024 * 1024), chunk },
    );
    diag.context("object", "{s}", .{object.text()});
    diag.fix(.{ .sentence = "free space on the disk that holds the store, then read it again" });
}

test "E1201 names which of the host's lacks keeps a lazy run from FUSE" {
    // Goal: the three causes the brief asks E1201 to name, and its memory cause, each end with
    // the run-without-lazy fix. Method: build each diagnostic from the errno a failed open or
    // mount carries, and compare the newest cause (the one the default output shows).
    const testing = std.testing;
    const Case = struct { errno: u16, mount: bool, cause: []const u8 };
    const missing = "/dev/fuse is missing: the fuse module is not loaded";
    const denied = "/dev/fuse is not openable: this user may not open it";
    const refused = "the kernel refused the FUSE mount in the user namespace";
    const cases = [_]Case{
        .{ .errno = 2, .mount = false, .cause = missing },
        .{ .errno = 6, .mount = false, .cause = missing },
        .{ .errno = 13, .mount = false, .cause = denied },
        .{ .errno = 1, .mount = false, .cause = denied },
        .{ .errno = 12, .mount = false, .cause = "/dev/fuse could not be opened" },
        .{ .errno = 19, .mount = true, .cause = missing },
        .{ .errno = 13, .mount = true, .cause = denied },
        .{ .errno = 1, .mount = true, .cause = refused },
        .{ .errno = 22, .mount = true, .cause = refused },
    };
    var diag: Diag = undefined;
    for (cases) |case| {
        diag.reset();
        const err = host_mod.error_for_errno(case.errno);
        if (case.mount) {
            mount_refused(&diag, "mounting the image's tree over FUSE", err, case.errno);
        } else {
            device_refused(&diag, err, case.errno);
        }
        try testing.expectEqual(@as(?@import("../diag/codes.zig").Code, .E1201), diag.code);
        try testing.expectEqualStrings(case.cause, diag.last_cause().?);
        const last = diag.fixes.items[diag.fixes.count - 1].sentence.slice();
        try testing.expect(std.mem.indexOf(u8, last, "without --lazy") != null);
    }
    diag.reset();
    out_of_memory(&diag, Digest.of("a tree"));
    try testing.expectEqualStrings(
        "this host has too little free memory for its chunk buffers and tables",
        diag.last_cause().?,
    );
}
