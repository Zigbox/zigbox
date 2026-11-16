//! The lazy start's diagnostics that slice 4 raises (docs/briefs/S2-lazy-start.md,
//! "Diagnostics"): an image too large for the server's table (E1207) and `--lazy` with an
//! option it does not take (E1208); and slice 5's: the start from a registry (W1201, E1202)
//! and the reads it serves (W1202, E1203, E1206).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;
const Digest = @import("../store/digest.zig").Digest;

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
    if (std.mem.eql(u8, flag, "-d")) {
        // A scope cut, not a rule: a detached lazy run, served by the supervisor, is a later
        // slice's (docs/demos/s2.md).
        diag.cause("'--lazy' does not yet support '-d': its files are served by this zbx " ++
            "process, which a detached run leaves", .{});
    } else {
        diag.cause("'--lazy' serves an image from the store to a run in the foreground, and " ++
            "does not take '{s}'", .{flag});
    }
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
    diag.cause("{s} sent bytes that do not match chunk {d}'s hash; none were used", .{
        source,
        chunk,
    });
    diag.context("object", "{s}", .{object.text()});
    diag.context("source", "{s}", .{source});
    diag.fix(.{ .sentence = "nothing to do here: the next source is asked; tell its owner" });
}

/// ZBX-E1203: no source gave chunk `chunk` of `object` within `lazy_read_deadline_ms`: the
/// reading process got `EIO`. `tried` is what each source did, already rendered.
pub fn chunk_unavailable(diag: *Diag, object: Digest, chunk: u32, tried: []const u8) void {
    assert(tried.len > 0);
    assert(diag.code == null);
    diag.raise(.E1203);
    diag.while_("fetching a chunk of a lazily started image", .{});
    diag.cause(
        "chunk {d} could not be fetched within {d} s; the reading process got EIO ({s})",
        .{ chunk, constants.lazy_read_deadline_ms / 1000, tried },
    );
    diag.context("object", "{s}", .{object.text()});
    diag.fix(.{ .sentence = "check the network and the registry, then read the file again" });
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
