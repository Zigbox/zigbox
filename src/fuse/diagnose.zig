//! The lazy start's diagnostics that slice 4 raises (docs/briefs/S2-lazy-start.md,
//! "Diagnostics"): an image too large for the server's table (E1207) and `--lazy` with an
//! option it does not take (E1208). The rest of the 12xx group comes with slice 5.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;
const Digest = @import("../store/digest.zig").Digest;

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
