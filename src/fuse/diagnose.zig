//! The lazy start's diagnostics that slice 4 raises (docs/briefs/S2-lazy-start.md,
//! "Diagnostics"): an image too large for the server's table (E1207) and `--lazy` with an
//! option it does not take (E1208). The rest of the 12xx group comes with slice 5.

const assert = @import("std").debug.assert;
const Diag = @import("../diag/diag.zig").Diag;
const Digest = @import("../store/digest.zig").Digest;

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
    diag.cause("'--lazy' serves an image from the store to a run in the foreground, and does " ++
        "not take '{s}'", .{flag});
    diag.context("cmd", "run", .{});
    diag.context("arg", "{s}", .{flag});
    diag.fix(.{ .sentence = "leave out --lazy, or the other option" });
}
