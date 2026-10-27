//! The diagnostics of unpacking layers, in one place: each function raises one registered code
//! (DIAGNOSTICS.md). The applier reports a `Failure` and facts; the words are here.
//!
//! An entry's path is shown cut and with unprintable bytes replaced, because it comes from an
//! archive nobody here wrote.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const errors = @import("../diag/errors.zig");
const text_util = @import("../text.zig");
const Diag = @import("../diag/diag.zig").Diag;
const apply = @import("apply.zig");
const reader_mod = @import("reader.zig");

const shown_bytes_max = 96;

const fix_untrusted = "do not run this image unless you built it, and check what it writes";
const fix_kept = "the downloaded blobs are kept, so the layers are not fetched again";
const fix_damaged = "the blob may be damaged on disk: remove it and pull again";
const fix_unusual = "the image is damaged or unusual; try another tag or build";

fn shown(storage: *[shown_bytes_max]u8, text: []const u8) []const u8 {
    assert(text.len <= apply.path_show_bytes);
    return text_util.sanitise(storage, text);
}

/// Which layer was being unpacked, for the message: counted from one.
pub const Place = struct {
    layer: u32,
    layers: u32,
    /// The store's directory, for a failure to write.
    root: []const u8,
};

/// ZBX-E0515, E0516, E0416 or E0417: the layer could not be unpacked, and why.
pub fn layer_refused(
    diag: *Diag,
    failure: *const apply.Failure,
    layer: *const reader_mod.Layer,
    place: Place,
) void {
    assert(diag.code == null);
    assert(place.layer >= 1);
    assert(place.layer <= place.layers);
    var storage: [shown_bytes_max]u8 = undefined;
    const path = shown(&storage, failure.path_text());
    if (failure.reason == .io or (failure.reason == .unreadable and layer.fault == .io)) {
        return write_failed(diag, failure, layer, place);
    }
    diag.raise(if (failure.reason.unsafe()) .E0515 else .E0516);
    diag.while_("unpacking layer {d} of {d}", .{ place.layer, place.layers });
    switch (failure.reason) {
        .absolute => diag.cause("layer {d} has '{s}', an absolute path", .{ place.layer, path }),
        .escapes => diag.cause(
            "layer {d} has '{s}', with a '..' that could leave the image's root",
            .{ place.layer, path },
        ),
        .through_symlink => diag.cause(
            "layer {d} has '{s}', which goes through a symlink",
            .{ place.layer, path },
        ),
        .link_target => diag.cause(
            "layer {d} has '{s}', a hard link to a path outside the image",
            .{ place.layer, path },
        ),
        .damaged, .unsupported, .too_long => unreadable_entry(diag, failure, path, place.layer),
        .too_big => diag.cause("layer {d} holds more than 64 GiB of files", .{place.layer}),
        .parent_not_directory => diag.cause(
            "layer {d}: a parent of '{s}' is a file, not a directory",
            .{ place.layer, path },
        ),
        .missing_link_target => diag.cause(
            "layer {d}: '{s}' is a hard link to a file the image lacks",
            .{ place.layer, path },
        ),
        .bad_whiteout => diag.cause(
            "layer {d}: '{s}' is a whiteout with no valid name to remove",
            .{ place.layer, path },
        ),
        .unmapped_owner => diag.cause(
            "layer {d}: the owner of '{s}' is outside the ids this user namespace maps",
            .{ place.layer, path },
        ),
        .unreadable => unreadable_stream(diag, layer, place.layer),
        .io => unreachable, // Handled above.
    }
    if (path.len > 0) diag.context("entry", "{s}", .{path});
    diag.context("layer", "{d}", .{place.layer});
    fixes(diag, failure.reason);
    assert(diag.code != null);
}

fn unreadable_entry(diag: *Diag, failure: *const apply.Failure, path: []const u8, layer: u32) void {
    if (path.len > 0) {
        diag.cause("layer {d}: '{s}' can't be unpacked: {s}", .{ layer, path, failure.detail });
    } else {
        diag.cause("layer {d} can't be unpacked: {s}", .{ layer, failure.detail });
    }
}

fn unreadable_stream(diag: *Diag, layer: *const reader_mod.Layer, number: u32) void {
    switch (layer.fault) {
        .corrupt => |word| diag.cause(
            "layer {d}'s compressed stream is damaged ({s})",
            .{ number, word },
        ),
        .empty => diag.cause("layer {d}'s blob is empty", .{number}),
        .none => diag.cause("layer {d} could not be read", .{number}),
        .io => unreachable, // Handled by the caller: it is a file system failure.
    }
}

fn fixes(diag: *Diag, reason: apply.Reason) void {
    if (reason.unsafe()) {
        diag.fix(.{ .sentence = fix_untrusted });
        diag.fix(.{ .sentence = fix_kept });
        return;
    }
    switch (reason) {
        .unreadable => diag.fix(.{ .sentence = fix_damaged }),
        .unmapped_owner => diag.fix(.{
            .sentence = "run `zbx doctor`: the subordinate id range may be too small",
        }),
        else => diag.fix(.{ .sentence = fix_unusual }),
    }
}

/// ZBX-E0416 for a full disk and ZBX-E0417 for any other failure of the file system.
fn write_failed(
    diag: *Diag,
    failure: *const apply.Failure,
    layer: *const reader_mod.Layer,
    place: Place,
) void {
    var err = failure.err;
    var errno = failure.errno;
    var step: []const u8 = failure.step;
    if (failure.reason == .unreadable) {
        err = layer.fault.io.err;
        errno = layer.fault.io.errno;
        step = "reading the layer blob";
    }
    const full = err == error.NoSpace;
    diag.raise(if (full) .E0416 else .E0417);
    diag.while_("unpacking layer {d} of {d}", .{ place.layer, place.layers });
    errors.cause_host_error(diag, step, err, errno);
    diag.context("path", "{s}", .{place.root});
    if (full) {
        diag.fix_with(
            "free space on the disk that holds the store, then run the same command again:",
            "df -h '{s}'",
            .{place.root},
        );
    } else {
        diag.fix(.{ .sentence = "check that you can write to the store directory, and the disk" });
    }
}

/// ZBX-W0501: devices, FIFOs and sockets were left out.
pub fn special_skipped(diag: *Diag, count: u64, first: []const u8) void {
    assert(diag.code == null);
    assert(count > 0);
    var storage: [shown_bytes_max]u8 = undefined;
    const path = shown(&storage, first);
    diag.raise(.W0501);
    diag.while_("unpacking the layers", .{});
    diag.cause(
        "{d} device nodes, FIFOs or sockets were left out; the first is '{s}'",
        .{ count, path },
    );
    diag.context("count", "{d}", .{count});
    diag.context("path", "{s}", .{path});
    diag.fix(.{ .sentence = "nothing to do: a container makes its own /dev" });
}

/// ZBX-W0502: extended attributes were left out.
pub fn xattrs_skipped(diag: *Diag, count: u64, first: []const u8) void {
    assert(diag.code == null);
    assert(count > 0);
    var storage: [shown_bytes_max]u8 = undefined;
    const path = shown(&storage, first);
    diag.raise(.W0502);
    diag.while_("unpacking the layers", .{});
    diag.cause(
        "{d} extended attributes were left out; the first is on '{s}'",
        .{ count, path },
    );
    diag.context("count", "{d}", .{count});
    diag.context("path", "{s}", .{path});
    diag.fix(.{ .sentence = "nothing to do unless the image relies on file capabilities" });
}
