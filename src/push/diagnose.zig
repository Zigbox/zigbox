//! The diagnostics of packing and exporting.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const errors = @import("../diag/errors.zig");
const host_mod = @import("../host.zig");
const text_util = @import("../text.zig");
const Diag = @import("../diag/diag.zig").Diag;
const Sha256 = @import("../registry/digest.zig").Sha256;
const export_mod = @import("export.zig");
const pack = @import("pack.zig");

fn echo_of(storage: *[constants.arg_echo_bytes_max]u8, argument: []const u8) []const u8 {
    assert(argument.len <= constants.file_bytes_max);
    return text_util.sanitise(storage, argument);
}

/// ZBX-E0550: `operand` cannot be packed. `why` is a sentence naming the reason.
pub fn cannot_pack(diag: *Diag, operand: []const u8, why: []const u8) void {
    assert(diag.code == null);
    assert(why.len > 0);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, operand);
    diag.raise(.E0550);
    diag.while_("packing an image", .{});
    diag.cause("'{s}' cannot be packed: {s}", .{ echo, why });
    diag.context("source", "{s}", .{echo});
    diag.fix(.{ .sentence = "list what the store keeps:", .command = "zbx store ls" });
    assert(diag.code.? == .E0550);
}

/// ZBX-E0550 for a pack that stopped: the reason is the packer's sentence.
pub fn pack_stopped(diag: *Diag, operand: []const u8, failure: *const pack.Failure) void {
    assert(diag.code == null);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    if (failure.stop == .write) {
        diag.raise(.E0417);
        diag.while_("packing an image", .{});
        errors.cause_host_error(diag, failure.stop.sentence(), error.IoFailed, failure.errno);
        diag.context("source", "{s}", .{echo_of(&storage, operand)});
        diag.fix(.{ .sentence = "check that you can write to the store directory, and the disk" });
        return;
    }
    cannot_pack(diag, operand, failure.stop.sentence());
    diag.context("tree", "{s}", .{failure.digest.text()});
}

/// ZBX-E0557, or ZBX-E0417 when the directory could not be written.
pub fn export_stopped(diag: *Diag, dir: []const u8, failure: *const export_mod.Failure) void {
    assert(diag.code == null);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, dir);
    if (failure.stop == .write) {
        diag.raise(.E0417);
        diag.while_("writing the export directory", .{});
        var operation: [constants.arg_echo_bytes_max + 48]u8 = undefined;
        const what = std.fmt.bufPrint(&operation, "writing the export directory '{s}'", .{
            echo,
        }) catch unreachable; // Sized for the echo and the words.
        errors.cause_host_error(diag, what, failure.err, failure.errno);
        diag.context("path", "{s}", .{echo});
        diag.fix(.{ .sentence = "check that the directory's parent exists, that you can write" ++
            " there, and the disk" });
        return;
    }
    if (failure.stop == .damaged) {
        diag.raise(.E0550);
        diag.while_("writing an OCI layout", .{});
        diag.cause("stored blob {s} is damaged (not its digest) and was dropped", .{
            failure.digest.text(),
        });
        diag.context("path", "{s}", .{echo});
        diag.fix(.{ .sentence = "run the same command again, which makes the blob again" });
        return;
    }
    diag.raise(.E0557);
    diag.while_("writing an OCI layout", .{});
    const what = if (failure.stop == .not_empty) "is not empty" else "is not a directory";
    diag.cause("'{s}' {s}, and an export never writes into what is there", .{ echo, what });
    diag.context("path", "{s}", .{echo});
    diag.fix(.{ .sentence = "name a directory that does not exist, or an empty one" });
    assert(diag.code.? == .E0557);
}

/// What a registry's refusal of an upload says.
pub const Refusal = struct {
    /// The step, as a phrase: "closing the upload".
    step: []const u8,
    status: u16,
    /// The registry's own code ("BLOB_UPLOAD_INVALID"); empty for none.
    code: []const u8,
    /// A sentence about what zbx saw, for a refusal that is not a status; empty for none.
    detail: []const u8,
    retry_after: []const u8,
};

fn refusal_fix(diag: *Diag, refusal: Refusal) void {
    assert(refusal.status >= 200);
    switch (refusal.status) {
        401, 403 => diag.fix(.{ .sentence = "the registry wants credentials; this build of zbx" ++
            " pushes without any, so push to a registry that takes anonymous writes" }),
        429 => diag.fix(.{ .sentence = "wait, then run the same command again; what the" ++
            " registry already holds is not sent twice" }),
        else => diag.fix(.{ .sentence = "run the same command again; what the registry already" ++
            " holds is not sent twice" }),
    }
}

fn refusal_context(diag: *Diag, host: []const u8, refusal: Refusal) void {
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    diag.context("host", "{s}", .{echo_of(&storage, host)});
    diag.context("status", "{d}", .{refusal.status});
    if (refusal.code.len > 0) diag.context("code", "{s}", .{refusal.code});
    if (refusal.retry_after.len > 0) {
        diag.context("retry", "{s}", .{echo_of(&storage, refusal.retry_after)});
    }
}

/// ZBX-E0555: the registry refused a step of a blob's upload.
pub fn blob_refused(diag: *Diag, host: []const u8, digest: Sha256, refusal: Refusal) void {
    assert(diag.code == null);
    assert(refusal.step.len > 0);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const shown = echo_of(&storage, host);
    const name = digest.text();
    diag.raise(.E0555);
    diag.while_("pushing an image", .{});
    diag.cause("{s} refused {s} for blob {s}: it answered {d}", .{
        shown,
        refusal.step,
        name[0 .. "sha256:".len + 12],
        refusal.status,
    });
    if (refusal.detail.len > 0) diag.cause("{s}", .{refusal.detail});
    refusal_context(diag, host, refusal);
    diag.context("blob", "{s}", .{&name});
    refusal_fix(diag, refusal);
    assert(diag.code.? == .E0555);
}

/// ZBX-E0556: the registry refused the manifest, or answered with another digest.
pub fn manifest_refused(diag: *Diag, host: []const u8, tag: []const u8, refusal: Refusal) void {
    assert(diag.code == null);
    assert(refusal.step.len > 0);
    var host_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    var tag_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const shown = echo_of(&host_storage, host);
    const tag_shown = echo_of(&tag_storage, tag);
    diag.raise(.E0556);
    diag.while_("pushing an image", .{});
    diag.cause("{s} refused the manifest for tag '{s}': it answered {d}", .{
        shown,
        tag_shown,
        refusal.status,
    });
    if (refusal.detail.len > 0) diag.cause("{s}", .{refusal.detail});
    refusal_context(diag, host, refusal);
    refusal_fix(diag, refusal);
    assert(diag.code.? == .E0556);
}

/// ZBX-E0550: a blob the push has to send is not in the store, or is not its digest.
pub fn blob_unreadable(diag: *Diag, digest: Sha256) void {
    assert(diag.code == null);
    diag.raise(.E0550);
    diag.while_("pushing an image", .{});
    diag.cause("stored blob {s} is missing or damaged", .{&digest.text()});
    diag.context("blob", "{s}", .{&digest.text()});
    diag.fix(.{ .sentence = "run the same command again, which packs the image afresh" });
    assert(diag.code.? == .E0550);
}

/// ZBX-E0551: the destination of a push is not usable.
pub fn destination_refused(diag: *Diag, operand: []const u8, why: []const u8) void {
    assert(diag.code == null);
    assert(why.len > 0);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, operand);
    diag.raise(.E0551);
    diag.cause("'{s}' cannot be pushed to: {s}", .{ echo, why });
    diag.context("dest", "{s}", .{echo});
    diag.fix(.{ .sentence = "name a registry, a repository and a tag:" ++
        " registry.example/team/app:1.0" });
    assert(diag.code.? == .E0551);
}
