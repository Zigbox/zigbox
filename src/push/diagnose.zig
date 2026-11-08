//! The diagnostics of packing and exporting.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const errors = @import("../diag/errors.zig");
const host_mod = @import("../host.zig");
const text_util = @import("../text.zig");
const Diag = @import("../diag/diag.zig").Diag;
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
