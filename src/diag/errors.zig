//! Translation of host failures into diagnostic causes, in one place (DIAGNOSTICS.md, "Syscall
//! failures are translated once"). Callers say which operation failed; this file knows how each
//! host error reads to a person, and which errno it stands for.
//!
//! `host.Error` is deliberately coarse (host_real.zig collapses errnos into it), so the errno
//! shown is the representative one for the variant, and `IoFailed` says "other" rather than
//! guessing. Slice 5 may widen the host layer if a doctor diagnostic needs the exact errno.

const std = @import("std");
const assert = std.debug.assert;
const host_mod = @import("../host.zig");
const Diag = @import("diag.zig").Diag;

const Explained = struct {
    /// The representative errno, or empty for failures that are not an errno (limits, stalls).
    errno: []const u8,
    reason: []const u8,
};

fn explain(err: host_mod.Error) Explained {
    const explained: Explained = switch (err) {
        error.NotFound => .{ .errno = "ENOENT", .reason = "no such file or directory" },
        error.AccessDenied => .{ .errno = "EACCES", .reason = "permission denied" },
        error.Interrupted => .{ .errno = "EINTR", .reason = "interrupted by a signal" },
        error.WouldBlock => .{ .errno = "EAGAIN", .reason = "the resource is busy, try again" },
        error.NoSpace => .{ .errno = "ENOSPC", .reason = "no space left on the device" },
        error.OutOfMemory => .{ .errno = "ENOMEM", .reason = "out of memory" },
        error.PathTooLong => .{ .errno = "ENAMETOOLONG", .reason = "the path is too long" },
        error.InvalidPath => .{ .errno = "EINVAL", .reason = "the path is not valid" },
        error.FileTooLarge => .{ .errno = "", .reason = "larger than the size limit zbx reads" },
        error.Stalled => .{ .errno = "", .reason = "the operation made no progress" },
        error.Unsupported => .{ .errno = "ENOSYS", .reason = "this kernel does not support it" },
        error.NoData => .{ .errno = "ENODATA", .reason = "the file has no such attribute" },
        error.IoFailed => .{ .errno = "EIO", .reason = "input/output error (or another errno)" },
    };
    assert(explained.reason.len > 0);
    assert(explained.errno.len <= 12);
    return explained;
}

/// Adds the cause "<operation> failed: <reason> (<errno>)". `operation` names the syscall or
/// action in the caller's words, for example "write(stdout)".
pub fn cause_host_error(diag: *Diag, operation: []const u8, err: host_mod.Error) void {
    assert(operation.len > 0);
    const explained = explain(err);
    if (explained.errno.len == 0) {
        diag.cause("{s} failed: {s}", .{ operation, explained.reason });
    } else {
        diag.cause("{s} failed: {s} ({s})", .{ operation, explained.reason, explained.errno });
    }
    assert(diag.causes.count > 0);
}

/// Classifies a failed write to stdout or stderr as `ZBX-E0009`, with the host's reason.
pub fn output_failed(diag: *Diag, comptime stream: host_mod.Stream, err: host_mod.Error) void {
    diag.raise(.E0009);
    cause_host_error(diag, "write(" ++ @tagName(stream) ++ ")", err);
    diag.fix(.{ .sentence = "free space or fix the redirect, then run the command again" });
    assert(diag.code.? == .E0009);
    assert(diag.fixes.count > 0);
}

test "every host error has a reason and a cause line" {
    // Goal: the translation is total; no variant renders empty or without its operation.
    inline for (@typeInfo(host_mod.Error).error_set.error_names.?) |name| {
        const err = @field(host_mod.Error, name);
        var diag: Diag = undefined;
        diag.reset();
        cause_host_error(&diag, "read(x)", err);
        const text = diag.last_cause().?;
        try std.testing.expect(std.mem.startsWith(u8, text, "read(x) failed: "));
        try std.testing.expect(std.mem.indexOf(u8, text, "error.") == null);
    }
}

test "an output failure is E0009 with the stream and errno named" {
    var diag: Diag = undefined;
    diag.reset();
    output_failed(&diag, .stdout, error.NoSpace);
    try std.testing.expectEqual(@as(u8, 2), diag.exit_code());
    try std.testing.expectEqualStrings(
        "write(stdout) failed: no space left on the device (ENOSPC)",
        diag.last_cause().?,
    );
}
