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

const linux = std.os.linux;

/// A one-line human reason for the errnos a failing write or read most often reports. Any other
/// errno gets the generic, true wording in `cause_host_error`, never a guess.
fn errno_reason(code: linux.E) ?[]const u8 {
    const reason: ?[]const u8 = switch (code) {
        .PERM => "operation not permitted",
        .NOENT => "no such file or directory",
        .INTR => "interrupted by a signal",
        .IO => "input/output error",
        .BADF => "bad file descriptor",
        .AGAIN => "the resource is busy, try again",
        .NOMEM => "out of memory",
        .ACCES => "permission denied",
        .FAULT => "bad address",
        .NODEV => "no such device",
        .INVAL => "invalid argument",
        .FBIG => "file too large",
        .NOSPC => "no space left on the device",
        .PIPE => "broken pipe",
        .ROFS => "read-only file system",
        .NAMETOOLONG => "the path is too long",
        .NOSYS => "this kernel does not support it",
        .NODATA => "the file has no such attribute",
        .DQUOT => "disk quota exceeded",
        else => null,
    };
    if (reason) |text| assert(text.len > 0);
    return reason;
}

/// Failures made inside host.zig itself, with no kernel errno behind them.
fn reason_without_errno(err: host_mod.Error) ?[]const u8 {
    const reason: ?[]const u8 = switch (err) {
        error.FileTooLarge => "larger than the size limit zbx reads",
        error.Stalled => "the operation made no progress",
        error.PathTooLong, error.InvalidPath => "the path is not valid",
        else => null,
    };
    if (reason) |text| assert(text.len > 0);
    return reason;
}

/// Adds the cause "<operation> failed: <reason> (<ENAME>)", naming the errno the kernel really
/// returned (`Host.last_errno`, read by the caller right after the failure). `operation` names the
/// syscall or action in the caller's words, for example "write(stdout)". If the errno is missing
/// or does not match the error (it is stale), the cause says the errno is unknown rather than
/// naming a wrong one.
pub fn cause_host_error(
    diag: *Diag,
    operation: []const u8,
    err: host_mod.Error,
    errno: u16,
) void {
    assert(operation.len > 0);
    assert(errno < 4096);
    if (reason_without_errno(err)) |reason| {
        diag.cause("{s} failed: {s}", .{ operation, reason });
        return;
    }
    const matches = errno != 0 and host_mod.error_for_errno(errno) == err;
    if (!matches) {
        diag.cause("{s} failed (the errno is unknown)", .{operation});
        return;
    }
    const code: linux.E = @fromBackingInt(errno);
    const name = std.enums.tagName(linux.E, code);
    if (name == null) {
        diag.cause("{s} failed: the kernel returned errno {d}", .{ operation, errno });
    } else if (errno_reason(code)) |reason| {
        diag.cause("{s} failed: {s} (E{s})", .{ operation, reason, name.? });
    } else {
        diag.cause("{s} failed: the kernel returned E{s}", .{ operation, name.? });
    }
    assert(diag.causes.count > 0);
}

/// Classifies a failed write to stdout or stderr as `ZBX-E0009`, with the real errno.
pub fn output_failed(
    diag: *Diag,
    comptime stream: host_mod.Stream,
    err: host_mod.Error,
    errno: u16,
) void {
    diag.raise(.E0009);
    cause_host_error(diag, "write(" ++ @tagName(stream) ++ ")", err, errno);
    diag.fix(.{ .sentence = "free space or fix the redirect, then run the command again" });
    assert(diag.code.? == .E0009);
    assert(diag.fixes.count > 0);
}

test "causes name the real errno, or say it is unknown, never a guess" {
    // Goal: principle 4. Method: the errno decides the words; a mismatched or missing errno is
    // reported as unknown; errors made inside host.zig carry no errno at all.
    var diag: Diag = undefined;
    diag.reset();
    cause_host_error(&diag, "write(stdout)", error.IoFailed, 9);
    try std.testing.expectEqualStrings(
        "write(stdout) failed: bad file descriptor (EBADF)",
        diag.last_cause().?,
    );
    cause_host_error(&diag, "write(stdout)", error.NoSpace, 28);
    try std.testing.expectEqualStrings(
        "write(stdout) failed: no space left on the device (ENOSPC)",
        diag.last_cause().?,
    );
    cause_host_error(&diag, "write(stdout)", error.IoFailed, 0);
    try std.testing.expectEqualStrings(
        "write(stdout) failed (the errno is unknown)",
        diag.last_cause().?,
    );
    cause_host_error(&diag, "write(stdout)", error.NoSpace, 9); // Stale: EBADF is not NoSpace.
    try std.testing.expectEqualStrings(
        "write(stdout) failed (the errno is unknown)",
        diag.last_cause().?,
    );
    cause_host_error(&diag, "write(stdout)", error.IoFailed, 61 + 1000); // No such name.
    try std.testing.expectEqualStrings(
        "write(stdout) failed: the kernel returned errno 1061",
        diag.last_cause().?,
    );
    // Named, no table reason: ECONNREFUSED.
    cause_host_error(&diag, "read(x)", error.IoFailed, 111);
    try std.testing.expectEqualStrings(
        "read(x) failed: the kernel returned ECONNREFUSED",
        diag.last_cause().?,
    );
    cause_host_error(&diag, "read(x)", error.Stalled, 9);
    try std.testing.expectEqualStrings(
        "read(x) failed: the operation made no progress",
        diag.last_cause().?,
    );
}

test "every host error renders a cause for every errno that maps to it" {
    // Goal: the translation is total and never shows a raw Zig error name.
    inline for (@typeInfo(host_mod.Error).error_set.error_names.?) |name| {
        const err = @field(host_mod.Error, name);
        var errno: u16 = 0;
        while (errno < 200) : (errno += 1) {
            var diag: Diag = undefined;
            diag.reset();
            cause_host_error(&diag, "read(x)", err, errno);
            const text = diag.last_cause().?;
            try std.testing.expect(std.mem.startsWith(u8, text, "read(x) failed"));
            try std.testing.expect(std.mem.indexOf(u8, text, "error.") == null);
        }
    }
}
