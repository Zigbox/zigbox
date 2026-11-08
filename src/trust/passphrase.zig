//! Getting a passphrase (M8): from the first line of a file only the user can read, or typed on
//! the terminal with echo off, and from nowhere else. Standard input is read only when it and
//! standard error are both terminals, so a script that forgot `--passphrase-file` is refused
//! instead of hanging or, worse, taking a line of its own input for a passphrase.
//!
//! The bytes are the caller's, in a buffer it zeroes after use; no function here prints them.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const fs_mod = @import("../store/fs.zig");
const diagnose = @import("diagnose.zig");
const key = @import("key.zig");

const Host = host_mod.Host;
const Problem = diagnose.PassphraseProblem;

/// A passphrase: `bytes[0..length]`. The caller zeroes the whole of it when done.
pub const Passphrase = struct {
    bytes: [constants.passphrase_bytes_max]u8,
    length: u32,

    pub fn text(passphrase: *const Passphrase) []const u8 {
        assert(passphrase.length > 0);
        return passphrase.bytes[0..passphrase.length];
    }

    pub fn wipe(passphrase: *Passphrase) void {
        std.crypto.secureZero(u8, &passphrase.bytes);
        passphrase.length = 0;
    }
};

pub const Error = error{Failed};

/// Where the passphrase can come from, in the order of trying: a file when one was named,
/// otherwise the terminal when both streams are one, otherwise nowhere.
pub fn available(host: Host, file: ?[]const u8) bool {
    if (file != null) return true;
    return host.input_is_terminal() and host.is_terminal(.stderr);
}

/// The passphrase for `name`: from `file`, or from the terminal (asked twice when `confirm`).
/// A failure sets `problem`. Nothing is read from standard input unless it is a terminal.
pub fn acquire(
    host: Host,
    file: ?[]const u8,
    name: []const u8,
    confirm: bool,
    out: *Passphrase,
    problem: *Problem,
) Error!void {
    assert(name.len > 0);
    out.length = 0;
    if (file) |path| return from_file(host, path, out, problem);
    if (!available(host, null)) {
        problem.* = .unavailable;
        return error.Failed;
    }
    try from_terminal(host, name, confirm, out, problem);
    assert(out.length > 0);
}

fn from_file(host: Host, path: []const u8, out: *Passphrase, problem: *Problem) Error!void {
    var path_buffer: fs_mod.PathBuf = undefined;
    path_buffer.set(&.{path}) catch return fail(problem, .file_unreadable);
    if (path.len == 0) return fail(problem, .file_unreadable);
    const fs = host.filesystem();
    // A link is refused with its own cause: it is what a secrets volume mounts, and "could not
    // be read" would hide why. The file it points to is read as itself.
    if (fs.lstat(path_buffer.text())) |linked| {
        if (linked.kind == .symlink) return fail(problem, .file_is_link);
    } else |err| {
        return fail(problem, if (err == error.NotFound) .file_missing else .file_unreadable);
    }
    const fd = fs.open_read(path_buffer.text()) catch |err| {
        return fail(problem, if (err == error.NotFound) .file_missing else .file_unreadable);
    };
    defer fs.close(fd);
    const stat = fs.fstat(fd) catch return fail(problem, .file_unreadable);
    if (stat.kind != .file) return fail(problem, .file_unreadable);
    if (key.mode_too_open(stat.mode)) return fail(problem, .file_too_open);
    var buffer: [constants.passphrase_file_bytes_max]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    const length = fs.read_full(fd, &buffer) catch return fail(problem, .file_unreadable);
    const line_end = std.mem.indexOfScalar(u8, buffer[0..length], '\n') orelse length;
    if (line_end > constants.passphrase_bytes_max) return fail(problem, .too_long);
    if (line_end == buffer.len) return fail(problem, .too_long);
    if (line_end == 0) return fail(problem, .empty);
    @memcpy(out.bytes[0..line_end], buffer[0..line_end]);
    out.length = @intCast(line_end);
}

fn fail(problem: *Problem, which: Problem) Error {
    problem.* = which;
    return error.Failed;
}

fn from_terminal(
    host: Host,
    name: []const u8,
    confirm: bool,
    out: *Passphrase,
    problem: *Problem,
) Error!void {
    assert(host.input_is_terminal());
    var saved: host_mod.TerminalSaved = undefined;
    saved.valid = false;
    host.input_raw(true, &saved) catch return fail(problem, .unavailable);
    defer host.input_raw(false, &saved) catch {}; // Echo is back on every way out.
    var prompt: [constants.key_name_bytes_max + 32]u8 = undefined;
    const first = std.fmt.bufPrint(&prompt, "Passphrase for key '{s}': ", .{name}) catch
        unreachable; // The name is at most key_name_bytes_max.
    try read_line(host, first, out, problem);
    if (!confirm) return;
    var again: Passphrase = undefined;
    defer again.wipe();
    try read_line(host, "Again: ", &again, problem);
    const same = again.length == out.length and
        std.crypto.timing_safe.eql([constants.passphrase_bytes_max]u8, again.bytes, out.bytes);
    if (!same) {
        out.wipe();
        return fail(problem, .mismatch);
    }
}

/// One line typed with echo off, ended by Enter. Backspace erases; Ctrl-C, Ctrl-D, Ctrl-Z and
/// Ctrl-\ cancel, so that none of them becomes a byte of the passphrase.
fn read_line(host: Host, prompt: []const u8, out: *Passphrase, problem: *Problem) Error!void {
    assert(prompt.len > 0);
    @memset(&out.bytes, 0);
    out.length = 0;
    host.write_all(.stderr, prompt) catch return fail(problem, .unavailable);
    // Raw mode has output processing off: a bare newline would not return the cursor.
    defer host.write_all(.stderr, "\r\n") catch {};
    while (true) {
        var byte: [1]u8 = undefined;
        const count = host.read_some(host.standard_input(), &byte) catch
            return fail(problem, .unavailable);
        if (count == 0) {
            if (out.length == 0) return fail(problem, .cancelled);
            return;
        }
        switch (byte[0]) {
            '\n', '\r' => break,
            3, 4, 26, 28 => { // Ctrl-C, Ctrl-D, Ctrl-Z, Ctrl-\: signals are off, so cancel here.
                out.wipe();
                return fail(problem, .cancelled);
            },
            8, 127 => erase(out),
            else => {
                if (out.length == constants.passphrase_bytes_max) {
                    out.wipe();
                    return fail(problem, .too_long);
                }
                out.bytes[out.length] = byte[0];
                out.length += 1;
            },
        }
    }
    if (out.length == 0) return fail(problem, .empty);
}

/// Removes the last character: its continuation bytes and then its first.
fn erase(out: *Passphrase) void {
    while (out.length > 0) {
        out.length -= 1;
        const was = out.bytes[out.length];
        out.bytes[out.length] = 0;
        if (was & 0xC0 != 0x80) break;
    }
}
