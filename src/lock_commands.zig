//! `zbx lock show`: the project's `zbx.lock`, read the way `run` reads it (the nearest one up
//! from the working directory) and printed: its path and, for each entry, the reference, the
//! manifest, the platform and the tree. Text is a table; `--output json` is the `zbx.lock/1`
//! document (`zbx schema lock-show`). It only reads: the lock stays a file people edit and
//! commit, and a lock that cannot be read is the same diagnostic `run` gives for it.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const bundle = @import("bundle.zig");
const errors = @import("diag/errors.zig");
const host_mod = @import("host.zig");
const image_diagnose = @import("image_diagnose.zig");
const lock_file = @import("lock_file.zig");
const text_util = @import("text.zig");
const Diag = @import("diag/diag.zig").Diag;

const Host = host_mod.Host;

pub const Error = error{ Failed, OutputFailed };

/// The largest piece written at once: a JSON entry with its reference escaped, or the path.
const piece_bytes_max = constants.path_bytes_max * 6 + 256;

comptime {
    // An entry's reference is at most `reference_bytes_max` bytes, six times that escaped.
    assert(constants.reference_bytes_max * 6 + 512 <= piece_bytes_max);
}

fn write(host: Host, text: []const u8, diag: *Diag) Error!void {
    assert(text.len > 0);
    assert(text.len <= piece_bytes_max);
    host.write_all(.stdout, text) catch |err| {
        errors.output_failed(diag, .stdout, err, host.last_errno());
        return error.OutputFailed;
    };
}

/// Prints the lock. `workspace` is the caller's, with room for a lock of the largest size.
pub fn run_show(host: Host, workspace: *lock_file.Workspace, json: bool, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(workspace.text.len == constants.lock_file_bytes_max);
    var failure: lock_file.Failure = undefined;
    lock_file.open_project(host, host.filesystem(), workspace, &failure) catch {
        const located = &workspace.located;
        const path = if (located.len > 0) located.text() else lock_file.file_name;
        image_diagnose.lock_failure(diag, path, failure);
        return error.Failed;
    };
    if (!workspace.located.exists) {
        image_diagnose.no_lock(diag, workspace.located.directory());
        return error.Failed;
    }
    assert(workspace.lock.count <= constants.lock_entries_max);
    if (json) return show_json(host, workspace, diag);
    return show_text(host, workspace, diag);
}

fn show_text(host: Host, workspace: *const lock_file.Workspace, diag: *Diag) Error!void {
    assert(workspace.located.exists);
    var buffer: [piece_bytes_max]u8 = undefined;
    var safe: [constants.store_source_bytes_max]u8 = undefined;
    const lock = &workspace.lock;
    var head: [constants.path_bytes_max + 32]u8 = undefined;
    const path = text_util.sanitise(&safe, workspace.located.text());
    // Cannot fail: a path cut to 1024 bytes and a few words.
    const plural = if (lock.count == 1) "" else "s";
    const format = "{s}: {d} image{s}\n";
    const first = std.fmt.bufPrint(&head, format, .{ path, lock.count, plural }) catch
        unreachable; // Same bound.
    try write(host, first, diag);
    if (lock.count == 0) return;
    const columns = "{s: <34} {s: <71} {s: <12} {s}\n";
    // Cannot fail: the columns are fixed and the words short.
    const names = .{ "IMAGE", "MANIFEST", "PLATFORM", "TREE" };
    const title = std.fmt.bufPrint(&buffer, columns, names) catch unreachable; // Same bound.
    try write(host, title, diag);
    for (lock.entries[0..lock.count]) |*entry| {
        const reference = text_util.sanitise(&safe, lock.reference(entry));
        // Cannot fail: a reference cut to 1024 bytes and fixed-width digests.
        const row = std.fmt.bufPrint(&buffer, columns, .{
            reference, &entry.manifest.text(), entry.platform_text(), entry.tree.text(),
        }) catch unreachable; // Same bound.
        try write(host, row, diag);
    }
}

fn show_json(host: Host, workspace: *const lock_file.Workspace, diag: *Diag) Error!void {
    assert(workspace.located.exists);
    var buffer: [piece_bytes_max]u8 = undefined;
    const lock = &workspace.lock;
    var writer = std.Io.Writer.fixed(&buffer);
    // Cannot fail: a path of at most 4095 bytes escaped six times over fits the buffer.
    writer.writeAll("{\"schema\":\"zbx.lock/1\",\"path\":") catch unreachable; // Same bound.
    bundle.write_json_string(&writer, workspace.located.text()) catch unreachable; // Same.
    writer.writeAll(",\"images\":[") catch unreachable; // Same bound.
    try write(host, writer.buffered(), diag);
    for (lock.entries[0..lock.count], 0..) |*entry, index| {
        writer = std.Io.Writer.fixed(&buffer);
        // Cannot fail: a reference of at most 1024 bytes escaped, and fixed-width digests.
        if (index > 0) writer.writeByte(',') catch unreachable; // Same bound.
        writer.writeAll("{\"reference\":") catch unreachable; // Same bound.
        bundle.write_json_string(&writer, lock.reference(entry)) catch unreachable; // Same.
        writer.print(",\"manifest\":\"{s}\",\"platform\":\"{s}\",\"tree\":\"{s}\"}}", .{
            &entry.manifest.text(), entry.platform_text(), entry.tree.text(),
        }) catch unreachable; // Same bound.
        try write(host, writer.buffered(), diag);
    }
    try write(host, "]}\n", diag);
}
