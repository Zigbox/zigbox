//! Opening the store for a command: find its directory, check `store.zon`, and create the layout
//! when the command writes. A command that only reads does not create a store: `ls` of a store
//! that does not exist is an empty list.
//!
//! Creating is crash-safe in the way everything else is: the directories first (each `mkdir` is
//! harmless to repeat), `store.zon` last, written atomically. A store without `store.zon` is
//! not yet a store, so an interrupted creation is finished by the next command.

const std = @import("std");
const assert = std.debug.assert;
const Diag = @import("../diag/diag.zig").Diag;
const host_mod = @import("../host.zig");
const diagnose = @import("diagnose.zig");
const fs_mod = @import("fs.zig");
const layout = @import("layout.zig");

const Host = host_mod.Host;
const PathBuf = fs_mod.PathBuf;
const Store = layout.Store;

pub const Error = error{Failed};

pub const Mode = enum {
    /// A command that writes: make the store if it is not there.
    create,
    /// A command that reads: report that there is no store.
    existing,
};

/// Fills `store` and checks its format. Returns false for a store that does not exist, which
/// only `Mode.existing` can see. A refusal is in `diag`.
pub fn open(host: Host, store: *Store, mode: Mode, diag: *Diag) Error!bool {
    assert(@intFromPtr(store) != 0);
    assert(diag.code == null);
    if (!store.locate(host)) {
        diagnose.no_data_directory(diag);
        return error.Failed;
    }
    return check(store, mode, diag);
}

/// The same for a store that is already located (`Store.at`), for tests and library callers.
pub fn check(store: *Store, mode: Mode, diag: *Diag) Error!bool {
    assert(store.root_len > 1);
    assert(diag.code == null);
    switch (layout.read_format(store)) {
        .ok => return true,
        .absent => {},
        else => |format| {
            diagnose.format_unusable(diag, store, format);
            return error.Failed;
        },
    }
    if (mode == .existing) return false;
    try create(store, diag);
    return true;
}

fn failed(store: *const Store, diag: *Diag, step: []const u8, err: host_mod.Error) Error {
    assert(step.len > 0);
    assert(diag.code == null);
    diagnose.write_failed(diag, store, step, err, store.fs.last_errno());
    return error.Failed;
}

/// Makes the directories of the layout, then `store.zon`.
fn create(store: *Store, diag: *Diag) Error!void {
    assert(store.existing_len < store.root_len);
    assert(layout.subdirectories.len == 6);
    const fs = store.fs;
    const root = store.root_text();
    var at: usize = store.existing_len;
    while (at < root.len) {
        // The next component ends at the next slash, or at the end of the path.
        const next = std.mem.indexOfScalarPos(u8, root, at + 1, '/') orelse root.len;
        var prefix: PathBuf = undefined;
        prefix.set(&.{root[0..next]}) catch unreachable; // A prefix of a path that fit.
        fs.make_directory(prefix.text(), true) catch |err| {
            return failed(store, diag, "creating the store directory", err);
        };
        at = next;
    }
    for (layout.subdirectories) |name| {
        var path: PathBuf = undefined;
        fs.make_directory(store.directory_path(&path, name), true) catch |err| {
            return failed(store, diag, "creating a store directory", err);
        };
    }
    var text_storage: [64]u8 = undefined;
    const text = layout.format_text(&text_storage);
    var temporary: PathBuf = undefined;
    var final: PathBuf = undefined;
    const temporary_path = store.tmp_path(&temporary);
    const final_path = store.path(&final, &.{ "/", layout.format_file });
    var failure: fs_mod.Failure = undefined;
    fs.write_atomic(temporary_path, final_path, root, text, 0o644, &failure) catch {
        diagnose.write_failed(diag, store, "writing store.zon", failure.err, failure.errno);
        return error.Failed;
    };
}
