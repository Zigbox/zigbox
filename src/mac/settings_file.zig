//! The settings record on disk: read at every boot, written by `zbx vm config`. A missing file
//! is not an error: the machine boots with the defaults.

const std = @import("std");
const assert = std.debug.assert;
const files = @import("files.zig");
const paths_mod = @import("paths.zig");
const settings = @import("settings.zig");
const diagnose = @import("diagnose.zig");
const Diag = @import("../diag/diag.zig").Diag;

pub const Source = enum { default, settings };

pub const Loaded = struct {
    values: settings.Settings,
    source: Source,
};

/// The values the next boot uses. A damaged or newer record is `E1008` in `diag`.
pub fn load(paths: *const paths_mod.Paths, host_cpus: u32, diag: *Diag) error{Failed}!Loaded {
    assert(paths.settings.length > 0);
    assert(diag.code == null);
    assert(host_cpus >= 1);
    var buffer: [settings.record_bytes_max + 1]u8 = undefined;
    const path = paths.settings.slice();
    const text = files.read_file(path, &buffer) catch |err| switch (err) {
        error.Failed => {
            if (std.mem.eql(u8, files.reason(), "no such file or directory")) {
                return .{ .values = settings.defaults(host_cpus), .source = .default };
            }
            const doing = "reading the virtual machine's settings";
            diagnose.directory(diag, doing, path, files.reason());
            return error.Failed;
        },
        else => {
            diagnose.settings_unreadable(diag, path, false);
            return error.Failed;
        },
    };
    const values = settings.parse(text) catch |err| {
        diagnose.settings_unreadable(diag, path, err == error.NewerVersion);
        return error.Failed;
    };
    return .{ .values = values, .source = .settings };
}

pub fn save(
    paths: *const paths_mod.Paths,
    values: settings.Settings,
    diag: *Diag,
) error{Failed}!void {
    assert(paths.settings.length > 0);
    assert(values.cpus >= 1);
    assert(diag.code == null);
    var buffer: [settings.record_bytes_max]u8 = undefined;
    const text = settings.render(&buffer, values);
    const path = paths.settings.slice();
    files.make_directories(paths.base.slice()) catch {
        const doing = "saving the virtual machine's settings";
        diagnose.directory(diag, doing, paths.base.slice(), files.reason());
        return error.Failed;
    };
    files.write_file_atomically(path, text, 0o600) catch {
        diagnose.directory(diag, "saving the virtual machine's settings", path, files.reason());
        return error.Failed;
    };
}
