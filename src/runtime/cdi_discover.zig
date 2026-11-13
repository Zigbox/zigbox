//! Finds the CDI specs of the host and resolves the devices a run asked for (M10 slice 2).
//! Directories, the first that has a device deciding it (as in the reference implementation,
//! where a later directory in `/etc/cdi`, `/var/run/cdi` order overrides an earlier one):
//! `$XDG_CONFIG_HOME/cdi` (`$HOME/.config/cdi` when it is unset), `/var/run/cdi`, `/etc/cdi`,
//! each read in name order, at most `cdi_dir_entries_max` spec files in all (more is refused). What the specs name is then looked at on the host:
//! a mount's source must be there (E0226) and a node must be one the caller can open (E0225).

const std = @import("std");
const assert = std.debug.assert;
const cdi = @import("cdi.zig");
const cdi_diagnose = @import("cdi_diagnose.zig");
const constants = @import("../constants.zig");
const devices = @import("devices.zig");
const devices_diagnose = @import("devices_diagnose.zig");
const host_mod = @import("../host.zig");
const Diag = @import("../diag/diag.zig").Diag;

const Host = host_mod.Host;

/// What resolving needs while it runs and the run does not keep: far too big for a stack, so the
/// caller gives it a place (the run's handle, or the resolving function's own frame for a
/// caller that has the room).
pub const Scratch = struct {
    parsed: cdi.Parsed,
    resolver: cdi.Resolver,
    listing: host_mod.DirListing,
    content: [constants.cdi_spec_bytes_max + 1]u8,
    files: u32,
    /// The directory that had more spec files than the bound (set with `too_many_files`).
    overflow: [constants.cdi_path_bytes_max + 1]u8,
    overflow_len: u32,
};

const fixed_directories = [_][:0]const u8{ "/var/run/cdi", "/etc/cdi" };
const config_suffix = "/cdi";
const config_default = "/.config";

/// Resolves `asked` (qualified names) into `out`. On a refusal the diagnostic is raised and the
/// result is false.
pub fn resolve(
    host: Host,
    asked: []const []const u8,
    scratch: *Scratch,
    out: *cdi.Resolved,
    diag: *Diag,
) bool {
    assert(asked.len > 0);
    assert(asked.len <= constants.run_devices_max);
    scratch.resolver.init(asked, &scratch.parsed, out);
    scratch.files = 0;
    scratch.overflow_len = 0;
    var refusal: ?cdi.Refusal = null;
    var path: [constants.cdi_path_bytes_max + 1]u8 = undefined;
    if (config_directory(host, &path)) |directory| {
        refusal = read_directory(host, directory, scratch);
    }
    for (fixed_directories) |directory| {
        if (refusal == null) refusal = read_directory(host, directory, scratch);
    }
    if (refusal == null) refusal = scratch.resolver.finish();
    if (refusal) |found| return refuse(asked, scratch, found, diag);
    return looked_at(host, scratch, out, diag);
}

fn config_directory(host: Host, buffer: *[constants.cdi_path_bytes_max + 1]u8) ?[:0]const u8 {
    const room = constants.cdi_path_bytes_max - config_default.len - config_suffix.len;
    var total: usize = 0;
    const config = host.environment("XDG_CONFIG_HOME", room);
    if (config != null and config.?.len > 0 and config.?[0] == '/') {
        total = append(buffer, total, config.?);
    } else {
        const home = host.environment("HOME", room) orelse return null;
        if (home.len == 0 or home[0] != '/') return null;
        total = append(buffer, total, home);
        total = append(buffer, total, config_default);
    }
    total = append(buffer, total, config_suffix);
    buffer[total] = 0;
    return buffer[0..total :0];
}

fn append(buffer: *[constants.cdi_path_bytes_max + 1]u8, at: usize, text: []const u8) usize {
    assert(at + text.len <= constants.cdi_path_bytes_max);
    @memcpy(buffer[at..][0..text.len], text);
    return at + text.len;
}

fn is_spec_name(name: []const u8) bool {
    const suffixes = [_][]const u8{ ".json", ".yaml", ".yml" };
    for (suffixes) |suffix| {
        if (std.mem.endsWith(u8, name, suffix)) return true;
    }
    return false;
}

fn name_less(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.lessThan(u8, left, right);
}

/// Reads the spec files of one directory, in name order (all of them are listed and sorted
/// before one is read, so the order does not depend on the file system). A directory that is not
/// there is not a problem; a refusal is from a device the run asked for, or `too_many_files`
/// when the specs of all directories pass `cdi_dir_entries_max`, or the listing was cut short.
fn read_directory(host: Host, directory: [:0]const u8, scratch: *Scratch) ?cdi.Refusal {
    host.list_directory(directory, &scratch.listing) catch return null;
    var names: [constants.cdi_dir_entries_max][]const u8 = undefined;
    var count: usize = 0;
    var at: usize = 0;
    var over = scratch.listing.truncated;
    while (at < scratch.listing.len) {
        const name = std.mem.span(@as([*:0]const u8, @ptrCast(&scratch.listing.bytes[at])));
        at += name.len + 1;
        if (!is_spec_name(name)) continue;
        if (count == names.len or scratch.files + count == names.len) {
            over = true;
            break;
        }
        names[count] = name;
        count += 1;
    }
    if (over) {
        const length = @min(directory.len, scratch.overflow.len - 1);
        @memcpy(scratch.overflow[0..length], directory[0..length]);
        scratch.overflow_len = @intCast(length);
        return .too_many_files;
    }
    std.mem.sort([]const u8, names[0..count], {}, name_less);
    for (names[0..count]) |name| {
        scratch.files += 1;
        assert(scratch.files <= constants.cdi_dir_entries_max);
        if (read_file(host, directory, name, scratch)) |refusal| return refusal;
    }
    return null;
}

fn read_file(host: Host, directory: []const u8, name: []const u8, scratch: *Scratch) ?cdi.Refusal {
    var path: [constants.cdi_path_bytes_max + constants.dir_name_bytes_max + 2]u8 = undefined;
    const total = directory.len + 1 + name.len;
    if (total >= path.len) {
        scratch.resolver.refuse_file(name, .path);
        return null;
    }
    @memcpy(path[0..directory.len], directory);
    path[directory.len] = '/';
    @memcpy(path[directory.len + 1 ..][0..name.len], name);
    const content = host.read_file(path[0..total], &scratch.content) catch |err| {
        const problem: cdi.Problem = if (err == error.FileTooLarge) .too_big else .unreadable;
        scratch.resolver.refuse_file(name, problem);
        return null;
    };
    return scratch.resolver.add_file(name, content);
}

/// Raises the diagnostic for a refusal. A device no spec has is E0226 when a spec file was
/// unusable (it may have been the one), else E0230.
fn refuse(asked: []const []const u8, scratch: *Scratch, refusal: cdi.Refusal, diag: *Diag) bool {
    const resolver = &scratch.resolver;
    switch (refusal) {
        .unknown => |index| {
            if (resolver.problems_count > 0) {
                cdi_diagnose.spec_unusable(diag, &resolver.problems[0]);
            } else {
                cdi_diagnose.unknown(diag, asked[index], resolver);
            }
        },
        .unsupported => |found| {
            const name = found.name[0..found.name_len];
            cdi_diagnose.unsupported(diag, asked[found.index], found.edit, name);
        },
        .too_big => |index| cdi_diagnose.too_big(diag, asked[index]),
        .too_many_files => cdi_diagnose.too_many_files(diag, scratch.overflow[0..scratch.overflow_len]),
    }
    return false;
}

/// Every mount's source is there (its kind noted) and every node can be opened.
fn looked_at(host: Host, scratch: *Scratch, out: *cdi.Resolved, diag: *Diag) bool {
    return host_has(host, out, scratch.resolver.asked, diag);
}

/// What the host must have for a resolved set: each mount's source (its kind noted in
/// `mount_is_dir`) and each node. Also the check for a set a caller resolved itself.
pub fn host_has(
    host: Host,
    out: *cdi.Resolved,
    asked: []const []const u8,
    diag: *Diag,
) bool {
    assert(asked.len > 0);
    for (out.mounts[0..out.mounts_count], 0..) |item, index| {
        const source = out.text(item.host);
        const stat = host.stat(source) catch {
            cdi_diagnose.host_lacks(diag, .stale, source, owner_of(asked, out.mount_owner[index]));
            return false;
        };
        out.mount_is_dir[index] = stat.mode & 0o170000 == 0o040000;
    }
    for (out.nodes[0..out.nodes_count]) |node| {
        const path = out.text(node);
        if (devices.look_path(host, path)) |problem| {
            devices_diagnose.refused(diag, path, problem);
            return false;
        }
    }
    return true;
}

/// The asked device that owns a mount; a given set, which has no asked list of its own, is
/// named by the first.
fn owner_of(asked: []const []const u8, owner: u8) []const u8 {
    assert(asked.len > 0);
    return asked[if (owner < asked.len) owner else 0];
}
