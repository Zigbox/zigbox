//! Applying the layers of an image, in order, to a directory: the staging directory that is then
//! imported as one tree. It runs inside the store's user-namespace child (`store/namespace.zig`),
//! so a tar entry owned by uid 1000 lands as container id 1000 under the M1 mapping, and the
//! directory it makes holds files that only that namespace can remove.
//!
//! What an entry does, by the OCI image specification (layer changesets):
//!   - a file, directory or symlink replaces what is at its path (a file over a directory removes
//!     the directory with everything in it); a directory over a directory keeps the contents;
//!   - `.wh.<name>` removes `<name>` from the directory, and `.wh..wh..opq` empties the directory
//!     of what lower layers put there (it should come first among the directory's entries, as
//!     Docker and BuildKit write it; entries of the same layer before it are removed too);
//!   - a hard link is made as a link in the staging directory, so it is a separate entry of the
//!     tree that shares its object with the target (`store import` makes them separate entries);
//!   - devices, FIFOs and sockets are skipped, counted, and reported once with a warning;
//!   - `SCHILY.xattr.*` pax records are set as extended attributes when the store would keep
//!     them (`xattrs.class_of`); the others are counted and skipped.
//!
//! What it refuses (`Failure`, ZBX-E0515 and E0516): a path that is absolute or has `..`, a
//! path that goes through a symlink (the layer made one earlier, or a lower layer did), a link
//! to a file outside the root, and the damaged or unsupported archives `tar.zig` refuses. The
//! check is by `lstat` of every directory on the way, cached for the last directory used, so the
//! cost is small and the guarantee does not depend on the file system following links.
//!
//! The root of the staging directory is the layer's `./`. It is made by the caller.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const fs_mod = @import("../store/fs.zig");
const names_mod = @import("../store/names.zig");
const remove = @import("../store/remove.zig");
const xattrs = @import("../store/xattrs.zig");
const reader_mod = @import("reader.zig");
const tar = @import("tar.zig");

const Fs = fs_mod.Fs;

/// The most bytes of file contents one layer may hold, whatever its compressed size.
pub const layer_bytes_max: u64 = 64 * 1024 * 1024 * 1024;

pub const Error = error{Failed};

pub const Reason = enum {
    // Unsafe entries (ZBX-E0515).
    absolute,
    escapes,
    through_symlink,
    link_target,
    // Layers that cannot be applied (ZBX-E0516).
    damaged,
    unsupported,
    too_long,
    too_big,
    parent_not_directory,
    missing_link_target,
    bad_whiteout,
    unmapped_owner,
    /// The layer's blob could not be read or decoded; `Layer.fault` says why.
    unreadable,
    // The file system (ZBX-E0416 and E0417).
    io,

    pub fn unsafe(reason: Reason) bool {
        assert(@tagName(reason).len > 0);
        assert(@tagName(reason).len < 32);
        return switch (reason) {
            .absolute, .escapes, .through_symlink, .link_target => true,
            else => false,
        };
    }
};

pub const Failure = struct {
    reason: Reason,
    /// The entry's path as the archive spells it, cut to fit.
    path: [path_show_bytes]u8,
    path_len: u32,
    /// A word for `damaged` and `unsupported`: which check failed.
    detail: []const u8,
    err: fs_mod.Error,
    errno: u16,
    step: []const u8,

    pub fn path_text(failure: *const Failure) []const u8 {
        assert(failure.path_len <= path_show_bytes);
        assert(failure.path_len <= failure.path.len);
        return failure.path[0..failure.path_len];
    }
};

pub const path_show_bytes = 300;

pub const Counts = struct {
    files: u64 = 0,
    directories: u64 = 0,
    symlinks: u64 = 0,
    hardlinks: u64 = 0,
    whiteouts: u64 = 0,
    opaque_directories: u64 = 0,
    /// Devices, FIFOs and sockets left out, and the first one's path.
    special_skipped: u64 = 0,
    xattrs_set: u64 = 0,
    xattrs_skipped: u64 = 0,
    bytes: u64 = 0,
    layers: u32 = 0,
};

const unsupported_type = "an entry type zbx does not read";
const whiteout_prefix = ".wh.";
const opaque_name = ".wh..wh..opq";
const errno_perm: u16 = 1;
const errno_exist: u16 = 17;
const errno_inval: u16 = 22;
const errno_notsup: u16 = 95;
/// Times are kept below 2^40 (the file systems' calls assert it); a later one is clamped.
const max_mtime: u64 = (1 << 40) - 1;
const batch_names: u32 = 256;
const names_region: u32 = batch_names * (constants.store_name_bytes_max + 1);

pub const Applier = struct {
    fs: Fs,
    root: [constants.path_bytes_max + 1]u8,
    root_len: u32,
    squash_owner: bool,
    counts: Counts,
    failure: Failure,
    first_special: [path_show_bytes]u8,
    first_special_len: u32,
    first_xattr: [path_show_bytes]u8,
    first_xattr_len: u32,
    /// The last directory known to be a real directory all the way (relative, no slashes at
    /// either end), so entries of one directory do not look at it again.
    verified: [constants.path_bytes_max + 1]u8,
    verified_len: u32,
    rel: [constants.path_bytes_max + 1]u8,
    full: [constants.path_bytes_max + 1]u8,
    target: [constants.path_bytes_max + 1]u8,
    link: [constants.path_bytes_max + 1]u8,
    xattr_name: [constants.store_xattr_name_bytes_max + 1]u8,
    io: [constants.blob_io_bytes]u8,
    names: [names_region]u8,
    removal: remove.Workspace,
    removal_failure: remove.Failure,
    removal_arena: [remove.arena_bytes]u8 align(8),
    reader: tar.Reader,

    /// Prepares to apply layers to the existing directory `root`.
    pub fn start(applier: *Applier, fs: Fs, root: []const u8, squash_owner: bool) void {
        assert(root.len > 1);
        assert(root.len + 64 < constants.path_bytes_max);
        applier.fs = fs;
        @memcpy(applier.root[0..root.len], root);
        applier.root[root.len] = 0;
        applier.root_len = @intCast(root.len);
        applier.squash_owner = squash_owner;
        applier.counts = .{};
        applier.first_special_len = 0;
        applier.first_xattr_len = 0;
        applier.verified_len = 0;
    }

    // ---- Failures ---------------------------------------------------------------------------

    fn fail(applier: *Applier, reason: Reason, name: []const u8, detail: []const u8) Error {
        assert(name.len <= constants.path_bytes_max);
        assert(detail.len < 128);
        const shown = name[0..@min(name.len, path_show_bytes)];
        @memcpy(applier.failure.path[0..shown.len], shown);
        applier.failure.path_len = @intCast(shown.len);
        applier.failure.reason = reason;
        applier.failure.detail = detail;
        applier.failure.err = error.IoFailed;
        applier.failure.errno = 0;
        applier.failure.step = "";
        return error.Failed;
    }

    fn fail_io(applier: *Applier, step: []const u8, name: []const u8, err: fs_mod.Error) Error {
        assert(step.len > 0);
        assert(applier.fs.last_errno() < 4096);
        return applier.fail_errno(step, name, err, applier.fs.last_errno());
    }

    fn fail_errno(
        applier: *Applier,
        step: []const u8,
        name: []const u8,
        err: fs_mod.Error,
        errno: u16,
    ) Error {
        assert(step.len > 0);
        assert(errno < 4096);
        _ = applier.fail(.io, name, "") catch {};
        applier.failure.err = err;
        applier.failure.errno = errno;
        applier.failure.step = step;
        return error.Failed;
    }

    fn fail_tar(applier: *Applier, layer: *reader_mod.Layer, err: tar.Error) Error {
        assert(@errorName(err).len > 0);
        assert(layer.open);
        switch (err) {
            error.ReadFailed => {
                layer.explain(error.ReadFailed);
                return applier.fail(.unreadable, "", "");
            },
            error.Truncated => return applier.fail(.damaged, "", "the archive ends early"),
            error.BadChecksum => return applier.fail(.damaged, "", "a header checksum is wrong"),
            error.BadNumber => return applier.fail(.damaged, "", "a header field is not a number"),
            error.BadPax => return applier.fail(.damaged, "", "a pax record is malformed"),
            error.TooLong => return applier.fail(.too_long, "", "a name or a record is too long"),
            error.Unsupported => return applier.fail(.unsupported, "", unsupported_type),
            error.TooBig => return applier.fail(.too_big, "", "the layer holds too many bytes"),
        }
    }

    // ---- Paths ------------------------------------------------------------------------------

    /// The entry's name as a clean relative path in `applier.rel`: no leading or trailing slash,
    /// no `.` or empty part. Empty means the root.
    fn clean(applier: *Applier, name: []const u8) Error![]const u8 {
        assert(name.len <= constants.path_bytes_max);
        if (name.len > 0 and name[0] == '/') return applier.fail(.absolute, name, "");
        if (std.mem.indexOfScalar(u8, name, 0) != null) {
            return applier.fail(.damaged, name, "a name has a NUL byte");
        }
        const room = constants.path_bytes_max - applier.root_len - 2;
        var length: usize = 0;
        var parts = std.mem.splitScalar(u8, name, '/');
        var seen: u32 = 0;
        while (parts.next()) |part| {
            seen += 1;
            assert(seen <= name.len + 1);
            if (part.len == 0 or std.mem.eql(u8, part, ".")) continue;
            if (std.mem.eql(u8, part, "..")) return applier.fail(.escapes, name, "");
            if (part.len > constants.store_name_bytes_max) {
                return applier.fail(.too_long, name, "a name is over 255 bytes");
            }
            const added = part.len + @intFromBool(length > 0);
            if (length + added > room) return applier.fail(.too_long, name, "the path is too long");
            if (length > 0) {
                applier.rel[length] = '/';
                length += 1;
            }
            @memcpy(applier.rel[length..][0..part.len], part);
            length += part.len;
        }
        applier.rel[length] = 0;
        return applier.rel[0..length];
    }

    /// `root/<relative>` in `buffer`, NUL-terminated.
    fn join(
        applier: *const Applier,
        buffer: *[constants.path_bytes_max + 1]u8,
        relative: []const u8,
    ) [:0]const u8 {
        assert(relative.len < constants.path_bytes_max);
        assert(applier.root_len + 1 + relative.len < buffer.len);
        @memcpy(buffer[0..applier.root_len], applier.root[0..applier.root_len]);
        var length: usize = applier.root_len;
        if (relative.len > 0) {
            buffer[length] = '/';
            length += 1;
            @memcpy(buffer[length..][0..relative.len], relative);
            length += relative.len;
        }
        buffer[length] = 0;
        return buffer[0..length :0];
    }

    /// True if the directory `parent` is the verified one or lies above it.
    fn covered(applier: *const Applier, parent: []const u8) bool {
        assert(parent.len <= constants.path_bytes_max);
        assert(applier.verified_len <= constants.path_bytes_max);
        const kept = applier.verified[0..applier.verified_len];
        if (parent.len > kept.len) return false;
        if (!std.mem.startsWith(u8, kept, parent)) return false;
        return parent.len == kept.len or kept[parent.len] == '/';
    }

    /// Makes sure every directory on the way to `parent` is a real directory, making the ones
    /// that are missing (`create`), and refuses a symlink or a file in the way. False if a
    /// directory is missing and `create` is off.
    fn parents(
        applier: *Applier,
        parent: []const u8,
        entry_name: []const u8,
        create: bool,
    ) Error!bool {
        assert(parent.len <= constants.path_bytes_max);
        assert(entry_name.len <= constants.path_bytes_max);
        if (parent.len == 0) return true;
        if (applier.covered(parent)) return true;
        const kept = applier.verified[0..applier.verified_len];
        // Resume after the components `parent` shares with the verified directory.
        const at = shared_components(parent, kept);
        var end = at;
        while (end < parent.len) {
            end = std.mem.indexOfScalarPos(u8, parent, end, '/') orelse parent.len;
            const path = applier.join(&applier.full, parent[0..end]);
            if (!try applier.directory_on_the_way(path, entry_name, create)) return false;
            end += 1;
        }
        @memcpy(applier.verified[0..parent.len], parent);
        applier.verified_len = @intCast(parent.len);
        return true;
    }

    fn directory_on_the_way(
        applier: *Applier,
        path: [:0]const u8,
        name: []const u8,
        create: bool,
    ) Error!bool {
        assert(path.len > applier.root_len);
        assert(path.len <= constants.path_bytes_max);
        const found = applier.fs.lstat(path) catch |err| switch (err) {
            error.NotFound => {
                if (!create) return false;
                applier.fs.make_directory(path, false) catch |made| {
                    return applier.fail_io("making a directory", name, made);
                };
                return true;
            },
            else => return applier.fail_io("looking at a directory", name, err),
        };
        switch (found.kind) {
            .dir => return true,
            .symlink => return applier.fail(.through_symlink, name, ""),
            else => return applier.fail(.parent_not_directory, name, ""),
        }
    }

    /// Removes whatever is at `path` (a file, a link, or a directory with all it holds).
    fn remove_existing(applier: *Applier, path: [:0]const u8, name: []const u8) Error!void {
        assert(path.len > applier.root_len);
        assert(std.mem.startsWith(u8, path, applier.root[0..applier.root_len]));
        applier.verified_len = 0;
        const arena = &applier.removal_arena;
        remove.tree(applier.fs, &applier.removal, arena, path, &applier.removal_failure) catch {
            const failed = &applier.removal_failure;
            return applier.fail_errno("replacing an entry", name, failed.err, failed.errno);
        };
    }

    // ---- Layers and entries -----------------------------------------------------------------

    /// Applies every entry of the layer in `layer` (opened by `Layer.start`), in order.
    pub fn apply_layer(applier: *Applier, layer: *reader_mod.Layer) Error!void {
        assert(layer.open);
        applier.reader.init(layer.tar_reader(), layer_bytes_max);
        applier.verified_len = 0;
        var entries: u64 = 0;
        while (true) {
            entries += 1;
            assert(entries < 1 << 40);
            const found = applier.reader.next() catch |err| return applier.fail_tar(layer, err);
            const entry = found orelse break;
            try applier.apply_entry(layer, &entry);
        }
        applier.counts.layers += 1;
    }

    fn apply_entry(
        applier: *Applier,
        layer: *reader_mod.Layer,
        entry: *const tar.Entry,
    ) Error!void {
        assert(layer.open);
        assert(entry.name.len <= constants.path_bytes_max);
        const name = entry.name;
        const rel = try applier.clean(name);
        if (rel.len == 0) {
            if (entry.kind != .directory) {
                return applier.fail(.damaged, name, "an entry names the root");
            }
            return applier.directory_metadata(applier.root[0..applier.root_len :0], entry, name);
        }
        const base_at = if (std.mem.lastIndexOfScalar(u8, rel, '/')) |slash| slash + 1 else 0;
        const base = rel[base_at..];
        const parent = rel[0..if (base_at > 0) base_at - 1 else 0];
        if (std.mem.startsWith(u8, base, whiteout_prefix)) {
            return applier.whiteout(parent, base, name);
        }
        if (entry.kind == .special) return applier.skip_special(name);
        _ = try applier.parents(parent, name, true);
        switch (entry.kind) {
            .file => try applier.put_file(layer, entry, rel),
            .directory => try applier.put_directory(entry, rel),
            .symlink => try applier.put_symlink(entry, rel),
            .hardlink => try applier.put_hardlink(entry, rel),
            .special => unreachable, // Returned above.
        }
    }

    fn skip_special(applier: *Applier, name: []const u8) void {
        assert(applier.first_special_len <= path_show_bytes);
        assert(name.len > 0);
        if (applier.counts.special_skipped == 0) {
            const shown = name[0..@min(name.len, path_show_bytes)];
            @memcpy(applier.first_special[0..shown.len], shown);
            applier.first_special_len = @intCast(shown.len);
        }
        applier.counts.special_skipped += 1;
    }

    pub fn first_special_path(applier: *const Applier) []const u8 {
        assert(applier.counts.special_skipped > 0);
        assert(applier.first_special_len <= path_show_bytes);
        return applier.first_special[0..applier.first_special_len];
    }

    pub fn first_xattr_path(applier: *const Applier) []const u8 {
        assert(applier.first_xattr_len <= path_show_bytes);
        return applier.first_xattr[0..applier.first_xattr_len];
    }

    fn skipped_xattr(applier: *Applier, name: []const u8) void {
        assert(name.len > 0);
        assert(applier.counts.xattrs_skipped < 1 << 62);
        if (applier.counts.xattrs_skipped == 0) {
            const shown = name[0..@min(name.len, path_show_bytes)];
            @memcpy(applier.first_xattr[0..shown.len], shown);
            applier.first_xattr_len = @intCast(shown.len);
        }
        applier.counts.xattrs_skipped += 1;
    }

    // ---- Whiteouts --------------------------------------------------------------------------

    fn whiteout(
        applier: *Applier,
        parent: []const u8,
        base: []const u8,
        name: []const u8,
    ) Error!void {
        assert(parent.len <= constants.path_bytes_max);
        assert(std.mem.startsWith(u8, base, whiteout_prefix));
        const target = base[whiteout_prefix.len..];
        if (std.mem.eql(u8, base, opaque_name)) return applier.make_opaque(parent, name);
        const dots = std.mem.eql(u8, target, ".") or std.mem.eql(u8, target, "..");
        const bad = target.len == 0 or dots;
        if (bad) return applier.fail(.bad_whiteout, name, "");
        // A whiteout in a directory that does not exist removes nothing.
        if (!try applier.parents(parent, name, false)) return;
        var joined: [constants.path_bytes_max + 1]u8 = undefined;
        const length = parent.len + @intFromBool(parent.len > 0) + target.len;
        if (length > constants.path_bytes_max - applier.root_len - 2) {
            return applier.fail(.too_long, name, "the path is too long");
        }
        @memcpy(joined[0..parent.len], parent);
        if (parent.len > 0) joined[parent.len] = '/';
        @memcpy(joined[parent.len + @intFromBool(parent.len > 0) ..][0..target.len], target);
        const path = applier.join(&applier.full, joined[0..length]);
        _ = applier.fs.lstat(path) catch |err| switch (err) {
            error.NotFound => return,
            else => return applier.fail_io("looking for a whiteout's target", name, err),
        };
        try applier.remove_existing(path, name);
        applier.counts.whiteouts += 1;
    }

    /// `.wh..wh..opq` in `directory`: what is there now was put by lower layers, and goes.
    fn make_opaque(applier: *Applier, directory: []const u8, name: []const u8) Error!void {
        assert(directory.len <= constants.path_bytes_max);
        assert(name.len > 0);
        // The directory is made if the layer has not yet (its own entry may come later).
        _ = try applier.parents(directory, name, true);
        try applier.empty_directory(directory, name);
        applier.counts.opaque_directories += 1;
    }

    /// Removes everything in `directory`, a batch of names at a time.
    fn empty_directory(applier: *Applier, directory: []const u8, name: []const u8) Error!void {
        applier.verified_len = 0;
        var rounds: u32 = 0;
        while (true) {
            rounds += 1;
            assert(rounds < 1 << 24);
            const path = applier.join(&applier.full, directory);
            var list = names_mod.NameList.init(&applier.names, batch_names);
            applier.fs.read_dir(path, list.visitor()) catch |err| {
                return applier.fail_io("listing a directory", name, err);
            };
            if (list.count == 0) return;
            var at: u32 = 0;
            var removed: u32 = 0;
            while (at < list.used) {
                const length = list.bytes[at];
                const child = list.bytes[at + 1 ..][0..length];
                at += 1 + length;
                try applier.remove_child(directory, child, name);
                removed += 1;
            }
            assert(removed == list.count);
        }
    }

    fn remove_child(
        applier: *Applier,
        directory: []const u8,
        child: []const u8,
        name: []const u8,
    ) Error!void {
        assert(child.len > 0);
        assert(std.mem.indexOfScalar(u8, child, '/') == null);
        var joined: [constants.path_bytes_max + 1]u8 = undefined;
        const length = directory.len + @intFromBool(directory.len > 0) + child.len;
        if (length > constants.path_bytes_max - applier.root_len - 2) {
            return applier.fail(.too_long, name, "the path is too long");
        }
        @memcpy(joined[0..directory.len], directory);
        if (directory.len > 0) joined[directory.len] = '/';
        @memcpy(joined[directory.len + @intFromBool(directory.len > 0) ..][0..child.len], child);
        const path = applier.join(&applier.target, joined[0..length]);
        try applier.remove_existing(path, name);
    }

    // ---- Files, directories and links -------------------------------------------------------

    fn exists_error(applier: *const Applier) bool {
        assert(applier.root_len > 1);
        assert(applier.fs.last_errno() < 4096);
        return applier.fs.last_errno() == errno_exist;
    }

    fn put_file(
        applier: *Applier,
        layer: *reader_mod.Layer,
        entry: *const tar.Entry,
        rel: []const u8,
    ) Error!void {
        assert(rel.len > 0);
        assert(entry.kind == .file);
        const path = applier.join(&applier.full, rel);
        const fs = applier.fs;
        const fd = fs.create(path, entry.mode & 0o777) catch |err| blk: {
            if (!applier.exists_error()) return applier.fail_io("creating a file", entry.name, err);
            try applier.remove_existing(path, entry.name);
            break :blk fs.create(path, entry.mode & 0o777) catch |again| {
                return applier.fail_io("creating a file", entry.name, again);
            };
        };
        defer fs.close(fd);
        try applier.copy_body(layer, fd, entry);
        try applier.owner_of_fd(fd, entry);
        try applier.xattrs_of_fd(fd, entry);
        fs.set_mode(fd, entry.mode) catch |err| {
            return applier.fail_io("setting a mode", entry.name, err);
        };
        const stamp = @min(entry.mtime, max_mtime);
        fs.set_mtime(fd, stamp) catch |err| {
            return applier.fail_io("setting a time", entry.name, err);
        };
        applier.counts.files += 1;
        applier.counts.bytes += entry.size;
    }

    fn copy_body(
        applier: *Applier,
        layer: *reader_mod.Layer,
        fd: fs_mod.Fd,
        entry: *const tar.Entry,
    ) Error!void {
        assert(entry.kind == .file);
        var left = entry.size;
        while (left > 0) {
            const count = applier.reader.read_body(&applier.io) catch |err| {
                return applier.fail_tar(layer, err);
            };
            if (count == 0) return applier.fail(.damaged, entry.name, "the archive ends early");
            applier.fs.write_all(fd, applier.io[0..count]) catch |err| {
                return applier.fail_io("writing a file", entry.name, err);
            };
            left -= count;
        }
        assert(left == 0);
    }

    fn owner_of_fd(applier: *Applier, fd: fs_mod.Fd, entry: *const tar.Entry) Error!void {
        assert(entry.uid != std.math.maxInt(u32));
        assert(fd < std.math.maxInt(i32));
        if (applier.squash_owner) return;
        applier.fs.set_owner(fd, entry.uid, entry.gid) catch |err| {
            return applier.owner_failed(entry, err);
        };
    }

    /// A chown the namespace refuses: the id is not one it maps.
    fn owner_failed(applier: *Applier, entry: *const tar.Entry, err: fs_mod.Error) Error {
        assert(entry.name.len > 0);
        assert(@errorName(err).len > 0);
        const errno = applier.fs.last_errno();
        if (errno == errno_inval or errno == errno_perm) {
            return applier.fail(.unmapped_owner, entry.name, "");
        }
        return applier.fail_errno("setting an owner", entry.name, err, errno);
    }

    fn xattrs_of_fd(applier: *Applier, fd: fs_mod.Fd, entry: *const tar.Entry) Error!void {
        assert(entry.xattrs.len <= tar.xattrs_max);
        assert(fd < std.math.maxInt(i32));
        applier.counts.xattrs_skipped += entry.xattrs_dropped;
        for (entry.xattrs) |attribute| {
            const name = applier.xattr_z(attribute) orelse {
                applier.skipped_xattr(entry.name);
                continue;
            };
            applier.fs.set_xattr(fd, name, attribute.value) catch |err| {
                try applier.xattr_refused(entry, err);
                continue;
            };
            applier.counts.xattrs_set += 1;
        }
    }

    fn xattrs_of_path(applier: *Applier, path: [:0]const u8, entry: *const tar.Entry) Error!void {
        assert(entry.xattrs.len <= tar.xattrs_max);
        assert(path.len > 0);
        applier.counts.xattrs_skipped += entry.xattrs_dropped;
        for (entry.xattrs) |attribute| {
            const name = applier.xattr_z(attribute) orelse {
                applier.skipped_xattr(entry.name);
                continue;
            };
            applier.fs.set_path_xattr(path, name, attribute.value) catch |err| {
                try applier.xattr_refused(entry, err);
                continue;
            };
            applier.counts.xattrs_set += 1;
        }
    }

    /// The attribute's name as C text if the store keeps it and it fits; null to skip it.
    fn xattr_z(applier: *Applier, attribute: tar.Xattr) ?[:0]const u8 {
        assert(attribute.name.len > 0);
        assert(applier.xattr_name.len > constants.store_xattr_name_bytes_max);
        const name = attribute.name;
        if (name.len > constants.store_xattr_name_bytes_max) return null;
        if (attribute.value.len > constants.store_xattr_value_bytes_max) return null;
        if (xattrs.class_of(name) != .keep) return null;
        @memcpy(applier.xattr_name[0..name.len], name);
        applier.xattr_name[name.len] = 0;
        return applier.xattr_name[0..name.len :0];
    }

    /// A file system that has no such attribute, or that the namespace may not set one on, is
    /// counted and skipped; anything else is a failure.
    fn xattr_refused(applier: *Applier, entry: *const tar.Entry, err: fs_mod.Error) Error!void {
        assert(entry.name.len > 0);
        assert(@errorName(err).len > 0);
        const errno = applier.fs.last_errno();
        const skip = errno == errno_perm or errno == errno_inval or errno == errno_notsup;
        if (!skip) return applier.fail_errno("setting an attribute", entry.name, err, errno);
        applier.skipped_xattr(entry.name);
    }

    fn put_directory(applier: *Applier, entry: *const tar.Entry, rel: []const u8) Error!void {
        assert(entry.kind == .directory);
        assert(rel.len > 0);
        const path = applier.join(&applier.full, rel);
        applier.fs.make_directory(path, true) catch |err| {
            return applier.fail_io("making a directory", entry.name, err);
        };
        // `exist_ok` also accepts a file or a link that was there: look.
        const found = applier.fs.lstat(path) catch |err| {
            return applier.fail_io("looking at a directory", entry.name, err);
        };
        if (found.kind != .dir) {
            try applier.remove_existing(path, entry.name);
            applier.fs.make_directory(path, false) catch |err| {
                return applier.fail_io("making a directory", entry.name, err);
            };
        }
        try applier.directory_metadata(path, entry, entry.name);
        applier.counts.directories += 1;
    }

    fn directory_metadata(
        applier: *Applier,
        path: [:0]const u8,
        entry: *const tar.Entry,
        name: []const u8,
    ) Error!void {
        assert(name.len > 0);
        assert(path.len > 0);
        assert(entry.mode <= 0o7777);
        const uid: u32 = if (applier.squash_owner) 0 else entry.uid;
        const gid: u32 = if (applier.squash_owner) 0 else entry.gid;
        applier.fs.set_path_attributes(path, .{
            .mode = entry.mode,
            .uid = uid,
            .gid = gid,
            .mtime = @min(entry.mtime, max_mtime),
        }) catch |err| return applier.owner_failed(entry, err);
        try applier.xattrs_of_path(path, entry);
    }

    fn put_symlink(applier: *Applier, entry: *const tar.Entry, rel: []const u8) Error!void {
        assert(entry.kind == .symlink);
        assert(rel.len > 0);
        const text = entry.link;
        if (text.len == 0) return applier.fail(.damaged, entry.name, "a symlink with no target");
        if (text.len > constants.store_symlink_target_bytes_max) {
            return applier.fail(.too_long, entry.name, "a symlink target is too long");
        }
        @memcpy(applier.target[0..text.len], text);
        applier.target[text.len] = 0;
        const target: [:0]const u8 = applier.target[0..text.len :0];
        const path = applier.join(&applier.full, rel);
        applier.fs.symlink(target, path) catch |err| {
            if (!applier.exists_error()) {
                return applier.fail_io("making a symlink", entry.name, err);
            }
            try applier.remove_existing(path, entry.name);
            applier.fs.symlink(target, path) catch |again| {
                return applier.fail_io("making a symlink", entry.name, again);
            };
        };
        const uid: u32 = if (applier.squash_owner) 0 else entry.uid;
        const gid: u32 = if (applier.squash_owner) 0 else entry.gid;
        applier.fs.set_path_attributes(path, .{
            .mode = null,
            .uid = uid,
            .gid = gid,
            .mtime = @min(entry.mtime, max_mtime),
        }) catch |err| return applier.owner_failed(entry, err);
        applier.counts.symlinks += 1;
    }

    fn put_hardlink(applier: *Applier, entry: *const tar.Entry, rel: []const u8) Error!void {
        assert(entry.kind == .hardlink);
        assert(rel.len > 0);
        const target_rel = try applier.link_target(entry);
        if (std.mem.eql(u8, target_rel, rel)) {
            return applier.fail(.damaged, entry.name, "a hard link to itself");
        }
        const slash = std.mem.lastIndexOfScalar(u8, target_rel, '/') orelse 0;
        const target_parent = target_rel[0..slash];
        if (!try applier.parents(target_parent, entry.name, false)) {
            return applier.fail(.missing_link_target, entry.name, "");
        }
        const target = applier.join(&applier.target, target_rel);
        const found = applier.fs.lstat(target) catch |err| switch (err) {
            error.NotFound => return applier.fail(.missing_link_target, entry.name, ""),
            else => return applier.fail_io("looking at a link target", entry.name, err),
        };
        if (found.kind == .dir) return applier.fail(.missing_link_target, entry.name, "");
        const path = applier.join(&applier.full, rel);
        applier.fs.link(target, path) catch |err| {
            if (!applier.exists_error()) {
                return applier.fail_io("making a hard link", entry.name, err);
            }
            try applier.remove_existing(path, entry.name);
            applier.fs.link(target, path) catch |again| {
                return applier.fail_io("making a hard link", entry.name, again);
            };
        };
        applier.counts.hardlinks += 1;
    }

    /// The link's target as a clean relative path in `applier.link`. A link names a path in the
    /// layer's root, so it may not be absolute or go up.
    fn link_target(applier: *Applier, entry: *const tar.Entry) Error![]const u8 {
        assert(entry.kind == .hardlink);
        assert(applier.link.len > constants.store_name_bytes_max);
        const text = entry.link;
        const unsafe = text.len > 0 and text[0] == '/';
        if (unsafe) return applier.fail(.link_target, entry.name, "");
        var length: usize = 0;
        var parts = std.mem.splitScalar(u8, text, '/');
        const room = constants.path_bytes_max - applier.root_len - 2;
        while (parts.next()) |part| {
            if (part.len == 0 or std.mem.eql(u8, part, ".")) continue;
            if (std.mem.eql(u8, part, "..")) return applier.fail(.link_target, entry.name, "");
            if (length + part.len + 1 > room) {
                return applier.fail(.too_long, entry.name, "the path is too long");
            }
            if (length > 0) {
                applier.link[length] = '/';
                length += 1;
            }
            @memcpy(applier.link[length..][0..part.len], part);
            length += part.len;
        }
        if (length == 0) return applier.fail(.damaged, entry.name, "a hard link with no target");
        applier.link[length] = 0;
        return applier.link[0..length];
    }
};

/// The length of the leading part of `path` (a clean relative path) that `other` also has, as
/// whole components and including the slash after the last one, so it is where the next
/// component starts.
pub fn shared_components(path: []const u8, other: []const u8) usize {
    assert(path.len < constants.path_bytes_max);
    assert(other.len < constants.path_bytes_max);
    var shared: usize = 0;
    var at: usize = 0;
    while (at < path.len and at < other.len and path[at] == other[at]) : (at += 1) {
        if (path[at] == '/') shared = at + 1;
    }
    // `other` ends where a component of `path` ends: all of it is shared.
    if (at == other.len and at < path.len and path[at] == '/') shared = at + 1;
    if (at == other.len and at == path.len) shared = at;
    return shared;
}

const testing = std.testing;
const builder = @import("../testing/vm/layer_fixture.zig");
const fs_sim = @import("../store/fs_sim.zig");

var test_fs: fs_sim.SimFs = undefined;
var test_applier: Applier = undefined;
var test_layer: reader_mod.Layer = undefined;
var test_tar: [96 * 1024]u8 = undefined;
var test_blob: [100 * 1024]u8 = undefined;

fn world() void {
    test_fs.init(1);
    test_fs.put_dir("/stage", 0o755);
    test_fs.put_dir("/outside", 0o755);
    test_applier.start(test_fs.interface(), "/stage", false);
}

/// Applies the archive in `tar_bytes`, wrapped as `compression`, as one layer.
fn apply(tar_bytes: []const u8, compression: reader_mod.Compression) Error!void {
    var blob: []const u8 = tar_bytes;
    switch (compression) {
        .none => {},
        .gzip => blob = builder.gzip(&test_blob, tar_bytes),
        .zstd => blob = builder.zstd(&test_blob, tar_bytes),
    }
    if (test_fs.kind_of("/layer") != null) test_fs.remove_path("/layer");
    test_fs.put_file("/layer", 0o644, blob);
    test_layer.start(test_fs.interface(), "/layer") catch {
        return test_applier.fail(.unreadable, "", "");
    };
    defer test_layer.close();
    try test_applier.apply_layer(&test_layer);
    _ = test_layer.finish() catch return test_applier.fail(.unreadable, "", "");
}

fn hard(target: []const u8) builder.Entry {
    return .{ .name = "h", .kind = .hardlink, .link = target };
}

fn expect_refused(reason: Reason) !void {
    try testing.expectEqual(reason, test_applier.failure.reason);
}

test "a layer makes its tree: directories, files, links, owners and modes" {
    // Goal: every entry kind lands as the archive says, with its owner and mode.
    world();
    var archive = builder.Tar.init(&test_tar);
    archive.add(.{ .name = "./", .kind = .directory, .mode = 0o755 });
    archive.add(.{ .name = "etc/", .kind = .directory, .mode = 0o750, .uid = 0, .gid = 5 });
    archive.add(.{
        .name = "etc/os-release",
        .data = "NAME=x\n",
        .mode = 0o640,
        .uid = 3,
        .gid = 4,
    });
    archive.add(.{ .name = "bin/busybox", .data = "ELF", .mode = 0o4755 });
    archive.add(.{ .name = "bin/sh", .kind = .hardlink, .link = "bin/busybox" });
    archive.add(.{ .name = "bin/ash", .kind = .symlink, .link = "busybox", .uid = 7, .gid = 8 });
    archive.finish();
    try apply(archive.bytes(), .none);
    const counts = test_applier.counts;
    try testing.expectEqual(@as(u64, 2), counts.files);
    try testing.expectEqual(@as(u64, 1), counts.hardlinks);
    try testing.expectEqual(@as(u64, 1), counts.symlinks);
    try testing.expectEqual(@as(u64, 10), counts.bytes);
    try testing.expectEqualStrings("NAME=x\n", test_fs.content_of("/stage/etc/os-release").?);
    const release = test_fs.stat_of("/stage/etc/os-release").?;
    try testing.expectEqual(@as(u32, 3), release.uid);
    try testing.expectEqual(@as(u32, 4), release.gid);
    try testing.expectEqual(@as(u16, 0o640), release.mode);
    const etc = test_fs.stat_of("/stage/etc").?;
    try testing.expectEqual(@as(u16, 0o750), etc.mode);
    try testing.expectEqual(@as(u32, 5), etc.gid);
    try testing.expectEqual(@as(u16, 0o4755), test_fs.stat_of("/stage/bin/busybox").?.mode);
    try testing.expectEqualStrings("ELF", test_fs.content_of("/stage/bin/sh").?);
    try testing.expectEqual(fs_mod.FileKind.symlink, test_fs.kind_of("/stage/bin/ash").?);
    try testing.expectEqual(@as(u32, 7), test_fs.stat_of("/stage/bin/ash").?.uid);
}

test "layers stack: replacement, whiteouts, an opaque directory, and a file over a directory" {
    // Goal: the OCI changeset rules, across two layers.
    world();
    var archive = builder.Tar.init(&test_tar);
    archive.add(.{ .name = "etc/", .kind = .directory });
    archive.add(.{ .name = "etc/conf", .data = "old" });
    archive.add(.{ .name = "etc/gone", .data = "x" });
    archive.add(.{ .name = "usr/old/", .kind = .directory });
    archive.add(.{ .name = "usr/old/a", .data = "a" });
    archive.add(.{ .name = "usr/old/b/c", .data = "c" });
    archive.add(.{ .name = "var/lib/x", .data = "tree" });
    archive.add(.{ .name = "opt/keep", .data = "k" });
    archive.finish();
    try apply(archive.bytes(), .none);
    var second = builder.Tar.init(&test_tar);
    second.add(.{ .name = "etc/conf", .data = "new!" });
    second.add(.{ .name = "etc/.wh.gone", .data = "" });
    second.add(.{ .name = "usr/old/.wh..wh..opq", .data = "" });
    second.add(.{ .name = "usr/old/fresh", .data = "f" });
    second.add(.{ .name = "var/lib", .data = "now a file" });
    second.add(.{ .name = "opt/.wh.missing", .data = "" });
    second.add(.{ .name = "nowhere/.wh.thing", .data = "" });
    second.finish();
    try apply(second.bytes(), .gzip);
    try testing.expectEqualStrings("new!", test_fs.content_of("/stage/etc/conf").?);
    try testing.expect(test_fs.kind_of("/stage/etc/gone") == null);
    try testing.expect(test_fs.kind_of("/stage/usr/old/a") == null);
    try testing.expect(test_fs.kind_of("/stage/usr/old/b") == null);
    try testing.expectEqualStrings("f", test_fs.content_of("/stage/usr/old/fresh").?);
    try testing.expectEqualStrings("now a file", test_fs.content_of("/stage/var/lib").?);
    try testing.expect(test_fs.kind_of("/stage/var/lib/x") == null);
    try testing.expectEqualStrings("k", test_fs.content_of("/stage/opt/keep").?);
    try testing.expect(test_fs.kind_of("/stage/nowhere") == null); // A whiteout makes nothing.
    // Only one of the three removed anything.
    try testing.expectEqual(@as(u64, 1), test_applier.counts.whiteouts);
    try testing.expectEqual(@as(u64, 1), test_applier.counts.opaque_directories);
    try testing.expectEqual(@as(u32, 2), test_applier.counts.layers);
}

test "an entry that escapes the root is refused and nothing outside is touched" {
    // Goal: an absolute path, `..`, a path through a symlink the layer made, a hard link to
    // an absolute or parent path, and a link to a file that is not there.
    const before = blk: {
        world();
        break :blk test_fs.live_count();
    };
    const cases = [_]struct { entries: []const builder.Entry, reason: Reason }{
        .{ .entries = &.{.{ .name = "/etc/passwd", .data = "x" }}, .reason = .absolute },
        .{ .entries = &.{.{ .name = "a/../../outside/x", .data = "x" }}, .reason = .escapes },
        .{ .entries = &.{.{ .name = "../outside/x", .data = "x" }}, .reason = .escapes },
        .{ .entries = &.{
            .{ .name = "etc", .kind = .symlink, .link = "/outside" },
            .{ .name = "etc/passwd", .data = "x" },
        }, .reason = .through_symlink },
        .{ .entries = &.{
            .{ .name = "d", .kind = .symlink, .link = "../outside" },
            .{ .name = "d/f", .kind = .directory },
        }, .reason = .through_symlink },
        .{ .entries = &.{hard("/outside/x")}, .reason = .link_target },
        .{ .entries = &.{hard("../outside/x")}, .reason = .link_target },
        .{ .entries = &.{hard("nothing")}, .reason = .missing_link_target },
        .{ .entries = &.{
            .{ .name = "s", .kind = .symlink, .link = "/outside" },
            .{ .name = "h", .kind = .hardlink, .link = "s/x" },
        }, .reason = .through_symlink },
        .{ .entries = &.{.{ .name = "a/.wh...", .data = "" }}, .reason = .bad_whiteout },
    };
    for (cases) |case| {
        world();
        var archive = builder.Tar.init(&test_tar);
        for (case.entries) |entry| archive.add(entry);
        archive.finish();
        try testing.expectError(error.Failed, apply(archive.bytes(), .none));
        try expect_refused(case.reason);
        const benign = case.reason == .missing_link_target or case.reason == .bad_whiteout;
        try testing.expect(case.reason.unsafe() != benign);
        try testing.expect(test_fs.kind_of("/outside/x") == null);
        try testing.expect(test_fs.kind_of("/outside/passwd") == null);
        _ = before;
    }
    world();
    var archive = builder.Tar.init(&test_tar);
    archive.add(.{ .name = "/etc/passwd", .data = "x" });
    archive.finish();
    try testing.expectError(error.Failed, apply(archive.bytes(), .none));
    try testing.expectEqualStrings("/etc/passwd", test_applier.failure.path_text());
}

test "devices are skipped and counted, and the first is remembered" {
    // Goal: a character device, a block device and a FIFO leave nothing, and are counted.
    world();
    var archive = builder.Tar.init(&test_tar);
    archive.add(.{ .name = "dev/null", .kind = .char_device });
    archive.add(.{ .name = "dev/sda", .kind = .block_device });
    archive.add(.{ .name = "run/fifo", .kind = .fifo });
    archive.add(.{ .name = "dev/ok", .data = "f" });
    archive.finish();
    try apply(archive.bytes(), .none);
    try testing.expectEqual(@as(u64, 3), test_applier.counts.special_skipped);
    try testing.expectEqualStrings("dev/null", test_applier.first_special_path());
    try testing.expect(test_fs.kind_of("/stage/dev/null") == null);
    try testing.expect(test_fs.kind_of("/stage/run") == null);
    try testing.expectEqualStrings("f", test_fs.content_of("/stage/dev/ok").?);
}

test "extended attributes are set when the store keeps them and counted when it does not" {
    // Goal: user.* and security.capability are set, trusted.* and the overlay's are skipped.
    world();
    var archive = builder.Tar.init(&test_tar);
    archive.add(.{ .name = "bin/ping", .data = "p", .xattrs = &.{
        .{ .name = "security.capability", .value = "\\x01\\x00\\x00\\x02" },
        .{ .name = "user.note", .value = "hi" },
        .{ .name = "trusted.secret", .value = "no" },
        .{ .name = "user.overlay.opaque", .value = "y" },
    } });
    archive.finish();
    try apply(archive.bytes(), .none);
    try testing.expectEqual(@as(u64, 2), test_applier.counts.xattrs_set);
    try testing.expectEqual(@as(u64, 2), test_applier.counts.xattrs_skipped);
    try testing.expectEqualStrings("bin/ping", test_applier.first_xattr_path());
    try testing.expect(test_fs.xattrs_of("/stage/bin/ping") != null);
}

test "a host that maps one id records every owner as root" {
    // Goal: with squash_owner the tar's owners are not applied.
    world();
    test_applier.start(test_fs.interface(), "/stage", true);
    var archive = builder.Tar.init(&test_tar);
    archive.add(.{ .name = "f", .data = "x", .uid = 1000, .gid = 1000 });
    archive.add(.{ .name = "d/", .kind = .directory, .uid = 5, .gid = 5 });
    archive.finish();
    try apply(archive.bytes(), .none);
    try testing.expectEqual(@as(u32, 0), test_fs.stat_of("/stage/f").?.uid);
    try testing.expectEqual(@as(u32, 0), test_fs.stat_of("/stage/d").?.gid);
}

test "the containers are read, and damage is told apart from a failing disk" {
    // Goal: gzip and zstd layers apply alike; a gzip cut short and a flipped byte are `unreadable`
    // with the decoder's word; a tar cut short is `damaged`.
    world();
    var archive = builder.Tar.init(&test_tar);
    archive.add(.{ .name = "f", .data = "zstd works" });
    archive.finish();
    try apply(archive.bytes(), .zstd);
    try testing.expectEqualStrings("zstd works", test_fs.content_of("/stage/f").?);

    world();
    try testing.expectError(error.Failed, apply(archive.bytes()[0..700], .none));
    try expect_refused(.damaged);

    world();
    const gz = builder.gzip(&test_blob, archive.bytes());
    if (test_fs.kind_of("/layer") != null) test_fs.remove_path("/layer");
    test_fs.put_file("/layer", 0o644, gz[0 .. gz.len - 700]);
    try test_layer.start(test_fs.interface(), "/layer");
    defer test_layer.close();
    try testing.expectError(error.Failed, test_applier.apply_layer(&test_layer));
    try expect_refused(.unreadable);
}

test "shared_components finds where the next directory to check starts" {
    // Goal: whole components only, so "ab" and "a" do not share "a".
    try testing.expectEqual(@as(usize, 0), shared_components("a/b", ""));
    try testing.expectEqual(@as(usize, 2), shared_components("a/b", "a"));
    try testing.expectEqual(@as(usize, 2), shared_components("a/b/c", "a/x"));
    try testing.expectEqual(@as(usize, 0), shared_components("ab", "a"));
    try testing.expectEqual(@as(usize, 3), shared_components("a/b", "a/b"));
    try testing.expectEqual(@as(usize, 4), shared_components("a/b/c", "a/b"));
    try testing.expectEqual(@as(usize, 0), shared_components("x", "y"));
}

fn expect_sample_layer() !void {
    // The text file is generated by the same formula the sample was made with.
    var expected: [400 * 1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&expected);
    for (0..9000) |index| try writer.print("line {d} of a compressible text file\n", .{index});
    const words = test_fs.content_of("/stage/usr/share/words.txt").?;
    try testing.expectEqualSlices(u8, writer.buffered(), words);
    const hard_content = test_fs.content_of("/stage/usr/share/hard").?;
    try testing.expectEqualSlices(u8, writer.buffered(), hard_content);
    const noise = test_fs.content_of("/stage/usr/share/noise.bin").?;
    try testing.expectEqual(@as(usize, 20000), noise.len);
    var sum: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(noise, &sum, .{});
    const hex = std.fmt.bytesToHex(sum, .lower);
    const expected_sum = "a23a346a52bea99a81333db1a0288acfd6fc88f6beff3c65c1a5a6c0214d2839";
    try testing.expectEqualStrings(expected_sum, &hex);
    const stat = test_fs.stat_of("/stage/usr/share/noise.bin").?;
    try testing.expectEqual(@as(u32, 1000), stat.uid);
    try testing.expectEqual(@as(u16, 0o600), stat.mode);
    try testing.expectEqual(fs_mod.FileKind.symlink, test_fs.kind_of("/stage/usr/share/link").?);
    const deep = "/stage/usr/share/deeply-nested-directory-name/deeply-nested-directory-name/" ++
        "deeply-nested-directory-name/deeply-nested-directory-name/" ++
        "deeply-nested-directory-name/file.txt";
    try testing.expectEqualStrings("long path\n", test_fs.content_of(deep).?);
    try testing.expectEqual(@as(u64, 1), test_applier.counts.xattrs_set);
    try testing.expectEqual(@as(u64, 1), test_applier.counts.xattrs_skipped);
}

test "layers compressed by real tools are read: gzip level 9 and zstd level 19" {
    // Goal: the standard library's decoders on data a real compressor made (the fixture's own
    // containers store without compressing): many blocks, a long text, noise, and pax records.
    const archives = [_]struct { name: []const u8, bytes: []const u8 }{
        .{ .name = "gzip", .bytes = @embedFile("../testdata/layers/sample.tar.gz") },
        .{ .name = "zstd", .bytes = @embedFile("../testdata/layers/sample.tar.zst") },
    };
    for (archives) |archive| {
        world();
        if (test_fs.kind_of("/layer") != null) test_fs.remove_path("/layer");
        test_fs.put_file("/layer", 0o644, archive.bytes);
        try test_layer.start(test_fs.interface(), "/layer");
        defer test_layer.close();
        try test_applier.apply_layer(&test_layer);
        const digest = try test_layer.finish();
        try testing.expect(digest.eql(@import("../registry/digest.zig").Sha256.of(archive.bytes)));
        try expect_sample_layer();
    }
}
