//! The file-system half of the host interface, which the store is written against. `host.zig`
//! hands one out (`Host.filesystem`): the real one is `host_real_fs.zig` (syscalls), the
//! simulator's is `fs_sim.zig` (an in-memory file tree with faults and crashes). Code above this
//! file does not know which it has, exactly as for the rest of the host (docs/STYLE.md, layer 4).
//!
//! It is a separate vtable only because the store needs about twenty operations the rest of the
//! host does not, and a store test needs a whole file tree, which the container simulator's
//! small model does not have. The rules are the host's: a plain `host.Error` per failure, the
//! raw errno of the last failed call from `last_errno`, no allocation, retries of interrupted
//! calls written once, in the wrappers here, so that the simulator's injected `EINTR` exercises
//! the code that runs in production.
//!
//! Ids are always the ones the calling process sees. The store's work runs inside the user's
//! user namespace (`namespace.zig`), so a `chown` here is a `chown` in the container's view.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host = @import("../host.zig");

pub const Error = host.Error;

/// An open file. A small integer, as in `host.Handle`, so the simulator can use a table.
pub const Fd = u32;

pub const FileKind = enum { file, dir, symlink, char_device, block_device, fifo, socket };

/// What `lstat` reports: the file itself, never what a symlink points to.
pub const Stat = struct {
    kind: FileKind,
    /// The permission bits and setuid, setgid and sticky (07777); never the file type.
    mode: u16,
    uid: u32,
    gid: u32,
    size: u64,
    inode: u64,
    links: u32,
    /// A device node's numbers; zero for anything else. A character device 0/0 is how an
    /// overlay's upper layer records a deletion.
    rdev_major: u32 = 0,
    rdev_minor: u32 = 0,
};

/// Called once per name in a directory, "." and ".." excluded, in the order the file system
/// gives them (which is not sorted and differs between file systems).
pub const Visitor = struct {
    context: *anyopaque,
    call: *const fn (context: *anyopaque, name: []const u8) void,
};

/// What `set_path_attributes` sets on a path, without following a symlink.
pub const PathAttributes = struct {
    /// Null for a symlink, which has no mode of its own.
    mode: ?u16,
    uid: u32,
    gid: u32,
    mtime: u64,
};

pub const VTable = struct {
    lstat: *const fn (context: *anyopaque, path: [:0]const u8) Error!Stat,
    read_dir: *const fn (context: *anyopaque, path: [:0]const u8, visitor: Visitor) Error!void,
    read_link: *const fn (context: *anyopaque, path: [:0]const u8, buffer: []u8) Error!u32,
    /// The names of the file's extended attributes, each ending in NUL. `FileTooLarge` if they
    /// do not fit `buffer`; a file system without attributes lists none.
    list_xattrs: *const fn (context: *anyopaque, path: [:0]const u8, buffer: []u8) Error!u32,
    /// One attribute's value (of the file itself, not of what a symlink points to).
    get_xattr: *const fn (
        context: *anyopaque,
        path: [:0]const u8,
        name: [:0]const u8,
        buffer: []u8,
    ) Error!u32,
    /// Opens a regular file for reading and refuses a symlink (`ELOOP`), so a file that was
    /// swapped for a link after `lstat` is not followed.
    open_read: *const fn (context: *anyopaque, path: [:0]const u8) Error!Fd,
    read: *const fn (context: *anyopaque, fd: Fd, buffer: []u8) Error!u32,
    /// Creates a new file for writing with the given permission bits (before any umask the
    /// process has: the real host clears it). Fails if the path exists.
    create: *const fn (context: *anyopaque, path: [:0]const u8, mode: u16) Error!Fd,
    write: *const fn (context: *anyopaque, fd: Fd, bytes: []const u8) Error!u32,
    fsync: *const fn (context: *anyopaque, fd: Fd) Error!void,
    close: *const fn (context: *anyopaque, fd: Fd) void,
    set_owner: *const fn (context: *anyopaque, fd: Fd, uid: u32, gid: u32) Error!void,
    set_mode: *const fn (context: *anyopaque, fd: Fd, mode: u16) Error!void,
    set_xattr: *const fn (
        context: *anyopaque,
        fd: Fd,
        name: [:0]const u8,
        value: []const u8,
    ) Error!void,
    set_mtime: *const fn (context: *anyopaque, fd: Fd, seconds: u64) Error!void,
    rename: *const fn (context: *anyopaque, from: [:0]const u8, to: [:0]const u8) Error!void,
    unlink: *const fn (context: *anyopaque, path: [:0]const u8) Error!void,
    /// Makes a directory (mode 0755 for the store's own; the real host clears the umask).
    /// An existing one is `error.Exists`-like success only when `exist_ok`.
    make_directory: *const fn (context: *anyopaque, path: [:0]const u8, exist_ok: bool) Error!void,
    remove_directory: *const fn (context: *anyopaque, path: [:0]const u8) Error!void,
    /// Makes the directory's entries (a rename, a new file) durable.
    sync_directory: *const fn (context: *anyopaque, path: [:0]const u8) Error!void,
    /// A second name for the file at `from`, at `to` (`link(2)`): the same inode, so the same
    /// bytes, owner, mode and attributes. The materialized cache is made of these.
    link: *const fn (context: *anyopaque, from: [:0]const u8, to: [:0]const u8) Error!void,
    /// A symbolic link at `path` pointing to `target`.
    symlink: *const fn (context: *anyopaque, target: [:0]const u8, path: [:0]const u8) Error!void,
    /// Owner, mode and modification time of the path itself (`lchown`, `chmod`, `utimensat`).
    set_path_attributes: *const fn (
        context: *anyopaque,
        path: [:0]const u8,
        attributes: PathAttributes,
    ) Error!void,
    /// An attribute of the path itself (`lsetxattr`).
    set_path_xattr: *const fn (
        context: *anyopaque,
        path: [:0]const u8,
        name: [:0]const u8,
        value: []const u8,
    ) Error!void,
    last_errno: *const fn (context: *anyopaque) u16,
};

pub const Fs = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub fn lstat(fs: Fs, path: [:0]const u8) Error!Stat {
        assert(path.len > 0);
        assert(path.len <= constants.path_bytes_max);
        for (0..constants.store_io_retries_max + 1) |_| {
            const found = fs.vtable.lstat(fs.context, path) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
            assert(found.mode <= 0o7777);
            return found;
        }
        return error.IoFailed;
    }

    pub fn read_dir(fs: Fs, path: [:0]const u8, visitor: Visitor) Error!void {
        assert(path.len > 0);
        assert(path.len <= constants.path_bytes_max);
        for (0..constants.store_io_retries_max + 1) |_| {
            fs.vtable.read_dir(fs.context, path, visitor) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
            return;
        }
        return error.IoFailed;
    }

    pub fn read_link(fs: Fs, path: [:0]const u8, buffer: []u8) Error![]const u8 {
        assert(path.len > 0);
        assert(buffer.len > 0);
        for (0..constants.store_io_retries_max + 1) |_| {
            const length = fs.vtable.read_link(fs.context, path, buffer) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
            assert(length <= buffer.len);
            return buffer[0..length];
        }
        return error.IoFailed;
    }

    pub fn list_xattrs(fs: Fs, path: [:0]const u8, buffer: []u8) Error![]const u8 {
        assert(path.len > 0);
        assert(buffer.len > 0);
        for (0..constants.store_io_retries_max + 1) |_| {
            const length = fs.vtable.list_xattrs(
                fs.context,
                path,
                buffer,
            ) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
            assert(length <= buffer.len);
            return buffer[0..length];
        }
        return error.IoFailed;
    }

    pub fn get_xattr(
        fs: Fs,
        path: [:0]const u8,
        name: [:0]const u8,
        buffer: []u8,
    ) Error![]const u8 {
        assert(path.len > 0);
        assert(name.len > 0);
        for (0..constants.store_io_retries_max + 1) |_| {
            const length = fs.vtable.get_xattr(
                fs.context,
                path,
                name,
                buffer,
            ) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
            assert(length <= buffer.len);
            return buffer[0..length];
        }
        return error.IoFailed;
    }

    pub fn open_read(fs: Fs, path: [:0]const u8) Error!Fd {
        assert(path.len > 0);
        assert(path.len <= constants.path_bytes_max);
        for (0..constants.store_io_retries_max + 1) |_| {
            return fs.vtable.open_read(fs.context, path) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
        }
        return error.IoFailed;
    }

    /// Reads up to `buffer.len` bytes; zero is the end of the file.
    pub fn read(fs: Fs, fd: Fd, buffer: []u8) Error!u32 {
        assert(buffer.len > 0);
        assert(buffer.len <= constants.store_io_buffer_bytes);
        for (0..constants.store_io_retries_max + 1) |_| {
            const count = fs.vtable.read(fs.context, fd, buffer) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
            assert(count <= buffer.len);
            return count;
        }
        return error.IoFailed;
    }

    /// Reads until `buffer` is full or the file ends; returns the bytes read.
    pub fn read_full(fs: Fs, fd: Fd, buffer: []u8) Error!u32 {
        assert(buffer.len > 0);
        var filled: u32 = 0;
        var calls: u32 = 0;
        while (filled < buffer.len) {
            // A read that returns bytes makes progress; the bound covers one-byte reads.
            calls += 1;
            if (calls > buffer.len + constants.store_io_retries_max) return error.Stalled;
            const room = buffer[filled..];
            const count = try fs.read(fd, room[0..@min(room.len, constants.store_io_buffer_bytes)]);
            if (count == 0) break;
            filled += count;
        }
        assert(filled <= buffer.len);
        return filled;
    }

    pub fn create(fs: Fs, path: [:0]const u8, mode: u16) Error!Fd {
        assert(path.len > 0);
        assert(mode <= 0o7777);
        for (0..constants.store_io_retries_max + 1) |_| {
            return fs.vtable.create(fs.context, path, mode) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
        }
        return error.IoFailed;
    }

    /// Writes every byte, continuing after a short write. A call that writes nothing is
    /// `Stalled`, so the loop ends.
    pub fn write_all(fs: Fs, fd: Fd, bytes: []const u8) Error!void {
        var written: usize = 0;
        var calls: usize = 0;
        var retries: u32 = 0;
        // A call that writes bytes counts toward `calls`, which cannot pass `bytes.len`; an
        // interrupted one counts toward `retries`, which only a call that wrote resets.
        while (written < bytes.len) {
            const count = fs.vtable.write(fs.context, fd, bytes[written..]) catch |err| {
                if (err != error.Interrupted) return err;
                retries += 1;
                if (retries > constants.store_io_retries_max) return error.IoFailed;
                continue;
            };
            if (count == 0) return error.Stalled;
            retries = 0;
            calls += 1;
            assert(calls <= bytes.len);
            assert(count <= bytes.len - written);
            written += count;
        }
        assert(written == bytes.len);
    }

    pub fn fsync(fs: Fs, fd: Fd) Error!void {
        assert(@intFromPtr(fs.vtable) != 0);
        assert(fd < std.math.maxInt(i32));
        for (0..constants.store_io_retries_max + 1) |_| {
            fs.vtable.fsync(fs.context, fd) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
            return;
        }
        return error.IoFailed;
    }

    pub fn close(fs: Fs, fd: Fd) void {
        assert(fd < std.math.maxInt(i32));
        assert(@intFromPtr(fs.vtable) != 0);
        fs.vtable.close(fs.context, fd);
    }

    pub fn set_owner(fs: Fs, fd: Fd, uid: u32, gid: u32) Error!void {
        assert(uid != std.math.maxInt(u32)); // (uid_t)-1 means "no change", never an owner.
        assert(gid != std.math.maxInt(u32));
        for (0..constants.store_io_retries_max + 1) |_| {
            fs.vtable.set_owner(fs.context, fd, uid, gid) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
            return;
        }
        return error.IoFailed;
    }

    pub fn set_mode(fs: Fs, fd: Fd, mode: u16) Error!void {
        assert(fd < std.math.maxInt(i32));
        assert(mode <= 0o7777);
        for (0..constants.store_io_retries_max + 1) |_| {
            fs.vtable.set_mode(fs.context, fd, mode) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
            return;
        }
        return error.IoFailed;
    }

    pub fn set_xattr(fs: Fs, fd: Fd, name: [:0]const u8, value: []const u8) Error!void {
        assert(name.len > 0);
        assert(value.len <= constants.store_xattr_value_bytes_max);
        for (0..constants.store_io_retries_max + 1) |_| {
            fs.vtable.set_xattr(fs.context, fd, name, value) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
            return;
        }
        return error.IoFailed;
    }

    pub fn set_mtime(fs: Fs, fd: Fd, seconds: u64) Error!void {
        assert(fd < std.math.maxInt(i32));
        assert(seconds < 1 << 40);
        for (0..constants.store_io_retries_max + 1) |_| {
            fs.vtable.set_mtime(fs.context, fd, seconds) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
            return;
        }
        return error.IoFailed;
    }

    pub fn rename(fs: Fs, from: [:0]const u8, to: [:0]const u8) Error!void {
        assert(from.len > 0);
        assert(to.len > 0);
        assert(!std.mem.eql(u8, from, to));
        for (0..constants.store_io_retries_max + 1) |_| {
            fs.vtable.rename(fs.context, from, to) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
            return;
        }
        return error.IoFailed;
    }

    pub fn unlink(fs: Fs, path: [:0]const u8) Error!void {
        assert(path.len <= constants.path_bytes_max);
        assert(path.len > 0);
        for (0..constants.store_io_retries_max + 1) |_| {
            fs.vtable.unlink(fs.context, path) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
            return;
        }
        return error.IoFailed;
    }

    pub fn make_directory(fs: Fs, path: [:0]const u8, exist_ok: bool) Error!void {
        assert(path.len > 0);
        assert(path.len <= constants.path_bytes_max);
        for (0..constants.store_io_retries_max + 1) |_| {
            fs.vtable.make_directory(fs.context, path, exist_ok) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
            return;
        }
        return error.IoFailed;
    }

    pub fn remove_directory(fs: Fs, path: [:0]const u8) Error!void {
        assert(path.len <= constants.path_bytes_max);
        assert(path.len > 0);
        for (0..constants.store_io_retries_max + 1) |_| {
            fs.vtable.remove_directory(fs.context, path) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
            return;
        }
        return error.IoFailed;
    }

    pub fn link(fs: Fs, from: [:0]const u8, to: [:0]const u8) Error!void {
        assert(from.len > 0);
        assert(to.len > 0);
        assert(!std.mem.eql(u8, from, to));
        for (0..constants.store_io_retries_max + 1) |_| {
            fs.vtable.link(fs.context, from, to) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
            return;
        }
        return error.IoFailed;
    }

    pub fn symlink(fs: Fs, target: [:0]const u8, path: [:0]const u8) Error!void {
        assert(target.len > 0);
        assert(path.len > 0);
        assert(target.len <= constants.store_symlink_target_bytes_max);
        for (0..constants.store_io_retries_max + 1) |_| {
            fs.vtable.symlink(fs.context, target, path) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
            return;
        }
        return error.IoFailed;
    }

    pub fn set_path_attributes(fs: Fs, path: [:0]const u8, attributes: PathAttributes) Error!void {
        assert(path.len > 0);
        assert(attributes.uid != std.math.maxInt(u32)); // (uid_t)-1 means "no change".
        assert(attributes.gid != std.math.maxInt(u32));
        if (attributes.mode) |mode| assert(mode <= 0o7777);
        for (0..constants.store_io_retries_max + 1) |_| {
            fs.vtable.set_path_attributes(fs.context, path, attributes) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
            return;
        }
        return error.IoFailed;
    }

    pub fn set_path_xattr(
        fs: Fs,
        path: [:0]const u8,
        name: [:0]const u8,
        value: []const u8,
    ) Error!void {
        assert(path.len > 0);
        assert(name.len > 0);
        assert(value.len <= constants.store_xattr_value_bytes_max);
        for (0..constants.store_io_retries_max + 1) |_| {
            fs.vtable.set_path_xattr(fs.context, path, name, value) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
            return;
        }
        return error.IoFailed;
    }

    pub fn sync_directory(fs: Fs, path: [:0]const u8) Error!void {
        assert(path.len <= constants.path_bytes_max);
        assert(path.len > 0);
        for (0..constants.store_io_retries_max + 1) |_| {
            fs.vtable.sync_directory(fs.context, path) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
            return;
        }
        return error.IoFailed;
    }

    /// The raw errno of the most recent failed call, 0 after a success.
    pub fn last_errno(fs: Fs) u16 {
        assert(@intFromPtr(fs.vtable) != 0);
        const errno = fs.vtable.last_errno(fs.context);
        assert(errno < 4096);
        return errno;
    }

    /// The whole file in `buffer` (`FileTooLarge` if it is longer), for the small files of the
    /// store: a tree object, a root's record, `store.zon`.
    pub fn read_whole(fs: Fs, path: [:0]const u8, buffer: []u8) Error![]u8 {
        assert(buffer.len > 0);
        assert(buffer.len < std.math.maxInt(u32));
        const fd = try fs.open_read(path);
        defer fs.close(fd);
        const length = try fs.read_full(fd, buffer);
        if (length == buffer.len) {
            // Full: one more byte tells exactly-full from too long.
            var extra: [1]u8 = undefined;
            if (try fs.read(fd, &extra) != 0) return error.FileTooLarge;
        }
        return buffer[0..length];
    }

    /// Writes `bytes` to `final` so that a reader and a crash see the old file or all of the new
    /// one, never part: a new file at `temporary`, written whole and flushed, renamed over
    /// `final`, then the directory flushed. `temporary` and `final` are on one file system.
    /// The file is owned by the calling process with `mode`; a failure removes the temporary.
    /// `failure` is what went wrong, read before the cleanup can change the errno.
    pub fn write_atomic(
        fs: Fs,
        temporary: [:0]const u8,
        final: [:0]const u8,
        directory: [:0]const u8,
        bytes: []const u8,
        mode: u16,
        failure: *Failure,
    ) Error!void {
        assert(bytes.len <= constants.store_tree_bytes_max);
        assert(!std.mem.eql(u8, temporary, final));
        const fd = fs.create(temporary, mode) catch |err| return fs.note(failure, err);
        fs.fill(fd, bytes) catch |err| {
            const noted = fs.note(failure, err);
            fs.close(fd);
            fs.unlink(temporary) catch {}; // The write's own error is the one to report.
            return noted;
        };
        fs.close(fd);
        fs.rename(temporary, final) catch |err| {
            const noted = fs.note(failure, err);
            fs.unlink(temporary) catch {}; // Same: the rename's error is the one to report.
            return noted;
        };
        fs.sync_directory(directory) catch |err| return fs.note(failure, err);
    }

    /// Records `err` with the errno it left, and returns it.
    pub fn note(fs: Fs, failure: *Failure, err: Error) Error {
        assert(@intFromPtr(failure) != 0);
        assert(fs.last_errno() < 4096);
        failure.* = .{ .err = err, .errno = fs.last_errno() };
        return err;
    }

    fn fill(fs: Fs, fd: Fd, bytes: []const u8) Error!void {
        assert(fd < std.math.maxInt(i32));
        assert(bytes.len <= constants.store_tree_bytes_max);
        try fs.write_all(fd, bytes);
        try fs.set_mtime(fd, constants.store_mtime_seconds);
        try fs.fsync(fd);
    }
};

/// A failed call and the errno it left, kept by the caller of a sequence of calls whose cleanup
/// would overwrite `last_errno`.
pub const Failure = struct {
    err: Error,
    errno: u16,
};

/// A NUL-terminated path built in a fixed buffer, from parts, never longer than a store path.
pub const PathBuf = struct {
    bytes: [constants.store_path_bytes_max + 1]u8,
    len: u32,

    pub const Error = error{PathTooLong};

    /// Replaces the contents with the parts joined; `/` is the caller's to include.
    pub fn set(path: *PathBuf, parts: []const []const u8) PathBuf.Error!void {
        assert(parts.len > 0);
        var length: usize = 0;
        for (parts) |part| {
            if (length + part.len > constants.store_path_bytes_max) return error.PathTooLong;
            @memcpy(path.bytes[length..][0..part.len], part);
            length += part.len;
        }
        path.bytes[length] = 0;
        path.len = @intCast(length);
        assert(path.bytes[path.len] == 0);
    }

    pub fn text(path: *const PathBuf) [:0]const u8 {
        assert(path.len <= constants.store_path_bytes_max);
        assert(path.bytes[path.len] == 0);
        return path.bytes[0..path.len :0];
    }
};
