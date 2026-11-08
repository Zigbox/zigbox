//! Where keys live and how they are read and written (M8): `$XDG_CONFIG_HOME/zbx/keys/` (default
//! `~/.config/zbx/keys/`), mode 0700, holding `<name>.key` (mode 0600, the secret record) and
//! `<name>.pub` (the public text). Not the store: peers write into the store.
//!
//! Nothing here prints or decides. Every call returns a `Problem` for the commands to say in
//! words, so that this file never holds a diagnostic and never a secret in a message.
//!
//! A new key is written to a hidden temporary file (created exclusively, mode 0600, with random
//! characters in its name), flushed, and then hard-linked to its final name: `link` fails when
//! the name exists, so an existing key is never replaced, even by a racing `key new`. The
//! temporary's name is the writer's alone, so no run ever removes or links another's file.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const fs_mod = @import("../store/fs.zig");
const key = @import("key.zig");

const Host = host_mod.Host;
const Fs = fs_mod.Fs;
const PathBuf = fs_mod.PathBuf;

pub const Problem = enum {
    /// Neither `XDG_CONFIG_HOME` nor `HOME` names a usable directory.
    no_home,
    /// The path is longer than a store path.
    path_too_long,
    /// The keys directory is readable by group or others.
    dir_too_open,
    /// The keys path is a symbolic link or some other thing that is not a real directory.
    dir_not_real,
    /// A key of that name is already there.
    exists,
    /// No such key.
    missing,
    /// The file is there and cannot be read, or the system failed.
    unreadable,
    /// The secret file is readable by group or others.
    secret_too_open,
    /// Not what `key.render` writes.
    malformed,
    /// A newer zbx wrote it.
    newer,
};

/// A problem and the errno behind it, where one came from the kernel.
pub const Failure = struct {
    problem: Problem,
    errno: u16 = 0,
};

pub const Error = error{Failed};

fn fail(failure: *Failure, problem: Problem, errno: u16) Error {
    failure.* = .{ .problem = problem, .errno = errno };
    return error.Failed;
}

pub const Paths = struct {
    /// `<config>/zbx/keys`.
    dir: PathBuf,
    /// How much of `dir` exists already: what `ensure` does not have to make. Zero until known.
    base_len: u32,
};

const suffix = "/zbx/keys";

/// The keys directory's path from the environment. False when there is no home to put it in.
pub fn locate(host: Host, paths: *Paths) bool {
    const limit: u32 = constants.store_path_bytes_max - suffix.len;
    var base: []const u8 = "";
    var from_home = false;
    if (host.environment("XDG_CONFIG_HOME", limit)) |config| {
        if (config.len > 0 and config[0] == '/') base = config;
    }
    if (base.len == 0) {
        const home = host.environment("HOME", limit - "/.config".len) orelse return false;
        if (home.len == 0 or home[0] != '/') return false;
        base = home;
        from_home = true;
    }
    const trimmed = std.mem.trimEnd(u8, base, "/");
    const middle: []const u8 = if (from_home) "/.config" else "";
    paths.dir.set(&.{ trimmed, middle, suffix }) catch return false;
    paths.base_len = @intCast(trimmed.len);
    assert(paths.base_len < paths.dir.len);
    return true;
}

/// `<dir>/<name><extension>`.
pub fn file_path(
    paths: *const Paths,
    name: []const u8,
    extension: []const u8,
    out: *PathBuf,
) error{PathTooLong}!void {
    assert(key.name_valid(name));
    assert(extension.len > 0);
    out.set(&.{ paths.dir.text(), "/", name, extension }) catch return error.PathTooLong;
}

/// The random bytes that make a temporary file's name one writer's own.
pub const Unique = [constants.key_temp_random_bytes]u8;

/// `<dir>/.<name><extension>.<hex of unique>.tmp`: hidden, and not any other run's.
pub fn temp_path(
    paths: *const Paths,
    name: []const u8,
    extension: []const u8,
    unique: *const Unique,
    out: *PathBuf,
) error{PathTooLong}!void {
    assert(key.name_valid(name));
    assert(extension.len > 0);
    const hex = std.fmt.bytesToHex(unique.*, .lower);
    const dir = paths.dir.text();
    const parts: []const []const u8 = &.{ dir, "/.", name, extension, ".", &hex, ".tmp" };
    out.set(parts) catch return error.PathTooLong;
}

fn exists(fs: Fs, path: [:0]const u8) bool {
    const stat = fs.lstat(path) catch return false;
    assert(stat.mode <= 0o7777);
    return true;
}

/// Makes the keys directory (and the directories above it that are missing) when it is not
/// there, with mode 0700; refuses one that group or others can read.
pub fn ensure_dir(fs: Fs, paths: *const Paths, failure: *Failure) Error!void {
    const dir = paths.dir.text();
    assert(paths.base_len < dir.len);
    if (fs.lstat(dir)) |stat| {
        return check_dir(stat, failure);
    } else |_| {}
    var at: usize = paths.base_len;
    while (at < dir.len) {
        const next = std.mem.indexOfScalarPos(u8, dir, at + 1, '/') orelse dir.len;
        var prefix: PathBuf = undefined;
        prefix.set(&.{dir[0..next]}) catch unreachable; // A prefix of a path that fits.
        fs.make_directory(prefix.text(), true) catch |err| {
            // The base is the user's: a missing one is the environment naming no directory.
            if (err == error.NotFound) return fail(failure, .no_home, fs.last_errno());
            return failure_of(fs, failure, err);
        };
        at = next;
    }
    const fd = fs.open_directory(dir) catch |err| return failure_of(fs, failure, err);
    defer fs.close(fd);
    fs.set_mode(fd, 0o700) catch |err| return failure_of(fs, failure, err);
}

/// The keys directory must be a real directory (not a link: `chmod` would follow it, and the
/// mode seen would not be the target's) that only its owner can use.
fn check_dir(stat: fs_mod.Stat, failure: *Failure) Error!void {
    if (stat.kind != .dir) return fail(failure, .dir_not_real, 0);
    if (key.mode_too_open(stat.mode)) return fail(failure, .dir_too_open, 0);
}

fn failure_of(fs: Fs, failure: *Failure, err: host_mod.Error) Error {
    const problem: Problem = switch (err) {
        error.NotFound => .missing,
        else => .unreadable,
    };
    return fail(failure, problem, fs.last_errno());
}

/// Writes `bytes` to `final` without ever replacing a file there.
fn write_new(
    fs: Fs,
    temporary: [:0]const u8,
    final: [:0]const u8,
    bytes: []const u8,
    mode: u16,
    failure: *Failure,
) Error!void {
    assert(bytes.len <= constants.key_file_bytes_max);
    if (mode != 0o644) assert(!key.mode_too_open(mode));
    if (exists(fs, final)) return fail(failure, .exists, 0);
    // Exclusive create of a name only this run knows. Never unlink a path before this point:
    // another run may own it.
    const fd = fs.create(temporary, mode) catch |err| return failure_of(fs, failure, err);
    defer fs.unlink(temporary) catch {}; // This run's own file; the final name is its link.
    defer fs.close(fd);
    // The umask may have taken bits off; the mode asked for is what the file gets.
    fs.set_mode(fd, mode) catch |err| return failure_of(fs, failure, err);
    fs.write_all(fd, bytes) catch |err| return failure_of(fs, failure, err);
    fs.fsync(fd) catch |err| return failure_of(fs, failure, err);
    fs.link(temporary, final) catch {
        const errno = fs.last_errno();
        if (exists(fs, final)) return fail(failure, .exists, 0);
        return fail(failure, .unreadable, errno);
    };
}

/// Writes the secret record and the public text of a new key, the secret first. Refuses a name
/// that has either file.
pub fn create(
    fs: Fs,
    paths: *const Paths,
    name: []const u8,
    record: *const key.Record,
    unique: *const Unique,
    failure: *Failure,
) Error!void {
    assert(key.name_valid(name));
    var secret_path: PathBuf = undefined;
    var secret_tmp: PathBuf = undefined;
    var pub_path: PathBuf = undefined;
    var pub_tmp: PathBuf = undefined;
    const all = [4]*PathBuf{ &secret_path, &secret_tmp, &pub_path, &pub_tmp };
    try name_paths(paths, name, unique, all, failure);
    if (exists(fs, secret_path.text()) or exists(fs, pub_path.text())) {
        return fail(failure, .exists, 0);
    }
    var buffer: [constants.key_file_bytes_max]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    const text = key.render(record, &buffer);
    try write_new(fs, secret_tmp.text(), secret_path.text(), text, 0o600, failure);
    var pub_buffer: [key.pub_file_bytes_max]u8 = undefined;
    const encryption: key.Encryption = record.body;
    const file: key.PubFile = .{ .public = record.public, .encryption = encryption };
    const public = key.render_pub(file, &pub_buffer);
    write_new(fs, pub_tmp.text(), pub_path.text(), public, 0o644, failure) catch |err| {
        // A secret with no public half would block the name for good: take it back.
        fs.unlink(secret_path.text()) catch {};
        return err;
    };
}

fn name_paths(
    paths: *const Paths,
    name: []const u8,
    unique: *const Unique,
    out: [4]*PathBuf,
    failure: *Failure,
) Error!void {
    assert(key.name_valid(name));
    const failed = .path_too_long;
    file_path(paths, name, ".key", out[0]) catch return fail(failure, failed, 0);
    temp_path(paths, name, ".key", unique, out[1]) catch return fail(failure, failed, 0);
    file_path(paths, name, ".pub", out[2]) catch return fail(failure, failed, 0);
    temp_path(paths, name, ".pub", unique, out[3]) catch return fail(failure, failed, 0);
}

/// The public key and encryption of `name`, from its `.pub` file.
pub fn read_pub(
    fs: Fs,
    paths: *const Paths,
    name: []const u8,
    failure: *Failure,
) Error!key.PubFile {
    assert(key.name_valid(name));
    var path: PathBuf = undefined;
    file_path(paths, name, ".pub", &path) catch return fail(failure, .path_too_long, 0);
    var buffer: [key.pub_file_bytes_max + 1]u8 = undefined;
    const bytes = fs.read_whole(path.text(), &buffer) catch |err| switch (err) {
        error.FileTooLarge => return fail(failure, .malformed, 0),
        else => return failure_of(fs, failure, err),
    };
    return key.parse_pub(bytes) orelse fail(failure, .malformed, 0);
}

/// The secret record of `name`, refused when its file can be read by group or others, or the
/// keys directory can. The caller zeroes `buffer` after use.
pub fn read_secret(
    fs: Fs,
    paths: *const Paths,
    name: []const u8,
    buffer: *[constants.key_file_bytes_max + 1]u8,
    failure: *Failure,
) Error!key.Record {
    assert(key.name_valid(name));
    const dir = fs.lstat(paths.dir.text()) catch |err| return failure_of(fs, failure, err);
    try check_dir(dir, failure);
    var path: PathBuf = undefined;
    file_path(paths, name, ".key", &path) catch return fail(failure, .path_too_long, 0);
    const fd = fs.open_read(path.text()) catch |err| return failure_of(fs, failure, err);
    defer fs.close(fd);
    const stat = fs.fstat(fd) catch |err| return failure_of(fs, failure, err);
    if (stat.kind != .file) return fail(failure, .malformed, 0);
    if (key.mode_too_open(stat.mode)) return fail(failure, .secret_too_open, 0);
    const length = fs.read_full(fd, buffer) catch |err| return failure_of(fs, failure, err);
    if (length > constants.key_file_bytes_max) return fail(failure, .malformed, 0);
    return key.parse(buffer[0..length]) catch |err| switch (err) {
        error.Malformed => fail(failure, .malformed, 0),
        error.Newer => fail(failure, .newer, 0),
    };
}

/// The names of the keys that have a `.pub` file, in byte order.
pub const Listing = struct {
    names: [constants.keys_listed_max][constants.key_name_bytes_max]u8,
    lengths: [constants.keys_listed_max]u8,
    count: u32,
    /// More keys than `keys_listed_max`: the rest are not shown.
    truncated: bool,
    /// Files whose names do not fit a key's: ignored, and counted.
    ignored: u32,

    pub fn name(listing: *const Listing, index: u32) []const u8 {
        assert(index < listing.count);
        return listing.names[index][0..listing.lengths[index]];
    }

    fn visit(context: *anyopaque, entry: []const u8) void {
        assert(entry.len > 0);
        const listing: *Listing = @ptrCast(@alignCast(context));
        const extension = ".pub";
        if (!std.mem.endsWith(u8, entry, extension)) return;
        const stem = entry[0 .. entry.len - extension.len];
        if (!key.name_valid(stem)) {
            listing.ignored += 1;
            return;
        }
        if (listing.count == constants.keys_listed_max) {
            listing.truncated = true;
            return;
        }
        @memcpy(listing.names[listing.count][0..stem.len], stem);
        listing.lengths[listing.count] = @intCast(stem.len);
        listing.count += 1;
    }

    fn less(listing: *const Listing, left: u32, right: u32) bool {
        return std.mem.lessThan(u8, listing.name(left), listing.name(right));
    }

    /// Insertion sort by name: at most `keys_listed_max` of them.
    fn sort(listing: *Listing) void {
        assert(listing.count <= constants.keys_listed_max);
        var index: u32 = 1;
        while (index < listing.count) : (index += 1) {
            var at = index;
            while (at > 0 and listing.less(at, at - 1)) : (at -= 1) {
                const names = &listing.names;
                std.mem.swap([constants.key_name_bytes_max]u8, &names[at], &names[at - 1]);
                std.mem.swap(u8, &listing.lengths[at], &listing.lengths[at - 1]);
            }
        }
    }
};

/// Lists the keys. A directory that is not there lists none.
pub fn list(fs: Fs, paths: *const Paths, listing: *Listing, failure: *Failure) Error!void {
    listing.count = 0;
    listing.truncated = false;
    listing.ignored = 0;
    const visitor: fs_mod.Visitor = .{ .context = listing, .call = Listing.visit };
    fs.read_dir(paths.dir.text(), visitor) catch |err| switch (err) {
        error.NotFound => return,
        else => return failure_of(fs, failure, err),
    };
    listing.sort();
}

/// True when either file of `name` is there.
pub fn name_taken(fs: Fs, paths: *const Paths, name: []const u8) bool {
    assert(key.name_valid(name));
    var secret: PathBuf = undefined;
    var public: PathBuf = undefined;
    file_path(paths, name, ".key", &secret) catch return false;
    file_path(paths, name, ".pub", &public) catch return false;
    return exists(fs, secret.text()) or exists(fs, public.text());
}

/// True when `name` has a `.key` and no `.pub`: what a run killed between its two links leaves.
/// Such a name is taken, yet `show` cannot open it.
pub fn orphan_secret(fs: Fs, paths: *const Paths, name: []const u8) bool {
    assert(key.name_valid(name));
    var secret: PathBuf = undefined;
    var public: PathBuf = undefined;
    file_path(paths, name, ".key", &secret) catch return false;
    file_path(paths, name, ".pub", &public) catch return false;
    return exists(fs, secret.text()) and !exists(fs, public.text());
}
