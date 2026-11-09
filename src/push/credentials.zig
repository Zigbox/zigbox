//! The credentials of a push (M8, slice 12): a username and a password that come from a file only
//! the user can read, or from standard input, and from nowhere else. Never an argument, never an
//! environment variable, never a file zbx writes.
//!
//! The bytes live in one buffer, `user ":" password`, which is also the text `Authorization:
//! Basic` encodes. The holder is the caller's; it zeroes the whole of it after use
//! (`wipe`, `std.crypto.secureZero`), and nothing here prints, logs or returns a byte of it in a
//! message. The realm rule, which decides where a password may be sent, is here too.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const diagnose = @import("diagnose.zig");
const fs_mod = @import("../store/fs.zig");
const host_mod = @import("../host.zig");
const key = @import("../trust/key.zig");
const net = @import("../registry/net.zig");
const reference_mod = @import("../registry/reference.zig");

const Host = host_mod.Host;
const Problem = diagnose.PasswordProblem;

pub const Error = error{Failed};

/// A username and a password: `bytes[0 .. user_len + 1 + password_len]` is `user:password`.
pub const Credentials = struct {
    bytes: [constants.push_credential_bytes_max]u8,
    user_len: u32,
    password_len: u32,

    pub fn empty() Credentials {
        return .{ .bytes = @splat(0), .user_len = 0, .password_len = 0 };
    }

    /// `user` and `password` joined; for tests, which have no file to read.
    pub fn of(user_text: []const u8, password: []const u8) Credentials {
        assert(user_text.len > 0);
        assert(user_text.len + 1 + password.len <= constants.push_credential_bytes_max);
        var made = empty();
        @memcpy(made.bytes[0..user_text.len], user_text);
        made.bytes[user_text.len] = ':';
        @memcpy(made.bytes[user_text.len + 1 ..][0..password.len], password);
        made.user_len = @intCast(user_text.len);
        made.password_len = @intCast(password.len);
        return made;
    }

    pub fn present(credentials: *const Credentials) bool {
        assert(credentials.user_len + credentials.password_len < credentials.bytes.len);
        return credentials.user_len > 0;
    }

    pub fn user(credentials: *const Credentials) []const u8 {
        assert(credentials.present());
        return credentials.bytes[0..credentials.user_len];
    }

    /// The `user:password` text.
    pub fn joined(credentials: *const Credentials) []const u8 {
        assert(credentials.present());
        return credentials.bytes[0 .. credentials.user_len + 1 + credentials.password_len];
    }

    pub fn wipe(credentials: *Credentials) void {
        std.crypto.secureZero(u8, &credentials.bytes);
        credentials.user_len = 0;
        credentials.password_len = 0;
    }
};

/// Where the password is read from.
pub const Source = union(enum) {
    file: []const u8,
    stdin,
};

/// Reads the password from `source` and joins it to `user`. A failure sets `problem`; no byte of
/// the password is in it. Nothing is read from standard input that is a terminal.
pub fn acquire(
    host: Host,
    user: []const u8,
    source: Source,
    out: *Credentials,
    problem: *Problem,
) Error!void {
    assert(user.len > 0);
    out.wipe();
    errdefer out.wipe();
    if (std.mem.indexOfScalar(u8, user, ':') != null) return fail(problem, .user_has_colon);
    if (user.len + 2 > constants.push_credential_bytes_max) return fail(problem, .too_long);
    var buffer: [constants.push_password_read_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    const length = switch (source) {
        .file => |path| try read_file(host, path, &buffer, problem),
        .stdin => try read_stdin(host, &buffer, problem),
    };
    var line = buffer[0..length];
    if (std.mem.indexOfScalar(u8, line, '\n')) |end| line = line[0..end];
    if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
    if (line.len == 0) return fail(problem, .empty);
    if (user.len + 1 + line.len > constants.push_credential_bytes_max) {
        return fail(problem, .too_long);
    }
    @memcpy(out.bytes[0..user.len], user);
    out.bytes[user.len] = ':';
    @memcpy(out.bytes[user.len + 1 ..][0..line.len], line);
    out.user_len = @intCast(user.len);
    out.password_len = @intCast(line.len);
    assert(out.present());
}

fn fail(problem: *Problem, which: Problem) Error {
    problem.* = which;
    return error.Failed;
}

fn read_file(host: Host, path: []const u8, buffer: []u8, problem: *Problem) Error!usize {
    assert(buffer.len == constants.push_password_read_bytes);
    var path_buffer: fs_mod.PathBuf = undefined;
    path_buffer.set(&.{path}) catch return fail(problem, .file_unreadable);
    if (path.len == 0) return fail(problem, .file_unreadable);
    const fs = host.filesystem();
    // A link is refused with its own cause, as for a passphrase file: a secrets volume mounts
    // links, and "could not be read" would hide why.
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
    const length = fs.read_full(fd, buffer) catch return fail(problem, .file_unreadable);
    return check_read(buffer, length, problem);
}

/// One line more than the bound is room to see that the line is too long.
fn check_read(buffer: []const u8, length: usize, problem: *Problem) Error!usize {
    assert(length <= buffer.len);
    const end = std.mem.indexOfScalar(u8, buffer[0..length], '\n') orelse length;
    if (end > constants.push_credential_bytes_max) return fail(problem, .too_long);
    if (end == buffer.len) return fail(problem, .too_long);
    return length;
}

fn read_stdin(host: Host, buffer: []u8, problem: *Problem) Error!usize {
    assert(buffer.len == constants.push_password_read_bytes);
    // A password typed on a terminal would show: it is refused, not read.
    if (host.input_is_terminal()) return fail(problem, .stdin_is_terminal);
    var length: usize = 0;
    while (length < buffer.len) {
        const count = host.read_some(host.standard_input(), buffer[length..]) catch {
            return fail(problem, .stdin_unreadable);
        };
        if (count == 0) break;
        length += count;
        if (std.mem.indexOfScalar(u8, buffer[0..length], '\n') != null) break;
    }
    return check_read(buffer, length, problem);
}

// ---- Where a credential may go -------------------------------------------------------------

/// Whether the token realm `realm` may be sent the password, for a push to `registry` (owner,
/// 2026-11-09): the realm is on the registry's own host, or is one of the known pairs (Docker
/// Hub's registry and its auth service), or, when the registry itself is on loopback, on
/// loopback. It is spoken to over TLS; plain HTTP only on loopback.
pub fn realm_allowed(registry_host: []const u8, registry_scheme: net.Scheme, realm: net.Url) bool {
    assert(registry_host.len > 0);
    assert(realm.host.len > 0);
    const loopback = reference_mod.is_loopback(realm.host);
    if (realm.scheme == .http and !(loopback and registry_scheme == .http)) return false;
    if (std.ascii.eqlIgnoreCase(realm.host, registry_host)) return true;
    if (loopback) return reference_mod.is_loopback(registry_host);
    for (known_pairs) |pair| {
        const same = std.ascii.eqlIgnoreCase(registry_host, pair.registry);
        if (same and std.ascii.eqlIgnoreCase(realm.host, pair.realm)) return true;
    }
    return false;
}

const Pair = struct { registry: []const u8, realm: []const u8 };

/// Registries whose token service is on another host by design.
const known_pairs = [_]Pair{
    .{ .registry = "registry-1.docker.io", .realm = "auth.docker.io" },
};

/// The `Authorization: Basic` value of `credentials`: the base64 of `user:password`, in `out`.
pub fn encode_basic(
    credentials: *const Credentials,
    out: *[constants.push_basic_bytes_max]u8,
) []const u8 {
    const joined = credentials.joined();
    assert(std.base64.standard.Encoder.calcSize(joined.len) <= out.len);
    return std.base64.standard.Encoder.encode(out, joined);
}
