//! What the macOS `zbx` and `zbx guest serve` say to each other over one vsock connection, one
//! forwarded command per connection. Shared by both sides (and so free of anything but `std`).
//!
//! A frame is a kind byte, a four-byte little-endian length and that many bytes. The client opens
//! with a `start` frame (command line, working directory, environment, which streams are
//! terminals, and the terminal's size);
//! after it, `stdin` and `stdin_eof` go to the guest, `stdout` and `stderr` come back, `signal`
//! and `window` go to the guest, and `exit` ends the conversation from the guest's side.
//!
//! `parse_header` and `parse_start` accept only what `render_header` and `render_start` write: a
//! frame with a kind the protocol does not have, a length past its bound, or a fixed-size frame of
//! the wrong size is refused, so a damaged stream stops at the first bad frame.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

pub const Kind = enum(u8) {
    start = 1,
    stdin = 2,
    stdin_eof = 3,
    stdout = 4,
    stderr = 5,
    signal = 6,
    window = 7,
    exit = 8,
    /// From the guest, before `exit`: the command failed and the store disk is nearly full.
    disk_full = 9,
};

pub const Header = struct {
    kind: Kind,
    length: u32,
};

/// The frame's size when the kind fixes it, else null.
fn fixed_length(kind: Kind) ?u32 {
    return switch (kind) {
        .stdin_eof => 0,
        .signal => 1,
        .window => 4,
        .exit => 2,
        .disk_full => 8,
        else => null,
    };
}

fn length_max(kind: Kind) u32 {
    return switch (kind) {
        .start => constants.forward_start_bytes_max,
        .stdin, .stdout, .stderr => constants.forward_data_bytes_max,
        else => fixed_length(kind).?,
    };
}

pub fn render_header(buffer: *[constants.forward_header_bytes]u8, kind: Kind, length: u32) void {
    assert(length <= length_max(kind));
    if (fixed_length(kind)) |fixed| assert(length == fixed);
    buffer[0] = @backingInt(kind);
    std.mem.writeInt(u32, buffer[1..5], length, .little);
    assert(buffer[0] != 0); // Kind tags start at 1: a zero byte is not a frame.
}

pub fn parse_header(bytes: *const [constants.forward_header_bytes]u8) ?Header {
    const kind = std.enums.fromInt(Kind, bytes[0]) orelse return null;
    const length = std.mem.readInt(u32, bytes[1..5], .little);
    if (length > length_max(kind)) return null;
    if (fixed_length(kind)) |fixed| {
        if (length != fixed) return null;
    }
    assert(length <= length_max(kind)); // Only a legal length is ever returned.
    return .{ .kind = kind, .length = length };
}

/// The first frame's content. The slices point into the buffer `parse_start` was given.
pub const Start = struct {
    /// The command's standard input and output are a pty: the Mac's stdin and stdout are both
    /// terminals. Otherwise they are pipes, so a redirect behaves as it does on Linux.
    pty: bool,
    /// The command's standard error is a pipe of its own, answered with `stderr` frames: the
    /// Mac's stderr is not a terminal, or there is no pty. With a pty and a terminal on stderr
    /// too, it is the pty.
    stderr_pipe: bool,
    rows: u16,
    columns: u16,
    working_directory: []const u8,
    arguments: []const []const u8,
    environment: []const []const u8,
};

/// A string in a start frame: a two-byte length and the bytes. No NUL, no more than this.
const string_bytes_max: u32 = constants.arg_bytes_max;

fn put_string(out: []u8, at: usize, text: []const u8) usize {
    assert(text.len <= string_bytes_max);
    assert(std.mem.indexOfScalar(u8, text, 0) == null);
    std.mem.writeInt(u16, out[at..][0..2], @intCast(text.len), .little);
    @memcpy(out[at + 2 ..][0..text.len], text);
    return at + 2 + text.len;
}

/// The start frame's payload, or null if it does not fit `forward_start_bytes_max`.
pub fn render_start(out: []u8, start: *const Start) ?[]const u8 {
    assert(out.len >= constants.forward_start_bytes_max);
    assert(start.arguments.len <= constants.args_count_max);
    assert(start.environment.len <= constants.forward_env_count_max);
    var size: usize = 1 + 4 + 2 + 2 + 2 + start.working_directory.len;
    for (start.arguments) |argument| size += 2 + argument.len;
    for (start.environment) |entry| size += 2 + entry.len;
    assert(size >= 11); // Flags, size, two counts and the directory's length.
    if (size > constants.forward_start_bytes_max) return null;
    // Without a pty every stream is a pipe, stderr included.
    if (!start.pty) assert(start.stderr_pipe);
    out[0] = @intFromBool(start.pty) | (@as(u8, @intFromBool(start.stderr_pipe)) << 1);
    std.mem.writeInt(u16, out[1..3], start.rows, .little);
    std.mem.writeInt(u16, out[3..5], start.columns, .little);
    std.mem.writeInt(u16, out[5..7], @intCast(start.arguments.len), .little);
    std.mem.writeInt(u16, out[7..9], @intCast(start.environment.len), .little);
    var at = put_string(out, 9, start.working_directory);
    for (start.arguments) |argument| at = put_string(out, at, argument);
    for (start.environment) |entry| at = put_string(out, at, entry);
    assert(at == size); // What was written is what was counted.
    assert(at <= constants.forward_start_bytes_max);
    return out[0..at];
}

/// Reads one string; null if the payload ends first, or the string is over its bound or has a
/// NUL.
fn take_string(payload: []const u8, at: *usize) ?[]const u8 {
    assert(at.* <= payload.len);
    if (at.* + 2 > payload.len) return null;
    const length = std.mem.readInt(u16, payload[at.*..][0..2], .little);
    if (length > string_bytes_max) return null;
    if (at.* + 2 + length > payload.len) return null;
    const text = payload[at.* + 2 ..][0..length];
    if (std.mem.indexOfScalar(u8, text, 0) != null) return null;
    at.* += 2 + length;
    assert(at.* <= payload.len); // One string never reads past the payload.
    return text;
}

/// The arrays hold the slices of the command line and the environment; the caller sizes them.
pub fn parse_start(
    payload: []const u8,
    arguments_storage: *[constants.args_count_max][]const u8,
    environment_storage: *[constants.forward_env_count_max][]const u8,
) ?Start {
    if (payload.len < 9) return null;
    // Bit 0: pty. Bit 1: stderr is a pipe. No pty means stderr is a pipe, so 0 is not written.
    if (payload[0] == 0 or payload[0] > 3) return null;
    const argument_count = std.mem.readInt(u16, payload[5..7], .little);
    const environment_count = std.mem.readInt(u16, payload[7..9], .little);
    if (argument_count == 0 or argument_count > constants.args_count_max) return null;
    if (environment_count > constants.forward_env_count_max) return null;
    var at: usize = 9;
    const directory = take_string(payload, &at) orelse return null;
    for (0..argument_count) |index| {
        arguments_storage[index] = take_string(payload, &at) orelse return null;
    }
    for (0..environment_count) |index| {
        const entry = take_string(payload, &at) orelse return null;
        if (std.mem.indexOfScalar(u8, entry, '=') == null) return null;
        if (entry[0] == '=') return null;
        environment_storage[index] = entry;
    }
    assert(at <= payload.len);
    if (at != payload.len) return null;
    return .{
        .pty = payload[0] & 1 == 1,
        .stderr_pipe = payload[0] & 2 == 2,
        .rows = std.mem.readInt(u16, payload[1..3], .little),
        .columns = std.mem.readInt(u16, payload[3..5], .little),
        .working_directory = directory,
        .arguments = arguments_storage[0..argument_count],
        .environment = environment_storage[0..environment_count],
    };
}

/// How a command ended: it exited with a code, or a signal killed it.
pub const Exit = struct {
    signaled: bool,
    value: u8,
};

pub fn render_exit(buffer: *[2]u8, exit: Exit) void {
    buffer[0] = @intFromBool(exit.signaled);
    buffer[1] = exit.value;
    assert(buffer[0] <= 1); // parse_exit refuses anything else.
}

pub fn parse_exit(bytes: *const [2]u8) ?Exit {
    if (bytes[0] > 1) return null;
    return .{ .signaled = bytes[0] == 1, .value = bytes[1] };
}

/// The store disk's room, in MiB, as the guest saw it when a command failed.
pub const DiskFull = struct {
    free_mib: u32,
    total_mib: u32,
};

pub fn render_disk_full(buffer: *[8]u8, note: DiskFull) void {
    assert(note.free_mib <= note.total_mib);
    std.mem.writeInt(u32, buffer[0..4], note.free_mib, .little);
    std.mem.writeInt(u32, buffer[4..8], note.total_mib, .little);
}

/// Null for a note that says more is free than the disk holds.
pub fn parse_disk_full(bytes: *const [8]u8) ?DiskFull {
    const note: DiskFull = .{
        .free_mib = std.mem.readInt(u32, bytes[0..4], .little),
        .total_mib = std.mem.readInt(u32, bytes[4..8], .little),
    };
    if (note.free_mib > note.total_mib) return null;
    return note;
}

pub fn render_window(buffer: *[4]u8, rows: u16, columns: u16) void {
    std.mem.writeInt(u16, buffer[0..2], rows, .little);
    std.mem.writeInt(u16, buffer[2..4], columns, .little);
}

/// The environment variable names that never come from the Mac: they would change where the guest
/// puts things or what the guest's programs load.
pub fn environment_name_allowed(name: []const u8) bool {
    if (name.len == 0 or name.len > constants.env_name_bytes_max) return false;
    for (name) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '_') return false;
    }
    const denied = [_][]const u8{ "PATH", "HOME", "USER", "LOGNAME", "SHELL", "PWD", "OLDPWD" };
    for (denied) |entry| {
        if (std.mem.eql(u8, name, entry)) return false;
    }
    const denied_prefixes = [_][]const u8{ "LD_", "XDG_", "DBUS_", "ZBX_CGROUP", "DYLD_" };
    for (denied_prefixes) |prefix| {
        if (std.mem.startsWith(u8, name, prefix)) return false;
    }
    return true;
}

const sample_arguments = [_][]const u8{ "zbx", "run", "alpine", "--", "cat", "/etc/os-release" };
const sample_environment = [_][]const u8{ "TERM=xterm-256color", "NO_COLOR=1" };

fn sample() Start {
    return .{
        .pty = true,
        .stderr_pipe = false,
        .rows = 24,
        .columns = 80,
        .working_directory = "/Users/ada/project",
        .arguments = &sample_arguments,
        .environment = &sample_environment,
    };
}

test "a header round-trips and a bad kind, length or fixed size is refused" {
    // Goal: parse accepts only what render writes. Method: every kind at a legal length, then
    // an unknown kind, a length one past the bound, and fixed-size kinds of the wrong size.
    var bytes: [constants.forward_header_bytes]u8 = @splat(0xaa);
    for (std.enums.values(Kind)) |kind| {
        const length = fixed_length(kind) orelse length_max(kind);
        render_header(&bytes, kind, length);
        const parsed = parse_header(&bytes).?;
        try std.testing.expectEqual(kind, parsed.kind);
        try std.testing.expectEqual(length, parsed.length);
        if (fixed_length(kind) == null) {
            std.mem.writeInt(u32, bytes[1..5], length + 1, .little);
            try std.testing.expect(parse_header(&bytes) == null);
        } else {
            std.mem.writeInt(u32, bytes[1..5], length + 1, .little);
            try std.testing.expect(parse_header(&bytes) == null);
        }
    }
    bytes[0] = 0;
    try std.testing.expect(parse_header(&bytes) == null);
    bytes[0] = 9;
    try std.testing.expect(parse_header(&bytes) == null);
}

test "a start frame round-trips and every damage is refused" {
    // Goal: the first frame. Method: render the sample, read it back, then cut it, pad it,
    // break a count, put a NUL in a string and drop the = of an environment entry.
    var out: [constants.forward_start_bytes_max]u8 = @splat(0xaa);
    const payload = render_start(&out, &sample()).?;
    var arguments: [constants.args_count_max][]const u8 = undefined;
    var environment: [constants.forward_env_count_max][]const u8 = undefined;
    const parsed = parse_start(payload, &arguments, &environment).?;
    try std.testing.expect(parsed.pty);
    try std.testing.expect(!parsed.stderr_pipe);
    try std.testing.expectEqual(@as(u16, 24), parsed.rows);
    try std.testing.expectEqualStrings("/Users/ada/project", parsed.working_directory);
    try std.testing.expectEqual(@as(usize, 6), parsed.arguments.len);
    try std.testing.expectEqualStrings("--", parsed.arguments[3]);
    try std.testing.expectEqualStrings("NO_COLOR=1", parsed.environment[1]);
    const cut = payload[0 .. payload.len - 1];
    try std.testing.expect(parse_start(cut, &arguments, &environment) == null);
    var padded: [constants.forward_start_bytes_max + 1]u8 = undefined;
    @memcpy(padded[0..payload.len], payload);
    padded[payload.len] = 0;
    const longer = padded[0 .. payload.len + 1];
    try std.testing.expect(parse_start(longer, &arguments, &environment) == null);
    var damaged: [constants.forward_start_bytes_max]u8 = undefined;
    @memcpy(damaged[0..payload.len], payload);
    damaged[5] = 0; // No arguments.
    damaged[6] = 0;
    try std.testing.expect(parse_start(damaged[0..payload.len], &arguments, &environment) == null);
    @memcpy(damaged[0..payload.len], payload);
    damaged[0] = 4; // Not a flag.
    try std.testing.expect(parse_start(damaged[0..payload.len], &arguments, &environment) == null);
    damaged[0] = 0; // No pty and stderr in the pty: not a combination render writes.
    try std.testing.expect(parse_start(damaged[0..payload.len], &arguments, &environment) == null);
    const bad_env = [_][]const u8{"TERM"};
    var no_equals = sample();
    no_equals.environment = &bad_env;
    const text = render_start(&out, &no_equals).?;
    try std.testing.expect(parse_start(text, &arguments, &environment) == null);
}

test "a start frame is refused at the bound and one past it" {
    // Goal: the size bound of the first frame. Method: arguments of the longest length, as many
    // as fit under forward_start_bytes_max and one more.
    var text: [constants.arg_bytes_max]u8 = @splat('a');
    var words: [16][]const u8 = undefined;
    for (&words) |*word| word.* = text[0..];
    var out: [constants.forward_start_bytes_max]u8 = undefined;
    const per_argument = 2 + constants.arg_bytes_max;
    const fixed = 9 + 2; // Header fields and the empty directory's length.
    const fits = (constants.forward_start_bytes_max - fixed) / per_argument;
    var start: Start = .{
        .pty = false,
        .stderr_pipe = true,
        .rows = 0,
        .columns = 0,
        .working_directory = "",
        .arguments = words[0..fits],
        .environment = &.{},
    };
    try std.testing.expect(render_start(&out, &start) != null);
    start.arguments = words[0 .. fits + 1];
    try std.testing.expect(render_start(&out, &start) == null);
}

test "exit and window payloads round-trip" {
    // Goal: the two small payloads. Method: every exit kind and a window size.
    var exit_bytes: [2]u8 = undefined;
    render_exit(&exit_bytes, .{ .signaled = true, .value = 9 });
    try std.testing.expectEqual(Exit{ .signaled = true, .value = 9 }, parse_exit(&exit_bytes).?);
    exit_bytes[0] = 2;
    try std.testing.expect(parse_exit(&exit_bytes) == null);
    var window: [4]u8 = undefined;
    render_window(&window, 50, 132);
    try std.testing.expectEqual(@as(u16, 132), std.mem.readInt(u16, window[2..4], .little));
}

test "a disk-full note round-trips and a free size above the disk is refused" {
    // Goal: the note's two numbers. Method: a typical note, then an impossible one.
    var bytes: [8]u8 = undefined;
    render_disk_full(&bytes, .{ .free_mib = 12, .total_mib = 65536 });
    try std.testing.expectEqual(DiskFull{ .free_mib = 12, .total_mib = 65536 }, parse_disk_full(&bytes).?);
    std.mem.writeInt(u32, bytes[0..4], 65537, .little);
    try std.testing.expect(parse_disk_full(&bytes) == null);
    var header: [constants.forward_header_bytes]u8 = undefined;
    render_header(&header, .disk_full, 8);
    try std.testing.expectEqual(Kind.disk_full, parse_header(&header).?.kind);
    std.mem.writeInt(u32, header[1..5], 7, .little);
    try std.testing.expect(parse_header(&header) == null);
}

test "environment names: the guest's own are never taken from the Mac" {
    // Goal: the allow rule. Method: names that must pass and names that must not.
    try std.testing.expect(environment_name_allowed("TERM"));
    try std.testing.expect(environment_name_allowed("HTTPS_PROXY"));
    try std.testing.expect(!environment_name_allowed("PATH"));
    try std.testing.expect(!environment_name_allowed("LD_PRELOAD"));
    try std.testing.expect(!environment_name_allowed("XDG_DATA_HOME"));
    try std.testing.expect(!environment_name_allowed("ZBX_CGROUP_ROOT"));
    try std.testing.expect(!environment_name_allowed("A B"));
    try std.testing.expect(!environment_name_allowed(""));
}
