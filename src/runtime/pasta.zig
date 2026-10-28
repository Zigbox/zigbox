//! pasta, the user-mode network of `--net user` (docs/briefs/M5-network.md, "pasta's
//! lifecycle"; docs/demos/m5.md for each fact below, settled against the pasta Ubuntu 24.04
//! ships, 0.0~git20240220.1e6f92b, and its manual and source at that commit). Pure: the words
//! zbx starts it with, how its ready line and its version read, and what its last line says
//! went wrong. `session.zig` starts it and waits for it; `diagnose.zig` explains a failure.
//!
//! How zbx drives it:
//!   - `pasta [options] PID` joins the user and network namespaces of PID (`/proc/PID/ns/user`
//!     and `/proc/PID/ns/net`): the container's PID 1, which waits on its sync pipe meanwhile.
//!   - `--config-net` gives the namespace pasta's interface, the host's addresses and routes;
//!     `--foreground` keeps pasta zbx's own child (no fork to the background, no PID namespace
//!     of its own), so zbx can end it and reap it; `--quiet` keeps its informational lines out
//!     of the log.
//!   - Readiness: `--pid /proc/self/fd/1` makes pasta write its PID to its standard output, a
//!     pipe zbx reads, once its set-up is done: after the namespace's interface is configured
//!     (`tap_sock_init`, which runs `pasta_ns_conf`) and the forwarded ports are bound
//!     (`tcp_init`). A pasta that fails before that writes nothing there and exits non-zero,
//!     with its reason as the last line of its standard error, which goes to the run's log.
//!     The descriptor is one of the three standard ones because later pasta releases close
//!     every inherited descriptor above 2.
//!   - `--tcp-ports H:C` per forward (or `none`), and `none` for the rest: pasta's default,
//!     `auto`, would forward every port the container listens on, both ways.
//!   - `--no-map-gw`: the gateway address does not lead to the host's own loopback, so a
//!     container cannot reach services that listen only there.
//!   - `--dns-forward 169.254.1.1`: DNS sent there is answered by the host's first resolver,
//!     asked from the host's side; on Ubuntu that is systemd-resolved's stub at 127.0.0.53,
//!     which the container could not reach itself.
//!   - pasta exits by itself when the namespace goes away: for a namespace named by a PID it
//!     checks `/proc/PID/ns/net` once a second (since 2024_02_16). zbx also kills it and reaps
//!     it when the container ends, and the kernel kills it if zbx dies (`Host.start_program`).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const spec = @import("spec.zig");

/// The words of pasta's command line, built in place: the strings and the argv that points into
/// them. Valid until it is moved.
pub const Arguments = struct {
    strings: [constants.pasta_argv_bytes_max]u8,
    strings_len: u32,
    argv: [constants.pasta_argv_words_max + 1]?[*:0]const u8,
    count: u32,

    fn add(arguments: *Arguments, text: []const u8) void {
        assert(text.len > 0);
        assert(arguments.count < constants.pasta_argv_words_max);
        assert(arguments.strings_len + text.len + 1 <= arguments.strings.len);
        const start = arguments.strings_len;
        @memcpy(arguments.strings[start..][0..text.len], text);
        arguments.strings[start + text.len] = 0;
        arguments.strings_len += @intCast(text.len + 1);
        arguments.argv[arguments.count] = @ptrCast(&arguments.strings[start]);
        arguments.count += 1;
    }

    pub fn argv_z(arguments: *const Arguments) [*:null]const ?[*:0]const u8 {
        assert(arguments.count > 1);
        assert(arguments.argv[arguments.count] == null);
        return @ptrCast(&arguments.argv);
    }

    /// The words joined by spaces, for a test or a diagnostic.
    pub fn word(arguments: *const Arguments, index: u32) []const u8 {
        assert(index < arguments.count);
        return std.mem.span(arguments.argv[index].?);
    }
};

/// The options every run gives, in order, before the forwards and the PID.
const fixed_words = [_][]const u8{
    "pasta",       "--config-net",    "--quiet",                   "--foreground",
    "--pid",       "/proc/self/fd/1", "--udp-ports",               "none",
    "--tcp-ns",    "none",            "--udp-ns",                  "none",
    "--no-map-gw", "--dns-forward",   constants.pasta_dns_forward,
};

comptime {
    assert(fixed_words.len + 2 * constants.publish_count_max + 1 <= constants.pasta_argv_words_max);
}

/// Builds pasta's command line for the container whose PID 1 is `pid`, with `publish`'s
/// forwards, into `out`.
pub fn build(out: *Arguments, publish: []const spec.Publish, pid: u32) void {
    assert(pid > 1);
    assert(spec.publish_problem(.user, publish) == null);
    out.strings_len = 0;
    out.count = 0;
    for (fixed_words) |fixed| out.add(fixed);
    if (publish.len == 0) {
        out.add("--tcp-ports");
        out.add("none");
    }
    for (publish) |forward| {
        var buffer: [spec.publish_text_bytes_max]u8 = undefined;
        out.add("--tcp-ports");
        out.add(forward.text(&buffer));
    }
    var pid_buffer: [12]u8 = undefined;
    // Cannot fail: a u32 has at most ten digits.
    out.add(std.fmt.bufPrint(&pid_buffer, "{d}", .{pid}) catch unreachable);
    out.argv[out.count] = null;
    assert(out.count == fixed_words.len + 2 * @max(publish.len, 1) + 1);
}

/// What the ready pipe held: the PID pasta wrote, once it was ready, or something else.
pub const Ready = union(enum) {
    /// A whole line of decimal digits: the PID.
    pid: u32,
    /// Not a line yet: more may come.
    partial,
    /// A line that is not a PID, or more bytes than one: not pasta's ready line.
    garbled,
};

pub fn read_ready(bytes: []const u8) Ready {
    assert(bytes.len <= constants.pasta_ready_line_bytes_max);
    const end = std.mem.indexOfScalar(u8, bytes, '\n') orelse {
        return if (bytes.len == constants.pasta_ready_line_bytes_max) .garbled else .partial;
    };
    if (end + 1 != bytes.len) return .garbled; // Nothing follows the PID.
    const digits = bytes[0..end];
    if (digits.len == 0 or digits.len > 10) return .garbled;
    for (digits) |byte| {
        if (byte < '0' or byte > '9') return .garbled;
    }
    const value = std.fmt.parseInt(u64, digits, 10) catch unreachable; // Ten digits at most.
    if (value < 2 or value > std.math.maxInt(i32)) return .garbled;
    return .{ .pid = @intCast(value) };
}

/// The release date in pasta's `--version` line, as YYYYMMDD: upstream builds print
/// "pasta 2024_02_20.1e6f92b", Debian's and Ubuntu's may print their package version
/// ("0.0~git20240220.1e6f92b-1"), and a build from a tree without git prints "unknown version".
/// Null when the line names no date: zbx cannot tell then, and does not refuse.
pub fn version_date(line: []const u8) ?u32 {
    assert(line.len <= constants.pasta_version_bytes_max);
    var at: usize = 0;
    while (at + 8 <= line.len) : (at += 1) {
        if (line[at] != '2' or line[at + 1] != '0') continue;
        // "YYYY_MM_DD", as upstream's tags are written.
        if (at + 10 <= line.len) {
            const text = line[at..][0..10];
            if (text[4] == '_' and text[7] == '_') {
                if (date_of(text[0..4], text[5..7], text[8..10])) |date| return date;
            }
        }
        // "gitYYYYMMDD", as a Debian snapshot is written.
        if (at >= 3 and std.mem.eql(u8, line[at - 3 .. at], "git")) {
            const text = line[at..][0..8];
            if (date_of(text[0..4], text[4..6], text[6..8])) |date| return date;
        }
    }
    return null;
}

fn date_of(year: []const u8, month: []const u8, day: []const u8) ?u32 {
    assert(year.len == 4);
    assert(month.len == 2);
    const y = std.fmt.parseInt(u32, year, 10) catch return null;
    const m = std.fmt.parseInt(u32, month, 10) catch return null;
    const d = std.fmt.parseInt(u32, day, 10) catch return null;
    if (m < 1 or m > 12 or d < 1 or d > 31) return null;
    return y * 10000 + m * 100 + d;
}

/// What pasta's last line says went wrong, for the right code.
pub const Failure = union(enum) {
    /// A host port another program holds (E0604).
    in_use: ?u16,
    /// A host port the host refuses an unprivileged bind of (E0605).
    refused: ?u16,
    /// Anything else (E0603).
    other,
};

/// Reads the reason from pasta's line: a failed bind names its port and `strerror`'s text
/// ("Failed to bind port 8080 (Address already in use) for option '-t 8080:80', exiting" in
/// 2024; "Listen failed for HOST tcp port */8080: Address already in use" in later releases).
/// The port is the one of `publish` that the line names, if it names one.
pub fn classify(line: []const u8, publish: []const spec.Publish) Failure {
    assert(publish.len <= constants.publish_count_max);
    const in_use = std.mem.indexOf(u8, line, "Address already in use") != null;
    const denied = std.mem.indexOf(u8, line, "Permission denied") != null;
    const about_bind = std.mem.indexOf(u8, line, "bind") != null or
        std.mem.indexOf(u8, line, "isten") != null;
    if (!about_bind) return .other;
    if (in_use) return .{ .in_use = port_named(line, publish) };
    if (denied) return .{ .refused = port_named(line, publish) };
    return .other;
}

/// The host port of `publish` that `line` names: the number after the word "port" (as in
/// "bind port 8080" and "tcp port */8080"), if it is one of them.
fn port_named(line: []const u8, publish: []const spec.Publish) ?u16 {
    const at = std.mem.indexOf(u8, line, "port ") orelse return null;
    var start = at + "port ".len;
    // Skip what comes before the number: an address, a wildcard and a slash.
    var skipped: u32 = 0;
    while (start < line.len and !std.ascii.isDigit(line[start])) : (start += 1) {
        skipped += 1;
        if (skipped > constants.pasta_port_prefix_bytes_max) return null;
    }
    var end = start;
    while (end < line.len and std.ascii.isDigit(line[end])) end += 1;
    if (end == start or end - start > 5) return null;
    const number = std.fmt.parseInt(u32, line[start..end], 10) catch unreachable; // Digits.
    for (publish) |forward| {
        if (forward.host == number) return forward.host;
    }
    return null;
}

/// The last line of `text` that is not empty, without its newline; empty if there is none.
pub fn last_line(text: []const u8) []const u8 {
    const trimmed = std.mem.trimEnd(u8, text, " \r\n\t");
    const start = if (std.mem.lastIndexOfScalar(u8, trimmed, '\n')) |at| at + 1 else 0;
    const result = std.mem.trim(u8, trimmed[start..], " \r\t");
    assert(std.mem.indexOfScalar(u8, result, '\n') == null);
    return result;
}

const testing = std.testing;

test "build: the fixed options, a forward per --publish, and the PID last" {
    // Goal: the command line docs/demos/m5.md settles. Method: build with two forwards and with
    // none, and compare word by word.
    var arguments: Arguments = undefined;
    const two = [_]spec.Publish{
        .{ .host = 8080, .container = 80 },
        .{ .host = 8443, .container = 443 },
    };
    build(&arguments, &two, 4242);
    const expected = fixed_words ++ [_][]const u8{
        "--tcp-ports", "8080:80", "--tcp-ports", "8443:443", "4242",
    };
    try testing.expectEqual(@as(u32, expected.len), arguments.count);
    for (expected, 0..) |want, index| {
        try testing.expectEqualStrings(want, arguments.word(@intCast(index)));
    }
    try testing.expect(arguments.argv[arguments.count] == null);
    build(&arguments, &.{}, 77);
    try testing.expectEqualStrings("--tcp-ports", arguments.word(arguments.count - 3));
    try testing.expectEqualStrings("none", arguments.word(arguments.count - 2));
    try testing.expectEqualStrings("77", arguments.word(arguments.count - 1));
}

test "build: sixteen forwards of the longest text fit" {
    // Goal: the bounds of `Arguments`. Method: the most forwards, each "6xxxx:65535".
    var list: [constants.publish_count_max]spec.Publish = undefined;
    for (&list, 0..) |*forward, index| {
        forward.* = .{ .host = @intCast(65535 - index), .container = 65535 };
    }
    var arguments: Arguments = undefined;
    build(&arguments, &list, std.math.maxInt(i32));
    try testing.expectEqualStrings("2147483647", arguments.word(arguments.count - 1));
    try testing.expectEqualStrings("65520:65535", arguments.word(arguments.count - 2));
}

test "read_ready: a PID line, a partial one, and what is not one" {
    // Goal: only a whole line of digits is ready. Method: the cases at each edge.
    try testing.expectEqual(@as(u32, 4242), read_ready("4242\n").pid);
    try testing.expect(read_ready("") == .partial);
    try testing.expect(read_ready("42") == .partial);
    try testing.expect(read_ready("\n") == .garbled);
    try testing.expect(read_ready("42x\n") == .garbled);
    try testing.expect(read_ready("42\nmore") == .garbled);
    try testing.expect(read_ready("1\n") == .garbled); // No process of ours is PID 1.
    try testing.expect(read_ready("2147483648\n") == .garbled);
    try testing.expect(read_ready("2147483647\n").pid == std.math.maxInt(i32));
    try testing.expect(read_ready("0123456789abcdef") == .garbled); // Full, and no newline.
}

test "version_date: upstream's tags, Debian's snapshots, and none" {
    // Goal: the dates the minimum is compared with. Method: real version lines (docs/demos/m5.md
    // for the one Ubuntu prints), and lines with no date or a malformed one.
    try testing.expectEqual(@as(?u32, 20240220), version_date("pasta 2024_02_20.1e6f92b"));
    try testing.expectEqual(@as(?u32, 20240216), version_date("pasta 2024_02_16.08344da"));
    try testing.expectEqual(@as(?u32, 20240220), version_date("pasta 0.0~git20240220.1e6f92b-1"));
    try testing.expectEqual(@as(?u32, 20231230), version_date("pasta 0.0~git20231230.f091893-1"));
    try testing.expectEqual(@as(?u32, null), version_date("pasta unknown version"));
    try testing.expectEqual(@as(?u32, null), version_date("pasta 2024_13_40.0000000"));
    try testing.expectEqual(@as(?u32, null), version_date(""));
    const minimum = constants.pasta_version_min_date;
    try testing.expect(version_date("pasta 2024_02_16.08344da").? >= minimum);
    try testing.expect(version_date("pasta 2024_02_14.aaaaaaa").? < minimum);
}

test "classify: a port in use, a port refused, and anything else" {
    // Goal: the code for pasta's last line. Method: the 2024 wording, the later wording, and
    // lines that are not about a bind; with one forward and with two.
    const one = [_]spec.Publish{.{ .host = 8080, .container = 80 }};
    const two = [_]spec.Publish{
        .{ .host = 8080, .container = 80 },
        .{ .host = 80, .container = 80 },
    };
    const in_use = "Failed to bind port 8080 (Address already in use) for option " ++
        "'-t 8080:80', exiting";
    try testing.expectEqual(@as(?u16, 8080), classify(in_use, &one).in_use);
    try testing.expectEqual(@as(?u16, 8080), classify(in_use, &two).in_use);
    const refused = "Failed to bind port 80 (Permission denied) for option '-t 80:80', exiting";
    try testing.expectEqual(@as(?u16, 80), classify(refused, &two).refused);
    const later = "WARNING: Listen failed for HOST tcp port */8080: Address already in use";
    try testing.expectEqual(@as(?u16, 8080), classify(later, &one).in_use);
    try testing.expect(classify("Couldn't open network namespace /proc/9/ns/net", &one) == .other);
    try testing.expect(classify("Permission denied", &one) == .other); // Not about a bind.
    const other = "Failed to bind port 9090 (Address already in use) for option '-t 9090:80'";
    try testing.expectEqual(@as(?u16, null), classify(other, &two).in_use);
}

test "last_line: the last line with something on it" {
    // Goal: the cause of E0603 is pasta's own last words. Method: trailing newlines, blanks.
    try testing.expectEqualStrings("b", last_line("a\nb\n\n"));
    try testing.expectEqualStrings("only", last_line("only"));
    try testing.expectEqualStrings("", last_line("\n\n"));
    try testing.expectEqualStrings("x y", last_line("first\n  x y \r\n"));
}
