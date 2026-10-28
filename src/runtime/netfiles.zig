//! The two files zbx generates for a container's `/etc` (docs/briefs/M5-network.md, "Inside the
//! container"): `hosts` and `resolv.conf`. Pure: the plan holds their text, the child writes it
//! and binds it, read-only, over the image's own files, which are never touched. They are not
//! part of an image, so a commit never sees them.
//!
//! `hosts` names `localhost` for 127.0.0.1 and ::1, and the container's own hostname. `resolv.conf`
//! has no nameserver for a container with no network (a lookup then fails at once, as it should)
//! and the host's file for one that shares the host's network, where the host's resolver is
//! reachable as it is, including the stub resolver of a systemd-resolved host at 127.0.0.53.
//! A `--net user` container names the address pasta forwards DNS on (`pasta_dns_forward`):
//! pasta asks the host's own resolver from the host's side, stub included.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const spec = @import("spec.zig");

/// The two files, in the order the plan handles them.
pub const File = enum(u8) {
    hosts,
    resolv_conf,

    /// The name in `/etc`.
    pub fn etc_name(file: File) []const u8 {
        const name: []const u8 = switch (file) {
            .hosts => "hosts",
            .resolv_conf => "resolv.conf",
        };
        assert(name.len > 0);
        assert(std.mem.indexOfScalar(u8, name, '/') == null);
        return name;
    }

    /// The hidden name in the container's `/dev` the text is written to first.
    pub fn stage_name(file: File) []const u8 {
        const name = switch (file) {
            .hosts => constants.etc_stage_hosts,
            .resolv_conf => constants.etc_stage_resolv,
        };
        assert(name[0] == '.'); // Hidden, so a listing of /dev does not show it for long.
        assert(name.len < 32);
        return name;
    }
};

pub const Buffer = [constants.etc_file_bytes_max]u8;

const no_network_note = "# zbx: this container has no network (--net none).\n";
const user_file = "# zbx: DNS goes through pasta to the host's resolver (--net user).\n" ++
    "nameserver " ++ constants.pasta_dns_forward ++ "\n";
const empty_host_note = "# zbx: the host's /etc/resolv.conf was empty or could not be read.\n";

/// `/etc/hosts` of a container called `name` (a valid container name, so a short label).
pub fn hosts(buffer: *Buffer, name: []const u8) []const u8 {
    assert(name.len > 0);
    assert(name.len <= constants.container_name_bytes_max);
    // Cannot fail: the fixed text is under 100 bytes and the name at most 63, twice.
    const text = std.fmt.bufPrint(
        buffer,
        "127.0.0.1\tlocalhost {s}\n::1\tlocalhost ip6-localhost ip6-loopback {s}\n",
        .{ name, name },
    ) catch unreachable; // Same bound as above.
    assert(std.mem.indexOf(u8, text, "127.0.0.1\tlocalhost") == 0);
    assert(std.mem.endsWith(u8, text, "\n"));
    return text;
}

/// `/etc/resolv.conf` for the network mode. `host_file` is the host's file, used for `host`
/// only; the caller has cut it to whole lines within `etc_file_bytes_max`.
pub fn resolv_conf(network: spec.Network, host_file: []const u8) []const u8 {
    assert(host_file.len <= constants.etc_file_bytes_max);
    if (network == .none) assert(no_network_note.len < constants.etc_file_bytes_max);
    switch (network) {
        .none => return no_network_note,
        .host => {
            if (host_file.len == 0) return empty_host_note;
            assert(host_file[host_file.len - 1] == '\n');
            return host_file;
        },
        .user => {
            assert(host_file.len == 0); // The host's file is read for `host` only.
            return user_file;
        },
    }
}

/// The host's `resolv.conf` as the container gets it: what fits `etc_file_bytes_max`, cut after
/// its last whole line, and ended with a newline if the file did not end with one. The bytes
/// are copied into `buffer`.
pub fn whole_lines(buffer: *Buffer, content: []const u8) []const u8 {
    const fit: usize = @min(content.len, buffer.len - 1); // One byte of room for a newline.
    var length = fit;
    if (fit < content.len) {
        // Cut: back to the end of the last whole line.
        length = if (std.mem.lastIndexOfScalar(u8, content[0..fit], '\n')) |at| at + 1 else 0;
    }
    @memcpy(buffer[0..length], content[0..length]);
    if (length > 0) {
        if (buffer[length - 1] != '\n') {
            buffer[length] = '\n';
            length += 1;
        }
    }
    assert(length <= buffer.len);
    if (length > 0) assert(buffer[length - 1] == '\n');
    return buffer[0..length];
}

const testing = std.testing;

test "hosts names localhost for both loopback addresses, and the container" {
    // Goal: the file the brief describes. Method: render it for a name and compare whole.
    var buffer: Buffer = undefined;
    const text = hosts(&buffer, "web-1");
    try testing.expectEqualStrings(
        "127.0.0.1\tlocalhost web-1\n" ++
            "::1\tlocalhost ip6-localhost ip6-loopback web-1\n",
        text,
    );
}

test "hosts of the longest name fits the buffer with room to spare" {
    // Goal: the bound. Method: a 63-character name.
    var buffer: Buffer = undefined;
    var name: [constants.container_name_bytes_max]u8 = undefined;
    @memset(&name, 'a');
    const text = hosts(&buffer, &name);
    try testing.expect(text.len < 256);
    try testing.expect(std.mem.indexOf(u8, text, &name) != null);
}

test "resolv.conf: no nameserver without a network, the host's file with the host's" {
    // Goal: the two modes of the brief. Method: no line of `none` starts with "nameserver"; the
    // host's text comes through unchanged; an empty host file gets a note, not an empty file.
    const none = resolv_conf(.none, "");
    try testing.expect(std.mem.indexOf(u8, none, "nameserver") == null);
    try testing.expect(none[0] == '#');
    const stub = "nameserver 127.0.0.53\noptions edns0 trust-ad\n";
    try testing.expectEqualStrings(stub, resolv_conf(.host, stub));
    const user = resolv_conf(.user, "");
    try testing.expect(std.mem.endsWith(u8, user, "\nnameserver 169.254.1.1\n"));
    try testing.expect(std.mem.indexOf(u8, user, "127.0.0.53") == null);
    const empty = resolv_conf(.host, "");
    try testing.expect(empty[0] == '#');
    try testing.expect(std.mem.indexOf(u8, empty, "nameserver") == null);
}

test "whole_lines cuts at a line, ends with a newline, and keeps a small file" {
    // Goal: the host's file is never cut in the middle of a line. Method: a file that fits, one
    // without a final newline, and one longer than the bound.
    var buffer: Buffer = undefined;
    const line = "nameserver 1.1.1.1\n";
    try testing.expectEqualStrings(line, whole_lines(&buffer, line));
    try testing.expectEqualStrings(line, whole_lines(&buffer, line[0 .. line.len - 1]));
    try testing.expectEqualStrings("", whole_lines(&buffer, ""));
    var big: [constants.etc_file_bytes_max + 100]u8 = undefined;
    const comment = "# a comment line of some length\n";
    var at: usize = 0;
    while (at + comment.len <= big.len) : (at += comment.len) {
        @memcpy(big[at..][0..comment.len], comment);
    }
    @memset(big[at..], 'x'); // A last line that is cut by the end of the file, not by a newline.
    const cut = whole_lines(&buffer, &big);
    try testing.expect(cut.len < constants.etc_file_bytes_max);
    try testing.expect(cut[cut.len - 1] == '\n');
    try testing.expect(std.mem.endsWith(u8, cut, comment));
    // One very long line with no newline at all is dropped whole rather than cut.
    @memset(&big, 'y');
    try testing.expectEqualStrings("", whole_lines(&buffer, &big));
}
