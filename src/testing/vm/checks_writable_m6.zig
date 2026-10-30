//! The assertions of M6b slice 1's writable mounts and `--user` as pure functions over the text
//! the guest printed, each unit-tested with right and wrong input. The commands that print it
//! are in writable_m6.zig, a part of demo-m6 until slice 4 moves it to demo-m6b.

const std = @import("std");
const checks = @import("checks.zig");

const Streams = checks.Streams;

pub const Error = error{
    ExitCodeWrong,
    /// A page is not the one asked for (the first version, or the edit).
    PageWrong,
    /// A file written inside is not the host user's, or one belongs to another id.
    OwnerWrong,
    /// A refusal lacks its code, the project directory, or the fixes.
    RefusalWrong,
    /// Something was made that must not be, or the run did not do what the flag asked.
    RunWrong,
    /// The JSON lacks the writable mounts or the user.
    JsonWrong,
};

fn contains(text: []const u8, part: []const u8) bool {
    return std.mem.indexOf(u8, text, part) != null;
}

fn has_line(text: []const u8, wanted: []const u8) bool {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.eql(u8, std.mem.trim(u8, line, " \r\t"), wanted)) return true;
    }
    return false;
}

/// `curl` of the page served from the mounted directory: it is `wanted` and not `other`.
pub fn check_page(output: []const u8, wanted: []const u8, other: []const u8) Error!void {
    if (!has_line(output, wanted)) return error.PageWrong;
    if (contains(output, other)) return error.PageWrong;
}

/// A run that wrote through a mount and printed `id -u` (`inside`), and on the host `stat -c %u`
/// of the file, `id -u` of the user, and a count of the files of the site not owned by that user
/// (`host`, three lines). The container ran as root, the file is the user's, and no file of the
/// site is another id's.
pub fn check_owner(inside: []const u8, host: []const u8) Error!void {
    if (!has_line(inside, "0")) return error.RunWrong;
    var lines = std.mem.tokenizeScalar(u8, host, '\n');
    const owner = std.mem.trim(u8, lines.next() orelse return error.OwnerWrong, " \r\t");
    const user = std.mem.trim(u8, lines.next() orelse return error.OwnerWrong, " \r\t");
    const others = std.mem.trim(u8, lines.next() orelse return error.OwnerWrong, " \r\t");
    if (lines.next() != null) return error.OwnerWrong;
    if (owner.len == 0 or !std.mem.eql(u8, owner, user)) return error.OwnerWrong;
    if (std.mem.eql(u8, user, "0")) return error.OwnerWrong; // The test user is not root.
    if (!std.mem.eql(u8, others, "0")) return error.OwnerWrong;
}

/// A refusal: exit 125, the code on the first line of stderr, and each text of `parts` in it.
pub fn check_refusal(
    streams: Streams,
    status: u8,
    code: []const u8,
    parts: []const []const u8,
) Error!void {
    if (status != 125) return error.ExitCodeWrong;
    var header: [32]u8 = undefined;
    const wanted = std.fmt.bufPrint(&header, "error[ZBX-{s}]", .{code}) catch
        return error.RefusalWrong;
    if (!std.mem.startsWith(u8, streams.stderr, wanted)) return error.RefusalWrong;
    for (parts) |part| {
        if (!contains(streams.stderr, part)) return error.RefusalWrong;
    }
    if (contains(streams.stderr, "errno")) return error.RefusalWrong;
}

/// Nothing is made by a refusal: `ls` of the directory the mount pointed at prints nothing.
pub fn check_nothing_made(output: []const u8) Error!void {
    if (std.mem.trim(u8, output, " \r\t\n").len != 0) return error.RunWrong;
}

/// The image's user with `--user 0`: it ran as root and wrote through the mount.
pub fn check_root_run(output: []const u8, status: u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!has_line(output, "0")) return error.RunWrong;
}

/// `run --output json`'s `container_exit` line (stderr) and `ps --output json` (stdout) list the
/// mount by its host path and target and the user.
pub fn check_json(text: []const u8, host: []const u8, target: []const u8) Error!void {
    var wanted: [512]u8 = undefined;
    const member = std.fmt.bufPrint(
        &wanted,
        "\"writable_mounts\":[{{\"host\":\"{s}\",\"target\":\"{s}\"}}]," ++
            "\"user\":{{\"uid\":0,\"gid\":0}}",
        .{ host, target },
    ) catch return error.JsonWrong;
    if (!contains(text, member)) return error.JsonWrong;
}

const testing = std.testing;

test "the page: the wanted one, and not the other" {
    try check_page("<h1>\nsecond-OMEGA\n", "second-OMEGA", "first-OMEGA");
    try testing.expectError(
        error.PageWrong,
        check_page("first-OMEGA\n", "second-OMEGA", "first-OMEGA"),
    );
    try testing.expectError(
        error.PageWrong,
        check_page("second-OMEGA\nfirst-OMEGA\n", "second-OMEGA", "first-OMEGA"),
    );
    try testing.expectError(error.PageWrong, check_page("", "second-OMEGA", "first-OMEGA"));
}

test "the owner: the user's own id for the file, and for every file of the site" {
    try check_owner("0\n", "1000\n1000\n0\n");
    try testing.expectError(error.RunWrong, check_owner("1000\n", "1000\n1000\n0\n"));
    try testing.expectError(error.RunWrong, check_owner("", "1000\n1000\n0\n"));
    try testing.expectError(error.OwnerWrong, check_owner("0\n", "100999\n1000\n0\n"));
    try testing.expectError(error.OwnerWrong, check_owner("0\n", "1000\n1000\n1\n"));
    try testing.expectError(error.OwnerWrong, check_owner("0\n", "0\n0\n0\n"));
    try testing.expectError(error.OwnerWrong, check_owner("0\n", "1000\n1000\n"));
    try testing.expectError(error.OwnerWrong, check_owner("0\n", "1000\n1000\n0\n7\n"));
    try testing.expectError(error.OwnerWrong, check_owner("0\n", ""));
}

test "a refusal: 125, its code first, its parts, and no errno" {
    const text = "error[ZBX-E0212]: a --mount source is outside the project\n" ++
        "  cause  --mount ../x is /home/demo/x, outside the project /home/demo/net-project\n";
    const streams: Streams = .{ .stdout = "", .stderr = text };
    const parts = [_][]const u8{ "/home/demo/net-project", "outside the project" };
    try check_refusal(streams, 125, "E0212", &parts);
    try testing.expectError(error.ExitCodeWrong, check_refusal(streams, 1, "E0212", &parts));
    try testing.expectError(error.RefusalWrong, check_refusal(streams, 125, "E0213", &parts));
    const other = [_][]const u8{"/home/demo/elsewhere"};
    try testing.expectError(error.RefusalWrong, check_refusal(streams, 125, "E0212", &other));
    const dump: Streams = .{ .stdout = "", .stderr = "error[ZBX-E0212]: x\n  errno 13\n" };
    try testing.expectError(error.RefusalWrong, check_refusal(dump, 125, "E0212", &.{}));
    const late: Streams = .{ .stdout = "", .stderr = "x\nerror[ZBX-E0212]: x\n" };
    try testing.expectError(error.RefusalWrong, check_refusal(late, 125, "E0212", &.{}));
}

test "nothing made, and a root run" {
    try check_nothing_made("");
    try check_nothing_made("\n");
    try testing.expectError(error.RunWrong, check_nothing_made("x\n"));
    try check_root_run("0\n", 0);
    try testing.expectError(error.RunWrong, check_root_run("1000\n", 0));
    try testing.expectError(error.ExitCodeWrong, check_root_run("0\n", 1));
}

test "the JSON lists the mount by host path and target, and the user" {
    const line = "{\"container_exit\":{\"reason\":\"exited\",\"code\":0,\"network\":\"none\"," ++
        "\"published\":[],\"writable_mounts\":[{\"host\":\"/home/demo/p/site\"," ++
        "\"target\":\"/srv\"}]," ++
        "\"user\":{\"uid\":0,\"gid\":0}},\"ran\":{\"kind\":\"image\"}}\n";
    try check_json(line, "/home/demo/p/site", "/srv");
    try testing.expectError(error.JsonWrong, check_json(line, "/home/demo/p/other", "/srv"));
    try testing.expectError(error.JsonWrong, check_json(line, "/home/demo/p/site", "/x"));
    const bare = "{\"container_exit\":{\"reason\":\"exited\",\"code\":0}}\n";
    try testing.expectError(error.JsonWrong, check_json(bare, "/home/demo/p/site", "/srv"));
}
