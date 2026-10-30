//! The assertions of demo-m6b's SPEC part (the five steps of the dev loop, spec_m6b.zig) as pure
//! functions over the text the guest printed, each unit-tested with right and wrong input. What
//! the five steps share with the acceptance checks (the page, the refusal, the owner by `stat`)
//! is checks_writable_m6b.zig's; this file adds what only the steps need: the owner as `ls -l`
//! prints it, and the log of exactly the requests the steps made.

const std = @import("std");

pub const Error = error{
    ExitCodeWrong,
    /// `ls -l` of the file written inside does not show the host user as its owner.
    OwnerWrong,
    /// The container's log does not show the requests the steps made, and only those.
    RequestsWrong,
    /// The edit did not reach the file the container reads, or the file holds other text.
    ContentWrong,
};

fn contains(text: []const u8, part: []const u8) bool {
    return std.mem.indexOf(u8, text, part) != null;
}

/// Step 3: `ls -l site/new.txt; cat site/new.txt` exits 0. The first line is the long listing of
/// a regular file whose owner (the third word) is `user` and whose last word is `path`, and the
/// file holds `content`. The owner is read by name: a subordinate id has no name in the host's
/// passwd file, so `ls` would print a number.
pub fn check_owner_listing(
    output: []const u8,
    status: u8,
    user: []const u8,
    path: []const u8,
    content: []const u8,
) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    std.debug.assert(user.len > 0);
    var lines = std.mem.splitScalar(u8, output, '\n');
    const listing = lines.next() orelse return error.OwnerWrong;
    var words = std.mem.tokenizeAny(u8, listing, " \r\t");
    const mode = words.next() orelse return error.OwnerWrong;
    if (mode.len < 10 or mode[0] != '-') return error.OwnerWrong;
    _ = words.next() orelse return error.OwnerWrong; // The link count.
    const owner = words.next() orelse return error.OwnerWrong;
    if (!std.mem.eql(u8, owner, user)) return error.OwnerWrong;
    var last: []const u8 = "";
    while (words.next()) |word| last = word;
    if (!std.mem.eql(u8, last, path)) return error.OwnerWrong;
    const body = lines.next() orelse return error.ContentWrong;
    if (!std.mem.eql(u8, std.mem.trim(u8, body, " \r\t"), content)) return error.ContentWrong;
}

/// Step 4: `zbx logs` exits 0 and shows exactly two requests, both `GET <path>` answered 200: the
/// two `curl`s of step 2, before and after the edit. A request that is not these (a probe that
/// asked for another path, a third `curl`) fails, so the log is the record of the steps and no
/// more.
pub fn check_two_requests(log: []const u8, status: u8, path: []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    var wanted: [128]u8 = undefined;
    const request = std.fmt.bufPrint(&wanted, "\"GET {s} HTTP/1.1\" 200", .{path}) catch
        return error.RequestsWrong;
    var requests: u32 = 0;
    var lines = std.mem.splitScalar(u8, log, '\n');
    while (lines.next()) |line| {
        if (!contains(line, " HTTP/1.")) continue;
        if (!contains(line, request)) return error.RequestsWrong;
        requests += 1;
    }
    if (requests != 2) return error.RequestsWrong;
}

const testing = std.testing;

test "the owner is the host user, by name, and the file holds what was written" {
    // Goal: step 3's `ls -l` names the presenter. Wrong: another owner (a number, as for a
    // subordinate id), a directory, another file, other content, a failed command.
    const listing = "-rw-r--r-- 1 demo demo 12 Oct 30 10:00 site/new.txt\nmade-inside\n";
    try check_owner_listing(listing, 0, "demo", "site/new.txt", "made-inside");
    const subordinate = "-rw-r--r-- 1 100000 100000 12 Oct 30 10:00 site/new.txt\nmade-inside\n";
    const wrong = check_owner_listing(subordinate, 0, "demo", "site/new.txt", "made-inside");
    try testing.expectError(error.OwnerWrong, wrong);
    const root = "-rw-r--r-- 1 root root 12 Oct 30 10:00 site/new.txt\nmade-inside\n";
    const owned = check_owner_listing(root, 0, "demo", "site/new.txt", "made-inside");
    try testing.expectError(error.OwnerWrong, owned);
    const directory = "drwxr-xr-x 1 demo demo 12 Oct 30 10:00 site/new.txt\nmade-inside\n";
    const dir = check_owner_listing(directory, 0, "demo", "site/new.txt", "made-inside");
    try testing.expectError(error.OwnerWrong, dir);
    const other = check_owner_listing(listing, 0, "demo", "site/old.txt", "made-inside");
    try testing.expectError(error.OwnerWrong, other);
    const text = check_owner_listing(listing, 0, "demo", "site/new.txt", "something-else");
    try testing.expectError(error.ContentWrong, text);
    const cut = listing[0 .. listing.len - 12];
    const bare = check_owner_listing(cut, 0, "demo", "site/new.txt", "x");
    try testing.expectError(error.ContentWrong, bare);
    const failed = check_owner_listing(listing, 2, "demo", "site/new.txt", "made-inside");
    try testing.expectError(error.ExitCodeWrong, failed);
    try testing.expectError(error.OwnerWrong, check_owner_listing("", 0, "demo", "a", "b"));
    // A user name that is a prefix of the owner is another user.
    const prefix = check_owner_listing(listing, 0, "dem", "site/new.txt", "made-inside");
    try testing.expectError(error.OwnerWrong, prefix);
}

test "the log has the two requests of the steps, and nothing else" {
    // Goal: step 4 shows two requests. Wrong: one, three, a 404, another path, no exit 0.
    const one = "127.0.0.1 - - [30/Oct/2026 10:00:00] \"GET /index.html HTTP/1.1\" 200 -\n";
    const two = one ++ one;
    try check_two_requests(two, 0, "/index.html");
    try testing.expectError(error.RequestsWrong, check_two_requests(one, 0, "/index.html"));
    try testing.expectError(error.RequestsWrong, check_two_requests("", 0, "/index.html"));
    try testing.expectError(error.RequestsWrong, check_two_requests(two ++ one, 0, "/index.html"));
    const missing = "127.0.0.1 - - [30/Oct/2026 10:00:01] \"GET /index.html HTTP/1.1\" 404 -\n";
    const with_404 = check_two_requests(one ++ missing, 0, "/index.html");
    try testing.expectError(error.RequestsWrong, with_404);
    const other = "127.0.0.1 - - [30/Oct/2026 10:00:01] \"GET / HTTP/1.1\" 200 -\n";
    const with_root = check_two_requests(one ++ other, 0, "/index.html");
    try testing.expectError(error.RequestsWrong, with_root);
    try testing.expectError(error.ExitCodeWrong, check_two_requests(two, 1, "/index.html"));
    // Other lines (the server's banner) are not requests.
    const banner = "Serving HTTP on 0.0.0.0 port 8000 ...\n";
    try check_two_requests(banner ++ two, 0, "/index.html");
}
