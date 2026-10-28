//! The M3 demo's assertions as pure functions over the text the guest printed, each unit-tested
//! with right and wrong input. The commands that print the text are in main_m3.zig, and so are
//! the markers (`STORE-SAME`, `ROOT-MODE:`, ...).

const std = @import("std");
const checks = @import("checks.zig");

const Streams = checks.Streams;

pub const Error = error{
    ExitCodeWrong,
    /// A line the step must print is missing or wrong.
    LineMissing,
    DigestWrong,
    /// The store changed while a container ran.
    StoreChanged,
    StderrNotEmpty,
    ReportWrong,
};

fn has_line(text: []const u8, wanted: []const u8) bool {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        if (std.mem.eql(u8, std.mem.trim(u8, raw, " \r\t"), wanted)) return true;
    }
    return false;
}

fn contains(text: []const u8, part: []const u8) bool {
    return std.mem.indexOf(u8, text, part) != null;
}

/// `b3:` and 64 lowercase hex digits.
pub fn is_digest(text: []const u8) bool {
    if (text.len != 67) return false;
    if (!std.mem.startsWith(u8, text, "b3:")) return false;
    for (text[3..]) |byte| {
        const hex = (byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f');
        if (!hex) return false;
    }
    return true;
}

/// `zbx store import` prints the digest alone on stdout, and exits 0.
pub fn check_import(streams: Streams, status: u8) Error![]const u8 {
    if (status != 0) return error.ExitCodeWrong;
    const digest = std.mem.trim(u8, streams.stdout, " \r\n\t");
    if (!is_digest(digest)) return error.DigestWrong;
    return digest;
}

/// The step prints `scribbled` when the container's script ran to its end: it wrote, changed
/// modes and owners, and deleted across the tree.
pub fn check_scribbled(streams: Streams, status: u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!has_line(streams.stdout, "scribbled")) return error.LineMissing;
}

/// The guest compares the store's listing and sums before and after (`cmp`), and prints which.
pub fn check_store_same(output: []const u8) Error!void {
    if (has_line(output, "STORE-DIFFERS")) return error.StoreChanged;
    if (!has_line(output, "STORE-SAME")) return error.LineMissing;
}

/// The container's writes are in its own upper layer: the guest prints how many entries it
/// has, and it must have some.
pub fn check_upper_written(output: []const u8, at_least: u32) Error!void {
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        const marker = "UPPER-ENTRIES:";
        if (!std.mem.startsWith(u8, line, marker)) continue;
        const count = std.fmt.parseInt(u32, line[marker.len..], 10) catch return error.LineMissing;
        if (count < at_least) return error.LineMissing;
        return;
    }
    return error.LineMissing;
}

/// `--read-only` with a digest: the write is refused by the file system, the one to /tmp works.
pub fn check_read_only(
    refused: Streams,
    refused_status: u8,
    allowed: Streams,
    status: u8,
) Error!void {
    if (refused_status == 0 or refused_status == 125) return error.ExitCodeWrong;
    if (!contains(refused.stderr, "Read-only file system")) return error.LineMissing;
    if (status != 0) return error.ExitCodeWrong;
    if (!has_line(allowed.stdout, "tmp-ok")) return error.LineMissing;
}

/// `stat -c '%a %u %g' /` inside a run of a tree whose root was imported as 711.
pub fn check_root(output: []const u8, mode_owner_group: []const u8) Error!void {
    var expected: [64]u8 = undefined;
    // Cannot fail: a mode and two ids fit 64 bytes.
    const line = std.fmt.bufPrint(&expected, "ROOT:{s}", .{mode_owner_group}) catch unreachable;
    if (!has_line(output, line)) return error.LineMissing;
}

/// A digest the store lacks: ZBX-E0410 on stderr and 125, nothing on stdout.
pub fn check_unknown_digest(streams: Streams, status: u8) Error!void {
    if (status != 125) return error.ExitCodeWrong;
    if (!contains(streams.stderr, "error[ZBX-E0410]")) return error.ReportWrong;
    if (streams.stdout.len != 0) return error.ReportWrong;
}

/// The run record names the tree and the upper layer.
pub fn check_record(output: []const u8, digest: []const u8) Error!void {
    if (!contains(output, digest)) return error.LineMissing;
    if (!contains(output, "/upper")) return error.LineMissing;
}

/// `zbx store diff` printed exactly the lines the container's changes make, and nothing else.
pub fn check_diff(streams: Streams, status: u8, expected: []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (streams.stderr.len != 0) return error.StderrNotEmpty;
    if (!std.mem.eql(u8, streams.stdout, expected)) return error.ReportWrong;
}

/// The JSON diff counts what the text lists.
pub fn check_diff_summary(output: []const u8, added: u32, removed: u32, changed: u32) Error!void {
    var wanted: [96]u8 = undefined;
    // Cannot fail: three small numbers fit 96 bytes.
    const text = std.fmt.bufPrint(
        &wanted,
        "\"summary\":{{\"added\":{d},\"removed\":{d},\"changed\":{d}}}",
        .{ added, removed, changed },
    ) catch unreachable; // Same bound.
    if (!contains(output, text)) return error.ReportWrong;
    if (!contains(output, "\"schema\":\"zbx.store.diff/1\"")) return error.ReportWrong;
}

/// The number after `"stored_bytes":` in the JSON of `zbx store du <digest>`.
pub fn stored_bytes(output: []const u8) Error!u64 {
    const key = "\"stored_bytes\":";
    const at = std.mem.indexOf(u8, output, key) orelse return error.LineMissing;
    var end = at + key.len;
    while (end < output.len and output[end] >= '0' and output[end] <= '9') end += 1;
    return std.fmt.parseInt(u64, output[at + key.len .. end], 10) catch error.LineMissing;
}

/// The tree without the large file costs at least `drop` bytes less to store (the brief's
/// demo step 5: no whiteout baggage).
pub fn check_stored_drop(parent: []const u8, child: []const u8, drop: u64) Error!void {
    const before = try stored_bytes(parent);
    const after = try stored_bytes(child);
    if (after >= before) return error.StoreChanged;
    if (before - after < drop) return error.StoreChanged;
}

/// A commit of a container that is still running is ZBX-E0427 and exit 1, with nothing on stdout.
pub fn check_commit_running(streams: Streams, status: u8) Error!void {
    if (status != 1) return error.ExitCodeWrong;
    if (!contains(streams.stderr, "error[ZBX-E0427]")) return error.ReportWrong;
    if (streams.stdout.len != 0) return error.ReportWrong;
}

/// A commit of a container that ran on a directory is ZBX-E0426 and exit 1.
pub fn check_no_layer(streams: Streams, status: u8) Error!void {
    if (status != 1) return error.ExitCodeWrong;
    if (!contains(streams.stderr, "error[ZBX-E0426]")) return error.ReportWrong;
    if (streams.stdout.len != 0) return error.ReportWrong;
}

/// A commit that changed nothing prints the parent's digest.
pub fn check_unchanged(streams: Streams, status: u8, parent: []const u8) Error!void {
    const digest = try check_import(streams, status);
    if (!std.mem.eql(u8, digest, parent)) return error.DigestWrong;
}

/// A commit that changed something prints another digest.
pub fn check_changed(streams: Streams, status: u8, parent: []const u8) Error![]const u8 {
    const digest = try check_import(streams, status);
    if (std.mem.eql(u8, digest, parent)) return error.DigestWrong;
    return digest;
}

// ---- Slice 4: verify, gc, restore ------------------------------------------------------------

/// The text after `key` in `text` up to the next `"`, or null.
fn json_text(text: []const u8, key: []const u8) ?[]const u8 {
    var needle: [64]u8 = undefined;
    const quoted = std.fmt.bufPrint(&needle, "\"{s}\":\"", .{key}) catch return null;
    const at = std.mem.indexOf(u8, text, quoted) orelse return null;
    const rest = text[at + quoted.len ..];
    const end = std.mem.indexOfScalar(u8, rest, '"') orelse return null;
    return rest[0..end];
}

/// The number after `key` in `text`.
fn json_number(text: []const u8, key: []const u8) ?u64 {
    var needle: [64]u8 = undefined;
    const quoted = std.fmt.bufPrint(&needle, "\"{s}\":", .{key}) catch return null;
    const at = std.mem.indexOf(u8, text, quoted) orelse return null;
    const rest = text[at + quoted.len ..];
    var end: usize = 0;
    while (end < rest.len and rest[end] >= '0' and rest[end] <= '9') end += 1;
    if (end == 0) return null;
    return std.fmt.parseInt(u64, rest[0..end], 10) catch null;
}

/// The path `CORRUPTED:objects/ab/<62 hex>` the corrupting script printed, as the object's id
/// text (`b3:` and 64 digits) in `buffer`.
pub fn corrupted_id(output: []const u8, buffer: *[67]u8) Error![]const u8 {
    const marker = "CORRUPTED:objects/";
    const at = std.mem.indexOf(u8, output, marker) orelse return error.LineMissing;
    const rest = output[at + marker.len ..];
    if (rest.len < 2 + 1 + 62) return error.LineMissing;
    if (rest[2] != '/') return error.LineMissing;
    const text = std.fmt.bufPrint(buffer, "b3:{s}{s}", .{ rest[0..2], rest[3..65] }) catch {
        return error.LineMissing;
    };
    if (!is_digest(text)) return error.DigestWrong;
    return text;
}

/// `verify` of a whole store: exit 0, one line on stdout saying so, nothing on stderr.
pub fn check_verify_clean(streams: Streams, status: u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (streams.stderr.len != 0) return error.StderrNotEmpty;
    if (!contains(streams.stdout, ": no damage")) return error.LineMissing;
}

/// `verify` of a store with one object damaged by hand: exit 2, one E0429 naming the object,
/// the summary E0430, and the damage counted on stdout.
pub fn check_verify_damaged(streams: Streams, status: u8, id: []const u8) Error!void {
    if (status != 2) return error.ExitCodeWrong;
    if (std.mem.count(u8, streams.stderr, "error[ZBX-E0429]") != 1) return error.ReportWrong;
    if (std.mem.count(u8, streams.stderr, "error[ZBX-E0430]") != 1) return error.ReportWrong;
    if (!contains(streams.stderr, id)) return error.ReportWrong;
    if (!contains(streams.stderr, "/etc/passwd")) return error.ReportWrong;
    if (!contains(streams.stdout, "1 damaged")) return error.LineMissing;
}

/// The same in JSON: the damaged thing, its id, and the path `/etc/passwd` in at least `roots`
/// root trees (each a `"root"` and `"path"` pair).
pub fn check_verify_json(streams: Streams, status: u8, id: []const u8, roots: u32) Error!void {
    if (status != 2) return error.ExitCodeWrong;
    if (!contains(streams.stdout, "\"schema\":\"zbx.store.verify/1\"")) return error.ReportWrong;
    if (!contains(streams.stdout, "\"ok\":false")) return error.ReportWrong;
    if (json_number(streams.stdout, "damaged") != 1) return error.ReportWrong;
    if (!contains(streams.stdout, id)) return error.ReportWrong;
    if (!contains(streams.stdout, "\"kind\":\"content\"")) return error.ReportWrong;
    const reached = json_number(streams.stdout, "reached") orelse return error.ReportWrong;
    if (reached < roots) return error.ReportWrong;
    const paths = std.mem.count(u8, streams.stdout, "\"path\":\"/etc/passwd\"");
    if (paths < roots) return error.ReportWrong;
}

/// A gc plan in JSON: not applied, with at least `bytes` bytes, one chunk list at least and
/// `tmp` leftovers; returns the hash to confirm with.
pub fn check_plan(streams: Streams, status: u8, bytes: u64, tmp: u64) Error![]const u8 {
    if (status != 0) return error.ExitCodeWrong;
    if (streams.stderr.len != 0) return error.StderrNotEmpty;
    if (!contains(streams.stdout, "\"applied\":false")) return error.ReportWrong;
    if ((json_number(streams.stdout, "bytes") orelse 0) < bytes) return error.ReportWrong;
    if ((json_number(streams.stdout, "lists") orelse 0) == 0) return error.ReportWrong;
    if ((json_number(streams.stdout, "objects") orelse 0) == 0) return error.ReportWrong;
    if ((json_number(streams.stdout, "tmp") orelse 0) != tmp) return error.ReportWrong;
    const hash = json_text(streams.stdout, "plan") orelse return error.LineMissing;
    if (!is_digest(hash)) return error.DigestWrong;
    return hash;
}

/// A plan that leaves a big tree alone because a container that can still be committed holds
/// it: not applied, under `bytes_max` bytes, and no chunk list (the big file's).
pub fn check_plan_holds(streams: Streams, status: u8, bytes_max: u64) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (streams.stderr.len != 0) return error.StderrNotEmpty;
    if (!contains(streams.stdout, "\"applied\":false")) return error.ReportWrong;
    if ((json_number(streams.stdout, "bytes") orelse bytes_max) >= bytes_max) {
        return error.ReportWrong;
    }
    if ((json_number(streams.stdout, "lists") orelse 1) != 0) return error.ReportWrong;
}

/// A confirmation with a hash that is not the plan: E0431, exit 1, nothing on stdout, and the
/// plan as it is now (`fresh`, null to take any) in the message.
pub fn check_stale(streams: Streams, status: u8, fresh: ?[]const u8) Error!void {
    if (status != 1) return error.ExitCodeWrong;
    if (!contains(streams.stderr, "error[ZBX-E0431]")) return error.ReportWrong;
    if (streams.stdout.len != 0) return error.ReportWrong;
    if (fresh) |hash| {
        if (!contains(streams.stderr, hash)) return error.ReportWrong;
    }
}

/// The new plan hash a stale refusal gave, from its fix `zbx store gc --confirm <hash>`.
pub fn stale_hash(stderr: []const u8) Error![]const u8 {
    const marker = "zbx store gc --confirm ";
    const at = std.mem.indexOf(u8, stderr, marker) orelse return error.LineMissing;
    const rest = stderr[at + marker.len ..];
    if (rest.len < 67) return error.LineMissing;
    if (!is_digest(rest[0..67])) return error.DigestWrong;
    return rest[0..67];
}

/// A confirmed gc in JSON: applied, with the plan's hash, a gc id of 12 digits, and what was
/// moved (at least `bytes` bytes, `tmp` leftovers deleted); returns the gc id.
pub fn check_applied(
    streams: Streams,
    status: u8,
    plan: []const u8,
    bytes: u64,
    tmp: u64,
) Error![]const u8 {
    if (status != 0) return error.ExitCodeWrong;
    if (streams.stderr.len != 0) return error.StderrNotEmpty;
    if (!contains(streams.stdout, "\"applied\":true")) return error.ReportWrong;
    if (!std.mem.eql(
        u8,
        json_text(streams.stdout, "plan") orelse "",
        plan,
    )) return error.ReportWrong;
    if ((json_number(streams.stdout, "bytes") orelse 0) < bytes) return error.ReportWrong;
    if ((json_number(streams.stdout, "tmp") orelse 0) != tmp) return error.ReportWrong;
    const id = json_text(streams.stdout, "gc") orelse return error.LineMissing;
    if (id.len != 12) return error.DigestWrong;
    if (!std.mem.startsWith(u8, plan[3..], id)) return error.DigestWrong; // The id is the plan's.
    return id;
}

/// A command that waited for the store lock and gave up: E0436, exit 1, nothing on stdout, and
/// the words for what held it (`"writers"` for shared holders, or a gc's command line).
pub fn check_busy(streams: Streams, status: u8, holder_words: []const u8) Error!void {
    if (status != 1) return error.ExitCodeWrong;
    if (std.mem.count(u8, streams.stderr, "error[ZBX-E0436]") != 1) return error.ReportWrong;
    if (!contains(streams.stderr, holder_words)) return error.ReportWrong;
    if (streams.stdout.len != 0) return error.ReportWrong;
}

/// The store's total bytes in `zbx --output json store du`.
pub fn store_total_bytes(stdout: []const u8) Error!u64 {
    const at = std.mem.indexOf(u8, stdout, "\"store\":{") orelse return error.LineMissing;
    return json_number(stdout[at..], "bytes") orelse error.LineMissing;
}

/// The store shrank by at least `drop` bytes between two `du` outputs.
pub fn check_shrank(before: u64, after: u64, drop: u64) Error!void {
    if (after >= before) return error.StoreChanged;
    if (before - after < drop) return error.StoreChanged;
}

/// `gc --trash` lists the gc id as complete.
pub fn check_trash_listed(streams: Streams, status: u8, id: []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!contains(streams.stdout, id)) return error.LineMissing;
    if (!contains(streams.stdout, "complete")) return error.LineMissing;
}

/// A restore: exit 0 and the counts of what came back.
pub fn check_restored(streams: Streams, status: u8, id: []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (streams.stderr.len != 0) return error.StderrNotEmpty;
    if (!contains(streams.stdout, "restored")) return error.LineMissing;
    if (!contains(streams.stdout, id)) return error.LineMissing;
}

/// A restore of a trash that is not there: E0433, exit 1.
pub fn check_no_trash(streams: Streams, status: u8) Error!void {
    if (status != 1) return error.ExitCodeWrong;
    if (!contains(streams.stderr, "error[ZBX-E0433]")) return error.ReportWrong;
    if (streams.stdout.len != 0) return error.ReportWrong;
}

// ---- Slice 5: the spec's steps, the acceptance criteria, the upgrade ------------------------

/// Spec step 2: the store grew by about the new file, not by a second rootfs. `at_most` is the
/// file plus slack for the tree objects that changed; a second copy of the rootfs is far past it.
pub fn check_growth(before: u64, after: u64, at_least: u64, at_most: u64) Error!void {
    if (after < before) return error.StoreChanged;
    const grew = after - before;
    if (grew < at_least or grew > at_most) return error.StoreChanged;
}

/// Spec step 3: the diff after `apk add` lists additions, and changes only to the files apk
/// itself keeps (its database and the list of what was asked for). `must_add` is a path the
/// package puts there. A deletion is never expected, and a change to any other path is not.
pub fn check_apk_diff(streams: Streams, status: u8, must_add: []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (streams.stderr.len != 0) return error.StderrNotEmpty;
    const changeable = [_][]const u8{
        "/etc/apk/world",
        "/lib/apk/db/installed",
        "/lib/apk/db/triggers",
        "/lib/apk/db/scripts.tar",
    };
    var added: u32 = 0;
    var found = false;
    var lines = std.mem.splitScalar(u8, streams.stdout, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (line.len < 3 or line[1] != ' ') return error.ReportWrong;
        const rest = line[2..];
        switch (line[0]) {
            'A' => {
                added += 1;
                if (std.mem.eql(u8, rest, must_add)) found = true;
            },
            'M' => {
                const path = rest[0 .. std.mem.indexOf(u8, rest, "  ") orelse rest.len];
                var allowed = false;
                for (changeable) |name| {
                    if (std.mem.eql(u8, path, name)) allowed = true;
                }
                if (!allowed) return error.ReportWrong;
            },
            else => return error.ReportWrong,
        }
    }
    if (!found or added < 1) return error.ReportWrong;
}

/// The run of `apk add` on stdin printed apk's own lines and ended 0.
pub fn check_apk_run(streams: Streams, status: u8, package: []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    var wanted: [96]u8 = undefined;
    // Cannot fail: a package name fits 96 bytes.
    const text = std.fmt.bufPrint(&wanted, "Installing {s} (", .{package}) catch unreachable;
    if (!contains(streams.stdout, text)) return error.LineMissing;
}

/// Two imports of one tree (the second with other mtimes, in a copy made afterwards) give one
/// digest.
pub fn check_same_digest(first: []const u8, second: []const u8) Error!void {
    if (!is_digest(first) or !is_digest(second)) return error.DigestWrong;
    if (!std.mem.eql(u8, first, second)) return error.DigestWrong;
}

/// What a container sees of a tree that was imported: the lines `stat -c 'RT:%n %a %u:%g %F'`
/// and `readlink` print, for the modes, owners, kinds and links the tree was made with.
pub const round_trip_lines = [_][]const u8{
    "RT:/rt/suid 4755 0:0 regular file",
    "RT:/rt/private 600 0:0 regular file",
    "RT:/rt/readonly 444 0:0 regular file",
    "RT:/rt/dir700 700 0:0 directory",
    "RT:/rt/link 777 0:0 symbolic link",
    "RT:/rt/dangling 777 0:0 symbolic link",
    "LINK:/rt/link suid",
    "LINK:/rt/dangling /nowhere",
};

/// The owners the container itself gave, committed, and seen again in a run of the new tree.
pub const owner_lines = [_][]const u8{
    "RT:/rt/owned 2750 5:6 regular empty file",
    "RT:/rt/olink 777 5:6 symbolic link",
    "LINK:/rt/olink owned",
};

pub fn check_lines(output: []const u8, wanted: []const []const u8) Error!void {
    for (wanted) |line| {
        if (!has_line(output, line)) return error.LineMissing;
    }
}

/// The extended attribute is on the file the container's lower directory is made of.
pub fn check_xattr(output: []const u8, name: []const u8, value: []const u8) Error!void {
    var wanted: [128]u8 = undefined;
    // Cannot fail: a name and a value fit 128 bytes.
    const line = std.fmt.bufPrint(&wanted, "XATTR:{s}={s}", .{ name, value }) catch unreachable;
    if (!has_line(output, line)) return error.LineMissing;
}

/// `ps --output json --all` lists every container named.
pub fn check_ps_lists(streams: Streams, status: u8, names: []const []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!contains(streams.stdout, "\"schema\":\"zbx.ps/1\"")) return error.ReportWrong;
    for (names) |name| {
        var wanted: [96]u8 = undefined;
        // Cannot fail: a container name fits 96 bytes.
        const text = std.fmt.bufPrint(&wanted, "\"name\":\"{s}\"", .{name}) catch unreachable;
        if (!contains(streams.stdout, text)) return error.LineMissing;
    }
}

/// The version of the run records the binary under test writes. M3 introduced version 4; M6
/// slice 1 made it 5 (the network, the forwards and the names of `-e`), and the earlier demos
/// that check what the current binary writes follow it.
pub const record_version_written: u32 = 5;

/// A run record file has the version line `.version = <n>,`.
pub fn check_record_version(output: []const u8, version: u32) Error!void {
    var wanted: [32]u8 = undefined;
    // Cannot fail: a small number fits 32 bytes.
    const line = std.fmt.bufPrint(&wanted, ".version = {d},", .{version}) catch unreachable;
    if (!has_line(output, line)) return error.LineMissing;
}

const testing = std.testing;

fn repeat(comptime byte: u8, comptime count: usize) [count]u8 {
    return @splat(byte);
}

test "a digest is b3: and 64 lowercase hex digits" {
    // Goal: the import check cannot pass on a path or a diagnostic. Method: good and bad text.
    const good = "b3:" ++ repeat('a', 64);
    try testing.expect(is_digest(good));
    try testing.expect(!is_digest(good[0..66]));
    try testing.expect(!is_digest("b3:" ++ repeat('G', 64)));
    try testing.expect(!is_digest("sha:" ++ repeat('0', 63)));
    try testing.expect(!is_digest(""));
}

test "an import prints the digest alone and exits 0" {
    const good = "b3:" ++ repeat('b', 64);
    const ok = try check_import(.{ .stdout = good ++ "\n", .stderr = "" }, 0);
    try testing.expectEqualStrings(good, ok);
    const bare: Streams = .{ .stdout = good, .stderr = "" };
    try testing.expectError(error.ExitCodeWrong, check_import(bare, 2));
    try testing.expectError(error.DigestWrong, check_import(.{ .stdout = "x\n", .stderr = "" }, 0));
    try testing.expectError(error.DigestWrong, check_import(.{ .stdout = "", .stderr = "" }, 0));
}

test "the scribble step needs its marker and a clean exit" {
    const done: Streams = .{ .stdout = "scribbled\n", .stderr = "" };
    try check_scribbled(done, 0);
    try testing.expectError(error.ExitCodeWrong, check_scribbled(done, 1));
    try testing.expectError(error.LineMissing, check_scribbled(.{ .stdout = "", .stderr = "" }, 0));
}

test "the store is the same only if the guest says so" {
    try check_store_same("x\nSTORE-SAME\n");
    try testing.expectError(error.StoreChanged, check_store_same("STORE-DIFFERS\n"));
    try testing.expectError(error.LineMissing, check_store_same("nothing\n"));
}

test "the upper layer has the container's writes" {
    try check_upper_written("UPPER-ENTRIES:120\n", 20);
    try testing.expectError(error.LineMissing, check_upper_written("UPPER-ENTRIES:3\n", 20));
    try testing.expectError(error.LineMissing, check_upper_written("none\n", 1));
}

test "read-only: the write is refused by the file system and /tmp works" {
    const refused: Streams = .{ .stdout = "", .stderr = "touch: /x: Read-only file system\n" };
    const allowed: Streams = .{ .stdout = "tmp-ok\n", .stderr = "" };
    try check_read_only(refused, 1, allowed, 0);
    try testing.expectError(error.ExitCodeWrong, check_read_only(refused, 0, allowed, 0));
    try testing.expectError(error.ExitCodeWrong, check_read_only(refused, 125, allowed, 0));
    const other: Streams = .{ .stdout = "", .stderr = "touch: /x: Permission denied\n" };
    try testing.expectError(error.LineMissing, check_read_only(other, 1, allowed, 0));
    const silent: Streams = .{ .stdout = "", .stderr = "" };
    try testing.expectError(error.LineMissing, check_read_only(refused, 1, silent, 0));
}

test "the root's mode and owner are the recorded ones" {
    try check_root("ROOT:711 0 0\n", "711 0 0");
    try testing.expectError(error.LineMissing, check_root("ROOT:755 0 0\n", "711 0 0"));
}

test "an unknown digest is E0410 and 125 with nothing on stdout" {
    const text = "error[ZBX-E0410]: no tree with that digest\n";
    const shown: Streams = .{ .stdout = "", .stderr = text };
    try check_unknown_digest(shown, 125);
    try testing.expectError(error.ExitCodeWrong, check_unknown_digest(shown, 1));
    const wrong: Streams = .{ .stdout = "", .stderr = "error[ZBX-E0412]" };
    try testing.expectError(error.ReportWrong, check_unknown_digest(wrong, 125));
    const noisy: Streams = .{ .stdout = "x", .stderr = text };
    try testing.expectError(error.ReportWrong, check_unknown_digest(noisy, 125));
}

test "the record names the tree and the upper layer" {
    try check_record("tree = \"b3:ab\"\nupper = \"/x/upper\"", "b3:ab");
    try testing.expectError(error.LineMissing, check_record("tree = \"b3:ab\"", "b3:ab"));
    try testing.expectError(error.LineMissing, check_record("upper = \"/x/upper\"", "b3:ab"));
}

fn out_err(stdout: []const u8, stderr: []const u8) Streams {
    return .{ .stdout = stdout, .stderr = stderr };
}

test "the diff must be exactly the expected lines on a clean stderr" {
    const lines = "A /a\nD /b\n";
    try check_diff(out_err(lines, ""), 0, lines);
    try testing.expectError(error.ExitCodeWrong, check_diff(out_err(lines, ""), 1, lines));
    try testing.expectError(error.StderrNotEmpty, check_diff(out_err(lines, "w"), 0, lines));
    try testing.expectError(error.ReportWrong, check_diff(out_err("A /a\n", ""), 0, lines));
    const more = lines ++ "M /c\n";
    try testing.expectError(error.ReportWrong, check_diff(out_err(more, ""), 0, lines));
}

test "the JSON diff's summary counts and schema" {
    const summary = "\"summary\":{\"added\":1,\"removed\":2,\"changed\":2}";
    const json = "{\"schema\":\"zbx.store.diff/1\",\"changes\":[]," ++ summary ++ "}";
    try check_diff_summary(json, 1, 2, 2);
    try testing.expectError(error.ReportWrong, check_diff_summary(json, 1, 2, 3));
    const unnamed = "{" ++ summary ++ "}";
    try testing.expectError(error.ReportWrong, check_diff_summary(unnamed, 1, 2, 2));
}

test "the stored size is read from the JSON and must drop by the large file" {
    const parent = "{\"tree\":{\"stored_bytes\":8007000,\"files\":3}}";
    const child = "{\"tree\":{\"stored_bytes\":7000,\"files\":2}}";
    try testing.expectEqual(@as(u64, 8007000), try stored_bytes(parent));
    try check_stored_drop(parent, child, 8_000_000);
    try testing.expectError(error.StoreChanged, check_stored_drop(parent, child, 8_000_001));
    try testing.expectError(error.StoreChanged, check_stored_drop(child, parent, 1));
    try testing.expectError(error.StoreChanged, check_stored_drop(parent, parent, 0));
    try testing.expectError(error.LineMissing, stored_bytes("{}"));
    try testing.expectError(error.LineMissing, stored_bytes("\"stored_bytes\":x"));
}

test "a commit of a running container, and of a directory run, are refused with their codes" {
    const running = out_err("", "error[ZBX-E0427]: the container is still running\n");
    try check_commit_running(running, 1);
    try testing.expectError(error.ExitCodeWrong, check_commit_running(running, 125));
    const other = out_err("", "error[ZBX-E0426]");
    try testing.expectError(error.ReportWrong, check_commit_running(other, 1));
    const noisy = out_err("b3:", running.stderr);
    try testing.expectError(error.ReportWrong, check_commit_running(noisy, 1));
    const bare = out_err("", "error[ZBX-E0426]: the container has no layer to commit\n");
    try check_no_layer(bare, 1);
    try testing.expectError(error.ReportWrong, check_no_layer(running, 1));
    try testing.expectError(error.ExitCodeWrong, check_no_layer(bare, 0));
}

test "a commit prints the parent's digest only if nothing changed" {
    const parent = "b3:" ++ repeat('a', 64);
    const child = "b3:" ++ repeat('b', 64);
    const same = out_err(parent ++ "\n", "");
    const other = out_err(child ++ "\n", "");
    try check_unchanged(same, 0, parent);
    try testing.expectError(error.DigestWrong, check_unchanged(other, 0, parent));
    const printed = try check_changed(other, 0, parent);
    try testing.expectEqualStrings(child, printed);
    try testing.expectError(error.DigestWrong, check_changed(same, 0, parent));
    try testing.expectError(error.ExitCodeWrong, check_changed(other, 1, parent));
}

test "the corrupted object's id is read from the script's line" {
    var buffer: [67]u8 = undefined;
    const line = "CORRUPTED:objects/ab/" ++ repeat('c', 62) ++ "\n";
    try testing.expectEqualStrings("b3:ab" ++ repeat('c', 62), try corrupted_id(line, &buffer));
    try testing.expectError(error.LineMissing, corrupted_id("nothing\n", &buffer));
    try testing.expectError(error.LineMissing, corrupted_id("CORRUPTED:objects/ab/c\n", &buffer));
    const bad = "CORRUPTED:objects/ab/" ++ repeat('G', 62);
    try testing.expectError(error.DigestWrong, corrupted_id(bad, &buffer));
}

test "verify: clean needs exit 0 and a quiet stderr; damage needs exit 2 and the report" {
    const clean = out_err("checked 3 objects (1 B), 2 trees, 1 roots: no damage\n", "");
    try check_verify_clean(clean, 0);
    try testing.expectError(error.ExitCodeWrong, check_verify_clean(clean, 2));
    try testing.expectError(
        error.StderrNotEmpty,
        check_verify_clean(out_err(clean.stdout, "w"), 0),
    );
    try testing.expectError(error.LineMissing, check_verify_clean(out_err("hi\n", ""), 0));
    const id = "b3:" ++ repeat('a', 64);
    const damaged = out_err(
        "checked 3 objects (1 B), 2 trees, 1 roots: 1 damaged\n",
        "error[ZBX-E0429]: x\n  cause  object " ++ id ++ " reached by /etc/passwd\n" ++
            "error[ZBX-E0430]: y\n",
    );
    try check_verify_damaged(damaged, 2, id);
    try testing.expectError(error.ExitCodeWrong, check_verify_damaged(damaged, 1, id));
    try testing.expectError(
        error.ReportWrong,
        check_verify_damaged(damaged, 2, "b3:" ++ repeat('b', 64)),
    );
    try testing.expectError(
        error.ReportWrong,
        check_verify_damaged(out_err(damaged.stdout, "error[ZBX-E0429] " ++ id), 2, id),
    );
    try testing.expectError(
        error.LineMissing,
        check_verify_damaged(out_err("ok\n", damaged.stderr), 2, id),
    );
}

test "verify in JSON: the id, the kind, the count and the path in each root" {
    const id = "b3:" ++ repeat('a', 64);
    const root = "b3:" ++ repeat('r', 64);
    const head = "{\"schema\":\"zbx.store.verify/1\",\"ok\":false,\"damaged\":1,";
    const one = "{\"root\":\"" ++ root ++ "\",\"path\":\"/etc/passwd\"}";
    const json = head ++ "\"things\":[{\"id\":\"" ++ id ++ "\",\"kind\":\"content\"," ++
        "\"reached\":2,\"paths\":[" ++ one ++ "," ++ one ++ "]}]}";
    try check_verify_json(out_err(json, ""), 2, id, 2);
    try testing.expectError(error.ReportWrong, check_verify_json(out_err(json, ""), 2, id, 3));
    try testing.expectError(error.ExitCodeWrong, check_verify_json(out_err(json, ""), 0, id, 2));
    const other = std.mem.replaceOwned(
        u8,
        testing.allocator,
        json,
        "content",
        "chunk_list",
    ) catch unreachable; // Cannot fail: a small test string.
    defer testing.allocator.free(other);
    try testing.expectError(error.ReportWrong, check_verify_json(out_err(other, ""), 2, id, 2));
}

const plan_head = "{\"schema\":\"zbx.store.gc/1\",\"applied\":false,\"plan\":\"b3:";
const plan_tail = "\",\"generation\":9,\"objects\":2,\"lists\":1,\"trees\":3,\"farms\":0," ++
    "\"tmp\":1,\"bytes\":8000100}";
const plan_json = plan_head ++ repeat('1', 64) ++ plan_tail;

test "a plan: not applied, big enough, with a hash, and the leftovers it was told of" {
    const hash = try check_plan(out_err(plan_json, ""), 0, 8_000_000, 1);
    try testing.expectEqualStrings("b3:" ++ repeat('1', 64), hash);
    try testing.expectError(error.ReportWrong, check_plan(out_err(plan_json, ""), 0, 9_000_000, 1));
    try testing.expectError(error.ReportWrong, check_plan(out_err(plan_json, ""), 0, 8_000_000, 0));
    try testing.expectError(error.ExitCodeWrong, check_plan(out_err(plan_json, ""), 1, 0, 1));
    try testing.expectError(error.StderrNotEmpty, check_plan(out_err(plan_json, "w"), 0, 0, 1));
    const applied = std.mem.replaceOwned(
        u8,
        testing.allocator,
        plan_json,
        "false",
        "true",
    ) catch unreachable; // Cannot fail: a small test string.
    defer testing.allocator.free(applied);
    try testing.expectError(error.ReportWrong, check_plan(out_err(applied, ""), 0, 0, 1));
}

test "a stale confirmation is E0431 and exit 1, with the fresh hash; the fix gives it back" {
    const fresh = "b3:" ++ repeat('2', 64);
    const fix = "  fix    read the plan again:   zbx store gc --confirm ";
    const text = out_err("", "error[ZBX-E0431]: the store changed\n" ++ fix ++ fresh ++ "\n");
    try check_stale(text, 1, fresh);
    try check_stale(text, 1, null);
    try testing.expectError(error.ExitCodeWrong, check_stale(text, 0, fresh));
    try testing.expectError(error.ReportWrong, check_stale(text, 1, "b3:" ++ repeat('3', 64)));
    try testing.expectError(error.ReportWrong, check_stale(out_err("x", text.stderr), 1, fresh));
    try testing.expectEqualStrings(fresh, try stale_hash(text.stderr));
    try testing.expectError(error.LineMissing, stale_hash("nothing"));
}

test "an applied gc: the plan's hash, the id that is the hash's start, and what it moved" {
    const plan = "b3:" ++ repeat('4', 64);
    const json = "{\"schema\":\"zbx.store.gc/1\",\"applied\":true,\"plan\":\"" ++ plan ++
        "\",\"gc\":\"444444444444\",\"objects\":2,\"tmp\":1,\"bytes\":8000100}";
    try testing.expectEqualStrings(
        "444444444444",
        try check_applied(out_err(json, ""), 0, plan, 8_000_000, 1),
    );
    try testing.expectError(
        error.ReportWrong,
        check_applied(out_err(json, ""), 0, "b3:" ++ repeat('5', 64), 0, 1),
    );
    try testing.expectError(
        error.ReportWrong,
        check_applied(out_err(json, ""), 0, plan, 9_000_000, 1),
    );
    try testing.expectError(error.ReportWrong, check_applied(out_err(json, ""), 0, plan, 0, 2));
    try testing.expectError(error.ExitCodeWrong, check_applied(out_err(json, ""), 2, plan, 0, 1));
    const odd = std.mem.replaceOwned(
        u8,
        testing.allocator,
        json,
        "\"gc\":\"444444444444",
        "\"gc\":\"555555555555",
    ) catch unreachable; // Cannot fail: a small test string.
    defer testing.allocator.free(odd);
    try testing.expectError(error.DigestWrong, check_applied(out_err(odd, ""), 0, plan, 0, 1));
}

test "the store's bytes shrink by the freed file, and the trash is listed and restored" {
    const big = "{\"schema\":\"zbx.store.du/1\",\"store\":{\"bytes\":15000000,\"objects\":5}}";
    const small = "{\"store\":{\"bytes\":6999900,\"objects\":4,\"trees\":1}}";
    const before = try store_total_bytes(big);
    const after = try store_total_bytes(small);
    try testing.expectEqual(@as(u64, 15000000), before);
    try check_shrank(before, after, 8_000_000);
    try testing.expectError(error.StoreChanged, check_shrank(before, after, 8_100_000));
    try testing.expectError(error.StoreChanged, check_shrank(after, before, 1));
    try testing.expectError(error.LineMissing, store_total_bytes("{}"));
    try check_trash_listed(out_err("GC  x\n444444444444 ... complete\n", ""), 0, "444444444444");
    try testing.expectError(
        error.LineMissing,
        check_trash_listed(out_err("GC\n", ""), 0, "444444444444"),
    );
    try testing.expectError(
        error.LineMissing,
        check_trash_listed(out_err("444444444444 incomplete?\n", ""), 0, "555555555555"),
    );
    try check_restored(
        out_err("restored 2 objects from the trash 444444444444\n", ""),
        0,
        "444444444444",
    );
    try testing.expectError(
        error.LineMissing,
        check_restored(out_err("nothing\n", ""), 0, "444444444444"),
    );
    try testing.expectError(
        error.ExitCodeWrong,
        check_restored(out_err("restored 444444444444", ""), 1, "444444444444"),
    );
    try check_no_trash(out_err("", "error[ZBX-E0433]: no trash\n"), 1);
    try testing.expectError(
        error.ReportWrong,
        check_no_trash(out_err("", "error[ZBX-E0432]\n"), 1),
    );
    try testing.expectError(
        error.ExitCodeWrong,
        check_no_trash(out_err("", "error[ZBX-E0433]\n"), 2),
    );
}

test "a busy store is E0436 and exit 1 with the words for the holder and nothing on stdout" {
    const text = "error[ZBX-E0436]: the store is in use\n  cause  other zbx commands are writing\n";
    try check_busy(out_err("", text), 1, "are writing");
    try testing.expectError(error.ExitCodeWrong, check_busy(out_err("", text), 2, "are writing"));
    try testing.expectError(error.ReportWrong, check_busy(out_err("", text), 1, "process 4242"));
    try testing.expectError(error.ReportWrong, check_busy(out_err("x", text), 1, "are writing"));
    const other = out_err("", "error[ZBX-E0431]\n");
    try testing.expectError(error.ReportWrong, check_busy(other, 1, ""));
}

test "a plan that spares a held tree is small and has no chunk list" {
    const small = "{\"schema\":\"zbx.store.gc/1\",\"applied\":false,\"plan\":\"b3:" ++
        repeat('1', 64) ++ "\",\"objects\":3,\"lists\":0,\"trees\":2,\"bytes\":4357}";
    try check_plan_holds(out_err(small, ""), 0, 1_000_000);
    try testing.expectError(error.ReportWrong, check_plan_holds(out_err(small, ""), 0, 4000));
    const limit: u64 = 1_000_000;
    try testing.expectError(error.ReportWrong, check_plan_holds(out_err(plan_json, ""), 0, limit));
    try testing.expectError(error.ExitCodeWrong, check_plan_holds(out_err(small, ""), 1, limit));
    try testing.expectError(error.StderrNotEmpty, check_plan_holds(out_err(small, "w"), 0, limit));
}

test "growth must be about the new file, not a second rootfs" {
    try check_growth(7_700_000, 17_750_000, 10_000_000, 10_500_000);
    try testing.expectError(
        error.StoreChanged,
        check_growth(7_700_000, 25_500_000, 10_000_000, 10_500_000),
    );
    try testing.expectError(
        error.StoreChanged,
        check_growth(7_700_000, 9_000_000, 10_000_000, 10_500_000),
    );
    try testing.expectError(error.StoreChanged, check_growth(7_700_000, 7_000_000, 0, 10));
}

test "the apk diff lists additions, and changes only apk's own files" {
    const good = "A /usr/bin/dtach\nA /lib/apk/db/lock\nM /etc/apk/world  content\n" ++
        "M /lib/apk/db/installed  content\n";
    try check_apk_diff(out_err(good, ""), 0, "/usr/bin/dtach");
    try testing.expectError(
        error.ReportWrong,
        check_apk_diff(out_err(good, ""), 0, "/usr/bin/other"),
    );
    try testing.expectError(
        error.ExitCodeWrong,
        check_apk_diff(out_err(good, ""), 1, "/usr/bin/dtach"),
    );
    try testing.expectError(
        error.StderrNotEmpty,
        check_apk_diff(out_err(good, "w"), 0, "/usr/bin/dtach"),
    );
    const deleted = good ++ "D /etc/shadow\n";
    try testing.expectError(
        error.ReportWrong,
        check_apk_diff(out_err(deleted, ""), 0, "/usr/bin/dtach"),
    );
    const touched = good ++ "M /etc/passwd  content\n";
    try testing.expectError(
        error.ReportWrong,
        check_apk_diff(out_err(touched, ""), 0, "/usr/bin/dtach"),
    );
    try testing.expectError(
        error.ReportWrong,
        check_apk_diff(out_err("M /etc/apk/world  content\n", ""), 0, "/usr/bin/dtach"),
    );
    try testing.expectError(error.ReportWrong, check_apk_diff(out_err("garbage\n", ""), 0, "/x"));
}

test "apk's run says what it installed and exits 0" {
    const text = "fetch http://x\n(1/1) Installing dtach (0.9-r5)\nOK: 8 MiB in 16 packages\n";
    try check_apk_run(out_err(text, ""), 0, "dtach");
    try testing.expectError(error.LineMissing, check_apk_run(out_err(text, ""), 0, "jq"));
    try testing.expectError(error.ExitCodeWrong, check_apk_run(out_err(text, ""), 1, "dtach"));
}

test "two imports must give one digest" {
    const a = "b3:" ++ repeat('a', 64);
    try check_same_digest(a, a);
    try testing.expectError(error.DigestWrong, check_same_digest(a, "b3:" ++ repeat('b', 64)));
    try testing.expectError(error.DigestWrong, check_same_digest(a, "b3:short"));
}

test "the round trip needs every mode, owner, kind and link line" {
    const all = "RT:/rt/suid 4755 0:0 regular file\nRT:/rt/private 600 0:0 regular file\n" ++
        "RT:/rt/readonly 444 0:0 regular file\nRT:/rt/dir700 700 0:0 directory\n" ++
        "RT:/rt/link 777 0:0 symbolic link\nRT:/rt/dangling 777 0:0 symbolic link\n" ++
        "LINK:/rt/link suid\nLINK:/rt/dangling /nowhere\n";
    try check_lines(all, &round_trip_lines);
    const wrong = "RT:/rt/suid 755 0:0 regular file\n";
    try testing.expectError(error.LineMissing, check_lines(wrong, &round_trip_lines));
    try testing.expectError(error.LineMissing, check_lines("", &owner_lines));
    try check_lines("RT:/rt/owned 2750 5:6 regular empty file\n" ++
        "RT:/rt/olink 777 5:6 symbolic link\n" ++
        "LINK:/rt/olink owned\n", &owner_lines);
}

test "the extended attribute must be on the lower file, with its value" {
    try check_xattr("noise\nXATTR:user.zbx=hello\n", "user.zbx", "hello");
    try testing.expectError(
        error.LineMissing,
        check_xattr("XATTR:user.zbx=other\n", "user.zbx", "hello"),
    );
    try testing.expectError(error.LineMissing, check_xattr("", "user.zbx", "hello"));
}

test "ps lists every container the old binary left, and a record has its version" {
    const json = "{\"schema\":\"zbx.ps/1\",\"containers\":[{\"name\":\"old1\"}," ++
        "{\"name\":\"old2\"}]}";
    try check_ps_lists(out_err(json, ""), 0, &.{ "old1", "old2" });
    try testing.expectError(
        error.LineMissing,
        check_ps_lists(out_err(json, ""), 0, &.{ "old1", "old3" }),
    );
    try testing.expectError(error.ExitCodeWrong, check_ps_lists(out_err(json, ""), 2, &.{"old1"}));
    try testing.expectError(error.ReportWrong, check_ps_lists(out_err("{}", ""), 0, &.{"old1"}));
    try check_record_version(".{\n    .version = 3,\n    .name = \"x\",\n}\n", 3);
    try testing.expectError(
        error.LineMissing,
        check_record_version(".{\n    .version = 3,\n}\n", 4),
    );
}
