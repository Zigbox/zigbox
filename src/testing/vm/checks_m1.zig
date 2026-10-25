//! The M1 demo's assertions as pure functions over the text the guest printed, so each can be
//! unit-tested, including with deliberately wrong input: a check that cannot fail proves
//! nothing. The commands that print this text are in demo_m1.zig; the formats here are theirs.

const std = @import("std");
const assert = std.debug.assert;
const checks = @import("checks.zig");

const Streams = checks.Streams;

pub const Error = error{
    /// stderr was not empty where nothing was expected.
    StderrNotEmpty,
    StdoutNotEmpty,
    ExitCodeWrong,
    /// A line the step must print is missing or wrong; the message names which.
    LineMissing,
    ProcessListWrong,
    IdMapWrong,
    HostProcessWrong,
    LeakFound,
    BundleMissing,
    NoteMissing,
    TooSlow,
};

fn has_line(text: []const u8, wanted: []const u8) bool {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        if (std.mem.eql(u8, std.mem.trim(u8, raw, " \r\t"), wanted)) return true;
    }
    return false;
}

fn has_line_starting(text: []const u8, prefix: []const u8) bool {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        if (std.mem.startsWith(u8, std.mem.trim(u8, raw, " \r\t"), prefix)) return true;
    }
    return false;
}

fn expect_quiet_stderr(streams: Streams) Error!void {
    if (std.mem.trim(u8, streams.stderr, " \r\n").len != 0) return error.StderrNotEmpty;
}

// ---- Step 1: the shell fed on stdin ---------------------------------------------------------

/// `id`, `ps`, `hostname` and `cat /etc/os-release` fed to the container's shell: root inside,
/// only the shell and `ps` in the process list, the container's name as its hostname, Alpine.
pub fn check_shell_session(streams: Streams, status: u8, name: []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    try expect_quiet_stderr(streams);
    const out = streams.stdout;
    if (std.mem.indexOf(u8, out, "uid=0(root)") == null) return error.LineMissing;
    if (!has_line(out, name)) return error.LineMissing;
    if (!has_line(out, "ID=alpine")) return error.LineMissing;
    if (!has_line_starting(out, "VERSION_ID=3.20.")) return error.LineMissing;
    try check_process_list(out);
}

/// The busybox `ps` table: a header, then exactly PID 1 (the shell) and the `ps` itself.
fn check_process_list(out: []const u8) Error!void {
    var lines = std.mem.splitScalar(u8, out, '\n');
    var in_table = false;
    var rows: u32 = 0;
    var first_is_shell = false;
    var second_is_ps = false;
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (std.mem.startsWith(u8, line, "PID ")) {
            in_table = true;
            continue;
        }
        if (!in_table) continue;
        const first = std.mem.indexOfScalar(u8, line, ' ') orelse break;
        _ = std.fmt.parseInt(u32, line[0..first], 10) catch break; // The table ended.
        rows += 1;
        if (rows == 1) first_is_shell = std.mem.startsWith(u8, line, "1 ") and
            std.mem.endsWith(u8, line, "/bin/sh");
        if (rows == 2) second_is_ps = std.mem.endsWith(u8, line, " ps");
    }
    if (rows != 2 or !first_is_shell or !second_is_ps) return error.ProcessListWrong;
}

// ---- Step 2: the host sees a process with the user's uid ------------------------------------

/// The output of the step's command: the host `ps` rows for `sleep 1000` (uid, then the
/// command), then `GONE:<n>`, the number of such processes left after zbx was stopped.
pub fn check_host_sees_user_process(output: []const u8, uid: u32) Error!void {
    var rows: u32 = 0;
    var lines = std.mem.splitScalar(u8, output, '\n');
    var gone = false;
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (std.mem.startsWith(u8, line, "GONE:")) {
            gone = std.mem.eql(u8, line, "GONE:0");
            continue;
        }
        if (!std.mem.endsWith(u8, line, " sleep 1000")) continue;
        var number_buffer: [16]u8 = undefined;
        const wanted = std.fmt.bufPrint(&number_buffer, "{d} ", .{uid}) catch unreachable; // Short.
        if (!std.mem.startsWith(u8, line, wanted)) return error.HostProcessWrong;
        rows += 1;
    }
    if (rows != 1) return error.HostProcessWrong;
    if (!gone) return error.HostProcessWrong;
}

// ---- Step 3: a write lands in the rootfs ----------------------------------------------------

/// `touch /etc/hacked` in the container: the file is in the rootfs, owned by the user, and not
/// on the host. Output: the owner and path, then `host-etc-clean`.
pub fn check_write_lands_in_rootfs(
    output: []const u8,
    user: []const u8,
    path: []const u8,
) Error!void {
    var buffer: [160]u8 = undefined;
    const wanted = std.fmt.bufPrint(
        &buffer,
        "{s} {s}",
        .{ user, path },
    ) catch return error.LineMissing;
    if (!has_line(output, wanted)) return error.LineMissing;
    if (!has_line(output, "host-etc-clean")) return error.LeakFound;
}

// ---- Step 4: the exit code passes through ---------------------------------------------------

pub fn check_exit_passes_through(streams: Streams, status: u8, expected: u8) Error!void {
    if (status != expected) return error.ExitCodeWrong;
    if (std.mem.trim(u8, streams.stdout, " \r\n").len != 0) return error.StdoutNotEmpty;
    try expect_quiet_stderr(streams);
}

// ---- Step 5: a real Ctrl-C ------------------------------------------------------------------

/// The Ctrl-C step: the exit status zbx printed after the byte 0x03, the time it took, the
/// limit, and the stderr text (the note naming the signal).
pub fn check_ctrl_c(status: u8, elapsed_ms: u64, limit_ms: u64, stderr: []const u8) Error!void {
    if (status != 130) return error.ExitCodeWrong;
    if (elapsed_ms > limit_ms) return error.TooSlow;
    const note = "zbx: the container was killed by signal 2 (SIGINT)";
    if (std.mem.indexOf(u8, stderr, note) == null) return error.NoteMissing;
}

// ---- Extra: the id map, the host's mounts and processes, a missing rootfs, the bundle -------

/// `/proc/self/uid_map`, `---`, `/proc/self/gid_map` from inside the container: root is the
/// user's own id, and ids 1 to 65536 map to the subordinate range.
pub fn check_full_id_maps(streams: Streams, status: u8, uid: u32, gid: u32) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    try expect_quiet_stderr(streams); // No W0201: the map is the full one.
    var parts = std.mem.splitSequence(u8, streams.stdout, "---");
    const ids = [_]u32{ uid, gid };
    for (ids) |own| {
        const map = parts.next() orelse return error.IdMapWrong;
        try check_one_map(map, own);
    }
}

fn check_one_map(map: []const u8, own: u32) Error!void {
    var rows: u32 = 0;
    var lines = std.mem.splitScalar(u8, map, '\n');
    while (lines.next()) |raw| {
        var words = std.mem.tokenizeAny(u8, raw, " \t\r");
        const inside = words.next() orelse continue;
        const outside = words.next() orelse return error.IdMapWrong;
        const count = words.next() orelse return error.IdMapWrong;
        if (words.next() != null) return error.IdMapWrong;
        const row = [_][]const u8{ inside, outside, count };
        var numbers: [3]u32 = undefined;
        for (row, 0..) |word, at| numbers[at] = std.fmt.parseInt(
            u32,
            word,
            10,
        ) catch return error.IdMapWrong;
        switch (rows) {
            0 => if (!std.mem.eql(u32, &numbers, &.{ 0, own, 1 })) return error.IdMapWrong,
            1 => if (!std.mem.eql(u32, &numbers, &.{ 1, 100000, 65536 })) return error.IdMapWrong,
            else => return error.IdMapWrong,
        }
        rows += 1;
    }
    if (rows != 2) return error.IdMapWrong;
}

/// Host side first (`HOST-MOUNT:yes`, `HOST-PROC:yes`, so the thing to hide exists), then the
/// container's own answers.
pub fn check_host_is_invisible(output: []const u8) Error!void {
    if (!has_line(output, "HOST-MOUNT:yes")) return error.LineMissing;
    if (!has_line(output, "HOST-PROC:yes")) return error.LineMissing;
    if (has_line(output, "MOUNT-LEAK") or has_line(output, "PROCESS-LEAK")) return error.LeakFound;
    if (!has_line(output, "mount-hidden")) return error.LineMissing;
    if (!has_line(output, "process-hidden")) return error.LineMissing;
}

/// A rootfs that does not exist: `error[ZBX-E0201]` on stderr, nothing on stdout, exit 125
/// (zbx's own failure before the command started, which a container's exit code cannot be).
pub fn check_missing_rootfs(streams: Streams, status: u8) Error!void {
    const header = "error[ZBX-E0201]: ";
    if (!std.mem.startsWith(u8, streams.stderr, header)) return error.NoteMissing;
    if (std.mem.trim(u8, streams.stdout, " \r\n").len != 0) return error.StdoutNotEmpty;
    if (status != 125) return error.ExitCodeWrong;
}

/// The bundle step prints `BUNDLE:<path>`, the `tar -tzf` listing, `LISTED-END`, then
/// `LEAKS:<n>` (planted secrets found in the extracted bundle) and `REDACTED:<n>` (markers).
pub fn check_bundle_has_no_secret(output: []const u8) Error!void {
    if (!has_line_starting(output, "BUNDLE:/")) return error.BundleMissing;
    const listing_end = std.mem.indexOf(u8, output, "LISTED-END") orelse return error.BundleMissing;
    const listing = output[0..listing_end];
    const members = [_][]const u8{
        "/MANIFEST.txt",
        "/run-record.zon",
        "/environment.txt",
        "/doctor.json",
    };
    for (members) |member| {
        if (std.mem.indexOf(u8, listing, member) == null) return error.BundleMissing;
    }
    if (!has_line(output, "LEAKS:0")) return error.LeakFound;
    const marker = "REDACTED:";
    const at = std.mem.indexOf(u8, output, marker) orelse return error.BundleMissing;
    const rest = output[at + marker.len ..];
    const end = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
    const count = std.fmt.parseInt(u32, std.mem.trim(u8, rest[0..end], " \r"), 10) catch
        return error.BundleMissing;
    if (count == 0) return error.BundleMissing; // Nothing was replaced: the test was vacuous.
}

// ---- Tests ---------------------------------------------------------------------------------

const testing = std.testing;

const shell_stdout =
    "uid=0(root) gid=0(root) groups=0(root)\n" ++
    "PID   USER     TIME  COMMAND\n" ++
    "    1 root      0:00 /bin/sh\n" ++
    "    7 root      0:00 ps\n" ++
    "demo1\n" ++
    "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.10\n";

test "shell session: root, two processes, the name, Alpine" {
    const name = "demo1";
    const good: Streams = .{ .stdout = shell_stdout, .stderr = "" };
    try check_shell_session(good, 0, "demo1");
    // Wrong in each way a real failure would be wrong.
    const bad_uid = std.mem.replaceOwned(
        u8,
        testing.allocator,
        shell_stdout,
        "uid=0(root)",
        "uid=1000(demo)",
    );
    const bad_uid_text = try bad_uid;
    defer testing.allocator.free(bad_uid_text);
    try testing.expectError(
        error.LineMissing,
        check_shell_session(.{ .stdout = bad_uid_text, .stderr = "" }, 0, "demo1"),
    );
    try testing.expectError(error.LineMissing, check_shell_session(good, 0, "other"));
    try testing.expectError(error.ExitCodeWrong, check_shell_session(good, 1, "demo1"));
    try testing.expectError(
        error.StderrNotEmpty,
        check_shell_session(.{ .stdout = shell_stdout, .stderr = "warning[ZBX-W0201]\n" }, 0, name),
    );
    const three = "uid=0(root)\nPID USER TIME COMMAND\n 1 root 0:00 /bin/sh\n 5 root " ++
        "0:00 sleep 9\n 7 root 0:00 ps\ndemo1\nID=alpine\nVERSION_ID=3.20.1\n";
    try testing.expectError(
        error.ProcessListWrong,
        check_shell_session(.{ .stdout = three, .stderr = "" }, 0, "demo1"),
    );
    const ubuntu = "uid=0(root)\nPID USER TIME COMMAND\n 1 root 0:00 /bin/sh\n 7 root " ++
        "0:00 ps\ndemo1\nID=ubuntu\nVERSION_ID=\"24.04\"\n";
    try testing.expectError(
        error.LineMissing,
        check_shell_session(.{ .stdout = ubuntu, .stderr = "" }, 0, "demo1"),
    );
}

test "host process: one sleep with the user's uid, none left afterwards" {
    try check_host_sees_user_process("1000 sleep 1000\nGONE:0\n", 1000);
    try testing.expectError(
        error.HostProcessWrong,
        check_host_sees_user_process("0 sleep 1000\nGONE:0\n", 1000),
    );
    try testing.expectError(error.HostProcessWrong, check_host_sees_user_process("GONE:0\n", 1000));
    try testing.expectError(
        error.HostProcessWrong,
        check_host_sees_user_process("1000 sleep 1000\nGONE:1\n", 1000),
    );
    try testing.expectError(
        error.HostProcessWrong,
        check_host_sees_user_process("1000 sleep 1000\n1000 sleep 1000\nGONE:0\n", 1000),
    );
}

test "rootfs write, exit code, Ctrl-C" {
    const path = "/home/demo/alpine/etc/hacked";
    try check_write_lands_in_rootfs("demo " ++ path ++ "\nhost-etc-clean\n", "demo", path);
    try testing.expectError(
        error.LineMissing,
        check_write_lands_in_rootfs("root " ++ path ++ "\nhost-etc-clean\n", "demo", path),
    );
    try testing.expectError(
        error.LeakFound,
        check_write_lands_in_rootfs("demo " ++ path ++ "\n", "demo", path),
    );
    try check_exit_passes_through(.{ .stdout = "", .stderr = "" }, 42, 42);
    try testing.expectError(
        error.ExitCodeWrong,
        check_exit_passes_through(.{ .stdout = "", .stderr = "" }, 1, 42),
    );
    try testing.expectError(
        error.StdoutNotEmpty,
        check_exit_passes_through(.{ .stdout = "x\n", .stderr = "" }, 42, 42),
    );
    const note = "zbx: the container was killed by signal 2 (SIGINT)\n";
    try check_ctrl_c(130, 900, 2000, note);
    try testing.expectError(error.ExitCodeWrong, check_ctrl_c(0, 900, 2000, note));
    try testing.expectError(error.TooSlow, check_ctrl_c(130, 2500, 2000, note));
    try testing.expectError(error.NoteMissing, check_ctrl_c(130, 900, 2000, ""));
}

test "id maps: the full range for both ids" {
    const good = "         0       1000          1\n         1     100000      " ++
        "65536\n---\n         0       1000          1\n         1     100000    " ++
        "  65536\n";
    try check_full_id_maps(.{ .stdout = good, .stderr = "" }, 0, 1000, 1000);
    const single = "         0       1000          1\n---\n         0       1000          1\n";
    try testing.expectError(
        error.IdMapWrong,
        check_full_id_maps(.{ .stdout = single, .stderr = "" }, 0, 1000, 1000),
    );
    try testing.expectError(
        error.IdMapWrong,
        check_full_id_maps(.{ .stdout = good, .stderr = "" }, 0, 1001, 1000),
    );
    try testing.expectError(
        error.StderrNotEmpty,
        check_full_id_maps(.{ .stdout = good, .stderr = "warning[ZBX-W0201]: x\n" }, 0, 1000, 1000),
    );
}

test "host invisibility, missing rootfs, bundle" {
    const hidden = "HOST-MOUNT:yes\nHOST-PROC:yes\nmount-hidden\nprocess-hidden\n";
    try check_host_is_invisible(hidden);
    try testing.expectError(
        error.LeakFound,
        check_host_is_invisible("HOST-MOUNT:yes\nHOST-PROC:yes\nMOUNT-LEAK\nprocess-hidden\n"),
    );
    try testing.expectError(
        error.LineMissing,
        check_host_is_invisible("mount-hidden\nprocess-hidden\n"),
    ); // Nothing to hide.
    try check_missing_rootfs(
        .{ .stdout = "", .stderr = "error[ZBX-E0201]: the rootfs is missing\n" },
        125,
    );
    // The old standard codes are wrong now: a container could exit with them.
    for ([_]u8{ 0, 1, 2, 70, 126, 127 }) |old| {
        try testing.expectError(
            error.ExitCodeWrong,
            check_missing_rootfs(.{ .stdout = "", .stderr = "error[ZBX-E0201]: x\n" }, old),
        );
    }
    try testing.expectError(
        error.NoteMissing,
        check_missing_rootfs(.{ .stdout = "", .stderr = "error[ZBX-E0001]: x\n" }, 125),
    );
    const bundle = "ran\nBUNDLE:/home/demo/.local/state/zbx/bundles/x.tar.gz\n" ++
        "x/MANIFEST.txt\nx/run-record.zon\nx/environment.txt\nx/doctor.json\n" ++
        "LISTED-END\nLEAKS:0\nREDACTED:4\n";
    try check_bundle_has_no_secret(bundle);
    const leaked = std.mem.replaceOwned(u8, testing.allocator, bundle, "LEAKS:0", "LEAKS:2");
    const leaked_text = try leaked;
    defer testing.allocator.free(leaked_text);
    try testing.expectError(error.LeakFound, check_bundle_has_no_secret(leaked_text));
    const vacuous = std.mem.replaceOwned(u8, testing.allocator, bundle, "REDACTED:4", "REDACTED:0");
    const vacuous_text = try vacuous;
    defer testing.allocator.free(vacuous_text);
    try testing.expectError(error.BundleMissing, check_bundle_has_no_secret(vacuous_text));
    try testing.expectError(error.BundleMissing, check_bundle_has_no_secret("ran\n"));
}
