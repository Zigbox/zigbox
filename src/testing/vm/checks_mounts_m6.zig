//! The assertions of M6's other mounts and `state export` (slice 3) as pure functions over the
//! text the guest printed, each unit-tested with right and wrong input. The commands that print
//! it are in mounts_m6.zig, a part of demo-m6.

const std = @import("std");
const checks = @import("checks.zig");

const Streams = checks.Streams;

pub const Error = error{
    ExitCodeWrong,
    /// A secret is not readable inside, not mode 0400 owned by root, or can be written.
    SecretWrong,
    /// A commit's diff holds a mount point, or lacks the change the container made.
    CommitWrong,
    /// A bundle holds the secret's bytes.
    BundleLeaks,
    /// A bind can be written, or does not show the host's file.
    BindWrong,
    /// A refusal lacks its code or does not say what was refused.
    RefusalWrong,
    /// A tmpfs is not the size, mode or flags asked for, or outlived its run.
    TmpfsWrong,
    /// An archive does not list the owners, links or times the volume had.
    ArchiveWrong,
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

/// A run that cats the secret, prints `stat -c '%a %u %g'`, tries to write it, and prints `id -u`.
pub fn check_secret(output: []const u8, status: u8, marker: []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!has_line(output, marker)) return error.SecretWrong;
    if (!has_line(output, "400 0 0")) return error.SecretWrong;
    if (!has_line(output, "readonly")) return error.SecretWrong;
    if (contains(output, "writable") and !has_line(output, "readonly")) return error.SecretWrong;
}

/// `zbx store diff <parent> <commit>`: the container's change, and none of its mount points.
pub fn check_commit_diff(output: []const u8) Error!void {
    if (!contains(output, "A /changed")) return error.CommitWrong;
    const points = [_][]const u8{ "run/key", "mnt/note", "hostdir", "scratch" };
    for (points) |point| {
        if (contains(output, point)) return error.CommitWrong;
    }
}

/// One `grep -c <marker>` per bundle: every count is zero.
pub fn check_bundles_clean(output: []const u8, bundles: u32) Error!void {
    var seen: u32 = 0;
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (line.len == 0) continue;
        if (!std.mem.eql(u8, line, "0")) return error.BundleLeaks;
        seen += 1;
    }
    if (seen != bundles) return error.BundleLeaks;
}

/// A run that reads a bind, tries to write the directory, the file, and to remove from it.
pub fn check_bind(output: []const u8, status: u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!has_line(output, "seen")) return error.BindWrong;
    if (!contains(output, "Read-only file system")) return error.BindWrong;
    if (!has_line(output, "n-readonly")) return error.BindWrong;
    if (!has_line(output, "rm-refused")) return error.BindWrong;
}

/// `ls` of the host's directory after the run: the file was there and nothing was added.
pub fn check_host_dir(output: []const u8) Error!void {
    if (!has_line(output, "seen")) return error.BindWrong;
    var lines = std.mem.splitScalar(u8, output, '\n');
    var count: u32 = 0;
    while (lines.next()) |line| {
        if (std.mem.trim(u8, line, " \r\t").len > 0) count += 1;
    }
    if (count != 1) return error.BindWrong;
}

/// A refusal of a source that is not there: exit 125, its code, and the path not made.
pub fn check_missing_source(streams: Streams, status: u8) Error!void {
    if (status != 125) return error.ExitCodeWrong;
    if (!contains(streams.stderr, "error[ZBX-E0210]")) return error.RefusalWrong;
    if (!contains(streams.stderr, "it does not exist")) return error.RefusalWrong;
}

/// A run that prints `df -k` of the tmpfs, its mode, its `mount` line, writes a file, and fills it.
pub fn check_tmpfs(output: []const u8, status: u8, size_kib: []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    var sized = false;
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |line| {
        if (!contains(line, "tmpfs")) continue;
        var words = std.mem.tokenizeAny(u8, line, " \t");
        _ = words.next(); // The file system.
        const total = words.next() orelse continue;
        if (std.mem.eql(u8, total, size_kib)) sized = true;
    }
    if (!sized) return error.TmpfsWrong;
    if (!has_line(output, "1777")) return error.TmpfsWrong;
    if (!contains(output, "noexec")) return error.TmpfsWrong;
    if (!has_line(output, "hi")) return error.TmpfsWrong;
    if (!contains(output, "No space left on device")) return error.TmpfsWrong;
}

/// The next run does not find the tmpfs or its file.
pub fn check_gone(output: []const u8, status: u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!has_line(output, "gone")) return error.TmpfsWrong;
}

/// A tmpfs larger than the memory limit, filled: the container is killed for memory (137).
pub fn check_memory_charged(status: u8) Error!void {
    if (status != 137) return error.ExitCodeWrong;
}

/// `tar -tzvf` owners counted (`awk '{print $2}' | sort | uniq -c`): the postgres user's 999 is
/// there and no id of the host's subordinate range is.
pub fn check_owners(output: []const u8) Error!void {
    var has_999 = false;
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |raw| {
        var words = std.mem.tokenizeAny(u8, raw, " \t\r");
        _ = words.next() orelse continue; // The count.
        const owner = words.next() orelse continue;
        const slash = std.mem.indexOfScalar(u8, owner, '/') orelse return error.ArchiveWrong;
        const uid = std.fmt.parseInt(u32, owner[0..slash], 10) catch return error.ArchiveWrong;
        const gid = std.fmt.parseInt(u32, owner[slash + 1 ..], 10) catch return error.ArchiveWrong;
        if (uid >= 1000 and uid != 65534 or gid >= 1000 and gid != 65534) {
            if (uid != 999 and gid != 999) return error.ArchiveWrong;
        }
        if (uid >= 100000 or gid >= 100000) return error.ArchiveWrong;
        if (uid == 999) has_999 = true;
    }
    if (!has_999) return error.ArchiveWrong;
}

/// `gzip -t`, `tar -xzOf <archive> ./PG_VERSION` and a count of entries.
pub fn check_archive_content(output: []const u8, version: []const u8) Error!void {
    if (!has_line(output, "gzip-ok")) return error.ArchiveWrong;
    if (!has_line(output, version)) return error.ArchiveWrong;
}

/// An export of a volume a container writes: exit 1, `E0706`, naming the holder.
pub fn check_export_in_use(streams: Streams, status: u8, holder: []const u8) Error!void {
    if (status != 1) return error.ExitCodeWrong;
    if (!contains(streams.stderr, "error[ZBX-E0706]")) return error.RefusalWrong;
    if (!contains(streams.stderr, holder)) return error.RefusalWrong;
}

/// The note for a fifo: one `ZBX-W0703`, and the export succeeded.
pub fn check_skip_note(streams: Streams, status: u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (std.mem.count(u8, streams.stderr, "warning[ZBX-W0703]") != 1) return error.RefusalWrong;
    if (!contains(streams.stderr, "fifo")) return error.RefusalWrong;
    // The path inside the volume (`/p`), never the host's layout.
    if (!contains(streams.stderr, "cause  /p is a fifo")) return error.RefusalWrong;
    if (contains(streams.stderr, ".local/share")) return error.RefusalWrong;
}

/// `tar -tzvf` of a volume with a symlink, a hard link, a directory of mode 750, a file with a
/// time set, and a fifo that is not in the archive.
pub fn check_links(listing: []const u8) Error!void {
    if (!contains(listing, " -> a")) return error.ArchiveWrong;
    if (!contains(listing, " link to ")) return error.ArchiveWrong;
    if (!contains(listing, "drwxr-x---")) return error.ArchiveWrong;
    if (!contains(listing, "2023-11-1")) return error.ArchiveWrong;
    if (contains(listing, "./p\n") or contains(listing, "./p ")) return error.ArchiveWrong;
}

const testing = std.testing;

test "the secret: readable, mode 400, root's, and read-only" {
    const good = "marker-1\n400 0 0\nreadonly\n0\n";
    try check_secret(good, 0, "marker-1");
    try testing.expectError(error.SecretWrong, check_secret(good, 0, "marker-2"));
    try testing.expectError(
        error.SecretWrong,
        check_secret("marker-1\n644 0 0\nreadonly\n", 0, "marker-1"),
    );
    try testing.expectError(
        error.SecretWrong,
        check_secret("marker-1\n400 1000 0\nreadonly\n", 0, "marker-1"),
    );
    try testing.expectError(
        error.SecretWrong,
        check_secret("marker-1\n400 0 0\nwritable\n", 0, "marker-1"),
    );
    try testing.expectError(error.ExitCodeWrong, check_secret(good, 1, "marker-1"));
}

test "the commit holds the change and no mount point; the bundles hold no secret" {
    try check_commit_diff("A /changed\n");
    try testing.expectError(error.CommitWrong, check_commit_diff(""));
    try testing.expectError(error.CommitWrong, check_commit_diff("A /changed\nA /run/key\n"));
    try testing.expectError(error.CommitWrong, check_commit_diff("A /changed\nA /scratch/\n"));
    try testing.expectError(
        error.CommitWrong,
        check_commit_diff("A /changed\nA /media/hostdir/\n"),
    );
    try check_bundles_clean("0\n0\n", 2);
    try testing.expectError(error.BundleLeaks, check_bundles_clean("0\n", 2));
    try testing.expectError(error.BundleLeaks, check_bundles_clean("0\n1\n", 2));
    try testing.expectError(error.BundleLeaks, check_bundles_clean("tar: error\n0\n", 2));
}

test "a bind that cannot be written, and a source that is not there" {
    const good = "seen\ntouch: /mnt/h/new: Read-only file system\nn-readonly\nrm-refused\n";
    try check_bind(good, 0);
    try testing.expectError(error.BindWrong, check_bind("seen\nn-readonly\nrm-refused\n", 0));
    try testing.expectError(
        error.BindWrong,
        check_bind("seen\nRead-only file system\nn-writable\nrm-refused\n", 0),
    );
    try testing.expectError(
        error.BindWrong,
        check_bind("Read-only file system\nn-readonly\nrm-refused\n", 0),
    );
    try check_host_dir("seen\n");
    try testing.expectError(error.BindWrong, check_host_dir("new\nseen\n"));
    try testing.expectError(error.BindWrong, check_host_dir("\n"));
    const refused: Streams = .{
        .stdout = "",
        .stderr = "error[ZBX-E0210]: a --bind or --secret source can't be used\n" ++
            "  cause  --bind /home/demo/nowhere: it does not exist\n",
    };
    try check_missing_source(refused, 125);
    try testing.expectError(error.ExitCodeWrong, check_missing_source(refused, 0));
    try testing.expectError(
        error.RefusalWrong,
        check_missing_source(.{ .stdout = "", .stderr = "error[ZBX-E0012]" }, 125),
    );
}

test "a tmpfs: its size, mode, flags and bound; gone with the run; charged to the memory" {
    const good = "tmpfs  8192  0  8192  0%  /scratch\n1777\ntmpfs on /scratch type tmpfs " ++
        "(rw,nosuid,nodev,noexec,size=8192k)\nhi\ndd: error writing '/scratch/big': " ++
        "No space left on device\n";
    try check_tmpfs(good, 0, "8192");
    try testing.expectError(error.TmpfsWrong, check_tmpfs(good, 0, "65536"));
    try testing.expectError(
        error.TmpfsWrong,
        check_tmpfs("tmpfs 8192 0 8192 0% /scratch\n777\n", 0, "8192"),
    );
    try testing.expectError(error.ExitCodeWrong, check_tmpfs(good, 1, "8192"));
    try check_gone("gone\n", 0);
    try testing.expectError(error.TmpfsWrong, check_gone("present\n", 0));
    try check_memory_charged(137);
    try testing.expectError(error.ExitCodeWrong, check_memory_charged(0));
}

test "an archive: owners as the container sees them, content, links, and refusals" {
    try check_owners("   40 999/999\n  300 999/0\n    2 0/0\n");
    try testing.expectError(error.ArchiveWrong, check_owners("  40 100998/100998\n   1 999/999\n"));
    try testing.expectError(error.ArchiveWrong, check_owners("   2 0/0\n"));
    try testing.expectError(error.ArchiveWrong, check_owners("  40 x\n"));
    try check_archive_content("gzip-ok\n16\n", "16");
    try testing.expectError(error.ArchiveWrong, check_archive_content("16\n", "16"));
    const refused: Streams = .{
        .stdout = "",
        .stderr = "error[ZBX-E0706]: the state volume is in use\n  cause the container pgw",
    };
    try check_export_in_use(refused, 1, "pgw");
    try testing.expectError(error.RefusalWrong, check_export_in_use(refused, 1, "other"));
    try testing.expectError(error.ExitCodeWrong, check_export_in_use(refused, 0, "pgw"));
    const note: Streams = .{
        .stdout = "",
        .stderr = "warning[ZBX-W0703]: a file was left out\n  cause  /p is a fifo\n",
    };
    try check_skip_note(note, 0);
    const host_path: Streams = .{
        .stdout = "",
        .stderr = "warning[ZBX-W0703]: a file was left out\n" ++
            "  cause  /home/demo/.local/share/zbx/state/lk/data/p is a fifo\n",
    };
    try testing.expectError(error.RefusalWrong, check_skip_note(host_path, 0));
    try testing.expectError(
        error.RefusalWrong,
        check_skip_note(.{ .stdout = "", .stderr = "" }, 0),
    );
    const listing = "-rw-r--r-- 0/0 4 2023-11-14 22:13 ./a\n" ++
        "hrw-r--r-- 0/0 0 2023-11-14 22:13 ./b link to ./a\n" ++
        "lrwxrwxrwx 0/0 0 2024-01-01 00:00 ./c -> a\ndrwxr-x--- 0/0 0 2024-01-01 00:00 ./d/\n";
    try check_links(listing);
    try testing.expectError(
        error.ArchiveWrong,
        check_links("-rw-r--r-- 0/0 4 2023-11-14 22:13 ./a\n"),
    );
    try testing.expectError(
        error.ArchiveWrong,
        check_links(listing ++ "prw------- 0/0 0 2024-01-01 00:00 ./p\n"),
    );
}
