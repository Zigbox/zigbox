//! What the guest's init sets up beyond the root: the store disk (`/dev/vda`, an ext4 file system
//! that is made only on a disk with nothing on it, checked before every mount and grown to the
//! size the Mac gave it), the Mac user's home directory (a virtio-fs share mounted at the path it
//! has on the Mac), and Rosetta (a virtio-fs share, registered with binfmt_misc so that an x86-64
//! program starts through it). Each returns true when it is done; init turns a false into the
//! setup failure the Mac shows.
//!
//! The disk is never reformatted: a disk that holds anything but an ext file system or zeros is
//! left alone and refused.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const constants = @import("constants.zig");

fn failed(result: usize) bool {
    return linux.errno(result) != .SUCCESS;
}

fn log(prefix: []const u8, detail: []const u8) void {
    assert(prefix.len < 256);
    assert(detail.len <= constants.vm_home_bytes_max); // A path, a code or a device name.
    const newline = "\n";
    _ = linux.write(2, prefix.ptr, prefix.len);
    if (detail.len > 0) _ = linux.write(2, detail.ptr, detail.len);
    _ = linux.write(2, newline, newline.len);
}

// ---- What is on the disk ------------------------------------------------------------------------

pub const DiskState = enum {
    /// An ext2, ext3 or ext4 superblock.
    ext,
    /// Nothing but zeros in the first sixty-four KiB: a disk the Mac just made.
    empty,
    /// Anything else. Never formatted.
    other,
};

/// How much of the disk is looked at: the superblock is at 1024, and a file system's other
/// first-block structures (a partition table, a boot sector, a GPT) all begin below this.
pub const probe_bytes: usize = 64 * 1024;
const superblock_magic_offset: usize = 1024 + 56;
const ext_magic: u16 = 0xEF53;

pub fn classify(head: []const u8) DiskState {
    assert(head.len == probe_bytes);
    assert(probe_bytes > superblock_magic_offset + 2); // The magic is inside what is read.
    const magic = std.mem.readInt(u16, head[superblock_magic_offset..][0..2], .little);
    if (magic == ext_magic) return .ext;
    for (head) |byte| {
        if (byte != 0) return .other;
    }
    return .empty;
}

var probe_buffer: [probe_bytes]u8 = undefined;

/// The size of the file system an ext superblock in `head` describes, in bytes.
pub fn file_system_bytes(head: []const u8) u64 {
    assert(head.len == probe_bytes);
    assert(classify(head) == .ext);
    const superblock = head[1024..];
    const blocks_low = std.mem.readInt(u32, superblock[4..8], .little);
    const log_block_size = std.mem.readInt(u32, superblock[24..28], .little);
    const incompatible = std.mem.readInt(u32, superblock[0x60..][0..4], .little);
    const wide: u32 = 0x80; // EXT4_FEATURE_INCOMPAT_64BIT: the block count has a high half.
    const blocks_high: u64 = if (incompatible & wide != 0)
        std.mem.readInt(u32, superblock[0x150..][0..4], .little)
    else
        0;
    // A block size past 64 KiB is not ext4's; the shift would mean nothing.
    if (log_block_size > 6) return 0;
    const blocks = (blocks_high << 32) | blocks_low;
    return blocks * (@as(u64, 1024) << @intCast(log_block_size));
}

/// The disk is bigger than the file system on it by at least a MiB: the Mac grew it.
pub fn needs_growth(file_system: u64, device: u64) bool {
    assert(device > 0); // A block device read to the end has a size.
    assert(file_system > 0); // The caller skips a superblock whose size it cannot read.
    return device >= file_system +| (1 << 20);
}

var device_bytes: u64 = 0;

fn read_state() ?DiskState {
    const opened = linux.open(constants.vm_disk_device, .{ .ACCMODE = .RDONLY }, 0);
    if (failed(opened)) return null;
    const descriptor: i32 = @intCast(opened);
    defer _ = linux.close(descriptor);
    const end = linux.lseek(descriptor, 0, linux.SEEK.END);
    if (failed(end)) return null;
    device_bytes = end;
    const got = linux.pread(descriptor, &probe_buffer, probe_buffer.len, 0);
    if (failed(got)) return null;
    if (got != probe_buffer.len) return null;
    assert(device_bytes >= probe_bytes); // The whole head was read, so the disk is that long.
    return classify(&probe_buffer);
}

// ---- Running the ext4 tools ---------------------------------------------------------------------

/// PID 1 ignores child exits (so that orphans leave no zombies), and a wait then fails. For the
/// length of one tool the default is back, and then the ignoring.
fn child_exits(ignored: bool) void {
    const action: linux.Sigaction = .{
        .handler = .{ .handler = if (ignored) linux.SIG.IGN else linux.SIG.DFL },
        .mask = linux.sigemptyset(),
        .flags = if (ignored) linux.SA.NOCLDWAIT else 0,
    };
    assert(!failed(linux.sigaction(.CHLD, &action, null)));
}

/// Runs the program to its end; its exit code, or 255 if it could not run or was killed.
fn run_tool(argv: [*:null]const ?[*:0]const u8) u32 {
    assert(argv[0] != null);
    child_exits(false);
    defer child_exits(true);
    const forked = linux.fork();
    if (failed(forked)) return 255;
    assert(forked != 1); // A process id is never init's.
    if (forked == 0) {
        const environment = [_:null]?[*:0]const u8{"PATH=/usr/sbin:/usr/bin:/bin"};
        _ = linux.execve(argv[0].?, argv, &environment);
        linux.exit_group(127);
    }
    var status: i32 = 0;
    var usage: linux.rusage = undefined;
    const waited = linux.wait4(@intCast(forked), &status, 0, &usage);
    if (failed(waited)) return 255;
    const code: u32 = @bitCast(status);
    if ((code & 0x7f) != 0) return 255; // Killed by a signal.
    return (code >> 8) & 0xff;
}

/// `e2fsck -p` repairs what is safe to repair without asking. 0 is clean and 1 is repaired; the
/// other codes (needs a person, or a failure) refuse the disk.
pub fn fsck_accepts(code: u32) bool {
    assert(code <= 255); // An exit code, or the 255 that `run_tool` makes of a failure.
    return code == 0 or code == 1;
}

const mke2fs_path = "/usr/sbin/mke2fs";
const e2fsck_path = "/usr/sbin/e2fsck";
const resize2fs_path = "/usr/sbin/resize2fs";

fn make_file_system(uid: u32, gid: u32) bool {
    assert(uid > 0); // The Mac user, never root.
    var owner: [48:0]u8 = @splat(0);
    // Cannot fail: two ids of ten digits fit.
    _ = std.fmt.bufPrint(&owner, "lazy_itable_init=1,nodiscard,root_owner={d}:{d}", .{
        uid, gid,
    }) catch unreachable; // Cannot fail: two ids of ten digits fit.
    assert(std.mem.indexOf(u8, &owner, "root_owner=") != null); // The option was not cut short.
    const argv = [_:null]?[*:0]const u8{
        mke2fs_path, "-q", "-t", "ext4", "-F",                     "-L", "zbx-store",
        "-m",        "1",  "-E", &owner, constants.vm_disk_device,
    };
    return run_tool(&argv) == 0;
}

fn check_file_system() bool {
    const argv = [_:null]?[*:0]const u8{ e2fsck_path, "-p", constants.vm_disk_device };
    const code = run_tool(&argv);
    assert(code <= 255);
    if (!fsck_accepts(code)) log("zbx-init: e2fsck refused the disk, exit code ", code_text(code));
    return fsck_accepts(code);
}

var code_buffer: [12]u8 = undefined;

fn code_text(code: u32) []const u8 {
    assert(code <= 255); // Three digits at most, and the buffer holds more.
    // Cannot fail: a u32 has at most ten digits.
    return std.fmt.bufPrint(&code_buffer, "{d}", .{code}) catch unreachable;
}

/// A disk that grew gets its file system grown, before it is mounted: `resize2fs` wants a
/// file system that `e2fsck -f` has just checked. A failure is only logged; the old size works.
fn grow_file_system() bool {
    assert(device_bytes > 0); // `read_state` measured the disk.
    const forced = [_:null]?[*:0]const u8{ e2fsck_path, "-f", "-p", constants.vm_disk_device };
    if (!fsck_accepts(run_tool(&forced))) return false;
    const argv = [_:null]?[*:0]const u8{ resize2fs_path, constants.vm_disk_device };
    const code = run_tool(&argv);
    if (code != 0) log("zbx-init: resize2fs failed, exit code ", code_text(code));
    return code == 0;
}

/// Makes the file system if the disk is empty, checks it, mounts it at `vm_disk_mount`, grows it,
/// and makes the directories zbx keeps its data and state in, owned by the user.
pub fn mount_disk(uid: u32, gid: u32) bool {
    assert(uid > 0);
    const state = read_state() orelse {
        log("zbx-init: cannot read ", constants.vm_disk_device);
        return false;
    };
    switch (state) {
        .other => {
            log("zbx-init: will not format a disk with data on it: ", constants.vm_disk_device);
            return false;
        },
        .empty => if (!make_file_system(uid, gid)) {
            log("zbx-init: mke2fs failed on ", constants.vm_disk_device);
            return false;
        },
        .ext => {},
    }
    assert(state != .other); // Returned above: a disk with data of another kind is not touched.
    if (!check_file_system()) return false;
    const have = if (state == .ext) file_system_bytes(&probe_buffer) else 0;
    if (have > 0 and needs_growth(have, device_bytes)) {
        // Failing to grow leaves the disk as it was, usable; it is not a reason to refuse.
        _ = grow_file_system();
    }
    _ = linux.mkdir(constants.vm_disk_mount, 0o755);
    const flags: u32 = linux.MS.NOATIME;
    const device = constants.vm_disk_device;
    const mounted = linux.mount(device, constants.vm_disk_mount, "ext4", flags, 0);
    if (failed(mounted)) {
        log("zbx-init: cannot mount ", constants.vm_disk_device);
        return false;
    }
    return own_directories(uid, gid);
}

/// Before the machine powers off: the disk is made read-only, which writes the journal out and
/// marks the file system clean, so that the next mount needs no recovery. A disk that cannot be
/// (a file still open for writing) stays as it is; the journal makes that safe too.
pub fn quiesce_disk() void {
    linux.sync();
    const flags: u32 = linux.MS.REMOUNT | linux.MS.RDONLY;
    _ = linux.mount(constants.vm_disk_device, constants.vm_disk_mount, "ext4", flags, 0);
}

fn own_directories(uid: u32, gid: u32) bool {
    assert(uid > 0); // The Mac user, never root.
    const directories = [_][:0]const u8{
        constants.vm_disk_mount,
        constants.vm_disk_mount ++ "/data",
        constants.vm_disk_mount ++ "/state",
    };
    for (directories) |path| {
        _ = linux.mkdir(path, 0o755);
        if (failed(linux.chown(path, uid, gid))) return false;
    }
    return true;
}

// ---- The shared home and Rosetta ----------------------------------------------------------------

/// Mounts the Mac's home, shared under the tag `home`, over the directory of the same path.
pub fn mount_home(home: [:0]const u8) bool {
    assert(home.len > 1);
    assert(home[0] == '/');
    const mounted = linux.mount(constants.vm_home_tag, home, "virtiofs", 0, 0);
    if (failed(mounted)) log("zbx-init: cannot mount the shared home at ", home);
    return !failed(mounted);
}

/// What binfmt_misc is told to start an x86-64 ELF with: a 64-bit little-endian executable of
/// machine type 0x3e (EM_X86_64). The mask leaves out the ELF's OS ABI and the file type's low
/// byte, and `F` has the kernel open Rosetta once, so that it runs in any container's root.
pub const rosetta_rule =
    ":rosetta:M::" ++
    "\\x7fELF\\x02\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00" ++
    "\\x02\\x00\\x3e\\x00" ++
    ":" ++
    "\\xff\\xff\\xff\\xff\\xff\\xfe\\xfe\\x00" ++
    "\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xfe\\xff\\xff\\xff" ++
    ":" ++ constants.vm_rosetta_mount ++ "/rosetta:F\n";

/// Mounts Rosetta (when the Mac shares it) and registers it. False means there is no Rosetta in
/// this machine, which is not a failure: only linux/amd64 images need it.
pub fn mount_rosetta() bool {
    _ = linux.mkdir(constants.vm_rosetta_mount, 0o755);
    const tag = constants.vm_rosetta_tag;
    if (failed(linux.mount(tag, constants.vm_rosetta_mount, "virtiofs", 0, 0))) return false;
    const registry = "/proc/sys/fs/binfmt_misc";
    if (failed(linux.mount("binfmt_misc", registry, "binfmt_misc", 0, 0))) {
        log("zbx-init: cannot mount binfmt_misc", "");
        return false;
    }
    const opened = linux.open(registry ++ "/register", .{ .ACCMODE = .WRONLY }, 0);
    if (failed(opened)) return false;
    const descriptor: i32 = @intCast(opened);
    defer _ = linux.close(descriptor);
    const written = linux.write(descriptor, rosetta_rule.ptr, rosetta_rule.len);
    if (failed(written)) {
        log("zbx-init: binfmt_misc refused the Rosetta rule", "");
        return false;
    }
    return true;
}

// ---- Tests --------------------------------------------------------------------------------------

test "a disk is empty, ext or something else by its first sixty-four KiB" {
    // Goal: the one decision that decides whether a disk is formatted. Method: zeros, a
    // superblock magic, the magic's neighbours, and data after the superblock.
    var head: [probe_bytes]u8 = @splat(0);
    try std.testing.expectEqual(DiskState.empty, classify(&head));
    head[superblock_magic_offset] = 0x53;
    head[superblock_magic_offset + 1] = 0xEF;
    try std.testing.expectEqual(DiskState.ext, classify(&head));
    head[superblock_magic_offset + 1] = 0xEE;
    try std.testing.expectEqual(DiskState.other, classify(&head));
    head[superblock_magic_offset] = 0;
    head[superblock_magic_offset + 1] = 0;
    try std.testing.expectEqual(DiskState.empty, classify(&head));
    head[probe_bytes - 1] = 1;
    try std.testing.expectEqual(DiskState.other, classify(&head));
    head[probe_bytes - 1] = 0;
    head[0] = 0x45; // A GPT or boot sector starts with something.
    try std.testing.expectEqual(DiskState.other, classify(&head));
}

test "the file system's size is read from the superblock and growth is a MiB or more" {
    // Goal: the host grows the disk file and the guest must notice, but never on rounding.
    // Method: a 4 KiB-block, 64-bit superblock of 16777216 blocks (64 GiB), as mke2fs wrote it.
    var head: [probe_bytes]u8 = @splat(0);
    std.mem.writeInt(u16, head[superblock_magic_offset..][0..2], ext_magic, .little);
    std.mem.writeInt(u32, head[1024 + 4 ..][0..4], 16777216, .little);
    std.mem.writeInt(u32, head[1024 + 24 ..][0..4], 2, .little);
    try std.testing.expectEqual(@as(u64, 64 << 30), file_system_bytes(&head));
    std.mem.writeInt(u32, head[1024 + 0x60 ..][0..4], 0x80, .little);
    std.mem.writeInt(u32, head[1024 + 0x150 ..][0..4], 1, .little);
    try std.testing.expectEqual(@as(u64, (64 << 30) + (16 << 40)), file_system_bytes(&head));
    std.mem.writeInt(u32, head[1024 + 24 ..][0..4], 7, .little);
    try std.testing.expectEqual(@as(u64, 0), file_system_bytes(&head));
    try std.testing.expect(!needs_growth(64 << 30, 64 << 30));
    try std.testing.expect(!needs_growth(64 << 30, (64 << 30) + (1 << 20) - 1));
    try std.testing.expect(needs_growth(64 << 30, (64 << 30) + (1 << 20)));
    try std.testing.expect(!needs_growth(64 << 30, 32 << 30));
}

test "fsck exit codes: clean and repaired mount, everything else refuses" {
    // Goal: only 0 and 1 let the disk be mounted (e2fsck(8)). Method: every documented code.
    try std.testing.expect(fsck_accepts(0));
    try std.testing.expect(fsck_accepts(1));
    for ([_]u32{ 2, 4, 8, 12, 16, 32, 128, 255 }) |code| {
        try std.testing.expect(!fsck_accepts(code));
    }
}

test "the Rosetta rule has the kernel's six fields and the mask matches the magic's length" {
    // Goal: binfmt_misc reads `:name:type:offset:magic:mask:interpreter:flags`, and the magic
    // and mask must be the same length. Method: split on the colons and count the bytes of each
    // escaped string.
    var fields = std.mem.splitScalar(u8, std.mem.trimEnd(u8, rosetta_rule, "\n"), ':');
    try std.testing.expectEqualStrings("", fields.next().?);
    try std.testing.expectEqualStrings("rosetta", fields.next().?);
    try std.testing.expectEqualStrings("M", fields.next().?);
    try std.testing.expectEqualStrings("", fields.next().?); // The offset: the file's start.
    const magic = fields.next().?;
    const mask = fields.next().?;
    try std.testing.expectEqualStrings(constants.vm_rosetta_mount ++ "/rosetta", fields.next().?);
    try std.testing.expectEqualStrings("F", fields.next().?);
    try std.testing.expect(fields.next() == null);
    try std.testing.expectEqual(escaped_length(magic), escaped_length(mask));
    try std.testing.expectEqual(@as(usize, 20), escaped_length(mask));
}

/// The bytes a binfmt_misc string stands for: `\xNN` is one, any other character is one.
fn escaped_length(text: []const u8) usize {
    var count: usize = 0;
    var index: usize = 0;
    while (index < text.len) : (count += 1) {
        index += if (text[index] == '\\') 4 else 1;
    }
    return count;
}
