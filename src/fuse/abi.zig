//! The kernel's FUSE protocol (`include/uapi/linux/fuse.h`), the parts the read-only lazy server
//! uses, written in Zig without libc. Every struct is `extern` with its size asserted at comptime
//! against the header, so a field out of place fails the build instead of a mount.
//!
//! The server speaks protocol 7.31 (`minor_version`): `FUSE_MAX_PAGES` (7.28) lets one `READ`
//! carry a whole 1 MiB chunk, and nothing newer is needed. The kernel answers with the smaller of
//! its minor and ours, and from 7.23 on every struct below has its full size, so no compat sizes
//! are handled. The in-header's `total_extlen` (7.38) stays zero because the server asks for no
//! extension (`FUSE_SECURITY_CTX`, `FUSE_CREATE_SUPP_GROUP`); a request carrying one is refused.

const std = @import("std");
const assert = std.debug.assert;

pub const major_version: u32 = 7;
pub const minor_version: u32 = 31;
/// The node id of the mount's root directory.
pub const root_id: u64 = 1;
/// The longest name the kernel sends (`FUSE_NAME_MAX`).
pub const name_bytes_max: u32 = 1024;
/// The smallest read buffer the kernel accepts on `/dev/fuse` (`FUSE_MIN_READ_BUFFER`).
pub const read_buffer_bytes_min: u32 = 8192;

pub const Opcode = enum(u32) {
    lookup = 1,
    forget = 2,
    getattr = 3,
    setattr = 4,
    readlink = 5,
    symlink = 6,
    mknod = 8,
    mkdir = 9,
    unlink = 10,
    rmdir = 11,
    rename = 12,
    link = 13,
    open = 14,
    read = 15,
    write = 16,
    statfs = 17,
    release = 18,
    fsync = 20,
    setxattr = 21,
    getxattr = 22,
    listxattr = 23,
    removexattr = 24,
    flush = 25,
    init = 26,
    opendir = 27,
    readdir = 28,
    releasedir = 29,
    fsyncdir = 30,
    getlk = 31,
    setlk = 32,
    setlkw = 33,
    access = 34,
    create = 35,
    interrupt = 36,
    bmap = 37,
    destroy = 38,
    ioctl = 39,
    poll = 40,
    notify_reply = 41,
    batch_forget = 42,
    fallocate = 43,
    readdirplus = 44,
    rename2 = 45,
    lseek = 46,
    copy_file_range = 47,
    setupmapping = 48,
    removemapping = 49,
    syncfs = 50,
    tmpfile = 51,
    statx = 52,
    _,
};

/// `fuse_init_in.flags` and `fuse_init_out.flags`: the ones the server asks for.
pub const init_async_read: u32 = 1 << 0;
pub const init_do_readdirplus: u32 = 1 << 13;
pub const init_parallel_dirops: u32 = 1 << 18;
pub const init_max_pages: u32 = 1 << 22;
pub const init_cache_symlinks: u32 = 1 << 23;
pub const init_ext: u32 = 1 << 30;

/// `fuse_open_out.open_flags`.
pub const open_keep_cache: u32 = 1 << 1;
pub const open_cache_dir: u32 = 1 << 3;

pub const InHeader = extern struct {
    len: u32,
    opcode: u32,
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    total_extlen: u16,
    padding: u16,
};

pub const OutHeader = extern struct {
    len: u32,
    /// Zero, or a negated errno.
    @"error": i32,
    unique: u64,
};

pub const Attr = extern struct {
    ino: u64,
    size: u64,
    blocks: u64,
    atime: u64,
    mtime: u64,
    ctime: u64,
    atimensec: u32,
    mtimensec: u32,
    ctimensec: u32,
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u32,
    blksize: u32,
    flags: u32,
};

pub const EntryOut = extern struct {
    nodeid: u64,
    generation: u64,
    entry_valid: u64,
    attr_valid: u64,
    entry_valid_nsec: u32,
    attr_valid_nsec: u32,
    attr: Attr,
};

pub const ForgetIn = extern struct {
    nlookup: u64,
};

pub const ForgetOne = extern struct {
    nodeid: u64,
    nlookup: u64,
};

pub const BatchForgetIn = extern struct {
    count: u32,
    dummy: u32,
};

pub const GetattrIn = extern struct {
    getattr_flags: u32,
    dummy: u32,
    fh: u64,
};

pub const AttrOut = extern struct {
    attr_valid: u64,
    attr_valid_nsec: u32,
    dummy: u32,
    attr: Attr,
};

pub const OpenIn = extern struct {
    flags: u32,
    open_flags: u32,
};

pub const OpenOut = extern struct {
    fh: u64,
    open_flags: u32,
    padding: u32,
};

pub const ReleaseIn = extern struct {
    fh: u64,
    flags: u32,
    release_flags: u32,
    lock_owner: u64,
};

pub const ReadIn = extern struct {
    fh: u64,
    offset: u64,
    size: u32,
    read_flags: u32,
    lock_owner: u64,
    flags: u32,
    padding: u32,
};

pub const Kstatfs = extern struct {
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    bsize: u32,
    namelen: u32,
    frsize: u32,
    padding: u32,
    spare: [6]u32,
};

pub const StatfsOut = extern struct {
    st: Kstatfs,
};

pub const GetxattrIn = extern struct {
    size: u32,
    padding: u32,
};

pub const GetxattrOut = extern struct {
    size: u32,
    padding: u32,
};

/// The first 16 bytes are all a kernel before 7.36 sends; `flags2` and the rest come after.
pub const InitIn = extern struct {
    major: u32,
    minor: u32,
    max_readahead: u32,
    flags: u32,
};

pub const InitOut = extern struct {
    major: u32,
    minor: u32,
    max_readahead: u32,
    flags: u32,
    max_background: u16,
    congestion_threshold: u16,
    max_write: u32,
    time_gran: u32,
    max_pages: u16,
    map_alignment: u16,
    flags2: u32,
    unused: [7]u32,
};

pub const InterruptIn = extern struct {
    unique: u64,
};

pub const Dirent = extern struct {
    ino: u64,
    off: u64,
    namelen: u32,
    type: u32,
};

pub const Direntplus = extern struct {
    entry_out: EntryOut,
    dirent: Dirent,
};

/// `FUSE_DIRENT_ALIGN`: every directory record is padded to 8 bytes.
pub fn dirent_align(length: u32) u32 {
    assert(length > 0);
    assert(length <= read_buffer_bytes_min + name_bytes_max);
    return std.mem.alignForward(u32, length, 8);
}

/// The size of one `fuse_direntplus` record with a name of `name_len` bytes.
pub fn direntplus_bytes(name_len: u32) u32 {
    assert(name_len > 0);
    assert(name_len <= name_bytes_max);
    return dirent_align(@sizeOf(Direntplus) + name_len);
}

/// The errors the server answers with, as Linux numbers them (the same on both release
/// targets); a reply carries one negated.
pub const Errno = enum(i32) {
    noent = 2,
    io = 5,
    notdir = 20,
    isdir = 21,
    inval = 22,
    rofs = 30,
    range = 34,
    nosys = 38,
    nodata = 61,
    proto = 71,
};

/// The `d_type` values (`DT_*`) a directory record carries in `fuse_dirent.type`.
pub const dt_dir: u32 = 4;
pub const dt_reg: u32 = 8;
pub const dt_lnk: u32 = 10;

comptime {
    // Sizes from `fuse.h` (7.39), checked so that a field out of place fails the build.
    assert(@sizeOf(InHeader) == 40);
    assert(@sizeOf(OutHeader) == 16);
    assert(@sizeOf(Attr) == 88);
    assert(@sizeOf(EntryOut) == 128);
    assert(@sizeOf(ForgetIn) == 8);
    assert(@sizeOf(ForgetOne) == 16);
    assert(@sizeOf(BatchForgetIn) == 8);
    assert(@sizeOf(GetattrIn) == 16);
    assert(@sizeOf(AttrOut) == 104);
    assert(@sizeOf(OpenIn) == 8);
    assert(@sizeOf(OpenOut) == 16);
    assert(@sizeOf(ReleaseIn) == 24);
    assert(@sizeOf(ReadIn) == 40);
    assert(@sizeOf(Kstatfs) == 80);
    assert(@sizeOf(StatfsOut) == 80);
    assert(@sizeOf(GetxattrIn) == 8);
    assert(@sizeOf(GetxattrOut) == 8);
    assert(@sizeOf(InitIn) == 16);
    assert(@sizeOf(InitOut) == 64);
    assert(@sizeOf(InterruptIn) == 8);
    assert(@sizeOf(Dirent) == 24);
    assert(@sizeOf(Direntplus) == 152);
    assert(@offsetOf(Direntplus, "dirent") == 128);
    assert(@offsetOf(Attr, "mode") == 60);
    assert(@offsetOf(InitOut, "max_pages") == 28);
    assert(@offsetOf(InitOut, "flags2") == 32);
    assert(@offsetOf(Attr, "flags") == 84);
    // A little-endian layout is what both release targets have; the structs are copied as bytes.
    assert(@import("builtin").cpu.arch.endian() == .little);
}

test "a direntplus record is padded to eight bytes" {
    // Goal: the record sizes match FUSE_DIRENTPLUS_SIZE. Method: compute it for names of the
    // lengths at each side of a boundary and compare with the header's formula by hand.
    try std.testing.expectEqual(@as(u32, 160), direntplus_bytes(1));
    try std.testing.expectEqual(@as(u32, 160), direntplus_bytes(8));
    try std.testing.expectEqual(@as(u32, 168), direntplus_bytes(9));
    try std.testing.expectEqual(@as(u32, 152 + 256), direntplus_bytes(255));
}
