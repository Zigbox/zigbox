//! The FUSE kernel ABI (`include/uapi/linux/fuse.h`) that S2's slice 1 probe needs, written in
//! Zig with comptime size checks against the header's sizes. Throwaway: slice 4 writes the real
//! ABI file for `zbx`; this one holds only what the probe's read-only server answers.

const std = @import("std");
const assert = std.debug.assert;

/// The protocol the probe speaks: 7.31, the brief's floor. `FUSE_MAX_PAGES`, which 1 MiB READs
/// need, came in 7.28; 7.31 added `map_alignment` for DAX, which the probe does not use.
pub const kernel_version_major: u32 = 7;
pub const kernel_minor_version_min: u32 = 31;

pub const Opcode = enum(u32) {
    lookup = 1,
    forget = 2,
    getattr = 3,
    readlink = 5,
    open = 14,
    read = 15,
    statfs = 17,
    release = 18,
    getxattr = 22,
    listxattr = 23,
    flush = 25,
    init = 26,
    opendir = 27,
    releasedir = 29,
    access = 34,
    interrupt = 36,
    destroy = 38,
    batch_forget = 42,
    readdirplus = 44,
    _,
};

pub const init_async_read: u32 = 1 << 0;
pub const init_do_readdirplus: u32 = 1 << 13;
pub const init_parallel_dirops: u32 = 1 << 18;
pub const init_max_pages: u32 = 1 << 22;

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
    @"error": i32,
    unique: u64,
};

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

pub const AttrOut = extern struct {
    attr_valid: u64,
    attr_valid_nsec: u32,
    dummy: u32,
    attr: Attr,
};

pub const OpenOut = extern struct {
    fh: u64,
    open_flags: u32,
    padding: u32,
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

pub const GetxattrIn = extern struct {
    size: u32,
    padding: u32,
};

pub const GetxattrOut = extern struct {
    size: u32,
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

/// The fixed part of `struct fuse_dirent`; the name follows, padded to 8 bytes.
pub const Dirent = extern struct {
    ino: u64,
    off: u64,
    namelen: u32,
    type: u32,
};

comptime {
    // The sizes `linux/fuse.h` gives each struct; a wrong field would shift every reply.
    assert(@sizeOf(InHeader) == 40);
    assert(@sizeOf(OutHeader) == 16);
    assert(@sizeOf(InitIn) == 16);
    assert(@sizeOf(InitOut) == 64);
    assert(@sizeOf(Attr) == 88);
    assert(@sizeOf(EntryOut) == 128);
    assert(@sizeOf(AttrOut) == 104);
    assert(@sizeOf(OpenOut) == 16);
    assert(@sizeOf(ReadIn) == 40);
    assert(@sizeOf(Kstatfs) == 80);
    assert(@sizeOf(Dirent) == 24);
    assert(@sizeOf(GetxattrOut) == 8);
}

/// The bytes a `fuse_direntplus` with a name of `name_len` takes, padded as the kernel reads it.
pub fn direntplus_size(name_len: usize) usize {
    assert(name_len > 0);
    assert(name_len <= 255);
    const unpadded = @sizeOf(EntryOut) + @sizeOf(Dirent) + name_len;
    const size = std.mem.alignForward(usize, unpadded, 8);
    assert(size % 8 == 0);
    return size;
}

test "direntplus sizes are padded to 8 bytes" {
    // Goal: an entry's name is padded so the next entry starts on 8 bytes, as FUSE_DIRENT_ALIGN.
    try std.testing.expectEqual(@as(usize, 160), direntplus_size(1));
    try std.testing.expectEqual(@as(usize, 160), direntplus_size(8));
    try std.testing.expectEqual(@as(usize, 168), direntplus_size(9));
}
