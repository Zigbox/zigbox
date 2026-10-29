//! A volume's lock: `flock` on `<state>/<name>/lock`, through the store's file-system interface
//! (`Fs.lock`, which creates the file, mode 0600, and takes the lock without waiting).
//!
//! A run that mounts a volume read-write holds it **exclusive** for its whole life; `:ro` holds
//! it **shared**, so any number of readers and no reader beside a writer. `zbx state rm` holds
//! it exclusive while it moves the volume to the trash. The lock is the kernel's, on an open
//! file description: it goes when the last descriptor of that description is closed, which the
//! kernel does for a process that dies however it dies. A lock file left behind by a crash is
//! therefore only a file, never a held lock, and needs no cleanup.
//!
//! An exclusive holder writes `<pid> <who>` into the file (`who` is the container's name, or
//! `zbx state rm`), cut to `store_lock_holder_bytes`; a shared holder writes nothing. The text
//! of an earlier exclusive holder stays after it is gone, so it is read only when the lock is
//! found held exclusive, and a refusal asks the run records for the full name (`holders.zig`).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const fs_mod = @import("../store/fs.zig");

const Fs = fs_mod.Fs;
const Host = host_mod.Host;

pub const Mode = enum { shared, exclusive };

/// `Busy`: held in a conflicting mode. `Failed`: the lock file cannot be opened; the errno is
/// the file system's `last_errno`.
pub const Error = error{ Busy, Failed };

/// What an exclusive holder writes: its pid and who it is, cut to the record's size.
pub const HolderText = struct {
    bytes: [constants.store_lock_holder_bytes]u8,
    len: u32,

    pub fn slice(text: *const HolderText) []const u8 {
        assert(text.len <= text.bytes.len);
        return text.bytes[0..text.len];
    }
};

pub fn holder_text(pid: u32, who: []const u8, out: *HolderText) void {
    assert(who.len > 0);
    // Cannot fail: a pid has at most ten digits, and the rest is cut to what is left.
    const head = std.fmt.bufPrint(&out.bytes, "{d} ", .{pid}) catch unreachable; // Same.
    const room = out.bytes.len - head.len;
    const kept = @min(room, who.len);
    @memcpy(out.bytes[head.len..][0..kept], who[0..kept]);
    out.len = @intCast(head.len + kept);
    assert(out.len <= constants.store_lock_holder_bytes);
}

/// Takes the lock, trying every `store_lock_retry_ms` for `wait_ms` (zero: one try).
pub fn take(
    host: Host,
    path: [:0]const u8,
    mode: Mode,
    holder: *const HolderText,
    wait_ms: u32,
) Error!fs_mod.Fd {
    assert(path.len > 0);
    assert(wait_ms <= constants.store_lock_wait_ms);
    const fs = host.filesystem();
    const exclusive = mode == .exclusive;
    const text = if (exclusive) holder.slice() else "";
    const attempts = wait_ms / constants.store_lock_retry_ms + 1;
    for (0..attempts) |attempt| {
        if (fs.lock(path, exclusive, text)) |fd| {
            return fd;
        } else |err| {
            if (err != error.WouldBlock) return error.Failed;
        }
        if (attempt + 1 < attempts) host.sleep_ms(constants.store_lock_retry_ms);
    }
    return error.Busy;
}

pub fn release(host: Host, fd: fs_mod.Fd) void {
    host.filesystem().close(fd);
}

/// Who holds a lock that `take` found busy.
pub const Holder = union(enum) {
    /// Held shared: containers read it (`holders.zig` names them from the run records).
    readers,
    /// Held exclusive, by the process and the `who` its record names.
    writer: struct { pid: u32, who: []const u8 },
    /// Held, and nothing more could be read.
    unknown,
};

/// Finds out how a busy lock is held, for a caller that wanted `wanted`. A caller that wanted
/// it shared was refused by a writer. One that wanted it exclusive tries it shared once without
/// waiting: if that works, the holders are readers (and the try is undone at once). Then the
/// text in the file is the writer's.
pub fn holder_of(
    host: Host,
    path: [:0]const u8,
    wanted: Mode,
    buffer: *[constants.store_lock_holder_bytes]u8,
) Holder {
    assert(path.len > 0);
    const fs = host.filesystem();
    if (wanted == .exclusive) {
        if (fs.lock(path, false, "")) |probe| {
            fs.close(probe);
            return .readers;
        } else |_| {}
    }
    const bytes = fs.read_whole(path, buffer) catch return .unknown;
    const text = std.mem.trimEnd(u8, bytes, "\x00 \n");
    const space = std.mem.indexOfScalar(u8, text, ' ') orelse return .unknown;
    const pid = std.fmt.parseInt(u32, text[0..space], 10) catch return .unknown;
    const who = text[space + 1 ..];
    if (pid == 0 or who.len == 0) return .unknown;
    return .{ .writer = .{ .pid = pid, .who = who } };
}

const testing = std.testing;
const HostSim = @import("../host_sim.zig").HostSim;
const SimFs = @import("../store/fs_sim.zig").SimFs;

var test_files: SimFs = undefined;

fn test_host(sim: *HostSim) Host {
    sim.init(1, &.{});
    test_files.init(1);
    test_files.put_dir("/v", 0o755);
    sim.store_fs = &test_files;
    return sim.interface();
}

test "one writer, many readers, and never both" {
    // Goal: the modes as the brief has them. Method: each pair, in the simulated flock.
    var sim: HostSim = undefined;
    const host = test_host(&sim);
    var text: HolderText = undefined;
    holder_text(4242, "pg", &text);
    const writer = try take(host, "/v/lock", .exclusive, &text, 0);
    try testing.expectError(error.Busy, take(host, "/v/lock", .exclusive, &text, 0));
    try testing.expectError(error.Busy, take(host, "/v/lock", .shared, &text, 0));
    var buffer: [constants.store_lock_holder_bytes]u8 = undefined;
    const held = holder_of(host, "/v/lock", .shared, &buffer);
    try testing.expectEqual(@as(u32, 4242), held.writer.pid);
    try testing.expectEqualStrings("pg", held.writer.who);
    release(host, writer);
    const first = try take(host, "/v/lock", .shared, &text, 0);
    const second = try take(host, "/v/lock", .shared, &text, 0);
    try testing.expectError(error.Busy, take(host, "/v/lock", .exclusive, &text, 0));
    // The writer's old text is still in the file, and must not be taken for a holder.
    try testing.expectEqual(Holder.readers, holder_of(host, "/v/lock", .exclusive, &buffer));
    release(host, first);
    release(host, second);
    const again = try take(host, "/v/lock", .exclusive, &text, 0);
    release(host, again);
    try testing.expectEqual(@as(u32, 0), test_files.open_count());
}

test "a crash frees the lock, and the file it leaves is no lock" {
    // Goal: SIGKILL of a holder. Method: the simulated machine restarts (every descriptor gone),
    // and the file is still there with the dead holder's text.
    var sim: HostSim = undefined;
    const host = test_host(&sim);
    var text: HolderText = undefined;
    holder_text(7, "web-1", &text);
    _ = try take(host, "/v/lock", .exclusive, &text, 0);
    test_files.restart();
    try testing.expect(test_files.kind_of("/v/lock") != null);
    const fd = try take(host, "/v/lock", .exclusive, &text, 0);
    release(host, fd);
}

test "the wait is bounded, and a missing directory is a failure, not busy" {
    // Goal: a busy lock is waited for `wait_ms` on the simulated clock and no longer. Method:
    // a holder that never lets go.
    var sim: HostSim = undefined;
    const host = test_host(&sim);
    var text: HolderText = undefined;
    holder_text(1, "a", &text);
    const fd = try take(host, "/v/lock", .exclusive, &text, 0);
    const before = sim.world.now_ms;
    try testing.expectError(error.Busy, take(host, "/v/lock", .exclusive, &text, 500));
    try testing.expectEqual(before + 500, sim.world.now_ms);
    release(host, fd);
    try testing.expectError(error.Failed, take(host, "/nowhere/lock", .shared, &text, 0));
}

test "the holder's text is cut to the record, and a long name keeps its start" {
    // Goal: the bound of the text. Method: a 63-byte name after a ten-digit pid.
    var text: HolderText = undefined;
    const name = @import("../test_util.zig").repeat('a', constants.container_name_bytes_max);
    holder_text(4294967295, name, &text);
    try testing.expectEqual(constants.store_lock_holder_bytes, text.len);
    try testing.expect(std.mem.startsWith(u8, text.slice(), "4294967295 aaa"));
}
