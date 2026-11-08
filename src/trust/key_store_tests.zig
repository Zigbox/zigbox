//! Tests of where keys are written and read (M8 slice 1): the temporary file of a new key is
//! its writer's alone, the secret file is refused when others can read it, and the keys
//! directory must be a real private directory. Two real processes race at the end, because the
//! simulator cannot pause one writer in the middle of its steps.

const std = @import("std");
const linux = std.os.linux;
const constants = @import("../constants.zig");
const host_real = @import("../host_real.zig");
const fs_mod = @import("../store/fs.zig");
const fs_sim = @import("../store/fs_sim.zig");
const key = @import("key.zig");
const store = @import("key_store.zig");

const testing = std.testing;

const directory = "/home/alice/.config/zbx/keys";
var files: fs_sim.SimFs = undefined;

fn start() store.Paths {
    files.init(1);
    files.put_dir("/home", 0o755);
    files.put_dir("/home/alice", 0o755);
    files.put_dir("/home/alice/.config", 0o755);
    files.put_dir("/home/alice/.config/zbx", 0o700);
    files.put_dir(directory, 0o700);
    return paths_at(directory);
}

fn paths_at(dir: []const u8) store.Paths {
    var paths: store.Paths = undefined;
    paths.dir.set(&.{dir}) catch unreachable; // A short test path.
    paths.base_len = 1;
    return paths;
}

fn record_of(byte: u8) key.Record {
    const seed: [constants.key_seed_bytes]u8 = @splat(byte);
    return .{ .public = key.public_of_seed(seed), .body = .{ .none = seed } };
}

fn unique_of(byte: u8) store.Unique {
    return @splat(byte);
}

fn secret_buffer() [constants.key_file_bytes_max + 1]u8 {
    return @splat(0xAA); // Known bytes, so that a short read shows.
}

test "a leftover temporary of another run is never removed, and a name is made beside it" {
    // Goal: a run touches only the temporary file it created. Method: another run's temporary
    // (a different random part) sits in the directory; a new key is made; the leftover is
    // untouched and the key is complete. The same random part twice cannot create twice.
    const paths = start();
    const fs = files.interface();
    const other = directory ++ "/.k.key.0101010101010101.tmp";
    files.put_file(other, 0o600, "another run's secret");
    var failure: store.Failure = undefined;
    try store.create(fs, &paths, "k", &record_of(7), &unique_of(2), &failure);
    try testing.expectEqualStrings("another run's secret", files.content_of(other).?);
    try testing.expect(files.kind_of(directory ++ "/k.key") != null);
    try testing.expect(files.kind_of(directory ++ "/k.pub") != null);
    try testing.expect(files.kind_of(directory ++ "/.k.key.0202020202020202.tmp") == null);
    try testing.expect(files.kind_of(directory ++ "/.k.pub.0202020202020202.tmp") == null);
    const again = store.create(fs, &paths, "k", &record_of(8), &unique_of(3), &failure);
    try testing.expectError(error.Failed, again);
    try testing.expectEqual(store.Problem.exists, failure.problem);
}

test "a temporary name that is taken is an error, not a file to remove" {
    // Goal: no unlink of a path this run did not create. Method: the exact temporary name is
    // there already (the astronomically unlikely clash); create refuses and leaves it.
    const paths = start();
    const fs = files.interface();
    files.put_file(directory ++ "/.k.key.0505050505050505.tmp", 0o600, "theirs");
    var failure: store.Failure = undefined;
    const result = store.create(fs, &paths, "k", &record_of(7), &unique_of(5), &failure);
    try testing.expectError(error.Failed, result);
    const theirs = directory ++ "/.k.key.0505050505050505.tmp";
    try testing.expectEqualStrings("theirs", files.content_of(theirs).?);
    try testing.expect(files.kind_of(directory ++ "/k.key") == null);
}

test "read_secret opens a private file and refuses one others can read" {
    // Goal: the rule that a secret others can read is refused, which nothing else exercises in
    // slice 1. Method: 0600 opens; 0640, 0644 and 0604 give secret_too_open; the check is on
    // the file itself.
    const paths = start();
    const fs = files.interface();
    var failure: store.Failure = undefined;
    try store.create(fs, &paths, "k", &record_of(7), &unique_of(1), &failure);
    var buffer = secret_buffer();
    const record = try store.read_secret(fs, &paths, "k", &buffer, &failure);
    try testing.expectEqualSlices(u8, &record_of(7).public, &record.public);
    for ([_]u16{ 0o640, 0o644, 0o604, 0o660, 0o666 }) |mode| {
        files.set_mode_of(directory ++ "/k.key", mode);
        buffer = secret_buffer();
        const result = store.read_secret(fs, &paths, "k", &buffer, &failure);
        try testing.expectError(error.Failed, result);
        try testing.expectEqual(store.Problem.secret_too_open, failure.problem);
    }
}

test "read_secret refuses a symbolic link, a file too big, and a loose or linked directory" {
    // Goal: the other refusals of read_secret. Method: a link in place of the file, a 1025-byte
    // file, a 0755 directory, and the directory replaced by a link to a private one.
    const paths = start();
    const fs = files.interface();
    var failure: store.Failure = undefined;
    var buffer = secret_buffer();
    files.put_symlink(directory ++ "/l.key", "/home/alice/real");
    try testing.expectError(error.Failed, store.read_secret(fs, &paths, "l", &buffer, &failure));
    try testing.expectEqual(store.Problem.unreadable, failure.problem);
    const big: [constants.key_file_bytes_max + 1]u8 = @splat('x');
    files.put_file(directory ++ "/big.key", 0o600, &big);
    buffer = secret_buffer();
    try testing.expectError(error.Failed, store.read_secret(fs, &paths, "big", &buffer, &failure));
    try testing.expectEqual(store.Problem.malformed, failure.problem);
    files.put_file(directory ++ "/ok.key", 0o600, "{}");
    buffer = secret_buffer();
    try testing.expectError(error.Failed, store.read_secret(fs, &paths, "ok", &buffer, &failure));
    try testing.expectEqual(store.Problem.malformed, failure.problem);
    files.set_mode_of(directory, 0o755);
    try testing.expectError(error.Failed, store.read_secret(fs, &paths, "ok", &buffer, &failure));
    try testing.expectEqual(store.Problem.dir_too_open, failure.problem);
    files.set_mode_of(directory, 0o700);
    files.put_dir("/home/alice/private", 0o700);
    files.remove_path(directory);
    files.put_symlink(directory, "/home/alice/private");
    try testing.expectError(error.Failed, store.read_secret(fs, &paths, "ok", &buffer, &failure));
    try testing.expectEqual(store.Problem.dir_not_real, failure.problem);
    try testing.expectError(error.Failed, store.ensure_dir(fs, &paths, &failure));
    try testing.expectEqual(store.Problem.dir_not_real, failure.problem);
}

// ---- Two processes on a real kernel -------------------------------------------------------

fn raw_ok(result: usize) bool {
    return linux.errno(result) == .SUCCESS;
}

/// The child: wait for the go byte, make the key `k` with a secret of its own, and exit with 0
/// when it won, 1 when the name was taken, 2 for anything else.
fn racer(
    subject: @import("../host.zig").Host,
    paths: *const store.Paths,
    go: [2]i32,
    byte: u8,
) noreturn {
    _ = linux.close(go[1]);
    var wait: [1]u8 = undefined;
    _ = linux.read(go[0], &wait, 1); // Returns at the parent's close.
    var seed: [constants.key_seed_bytes]u8 = @splat(byte);
    subject.random_bytes(seed[0..8]) catch linux.exit_group(2);
    var unique: store.Unique = undefined;
    subject.random_bytes(&unique) catch linux.exit_group(2);
    const record: key.Record = .{ .public = key.public_of_seed(seed), .body = .{ .none = seed } };
    var failure: store.Failure = undefined;
    store.create(subject.filesystem(), paths, "k", &record, &unique, &failure) catch {
        linux.exit_group(if (failure.problem == .exists) 1 else 2);
    };
    linux.exit_group(0);
}

fn wait_for(pid: usize) !u8 {
    var status: u32 = 0;
    try testing.expectEqual(pid, linux.waitpid(@intCast(pid), @ptrCast(&status), 0));
    try testing.expect(linux.W.IFEXITED(status));
    return linux.W.EXITSTATUS(status);
}

test "two real processes making one key: one wins, and its halves match" {
    // Goal: the race the review found. Method: two processes released together make the key
    // `k` in a fresh directory, many times; each round exactly one wins, the other is told the
    // name is taken, and the public key derived from the winner's .key equals its .pub.
    var real: host_real.HostReal = .{};
    const subject = real.interface();
    const fs = subject.filesystem();
    // A directory this test owns (removed with it), not a fixed path under /tmp.
    var scratch = testing.tmpDir(.{});
    defer scratch.cleanup();
    var root_storage: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try scratch.dir.realPath(testing.io, &root_storage);
    const root = root_storage[0..root_len];
    var paths: store.Paths = undefined;
    try paths.dir.set(&.{ root, "/keys" });
    paths.base_len = @intCast(root.len);
    try fs.make_directory(paths.dir.text(), true);
    const dir_fd = try fs.open_directory(paths.dir.text());
    try fs.set_mode(dir_fd, 0o700);
    fs.close(dir_fd);
    for (0..rounds) |_| try race_round(subject, &paths);
}

const rounds = 150;

fn race_round(subject: @import("../host.zig").Host, paths: *const store.Paths) !void {
    const fs = subject.filesystem();
    var go: [2]i32 = undefined;
    try testing.expect(raw_ok(linux.pipe2(&go, .{ .CLOEXEC = true })));
    var pids: [2]usize = undefined;
    for (&pids, 0..) |*pid, index| {
        pid.* = linux.fork();
        try testing.expect(raw_ok(pid.*));
        if (pid.* == 0) racer(subject, paths, go, @intCast(index + 1));
    }
    _ = linux.close(go[0]);
    _ = linux.close(go[1]); // Both children read the end of file and start.
    const first = try wait_for(pids[0]);
    const second = try wait_for(pids[1]);
    defer cleanup(fs, paths);
    const winners = @intFromBool(first == 0) + @as(u8, @intFromBool(second == 0));
    try testing.expectEqual(@as(u8, 1), winners);
    try testing.expect(first <= 1 and second <= 1);
    var buffer = secret_buffer();
    defer std.crypto.secureZero(u8, &buffer);
    var failure: store.Failure = undefined;
    const secret = try store.read_secret(fs, paths, "k", &buffer, &failure);
    const public = try store.read_pub(fs, paths, "k", &failure);
    try testing.expectEqualSlices(u8, &public.public, &secret.public);
    try testing.expectEqualSlices(u8, &key.public_of_seed(secret.body.none), &secret.public);
}

/// Removes what a round made, the keys and any temporary a loser left, so that the next round
/// starts empty.
fn cleanup(fs: fs_mod.Fs, paths: *const store.Paths) void {
    const Remover = struct {
        fs: fs_mod.Fs,
        dir: []const u8,
        fn visit(context: *anyopaque, entry: []const u8) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            var path: fs_mod.PathBuf = undefined;
            path.set(&.{ self.dir, "/", entry }) catch return;
            self.fs.unlink(path.text()) catch {};
        }
    };
    var remover: Remover = .{ .fs = fs, .dir = paths.dir.text() };
    // Collect first, then remove: the listing is not to change under the walk.
    var names: [16][64]u8 = undefined;
    var lengths: [16]u8 = @splat(0);
    var collector: Collector = .{ .names = &names, .lengths = &lengths, .count = 0 };
    fs.read_dir(paths.dir.text(), .{ .context = &collector, .call = Collector.visit }) catch return;
    for (0..collector.count) |index| Remover.visit(&remover, names[index][0..lengths[index]]);
}

const Collector = struct {
    names: *[16][64]u8,
    lengths: *[16]u8,
    count: u32,

    fn visit(context: *anyopaque, entry: []const u8) void {
        const self: *Collector = @ptrCast(@alignCast(context));
        if (self.count == 16 or entry.len > 64) return;
        @memcpy(self.names[self.count][0..entry.len], entry);
        self.lengths[self.count] = @intCast(entry.len);
        self.count += 1;
    }
};
