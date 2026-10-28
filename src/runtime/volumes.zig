//! A run's state volumes, on the parent's side: each is made if it is new, its lock taken
//! (exclusive, or shared for `:ro`) before the container is created, and its record noted with
//! this container; the locks are let go when the run ends (`release`), on every path.
//!
//! **Who holds the locks.** The process that calls `start` and `wait`: `zbx run` in the
//! foreground, the supervisor of a detached run (`run -d` forks it before `start`, so the caller
//! never holds one), or Zigcube's agent's supervisor. A lock is the kernel's, on an open file
//! description opened with `O_CLOEXEC`: the container's child inherits the descriptor through
//! `clone3` and closes it at `execve`, the keeper closes every descriptor it does not need, and
//! pasta's `execve` closes it too, so the holder is that one process. When it ends, whatever
//! ends it (SIGKILL included), the kernel closes the descriptor and the lock is free; the
//! container dies with it (`die_with_parent`), so a volume never has a writer the lock does not
//! know of. `wait` lets go after the container is reaped (a clean exit, `zbx stop`, `--timeout`,
//! a killed container); a start that fails lets go before it returns.
//!
//! The volume's directory and lock file are the user's (made here, in the parent); its `data`
//! directory is made by the container's root in the container's user namespace (a plan step,
//! `make_state_data`), so that what the container `chown`s inside it is owned through the map.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const Diag = @import("../diag/diag.zig").Diag;
const fs_mod = @import("../store/fs.zig");
const records = @import("records.zig");
const plan_mod = @import("plan.zig");
const volume = @import("../state/volume.zig");
const record_mod = @import("../state/record.zig");
const lock = @import("../state/lock.zig");
const holders = @import("../state/holders.zig");
const diagnose = @import("../state/diagnose.zig");

const Host = host_mod.Host;

pub const Error = error{StartFailed};

/// The volumes a run holds. The mounts point into the caller's `Spec`, which outlives the run.
pub const Held = struct {
    count: u32,
    mounts: [constants.state_volumes_max]volume.Mount,
    fds: [constants.state_volumes_max]fs_mod.Fd,
    data: [constants.state_volumes_max]volume.Path,
    inputs: [constants.state_volumes_max]plan_mod.StateInput,
    /// Room to read one run record while a refusal looks for the holder, and the record of a
    /// volume while it is noted.
    scratch: records.Parsed,
    found: holders.Found,

    pub fn mount_slice(held: *const Held) []const volume.Mount {
        assert(held.count <= constants.state_volumes_max);
        return held.mounts[0..held.count];
    }

    pub fn input_slice(held: *const Held) []const plan_mod.StateInput {
        assert(held.count <= constants.state_volumes_max);
        return held.inputs[0..held.count];
    }
};

/// Takes every volume of `mounts` for the container `name`, in order; on a failure, what was
/// taken is let go and `diag` says why.
pub fn take(
    host: Host,
    mounts: []const volume.Mount,
    name: []const u8,
    held: *Held,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    held.count = 0;
    if (mounts.len == 0) return;
    try check(mounts, diag);
    var root: volume.Root = undefined;
    if (!root.locate(host)) {
        diagnose.directory_failed(diag, null);
        return error.StartFailed;
    }
    errdefer release(host, held);
    for (mounts) |*mount| {
        const index = held.count;
        held.mounts[index] = mount.*;
        held.fds[index] = try take_one(host, &root, mount, name, held, diag);
        held.count += 1;
        root.volume(&held.data[index], mount.name, volume.data_name);
        held.inputs[index] = .{
            .name = mount.name,
            .data = held.data[index].text(),
            .target = mount.target,
            .read_only = mount.read_only,
        };
    }
    assert(held.count == mounts.len);
}

/// Lets go of every lock `take` took. Called once a run is over, on every path.
pub fn release(host: Host, held: *Held) void {
    assert(held.count <= constants.state_volumes_max);
    for (held.fds[0..held.count]) |fd| lock.release(host, fd);
    held.count = 0;
}

/// A library caller's list, held to the rules the command line applies (`volume.zig`).
fn check(mounts: []const volume.Mount, diag: *Diag) Error!void {
    for (mounts) |mount| {
        if (volume.name_problem(mount.name)) |problem| {
            diagnose.bad_name(diag, mount.name, problem);
            return error.StartFailed;
        }
        if (volume.target_problem(mount.target)) |problem| {
            diagnose.bad_value(diag, mount.target, problem.sentence());
            return error.StartFailed;
        }
    }
    if (volume.list_problem(mounts)) |problem| {
        const at = switch (problem) {
            .too_many => constants.state_volumes_max,
            .same_name => |index| index,
            .same_target => |index| index,
        };
        diagnose.bad_value(diag, mounts[at].name, diagnose.list_sentence(problem));
        return error.StartFailed;
    }
}

/// The volume's directory made if new, its lock taken, its record noted. The lock's descriptor.
fn take_one(
    host: Host,
    root: *const volume.Root,
    mount: *const volume.Mount,
    name: []const u8,
    held: *Held,
    diag: *Diag,
) Error!fs_mod.Fd {
    try make_directories(host, root, mount.name, diag);
    var path: volume.Path = undefined;
    root.volume(&path, mount.name, volume.lock_name);
    var text: lock.HolderText = undefined;
    lock.holder_text(host.own_pid(), name, &text);
    const mode: lock.Mode = if (mount.read_only) .shared else .exclusive;
    const fd = lock.take(host, path.text(), mode, &text, constants.state_lock_wait_ms) catch |err| {
        switch (err) {
            error.Busy => refuse_busy(host, path.text(), mount, held, diag),
            error.Failed => directory_failure(host, diag, "locking", path.text()),
        }
        return error.StartFailed;
    };
    errdefer lock.release(host, fd);
    try note_use(host, root, mount, name, diag);
    return fd;
}

/// The state directory and the volume's own, each made if missing, from the first part that
/// must already exist (HOME or XDG_DATA_HOME).
fn make_directories(
    host: Host,
    root: *const volume.Root,
    name: []const u8,
    diag: *Diag,
) Error!void {
    const fs = host.filesystem();
    var path: volume.Path = undefined;
    root.volume(&path, name, null);
    const full = path.text();
    var at: usize = root.existing_len + 1;
    while (at <= full.len) : (at += 1) {
        if (at < full.len and full[at] != '/') continue;
        var prefix: volume.Path = undefined;
        @memcpy(prefix.bytes[0..at], full[0..at]);
        prefix.bytes[at] = 0;
        prefix.len = @intCast(at);
        fs.make_directory(prefix.text(), true) catch {
            directory_failure(host, diag, "making the directory", prefix.text());
            return error.StartFailed;
        };
    }
}

fn directory_failure(host: Host, diag: *Diag, operation: []const u8, path: []const u8) void {
    const fs = host.filesystem();
    diagnose.directory_failed(diag, .{
        .operation = operation,
        .path = path,
        .err = host_mod.error_for_errno(fs.last_errno()),
        .errno = fs.last_errno(),
    });
}

fn refuse_busy(
    host: Host,
    path: [:0]const u8,
    mount: *const volume.Mount,
    held: *Held,
    diag: *Diag,
) void {
    var buffer: [constants.store_lock_holder_bytes]u8 = undefined;
    const wanted: lock.Mode = if (mount.read_only) .shared else .exclusive;
    const holder = lock.holder_of(host, path, wanted, &buffer);
    holders.find(host, mount.name, &held.scratch, &held.found);
    var named: diagnose.Holders = undefined;
    holders.describe(holder, &held.found, &named);
    diagnose.in_use(diag, mount.name, mount.read_only, &named);
}

/// Reads the volume's record (a new one for a new volume), notes this container, writes it.
fn note_use(
    host: Host,
    root: *const volume.Root,
    mount: *const volume.Mount,
    name: []const u8,
    diag: *Diag,
) Error!void {
    const fs = host.filesystem();
    var path: volume.Path = undefined;
    root.volume(&path, mount.name, volume.record_name);
    const now = @min(host.time_now(), constants.state_time_max - 1);
    var record: record_mod.Record = undefined;
    var buffer: [constants.state_record_bytes_max]u8 = undefined;
    if (fs.read_whole(path.text(), &buffer)) |text| {
        record_mod.parse(text, &record) catch |err| {
            diagnose.record_unreadable(diag, path.text(), err == error.Newer);
            return error.StartFailed;
        };
        if (!std.mem.eql(u8, record.name_slice(), mount.name)) {
            diagnose.record_unreadable(diag, path.text(), false);
            return error.StartFailed;
        }
    } else |err| {
        if (err == error.FileTooLarge) {
            diagnose.record_unreadable(diag, path.text(), false);
            return error.StartFailed;
        }
        if (err != error.NotFound) {
            directory_failure(host, diag, "reading", path.text());
            return error.StartFailed;
        }
        record.init(mount.name, now);
    }
    record.use(name, mount, now);
    try write_record(host, root, mount.name, &record, diag);
}

fn write_record(
    host: Host,
    root: *const volume.Root,
    name: []const u8,
    record: *const record_mod.Record,
    diag: *Diag,
) Error!void {
    const fs = host.filesystem();
    var buffer: [constants.state_record_bytes_max]u8 = undefined;
    const text = record_mod.render(record, &buffer);
    var final: volume.Path = undefined;
    root.volume(&final, name, volume.record_name);
    var directory: volume.Path = undefined;
    root.volume(&directory, name, null);
    var temporary: volume.Path = undefined;
    var leaf: [32]u8 = undefined;
    // Cannot fail: "state.zon." and a pid of at most ten digits fit 32 bytes.
    const pid = host.own_pid();
    const leaf_text = std.fmt.bufPrint(&leaf, "{s}.{d}", .{ volume.record_name, pid }) catch
        unreachable; // Same bound.
    root.volume(&temporary, name, leaf_text);
    var failure: fs_mod.Failure = undefined;
    fs.write_atomic_stamped(
        temporary.text(),
        final.text(),
        directory.text(),
        text,
        0o644,
        false,
        &failure,
    ) catch {
        diagnose.directory_failed(diag, .{
            .operation = "writing",
            .path = final.text(),
            .err = failure.err,
            .errno = failure.errno,
        });
        return error.StartFailed;
    };
}
