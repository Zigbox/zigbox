//! A copy step's `.chown` and `.chmod`, in the store's namespace (`store/namespace.zig`): each
//! entry's selection restamped (`copy_owner.zig`) in the single-threaded child, since writing a
//! file object with a container owner is a `chown` only the namespace's root may do. The new
//! trees' digests, or the diagnostic, come back on a pipe, as an import's do (`input_job.zig`).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const doctor = @import("../doctor.zig");
const host_mod = @import("../host.zig");
const Diag = @import("../diag/diag.zig").Diag;
const layout = @import("../store/layout.zig");
const namespace = @import("../store/namespace.zig");
const store_diagnose = @import("../store/diagnose.zig");
const digest_mod = @import("../store/digest.zig");
const assemble = @import("assemble.zig");
const copy_owner = @import("copy_owner.zig");
const diagnose = @import("diagnose.zig");

const Host = host_mod.Host;
const Digest = digest_mod.Digest;
const Store = layout.Store;

pub const Error = error{Failed};

/// What the caller gives: one selection, its `.to` and its stamp per entry, and where the stamped
/// trees go (`stamped[at]` is `selections[at]` for an entry with no stamp).
pub const Request = struct {
    host: Host,
    facts: *doctor.Facts,
    store: *Store,
    /// The step's name, for a failure to name.
    name: []const u8,
    selections: []const Digest,
    tos: []const []const u8,
    /// Each entry's `.chown` text as written (null: none), for a refusal to name.
    chowns: []const ?[]const u8,
    stamps: []const copy_owner.Stamp,
    ws: *copy_owner.Workspace,
    stamped: []Digest,
};

const Job = struct {
    request: *const Request,
    report: host_mod.Pipe,
};

const report_bytes_max = @max(
    constants.diag_carry_bytes_max,
    constants.build_copy_entries_max * constants.store_digest_bytes,
);

/// Fills `request.stamped`. The caller holds the store's shared lock from before this until the
/// step's cache entry holds the output, so the new trees need no root.
pub fn restamp(request: *const Request, diag: *Diag) Error!void {
    assert(diag.code == null);
    const count = request.selections.len;
    assert(count > 0);
    assert(count <= constants.build_copy_entries_max);
    assert(request.tos.len == count);
    assert(request.chowns.len == count);
    assert(request.stamps.len == count);
    assert(request.stamped.len == count);
    var changed: u32 = 0;
    for (request.stamps, request.selections, request.stamped) |stamp, selection, *out| {
        out.* = selection;
        if (stamp.changes()) changed += 1;
    }
    if (changed == 0) return;
    const host = request.host;
    var job: Job = .{
        .request = request,
        .report = host.pipe() catch |err| {
            store_diagnose.worker_ended(diag, .{ .step = .{
                .name = "pipe",
                .err = err,
                .errno = host.last_errno(),
            } });
            return error.Failed;
        },
    };
    defer host.close(job.report.read);
    const work: namespace.Work = .{ .context = &job, .call = job_call, .store = request.store };
    const code = namespace.run(host, request.facts, work, null, diag) catch {
        host.close(job.report.write);
        return error.Failed;
    };
    host.close(job.report.write);
    var bytes: [report_bytes_max]u8 = undefined;
    var length: usize = 0;
    while (length < bytes.len) {
        const read = host.read_some(job.report.read, bytes[length..]) catch break;
        if (read == 0) break;
        length += read;
    }
    if (code == constants.exit_ok and length == changed * constants.store_digest_bytes) {
        var at: usize = 0;
        for (request.stamps, request.stamped) |stamp, *out| {
            if (!stamp.changes()) continue;
            out.* = .{ .bytes = bytes[at..][0..constants.store_digest_bytes].* };
            at += constants.store_digest_bytes;
        }
        assert(at == length);
        return;
    }
    if (length > 0 and code != constants.exit_ok and diag.decode(bytes[0..length])) {
        return error.Failed;
    }
    diag.reset();
    store_diagnose.worker_ended(diag, .{ .step = .{
        .name = "copy",
        .err = error.IoFailed,
        .errno = 0,
    } });
    return error.Failed;
}

/// The child: restamps each selection that has a stamp, and writes the digests in order, or the
/// encoded diagnostic, to the pipe. Under the one-id map (W0201) every owner is container root,
/// as every other file the store writes there is; the mode still applies. Under the full map an
/// owner the map does not reach is refused before anything is written: the kernel would refuse
/// its `fchown` with `EINVAL`, which would read as a store failure.
fn job_call(context: *anyopaque, squash_owner: bool) u8 {
    const job: *Job = @ptrCast(@alignCast(context));
    const request = job.request;
    var diag: Diag = undefined;
    diag.reset();
    var bytes: [report_bytes_max]u8 = undefined;
    var length: usize = 0;
    if (!squash_owner) unmappable(request, &diag);
    for (request.stamps, request.selections, request.tos) |stamp_given, selection, to| {
        if (diag.code != null) break;
        if (!stamp_given.changes()) continue;
        var stamp = stamp_given;
        if (squash_owner and stamp.owner != null) stamp.owner = .{ .uid = 0, .gid = 0 };
        const digest = stamped(request, selection, to, stamp, &diag) orelse break;
        @memcpy(bytes[length..][0..constants.store_digest_bytes], &digest.bytes);
        length += constants.store_digest_bytes;
    }
    if (diag.code == null) {
        request.host.write_handle_all(job.report.write, bytes[0..length]) catch {};
        return constants.exit_ok;
    }
    var encoded: [constants.diag_carry_bytes_max]u8 = undefined;
    request.host.write_handle_all(job.report.write, diag.encode(&encoded)) catch {};
    return diag.exit_code();
}

/// `E0817` in `diag` for the first owner the full map does not reach (ids 0 to
/// `subid_range_min`, as `namespace.run` writes the map); nothing if every one is reached.
fn unmappable(request: *const Request, diag: *Diag) void {
    assert(diag.code == null);
    assert(request.stamps.len == request.chowns.len);
    for (request.stamps, request.chowns) |stamp, chown| {
        const owner = stamp.owner orelse continue;
        const id = @max(owner.uid, owner.gid);
        if (id <= constants.subid_range_min) continue;
        diagnose.copy_owner_unmappable(diag, request.name, chown.?, id);
        assert(diag.code != null);
        return;
    }
}

fn stamped(
    request: *const Request,
    selection: Digest,
    to: []const u8,
    stamp: copy_owner.Stamp,
    diag: *Diag,
) ?Digest {
    assert(diag.code == null);
    assert(stamp.changes());
    var failure: assemble.Failure = undefined;
    const context: copy_owner.Context = .{ .store = request.store, .failure = &failure };
    return copy_owner.restamp(context, request.ws, selection, to, stamp) catch {
        failed(diag, request.store, &failure, request.name, to);
        return null;
    };
}

/// The diagnostic for a restamp that failed: as a copy's assembly reports one.
pub fn failed(
    diag: *Diag,
    store: *Store,
    failure: *const assemble.Failure,
    name: []const u8,
    to: []const u8,
) void {
    assert(diag.code == null);
    assert(to.len > 0);
    switch (failure.*) {
        .io => |io| store_diagnose.write_failed(diag, store, io.step, io.err, io.errno),
        .damaged => {
            const operation = "reading a tree to copy";
            store_diagnose.write_failed(diag, store, operation, error.IoFailed, 0);
        },
        else => diagnose.copy_refused(diag, failure, name, to),
    }
}
