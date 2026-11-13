//! The provenance record of a build (docs/briefs/M8-trust.md, "Provenance"): `zbx build` writes
//! it once the image result is saved, on a build of all hits as on a build of misses. The record
//! is a function of the build's inputs (build file, lock, every step's key, input, needs and
//! output, the image key, the bases the lock named, the zbx that ran) and of its two times, and
//! of nothing else: that is what makes a second build of an unchanged project write the same
//! bytes but for the times. Everything it says is in memory by then; nothing is read back from
//! the cache except `zbx.lock` and the zbx executable, hashed.
//!
//! The caller holds the store lock. A store that already holds `trust_records_max` provenance
//! records takes no new one (it replaces one it has): the build still succeeds, the result is
//! simply not recorded, and `Outcome.full` says so.

const std = @import("std");
const assert = std.debug.assert;
const builtin = @import("builtin");
const build_options = @import("build_options");
const constants = @import("../constants.zig");
const Host = @import("../host.zig").Host;
const Diag = @import("../diag/diag.zig").Diag;
const lock_file = @import("../lock_file.zig");
const digest_mod = @import("../store/digest.zig");
const fs_mod = @import("../store/fs.zig");
const layout = @import("../store/layout.zig");
const store_diagnose = @import("../store/diagnose.zig");
const provenance = @import("../trust/provenance.zig");
const provenance_store = @import("../trust/provenance_store.zig");
const load_mod = @import("load.zig");
const graph_mod = @import("graph.zig");

const Digest = digest_mod.Digest;
const Store = layout.Store;

pub const Error = error{Failed};

pub const Outcome = enum { written, full };

/// What the build knows when its image is saved.
pub const Request = struct {
    host: Host,
    store: *Store,
    loaded: *const load_mod.Workspace,
    locking: *lock_file.Workspace,
    /// By step index.
    keys: []const Digest,
    inputs: []const Digest,
    outputs: []const Digest,
    image_key: Digest,
    tree: Digest,
    result: Digest,
    started: u64,
    /// How many records the store may hold; `trust_records_max`, lower only in a test (the
    /// simulated disk cannot hold that many files).
    records_max: u32,
};

/// The memory the record and its bytes take.
pub const Workspace = struct {
    record: provenance.Record,
    bytes: [constants.statement_bytes_max]u8,
};

/// Writes the record of `request.result`.
pub fn write(
    request: *const Request,
    ws: *Workspace,
    diag: *Diag,
) Error!Outcome {
    assert(request.keys.len == request.loaded.file.steps_count);
    assert(request.inputs.len == request.keys.len);
    assert(request.outputs.len == request.keys.len);
    const record = &ws.record;
    record.clear();
    try fill(request, record, diag);
    const payload = provenance.render(&ws.bytes, record);
    var errno: u16 = 0;
    if (!provenance_store.exists(request.store, request.result)) {
        const held = provenance_store.count(request.store, &errno) catch |err| {
            store_diagnose.cannot_read(diag, request.store, "counting provenance", err, errno);
            return error.Failed;
        };
        assert(request.records_max <= constants.trust_records_max);
        if (held >= request.records_max) return .full;
    }
    var failure: fs_mod.Failure = undefined;
    provenance_store.save(request.store, request.result, payload, &failure) catch |err| {
        store_diagnose.write_failed(
            diag,
            request.store,
            "writing the provenance record",
            err,
            failure.errno,
        );
        return error.Failed;
    };
    return .written;
}

/// The record's fields, from the build's memory.
pub fn fill(request: *const Request, record: *provenance.Record, diag: *Diag) Error!void {
    const loaded = request.loaded;
    const file = &loaded.file;
    const lock = &request.locking.lock;
    record.tree = request.tree.bytes;
    record.result = request.result.bytes;
    record.set_build_file(loaded.shown());
    record.build_file_digest = Digest.of(loaded.text[0..loaded.text_len]).bytes;
    record.lock = try lock_digest(request, diag);
    record.image_key = request.image_key.bytes;
    record.set_version(build_options.version, platform);
    record.zbx = binary_digest(request.store.fs);
    record.started = request.started;
    record.finished = request.host.time_now();
    for (file.steps_slice(), 0..) |step, index| {
        const made = record.add_step(file.text(step.name));
        const reference = file.text(step.base);
        const entry = &lock.entries[lock.find(reference).?]; // The build resolved it.
        made.base = record.add_base(reference, entry.manifest.bytes, entry.tree.bytes);
        made.key = request.keys[index].bytes;
        made.input = request.inputs[index].bytes;
        made.output = request.outputs[index].bytes;
        made.network = step.network;
        for (loaded.graph.needs_slice(file, @intCast(index))) |need| {
            const name = file.text(file.steps[need].name);
            provenance.Record.add_need(made, name, request.outputs[need].bytes);
        }
    }
    if (file.image.base) |text| {
        // A `step:` base is the image its chain began with.
        const reference = if (loaded.graph.image_base) |target|
            file.text(file.steps[graph_mod.chain_start(&loaded.graph, target)].base)
        else
            file.text(text);
        const entry = &lock.entries[lock.find(reference).?]; // The build resolved it.
        record.image_base = record.add_base(reference, entry.manifest.bytes, entry.tree.bytes);
    }
    assert(record.steps_count == file.steps_count);
}

const platform = switch (builtin.cpu.arch) {
    .x86_64 => "linux/amd64",
    .aarch64 => "linux/arm64",
    else => "linux/unknown",
};

/// The BLAKE3 of `zbx.lock` as it is on disk; null when the project has none (a build with no
/// base needs none).
fn lock_digest(request: *const Request, diag: *Diag) Error!?[constants.store_digest_bytes]u8 {
    const located = &request.locking.located;
    if (!located.exists) return null;
    const fs = request.store.fs;
    const buffer = request.locking.text[0..constants.lock_file_bytes_max];
    const text = fs.read_whole(located.text(), buffer) catch |err| {
        store_diagnose.cannot_read(diag, request.store, "reading zbx.lock", err, fs.last_errno());
        return error.Failed;
    };
    return Digest.of(text).bytes;
}

/// The BLAKE3 of the running executable; zero where it cannot be read, or where it is longer
/// than `package_file_bytes_max` (no `zbx` is).
fn binary_digest(fs: fs_mod.Fs) [constants.store_digest_bytes]u8 {
    var hasher = digest_mod.Hasher.init();
    const fd = fs.open_read("/proc/self/exe") catch return @splat(0);
    defer fs.close(fd);
    var buffer: [64 * 1024]u8 = undefined;
    comptime assert(constants.package_file_bytes_max % buffer.len == 0);
    var reads_left: u32 = @divExact(constants.package_file_bytes_max, buffer.len) + 1;
    while (reads_left > 0) : (reads_left -= 1) {
        const got = fs.read(fd, &buffer) catch return @splat(0);
        if (got == 0) break;
        assert(got <= buffer.len);
        hasher.update(buffer[0..got]);
    } else return @splat(0);
    return hasher.final().bytes;
}
