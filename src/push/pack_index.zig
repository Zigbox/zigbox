//! Layer writer 2's index side: while the pack walks the tree, the recorder lists each tree and
//! each file object at its first appearance, and each chunk of an object's first body, in three
//! spill files under the store's `tmp/` (an index can reach `lazy_index_bytes_max`, far more than
//! a workspace holds). After the tar's end-of-archive the pack copies the header and the three
//! spills, in order, into the layer's stream. The format is
//! `docs/decisions/2026-11-14-s2-index-format.md`.
//!
//! A tree with more than `lazy_nodes_max` names, or whose index would pass
//! `lazy_index_bytes_max`, gets no index: the recorder stops recording, and the pack writes the
//! layer without one (the image runs eagerly, `W1201`).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const fs_mod = @import("../store/fs.zig");
const digest_mod = @import("../store/digest.zig");
const layout = @import("../store/layout.zig");
const index_mod = @import("../lazy/index.zig");
const seen_mod = @import("../lazy/seen.zig");

const Digest = digest_mod.Digest;
const Fs = fs_mod.Fs;
const PathBuf = fs_mod.PathBuf;
const Store = layout.Store;

pub const spill_buffer_bytes: u32 = 64 * 1024;

comptime {
    assert(spill_buffer_bytes >= index_mod.tree_head_bytes + index_mod.object_record_bytes);
    assert(spill_buffer_bytes <= constants.store_io_buffer_bytes);
}

/// One section of the index, written to a temporary file as the walk finds it.
const Spill = struct {
    path: PathBuf,
    fd: fs_mod.Fd,
    open: bool,
    made: bool,
    bytes: u64,
    end: u32,
    buffer: [spill_buffer_bytes]u8,

    fn put(spill: *Spill, fs: Fs, data: []const u8) fs_mod.Error!void {
        assert(spill.open);
        assert(spill.end <= spill.buffer.len);
        if (spill.end + data.len > spill.buffer.len) try spill.flush(fs);
        if (data.len > spill.buffer.len) {
            try fs.write_all(spill.fd, data);
        } else {
            @memcpy(spill.buffer[spill.end..][0..data.len], data);
            spill.end += @intCast(data.len);
        }
        spill.bytes += data.len;
    }

    fn flush(spill: *Spill, fs: Fs) fs_mod.Error!void {
        assert(spill.open);
        if (spill.end == 0) return;
        try fs.write_all(spill.fd, spill.buffer[0..spill.end]);
        spill.end = 0;
    }
};

const Section = enum(u2) { trees = 0, objects = 1, chunks = 2 };

/// The index being recorded: about 20 MiB (the seen set) plus the spill buffers.
pub const Recorder = struct {
    /// Still writing an index: false once the tree is past a bound.
    recording: bool,
    names: u32,
    /// `lazy_nodes_max`, or less in a test.
    names_max: u32,
    /// `lazy_index_bytes_max`, or less in a test.
    index_bytes_max: u64,
    trees: u32,
    objects: u32,
    chunks: u32,
    spills: [3]Spill,
    seen: seen_mod.Seen,

    /// Makes the three spill files; on failure none is left.
    pub fn start(
        recorder: *Recorder,
        store: *Store,
        names_max: u32,
        index_bytes_max: u64,
    ) fs_mod.Error!void {
        assert(names_max >= 1);
        assert(names_max <= constants.lazy_nodes_max);
        assert(index_bytes_max >= index_mod.header_bytes);
        assert(index_bytes_max <= constants.lazy_index_bytes_max);
        recorder.recording = true;
        recorder.names_max = names_max;
        recorder.index_bytes_max = index_bytes_max;
        recorder.names = 0;
        recorder.trees = 0;
        recorder.objects = 0;
        recorder.chunks = 0;
        var key: [seen_mod.key_bytes]u8 = undefined;
        try store.host.random_bytes(&key);
        recorder.seen.reset(&key);
        for (&recorder.spills) |*spill| {
            spill.open = false;
            spill.made = false;
            spill.bytes = 0;
            spill.end = 0;
        }
        const fs = store.fs;
        for (&recorder.spills) |*spill| {
            _ = store.tmp_path(&spill.path);
            spill.fd = fs.create(spill.path.text(), 0o600) catch |err| {
                recorder.discard(fs);
                return err;
            };
            spill.open = true;
            spill.made = true;
        }
    }

    /// The index's length so far: its header and every section.
    pub fn index_bytes(recorder: *const Recorder) u64 {
        var total: u64 = index_mod.header_bytes;
        for (&recorder.spills) |*spill| total += spill.bytes;
        return total;
    }

    fn put(recorder: *Recorder, fs: Fs, section: Section, data: []const u8) fs_mod.Error!void {
        assert(recorder.recording);
        try recorder.spills[@backingInt(section)].put(fs, data);
        if (recorder.index_bytes() > recorder.index_bytes_max) recorder.recording = false;
    }

    /// Counts one name of the tree (every tar entry but the root's).
    pub fn name(recorder: *Recorder) void {
        if (!recorder.recording) return;
        assert(recorder.names <= recorder.names_max);
        recorder.names += 1;
        if (recorder.names > recorder.names_max) recorder.recording = false;
    }

    /// Lists the tree `digest` at its first appearance.
    pub fn tree(recorder: *Recorder, fs: Fs, digest: Digest, bytes: []const u8) fs_mod.Error!void {
        if (!recorder.recording) return;
        assert(bytes.len >= 1);
        assert(bytes.len <= constants.store_tree_bytes_max);
        if (recorder.seen.get(.tree, digest) != null) return;
        const added = recorder.seen.add(.tree, digest, recorder.trees);
        assert(added); // Within `lazy_nodes_max`, which the set is sized for.
        recorder.trees += 1;
        var head: [index_mod.tree_head_bytes]u8 = undefined;
        index_mod.encode_tree_head(digest, @intCast(bytes.len), &head);
        try recorder.put(fs, .trees, &head);
        if (recorder.recording) try recorder.put(fs, .trees, bytes);
    }

    /// Lists the object `id` at its first appearance; true when it is new and recording, so
    /// the chunks of this body are its chunks.
    pub fn object(recorder: *Recorder, fs: Fs, id: Digest, size: u64) fs_mod.Error!bool {
        if (!recorder.recording) return false;
        assert(size <= index_mod.file_bytes_max);
        if (recorder.seen.get(.object, id) != null) return false;
        const added = recorder.seen.add(.object, id, recorder.objects);
        assert(added); // Within `lazy_nodes_max`, which the set is sized for.
        recorder.objects += 1;
        const count = index_mod.chunk_count(size);
        var record: [index_mod.object_record_bytes]u8 = undefined;
        index_mod.encode_object(.{
            .id = id,
            .size = size,
            .first_chunk = recorder.chunks,
            .chunk_count = count,
        }, &record);
        recorder.chunks += count;
        try recorder.put(fs, .objects, &record);
        return recorder.recording;
    }

    /// Lists one chunk of the object last listed; chunks come in order.
    pub fn chunk(recorder: *Recorder, fs: Fs, record: index_mod.Chunk) fs_mod.Error!void {
        if (!recorder.recording) return;
        var bytes: [index_mod.chunk_record_bytes]u8 = undefined;
        index_mod.encode_chunk(record, &bytes);
        try recorder.put(fs, .chunks, &bytes);
    }

    /// The header of the index recorded for the tree `root`.
    pub fn header(recorder: *const Recorder, root: Digest) index_mod.Header {
        assert(recorder.recording);
        assert(recorder.spills[2].bytes ==
            @as(u64, recorder.chunks) * index_mod.chunk_record_bytes);
        return .{
            .complete = true,
            .tree = root,
            .names = recorder.names,
            .trees = recorder.trees,
            .objects = recorder.objects,
            .chunks = recorder.chunks,
            .order = 0,
        };
    }

    /// Writes the header and the three spills to `out` and hashes them into `hasher`; `io` is
    /// the room the spills are read back through.
    pub fn emit(
        recorder: *Recorder,
        fs: Fs,
        root: Digest,
        out: *std.Io.Writer,
        hasher: *digest_mod.Hasher,
        io: []u8,
    ) (fs_mod.Error || error{ WriteFailed, Short })!void {
        assert(recorder.recording);
        assert(io.len > 0);
        var head: [index_mod.header_bytes]u8 = undefined;
        recorder.header(root).encode(&head);
        hasher.update(&head);
        try out.writeAll(&head);
        for (&recorder.spills) |*spill| {
            try spill.flush(fs);
            fs.close(spill.fd);
            spill.open = false;
            const fd = try fs.open_read(spill.path.text());
            defer fs.close(fd);
            var total: u64 = 0;
            while (true) {
                const count = try fs.read(fd, io);
                if (count == 0) break;
                total += count;
                if (total > spill.bytes) return error.Short;
                hasher.update(io[0..count]);
                try out.writeAll(io[0..count]);
            }
            if (total != spill.bytes) return error.Short;
        }
    }

    /// Closes and removes the spill files; safe on every path, and more than once.
    pub fn discard(recorder: *Recorder, fs: Fs) void {
        for (&recorder.spills) |*spill| {
            if (spill.open) fs.close(spill.fd);
            spill.open = false;
            // A spill that cannot be removed is left in `tmp/`, which gc sweeps.
            if (spill.made) fs.unlink(spill.path.text()) catch {};
            spill.made = false;
        }
    }
};
