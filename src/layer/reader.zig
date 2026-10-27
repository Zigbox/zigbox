//! Reading a layer blob: a file of the cache, through its SHA-256, through the decompressor its
//! first bytes name, as a `std.Io.Reader` of tar bytes.
//!
//! The blob was verified when it arrived. It is hashed again on the way through, here, because
//! this is the one place every byte passes: a blob that changed on the disk since is found
//! before its tree is imported (`finish`). The decompressors are the standard library's
//! (`std.compress.flate` and `std.compress.zstd`; docs/demos/m4.md says what was checked).
//!
//! A layer needs no more than a few windows of memory whatever its size: the gzip window of
//! 64 KiB or the zstd window of 8 MiB, and a read buffer. All of it is in the caller's `Reader`.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const constants = @import("../constants.zig");
const digest_mod = @import("../registry/digest.zig");
const fs_mod = @import("../store/fs.zig");

const Fs = fs_mod.Fs;
const Sha256 = digest_mod.Sha256;

pub const Compression = enum { none, gzip, zstd };

/// The window a zstd layer may use. A stream that asks for more is refused: the memory is a
/// fixed buffer. The reference encoder's default for its highest levels is 8 MiB.
pub const zstd_window_bytes: u32 = std.compress.zstd.default_window_len;
const decoder_buffer_bytes: u32 = zstd_window_bytes + std.compress.zstd.block_size_max;

/// Why reading stopped: the file system failed, or the stream is not what its first bytes say.
pub const Fault = union(enum) {
    none,
    io: struct { err: fs_mod.Error, errno: u16 },
    /// The decompressor's name for what is wrong.
    corrupt: []const u8,
    /// The blob is empty or shorter than any container.
    empty,
};

pub const Layer = struct {
    fs: Fs,
    fd: fs_mod.Fd,
    hasher: digest_mod.Hasher,
    /// The bytes of the file read so far.
    file_bytes: u64,
    fault: Fault,
    file: Io.Reader,
    file_buffer: [constants.blob_io_bytes]u8,
    compression: Compression,
    gzip: std.compress.flate.Decompress,
    zstd: std.compress.zstd.Decompress,
    window: [decoder_buffer_bytes]u8,
    open: bool,

    /// Opens `path` and finds the container by the first bytes. The reader of tar bytes is
    /// `tar_reader()`. `Fault.empty` or `.io` is in `fault` on failure.
    pub fn start(layer: *Layer, fs: Fs, path: [:0]const u8) error{Failed}!void {
        assert(path.len > 0);
        layer.fs = fs;
        layer.fault = .none;
        layer.open = false;
        layer.hasher = digest_mod.Hasher.init();
        layer.file_bytes = 0;
        layer.fd = fs.open_read(path) catch |err| {
            layer.fault = .{ .io = .{ .err = err, .errno = fs.last_errno() } };
            return error.Failed;
        };
        layer.open = true;
        layer.compression = .none;
        layer.file = .{
            .vtable = &file_vtable,
            .buffer = &layer.file_buffer,
            .seek = 0,
            .end = 0,
        };
        const head = layer.file.peek(2) catch |err| return layer.file_failed(err, true);
        if (head[0] == 0x1f and head[1] == 0x8b) layer.compression = .gzip;
        if (head[0] == 0x28 and head[1] == 0xb5) layer.compression = .zstd;
        switch (layer.compression) {
            .none => {},
            .gzip => layer.gzip = std.compress.flate.Decompress.init(
                &layer.file,
                .gzip,
                layer.window[0..std.compress.flate.max_window_len],
            ),
            .zstd => layer.zstd = std.compress.zstd.Decompress.init(&layer.file, &layer.window, .{
                .window_len = zstd_window_bytes,
            }),
        }
        assert(layer.open);
    }

    pub fn close(layer: *Layer) void {
        assert(layer.fd < std.math.maxInt(i32));
        assert(@backingInt(layer.compression) <= 2);
        if (layer.open) layer.fs.close(layer.fd);
        layer.open = false;
    }

    /// The reader of the tar bytes.
    pub fn tar_reader(layer: *Layer) *Io.Reader {
        assert(layer.file.buffer.len == constants.blob_io_bytes);
        assert(layer.open);
        return switch (layer.compression) {
            .none => &layer.file,
            .gzip => &layer.gzip.reader,
            .zstd => &layer.zstd.reader,
        };
    }

    /// A read through `tar_reader()` failed with `err`: set `fault` to say why.
    pub fn explain(layer: *Layer, err: Io.Reader.Error) void {
        assert(layer.open);
        assert(@errorName(err).len > 0);
        layer.file_failed(err, false) catch {}; // It sets `fault`, which is the answer.
    }

    fn file_failed(layer: *Layer, err: Io.Reader.Error, at_start: bool) error{Failed} {
        assert(layer.open);
        assert(@errorName(err).len > 0);
        if (layer.fault != .none) return error.Failed;
        switch (layer.compression) {
            .gzip => if (layer.gzip.err) |inner| {
                layer.fault = .{ .corrupt = @errorName(inner) };
                return error.Failed;
            },
            .zstd => if (layer.zstd.err) |inner| {
                layer.fault = .{ .corrupt = @errorName(inner) };
                return error.Failed;
            },
            .none => {},
        }
        if (err == error.EndOfStream) {
            layer.fault = if (at_start) .empty else .{ .corrupt = "EndOfStream" };
        } else {
            layer.fault = .{ .io = .{ .err = error.IoFailed, .errno = layer.fs.last_errno() } };
        }
        return error.Failed;
    }

    /// Reads the rest of the file (the padding after the tar's end, a container's footer), and
    /// returns the SHA-256 of all of it. A fault of the file system is `Failed`.
    pub fn finish(layer: *Layer) error{Failed}!Sha256 {
        assert(layer.open);
        var scratch: [constants.blob_io_bytes]u8 = undefined;
        const file = &layer.file;
        // What the buffer holds is already hashed; the rest is read straight from the file.
        file.tossBuffered();
        var reads: u64 = 0;
        while (true) {
            reads += 1;
            assert(reads < 1 << 40);
            const count = layer.fs.read(layer.fd, &scratch) catch |err| {
                layer.fault = .{ .io = .{ .err = err, .errno = layer.fs.last_errno() } };
                return error.Failed;
            };
            if (count == 0) break;
            layer.hasher.update(scratch[0..count]);
            layer.file_bytes += count;
        }
        return layer.hasher.final();
    }

    const file_vtable: Io.Reader.VTable = .{ .stream = file_stream };

    fn file_stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const layer: *Layer = @alignCast(@fieldParentPtr("file", r));
        const room = limit.slice(try w.writableSliceGreedy(1));
        assert(room.len > 0);
        const want = @min(room.len, constants.blob_io_bytes);
        const count = layer.fs.read(layer.fd, room[0..want]) catch |err| {
            layer.fault = .{ .io = .{ .err = err, .errno = layer.fs.last_errno() } };
            return error.ReadFailed;
        };
        if (count == 0) return error.EndOfStream;
        layer.hasher.update(room[0..count]);
        layer.file_bytes += count;
        w.advance(count);
        return count;
    }
};

comptime {
    assert(constants.blob_io_bytes <= constants.store_io_buffer_bytes);
    assert(decoder_buffer_bytes > std.compress.flate.max_window_len);
}
