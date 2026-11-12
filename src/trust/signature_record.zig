//! The signature record as data (docs/briefs/M8-trust.md, "The signature record"): up to
//! `signatures_per_tree_max` DSSE envelopes, one per line, each ending in a newline. This file is
//! the pure part of `record.zig`: it needs only `constants.zig`, no host, store or provenance, so
//! `zigbox.trust` can export it and the verdict can take it, for `wasm32-freestanding` too.
//! Reading a record from bytes and checking its lines is `record.zig`.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

pub const AddError = error{
    /// The record already has `signatures_per_tree_max` distinct lines.
    Full,
};

pub const Added = enum { added, present };

pub const Record = struct {
    bytes: [constants.signature_record_bytes_max]u8,
    length: u32,
    count: u32,

    pub fn clear(record: *Record) void {
        record.length = 0;
        record.count = 0;
    }

    pub fn text(record: *const Record) []const u8 {
        assert(record.length <= constants.signature_record_bytes_max);
        return record.bytes[0..record.length];
    }

    /// Line `index` (0-based), without its newline.
    pub fn line(record: *const Record, index: u32) []const u8 {
        assert(index < record.count);
        var start: usize = 0;
        var at: u32 = 0;
        const bytes = record.text();
        while (true) {
            const end = std.mem.indexOfScalarPos(u8, bytes, start, '\n').?;
            if (at == index) return bytes[start..end];
            start = end + 1;
            at += 1;
        }
    }

    /// True if `envelope` (one line's bytes, no newline) is already a line.
    pub fn has(record: *const Record, envelope: []const u8) bool {
        for (0..record.count) |index| {
            if (std.mem.eql(u8, record.line(@intCast(index)), envelope)) return true;
        }
        return false;
    }

    /// Appends `envelope` as a line unless it is there already. The caller made the envelope
    /// itself, so it is well formed; this only enforces the bounds.
    pub fn add(record: *Record, envelope: []const u8) AddError!Added {
        assert(envelope.len > 0);
        assert(envelope.len <= constants.envelope_bytes_max);
        assert(std.mem.indexOfScalar(u8, envelope, '\n') == null);
        if (record.has(envelope)) return .present;
        if (record.count == constants.signatures_per_tree_max) return error.Full;
        const need = envelope.len + 1;
        // Eight lines of the longest envelope fit by the constant's definition.
        assert(record.length + need <= constants.signature_record_bytes_max);
        @memcpy(record.bytes[record.length..][0..envelope.len], envelope);
        record.bytes[record.length + envelope.len] = '\n';
        record.length += @intCast(need);
        record.count += 1;
        return .added;
    }
};
