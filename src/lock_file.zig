//! `zbx.lock`: which image each reference of a project means. One entry per reference: the
//! reference as it was written, the digest of the image manifest it resolved to, the platform,
//! and the tree digest the image became. The lock lives in the project directory, which is the
//! nearest directory up from the working directory that has one, or else the working directory.
//!
//! The file is ZON, versioned, sorted by reference, and written atomically. It is written one
//! field a line, in this shape, and read line by line (a hand edit of a digest is the use case):
//!
//!   .{
//!       .version = 1,
//!       .images = .{
//!           .{
//!               .reference = "alpine:3.20",
//!               .manifest = "sha256:...",
//!               .platform = "linux/amd64",
//!               .tree = "b3:...",
//!           },
//!       },
//!   }
//!
//! A lock may also hold output pins (M9 slice 3c, docs/decisions/2026-11-14-m9-pinned-fetches-
//! and-output-pins.md): the output digest a network step of a build file is expected to give,
//! with the step's key when it was pinned. A lock with pins is `.version = 2` and has a `.pins`
//! list after `.images`, sorted by file then step:
//!
//!       .pins = .{
//!           .{
//!               .file = "zbx.build.zon",
//!               .step = "fetch",
//!               .key = "b3:...",
//!               .output = "b3:...",
//!           },
//!       },
//!
//! A lock without pins is version 1 and byte for byte what M7 wrote, so an older zbx reads every
//! lock it could read before and refuses one with pins rather than ignoring them.
//!
//! Two references that mean the same image (`alpine:3.20`, `docker.io/library/alpine:3.20`) are
//! one entry. The lock never records where bytes came from: a mirror (`ZBX_REGISTRY_MIRRORS`) is
//! not in it.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const host_mod = @import("host.zig");
const reference_mod = @import("registry/reference.zig");
const digest_mod = @import("store/digest.zig");
const fs_mod = @import("store/fs.zig");
const roots = @import("store/roots.zig");
const Sha256 = @import("registry/digest.zig").Sha256;

const Digest = digest_mod.Digest;
const Fs = fs_mod.Fs;
const Host = host_mod.Host;

pub const file_name = "zbx.lock";
/// The version of a lock without pins, and of one with them.
pub const version: u32 = 1;
pub const version_pins: u32 = 2;

/// An output pin: the step `step` of the build file `file` (relative to the lock's directory)
/// gave `output` when its key was `key`.
pub const Pin = struct {
    file_at: u32,
    file_len: u16,
    step_at: u32,
    step_len: u8,
    key: Digest,
    output: Digest,
};

pub const Entry = struct {
    reference_at: u32,
    reference_len: u16,
    manifest: Sha256,
    tree: Digest,
    platform: [16]u8,
    platform_len: u8,

    pub fn platform_text(entry: *const Entry) []const u8 {
        assert(entry.platform_len > 0);
        assert(entry.platform_len <= entry.platform.len);
        return entry.platform[0..entry.platform_len];
    }
};

pub const Lock = struct {
    entries: [constants.lock_entries_max]Entry,
    count: u32,
    pins: [constants.lock_pins_max]Pin,
    pin_count: u32,
    /// The bytes of the references, and of the pins' files and steps.
    pool: [constants.lock_pool_bytes]u8,
    pool_len: u32,

    pub fn clear(lock: *Lock) void {
        assert(lock.pool.len == constants.lock_pool_bytes);
        assert(lock.entries.len == constants.lock_entries_max);
        assert(lock.pins.len == constants.lock_pins_max);
        lock.count = 0;
        lock.pin_count = 0;
        lock.pool_len = 0;
    }

    pub fn pin_file(lock: *const Lock, pin: *const Pin) []const u8 {
        assert(pin.file_at + @as(u32, pin.file_len) <= lock.pool_len);
        return lock.pool[pin.file_at..][0..pin.file_len];
    }

    pub fn pin_step(lock: *const Lock, pin: *const Pin) []const u8 {
        assert(pin.step_at + @as(u32, pin.step_len) <= lock.pool_len);
        return lock.pool[pin.step_at..][0..pin.step_len];
    }

    /// The pin of step `step` in build file `file`, or null.
    pub fn find_pin(lock: *const Lock, file: []const u8, step: []const u8) ?*const Pin {
        assert(lock.pin_count <= constants.lock_pins_max);
        assert(step.len <= constants.build_step_name_bytes_max);
        for (lock.pins[0..lock.pin_count]) |*pin| {
            if (!std.mem.eql(u8, lock.pin_step(pin), step)) continue;
            if (std.mem.eql(u8, lock.pin_file(pin), file)) return pin;
        }
        return null;
    }

    /// Adds the pin, or replaces the one for the same file and step. The pins stay sorted by
    /// file, then step. Full when the pins, the pool or the rendered file would pass a bound.
    pub fn put_pin(
        lock: *Lock,
        file: []const u8,
        step: []const u8,
        key: Digest,
        output: Digest,
    ) PutError!void {
        assert(lock.pin_count <= constants.lock_pins_max);
        if (file.len == 0 or file.len > constants.path_bytes_max) return error.BadReference;
        if (step.len == 0 or step.len > constants.build_step_name_bytes_max) {
            return error.BadReference;
        }
        if (lock.find_pin(file, step)) |found| {
            const index = (@intFromPtr(found) - @intFromPtr(&lock.pins[0])) / @sizeOf(Pin);
            lock.pins[index].key = key;
            lock.pins[index].output = output;
            return;
        }
        if (lock.pin_count == constants.lock_pins_max) return error.Full;
        if (lock.pool_len + file.len + step.len > lock.pool.len) return error.Full;
        const saved_pool = lock.pool_len;
        const file_at = lock.pool_len;
        @memcpy(lock.pool[file_at..][0..file.len], file);
        const step_at: u32 = file_at + @as(u32, @intCast(file.len));
        @memcpy(lock.pool[step_at..][0..step.len], step);
        lock.pool_len = step_at + @as(u32, @intCast(step.len));
        insert_pin(lock, .{
            .file_at = file_at,
            .file_len = @intCast(file.len),
            .step_at = step_at,
            .step_len = @intCast(step.len),
            .key = key,
            .output = output,
        });
        if (rendered_bytes(lock) > constants.lock_file_bytes_max) {
            remove_pin(lock, file, step);
            lock.pool_len = saved_pool;
            return error.Full;
        }
    }

    pub fn reference(lock: *const Lock, entry: *const Entry) []const u8 {
        assert(entry.reference_at + @as(u32, entry.reference_len) <= lock.pool_len);
        return lock.pool[entry.reference_at..][0..entry.reference_len];
    }

    /// The index of the entry that means the same image as `written`, or null.
    pub fn find(lock: *const Lock, written: []const u8) ?u32 {
        assert(written.len <= constants.arg_bytes_max);
        for (lock.entries[0..lock.count], 0..) |*entry, index| {
            if (same_reference(lock.reference(entry), written)) return @intCast(index);
        }
        return null;
    }

    pub const PutError = error{ Full, BadReference };

    /// Adds the entry or replaces the one for the same image (it keeps the reference as it was
    /// first written). The entries stay sorted by reference.
    pub fn put(
        lock: *Lock,
        written: []const u8,
        manifest: Sha256,
        platform: []const u8,
        tree: Digest,
    ) PutError!void {
        assert(lock.count <= constants.lock_entries_max);
        assert(platform.len > 0);
        assert(platform.len <= 16);
        if (written.len == 0 or written.len > constants.reference_bytes_max) {
            return error.BadReference;
        }
        if (lock.find(written)) |index| {
            const entry = &lock.entries[index];
            entry.manifest = manifest;
            entry.tree = tree;
            @memcpy(entry.platform[0..platform.len], platform);
            entry.platform_len = @intCast(platform.len);
            return;
        }
        if (lock.count == constants.lock_entries_max) return error.Full;
        if (lock.pool_len + written.len > lock.pool.len) return error.Full;
        const at = lock.pool_len;
        @memcpy(lock.pool[at..][0..written.len], written);
        lock.pool_len += @intCast(written.len);
        var entry: Entry = .{
            .reference_at = at,
            .reference_len = @intCast(written.len),
            .manifest = manifest,
            .tree = tree,
            .platform = undefined,
            .platform_len = @intCast(platform.len),
        };
        @memcpy(entry.platform[0..platform.len], platform);
        var place: u32 = lock.count;
        while (place > 0 and std.mem.order(
            u8,
            lock.reference(&lock.entries[place - 1]),
            written,
        ) == .gt) {
            lock.entries[place] = lock.entries[place - 1];
            place -= 1;
        }
        lock.entries[place] = entry;
        lock.count += 1;
        if (rendered_bytes(lock) > constants.lock_file_bytes_max) {
            while (place + 1 < lock.count) : (place += 1) {
                lock.entries[place] = lock.entries[place + 1];
            }
            lock.count -= 1;
            lock.pool_len = at;
            return error.Full;
        }
    }
};

/// Pins are ordered by file, then step.
fn pin_order(lock: *const Lock, first: *const Pin, second: *const Pin) std.math.Order {
    assert(first.file_len > 0);
    assert(second.file_len > 0);
    const files = std.mem.order(u8, lock.pin_file(first), lock.pin_file(second));
    if (files != .eq) return files;
    return std.mem.order(u8, lock.pin_step(first), lock.pin_step(second));
}

/// Puts `pin` in its sorted place; the caller has checked there is room and no equal pin.
fn insert_pin(lock: *Lock, pin: Pin) void {
    assert(lock.pin_count < constants.lock_pins_max);
    var place: u32 = lock.pin_count;
    while (place > 0 and pin_order(lock, &lock.pins[place - 1], &pin) == .gt) {
        lock.pins[place] = lock.pins[place - 1];
        place -= 1;
    }
    lock.pins[place] = pin;
    lock.pin_count += 1;
    if (place > 0) assert(pin_order(lock, &lock.pins[place - 1], &pin) == .lt);
}

fn remove_pin(lock: *Lock, file: []const u8, step: []const u8) void {
    assert(lock.pin_count > 0);
    const found = lock.find_pin(file, step).?;
    var index = (@intFromPtr(found) - @intFromPtr(&lock.pins[0])) / @sizeOf(Pin);
    while (index + 1 < lock.pin_count) : (index += 1) lock.pins[index] = lock.pins[index + 1];
    lock.pin_count -= 1;
    assert(lock.find_pin(file, step) == null);
}

/// True if the two references name the same image: the same registry, repository, tag and
/// digest. Text that is not a reference is equal only to itself.
pub fn same_reference(first: []const u8, second: []const u8) bool {
    assert(first.len <= constants.reference_bytes_max);
    assert(second.len <= constants.arg_bytes_max);
    if (std.mem.eql(u8, first, second)) return true;
    var one: reference_mod.Reference = undefined;
    var other: reference_mod.Reference = undefined;
    reference_mod.parse(first, &one) catch return false;
    reference_mod.parse(second, &other) catch return false;
    var one_text: reference_mod.Formatted = undefined;
    var other_text: reference_mod.Formatted = undefined;
    return std.mem.eql(u8, one.format(&one_text), other.format(&other_text));
}

// ---- Writing -------------------------------------------------------------------------------

/// The lock as text; the buffer is `constants.lock_file_bytes_max`.
pub fn render(lock: *const Lock, buffer: []u8) []const u8 {
    assert(buffer.len >= constants.lock_file_bytes_max);
    assert(lock.count <= constants.lock_entries_max);
    // Cannot fail: `parse` and `put_pin` refuse a lock whose rendering is longer than
    // `lock_file_bytes_max`, and `put` adds a reference of printable text, which renders as
    // itself plus fixed text.
    assert(rendered_bytes(lock) <= constants.lock_file_bytes_max);
    var writer = std.Io.Writer.fixed(buffer);
    render_to(lock, &writer) catch unreachable; // Sized above.
    return writer.buffered();
}

/// The length of the lock's rendering.
pub fn rendered_bytes(lock: *const Lock) u64 {
    assert(lock.count <= constants.lock_entries_max);
    assert(lock.pin_count <= constants.lock_pins_max);
    var discarding = std.Io.Writer.Discarding.init(&.{});
    // Cannot fail: a discarding writer only counts.
    render_to(lock, &discarding.writer) catch unreachable;
    return discarding.fullCount();
}

fn render_to(lock: *const Lock, writer: *std.Io.Writer) std.Io.Writer.Error!void {
    assert(lock.count <= constants.lock_entries_max);
    assert(lock.pin_count <= constants.lock_pins_max);
    const shown_version = if (lock.pin_count == 0) version else version_pins;
    try writer.print(".{{\n    .version = {d},\n    .images = .{{\n", .{shown_version});
    for (lock.entries[0..lock.count]) |*entry| {
        try writer.writeAll("        .{\n            .reference = ");
        try put_text(writer, lock.reference(entry));
        try writer.print(",\n            .manifest = \"{s}\",\n", .{&entry.manifest.text()});
        try writer.print("            .platform = \"{s}\",\n", .{entry.platform_text()});
        try writer.print("            .tree = \"{s}\",\n        }},\n", .{entry.tree.text()});
    }
    try writer.writeAll("    },\n");
    if (lock.pin_count > 0) {
        try writer.writeAll("    .pins = .{\n");
        for (lock.pins[0..lock.pin_count]) |*pin| {
            try writer.writeAll("        .{\n            .file = ");
            try put_text(writer, lock.pin_file(pin));
            try writer.writeAll(",\n            .step = ");
            try put_text(writer, lock.pin_step(pin));
            try writer.print(",\n            .key = \"{s}\",\n", .{pin.key.text()});
            try writer.print("            .output = \"{s}\",\n        }},\n", .{pin.output.text()});
        }
        try writer.writeAll("    },\n");
    }
    try writer.writeAll("}\n");
}

/// A reference or a pin's file is printable ASCII; anything else (a hand edit gone wrong) is
/// escaped.
fn put_text(writer: *std.Io.Writer, text: []const u8) std.Io.Writer.Error!void {
    assert(text.len <= constants.path_bytes_max);
    try writer.writeAll("\"");
    for (text) |byte| {
        switch (byte) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            0x20...0x21, 0x23...0x5b, 0x5d...0x7e => try writer.writeByte(byte),
            else => try writer.print("\\x{x:0>2}", .{byte}),
        }
    }
    try writer.writeAll("\"");
}

// ---- Reading -------------------------------------------------------------------------------

pub const ProblemKind = enum {
    /// A line that is none of the lines of a lock.
    unknown_line,
    /// A value that is not a quoted string, a digest or a platform of the right shape.
    bad_value,
    /// An entry without one of its four fields, or a field twice.
    incomplete_entry,
    /// No `.version`.
    no_version,
    /// A newer version than this zbx reads.
    newer,
    /// Two entries for one image, two pins for one step, or a second `.version`.
    duplicate,
    /// More entries, pins or bytes than a lock holds, or a lock whose rendering would be.
    too_big,
};

pub const Problem = struct {
    kind: ProblemKind,
    /// The line, counting from 1; 0 for the file as a whole.
    line: u32,
};

const PinFields = packed struct(u8) {
    file: bool = false,
    step: bool = false,
    key: bool = false,
    output: bool = false,
    _unused: u4 = 0,

    fn complete(fields: PinFields) bool {
        return fields.file and fields.step and fields.key and fields.output;
    }
};

const Fields = packed struct(u8) {
    reference: bool = false,
    manifest: bool = false,
    platform: bool = false,
    tree: bool = false,
    _unused: u4 = 0,

    fn complete(fields: Fields) bool {
        return fields.reference and fields.manifest and fields.platform and fields.tree;
    }
};

/// What `parse` is reading: an image entry, a pin, or neither.
const Reading = struct {
    version_seen: u32 = 0,
    /// Whether `.pins = .{` has been read: from then on entries are pins.
    in_pins: bool = false,
    open: ?Entry = null,
    fields: Fields = .{},
    pin: ?Pin = null,
    pin_fields: PinFields = .{},
};

/// Reads `text` into `lock`; null if it is a lock, else what is wrong and where. A lock is
/// refused if its rendering would not fit `lock_file_bytes_max`, so what reads also writes.
pub fn parse(text: []const u8, lock: *Lock) ?Problem {
    assert(text.len <= constants.lock_file_bytes_max);
    lock.clear();
    var reading: Reading = .{};
    var number: u32 = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        number += 1;
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        if (is_structure(line)) continue;
        const equals = std.mem.indexOf(u8, line, " = ");
        if (line[0] != '.' or equals == null) return .{ .kind = .unknown_line, .line = number };
        const key = line[1..equals.?];
        var value = line[equals.? + 3 ..];
        if (value.len > 0 and value[value.len - 1] == ',') value = value[0 .. value.len - 1];
        if (parse_line(lock, &reading, key, value, number)) |problem| return problem;
    }
    if (finish_entry(lock, &reading.open, reading.fields, number)) |problem| return problem;
    if (finish_pin(lock, &reading.pin, reading.pin_fields, number)) |problem| return problem;
    if (reading.version_seen == 0) return .{ .kind = .no_version, .line = 0 };
    // A version 2 lock without pins reads (it renders as version 1); a version 1 lock with pins
    // cannot, since `.pins` is refused before a `.version = 2`.
    if (lock.pin_count > 0) assert(reading.version_seen == version_pins);
    if (rendered_bytes(lock) > constants.lock_file_bytes_max) {
        return .{ .kind = .too_big, .line = 0 };
    }
    return null;
}

fn parse_line(
    lock: *Lock,
    reading: *Reading,
    key: []const u8,
    value: []const u8,
    number: u32,
) ?Problem {
    assert(number > 0);
    assert(lock.count <= constants.lock_entries_max);
    if (std.mem.eql(u8, key, "version")) {
        // One `.version`, so a later line cannot unsay the version the pins were read under.
        if (reading.version_seen != 0) return .{ .kind = .duplicate, .line = number };
        reading.version_seen = std.fmt.parseInt(u32, value, 10) catch {
            return .{ .kind = .bad_value, .line = number };
        };
        if (reading.version_seen == 0) return .{ .kind = .bad_value, .line = number };
        if (reading.version_seen > version_pins) return .{ .kind = .newer, .line = number };
    } else if (std.mem.eql(u8, key, "images")) {
        if (reading.in_pins) return .{ .kind = .unknown_line, .line = number };
    } else if (std.mem.eql(u8, key, "pins")) {
        // Pins need a version that says so, and come once, after the images.
        if (reading.version_seen != version_pins) return .{ .kind = .unknown_line, .line = number };
        if (reading.in_pins) return .{ .kind = .unknown_line, .line = number };
        if (finish_entry(lock, &reading.open, reading.fields, number)) |problem| return problem;
        reading.in_pins = true;
    } else if (reading.in_pins) {
        return parse_pin_line(lock, reading, key, value, number);
    } else if (std.mem.eql(u8, key, "reference")) {
        if (finish_entry(lock, &reading.open, reading.fields, number)) |problem| return problem;
        reading.fields = .{ .reference = true };
        reading.open = start_entry(lock, value) orelse {
            return .{ .kind = .bad_value, .line = number };
        };
    } else if (reading.open) |*entry| {
        if (set_field(entry, &reading.fields, key, value) == false) {
            return .{ .kind = .bad_value, .line = number };
        }
    } else {
        return .{ .kind = .unknown_line, .line = number };
    }
    return null;
}

fn parse_pin_line(
    lock: *Lock,
    reading: *Reading,
    key: []const u8,
    value: []const u8,
    number: u32,
) ?Problem {
    assert(reading.in_pins);
    assert(reading.open == null);
    if (std.mem.eql(u8, key, "file")) {
        if (finish_pin(lock, &reading.pin, reading.pin_fields, number)) |problem| return problem;
        reading.pin_fields = .{ .file = true };
        reading.pin = start_pin(lock, value) orelse return .{ .kind = .bad_value, .line = number };
    } else if (reading.pin) |*pin| {
        if (set_pin_field(lock, pin, &reading.pin_fields, key, value) == false) {
            return .{ .kind = .bad_value, .line = number };
        }
    } else {
        return .{ .kind = .unknown_line, .line = number };
    }
    return null;
}

fn start_pin(lock: *Lock, value: []const u8) ?Pin {
    assert(lock.pin_count <= constants.lock_pins_max);
    var word: [constants.path_bytes_max]u8 = undefined;
    const length = roots.parse_string(value, &word) orelse return null;
    if (length == 0) return null;
    if (lock.pool_len + length > lock.pool.len) return null;
    const at = lock.pool_len;
    @memcpy(lock.pool[at..][0..length], word[0..length]);
    lock.pool_len += @intCast(length);
    return .{
        .file_at = at,
        .file_len = @intCast(length),
        .step_at = 0,
        .step_len = 0,
        .key = undefined,
        .output = undefined,
    };
}

fn set_pin_field(
    lock: *Lock,
    pin: *Pin,
    fields: *PinFields,
    key: []const u8,
    value: []const u8,
) bool {
    assert(pin.file_len > 0);
    assert(fields.file);
    var word: [constants.store_digest_text_bytes + 8]u8 = undefined;
    const length = roots.parse_string(value, &word) orelse return false;
    const text = word[0..length];
    if (std.mem.eql(u8, key, "step")) {
        if (fields.step) return false;
        if (text.len == 0 or text.len > constants.build_step_name_bytes_max) return false;
        if (lock.pool_len + text.len > lock.pool.len) return false;
        pin.step_at = lock.pool_len;
        pin.step_len = @intCast(text.len);
        @memcpy(lock.pool[pin.step_at..][0..text.len], text);
        lock.pool_len += @intCast(text.len);
        fields.step = true;
    } else if (std.mem.eql(u8, key, "key")) {
        if (fields.key) return false;
        pin.key = Digest.parse(text) orelse return false;
        fields.key = true;
    } else if (std.mem.eql(u8, key, "output")) {
        if (fields.output) return false;
        pin.output = Digest.parse(text) orelse return false;
        fields.output = true;
    } else {
        return false;
    }
    return true;
}

/// Adds the pin being read, if there is one: it must have its four fields and be new.
fn finish_pin(lock: *Lock, open: *?Pin, fields: PinFields, number: u32) ?Problem {
    assert(number > 0);
    const pin = open.* orelse return null;
    open.* = null;
    if (!fields.complete()) return .{ .kind = .incomplete_entry, .line = number };
    if (lock.pin_count == constants.lock_pins_max) return .{ .kind = .too_big, .line = number };
    if (lock.find_pin(lock.pin_file(&pin), lock.pin_step(&pin)) != null) {
        return .{ .kind = .duplicate, .line = number };
    }
    insert_pin(lock, pin);
    return null;
}

/// The lines that only shape the file: braces and the `.images = .{` opener.
fn is_structure(line: []const u8) bool {
    assert(line.len > 0);
    const names = [_][]const u8{ ".{", "}", "},", "}," };
    for (names) |name| {
        if (std.mem.eql(u8, line, name)) return true;
    }
    return false;
}

fn start_entry(lock: *Lock, value: []const u8) ?Entry {
    assert(lock.count <= constants.lock_entries_max);
    var word: [constants.reference_bytes_max]u8 = undefined;
    const length = roots.parse_string(value, &word) orelse return null;
    if (length == 0) return null;
    if (lock.pool_len + length > lock.pool.len) return null;
    const at = lock.pool_len;
    @memcpy(lock.pool[at..][0..length], word[0..length]);
    lock.pool_len += @intCast(length);
    return .{
        .reference_at = at,
        .reference_len = @intCast(length),
        .manifest = undefined,
        .tree = undefined,
        .platform = undefined,
        .platform_len = 0,
    };
}

fn set_field(entry: *Entry, fields: *Fields, key: []const u8, value: []const u8) bool {
    assert(entry.reference_len > 0);
    var word: [constants.store_digest_text_bytes + 8]u8 = undefined;
    const length = roots.parse_string(value, &word) orelse return false;
    const text = word[0..length];
    if (std.mem.eql(u8, key, "manifest")) {
        if (fields.manifest) return false;
        entry.manifest = Sha256.parse(text) orelse return false;
        fields.manifest = true;
    } else if (std.mem.eql(u8, key, "tree")) {
        if (fields.tree) return false;
        entry.tree = Digest.parse(text) orelse return false;
        fields.tree = true;
    } else if (std.mem.eql(u8, key, "platform")) {
        if (fields.platform) return false;
        if (text.len == 0 or text.len > entry.platform.len) return false;
        @memcpy(entry.platform[0..text.len], text);
        entry.platform_len = @intCast(text.len);
        fields.platform = true;
    } else {
        return false;
    }
    return true;
}

/// Adds the entry being read, if there is one: it must have its four fields and be new.
fn finish_entry(lock: *Lock, open: *?Entry, fields: Fields, number: u32) ?Problem {
    assert(number > 0);
    const entry = open.* orelse return null;
    open.* = null;
    if (!fields.complete()) return .{ .kind = .incomplete_entry, .line = number };
    if (lock.count == constants.lock_entries_max) return .{ .kind = .too_big, .line = number };
    const written = lock.pool[entry.reference_at..][0..entry.reference_len];
    // The reference was copied into the pool when the entry began, so the lock holds it; look
    // among the entries before this one.
    for (lock.entries[0..lock.count]) |*other| {
        if (same_reference(lock.reference(other), written)) {
            return .{ .kind = .duplicate, .line = number };
        }
    }
    var place: u32 = lock.count;
    while (place > 0 and std.mem.order(
        u8,
        lock.reference(&lock.entries[place - 1]),
        written,
    ) == .gt) {
        lock.entries[place] = lock.entries[place - 1];
        place -= 1;
    }
    lock.entries[place] = entry;
    lock.count += 1;
    return null;
}

// ---- Where it is, and the file -------------------------------------------------------------

/// The path of the lock to use.
pub const Located = struct {
    path: [constants.path_bytes_max + 1]u8,
    len: u32,
    /// The directory of the lock, without the file name or the last slash ("" for the root).
    directory_len: u32,
    /// Whether the file is there.
    exists: bool,

    pub fn text(located: *const Located) [:0]const u8 {
        assert(located.len > 0);
        assert(located.path[located.len] == 0);
        return located.path[0..located.len :0];
    }

    pub fn directory(located: *const Located) []const u8 {
        assert(located.directory_len < located.len);
        return located.path[0..located.directory_len];
    }

    fn set(located: *Located, directory_text: []const u8) bool {
        assert(directory_text.len < constants.path_bytes_max);
        // The root's directory is "": the path is "/zbx.lock".
        const trimmed = std.mem.trimEnd(u8, directory_text, "/");
        const total = trimmed.len + 1 + file_name.len;
        if (total > constants.path_bytes_max) return false;
        @memcpy(located.path[0..trimmed.len], trimmed);
        located.path[trimmed.len] = '/';
        @memcpy(located.path[trimmed.len + 1 ..][0..file_name.len], file_name);
        located.path[total] = 0;
        located.len = @intCast(total);
        located.directory_len = @intCast(trimmed.len);
        return true;
    }
};

pub const LocateError = error{ NoDirectory, TooLong };

/// The lock of the project: the nearest `zbx.lock` from the working directory up, else the
/// place for one in the working directory.
pub fn locate(host: Host, fs: Fs, located: *Located) LocateError!void {
    assert(located.path.len > constants.path_bytes_max);
    var cwd_storage: [constants.path_bytes_max]u8 = undefined;
    const cwd = host.working_directory(&cwd_storage) catch return error.NoDirectory;
    var directory: []const u8 = cwd;
    while (true) {
        if (!located.set(directory)) return error.TooLong;
        if (fs.lstat(located.text())) |stat| {
            if (stat.kind == .file) {
                located.exists = true;
                return;
            }
        } else |_| {}
        if (directory.len <= 1) break;
        const slash = std.mem.lastIndexOfScalar(u8, directory, '/') orelse break;
        directory = directory[0..slash];
    }
    if (!located.set(cwd)) return error.TooLong;
    located.exists = false;
}

pub const ReadError = error{ Unreadable, TooBig };

/// Reads the file at `located` into `lock`. `buffer` is `constants.lock_file_bytes_max`. A lock
/// that is not there is an empty one; whether the text is a lock is `parse`'s answer.
pub fn read(fs: Fs, located: *const Located, buffer: []u8, lock: *Lock) ReadError!?Problem {
    assert(buffer.len >= constants.lock_file_bytes_max);
    if (!located.exists) {
        lock.clear();
        return null;
    }
    const text = fs.read_whole(
        located.text(),
        buffer[0..constants.lock_file_bytes_max],
    ) catch |err| {
        return if (err == error.FileTooLarge) error.TooBig else error.Unreadable;
    };
    return parse(text, lock);
}

/// Writes the lock atomically: a temporary file in the same directory, flushed, renamed over.
pub fn write(
    host: Host,
    fs: Fs,
    located: *const Located,
    lock: *const Lock,
    buffer: []u8,
    failure: *fs_mod.Failure,
) host_mod.Error!void {
    assert(buffer.len >= constants.lock_file_bytes_max);
    const text = render(lock, buffer);
    var temporary: [constants.path_bytes_max + 1]u8 = undefined;
    const made = std.fmt.bufPrintSentinel(&temporary, "{s}/.{s}.{d}", .{
        located.directory(), file_name, host.own_pid(),
    }, 0) catch return fs.note(failure, error.FileTooLarge);
    // The directory to flush: its path, or "/" for the root.
    var directory_storage: [constants.path_bytes_max + 1]u8 = undefined;
    const shown = if (located.directory_len == 0) "/" else located.directory();
    const directory = std.fmt.bufPrintSentinel(&directory_storage, "{s}", .{shown}, 0) catch {
        return fs.note(failure, error.FileTooLarge);
    };
    try fs.write_atomic_stamped(made, located.text(), directory, text, 0o644, false, failure);
}

/// The lock of the project and the memory to read and write it in; the caller's.
pub const Workspace = struct {
    lock: Lock,
    text: [constants.lock_file_bytes_max]u8,
    located: Located,
};

/// Why the lock could not be opened or saved.
pub const Failure = union(enum) {
    /// The working directory is not known, or the lock's path is too long.
    no_directory,
    unreadable,
    problem: Problem,
    full,
    write: fs_mod.Failure,
};

pub const Error = error{Failed};

/// Finds the project's lock and reads it into `workspace.lock` (empty if there is none).
pub fn open_project(host: Host, fs: Fs, workspace: *Workspace, failure: *Failure) Error!void {
    assert(workspace.text.len == constants.lock_file_bytes_max);
    locate(host, fs, &workspace.located) catch {
        failure.* = .no_directory;
        return error.Failed;
    };
    const found = read(fs, &workspace.located, &workspace.text, &workspace.lock) catch {
        failure.* = .unreadable;
        return error.Failed;
    };
    if (found) |problem| {
        failure.* = .{ .problem = problem };
        return error.Failed;
    }
}

/// Writes `workspace.lock` to its place, atomically.
pub fn save(host: Host, fs: Fs, workspace: *Workspace, failure: *Failure) Error!void {
    assert(workspace.located.len > 0);
    var raised: fs_mod.Failure = undefined;
    write(host, fs, &workspace.located, &workspace.lock, &workspace.text, &raised) catch {
        failure.* = .{ .write = raised };
        return error.Failed;
    };
    workspace.located.exists = true;
}

const testing = std.testing;

fn digest_of(text: []const u8) Sha256 {
    return Sha256.of(text);
}

fn filled() Lock {
    var lock: Lock = undefined;
    lock.clear();
    return lock;
}

test "entries are kept sorted, and one image is one entry" {
    // Goal: put sorts; a second spelling of the same image replaces, and keeps the first text.
    var lock = filled();
    try lock.put("python:3.12-slim", digest_of("p"), "linux/amd64", Digest.of("pt"));
    try lock.put("alpine:3.20", digest_of("a"), "linux/amd64", Digest.of("at"));
    try lock.put("ghcr.io/o/i:v1", digest_of("g"), "linux/arm64", Digest.of("gt"));
    try testing.expectEqual(@as(u32, 3), lock.count);
    try testing.expectEqualStrings("alpine:3.20", lock.reference(&lock.entries[0]));
    try testing.expectEqualStrings("ghcr.io/o/i:v1", lock.reference(&lock.entries[1]));
    try testing.expectEqualStrings("python:3.12-slim", lock.reference(&lock.entries[2]));
    try lock.put("docker.io/library/alpine:3.20", digest_of("a2"), "linux/amd64", Digest.of("at2"));
    try testing.expectEqual(@as(u32, 3), lock.count);
    try testing.expectEqualStrings("alpine:3.20", lock.reference(&lock.entries[0]));
    try testing.expect(lock.entries[0].manifest.eql(digest_of("a2")));
    try testing.expectEqual(@as(?u32, 0), lock.find("docker.io/library/alpine:3.20"));
    try testing.expectEqual(@as(?u32, null), lock.find("alpine:3.19"));
    try testing.expectEqual(@as(?u32, null), lock.find("not a reference"));
}

test "a lock round-trips, and what it writes is ZON in the documented shape" {
    // Goal: render then parse gives the same entries; the text is the shape the header shows.
    var lock = filled();
    try lock.put("b:2", digest_of("b"), "linux/amd64", Digest.of("bt"));
    try lock.put("a:1", digest_of("a"), "linux/arm64", Digest.of("at"));
    var buffer: [constants.lock_file_bytes_max]u8 = undefined;
    const text = render(&lock, &buffer);
    try testing.expect(std.mem.startsWith(u8, text, ".{\n    .version = 1,\n    .images = .{\n"));
    try testing.expect(std.mem.indexOf(u8, text, ".reference = \"a:1\"").? <
        std.mem.indexOf(u8, text, ".reference = \"b:2\"").?);
    var back = filled();
    try testing.expectEqual(@as(?Problem, null), parse(text, &back));
    try testing.expectEqual(@as(u32, 2), back.count);
    try testing.expectEqualStrings("a:1", back.reference(&back.entries[0]));
    try testing.expect(back.entries[1].tree.eql(Digest.of("bt")));
    try testing.expectEqualStrings("linux/arm64", back.entries[0].platform_text());
    // Writing what was read gives the same bytes.
    var again: [constants.lock_file_bytes_max]u8 = undefined;
    try testing.expectEqualStrings(text, render(&back, &again));
}

fn problem_of(text: []const u8) ?Problem {
    var lock = filled();
    return parse(text, &lock);
}

fn entry_text(manifest: []const u8, tree: []const u8) [512]u8 {
    var out: [512]u8 = @splat(0);
    _ = std.fmt.bufPrint(&out, ".{{\n    .version = 1,\n    .images = .{{\n        .{{\n" ++
        "            .reference = \"a:1\",\n            .manifest = \"{s}\",\n" ++
        "            .platform = \"linux/amd64\",\n            .tree = \"{s}\",\n        }},\n" ++
        "    }},\n}}\n", .{ manifest, tree }) catch unreachable; // Short.
    return out;
}

test "a lock that is not one is refused, with the line" {
    // Goal: every ProblemKind, each at the right line.
    const good_manifest = digest_of("m").text();
    const good_tree = Digest.of("t").text();
    const ok = entry_text(&good_manifest, &good_tree);
    try testing.expectEqual(@as(?Problem, null), problem_of(std.mem.sliceTo(&ok, 0)));
    const bad_tree = entry_text(&good_manifest, "b3:12");
    const bad = problem_of(std.mem.sliceTo(&bad_tree, 0)).?;
    try testing.expectEqual(ProblemKind.bad_value, bad.kind);
    try testing.expectEqual(@as(u32, 8), problem_of(std.mem.sliceTo(&bad_tree, 0)).?.line);
    const wrong = entry_text("sha256:abc", &good_tree);
    try testing.expectEqual(@as(u32, 6), problem_of(std.mem.sliceTo(&wrong, 0)).?.line);
    try testing.expectEqual(ProblemKind.no_version, problem_of("").?.kind);
    try testing.expectEqual(ProblemKind.newer, problem_of(".{\n    .version = 3,\n}\n").?.kind);
    try testing.expectEqual(ProblemKind.unknown_line, problem_of(".{\n    hello\n}\n").?.kind);
    const cut = ".{\n    .version = 1,\n    .images = .{\n        .{\n" ++
        "            .reference = \"a:1\",\n";
    try testing.expectEqual(ProblemKind.incomplete_entry, problem_of(cut).?.kind);
    const twice = std.mem.sliceTo(&ok, 0)[0..std.mem.indexOf(u8, &ok, "    },\n}").?];
    var double_buffer: [1200]u8 = undefined;
    const doubled = try std.fmt.bufPrint(&double_buffer, "{s}{s}    }},\n}}\n", .{
        twice, twice[std.mem.indexOf(u8, twice, "        .{").?..],
    });
    try testing.expectEqual(ProblemKind.duplicate, problem_of(doubled).?.kind);
}

test "an edit by hand with other spacing still reads" {
    // Goal: the use case of the demo: a person changes a digest, maybe reformats.
    const good_manifest = digest_of("m").text();
    const good_tree = Digest.of("t").text();
    var buffer: [600]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer, ".{{\r\n\t.version = 1,\r\n\t.images = .{{\r\n" ++
        "\t\t.{{ \r\n\t\t\t.reference = \"a:1\",\r\n\t\t\t.tree = \"{s}\",\r\n" ++
        "\t\t\t.manifest = \"{s}\",\r\n\t\t\t.platform = \"linux/amd64\"\r\n" ++
        "\t\t}},\r\n\t}},\r\n}}\r\n", .{
        &good_tree, &good_manifest,
    });
    var lock = filled();
    try testing.expectEqual(@as(?Problem, null), parse(text, &lock));
    try testing.expectEqual(@as(u32, 1), lock.count);
}

test "the lock is full at its bounds" {
    // Goal: the entry bound is exact and says Full.
    var lock = filled();
    var name: [32]u8 = undefined;
    for (0..constants.lock_entries_max) |index| {
        const text = try std.fmt.bufPrint(&name, "img{d:0>4}:1", .{index});
        try lock.put(text, digest_of("x"), "linux/amd64", Digest.of("y"));
    }
    const more = lock.put("one-more:1", digest_of("x"), "linux/amd64", Digest.of("y"));
    try testing.expectError(error.Full, more);
    var buffer: [constants.lock_file_bytes_max]u8 = undefined;
    const text = render(&lock, &buffer);
    var back = filled();
    try testing.expectEqual(@as(?Problem, null), parse(text, &back));
    try testing.expectEqual(@as(u32, constants.lock_entries_max), back.count);
}

test "the worst reference still renders" {
    // Goal: the render buffer holds a lock of the longest, all-escaped references.
    var lock = filled();
    var long: [constants.reference_bytes_max]u8 = @splat('"');
    try lock.put(&long, digest_of("x"), "linux/amd64", Digest.of("y"));
    var buffer: [constants.lock_file_bytes_max]u8 = undefined;
    const text = render(&lock, &buffer);
    var back = filled();
    // The reference is not a valid one, but the file format carries any text.
    try testing.expectEqual(@as(?Problem, null), parse(text, &back));
    try testing.expectEqual(@as(u16, constants.reference_bytes_max), back.entries[0].reference_len);
}

test "the M7 and M9 locks read and write back byte for byte" {
    // Goal: a lock without pins is still exactly what M7 wrote (the version rule). Method: the
    // checked-in locks the VM demos use, parsed and rendered again.
    const texts = [_][]const u8{
        @embedFile("testing/vm/m7_project/zbx.lock"),
        @embedFile("testing/vm/m9_project/zbx.lock"),
    };
    for (texts) |text| {
        var lock = filled();
        try testing.expectEqual(@as(?Problem, null), parse(text, &lock));
        try testing.expectEqual(@as(u32, 0), lock.pin_count);
        var buffer: [constants.lock_file_bytes_max]u8 = undefined;
        try testing.expectEqualStrings(text, render(&lock, &buffer));
    }
}

test "pins are kept sorted by file then step, and round-trip as version 2" {
    // Goal: put_pin sorts and replaces; render writes version 2 with a .pins list that parses
    // back to the same pins; deleting every pin gives back the version 1 bytes.
    var lock = filled();
    try lock.put("alpine:3.20", digest_of("a"), "linux/amd64", Digest.of("at"));
    var before: [constants.lock_file_bytes_max]u8 = undefined;
    const plain = render(&lock, &before);
    try lock.put_pin("zbx.build.zon", "fetch", Digest.of("k1"), Digest.of("o1"));
    try lock.put_pin("drift.build.zon", "use", Digest.of("k2"), Digest.of("o2"));
    try lock.put_pin("drift.build.zon", "fetch", Digest.of("k3"), Digest.of("o3"));
    try lock.put_pin("zbx.build.zon", "fetch", Digest.of("k4"), Digest.of("o4"));
    try testing.expectEqual(@as(u32, 3), lock.pin_count);
    try testing.expectEqualStrings("fetch", lock.pin_step(&lock.pins[0]));
    try testing.expectEqualStrings("use", lock.pin_step(&lock.pins[1]));
    try testing.expectEqualStrings("zbx.build.zon", lock.pin_file(&lock.pins[2]));
    try testing.expect(lock.pins[2].output.eql(Digest.of("o4")));
    try testing.expect(lock.find_pin("zbx.build.zon", "use") == null);
    var buffer: [constants.lock_file_bytes_max]u8 = undefined;
    const text = render(&lock, &buffer);
    try testing.expect(std.mem.startsWith(u8, text, ".{\n    .version = 2,\n    .images = .{\n"));
    try testing.expect(std.mem.indexOf(u8, text, "    },\n    .pins = .{\n        .{\n" ++
        "            .file = \"drift.build.zon\",\n            .step = \"fetch\",\n") != null);
    var back = filled();
    try testing.expectEqual(@as(?Problem, null), parse(text, &back));
    try testing.expectEqual(@as(u32, 3), back.pin_count);
    try testing.expect(back.find_pin("drift.build.zon", "fetch").?.key.eql(Digest.of("k3")));
    var again: [constants.lock_file_bytes_max]u8 = undefined;
    try testing.expectEqualStrings(text, render(&back, &again));
    // Without pins, a version 2 lock is written as version 1, the bytes M7 wrote.
    back.pin_count = 0;
    try testing.expectEqualStrings(plain, render(&back, &again));
}

test "pins are refused in a version 1 lock, twice, or incomplete" {
    // Goal: parse accepts only what render writes: .pins needs .version = 2; a pin repeated or
    // missing a field is refused at its line; version 3 is newer.
    const pin = "    .pins = .{\n        .{\n            .file = \"f\",\n" ++
        "            .step = \"s\",\n            .key = \"" ++ Digest.of("k").text() ++
        "\",\n            .output = \"" ++ Digest.of("o").text() ++ "\",\n        },\n";
    const v2 = ".{\n    .version = 2,\n    .images = .{\n    },\n";
    const v1 = ".{\n    .version = 1,\n    .images = .{\n    },\n";
    try testing.expectEqual(@as(?Problem, null), problem_of(v2 ++ pin ++ "    },\n}\n"));
    const old = problem_of(v1 ++ pin ++ "    },\n}\n").?;
    try testing.expectEqual(ProblemKind.unknown_line, old.kind);
    try testing.expectEqual(@as(u32, 5), old.line);
    const second = "        .{\n            .file = \"f\",\n            .step = \"s\",\n" ++
        "            .key = \"" ++ Digest.of("k").text() ++ "\",\n            .output = \"" ++
        Digest.of("o").text() ++ "\",\n        },\n";
    const twice = problem_of(v2 ++ pin ++ second ++ "    },\n}\n").?;
    try testing.expectEqual(ProblemKind.duplicate, twice.kind);
    const cut = v2 ++ "    .pins = .{\n        .{\n            .file = \"f\",\n" ++
        "            .step = \"s\",\n        },\n    },\n}\n";
    try testing.expectEqual(ProblemKind.incomplete_entry, problem_of(cut).?.kind);
    const step_too_long: [constants.build_step_name_bytes_max + 1]u8 = @splat('s');
    const long_step = v2 ++ "    .pins = .{\n        .{\n            .file = \"f\",\n" ++
        "            .step = \"" ++ step_too_long ++ "\",\n";
    try testing.expectEqual(ProblemKind.bad_value, problem_of(long_step).?.kind);
}

test "a second .version, or a .step twice in a pin, is refused at its line" {
    // Goal: a version 2 lock cannot be unsaid by a later `.version = 1` (which used to reach the
    // pin-version assert), and a pin cannot name its step twice.
    const pin = "    .pins = .{\n        .{\n            .file = \"f\",\n" ++
        "            .step = \"s\",\n            .key = \"" ++ Digest.of("k").text() ++
        "\",\n            .output = \"" ++ Digest.of("o").text() ++ "\",\n        },\n";
    const v2 = ".{\n    .version = 2,\n    .images = .{\n    },\n";
    const after = problem_of(v2 ++ pin ++ "    },\n    .version = 1,\n}\n").?;
    try testing.expectEqual(ProblemKind.duplicate, after.kind);
    try testing.expectEqual(@as(u32, 13), after.line);
    const twice = problem_of(".{\n    .version = 1,\n    .version = 1,\n}\n").?;
    try testing.expectEqual(ProblemKind.duplicate, twice.kind);
    try testing.expectEqual(@as(u32, 3), twice.line);
    const zero = problem_of(".{\n    .version = 0,\n}\n").?;
    try testing.expectEqual(ProblemKind.bad_value, zero.kind);
    const step_twice = v2 ++ "    .pins = .{\n        .{\n            .file = \"f\",\n" ++
        "            .step = \"s\",\n            .step = \"t\",\n";
    const repeated = problem_of(step_twice).?;
    try testing.expectEqual(ProblemKind.bad_value, repeated.kind);
    try testing.expectEqual(@as(u32, 9), repeated.line);
}

test "the pins are full at lock_pins_max" {
    // Goal: the pin bound is exact: lock_pins_max pins fit, render and read back; one more is
    // Full, and a lock that reads that many pins plus one is too_big.
    var lock = filled();
    var name: [32]u8 = undefined;
    for (0..constants.lock_pins_max) |index| {
        const step = try std.fmt.bufPrint(&name, "s{d:0>4}", .{index});
        try lock.put_pin("zbx.build.zon", step, Digest.of("k"), Digest.of("o"));
    }
    const more = lock.put_pin("zbx.build.zon", "one-more", Digest.of("k"), Digest.of("o"));
    try testing.expectError(error.Full, more);
    var buffer: [constants.lock_file_bytes_max]u8 = undefined;
    const text = render(&lock, &buffer);
    var back = filled();
    try testing.expectEqual(@as(?Problem, null), parse(text, &back));
    try testing.expectEqual(@as(u32, constants.lock_pins_max), back.pin_count);
    var longer: [constants.lock_file_bytes_max]u8 = undefined;
    const end = std.mem.lastIndexOf(u8, text, "    },\n}\n").?;
    const pin_format = "{s}        .{{\n            .file = \"z\",\n" ++
        "            .step = \"z\",\n            .key = \"{s}\",\n" ++
        "            .output = \"{s}\",\n        }},\n    }},\n}}\n";
    const digests = .{ Digest.of("k").text(), Digest.of("o").text() };
    const values = .{ text[0..end], digests[0], digests[1] };
    const extra = try std.fmt.bufPrint(&longer, pin_format, values);
    try testing.expectEqual(ProblemKind.too_big, problem_of(extra).?.kind);
}

test "a lock whose rendering would pass the file bound is refused, not crashed on" {
    // Goal: parse refuses (too_big) a lock it could read but not write back: references full of
    // bytes that render escaped, read in their shortest written form.
    var text: [constants.lock_file_bytes_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&text);
    try writer.writeAll(".{\n.version = 1,\n");
    var index: u32 = 0;
    const manifest = digest_of("m").text();
    const tree = Digest.of("t").text();
    // Each reference is 99 bytes written `\x01`, which renders as the same four bytes a byte;
    // the rendering is longer by its indentation alone, which this form leaves out.
    var escaped: [396]u8 = undefined;
    for (0..99) |at| @memcpy(escaped[at * 4 ..][0..4], "\\x01");
    while (index < constants.lock_entries_max) : (index += 1) {
        try writer.print(".reference = \"{d:0>4}{s}\",\n.manifest = \"{s}\",\n" ++
            ".platform = \"linux/amd64\",\n.tree = \"{s}\",\n", .{
            index, &escaped, &manifest, &tree,
        });
    }
    try testing.expectEqual(ProblemKind.too_big, problem_of(writer.buffered()).?.kind);
}
