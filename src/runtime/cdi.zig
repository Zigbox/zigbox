//! CDI specs (M10 slice 2, docs/briefs/M10-gpu.md): the Container Device Interface's JSON spec
//! files, read into a fixed-capacity structure and resolved to the edits one run applies. This
//! file is pure: it reads text it is given and touches no host, so that Zigcube's agent can
//! resolve devices on its own host and hand the result to a run (`Resolved`, `Spec.cdi`).
//!
//! Of a device's container edits Zigbox applies `deviceNodes` (bound at their own path),
//! `mounts` (read-only binds), `env` and the one hook NVIDIA's specs carry,
//! `nvidia-cdi-hook update-ldcache`, which becomes the built-in `ldconfig` step. Every other
//! edit is parsed, remembered by name, and refused only when a device that has it is asked for
//! (ZBX-E0227): a spec may hold devices the user never uses. Zigbox never runs a host program
//! from a spec.
//!
//! Every bound is a named constant (`cdi_*` in `constants.zig`); exceeding one refuses the spec
//! (ZBX-E0226), never cuts it.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const devices_mod = @import("devices.zig");

pub const Text = struct {
    at: u32,
    len: u32,
};

/// An edit Zigbox does not apply.
pub const Unsupported = enum {
    none,
    /// A hook other than `nvidia-cdi-hook update-ldcache` at `createContainer`.
    hook,
    intel_rdt,
    additional_gids,
    /// A mount whose type is not a bind, or a node that is not a character device or whose
    /// `hostPath` is another path than its `path`.
    mount_type,
    node_kind,
    /// An edit key the parser does not know (`cgroupsPath`, ...).
    other,
    /// Two mounts at one container path from different host paths.
    mount_conflict,
    /// Mounts, in a run whose root is read-only (`--read-only`): there is no place to make
    /// their targets. Raised by the run, not by a spec's parse.
    read_only_mounts,

    pub fn sentence(edit: Unsupported) []const u8 {
        assert(@backingInt(edit) <= @backingInt(Unsupported.read_only_mounts));
        return switch (edit) {
            .none => "none",
            .hook => "a hook other than nvidia-cdi-hook update-ldcache",
            .intel_rdt => "an intelRdt edit",
            .additional_gids => "additionalGids",
            .mount_type => "a mount that is not a bind",
            .node_kind => "a device node that is not a character device at its own path",
            .other => "an edit Zigbox does not know",
            .mount_conflict => "two mounts at one path from different host paths",
            .read_only_mounts => "mounts, which a read-only root (--read-only) cannot take",
        };
    }
};

/// What a spec file lacks, by the file's text: why Zigbox cannot use it.
pub const Problem = enum {
    yaml,
    too_big,
    not_json,
    too_deep,
    string_too_long,
    wrong_type,
    version,
    kind,
    missing,
    device_name,
    device_repeated,
    path,
    env,
    too_many,
    unreadable,
    /// A mount source the host does not have, found when the run looks at it.
    stale,
    /// A node's host side cannot be used (checked by the run, `devices.look`).
    node,

    pub fn sentence(problem: Problem) []const u8 {
        assert(@backingInt(problem) <= @backingInt(Problem.node));
        return switch (problem) {
            .yaml => "YAML specs are not read",
            .too_big => "the file is over 256 KiB",
            .not_json => "it is not valid JSON",
            .too_deep => "it nests too deep, or has too many escaped strings",
            .string_too_long => "a string in it is over 1024 bytes",
            .wrong_type => "a field has the wrong type",
            .version => "cdiVersion is not 0.3.0 to 0.9.x",
            .kind => "kind is not vendor/class",
            .missing => "a required field is missing",
            .device_name => "a device name is not valid",
            .device_repeated => "a device name is given twice",
            .path => "a path is not valid here",
            .env => "an env entry is not NAME=VALUE",
            .too_many => "it holds more than Zigbox's bound of devices, nodes, mounts or variables",
            .unreadable => "it cannot be read",
            .stale => "a mount source it names is not on this host",
            .node => "a device node it names cannot be used",
        };
    }
};

/// The field a problem is at, for the diagnostic.
pub const Field = enum {
    document,
    cdi_version,
    kind,
    devices,
    device_name,
    container_edits,
    env,
    device_nodes,
    mounts,
    hooks,

    pub fn text(field: Field) []const u8 {
        assert(@backingInt(field) <= @backingInt(Field.hooks));
        return switch (field) {
            .document => "the document",
            .cdi_version => "cdiVersion",
            .kind => "kind",
            .devices => "devices",
            .device_name => "devices[].name",
            .container_edits => "containerEdits",
            .env => "containerEdits.env",
            .device_nodes => "containerEdits.deviceNodes",
            .mounts => "containerEdits.mounts",
            .hooks => "containerEdits.hooks",
        };
    }
};

pub const Node = struct { path: Text };
pub const Mount = struct { host: Text, container: Text };

/// The edits of one block (the spec's, or a device's): ranges into the spec's tables.
pub const Edits = struct {
    nodes_at: u32 = 0,
    nodes_count: u32 = 0,
    mounts_at: u32 = 0,
    mounts_count: u32 = 0,
    env_at: u32 = 0,
    env_count: u32 = 0,
    dirs_at: u32 = 0,
    dirs_count: u32 = 0,
    unsupported: Unsupported = .none,
    /// What the unsupported edit is, when it has a name (a hook's program, an edit's key).
    unsupported_name: Text = .{ .at = 0, .len = 0 },
};

pub const Device = struct { name: Text, edits: Edits };

/// One parsed spec, in tables of fixed size. Fill it with `parse`.
pub const Parsed = struct {
    kind: Text,
    devices_count: u32,
    devices: [constants.cdi_devices_max]Device,
    common: Edits,
    nodes_count: u32,
    nodes: [constants.cdi_nodes_max]Node,
    mounts_count: u32,
    mounts: [constants.cdi_mounts_max]Mount,
    env_count: u32,
    env: [constants.cdi_env_max]Text,
    dirs_count: u32,
    dirs: [constants.cdi_ldcache_dirs_max]Text,
    strings_len: u32,
    strings: [constants.cdi_strings_bytes_max]u8,
    scratch: [constants.cdi_scratch_bytes_max]u8,
    /// Why `parse` refused, and where.
    problem: Problem,
    field: Field,
    index: u32,

    pub fn slice(parsed: *const Parsed, text: Text) []const u8 {
        assert(text.at + text.len <= parsed.strings_len);
        return parsed.strings[text.at..][0..text.len];
    }
};

/// Why a spec file cannot be used, with its name, for E0226.
pub const FileProblem = struct {
    name: [64]u8,
    name_len: u8,
    problem: Problem,
    field: Field,
    index: u32,

    pub fn file(found: *const FileProblem) []const u8 {
        assert(found.name_len <= found.name.len);
        return found.name[0..found.name_len];
    }
};

// ---- Names ----------------------------------------------------------------------------------

fn is_alnum(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte);
}

/// A kind, `vendor.tld/class`: the vendor starts and ends with a letter or digit and holds
/// letters, digits, `-`, `_` and `.`; the class the same without the dot.
pub fn kind_valid(kind: []const u8) bool {
    if (kind.len == 0 or kind.len > constants.cdi_kind_bytes_max) return false;
    const slash = std.mem.indexOfScalar(u8, kind, '/') orelse return false;
    const vendor = kind[0..slash];
    const class = kind[slash + 1 ..];
    return part_valid(vendor, true) and part_valid(class, false);
}

fn part_valid(part: []const u8, dots: bool) bool {
    if (part.len == 0) return false;
    if (!is_alnum(part[0]) or !is_alnum(part[part.len - 1])) return false;
    for (part) |byte| {
        const punctuation = byte == '-' or byte == '_' or (dots and byte == '.');
        if (!is_alnum(byte) and !punctuation) return false;
    }
    return true;
}

/// A device name: starts with a letter or digit; then letters, digits, `_`, `-`, `.` and `:`.
pub fn device_name_valid(name: []const u8) bool {
    if (name.len == 0 or name.len > constants.cdi_device_name_bytes_max) return false;
    if (!is_alnum(name[0])) return false;
    for (name) |byte| {
        const punctuation = byte == '_' or byte == '-' or byte == '.' or byte == ':';
        if (!is_alnum(byte) and !punctuation) return false;
    }
    return true;
}

/// A qualified name `kind=name`, split; null when it is not one. Used for what `--device` gives
/// that does not start with `/dev/`.
pub const Qualified = struct { kind: []const u8, name: []const u8 };

pub fn split_qualified(text: []const u8) ?Qualified {
    if (text.len > constants.cdi_name_bytes_max) return null;
    const equals = std.mem.indexOfScalar(u8, text, '=') orelse return null;
    const kind = text[0..equals];
    const name = text[equals + 1 ..];
    if (!kind_valid(kind)) return null;
    if (!device_name_valid(name)) return null;
    return .{ .kind = kind, .name = name };
}

fn version_valid(version: []const u8) bool {
    var parts = std.mem.splitScalar(u8, version, '.');
    const major = parts.next() orelse return false;
    const minor_text = parts.next() orelse return false;
    const patch = parts.next() orelse return false;
    if (parts.next() != null) return false;
    if (!std.mem.eql(u8, major, "0")) return false;
    const minor = std.fmt.parseInt(u32, minor_text, 10) catch return false;
    _ = std.fmt.parseInt(u32, patch, 10) catch return false;
    return minor >= 3 and minor <= 9;
}

/// A path in a spec: absolute, no empty, `.` or `..` part, no trailing slash, only printable
/// ASCII without a space, quote or backslash, within `cdi_path_bytes_max`.
pub fn path_valid(path: []const u8) bool {
    if (path.len < 2 or path.len > constants.cdi_path_bytes_max) return false;
    if (path[0] != '/') return false;
    for (path) |byte| {
        const escaped = byte == '"' or byte == '\\';
        if (escaped or byte <= ' ' or byte >= 0x7f) return false;
    }
    var parts = std.mem.splitScalar(u8, path[1..], '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) {
            return false;
        }
    }
    return true;
}

/// `NAME=VALUE`: a name of letters, digits and `_` not starting with a digit, and a value of
/// printable ASCII (a space is fine; no quote or backslash, which the record would escape).
pub fn env_valid(entry: []const u8) bool {
    const equals = std.mem.indexOfScalar(u8, entry, '=') orelse return false;
    const name = entry[0..equals];
    if (name.len == 0 or name.len > constants.env_name_bytes_max) return false;
    if (std.ascii.isDigit(name[0])) return false;
    for (name) |byte| {
        if (!is_alnum(byte) and byte != '_') return false;
    }
    const value = entry[equals + 1 ..];
    if (value.len > constants.env_value_bytes_max) return false;
    for (value) |byte| {
        const escaped = byte == '"' or byte == '\\';
        if (escaped or byte < ' ' or byte >= 0x7f) return false;
    }
    return true;
}

// ---- Parsing --------------------------------------------------------------------------------

const Refused = error{Refused};
const Token = std.json.Token;

/// The scanner and where it has got to. `fba` serves the scanner's stack and escaped strings.
const Reader = struct {
    parsed: *Parsed,
    scanner: std.json.Scanner,
    fba: std.heap.FixedBufferAllocator,

    fn refuse(reader: *Reader, problem: Problem, field: Field) Refused {
        reader.parsed.problem = problem;
        reader.parsed.field = field;
        return error.Refused;
    }

    fn next(reader: *Reader, field: Field) Refused!Token {
        const max = constants.cdi_string_bytes_max;
        const allocator = reader.fba.allocator();
        const token = reader.scanner.nextAllocMax(allocator, .alloc_if_needed, max) catch |err| {
            const problem: Problem = switch (err) {
                error.OutOfMemory => .too_deep,
                error.ValueTooLong => .string_too_long,
                else => .not_json,
            };
            return reader.refuse(problem, field);
        };
        if (reader.scanner.stackHeight() > constants.cdi_depth_max) {
            return reader.refuse(.too_deep, field);
        }
        return token;
    }

    /// The next token must be a string; its bytes are valid until the next call.
    fn string(reader: *Reader, field: Field) Refused![]const u8 {
        const token = try reader.next(field);
        return switch (token) {
            .string => |text| text,
            .allocated_string => |text| text,
            else => reader.refuse(.wrong_type, field),
        };
    }

    fn skip(reader: *Reader, field: Field) Refused!void {
        reader.scanner.skipValue() catch |err| {
            const problem: Problem = if (err == error.OutOfMemory) .too_deep else .not_json;
            return reader.refuse(problem, field);
        };
    }

    /// Copies `text` into the spec's string table.
    fn keep(reader: *Reader, text: []const u8, field: Field) Refused!Text {
        const parsed = reader.parsed;
        const room = constants.cdi_strings_bytes_max - parsed.strings_len;
        if (text.len > room) return reader.refuse(.too_many, field);
        const at = parsed.strings_len;
        @memcpy(parsed.strings[at..][0..text.len], text);
        parsed.strings_len += @intCast(text.len);
        return .{ .at = at, .len = @intCast(text.len) };
    }
};

/// Reads a CDI spec's JSON `input` into `parsed`. Null when it was read; else why not, in
/// `parsed.problem` and `parsed.field`.
pub fn parse(parsed: *Parsed, input: []const u8) ?Problem {
    parsed.kind = .{ .at = 0, .len = 0 };
    parsed.devices_count = 0;
    parsed.common = .{};
    parsed.nodes_count = 0;
    parsed.mounts_count = 0;
    parsed.env_count = 0;
    parsed.dirs_count = 0;
    parsed.strings_len = 0;
    parsed.problem = .not_json;
    parsed.field = .document;
    parsed.index = 0;
    if (input.len > constants.cdi_spec_bytes_max) return .too_big;
    var reader: Reader = .{
        .parsed = parsed,
        .fba = std.heap.FixedBufferAllocator.init(&parsed.scratch),
        .scanner = undefined,
    };
    reader.scanner = std.json.Scanner.initCompleteInput(reader.fba.allocator(), input);
    parse_document(&reader) catch return parsed.problem;
    assert(parsed.kind.len > 0);
    assert(parsed.devices_count > 0);
    return null;
}

fn parse_document(reader: *Reader) Refused!void {
    assert(reader.parsed.devices_count <= constants.cdi_devices_max);
    const parsed = reader.parsed;
    var seen_version = false;
    try expect(reader, .object_begin, .document);
    while (true) {
        const key = try object_key(reader, .document);
        if (key == null) break;
        if (std.mem.eql(u8, key.?, "cdiVersion")) {
            const version = try reader.string(.cdi_version);
            if (!version_valid(version)) return reader.refuse(.version, .cdi_version);
            seen_version = true;
        } else if (std.mem.eql(u8, key.?, "kind")) {
            const kind = try reader.string(.kind);
            if (!kind_valid(kind)) return reader.refuse(.kind, .kind);
            parsed.kind = try reader.keep(kind, .kind);
        } else if (std.mem.eql(u8, key.?, "devices")) {
            try parse_devices(reader);
        } else if (std.mem.eql(u8, key.?, "containerEdits")) {
            parsed.common = try parse_edits(reader);
        } else try reader.skip(.document);
    }
    const end = try reader.next(.document);
    if (end != .end_of_document) return reader.refuse(.not_json, .document);
    if (!seen_version) return reader.refuse(.missing, .cdi_version);
    if (parsed.kind.len == 0) return reader.refuse(.missing, .kind);
    if (parsed.devices_count == 0) return reader.refuse(.missing, .devices);
}

/// The next token must be `want`.
fn expect(reader: *Reader, want: std.meta.Tag(Token), field: Field) Refused!void {
    const token = try reader.next(field);
    if (std.meta.activeTag(token) != want) return reader.refuse(.wrong_type, field);
}

/// The next key of an object, or null at its end. The bytes are valid until the next call.
fn object_key(reader: *Reader, field: Field) Refused!?[]const u8 {
    const token = try reader.next(field);
    return switch (token) {
        .object_end => null,
        .string => |text| text,
        .allocated_string => |text| text,
        else => reader.refuse(.not_json, field),
    };
}

fn parse_devices(reader: *Reader) Refused!void {
    assert(reader.parsed.devices_count <= constants.cdi_devices_max);
    const parsed = reader.parsed;
    try expect(reader, .array_begin, .devices);
    while (true) {
        const token = try reader.next(.devices);
        if (token == .array_end) return;
        if (token != .object_begin) return reader.refuse(.wrong_type, .devices);
        if (parsed.devices_count == constants.cdi_devices_max) {
            return reader.refuse(.too_many, .devices);
        }
        const at = parsed.devices_count;
        parsed.index = at;
        parsed.devices[at] = .{ .name = .{ .at = 0, .len = 0 }, .edits = .{} };
        try parse_device(reader, &parsed.devices[at]);
        if (parsed.devices[at].name.len == 0) return reader.refuse(.missing, .device_name);
        for (parsed.devices[0..at]) |before| {
            const named = parsed.slice(parsed.devices[at].name);
            const same = std.mem.eql(u8, parsed.slice(before.name), named);
            if (same) return reader.refuse(.device_repeated, .device_name);
        }
        parsed.devices_count += 1;
    }
}

fn parse_device(reader: *Reader, device: *Device) Refused!void {
    while (true) {
        const key = try object_key(reader, .devices);
        if (key == null) return;
        if (std.mem.eql(u8, key.?, "name")) {
            const name = try reader.string(.device_name);
            if (!device_name_valid(name)) return reader.refuse(.device_name, .device_name);
            device.name = try reader.keep(name, .device_name);
        } else if (std.mem.eql(u8, key.?, "containerEdits")) {
            device.edits = try parse_edits(reader);
        } else try reader.skip(.devices);
    }
}

/// A `containerEdits` object (or null, which is none): the ranges it adds to the tables.
fn parse_edits(reader: *Reader) Refused!Edits {
    const parsed = reader.parsed;
    var edits: Edits = .{
        .nodes_at = parsed.nodes_count,
        .mounts_at = parsed.mounts_count,
        .env_at = parsed.env_count,
        .dirs_at = parsed.dirs_count,
    };
    const first = try reader.next(.container_edits);
    if (first == .null) return edits;
    if (first != .object_begin) return reader.refuse(.wrong_type, .container_edits);
    while (true) {
        const key = try object_key(reader, .container_edits);
        if (key == null) break;
        if (std.mem.eql(u8, key.?, "env")) {
            try parse_env(reader);
        } else if (std.mem.eql(u8, key.?, "deviceNodes")) {
            try parse_nodes(reader, &edits);
        } else if (std.mem.eql(u8, key.?, "mounts")) {
            try parse_mounts(reader, &edits);
        } else if (std.mem.eql(u8, key.?, "hooks")) {
            try parse_hooks(reader, &edits);
        } else if (std.mem.eql(u8, key.?, "intelRdt")) {
            try note_unsupported(reader, &edits, .intel_rdt, null);
            try reader.skip(.container_edits);
        } else if (std.mem.eql(u8, key.?, "additionalGids")) {
            try parse_gids(reader, &edits);
        } else {
            try note_unsupported(reader, &edits, .other, key.?);
            try reader.skip(.container_edits);
        }
    }
    edits.nodes_count = parsed.nodes_count - edits.nodes_at;
    edits.mounts_count = parsed.mounts_count - edits.mounts_at;
    edits.env_count = parsed.env_count - edits.env_at;
    edits.dirs_count = parsed.dirs_count - edits.dirs_at;
    return edits;
}

/// Remembers the first edit of a block that Zigbox does not apply.
fn note_unsupported(
    reader: *Reader,
    edits: *Edits,
    edit: Unsupported,
    name: ?[]const u8,
) Refused!void {
    assert(edit != .none);
    if (edits.unsupported != .none) return;
    edits.unsupported = edit;
    if (name) |text| {
        const cut = text[0..@min(text.len, 48)];
        edits.unsupported_name = try reader.keep(cut, .container_edits);
    }
}

fn parse_env(reader: *Reader) Refused!void {
    assert(reader.parsed.strings_len <= constants.cdi_spec_bytes_max);
    const parsed = reader.parsed;
    try expect(reader, .array_begin, .env);
    while (true) {
        const token = try reader.next(.env);
        const entry = switch (token) {
            .array_end => return,
            .string => |text| text,
            .allocated_string => |text| text,
            else => return reader.refuse(.wrong_type, .env),
        };
        if (!env_valid(entry)) return reader.refuse(.env, .env);
        if (parsed.env_count == constants.cdi_env_max) return reader.refuse(.too_many, .env);
        parsed.env[parsed.env_count] = try reader.keep(entry, .env);
        parsed.env_count += 1;
    }
}

fn parse_nodes(reader: *Reader, edits: *Edits) Refused!void {
    assert(reader.parsed.strings_len <= constants.cdi_spec_bytes_max);
    const parsed = reader.parsed;
    try expect(reader, .array_begin, .device_nodes);
    while (true) {
        const token = try reader.next(.device_nodes);
        if (token == .array_end) return;
        if (token != .object_begin) return reader.refuse(.wrong_type, .device_nodes);
        var path: ?Text = null;
        // A `hostPath` that comes before `path` is kept, and compared once the object is read.
        var early_host: ?Text = null;
        while (try object_key(reader, .device_nodes)) |key| {
            if (std.mem.eql(u8, key, "path")) {
                const text = try reader.string(.device_nodes);
                if (devices_mod.path_problem(text) != null) {
                    return reader.refuse(.path, .device_nodes);
                }
                path = try reader.keep(text, .device_nodes);
            } else if (std.mem.eql(u8, key, "hostPath")) {
                const text = try reader.string(.device_nodes);
                if (path) |known| {
                    const own = std.mem.eql(u8, parsed.slice(known), text);
                    if (!own) try note_unsupported(reader, edits, .node_kind, null);
                } else early_host = try reader.keep(text, .device_nodes);
            } else if (std.mem.eql(u8, key, "type")) {
                const text = try reader.string(.device_nodes);
                const character = text.len == 0 or std.mem.eql(u8, text, "c");
                if (!character) try note_unsupported(reader, edits, .node_kind, null);
            } else try reader.skip(.device_nodes);
        }
        const found = path orelse return reader.refuse(.missing, .device_nodes);
        if (early_host) |host_text| {
            const own = std.mem.eql(u8, parsed.slice(host_text), parsed.slice(found));
            if (!own) try note_unsupported(reader, edits, .node_kind, null);
        }
        if (parsed.nodes_count == constants.cdi_nodes_max) {
            return reader.refuse(.too_many, .device_nodes);
        }
        parsed.nodes[parsed.nodes_count] = .{ .path = found };
        parsed.nodes_count += 1;
    }
}

fn parse_mounts(reader: *Reader, edits: *Edits) Refused!void {
    assert(reader.parsed.strings_len <= constants.cdi_spec_bytes_max);
    const parsed = reader.parsed;
    try expect(reader, .array_begin, .mounts);
    while (true) {
        const token = try reader.next(.mounts);
        if (token == .array_end) return;
        if (token != .object_begin) return reader.refuse(.wrong_type, .mounts);
        var host: ?Text = null;
        var container: ?Text = null;
        while (try object_key(reader, .mounts)) |key| {
            if (std.mem.eql(u8, key, "hostPath")) {
                const text = try reader.string(.mounts);
                if (!path_valid(text)) return reader.refuse(.path, .mounts);
                host = try reader.keep(text, .mounts);
            } else if (std.mem.eql(u8, key, "containerPath")) {
                const text = try reader.string(.mounts);
                if (!path_valid(text)) return reader.refuse(.path, .mounts);
                container = try reader.keep(text, .mounts);
            } else if (std.mem.eql(u8, key, "type")) {
                const text = try reader.string(.mounts);
                const bind = text.len == 0 or std.mem.eql(u8, text, "bind");
                if (!bind) try note_unsupported(reader, edits, .mount_type, null);
            } else try reader.skip(.mounts); // `options`: a bind is read-only here whatever.
        }
        const found_host = host orelse return reader.refuse(.missing, .mounts);
        const found_container = container orelse return reader.refuse(.missing, .mounts);
        if (parsed.mounts_count == constants.cdi_mounts_max) {
            return reader.refuse(.too_many, .mounts);
        }
        parsed.mounts[parsed.mounts_count] = .{ .host = found_host, .container = found_container };
        parsed.mounts_count += 1;
    }
}

fn parse_gids(reader: *Reader, edits: *Edits) Refused!void {
    try expect(reader, .array_begin, .container_edits);
    const first = try reader.next(.container_edits);
    if (first == .array_end) return;
    try note_unsupported(reader, edits, .additional_gids, null);
    // The rest of the array is read and dropped, token by token, to its end.
    var token = first;
    while (token != .array_end) token = try reader.next(.container_edits);
}

/// Reads the hooks array: only `createContainer` `nvidia-cdi-hook update-ldcache` is applied.
fn parse_hooks(reader: *Reader, edits: *Edits) Refused!void {
    try expect(reader, .array_begin, .hooks);
    while (true) {
        const token = try reader.next(.hooks);
        if (token == .array_end) return;
        if (token != .object_begin) return reader.refuse(.wrong_type, .hooks);
        var hook: HookFacts = .{};
        while (try object_key(reader, .hooks)) |key| {
            if (std.mem.eql(u8, key, "hookName")) {
                const text = try reader.string(.hooks);
                hook.create_container = std.mem.eql(u8, text, "createContainer");
            } else if (std.mem.eql(u8, key, "path")) {
                hook.program = try program_of(reader, try reader.string(.hooks));
            } else if (std.mem.eql(u8, key, "args")) {
                try parse_hook_args(reader, edits, &hook);
            } else try reader.skip(.hooks);
        }
        try judge_hook(reader, edits, &hook);
    }
}

const Program = enum { other, nvidia_cdi_hook, nvidia_ctk };

fn program_of(reader: *Reader, path: []const u8) Refused!Program {
    _ = reader;
    const slash = std.mem.lastIndexOfScalar(u8, path, '/');
    const base = if (slash) |at| path[at + 1 ..] else path;
    if (std.mem.eql(u8, base, "nvidia-cdi-hook")) return .nvidia_cdi_hook;
    if (std.mem.eql(u8, base, "nvidia-ctk")) return .nvidia_ctk;
    return .other;
}

const HookFacts = struct {
    create_container: bool = false,
    program: Program = .other,
    update_ldcache: bool = false,
    /// Library directories this hook adds (`--folder`), counted into `edits.dirs_count` later.
    dirs_added: u32 = 0,
    /// The hook's arguments hold something the update does not take.
    stray: bool = false,
};

/// The hook's args: `[program, update-ldcache, --folder, dir, ...]`, with `hook` between for
/// `nvidia-ctk`. Directories are kept in the tables as they come; if the hook turns out not to
/// be the one Zigbox applies they are rolled back by `judge_hook`.
fn parse_hook_args(reader: *Reader, edits: *Edits, hook: *HookFacts) Refused!void {
    _ = edits;
    const parsed = reader.parsed;
    try expect(reader, .array_begin, .hooks);
    var position: u32 = 0;
    var want_folder = false;
    while (true) {
        const token = try reader.next(.hooks);
        const arg = switch (token) {
            .array_end => return,
            .string => |text| text,
            .allocated_string => |text| text,
            else => return reader.refuse(.wrong_type, .hooks),
        };
        defer position += 1;
        if (position == 0) continue; // The program's own name.
        if (want_folder) {
            want_folder = false;
            if (!path_valid(arg)) return reader.refuse(.path, .hooks);
            if (parsed.dirs_count == constants.cdi_ldcache_dirs_max) {
                return reader.refuse(.too_many, .hooks);
            }
            parsed.dirs[parsed.dirs_count] = try reader.keep(arg, .hooks);
            parsed.dirs_count += 1;
            hook.dirs_added += 1;
        } else if (std.mem.eql(u8, arg, "update-ldcache")) {
            hook.update_ldcache = true;
        } else if (std.mem.eql(u8, arg, "--folder")) {
            want_folder = true;
        } else if (!std.mem.eql(u8, arg, "hook")) {
            hook.stray = true; // `--ldconfig-path=...` and the like: not applied.
        }
    }
}

/// Whether a parsed hook is the one Zigbox applies; if it is not, its directories are dropped
/// again and the edit is noted as unsupported.
fn judge_hook(reader: *Reader, edits: *Edits, hook: *const HookFacts) Refused!void {
    const parsed = reader.parsed;
    const known = hook.program != .other and hook.create_container and hook.update_ldcache;
    if (known) return;
    assert(parsed.dirs_count >= hook.dirs_added);
    parsed.dirs_count -= hook.dirs_added;
    try note_unsupported(reader, edits, .hook, null);
}

// ---- Resolution -----------------------------------------------------------------------------

/// What one run applies, merged from the devices it asked for. Text is NUL-ended in `strings`.
pub const Resolved = struct {
    nodes_count: u32,
    nodes: [constants.cdi_run_nodes_max]Text,
    /// The asked device (an index into the asked list) that first needed each mount, so that a
    /// refusal names that one.
    mount_owner: [constants.cdi_run_mounts_max]u8,
    mounts_count: u32,
    mounts: [constants.cdi_run_mounts_max]Mount,
    /// Whether each mount's source is a directory; set by the run, which looks at the host.
    mount_is_dir: [constants.cdi_run_mounts_max]bool,
    env_count: u32,
    env: [constants.cdi_run_env_max]Text,
    dirs_count: u32,
    dirs: [constants.cdi_run_dirs_max]Text,
    strings_len: u32,
    strings: [constants.cdi_run_strings_bytes_max]u8,

    pub fn reset(resolved: *Resolved) void {
        resolved.nodes_count = 0;
        @memset(&resolved.mount_owner, 0);
        resolved.mounts_count = 0;
        resolved.env_count = 0;
        resolved.dirs_count = 0;
        resolved.strings_len = 0;
    }

    pub fn text(resolved: *const Resolved, item: Text) [:0]const u8 {
        assert(item.at + item.len < resolved.strings_len);
        assert(resolved.strings[item.at + item.len] == 0);
        return resolved.strings[item.at..][0..item.len :0];
    }

    pub fn is_empty(resolved: *const Resolved) bool {
        return resolved.nodes_count + resolved.mounts_count + resolved.env_count +
            resolved.dirs_count == 0;
    }

    pub fn keep(resolved: *Resolved, bytes: []const u8) ?Text {
        const room = constants.cdi_run_strings_bytes_max - resolved.strings_len;
        if (bytes.len + 1 > room) return null;
        const at = resolved.strings_len;
        @memcpy(resolved.strings[at..][0..bytes.len], bytes);
        resolved.strings[at + bytes.len] = 0;
        resolved.strings_len += @intCast(bytes.len + 1);
        return .{ .at = at, .len = @intCast(bytes.len) };
    }
};

/// Why a run's devices cannot be resolved.
pub const Refusal = union(enum) {
    /// The asked device (an index into the asked list) is in no spec.
    unknown: u32,
    /// The asked device has an edit Zigbox does not apply.
    unsupported: struct { index: u32, edit: Unsupported, name: [48]u8, name_len: u8 },
    /// What the devices ask for together is over a bound of `Resolved`.
    too_big: u32,
    /// The spec directories hold more files than a run reads (`cdi_dir_entries_max`).
    too_many_files,
};

/// Resolves the devices a run asked for, one spec file at a time: `add_file` for each file found,
/// then `finish`. The caller supplies the scratch (`Parsed` is 150 KiB) and the asked list, which
/// holds the qualified names (`kind=name`) only.
pub const Resolver = struct {
    asked: []const []const u8,
    parsed: *Parsed,
    out: *Resolved,
    found: [constants.run_devices_max]bool,
    problems: [constants.cdi_spec_files_max]FileProblem,
    problems_count: u32,
    /// `kind=name` of the devices of the specs read, for E0230; the first `cdi_names_listed_max`.
    known: [constants.cdi_names_listed_max][constants.cdi_name_bytes_max]u8,
    known_len: [constants.cdi_names_listed_max]u8,
    known_count: u32,

    pub fn init(
        resolver: *Resolver,
        asked: []const []const u8,
        parsed: *Parsed,
        out: *Resolved,
    ) void {
        assert(asked.len <= constants.run_devices_max);
        for (asked) |name| assert(split_qualified(name) != null);
        resolver.asked = asked;
        resolver.parsed = parsed;
        resolver.out = out;
        resolver.found = @splat(false);
        resolver.problems_count = 0;
        resolver.known_count = 0;
        out.reset();
    }

    pub fn problem_slice(resolver: *const Resolver) []const FileProblem {
        assert(resolver.problems_count <= constants.cdi_spec_files_max);
        return resolver.problems[0..resolver.problems_count];
    }

    pub fn known_name(resolver: *const Resolver, index: u32) []const u8 {
        assert(index < resolver.known_count);
        return resolver.known[index][0..resolver.known_len[index]];
    }

    /// Notes a file that could not be read or whose name says it is not JSON.
    pub fn refuse_file(resolver: *Resolver, name: []const u8, problem: Problem) void {
        resolver.note_problem(name, problem, .document, 0);
    }

    fn note_problem(
        resolver: *Resolver,
        name: []const u8,
        problem: Problem,
        field: Field,
        index: u32,
    ) void {
        if (resolver.problems_count == constants.cdi_spec_files_max) return;
        const at = &resolver.problems[resolver.problems_count];
        const length = @min(name.len, at.name.len);
        @memcpy(at.name[0..length], name[0..length]);
        at.name_len = @intCast(length);
        at.problem = problem;
        at.field = field;
        at.index = index;
        resolver.problems_count += 1;
    }

    /// Reads one spec file. A file that cannot be used is noted (`problem_slice`) and skipped; a
    /// refusal comes only from a device the run asked for.
    pub fn add_file(resolver: *Resolver, name: []const u8, content: []const u8) ?Refusal {
        assert(content.len <= constants.cdi_spec_bytes_max);
        assert(name.len > 0);
        const parsed = resolver.parsed;
        const yaml = std.mem.endsWith(u8, name, ".yaml");
        const lower_yaml = yaml or std.mem.endsWith(u8, name, ".yml");
        if (lower_yaml) {
            resolver.note_problem(name, .yaml, .document, 0);
            return null;
        }
        if (parse(parsed, content)) |problem| {
            resolver.note_problem(name, problem, parsed.field, parsed.index);
            return null;
        }
        resolver.note_names(parsed);
        var common_taken = false;
        for (resolver.asked, 0..) |asked, index| {
            if (resolver.found[index]) continue;
            const split = split_qualified(asked).?;
            if (!std.mem.eql(u8, split.kind, parsed.slice(parsed.kind))) continue;
            const refusal = resolver.take(@intCast(index), split.name, &common_taken);
            if (refusal != null) return refusal;
        }
        return null;
    }

    /// After every file: the first asked device that no spec has.
    pub fn finish(resolver: *const Resolver) ?Refusal {
        assert(resolver.asked.len <= constants.run_devices_max);
        assert(resolver.problems_count <= constants.cdi_spec_files_max);
        for (resolver.asked, 0..) |_, index| {
            if (!resolver.found[index]) return .{ .unknown = @intCast(index) };
        }
        return null;
    }

    fn note_names(resolver: *Resolver, parsed: *const Parsed) void {
        for (parsed.devices[0..parsed.devices_count]) |device| {
            if (resolver.known_count == constants.cdi_names_listed_max) return;
            const at = resolver.known_count;
            const kind = parsed.slice(parsed.kind);
            const name = parsed.slice(device.name);
            const buffer = &resolver.known[at];
            const printed = std.fmt.bufPrint(buffer, "{s}={s}", .{ kind, name }) catch continue;
            resolver.known_len[at] = @intCast(printed.len);
            resolver.known_count += 1;
        }
    }

    /// Takes the device `name` of the current spec for the asked device `index`: the device, or
    /// for `all` without a device of that name, every device of the spec.
    fn take(resolver: *Resolver, index: u32, name: []const u8, common_taken: *bool) ?Refusal {
        assert(index < resolver.asked.len);
        const parsed = resolver.parsed;
        var matched: u32 = 0;
        for (parsed.devices[0..parsed.devices_count]) |*device| {
            if (!std.mem.eql(u8, parsed.slice(device.name), name)) continue;
            matched += 1;
            if (resolver.apply(index, device, common_taken)) |refusal| return refusal;
        }
        if (matched == 0 and std.mem.eql(u8, name, "all")) {
            for (parsed.devices[0..parsed.devices_count]) |*device| {
                if (resolver.apply(index, device, common_taken)) |refusal| return refusal;
                matched += 1;
            }
        }
        resolver.found[index] = matched > 0;
        return null;
    }

    fn apply(
        resolver: *Resolver,
        index: u32,
        device: *const Device,
        common_taken: *bool,
    ) ?Refusal {
        const parsed = resolver.parsed;
        if (!common_taken.*) {
            common_taken.* = true;
            if (resolver.merge(index, &parsed.common)) |refusal| return refusal;
        }
        return resolver.merge(index, &device.edits);
    }

    /// Adds one block of edits to the run's, once each by node path and container path; the
    /// later value of a variable replaces the earlier.
    fn merge(resolver: *Resolver, index: u32, edits: *const Edits) ?Refusal {
        assert(index < resolver.asked.len);
        const parsed = resolver.parsed;
        if (edits.unsupported != .none) return refusal_of(parsed, index, edits);
        for (parsed.nodes[edits.nodes_at..][0..edits.nodes_count]) |node| {
            if (!resolver.add_node(parsed.slice(node.path))) return .{ .too_big = index };
        }
        for (parsed.mounts[edits.mounts_at..][0..edits.mounts_count]) |mount| {
            const host = parsed.slice(mount.host);
            const container = parsed.slice(mount.container);
            const added = resolver.add_mount(host, container, index);
            switch (added) {
                .added, .same => {},
                .conflict => return conflict_of(index, container),
                .full => return .{ .too_big = index },
            }
        }
        for (parsed.env[edits.env_at..][0..edits.env_count]) |entry| {
            if (!resolver.add_env(parsed.slice(entry))) return .{ .too_big = index };
        }
        for (parsed.dirs[edits.dirs_at..][0..edits.dirs_count]) |dir| {
            if (!resolver.add_dir(parsed.slice(dir))) return .{ .too_big = index };
        }
        return null;
    }

    fn add_node(resolver: *Resolver, path: []const u8) bool {
        assert(path_valid(path));
        assert(resolver.out.nodes_count <= constants.cdi_run_nodes_max);
        const out = resolver.out;
        for (out.nodes[0..out.nodes_count]) |node| {
            if (std.mem.eql(u8, out.text(node), path)) return true;
        }
        if (out.nodes_count == constants.cdi_run_nodes_max) return false;
        out.nodes[out.nodes_count] = out.keep(path) orelse return false;
        out.nodes_count += 1;
        return true;
    }

    const Added = enum { added, same, conflict, full };

    fn add_mount(resolver: *Resolver, host: []const u8, container: []const u8, owner: u32) Added {
        assert(path_valid(container));
        assert(resolver.out.mounts_count <= constants.cdi_run_mounts_max);
        const out = resolver.out;
        for (out.mounts[0..out.mounts_count]) |mount| {
            if (!std.mem.eql(u8, out.text(mount.container), container)) continue;
            return if (std.mem.eql(u8, out.text(mount.host), host)) .same else .conflict;
        }
        if (out.mounts_count == constants.cdi_run_mounts_max) return .full;
        const kept_host = out.keep(host) orelse return .full;
        const kept_container = out.keep(container) orelse return .full;
        out.mounts[out.mounts_count] = .{ .host = kept_host, .container = kept_container };
        out.mount_is_dir[out.mounts_count] = false;
        out.mount_owner[out.mounts_count] = @intCast(owner);
        out.mounts_count += 1;
        return .added;
    }

    fn add_env(resolver: *Resolver, entry: []const u8) bool {
        assert(env_valid(entry));
        assert(resolver.out.env_count <= constants.cdi_run_env_max);
        const out = resolver.out;
        const name = entry[0 .. std.mem.indexOfScalar(u8, entry, '=').? + 1];
        const kept = out.keep(entry) orelse return false;
        for (out.env[0..out.env_count]) |*present| {
            if (!std.mem.startsWith(u8, out.text(present.*), name)) continue;
            present.* = kept; // The later one wins.
            return true;
        }
        if (out.env_count == constants.cdi_run_env_max) return false;
        out.env[out.env_count] = kept;
        out.env_count += 1;
        return true;
    }

    fn add_dir(resolver: *Resolver, path: []const u8) bool {
        assert(path_valid(path));
        assert(resolver.out.dirs_count <= constants.cdi_run_dirs_max);
        const out = resolver.out;
        for (out.dirs[0..out.dirs_count]) |dir| {
            if (std.mem.eql(u8, out.text(dir), path)) return true;
        }
        if (out.dirs_count == constants.cdi_run_dirs_max) return false;
        out.dirs[out.dirs_count] = out.keep(path) orelse return false;
        out.dirs_count += 1;
        return true;
    }
};

fn refusal_of(parsed: *const Parsed, index: u32, edits: *const Edits) Refusal {
    assert(edits.unsupported != .none);
    var refusal: Refusal = .{ .unsupported = .{
        .index = index,
        .edit = edits.unsupported,
        .name = undefined,
        .name_len = 0,
    } };
    const name = parsed.slice(edits.unsupported_name);
    @memcpy(refusal.unsupported.name[0..name.len], name);
    refusal.unsupported.name_len = @intCast(name.len);
    return refusal;
}

fn conflict_of(index: u32, container: []const u8) Refusal {
    var refusal: Refusal = .{ .unsupported = .{
        .index = index,
        .edit = .mount_conflict,
        .name = undefined,
        .name_len = 0,
    } };
    const length = @min(container.len, refusal.unsupported.name.len);
    @memcpy(refusal.unsupported.name[0..length], container[0..length]);
    refusal.unsupported.name_len = @intCast(length);
    return refusal;
}

comptime {
    assert(constants.cdi_kind_bytes_max + 1 + constants.cdi_device_name_bytes_max <=
        constants.cdi_name_bytes_max);
    assert(constants.cdi_path_bytes_max == constants.mount_path_bytes_max);
    assert(constants.cdi_run_nodes_max <= constants.cdi_nodes_max);
    assert(constants.cdi_run_mounts_max <= constants.cdi_mounts_max);
    assert(constants.cdi_run_env_max <= constants.cdi_env_max);
    assert(constants.cdi_run_dirs_max <= constants.cdi_ldcache_dirs_max);
    assert(constants.cdi_string_bytes_max <= constants.cdi_scratch_bytes_max);
    assert(constants.cdi_name_bytes_max >= constants.device_path_bytes_max);
    // A hostile spec's worst merged run still names a state the plan can hold.
    assert(constants.cdi_run_env_max <= constants.run_env_count_max);
}
