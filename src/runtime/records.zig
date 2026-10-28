//! Run records: one small ZON file per run in `$XDG_STATE_HOME/zbx/runs/<name>.zon` (or
//! `~/.local/state/zbx/runs/` when that is unset), with the name, the rootfs, the command, the
//! times and how the run ended. It is the state `zbx bundle` needs (slice 3) and what a later
//! `list` and re-adoption (M2) read. It is not a registry: nothing here starts, stops or lists.
//!
//! The format has a version, written first. A reader accepts every version up to
//! `constants.record_version` and fills what an older one lacks with defaults; a newer one is
//! skipped, never misread. Version 6 added the state volumes the run mounted (`.state`, one
//! string of `--state` values, `NAME:PATH[:ro]`, separated by spaces), so that `zbx state ls` can
//! say which container uses a volume; an older record has none. Version 5 added what the run
//! could reach (`network`, `publish`) and the names, never the values, of the variables set with
//! `-e`; an older record reads with no
//! network (unknown), no forwards and no names. Version 4 added the digest of the tree the
//! container was started from and the path of its upper layer (both empty for a run of a plain
//! `--rootfs` directory). Version 3 added the host pid of the container's PID 1 and of the
//! supervisor that waits for it (what re-adoption looks for). Version 2 added the limits, the
//! scope's name, why the run ended (`EndReason`) and whether it was detached; a version 1
//! record reads with no limits, no scope, not detached, and the reason its exit implies. Unknown
//! fields are ignored, so a later zbx may add some. The file is plain ZON, but the reader is a
//! line reader for the shape the writer produces (one field per
//! line), because the standard ZON parser allocates and this must not.
//!
//! Writing is atomic: the bytes go to a temporary file in the same directory, which is renamed
//! over the final name, so a reader sees the old record or the new one. At most
//! `constants.runs_max` records are kept; saving one past that deletes the oldest. A record that
//! cannot be read is skipped and counted, never fatal, and it is the first to be deleted.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const codes = @import("../diag/codes.zig");
const spec_mod = @import("spec.zig");
const volume = @import("../state/volume.zig");

const Host = host_mod.Host;

const labels_bytes_max = constants.labels_count_max *
    (constants.label_key_bytes_max + constants.label_value_bytes_max + 2);
const env_names_bytes_max = constants.run_env_count_max * (constants.env_name_bytes_max + 1);

pub const IdsMode = enum { single, full };

pub const Exit = union(enum) {
    /// Written when the run starts; still this after a zbx that died with its container.
    running,
    exited: u8,
    signaled: u8,
    /// The command never started; this is the diagnostic code that said why.
    start_failed: codes.Code,
    /// The run was lost: zbx could not wait for the container to the end.
    lost,
};

/// Why a run ended, as the exit report says it (`ExitReason`): the same words as the JSON
/// `container_exit.reason`. `none` is a run that has not ended, never started or was lost.
pub const EndReason = enum { none, exited, signal, oom, pid_limit };

/// The reason an exit implies when nothing more is known (version 1 records, or a view that
/// does not say).
pub fn reason_of(exit: Exit) EndReason {
    if (exit == .signaled) assert(exit.signaled > 0);
    return switch (exit) {
        .exited => .exited,
        .signaled => .signal,
        .running, .start_failed, .lost => .none,
    };
}

pub const Label = spec_mod.Label;

/// What goes into a record.
pub const View = struct {
    name: []const u8,
    rootfs: []const u8,
    command: []const []const u8,
    labels: []const Label,
    started: u64,
    ended: ?u64,
    exit: Exit,
    ids: IdsMode,
    zbx_version: []const u8,
    /// The JSON line of the diagnostic that ended the run, for a bundle; empty for none.
    diagnostic: []const u8 = "",
    /// Why it ended; `none` means what `exit` implies (`reason_of`).
    reason: EndReason = .none,
    limits: spec_mod.Limits = .{},
    /// The cgroup scope's name, or empty if the run had none.
    scope: []const u8 = "",
    detached: bool = false,
    /// The run was stopped because its time (`--timeout`) was up; `exit` and `reason` still say
    /// how it ended (the signal that did it).
    timed_out: bool = false,
    /// The host's pid of the container's PID 1, and of the process that waits for it (the
    /// `zbx` that started the run, or the supervisor of a detached one); zero if unknown.
    pid: u32 = 0,
    supervisor: u32 = 0,
    /// Version 4: the digest of the tree the run started from, and the upper layer of its
    /// overlay; empty for a run of a directory.
    tree: []const u8 = "",
    upper: []const u8 = "",
    /// Version 5: what the container could reach, the forwards of `--publish` (only with
    /// `user`), and the names of the variables set with `-e`. A value is never in a record.
    network: spec_mod.Network = .none,
    publish: []const spec_mod.Publish = &.{},
    env_names: []const []const u8 = &.{},
    /// Version 6: the state volumes the run mounted.
    state: []const volume.Mount = &.{},
};

// ---- Writing -------------------------------------------------------------------------------

fn write_string(writer: *std.Io.Writer, text: []const u8) void {
    assert(text.len <= constants.file_bytes_max);
    write_bytes(writer, "\"");
    for (text) |byte| {
        switch (byte) {
            '"' => write_bytes(writer, "\\\""),
            '\\' => write_bytes(writer, "\\\\"),
            '\n' => write_bytes(writer, "\\n"),
            0x20...0x21, 0x23...0x5b, 0x5d...0x7e => write_byte(writer, byte),
            else => write_format(writer, "\\x{x:0>2}", .{byte}),
        }
    }
    write_bytes(writer, "\"");
}

// The record is rendered into a buffer that `render` proves large enough for the worst case, so
// these three cannot fail.

fn write_bytes(writer: *std.Io.Writer, bytes: []const u8) void {
    assert(writer.buffer.len >= constants.record_bytes_max);
    writer.writeAll(bytes) catch unreachable; // Cannot fail: the buffer holds a maximal record.
}

fn write_byte(writer: *std.Io.Writer, byte: u8) void {
    assert(writer.buffer.len >= constants.record_bytes_max);
    writer.writeByte(byte) catch unreachable; // Cannot fail: same bound as `write_bytes`.
}

fn write_format(writer: *std.Io.Writer, comptime format: []const u8, args: anytype) void {
    assert(writer.buffer.len >= constants.record_bytes_max);
    writer.print(format, args) catch unreachable; // Cannot fail: same bound as `write_bytes`.
}

/// The record as ZON text, in `buffer` (which must be `record_bytes_max` bytes). The worst case
/// fits: every string byte is at most four bytes escaped, and the command, the labels, the name
/// and the rootfs are bounded (the comptime check below adds them up).
pub fn render(view: *const View, buffer: *[constants.record_bytes_max]u8) []const u8 {
    assert(view.name.len > 0);
    assert(view.command.len > 0);
    var writer = std.Io.Writer.fixed(buffer);
    write_bytes(&writer, ".{\n");
    write_format(&writer, "    .version = {d},\n", .{constants.record_version});
    write_bytes(&writer, "    .name = ");
    write_string(&writer, view.name);
    write_bytes(&writer, ",\n    .rootfs = ");
    write_string(&writer, view.rootfs);
    write_bytes(&writer, ",\n");
    write_command(&writer, view.command);
    write_labels(&writer, view.labels);
    write_format(&writer, "    .started = {d},\n", .{view.started});
    if (view.ended) |ended| {
        write_format(&writer, "    .ended = {d},\n", .{ended});
    } else {
        write_bytes(&writer, "    .ended = null,\n");
    }
    write_exit(&writer, view.exit);
    write_format(&writer, "    .ids = .{s},\n", .{@tagName(view.ids)});
    write_scope_fields(&writer, view);
    write_bytes(&writer, "    .zbx = ");
    write_string(&writer, view.zbx_version);
    write_bytes(&writer, ",\n");
    if (view.diagnostic.len > 0) {
        assert(view.diagnostic.len <= constants.diag_json_bytes_max);
        write_bytes(&writer, "    .diagnostic = ");
        write_string(&writer, view.diagnostic);
        write_bytes(&writer, ",\n");
    }
    write_bytes(&writer, "}\n");
    const text = writer.buffered();
    assert(text.len <= buffer.len);
    return text;
}

/// The fields version 2 added, one per line like the rest.
fn write_scope_fields(writer: *std.Io.Writer, view: *const View) void {
    assert(view.scope.len <= constants.scope_name_bytes_max);
    const reason = if (view.reason == .none) reason_of(view.exit) else view.reason;
    write_format(writer, "    .reason = .{s},\n", .{@tagName(reason)});
    write_format(writer, "    .detached = {s},\n", .{if (view.detached) "true" else "false"});
    write_format(writer, "    .timed_out = {s},\n", .{if (view.timed_out) "true" else "false"});
    write_bytes(writer, "    .scope = ");
    write_string(writer, view.scope);
    write_bytes(writer, ",\n");
    write_format(writer, "    .pid = {d},\n", .{view.pid});
    write_format(writer, "    .supervisor = {d},\n", .{view.supervisor});
    write_limit(writer, "limit_memory", view.limits.memory_bytes);
    write_limit(writer, "limit_pids", view.limits.pids);
    write_limit(writer, "limit_cpu_millis", view.limits.cpu_millis);
    assert(view.tree.len <= constants.store_digest_text_bytes);
    assert(view.upper.len <= constants.containers_path_bytes_max);
    write_bytes(writer, "    .tree = ");
    write_string(writer, view.tree);
    write_bytes(writer, ",\n    .upper = ");
    write_string(writer, view.upper);
    write_bytes(writer, ",\n");
    write_network_fields(writer, view);
}

/// The fields version 5 added: the network, the forwards as the text typed, the `-e` names.
fn write_network_fields(writer: *std.Io.Writer, view: *const View) void {
    assert(spec_mod.publish_problem(view.network, view.publish) == null);
    assert(spec_mod.env_names_problem(view.env_names) == null);
    write_format(writer, "    .network = .{s},\n", .{@tagName(view.network)});
    write_bytes(writer, "    .publish = .{");
    for (view.publish, 0..) |forward, index| {
        var storage: [spec_mod.publish_text_bytes_max]u8 = undefined;
        write_bytes(writer, if (index == 0) " \"" else ", \"");
        write_bytes(writer, forward.text(&storage));
        write_bytes(writer, "\"");
    }
    // The names are one string, separated by spaces (a POSIX name has none): two strings in a row
    // would read to the bundle's redactor as a secret name and its value.
    write_bytes(writer, " },\n    .env_names = \"");
    for (view.env_names, 0..) |name, index| {
        if (index > 0) write_bytes(writer, " ");
        write_bytes(writer, name);
    }
    write_bytes(writer, "\",\n");
    write_state(writer, view.state);
}

/// `.state = "pgdata:/var/lib/postgresql/data cfg:/etc/app:ro",`: one string, as `env_names` is
/// (a target holds no space), so that the bundle's redactor never reads two strings in a row.
fn write_state(writer: *std.Io.Writer, mounts: []const volume.Mount) void {
    assert(volume.list_problem(mounts) == null);
    var text: [state_text_bytes_max]u8 = undefined;
    var used: usize = 0;
    for (mounts, 0..) |*mount, index| {
        var buffer: [constants.state_value_bytes_max]u8 = undefined;
        const value = volume.mount_text(mount, &buffer);
        if (index > 0) {
            text[used] = ' ';
            used += 1;
        }
        @memcpy(text[used..][0..value.len], value);
        used += value.len;
    }
    write_bytes(writer, "    .state = ");
    write_string(writer, text[0..used]);
    write_bytes(writer, ",\n");
}

const state_text_bytes_max = constants.state_volumes_max * (constants.state_value_bytes_max + 1);

fn write_limit(writer: *std.Io.Writer, name: []const u8, value: anytype) void {
    assert(name.len > 0);
    assert(writer.buffer.len >= constants.record_bytes_max);
    if (value) |number| {
        write_format(writer, "    .{s} = {d},\n", .{ name, number });
    } else {
        write_format(writer, "    .{s} = null,\n", .{name});
    }
}

fn write_command(writer: *std.Io.Writer, command: []const []const u8) void {
    var bytes: usize = 0;
    var kept: usize = 0;
    assert(command.len <= constants.record_command_bytes_max); // Every word is at least a byte.
    for (command) |word| {
        if (bytes + word.len > constants.record_command_bytes_max) break;
        bytes += word.len;
        kept += 1;
    }
    write_bytes(writer, "    .command = .{");
    for (command[0..kept], 0..) |word, index| {
        write_bytes(writer, if (index == 0) " " else ", ");
        write_string(writer, word);
    }
    write_bytes(writer, " },\n");
    assert(kept <= command.len);
    const truncated = if (kept < command.len) "true" else "false";
    write_format(writer, "    .command_truncated = {s},\n", .{truncated});
}

fn write_labels(writer: *std.Io.Writer, labels: []const Label) void {
    assert(labels.len <= constants.labels_count_max);
    assert(writer.buffer.len >= constants.record_bytes_max);
    write_bytes(writer, "    .labels = .{");
    for (labels, 0..) |label, index| {
        write_bytes(writer, if (index == 0) " .{ " else ", .{ ");
        write_string(writer, label.key);
        write_bytes(writer, ", ");
        write_string(writer, label.value);
        write_bytes(writer, " }");
    }
    write_bytes(writer, " },\n");
}

fn write_exit(writer: *std.Io.Writer, exit: Exit) void {
    assert(writer.buffer.len >= constants.record_bytes_max);
    if (exit == .signaled) assert(exit.signaled > 0);
    switch (exit) {
        .running => write_bytes(writer, "    .exit = .running,\n"),
        .lost => write_bytes(writer, "    .exit = .lost,\n"),
        .exited => |code| write_format(writer, "    .exit = .{{ .exited = {d} }},\n", .{code}),
        .signaled => |number| {
            write_format(writer, "    .exit = .{{ .signaled = {d} }},\n", .{number});
        },
        .start_failed => |code| {
            const format = "    .exit = .{{ .start_failed = \"{s}\" }},\n";
            write_format(writer, format, .{codes.full_name(code)});
        },
    }
}

comptime {
    // The worst record: a name and a rootfs and a version string with every byte escaped to four,
    // the command at its cut, eight labels at their bounds with every byte escaped, and the
    // fixed text and numbers. It must fit.
    const strings = 4 * (constants.container_name_bytes_max + constants.rootfs_bytes_max + 64);
    const command = 4 * constants.record_command_bytes_max + 8 * constants.command_words_count_max;
    const label_bytes = 4 * (constants.label_key_bytes_max + constants.label_value_bytes_max);
    const labels = constants.labels_count_max * (label_bytes + 16);
    const diagnostic = 4 * constants.diag_json_bytes_max + 32;
    const scope = 4 * constants.scope_name_bytes_max + 160; // The name and the version 2 lines.
    const store_strings = constants.store_digest_text_bytes + constants.containers_path_bytes_max;
    const store = 4 * store_strings + 64;
    const network = constants.publish_count_max * 16 +
        4 * constants.run_env_count_max * (constants.env_name_bytes_max + 4) + 128;
    const state = 4 * state_text_bytes_max + 32;
    const total = strings + command + labels + diagnostic + scope + store + network + state + 512;
    assert(total <= constants.record_bytes_max);
}

// ---- Reading -------------------------------------------------------------------------------

/// A record read back. Only what the readers so far need: the rest of the file is ignored.
pub const Parsed = struct {
    /// 0 for a record with no version field (older than the field).
    version: u32,
    name: [constants.container_name_bytes_max]u8,
    name_len: u8,
    rootfs: [constants.rootfs_bytes_max]u8,
    rootfs_len: u16,
    started: u64,
    ended: ?u64,
    exit: Exit,
    ids: ?IdsMode,
    /// The diagnostic JSON line the run ended with; empty when the record has none.
    diagnostic: [constants.diag_json_bytes_max]u8,
    diagnostic_len: u16,
    /// Version 2: why it ended (derived from `exit` for an older record).
    reason: EndReason,
    detached: bool,
    /// Version 3: the run was stopped for its time.
    timed_out: bool,
    scope: [constants.scope_name_bytes_max]u8,
    scope_len: u8,
    limits: spec_mod.Limits,
    /// Version 3: the host pids (zero for an older record).
    pid: u32,
    supervisor: u32,
    /// Version 4: the tree digest and the upper layer; empty for an older record.
    tree: [constants.store_digest_text_bytes]u8,
    tree_len: u8,
    upper: [constants.containers_path_bytes_max]u8,
    upper_len: u16,
    /// The command's words, each followed by a NUL; `command_truncated` says the record cut it.
    command: [constants.record_command_bytes_max + constants.command_words_count_max]u8,
    command_len: u16,
    command_words: u8,
    /// The labels, key then value, each followed by a NUL.
    labels: [labels_bytes_max]u8,
    labels_len: u16,
    labels_count: u8,
    /// Version 5: null for an older record, which did not say what the container could reach.
    network: ?spec_mod.Network,
    publish: [constants.publish_count_max]spec_mod.Publish,
    publish_count: u8,
    /// The names of the `-e` variables, each followed by a NUL. Never a value.
    env_names: [env_names_bytes_max]u8,
    env_names_len: u16,
    env_names_count: u8,
    /// Version 6: the state volumes, each as `--state` takes it, followed by a NUL.
    state: [state_text_bytes_max]u8,
    state_len: u16,
    state_count: u8,

    /// The `index`th state volume the run mounted.
    pub fn state_mount(parsed: *const Parsed, index: u32) volume.Mount {
        assert(index < parsed.state_count);
        assert(parsed.state_len > 0);
        var parts = std.mem.splitScalar(u8, parsed.state[0..parsed.state_len], 0);
        var at: u32 = 0;
        while (parts.next()) |text| : (at += 1) {
            if (at == index) return volume.parse_mount(text).ok; // `parse_state` checked each.
        }
        unreachable; // The count says it is there.
    }

    pub fn publish_slice(parsed: *const Parsed) []const spec_mod.Publish {
        assert(parsed.publish_count <= constants.publish_count_max);
        return parsed.publish[0..parsed.publish_count];
    }

    /// The `index`th name of the `-e` variables.
    pub fn env_name(parsed: *const Parsed, index: u32) []const u8 {
        assert(index < parsed.env_names_count);
        var parts = std.mem.splitScalar(u8, parsed.env_names[0..parsed.env_names_len], 0);
        var at: u32 = 0;
        while (parts.next()) |name| : (at += 1) {
            if (at == index) return name;
        }
        unreachable; // The count says it is there.
    }

    /// The `index`th word of the command.
    pub fn command_word(parsed: *const Parsed, index: u32) []const u8 {
        assert(index < parsed.command_words);
        assert(parsed.command_len > 0);
        var words = std.mem.splitScalar(u8, parsed.command[0..parsed.command_len], 0);
        var at: u32 = 0;
        while (words.next()) |word| : (at += 1) {
            if (at == index) return word;
        }
        unreachable; // The count says it is there.
    }

    /// The `index`th label's key and value.
    pub fn label(parsed: *const Parsed, index: u32) [2][]const u8 {
        assert(index < parsed.labels_count);
        assert(parsed.labels_len > 0);
        var parts = std.mem.splitScalar(u8, parsed.labels[0..parsed.labels_len], 0);
        var at: u32 = 0;
        while (parts.next()) |key| : (at += 1) {
            const value = parts.next().?; // Written in pairs.
            if (at == index) return .{ key, value };
        }
        unreachable; // The count says it is there.
    }

    pub fn tree_slice(parsed: *const Parsed) []const u8 {
        assert(parsed.tree_len <= parsed.tree.len);
        return parsed.tree[0..parsed.tree_len];
    }

    pub fn upper_slice(parsed: *const Parsed) []const u8 {
        assert(parsed.upper_len <= parsed.upper.len);
        return parsed.upper[0..parsed.upper_len];
    }

    pub fn scope_slice(parsed: *const Parsed) []const u8 {
        assert(parsed.scope_len <= constants.scope_name_bytes_max);
        return parsed.scope[0..parsed.scope_len];
    }

    pub fn diagnostic_slice(parsed: *const Parsed) []const u8 {
        assert(parsed.diagnostic_len <= parsed.diagnostic.len);
        return parsed.diagnostic[0..parsed.diagnostic_len];
    }

    pub fn name_slice(parsed: *const Parsed) []const u8 {
        assert(parsed.name_len > 0);
        return parsed.name[0..parsed.name_len];
    }

    pub fn rootfs_slice(parsed: *const Parsed) []const u8 {
        assert(parsed.rootfs_len <= parsed.rootfs.len);
        return parsed.rootfs[0..parsed.rootfs_len];
    }
};

pub const ParseError = error{
    /// Not a record this reader can use.
    Malformed,
    /// Written by a newer zbx.
    Newer,
};

fn hex_digit(byte: u8) ?u8 {
    return std.fmt.charToDigit(byte, 16) catch null;
}

/// Reads a ZON string literal into `out`; returns its length. Null if it is not one, does not
/// fit, or uses an escape the writer never produces.
fn parse_string(literal: []const u8, out: []u8) ?usize {
    if (literal.len < 2) return null;
    if (literal[0] != '"') return null;
    if (literal[literal.len - 1] != '"') return null;
    const body = literal[1 .. literal.len - 1];
    var length: usize = 0;
    var at: usize = 0;
    while (at < body.len) : (at += 1) {
        if (length == out.len) return null;
        var byte = body[at];
        if (byte == '"') return null; // An unescaped quote ends the string early.
        if (byte == '\\') {
            at += 1;
            if (at == body.len) return null;
            switch (body[at]) {
                '"', '\\' => byte = body[at],
                'n' => byte = '\n',
                'x' => {
                    if (at + 2 >= body.len) return null;
                    const high = hex_digit(body[at + 1]) orelse return null;
                    const low = hex_digit(body[at + 2]) orelse return null;
                    byte = high * 16 + low;
                    at += 2;
                },
                else => return null,
            }
        }
        out[length] = byte;
        length += 1;
    }
    return length;
}

fn parse_exit(value: []const u8) ?Exit {
    assert(value.len <= constants.record_bytes_max);
    assert(value.len > 0);
    if (std.mem.eql(u8, value, ".running")) return .running;
    if (std.mem.eql(u8, value, ".lost")) return .lost;
    const open = ".{ .";
    if (!std.mem.startsWith(u8, value, open)) return null;
    if (!std.mem.endsWith(u8, value, " }")) return null;
    const inner = value[open.len .. value.len - 2];
    const equals = std.mem.indexOf(u8, inner, " = ") orelse return null;
    const key = inner[0..equals];
    const operand = inner[equals + 3 ..];
    if (std.mem.eql(u8, key, "start_failed")) {
        var text: [16]u8 = undefined;
        const length = parse_string(operand, &text) orelse return null;
        return .{ .start_failed = codes.parse(text[0..length]) orelse return null };
    }
    const number = std.fmt.parseInt(u8, operand, 10) catch return null;
    if (std.mem.eql(u8, key, "exited")) return .{ .exited = number };
    if (std.mem.eql(u8, key, "signaled")) {
        if (number == 0) return null;
        if (number >= constants.signal_number_max) return null;
        return .{ .signaled = number };
    }
    return null;
}

/// Reads a record. `Newer` for a version this zbx does not know; `Malformed` for anything that
/// is not a record this reader understands. Never reads past `text`, never allocates.
pub fn parse(text: []const u8, out: *Parsed) ParseError!void {
    assert(text.len <= constants.file_bytes_max);
    out.version = 0;
    out.name_len = 0;
    out.rootfs_len = 0;
    out.started = 0;
    out.ended = null;
    out.exit = .running;
    out.ids = null;
    out.diagnostic_len = 0;
    out.reason = .none;
    out.detached = false;
    out.timed_out = false;
    out.scope_len = 0;
    out.limits = .{};
    out.pid = 0;
    out.supervisor = 0;
    out.tree_len = 0;
    out.upper_len = 0;
    out.command_len = 0;
    out.command_words = 0;
    out.labels_len = 0;
    out.labels_count = 0;
    out.network = null;
    out.publish_count = 0;
    out.env_names_len = 0;
    out.env_names_count = 0;
    out.state_len = 0;
    out.state_count = 0;
    var has_reason = false;
    var have_start = false;
    var opened = false;
    var closed = false;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        if (!opened) {
            if (!std.mem.eql(u8, line, ".{")) return error.Malformed;
            opened = true;
            continue;
        }
        if (closed) return error.Malformed; // Nothing follows the closing brace.
        if (std.mem.eql(u8, line, "}")) {
            closed = true;
            continue;
        }
        try parse_field(line, out, &have_start);
        if (std.mem.startsWith(u8, line, ".reason = ")) has_reason = true;
    }
    if (!opened or !closed) return error.Malformed;
    if (out.version > constants.record_version) return error.Newer;
    if (out.name_len == 0) return error.Malformed;
    if (!have_start) return error.Malformed;
    if (!has_reason) out.reason = reason_of(out.exit);
    if (spec_mod.name_problem(out.name_slice()) != null) return error.Malformed;
    try check_network_fields(out);
}

/// What `render` asserts about the version 5 fields, so that a damaged file cannot read as valid
/// and crash the next write: forwards only with `user`, none twice; names unique and POSIX.
fn check_network_fields(out: *const Parsed) ParseError!void {
    const network = out.network orelse {
        // A record that does not say the network does not say forwards either.
        if (out.publish_count > 0) return error.Malformed;
        return;
    };
    // `publish_problem` asserts the implication, so a damaged file is refused before it.
    if (out.publish_count > 0 and network != .user) return error.Malformed;
    if (spec_mod.publish_problem(network, out.publish_slice()) != null) return error.Malformed;
    var words: [constants.run_env_count_max][]const u8 = undefined;
    for (0..out.env_names_count) |at| words[at] = out.env_name(@intCast(at));
    if (spec_mod.env_names_problem(words[0..out.env_names_count]) != null) {
        return error.Malformed;
    }
}

fn parse_field(line: []const u8, out: *Parsed, have_start: *bool) ParseError!void {
    assert(line.len <= constants.record_bytes_max);
    assert(out.name_len <= constants.container_name_bytes_max);
    if (line[0] != '.') return error.Malformed;
    const equals = std.mem.indexOf(u8, line, " = ") orelse return error.Malformed;
    const key = line[1..equals];
    var value = line[equals + 3 ..];
    if (value.len == 0 or value[value.len - 1] != ',') return error.Malformed;
    value = value[0 .. value.len - 1];
    if (value.len == 0) return error.Malformed; // `.key = ,`: no field has an empty value.
    if (std.mem.eql(u8, key, "version")) {
        out.version = std.fmt.parseInt(u32, value, 10) catch return error.Malformed;
    } else if (std.mem.eql(u8, key, "name")) {
        const length = parse_string(value, &out.name) orelse return error.Malformed;
        out.name_len = @intCast(length);
    } else if (std.mem.eql(u8, key, "rootfs")) {
        out.rootfs_len = @intCast(parse_string(value, &out.rootfs) orelse return error.Malformed);
    } else if (std.mem.eql(u8, key, "started")) {
        out.started = std.fmt.parseInt(u64, value, 10) catch return error.Malformed;
        have_start.* = true;
    } else if (std.mem.eql(u8, key, "ended")) {
        const none = std.mem.eql(u8, value, "null");
        const number = if (none) 0 else std.fmt.parseInt(u64, value, 10) catch
            return error.Malformed;
        out.ended = if (none) null else number;
    } else if (std.mem.eql(u8, key, "exit")) {
        out.exit = parse_exit(value) orelse return error.Malformed;
    } else if (std.mem.eql(u8, key, "diagnostic")) {
        const length = parse_string(value, &out.diagnostic) orelse return error.Malformed;
        out.diagnostic_len = @intCast(length);
    } else if (parse_scope_field(key, value, out)) |accepted| {
        if (!accepted) return error.Malformed;
    } else if (std.mem.eql(u8, key, "ids")) {
        out.ids = std.meta.stringToEnum(IdsMode, std.mem.trimStart(u8, value, ".")) orelse
            return error.Malformed;
    }
    // Any other field is ignored: a later zbx may add some.
}

/// A field version 2 added: null if `key` is not one, else whether the value was good.
fn parse_scope_field(key: []const u8, value: []const u8, out: *Parsed) ?bool {
    assert(key.len > 0);
    assert(value.len > 0);
    if (std.mem.eql(u8, key, "reason")) {
        const name = std.mem.trimStart(u8, value, ".");
        out.reason = std.meta.stringToEnum(EndReason, name) orelse return false;
        return true;
    }
    if (std.mem.eql(u8, key, "detached")) {
        const yes = std.mem.eql(u8, value, "true");
        if (!yes and !std.mem.eql(u8, value, "false")) return false;
        out.detached = yes;
        return true;
    }
    if (std.mem.eql(u8, key, "timed_out")) {
        const yes = std.mem.eql(u8, value, "true");
        if (!yes and !std.mem.eql(u8, value, "false")) return false;
        out.timed_out = yes;
        return true;
    }
    if (std.mem.eql(u8, key, "scope")) {
        const length = parse_string(value, &out.scope) orelse return false;
        out.scope_len = @intCast(length);
        return true;
    }
    if (std.mem.eql(u8, key, "pid")) {
        out.pid = std.fmt.parseInt(u32, value, 10) catch return false;
        return true;
    }
    if (std.mem.eql(u8, key, "supervisor")) {
        out.supervisor = std.fmt.parseInt(u32, value, 10) catch return false;
        return true;
    }
    if (std.mem.eql(u8, key, "tree")) {
        const length = parse_string(value, &out.tree) orelse return false;
        out.tree_len = @intCast(length);
        return true;
    }
    if (std.mem.eql(u8, key, "upper")) {
        const length = parse_string(value, &out.upper) orelse return false;
        out.upper_len = @intCast(length);
        return true;
    }
    if (std.mem.eql(u8, key, "network")) {
        const name = std.mem.trimStart(u8, value, ".");
        out.network = std.meta.stringToEnum(spec_mod.Network, name) orelse return false;
        return true;
    }
    if (std.mem.eql(u8, key, "publish")) return parse_publish_list(value, out);
    if (std.mem.eql(u8, key, "env_names")) return parse_env_names(value, out);
    if (std.mem.eql(u8, key, "state")) return parse_state(value, out);
    if (std.mem.eql(u8, key, "command")) return parse_command(value, out);
    if (std.mem.eql(u8, key, "labels")) return parse_labels(value, out);
    if (std.mem.eql(u8, key, "limit_memory")) {
        out.limits.memory_bytes = parse_limit(u64, value) orelse return false;
        return true;
    }
    if (std.mem.eql(u8, key, "limit_pids")) {
        out.limits.pids = parse_limit(u32, value) orelse return false;
        return true;
    }
    if (std.mem.eql(u8, key, "limit_cpu_millis")) {
        out.limits.cpu_millis = parse_limit(u32, value) orelse return false;
        return true;
    }
    return null;
}

/// The next string literal of `text` from `at`: its slice including the quotes, and where to go
/// on. Null when there is none. A backslash escapes the next byte (the writer's only escapes).
fn next_literal(text: []const u8, at: usize) ?struct { literal: []const u8, next: usize } {
    assert(at <= text.len);
    assert(text.len <= constants.record_bytes_max);
    const open = std.mem.indexOfScalarPos(u8, text, at, '"') orelse return null;
    var end = open + 1;
    while (end < text.len) : (end += 1) {
        if (text[end] == '\\') {
            end += 1;
            continue;
        }
        if (text[end] == '"') return .{ .literal = text[open .. end + 1], .next = end + 1 };
    }
    return null;
}

/// `.{ "word", "word" }`: the words of the command, kept NUL-separated (cut at the room).
fn parse_command(value: []const u8, out: *Parsed) bool {
    out.command_len = 0; // A repeated field: the later one wins.
    out.command_words = 0;
    var at: usize = 0;
    while (next_literal(value, at)) |found| : (at = found.next) {
        const room = out.command[out.command_len..];
        if (room.len < 2) break;
        const length = parse_string(found.literal, room[0 .. room.len - 1]) orelse return false;
        room[length] = 0;
        out.command_len += @intCast(length + 1);
        out.command_words += 1;
        if (out.command_words == constants.command_words_count_max) break;
    }
    return true;
}

/// `.{ "8080:80", ... }`: the forwards, each as `--publish` typed it.
fn parse_publish_list(value: []const u8, out: *Parsed) bool {
    out.publish_count = 0; // A repeated field: the later one wins.
    var at: usize = 0;
    while (next_literal(value, at)) |found| : (at = found.next) {
        if (out.publish_count == constants.publish_count_max) return false;
        var text: [spec_mod.publish_text_bytes_max + 1]u8 = undefined;
        const length = parse_string(found.literal, &text) orelse return false;
        const forward = switch (spec_mod.parse_publish(text[0..length])) {
            .ok => |parsed| parsed,
            .problem => return false,
        };
        out.publish[out.publish_count] = forward;
        out.publish_count += 1;
    }
    return true;
}

/// `"NAME NAME"`: the names of the `-e` variables, kept NUL-separated.
fn parse_env_names(value: []const u8, out: *Parsed) bool {
    out.env_names_len = 0; // A repeated field: the later one wins.
    out.env_names_count = 0;
    var text: [env_names_bytes_max]u8 = undefined;
    const length = parse_string(value, &text) orelse return false;
    if (length == 0) return true;
    var names_split = std.mem.splitScalar(u8, text[0..length], ' ');
    while (names_split.next()) |name| {
        if (out.env_names_count == constants.run_env_count_max) return false;
        const room = out.env_names[out.env_names_len..];
        if (room.len < name.len + 1) return false;
        @memcpy(room[0..name.len], name);
        room[name.len] = 0;
        out.env_names_len += @intCast(name.len + 1);
        out.env_names_count += 1;
    }
    return true;
}

/// `"NAME:PATH NAME:PATH:ro"`: each a mount `--state` would take, and together a list a run may
/// have (what `write_state` asserts), so that a record that reads can be written again.
fn parse_state(value: []const u8, out: *Parsed) bool {
    out.state_len = 0; // A repeated field: the later one wins.
    out.state_count = 0;
    var text: [state_text_bytes_max]u8 = undefined;
    const length = parse_string(value, &text) orelse return false;
    if (length == 0) return true;
    var mounts: [constants.state_volumes_max]volume.Mount = undefined;
    var parts = std.mem.splitScalar(u8, text[0..length], ' ');
    while (parts.next()) |part| {
        if (out.state_count == constants.state_volumes_max) return false;
        if (part.len > constants.state_value_bytes_max) return false;
        const room = out.state[out.state_len..];
        assert(room.len > part.len); // The room holds every value at its bound.
        @memcpy(room[0..part.len], part);
        room[part.len] = 0;
        const parsed = volume.parse_mount(room[0..part.len]);
        if (parsed != .ok) return false;
        mounts[out.state_count] = parsed.ok;
        out.state_len += @intCast(part.len + 1);
        out.state_count += 1;
    }
    return volume.list_problem(mounts[0..out.state_count]) == null;
}

/// `.{ .{ "key", "value" }, ... }`: the labels as key and value, NUL-separated.
fn parse_labels(value: []const u8, out: *Parsed) bool {
    out.labels_len = 0; // A repeated field: the later one wins.
    out.labels_count = 0;
    var at: usize = 0;
    while (next_literal(value, at)) |key| {
        const second = next_literal(value, key.next) orelse return false;
        at = second.next;
        if (out.labels_count == constants.labels_count_max) return false;
        for ([_][]const u8{ key.literal, second.literal }) |literal| {
            const room = out.labels[out.labels_len..];
            if (room.len < 2) return false;
            const length = parse_string(literal, room[0 .. room.len - 1]) orelse return false;
            room[length] = 0;
            out.labels_len += @intCast(length + 1);
        }
        out.labels_count += 1;
    }
    return true;
}

/// `null` is no limit; a number is the limit. Anything else is not a limit at all, which the
/// caller tells from "no limit" by the optional-of-optional.
fn parse_limit(comptime Int: type, value: []const u8) ??Int {
    assert(value.len > 0); // The line reader refused an empty value.
    assert(@typeInfo(Int) == .int);
    if (std.mem.eql(u8, value, "null")) return @as(?Int, null);
    const number = std.fmt.parseInt(Int, value, 10) catch return null;
    return @as(?Int, number);
}

// ---- Where records live --------------------------------------------------------------------

/// The runs directory and the pieces needed to create it.
pub const Dir = struct {
    /// The path of the runs directory, NUL-terminated at `len`.
    path: [constants.state_path_bytes_max + 1]u8,
    len: u32,
    /// Bytes of `path` that must already exist (HOME, or the state base): directories are made
    /// from there on.
    existing_len: u32,

    pub fn text(dir: *const Dir) [:0]const u8 {
        assert(dir.len > 0);
        assert(dir.path[dir.len] == 0);
        return dir.path[0..dir.len :0];
    }
};

/// Finds the runs directory from the environment. False if neither XDG_STATE_HOME nor HOME gives
/// an absolute path that fits.
pub fn locate(host: Host, dir: *Dir) bool {
    const suffix = "/zbx/runs";
    const limit: u32 = constants.state_path_bytes_max - suffix.len;
    var base: []const u8 = "";
    var from_home = false;
    if (host.environment("XDG_STATE_HOME", limit)) |state| {
        if (state.len > 0 and state[0] == '/') base = state;
    }
    var home: []const u8 = "";
    if (base.len == 0) {
        const found = host.environment("HOME", limit - "/.local/state".len) orelse return false;
        if (found.len == 0 or found[0] != '/') return false;
        home = std.mem.trimEnd(u8, found, "/");
        from_home = true;
    }
    const joined = if (from_home)
        std.fmt.bufPrint(&dir.path, "{s}/.local/state{s}", .{ home, suffix })
    else
        std.fmt.bufPrint(&dir.path, "{s}{s}", .{ std.mem.trimEnd(u8, base, "/"), suffix });
    const text = joined catch return false;
    dir.len = @intCast(text.len);
    dir.path[dir.len] = 0;
    dir.existing_len = if (from_home) @intCast(home.len) else @intCast(text.len - suffix.len);
    assert(dir.existing_len <= dir.len);
    return true;
}

/// Makes the runs directory and every directory above it that is missing.
pub fn ensure(host: Host, dir: *const Dir) host_mod.Error!void {
    assert(dir.len > dir.existing_len);
    var at: u32 = dir.existing_len;
    while (at < dir.len) {
        // The next component ends at the next slash, or at the end of the path.
        const next = std.mem.indexOfScalarPos(u8, dir.path[0..dir.len], at + 1, '/') orelse dir.len;
        var prefix: [constants.state_path_bytes_max + 1]u8 = undefined;
        @memcpy(prefix[0..next], dir.path[0..next]);
        prefix[next] = 0;
        try host.make_directory(prefix[0..next :0], true);
        at = @intCast(next);
    }
    assert(at == dir.len);
}

/// `<runs>/<name>.zon`, or with `hidden` the temporary `<runs>/.<name>.tmp` it is written to.
fn file_path(
    dir: *const Dir,
    name: []const u8,
    hidden: bool,
    buffer: *[constants.state_path_bytes_max + 80]u8,
) [:0]const u8 {
    assert(name.len > 0);
    assert(name.len <= constants.container_name_bytes_max);
    const runs = dir.path[0..dir.len];
    // Cannot fail: the runs directory is at most state_path_bytes_max and the rest is 70 bytes.
    const text = if (hidden)
        // Cannot fail: the caller's buffer holds the longest path plus a suffix.
        std.fmt.bufPrintSentinel(buffer, "{s}/.{s}.tmp", .{ runs, name }, 0) catch unreachable
    else
        // Cannot fail: as above.
        std.fmt.bufPrintSentinel(buffer, "{s}/{s}.zon", .{ runs, name }, 0) catch unreachable;
    return text; // Both branches have the same bound.
}

/// `<runs>/<name>.zon`.
pub fn record_path(
    dir: *const Dir,
    name: []const u8,
    buffer: *[constants.state_path_bytes_max + 80]u8,
) [:0]const u8 {
    assert(dir.len > 0);
    assert(name.len > 0);
    return file_path(dir, name, false, buffer);
}

/// The name of the record with the latest start time (ties go to the larger name), or null when
/// the directory holds none that can be read. Unreadable records are passed over.
pub fn newest(host: Host, dir: *const Dir, name_out: *[constants.container_name_bytes_max]u8) ?u8 {
    var listing: host_mod.DirListing = undefined;
    host.list_directory(dir.text(), &listing) catch return null;
    var best: ?u32 = null;
    var best_started: u64 = 0;
    var ignored: Skipped = undefined;
    ignored.reset();
    for (0..listing.count) |at| {
        const name = listing.name(@intCast(at));
        if (!is_record_name(name)) continue;
        if (name.len - constants.record_suffix.len > constants.container_name_bytes_max) continue;
        const started = started_of(host, dir, name, &ignored);
        if (started == 0) continue; // Unreadable, or without a time: not a candidate.
        const better = best == null or started > best_started or
            (started == best_started and std.mem.lessThan(u8, listing.name(best.?), name));
        if (!better) continue;
        best = @intCast(at);
        best_started = started;
    }
    const found = best orelse return null;
    const stem = listing.name(found);
    const length = stem.len - constants.record_suffix.len;
    @memcpy(name_out[0..length], stem[0..length]);
    assert(length > 0);
    return @intCast(length);
}

/// Writes the record atomically: a temporary file, then a rename over the final name.
pub fn save(host: Host, dir: *const Dir, view: *const View) host_mod.Error!void {
    var bytes: [constants.record_bytes_max]u8 = undefined;
    const text = render(view, &bytes);
    assert(text.len > 0);
    assert(text.len <= bytes.len);
    var temporary_storage: [constants.state_path_bytes_max + 80]u8 = undefined;
    var final_storage: [constants.state_path_bytes_max + 80]u8 = undefined;
    const temporary = file_path(dir, view.name, true, &temporary_storage);
    const final = file_path(dir, view.name, false, &final_storage);
    try host.write_file(temporary, text);
    host.rename(temporary, final) catch |err| {
        // The temporary file must not outlive a failed save; if it cannot go, nothing more to do.
        host.remove_file(temporary) catch {};
        return err;
    };
}

/// What pruning found that the user should hear about.
pub const Skipped = struct {
    count: u32,
    /// The first record skipped, and why.
    first_name: [constants.dir_name_bytes_max]u8,
    first_name_len: u8,
    first_reason: Reason,

    pub const Reason = enum { unreadable, damaged, newer };

    pub fn reset(skipped: *Skipped) void {
        skipped.count = 0;
        skipped.first_name_len = 0;
        skipped.first_reason = .unreadable;
        assert(skipped.first_name.len == constants.dir_name_bytes_max);
        assert(skipped.count == 0);
    }

    fn note(skipped: *Skipped, name: []const u8, reason: Reason) void {
        assert(name.len <= constants.dir_name_bytes_max);
        if (skipped.count == 0) {
            @memcpy(skipped.first_name[0..name.len], name);
            skipped.first_name_len = @intCast(name.len);
            skipped.first_reason = reason;
        }
        skipped.count += 1;
    }

    pub fn first(skipped: *const Skipped) []const u8 {
        return skipped.first_name[0..skipped.first_name_len];
    }
};

/// The names of the runs whose records `prune` deleted, so that whoever kept something for
/// them (a container's upper layer) can let it go.
pub const Pruned = struct {
    count: u32,
    names: [constants.dir_entries_max][constants.container_name_bytes_max]u8,
    lengths: [constants.dir_entries_max]u8,

    fn add(pruned: *Pruned, stem: []const u8) void {
        assert(stem.len > 0);
        // Not a name we made (a stray `Notes.zon`): it owns no container directory.
        if (spec_mod.name_problem(stem) != null) return;
        if (pruned.count == pruned.names.len) return;
        @memcpy(pruned.names[pruned.count][0..stem.len], stem);
        pruned.lengths[pruned.count] = @intCast(stem.len);
        pruned.count += 1;
    }

    pub fn name(pruned: *const Pruned, index: u32) []const u8 {
        assert(index < pruned.count);
        return pruned.names[index][0..pruned.lengths[index]];
    }
};

const Entry = struct {
    index: u32,
    started: u64,
    keep: bool,
};

fn is_record_name(name: []const u8) bool {
    assert(name.len <= constants.dir_name_bytes_max);
    if (name.len <= constants.record_suffix.len) return false;
    if (name[0] == '.') return false;
    return std.mem.endsWith(u8, name, constants.record_suffix);
}

/// Deletes the oldest records until at most `runs_max` remain. `keep` (the one just saved) is
/// never deleted. Records that cannot be read count as the oldest and are noted in `skipped`.
pub fn prune(
    host: Host,
    dir: *const Dir,
    keep: []const u8,
    skipped: *Skipped,
    pruned: *Pruned,
) host_mod.Error!void {
    skipped.reset();
    pruned.count = 0;
    var listing: host_mod.DirListing = undefined;
    try host.list_directory(dir.text(), &listing);
    var records_listed: u32 = 0;
    for (0..listing.count) |at| {
        if (is_record_name(listing.name(@intCast(at)))) records_listed += 1;
    }
    // With room to spare nothing is deleted, so nothing is read: a run does not pay for the
    // records, or hear about the ones it cannot read, until there are too many to keep.
    if (records_listed <= constants.runs_max and !listing.truncated) return;
    var entries: [constants.dir_entries_max]Entry = undefined;
    var count: u32 = 0;
    var index: u32 = 0;
    while (index < listing.count) : (index += 1) {
        const name = listing.name(index);
        if (!is_record_name(name)) continue;
        const stem = name[0 .. name.len - constants.record_suffix.len];
        entries[count] = .{
            .index = index,
            .started = started_of(host, dir, name, skipped),
            .keep = std.mem.eql(u8, stem, keep),
        };
        count += 1;
    }
    var remaining = count;
    for (0..count) |_| {
        if (remaining <= constants.runs_max) break;
        const oldest = oldest_of(&listing, entries[0..count]) orelse break;
        const gone = listing.name(entries[oldest].index);
        try remove_record(host, dir, gone);
        pruned.add(gone[0 .. gone.len - constants.record_suffix.len]);
        entries[oldest].keep = true; // Gone: out of the running.
        entries[oldest].started = std.math.maxInt(u64);
        remaining -= 1;
    }
    assert(remaining <= count);
}

/// The index in `entries` of the oldest one that may still be deleted; ties go to the
/// smaller name.
fn oldest_of(listing: *const host_mod.DirListing, entries: []const Entry) ?usize {
    var best: ?usize = null;
    assert(entries.len <= constants.dir_entries_max);
    for (entries, 0..) |entry, at| {
        if (entry.keep) continue;
        const current = best orelse {
            best = at;
            continue;
        };
        const older = entry.started < entries[current].started;
        const same = entry.started == entries[current].started;
        const name = listing.name(entry.index);
        const smaller = std.mem.lessThan(u8, name, listing.name(entries[current].index));
        if (older or (same and smaller)) best = at;
    }
    if (best) |at| assert(!entries[at].keep);
    return best;
}

fn remove_record(host: Host, dir: *const Dir, file_name: []const u8) host_mod.Error!void {
    assert(is_record_name(file_name));
    assert(dir.len > 0);
    var storage: [constants.state_path_bytes_max + 80]u8 = undefined;
    const text = std.fmt.bufPrintSentinel(
        &storage,
        "{s}/{s}",
        .{ dir.path[0..dir.len], file_name },
        0,
    ) catch
        unreachable; // The directory is bounded and a listed name is at most 72 bytes.
    try host.remove_file(text);
}

pub const LoadError = error{ NotFound, Unreadable, Damaged, Newer };

/// Reads the record of the run called `name` into `out`.
pub fn load(host: Host, dir: *const Dir, name: []const u8, out: *Parsed) LoadError!void {
    // The name comes from a command line: one that is not a run name (a slash, say) names no
    // record, and is never made into a path.
    if (spec_mod.name_problem(name) != null) return error.NotFound;
    var path_storage: [constants.state_path_bytes_max + 80]u8 = undefined;
    const path = record_path(dir, name, &path_storage);
    var bytes: [constants.record_bytes_max]u8 = undefined;
    const content = host.read_file(path, &bytes) catch |err| {
        return if (err == error.NotFound) error.NotFound else error.Unreadable;
    };
    parse(content, out) catch |err| return if (err == error.Newer) error.Newer else error.Damaged;
    // A record under another name than its file's is not one of ours.
    if (!std.mem.eql(u8, out.name_slice(), name)) return error.Damaged;
    assert(out.name_len > 0);
}

/// The names of the records in the directory, in no order. The listing is the caller's.
pub fn names(host: Host, dir: *const Dir, listing: *host_mod.DirListing) host_mod.Error!void {
    assert(dir.len > 0);
    try host.list_directory(dir.text(), listing);
    assert(listing.count <= constants.dir_entries_max);
}

/// The run name in a listed file name ("web-1.zon" is "web-1"), or null if it is not a record's.
pub fn name_of(file_name: []const u8) ?[]const u8 {
    if (!is_record_name(file_name)) return null;
    const stem = file_name[0 .. file_name.len - constants.record_suffix.len];
    if (stem.len > constants.container_name_bytes_max) return null;
    return stem;
}

/// The start time of the record in `file_name`, or 0 if it cannot be used (and noted).
fn started_of(host: Host, dir: *const Dir, file_name: []const u8, skipped: *Skipped) u64 {
    var path_storage: [constants.state_path_bytes_max + 80]u8 = undefined;
    const format = "{s}/{s}";
    const path = std.fmt.bufPrint(&path_storage, format, .{ dir.path[0..dir.len], file_name }) catch
        return 0;
    var bytes: [constants.record_bytes_max]u8 = undefined;
    const content = host.read_file(path, &bytes) catch {
        skipped.note(file_name, .unreadable);
        return 0;
    };
    var parsed: Parsed = undefined;
    parse(content, &parsed) catch |err| {
        skipped.note(file_name, if (err == error.Newer) .newer else .damaged);
        return 0;
    };
    return parsed.started;
}

const testing = std.testing;
const HostSim = @import("../host_sim.zig").HostSim;

fn sample_view() View {
    return .{
        .name = "web-1",
        .rootfs = "/srv/alpine",
        .command = &.{ "/bin/sh", "-c", "echo \"hi\"\n" },
        .labels = &.{.{ .key = "app", .value = "web" }},
        .started = 1_760_000_000,
        .ended = null,
        .exit = .running,
        .ids = .full,
        .zbx_version = "0.0.0",
    };
}

test "a record is valid ZON in the shape the reader expects, and reads back" {
    // Goal: render and parse are inverse for every exit form, and the text is a ZON tuple with
    // the version first. Method: each exit, with an escaped command word.
    const exits = [_]Exit{
        .running,
        .{ .exited = 0 },
        .{ .exited = 255 },
        .{ .signaled = 9 },
        .{ .start_failed = .E0205 },
        .lost,
    };
    for (exits) |exit| {
        var view = sample_view();
        view.exit = exit;
        view.ended = if (exit == .running) null else 1_760_000_042;
        var buffer: [constants.record_bytes_max]u8 = undefined;
        const text = render(&view, &buffer);
        try testing.expect(std.mem.startsWith(u8, text, ".{\n    .version = 6,\n"));
        try testing.expect(std.mem.endsWith(u8, text, "}\n"));
        var parsed: Parsed = undefined;
        try parse(text, &parsed);
        try testing.expectEqual(constants.record_version, parsed.version);
        try testing.expectEqualStrings("web-1", parsed.name_slice());
        try testing.expectEqualStrings("/srv/alpine", parsed.rootfs_slice());
        try testing.expectEqual(@as(u64, 1_760_000_000), parsed.started);
        try testing.expectEqual(view.ended, parsed.ended);
        try testing.expectEqual(exit, parsed.exit);
        try testing.expectEqual(@as(?IdsMode, .full), parsed.ids);
    }
}

test "the command is cut at its bound and says so" {
    // Goal: a huge command cannot make an unbounded record.
    var view = sample_view();
    const word = @import("../test_util.zig").repeat('w', 1000);
    view.command = &.{ word, word, word };
    var buffer: [constants.record_bytes_max]u8 = undefined;
    const text = render(&view, &buffer);
    try testing.expect(std.mem.indexOf(u8, text, ".command_truncated = true") != null);
    var parsed: Parsed = undefined;
    try parse(text, &parsed);
}

test "older, newer and damaged records: the reader accepts, skips or refuses exactly" {
    // Goal: the format rules. A record with no version field is version 0 and readable; a field
    // this reader does not know is ignored; version 3 is Newer; anything that is not a record, a
    // missing name or start, a bad name, and text after the closing brace are Malformed.
    var parsed: Parsed = undefined;
    const old = ".{\n    .name = \"old\",\n    .started = 5,\n}\n";
    try parse(old, &parsed);
    try testing.expectEqual(@as(u32, 0), parsed.version);
    try testing.expect(parsed.ids == null);
    const head = ".{\n    .version = 1,\n    .name = \"x\",\n    .started = 5,\n";
    try parse(head ++ "    .future = .{ 1, 2 },\n}\n", &parsed);
    // A repeated field: the later one wins, and the counts start again.
    const twice = head ++ "    .command = .{ \"a\" },\n    .command = .{ \"b\", \"c\" },\n}\n";
    try parse(twice, &parsed);
    try testing.expectEqual(@as(u8, 2), parsed.command_words);
    try testing.expectEqualStrings("c", parsed.command_word(1));
    const newer = ".{\n    .version = 7,\n    .name = \"x\",\n    .started = 5,\n}\n";
    try testing.expectError(error.Newer, parse(newer, &parsed));
    const bad = [_][]const u8{
        "",
        "garbage",
        ".{\n",
        ".{\n    .version = 1,\n    .started = 5,\n}\n",
        ".{\n    .version = 1,\n    .name = \"x\",\n}\n",
        ".{\n    .name = \"X\",\n    .started = 5,\n}\n",
        ".{\n    .name = \"x\",\n    .started = five,\n}\n",
        ".{\n    .name = \"x\",\n    .started = 5,\n    .exit = .{ .exited = 999 },\n}\n",
        ".{\n    .name = \"x\",\n    .started = 5,\n}\nextra\n",
        ".{\n    .name = \"unterminated,\n    .started = 5,\n}\n",
        ".{\n    .name = \"x\",\n    .started = 5\n}\n",
        ".{\n    .name = \"x\",\n    .started = 5,\n    .scope = ,\n}\n",
    };
    for (bad) |text| try testing.expectError(error.Malformed, parse(text, &parsed));
}

test "string escapes round-trip, including bytes the writer escapes in hex" {
    // Goal: a command word with a quote, a backslash, a newline and a control byte survives.
    var view = sample_view();
    view.rootfs = "/a\"b\\c\n\x01\xff";
    var buffer: [constants.record_bytes_max]u8 = undefined;
    const text = render(&view, &buffer);
    var parsed: Parsed = undefined;
    try parse(text, &parsed);
    try testing.expectEqualStrings(view.rootfs, parsed.rootfs_slice());
}

fn sim_with_home(sim: *HostSim) void {
    sim.init(1, &.{});
    sim.environment_variables = &.{.{ .name = "HOME", .value = "/home/alice" }};
    sim.world.add_node("/home/alice", .dir);
}

test "the runs directory follows XDG_STATE_HOME, else HOME, and is made as needed" {
    // Goal: where records go, and that a missing directory (the first run on a machine) is
    // created, one level at a time, without failing.
    var sim: HostSim = undefined;
    sim_with_home(&sim);
    var dir: Dir = undefined;
    try testing.expect(locate(sim.interface(), &dir));
    try testing.expectEqualStrings("/home/alice/.local/state/zbx/runs", dir.text());
    try ensure(sim.interface(), &dir);
    try ensure(sim.interface(), &dir); // Again: they exist now.
    const kind = sim.world.node_kind("/home/alice/.local/state/zbx/runs");
    try testing.expectEqual(@as(?@import("../sim_world.zig").NodeKind, .dir), kind);

    const state = [_]@import("../host_sim.zig").EnvironmentVariable{
        .{ .name = "XDG_STATE_HOME", .value = "/var/state/" },
        .{ .name = "HOME", .value = "/home/alice" },
    };
    sim.environment_variables = &state;
    try testing.expect(locate(sim.interface(), &dir));
    try testing.expectEqualStrings("/var/state/zbx/runs", dir.text());

    sim.environment_variables = &.{.{ .name = "XDG_STATE_HOME", .value = "relative" }};
    try testing.expect(!locate(sim.interface(), &dir));
    sim.environment_variables = &.{};
    try testing.expect(!locate(sim.interface(), &dir));
}

test "saving is atomic, a failed rename leaves no temporary file, and a full disk is an error" {
    // Goal: a reader sees a whole record or none, and failures are reported, not hidden.
    var sim: HostSim = undefined;
    sim_with_home(&sim);
    var dir: Dir = undefined;
    try testing.expect(locate(sim.interface(), &dir));
    try ensure(sim.interface(), &dir);
    const view = sample_view();
    try save(sim.interface(), &dir, &view);
    const final = "/home/alice/.local/state/zbx/runs/web-1.zon";
    const temporary = "/home/alice/.local/state/zbx/runs/.web-1.tmp";
    try testing.expect(sim.world.read_written(final) != null);
    try testing.expect(sim.world.read_written(temporary) == null);

    sim.world.disk_full = true;
    try testing.expectError(error.NoSpace, save(sim.interface(), &dir, &view));
    try testing.expect(sim.world.read_written(temporary) == null);
    // The old record is still whole.
    var parsed: Parsed = undefined;
    try parse(sim.world.read_written(final).?, &parsed);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "pruning keeps the newest runs_max, deletes the oldest first, and counts what it cannot read" {
    // Goal: the retention rule and the upgrade rules together. Method: 30 good records with
    // distinct start times, one old-format record, one damaged, one newer-format and the one
    // just saved: 34 in all. The two that cannot be read count as the oldest and go; the
    // old-format one is a record like any other and stays.
    var sim: HostSim = undefined;
    sim_with_home(&sim);
    var dir: Dir = undefined;
    try testing.expect(locate(sim.interface(), &dir));
    try ensure(sim.interface(), &dir);
    var view = sample_view();
    var name_buffer: [16]u8 = undefined;
    for (0..30) |number| {
        view.name = try std.fmt.bufPrint(&name_buffer, "run-{d:0>2}", .{number});
        view.started = 1_000 + number;
        try save(sim.interface(), &dir, &view);
    }
    const prefix = "/home/alice/.local/state/zbx/runs/";
    const legacy = ".{\n    .name = \"legacy\",\n    .started = 500,\n}\n";
    const future = ".{\n    .version = 9,\n    .name = \"future\",\n    .started = 600,\n}\n";
    try testing.expect(sim.world.write_file(prefix ++ "legacy.zon", legacy) == null);
    try testing.expect(sim.world.write_file(prefix ++ "damaged.zon", "not a record") == null);
    try testing.expect(sim.world.write_file(prefix ++ "future.zon", future) == null);
    view.name = "latest";
    view.started = 2_000;
    try save(sim.interface(), &dir, &view);
    var skipped: Skipped = undefined;
    var pruned: Pruned = undefined;
    try prune(sim.interface(), &dir, "latest", &skipped, &pruned);
    try testing.expectEqual(@as(u32, 2), skipped.count);
    var listing: host_mod.DirListing = undefined;
    try sim.interface().list_directory(dir.text(), &listing);
    try testing.expectEqual(@as(u32, constants.runs_max), listing.count);
    try testing.expect(sim.world.read_written(prefix ++ "latest.zon") != null);
    try testing.expect(sim.world.read_written(prefix ++ "damaged.zon") == null);
    try testing.expect(sim.world.read_written(prefix ++ "future.zon") == null);
    try testing.expect(sim.world.read_written(prefix ++ "legacy.zon") != null);
    try testing.expect(sim.world.read_written(prefix ++ "run-00.zon") != null);
}

test "a record file whose stem is not a container name owns no container directory" {
    // Goal: pruning must not hand `Notes` or `my run` to the code that removes a container's
    // directory (it asserts a valid name). Method: 31 good records, the one just saved and two
    // strays that cannot be read make 34; the strays go as the oldest, and are not in `pruned`.
    var sim: HostSim = undefined;
    sim_with_home(&sim);
    var dir: Dir = undefined;
    try testing.expect(locate(sim.interface(), &dir));
    try ensure(sim.interface(), &dir);
    var view = sample_view();
    var name_buffer: [16]u8 = undefined;
    for (0..31) |number| {
        view.name = try std.fmt.bufPrint(&name_buffer, "run-{d:0>2}", .{number});
        view.started = 1_000 + number;
        try save(sim.interface(), &dir, &view);
    }
    const prefix = "/home/alice/.local/state/zbx/runs/";
    try testing.expect(sim.world.write_file(prefix ++ "Notes.zon", "notes") == null);
    try testing.expect(sim.world.write_file(prefix ++ "my run.zon", "x") == null);
    view.name = "latest";
    view.started = 2_000;
    try save(sim.interface(), &dir, &view);
    var skipped: Skipped = undefined;
    var pruned: Pruned = undefined;
    try prune(sim.interface(), &dir, "latest", &skipped, &pruned);
    try testing.expect(sim.world.read_written(prefix ++ "Notes.zon") == null);
    try testing.expectEqual(@as(u32, 0), pruned.count);
    try testing.expect(sim.world.read_written(prefix ++ "run-00.zon") != null);
}

test "version 4 keeps the tree and the upper layer, and an older record has neither" {
    // Goal: the fields the store added read back, and version 3 records (written by the M2
    // release) still read, with the two empty. Method: render with both, then cut them out.
    var view: View = .{
        .name = "web-1",
        .rootfs = "/home/alice/.local/state/zbx/containers/web-1/merged",
        .command = &.{"sh"},
        .labels = &.{},
        .started = 5,
        .ended = null,
        .exit = .running,
        .ids = .full,
        .zbx_version = "0.0.0",
    };
    view.tree = "b3:" ++ @import("../test_util.zig").repeat('a', 64);
    view.upper = "/home/alice/.local/state/zbx/containers/web-1/upper";
    var buffer: [constants.record_bytes_max]u8 = undefined;
    const text = render(&view, &buffer);
    var parsed: Parsed = undefined;
    try parse(text, &parsed);
    try testing.expectEqualStrings(view.tree, parsed.tree_slice());
    try testing.expectEqualStrings(view.upper, parsed.upper_slice());
    // A version 3 record: no such lines, and the version says 3.
    var old: [constants.record_bytes_max]u8 = undefined;
    var length: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "    .tree = ")) continue;
        if (std.mem.startsWith(u8, line, "    .upper = ")) continue;
        const now = std.fmt.comptimePrint("    .version = {d},", .{constants.record_version});
        const fixed = if (std.mem.eql(u8, line, now)) "    .version = 3," else line;
        @memcpy(old[length..][0..fixed.len], fixed);
        old[length + fixed.len] = '\n';
        length += fixed.len + 1;
    }
    try parse(old[0 .. length - 1], &parsed);
    try testing.expectEqual(@as(u32, 3), parsed.version);
    try testing.expectEqual(@as(usize, 0), parsed.tree_slice().len);
    try testing.expectEqual(@as(usize, 0), parsed.upper_slice().len);
    try testing.expectEqualStrings("web-1", parsed.name_slice());
}

/// A run record exactly as the M5 release wrote it (version 4), captured from that release's
/// own writer (commit 1fb59e1, `records.render`), not from the code above.
const record_written_by_m5 =
    \\.{
    \\    .version = 4,
    \\    .name = "web-1",
    \\    .rootfs = "/srv/alpine",
    \\    .command = .{ "/bin/sh", "-c", "echo \\"hi\\"\\n" },
    \\    .command_truncated = false,
    \\    .labels = .{ .{ "app", "web" } },
    \\    .started = 1760000000,
    \\    .ended = 1760000042,
    \\    .exit = .{ .exited = 3 },
    \\    .ids = .full,
    \\    .reason = .exited,
    \\    .detached = false,
    \\    .timed_out = false,
    \\    .scope = "",
    \\    .pid = 0,
    \\    .supervisor = 0,
    \\    .limit_memory = null,
    \\    .limit_pids = null,
    \\    .limit_cpu_millis = null,
    \\    .tree = "b3:abababababababababababababababababababababababababababababababab",
    \\    .upper = "",
    \\    .zbx = "0.0.0",
    \\}
    \\
;

test "a version 4 record, as M5 wrote it, reads with no network, forwards or names" {
    // Goal: the next release reads the last one's records (REVIEW.md). Method: the text M5's
    // writer produced; the fields version 5 added are unknown, not zero.
    var parsed: Parsed = undefined;
    try parse(record_written_by_m5, &parsed);
    try testing.expectEqual(@as(u32, 4), parsed.version);
    try testing.expectEqualStrings("web-1", parsed.name_slice());
    try testing.expect(parsed.network == null);
    try testing.expectEqual(@as(usize, 0), parsed.publish_slice().len);
    try testing.expectEqual(@as(u8, 0), parsed.env_names_count);
    try testing.expectEqual(@as(usize, 1), @as(usize, parsed.labels_count));
}

test "version 5 keeps the network, the forwards and the names of -e, and never a value" {
    // Goal: the new fields round-trip and nothing else about -e is in the text. Method: render
    // with a forward and two names; parse back; search the text for a marker no field holds.
    var view = sample_view();
    const forward = [_]spec_mod.Publish{
        .{ .host = 8080, .container = 80 },
        .{ .host = 1, .container = 2 },
    };
    const variables = [_][]const u8{ "POSTGRES_PASSWORD", "_x9" };
    view.network = .user;
    view.publish = &forward;
    view.env_names = &variables;
    var buffer: [constants.record_bytes_max]u8 = undefined;
    const text = render(&view, &buffer);
    try testing.expect(std.mem.indexOf(u8, text, "    .network = .user,\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, ".publish = .{ \"8080:80\", \"1:2\" },") != null);
    var parsed: Parsed = undefined;
    try parse(text, &parsed);
    try testing.expectEqual(@as(?spec_mod.Network, .user), parsed.network);
    try testing.expectEqual(@as(usize, 2), parsed.publish_slice().len);
    try testing.expectEqual(@as(u16, 8080), parsed.publish_slice()[0].host);
    try testing.expectEqual(@as(u8, 2), parsed.env_names_count);
    try testing.expectEqualStrings("POSTGRES_PASSWORD", parsed.env_name(0));
    try testing.expectEqualStrings("_x9", parsed.env_name(1));
    // The record of a run with none of them says so.
    const bare = render(&sample_view(), &buffer);
    try parse(bare, &parsed);
    try testing.expectEqual(@as(?spec_mod.Network, .none), parsed.network);
    try testing.expectEqual(@as(u8, 0), parsed.env_names_count);
}

test "version 5 fields that render never writes are Malformed, not a crash later" {
    // Goal: parse accepts only what render can write (REVIEW.md). Method: each damage of the
    // three fields on top of a good record.
    var view = sample_view();
    const forward = [_]spec_mod.Publish{.{ .host = 8080, .container = 80 }};
    view.network = .user;
    view.publish = &forward;
    var buffer: [constants.record_bytes_max]u8 = undefined;
    const good = render(&view, &buffer);
    var parsed: Parsed = undefined;
    try parse(good, &parsed);
    const damages = [_]struct { from: []const u8, to: []const u8 }{
        .{ .from = ".network = .user", .to = ".network = .none" }, // A forward without `user`.
        .{ .from = ".network = .user", .to = ".network = .other" },
        .{ .from = "\"8080:80\"", .to = "\"8080:80\", \"8080:81\"" }, // A host port twice.
        .{ .from = "\"8080:80\"", .to = "\"0:80\"" },
        .{ .from = "\"8080:80\"", .to = "\"8080\"" },
        .{ .from = ".env_names = \"\"", .to = ".env_names = \"A A\"" },
        .{ .from = ".env_names = \"\"", .to = ".env_names = \"1x\"" },
        .{ .from = ".env_names = \"\"", .to = ".env_names = \"a=b\"" },
        .{ .from = ".env_names = \"\"", .to = ".env_names = \"A  B\"" },
        .{ .from = ".env_names = \"\"", .to = ".env_names = \" A\"" },
        .{ .from = ".env_names = \"\"", .to = ".env_names = .{ \"A\" }" },
    };
    for (damages) |damage| {
        var copy: [constants.record_bytes_max]u8 = undefined;
        const length = std.mem.replacementSize(u8, good, damage.from, damage.to);
        _ = std.mem.replace(u8, good, damage.from, damage.to, &copy);
        try testing.expectError(error.Malformed, parse(copy[0..length], &parsed));
    }
    // Too many names: one past the bound.
    var many: [constants.run_env_count_max + 1][]const u8 = undefined;
    var storage: [constants.run_env_count_max + 1][4]u8 = undefined;
    for (&many, &storage, 0..) |*word, *bytes, index| {
        word.* = std.fmt.bufPrint(bytes, "V{d}", .{index}) catch unreachable; // Short.
    }
    var text: [constants.record_bytes_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&text);
    const head = ".{\n    .name = \"x\",\n    .started = 5,\n    .network = .none,\n" ++
        "    .env_names = \"";
    try writer.writeAll(head);
    for (many, 0..) |word, index| {
        try writer.print("{s}{s}", .{ if (index == 0) "" else " ", word });
    }
    try writer.writeAll("\",\n}\n");
    try testing.expectError(error.Malformed, parse(writer.buffered(), &parsed));
}

/// A run record exactly as M6 slice 1 wrote it (version 5), captured from that commit's own
/// writer (82c1f70, `records.render` of `sample_view` with a forward and an `-e` name), not from
/// the code above.
const record_written_by_m6_slice_1 =
    \\.{
    \\    .version = 5,
    \\    .name = "web-1",
    \\    .rootfs = "/srv/alpine",
    \\    .command = .{ "/bin/sh", "-c", "echo \"hi\"\n" },
    \\    .command_truncated = false,
    \\    .labels = .{ .{ "app", "web" } },
    \\    .started = 1760000000,
    \\    .ended = null,
    \\    .exit = .running,
    \\    .ids = .full,
    \\    .reason = .none,
    \\    .detached = false,
    \\    .timed_out = false,
    \\    .scope = "",
    \\    .pid = 0,
    \\    .supervisor = 0,
    \\    .limit_memory = null,
    \\    .limit_pids = null,
    \\    .limit_cpu_millis = null,
    \\    .tree = "",
    \\    .upper = "",
    \\    .network = .user,
    \\    .publish = .{ "5432:5432" },
    \\    .env_names = "POSTGRES_PASSWORD",
    \\    .zbx = "0.0.0",
    \\}
    \\
;

test "version 6 keeps the state volumes; versions 4 and 5, as written, read with none" {
    // Goal: the field this version adds round-trips as one string (two strings in a row would
    // read to the bundle's redactor as a secret's name and value), a list a run could not have
    // is refused, and the records the two releases before wrote read. Method: render, parse;
    // edits of the field; then the captured texts.
    var view: View = sample_view();
    const mounts = [_]volume.Mount{
        .{ .name = "pgdata", .target = "/var/lib/postgresql/data", .read_only = false },
        .{ .name = "cfg", .target = "/etc/app", .read_only = true },
    };
    view.state = &mounts;
    var buffer: [constants.record_bytes_max]u8 = undefined;
    const text = render(&view, &buffer);
    const line = "    .state = \"pgdata:/var/lib/postgresql/data cfg:/etc/app:ro\",\n";
    try testing.expect(std.mem.indexOf(u8, text, line) != null);
    var parsed: Parsed = undefined;
    try parse(text, &parsed);
    try testing.expectEqual(constants.record_version, parsed.version);
    try testing.expectEqual(@as(u8, 2), parsed.state_count);
    try testing.expectEqualStrings("pgdata", parsed.state_mount(0).name);
    try testing.expectEqualStrings("/etc/app", parsed.state_mount(1).target);
    try testing.expect(parsed.state_mount(1).read_only);
    const bad = [_][]const u8{
        "    .state = \"pgdata\",\n",
        "    .state = \"a:/x a:/y\",\n",
        "    .state = \"a:/x b:/x/y\",\n",
        "    .state = \"Bad:/x\",\n",
        "    .state = \"a:/x  b:/y\",\n",
        "    .state = \"a:/x b:/y c:/z d:/w e:/v f:/u g:/t h:/s i:/r\",\n",
    };
    for (bad) |edit| {
        var edited: [constants.record_bytes_max]u8 = undefined;
        const size = std.mem.replacementSize(u8, text, line, edit);
        _ = std.mem.replace(u8, text, line, edit, &edited);
        try testing.expectError(error.Malformed, parse(edited[0..size], &parsed));
    }
    try parse(record_written_by_m6_slice_1, &parsed);
    try testing.expectEqual(@as(u32, 5), parsed.version);
    try testing.expectEqual(@as(u8, 0), parsed.state_count);
    try testing.expectEqualStrings("POSTGRES_PASSWORD", parsed.env_name(0));
    try parse(record_written_by_m5, &parsed);
    try testing.expectEqual(@as(u32, 4), parsed.version);
    try testing.expectEqual(@as(u8, 0), parsed.state_count);
}
