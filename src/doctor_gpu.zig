//! The GPU section of `zbx doctor` (M10 slice 3, docs/briefs/M10-gpu.md). Not a check: nothing
//! here fails the doctor, since a host without a GPU is a fine host. It lists what a `--gpu` or
//! `--device` run would find, and for each gap the one-line fix:
//!   - the CDI specs in the three directories, each read (or refused, and why), and the devices
//!     each names with whether this user can open every node it needs;
//!   - the NVIDIA driver version from /proc/driver/nvidia/version;
//!   - the render nodes and /dev/kfd with mode, group and whether the user is in the group.
//! Gathered into a fixed list of items (`Section`), then rendered as text lines or as the
//! `gpu` array of the `zbx.doctor/1` document.

const std = @import("std");
const assert = std.debug.assert;
const cdi = @import("runtime/cdi.zig");
const constants = @import("constants.zig");
const devices = @import("runtime/devices.zig");
const gpu = @import("runtime/gpu.zig");
const host_mod = @import("host.zig");
const text_util = @import("text.zig");

const Host = host_mod.Host;

pub const Kind = enum { spec, device, driver, node, fix };

pub const Item = struct {
    kind: Kind,
    /// Whether the thing is usable: a spec read, a device whose nodes this user can open.
    ok: bool,
    subject: text_util.Bounded(constants.doctor_gpu_subject_bytes_max) = .{},
    detail: text_util.Bounded(constants.doctor_gpu_detail_bytes_max) = .{},
};

pub const Section = struct {
    items: [constants.doctor_gpu_items_max]Item,
    count: u32,
    /// Items left out for want of room.
    omitted: u32,

    pub fn slice(section: *const Section) []const Item {
        assert(section.count <= section.items.len);
        return section.items[0..section.count];
    }

    fn add(section: *Section, kind: Kind, ok: bool) ?*Item {
        if (section.count == section.items.len) {
            section.omitted += 1;
            return null;
        }
        const item = &section.items[section.count];
        item.* = .{ .kind = kind, .ok = ok };
        section.count += 1;
        return item;
    }
};

const spec_directories = [_][:0]const u8{ "/var/run/cdi", "/etc/cdi" };
const generate = "nvidia-ctk cdi generate --format=json --output=/etc/cdi/nvidia.json";

/// Reads the host into `section`.
pub fn gather(host: Host, section: *Section) void {
    section.count = 0;
    section.omitted = 0;
    var gaps = Gaps{};
    gather_specs(host, section, &gaps);
    gather_driver(host, section, &gaps);
    gather_nodes(host, section, &gaps);
    gather_fixes(section, &gaps);
    assert(section.count <= section.items.len);
}

/// What to say a fix for, noted while gathering.
const Gaps = struct {
    specs: u32 = 0,
    driver: bool = false,
    /// A node the user cannot open, and its group.
    closed_gid: ?u32 = null,
    refused: bool = false,
    nodes: u32 = 0,
};

fn gather_specs(host: Host, section: *Section, gaps: *Gaps) void {
    var path: [constants.cdi_path_bytes_max + 1]u8 = undefined;
    var directories: [3][]const u8 = undefined;
    var count: usize = 0;
    if (config_directory(host, &path)) |config| {
        directories[count] = config;
        count += 1;
    }
    for (spec_directories) |directory| {
        directories[count] = directory;
        count += 1;
    }
    var files: u32 = 0;
    for (directories[0..count]) |directory| read_directory(host, directory, section, gaps, &files);
}

fn config_directory(host: Host, buffer: *[constants.cdi_path_bytes_max + 1]u8) ?[]const u8 {
    const room = constants.cdi_path_bytes_max - "/.config/cdi".len;
    const config = host.environment("XDG_CONFIG_HOME", room);
    if (config != null and config.?.len > 0 and config.?[0] == '/') {
        return std.fmt.bufPrint(buffer, "{s}/cdi", .{config.?}) catch null;
    }
    const home = host.environment("HOME", room) orelse return null;
    if (home.len == 0 or home[0] != '/') return null;
    return std.fmt.bufPrint(buffer, "{s}/.config/cdi", .{home}) catch null;
}

fn is_spec_name(name: []const u8) bool {
    const suffixes = [_][]const u8{ ".json", ".yaml", ".yml" };
    for (suffixes) |suffix| {
        if (std.mem.endsWith(u8, name, suffix)) return true;
    }
    return false;
}

fn name_less(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.lessThan(u8, left, right);
}

fn read_directory(
    host: Host,
    directory: []const u8,
    section: *Section,
    gaps: *Gaps,
    files: *u32,
) void {
    var directory_z: [constants.cdi_path_bytes_max + 1]u8 = undefined;
    @memcpy(directory_z[0..directory.len], directory);
    directory_z[directory.len] = 0;
    var listing: host_mod.DirListing = undefined;
    host.list_directory(directory_z[0..directory.len :0], &listing) catch return;
    var names: [constants.dir_entries_max][]const u8 = undefined;
    var count: usize = 0;
    var index: u32 = 0;
    while (index < listing.count) : (index += 1) {
        const name = listing.name(index);
        if (!is_spec_name(name)) continue;
        names[count] = name;
        count += 1;
    }
    std.mem.sort([]const u8, names[0..count], {}, name_less);
    for (names[0..count]) |name| {
        if (files.* == constants.cdi_dir_entries_max) return;
        files.* += 1;
        read_spec(host, directory, name, section, gaps);
    }
}

fn read_spec(
    host: Host,
    directory: []const u8,
    name: []const u8,
    section: *Section,
    gaps: *Gaps,
) void {
    var path: [constants.cdi_path_bytes_max + constants.dir_name_bytes_max + 2]u8 = undefined;
    const full = std.fmt.bufPrint(&path, "{s}/{s}", .{ directory, name }) catch return;
    gaps.specs += 1;
    var content: [constants.cdi_spec_bytes_max + 1]u8 = undefined;
    const bytes = host.read_file(full, &content) catch |err| {
        const why = if (err == error.FileTooLarge) "is bigger than 64 KiB" else "cannot be read";
        refused_spec(section, gaps, full, why);
        return;
    };
    var parsed: cdi.Parsed = undefined;
    if (cdi.parse(&parsed, bytes)) |problem| {
        refused_spec(section, gaps, full, problem.sentence());
        return;
    }
    const item = section.add(.spec, true) orelse return;
    item.subject.append_sanitised(full, constants.doctor_gpu_subject_bytes_max);
    item.detail.print("{s}, {d} devices", .{ parsed.slice(parsed.kind), parsed.devices_count });
    var index: u32 = 0;
    while (index < parsed.devices_count) : (index += 1) {
        device_row(host, &parsed, index, section, gaps);
    }
}

fn refused_spec(section: *Section, gaps: *Gaps, path: []const u8, why: []const u8) void {
    gaps.refused = true;
    const item = section.add(.spec, false) orelse return;
    item.subject.append_sanitised(path, constants.doctor_gpu_subject_bytes_max);
    item.detail.print("refused: {s}", .{why});
}

/// One device of a spec: its qualified name, and the first node of it (or of the spec's common
/// edits) that this user cannot open.
fn device_row(
    host: Host,
    parsed: *const cdi.Parsed,
    index: u32,
    section: *Section,
    gaps: *Gaps,
) void {
    const device = parsed.devices[index];
    var ok = true;
    var why: text_util.Bounded(constants.doctor_gpu_detail_bytes_max) = .{};
    const blocks = [_]cdi.Edits{ device.edits, parsed.common };
    for (blocks) |edits| {
        for (parsed.nodes[edits.nodes_at..][0..edits.nodes_count]) |node| {
            const path = parsed.slice(node.path);
            const problem = devices.look_path(host, path) orelse continue;
            if (ok) note_node(&why, path, problem, gaps);
            ok = false;
        }
    }
    const item = section.add(.device, ok) orelse return;
    item.subject.print("{s}={s}", .{ parsed.slice(parsed.kind), parsed.slice(device.name) });
    if (ok) item.detail.print("every node can be opened by you", .{}) else {
        item.detail.print("{s}", .{why.slice()});
    }
}

fn note_node(
    why: *text_util.Bounded(constants.doctor_gpu_detail_bytes_max),
    path: []const u8,
    problem: devices.NodeProblem,
    gaps: *Gaps,
) void {
    switch (problem) {
        .missing => why.print("{s} is not on this host", .{path}),
        .unreadable => why.print("{s} could not be looked at", .{path}),
        .not_character => why.print("{s} is not a character device", .{path}),
        .cannot_open => |node| {
            gaps.closed_gid = node.gid;
            why.print("you cannot open {s}: mode {o:0>4}, group {d}, {s}", .{
                path, node.mode & 0o7777, node.gid, membership(node),
            });
        },
    }
}

fn membership(node: host_mod.DeviceNode) []const u8 {
    return if (node.member) "you are in that group" else "you are not in that group";
}

fn gather_driver(host: Host, section: *Section, gaps: *Gaps) void {
    var content: [constants.file_bytes_max]u8 = undefined;
    const bytes = host.read_file("/proc/driver/nvidia/version", &content) catch return;
    gaps.driver = true;
    const item = section.add(.driver, true) orelse return;
    item.subject.print("NVIDIA driver", .{});
    item.detail.append_sanitised(driver_version(bytes), constants.doctor_gpu_detail_bytes_max);
}

/// The version of `NVRM version: NVIDIA UNIX x86_64 Kernel Module  550.54.15  Thu ...`: the
/// first word that starts with a digit and holds a dot; the whole first line when there is none.
fn driver_version(bytes: []const u8) []const u8 {
    const line = bytes[0 .. std.mem.indexOfScalar(u8, bytes, '\n') orelse bytes.len];
    var words = std.mem.tokenizeScalar(u8, line, ' ');
    while (words.next()) |word| {
        const digit = word.len > 0 and std.ascii.isDigit(word[0]);
        if (digit and std.mem.indexOfScalar(u8, word, '.') != null) return word;
    }
    return line;
}

fn gather_nodes(host: Host, section: *Section, gaps: *Gaps) void {
    var listing: host_mod.DirListing = undefined;
    var names: [constants.dir_entries_max][]const u8 = undefined;
    var count: usize = 0;
    if (host.list_directory(gpu.dri_directory, &listing)) {
        var index: u32 = 0;
        while (index < listing.count) : (index += 1) {
            const name = listing.name(index);
            if (std.mem.startsWith(u8, name, gpu.render_prefix)) {
                names[count] = name;
                count += 1;
            }
        }
    } else |_| {}
    std.mem.sort([]const u8, names[0..count], {}, name_less);
    for (names[0..count]) |name| {
        var path: [constants.device_path_bytes_max + 1]u8 = undefined;
        const full = std.fmt.bufPrint(&path, "/dev/dri/{s}", .{name}) catch continue;
        node_row(host, full, section, gaps);
    }
    node_row(host, gpu.kfd_path, section, gaps);
}

fn node_row(host: Host, path: []const u8, section: *Section, gaps: *Gaps) void {
    const node = host.device_node(path) catch return; // Not there: nothing to say.
    gaps.nodes += 1;
    const character = node.mode & 0o170000 == 0o020000;
    const open = character and node.can_open;
    if (!open and character) gaps.closed_gid = node.gid;
    const item = section.add(.node, open) orelse return;
    item.subject.append_sanitised(path, constants.device_path_bytes_max);
    item.detail.print("mode {o:0>4}, group {d}, {s}{s}", .{
        node.mode & 0o7777,
        node.gid,
        membership(node),
        if (open) "" else ", so you cannot open it",
    });
}

fn gather_fixes(section: *Section, gaps: *const Gaps) void {
    // A host with nothing GPU-shaped gets no section at all: its report is unchanged.
    if (gaps.driver and gaps.specs == 0) {
        const item = section.add(.fix, false) orelse return;
        item.subject.print("no CDI spec", .{});
        item.detail.print("write the host's spec first: {s}", .{generate});
    }
    if (gaps.refused) {
        const item = section.add(.fix, false) orelse return;
        item.subject.print("a spec was refused", .{});
        item.detail.print("fix or remove the file named above; a spec is read at every start", .{});
    }
    if (gaps.closed_gid) |gid| {
        const item = section.add(.fix, false) orelse return;
        item.subject.print("a node is closed to you", .{});
        item.detail.print("ask whoever runs this host to put you in group {d} (render for " ++
            "render nodes: sudo usermod -aG render $USER), then log in again", .{gid});
    }
}

/// One line per item, `gpu <kind> <subject>  <detail>`; false marks a gap with a `-` before it.
pub fn write_text(section: *const Section, writer: *std.Io.Writer) void {
    assert(section.count <= section.items.len);
    for (section.slice()) |item| {
        const mark = if (item.ok) "ok  " else "gap ";
        // Cannot fail: constants.zig asserts, at comptime, that the section fits a message.
        writer.print("gpu  {s}{s} {s}  {s}\n", .{
            mark, @tagName(item.kind), item.subject.slice(), item.detail.slice(),
        }) catch unreachable; // Same.
    }
    if (section.omitted > 0) {
        const more = "gpu  ... {d} more not shown\n";
        writer.print(more, .{section.omitted}) catch unreachable; // Same.
    }
}

/// The items as a JSON array body (no brackets), each
/// `{"kind":...,"ok":...,"subject":...,"detail":...}`.
pub fn write_json(section: *const Section, writer: *std.Io.Writer) void {
    assert(section.count <= section.items.len);
    const json_string = @import("bundle.zig").write_json_string;
    for (section.slice(), 0..) |item, index| {
        if (index > 0) writer.writeByte(',') catch unreachable; // Same bound as write_text.
        writer.print("{{\"kind\":\"{s}\",\"ok\":{s},\"subject\":", .{
            @tagName(item.kind), if (item.ok) "true" else "false",
        }) catch unreachable; // Same.
        json_string(writer, item.subject.slice()) catch unreachable; // Same.
        writer.writeAll(",\"detail\":") catch unreachable; // Same.
        json_string(writer, item.detail.slice()) catch unreachable; // Same.
        writer.writeByte('}') catch unreachable; // Same.
    }
}
