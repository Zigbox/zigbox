//! `zbx build --graph`: the project's build file, read and checked as a build would (`build/load
//! .zig`), and its graph printed without running anything: the steps in topological order, ties
//! broken by name, then the image. Text is one row per node, in padded columns; `--output json`
//! is the `zbx.build_graph/1` document of nodes and edges (`zbx schema build-graph`).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const bundle = @import("bundle.zig");
const errors = @import("diag/errors.zig");
const host_mod = @import("host.zig");
const text_util = @import("text.zig");
const file_mod = @import("build/file.zig");
const load_mod = @import("build/load.zig");
const graph_mod = @import("build/graph.zig");
const diagnose = @import("build/diagnose.zig");
const compose = @import("build/compose.zig");
const doctor = @import("doctor.zig");
const Diag = @import("diag/diag.zig").Diag;

const Host = host_mod.Host;
const BuildFile = file_mod.BuildFile;

pub const Error = error{ Failed, OutputFailed };
pub const Workspace = struct {
    loaded: load_mod.Workspace,
    composed: compose.Workspace,
};

/// The name the graph gives the image: no step can have it.
const image_name = "image";
/// The room output is gathered in before it is written: a string escaped for JSON, and more.
const out_bytes = 6 * constants.build_string_bytes_max + 1024;
/// The space between columns.
const gap = 3;

/// Output gathered and written in pieces of at most `out_bytes`.
const Out = struct {
    host: Host,
    diag: *Diag,
    buffer: [out_bytes]u8,
    len: u32,

    fn put(out: *Out, bytes: []const u8) Error!void {
        assert(out.len <= out_bytes);
        var rest = bytes;
        while (rest.len > 0) {
            if (out.len == out_bytes) try out.flush();
            const room = out_bytes - out.len;
            const length = @min(room, rest.len);
            @memcpy(out.buffer[out.len..][0..length], rest[0..length]);
            out.len += @intCast(length);
            rest = rest[length..];
        }
        assert(out.len <= out_bytes);
    }

    fn pad(out: *Out, count: usize) Error!void {
        assert(count <= out_bytes);
        const spaces: [64]u8 = @splat(' ');
        var left = count;
        while (left > 0) {
            const length = @min(left, spaces.len);
            try out.put(spaces[0..length]);
            left -= length;
        }
    }

    /// A value of the file, with unprintable bytes as `?`.
    fn put_text(out: *Out, text: []const u8) Error!void {
        assert(text.len <= constants.build_string_bytes_max);
        var safe: [constants.build_string_bytes_max]u8 = undefined;
        try out.put(text_util.sanitise(&safe, text));
    }

    fn put_json(out: *Out, text: []const u8) Error!void {
        assert(text.len <= constants.build_string_bytes_max);
        var escaped: [6 * constants.build_string_bytes_max + 2]u8 = undefined;
        var writer = std.Io.Writer.fixed(&escaped);
        // Cannot fail: each byte escapes to at most six, and the quotes fit.
        bundle.write_json_string(&writer, text) catch unreachable; // Same bound.
        try out.put(writer.buffered());
    }

    fn flush(out: *Out) Error!void {
        assert(out.len <= out_bytes);
        if (out.len == 0) return;
        out.host.write_all(.stdout, out.buffer[0..out.len]) catch |err| {
            errors.output_failed(out.diag, .stdout, err, out.host.last_errno());
            return error.OutputFailed;
        };
        out.len = 0;
    }
};

/// `zbx build`: with `--graph`, prints the graph; otherwise builds the steps in order, a row
/// each. `args.file` is `-f`'s value.
pub fn run(
    host: Host,
    workspace: *Workspace,
    args: anytype,
    options: compose.Options,
    facts: *doctor.Facts,
    diag: *Diag,
) Error!void {
    const json = options.json;
    assert(diag.code == null);
    const given: []const u8 = args.file orelse "";
    load_mod.load(host, host.filesystem(), given, &workspace.loaded, diag) catch {
        return error.Failed;
    };
    if (args.graph) return print_graph(host, &workspace.loaded, json, diag);
    const composed = &workspace.composed;
    const loaded = &workspace.loaded;
    if (graph_mod.unrunnable(&loaded.file, &loaded.graph)) |found| {
        diagnose.unrunnable(diag, loaded.shown(), &loaded.file, found);
        return error.Failed;
    }
    compose.run_steps(host, facts, loaded, composed, options, diag) catch |err| {
        return if (err == error.OutputFailed) error.OutputFailed else error.Failed;
    };
}

fn print_graph(
    host: Host,
    workspace: *const load_mod.Workspace,
    json: bool,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    var out: Out = .{ .host = host, .diag = diag, .buffer = undefined, .len = 0 };
    if (json) try graph_json(&out, workspace) else try graph_text(&out, workspace);
    try out.flush();
    assert(out.len == 0);
}

fn base_of(file: *const BuildFile) []const u8 {
    const base = if (file.image.base) |given| file.text(given) else "(empty)";
    assert(base.len > 0);
    return base;
}

fn graph_text(out: *Out, workspace: *const load_mod.Workspace) Error!void {
    const file = &workspace.file;
    const graph = &workspace.graph;
    assert(graph.count == file.steps_count);
    var name_width: u32 = image_name.len;
    var base_width: u32 = @intCast(base_of(file).len);
    for (file.steps_slice()) |*step| {
        name_width = @max(name_width, @as(u32, @intCast(file.text(step.name).len)));
        base_width = @max(base_width, @as(u32, @intCast(file.text(step.base).len)));
    }
    for (graph.order_slice()) |index| {
        const step = &file.steps[index];
        const name = file.text(step.name);
        var row = try Row.start(out, name, file.text(step.base), name_width, base_width);
        try row.words(file, "inputs ", step.inputs.slice());
        try row.words(file, "needs ", step.needs.slice());
        if (step.network) try row.part("network");
        if (step.output == .root) try row.part("output root");
        if (step.copy.count > 0) try row.count_part("copies ", step.copy.count);
        try out.put("\n");
    }
    var row = try Row.start(out, image_name, base_of(file), name_width, base_width);
    for (file.adds_slice(), 0..) |*add, index| {
        if (index == 0) try row.part("adds ") else try out.put(", ");
        try out.put_text(file.text(add.from));
        try out.put(" -> ");
        try out.put_text(file.text(add.to));
    }
    try out.put("\n");
}

/// One row of the text: the name and the base in their columns, then the parts, a gap between
/// each. Nothing pads the end of a row.
const Row = struct {
    out: *Out,
    /// The padding the first part gets after the base.
    base_pad: u32,
    parts: u32,

    fn start(
        out: *Out,
        name: []const u8,
        base: []const u8,
        name_width: u32,
        base_width: u32,
    ) Error!Row {
        assert(name.len <= name_width);
        assert(base.len <= base_width);
        try out.put_text(name);
        try out.pad(name_width - name.len + gap);
        try out.put("base ");
        try out.put_text(base);
        return .{ .out = out, .base_pad = @intCast(base_width - base.len + gap), .parts = 0 };
    }

    /// Starts a part with `head`; the caller writes the rest of it.
    fn part(row: *Row, head: []const u8) Error!void {
        assert(head.len > 0);
        try row.out.pad(if (row.parts == 0) row.base_pad else gap);
        try row.out.put(head);
        row.parts += 1;
        assert(row.parts <= 6);
    }

    /// A part that is a label and a number.
    fn count_part(row: *Row, label: []const u8, count: u32) Error!void {
        assert(count > 0);
        try row.part(label);
        var digits: [10]u8 = undefined;
        const text = std.fmt.bufPrint(&digits, "{d}", .{count}) catch unreachable; // u32 fits.
        try row.out.put(text);
    }

    fn words(
        row: *Row,
        file: *const BuildFile,
        label: []const u8,
        list: []const file_mod.Text,
    ) Error!void {
        assert(label.len > 0);
        if (list.len == 0) return;
        try row.part(label);
        for (list, 0..) |item, index| {
            if (index > 0) try row.out.put(" ");
            try row.out.put_text(file.text(item));
        }
    }
};

fn graph_json(out: *Out, workspace: *const load_mod.Workspace) Error!void {
    const file = &workspace.file;
    const graph = &workspace.graph;
    assert(graph.count == file.steps_count);
    try out.put("{\"schema\":\"zbx.build_graph/1\",\"path\":");
    try out.put_json(workspace.path.text());
    try out.put(",\"nodes\":[");
    for (graph.order_slice()) |index| {
        const step = &file.steps[index];
        try out.put("{\"name\":");
        try out.put_json(file.text(step.name));
        try out.put(",\"kind\":\"step\",\"base\":");
        try out.put_json(file.text(step.base));
        try json_list(out, file, ",\"inputs\":", step.inputs.slice());
        try json_list(out, file, ",\"needs\":", step.needs.slice());
        try out.put(if (step.network) ",\"network\":true" else ",\"network\":false");
        if (step.output == .root) try out.put(",\"output\":\"root\"");
        if (step.copy.count > 0) try json_count(out, ",\"copies\":", step.copy.count);
        try out.put("},");
    }
    try out.put("{\"name\":\"image\",\"kind\":\"image\",\"base\":");
    if (file.image.base) |base| try out.put_json(file.text(base)) else try out.put("null");
    try out.put(",\"adds\":[");
    for (file.adds_slice(), 0..) |*add, index| {
        try out.put(if (index == 0) "{\"from\":" else ",{\"from\":");
        try out.put_json(file.text(add.from));
        try out.put(",\"to\":");
        try out.put_json(file.text(add.to));
        try out.put("}");
    }
    try out.put("]}],\"edges\":[");
    try json_edges(out, workspace);
    try out.put("]}\n");
}

fn json_count(out: *Out, key: []const u8, count: u32) Error!void {
    assert(count > 0);
    try out.put(key);
    var digits: [10]u8 = undefined;
    const text = std.fmt.bufPrint(&digits, "{d}", .{count}) catch unreachable; // u32 fits.
    try out.put(text);
}

fn json_list(
    out: *Out,
    file: *const BuildFile,
    key: []const u8,
    list: []const file_mod.Text,
) Error!void {
    assert(key.len > 0);
    try out.put(key);
    try out.put("[");
    for (list, 0..) |item, index| {
        if (index > 0) try out.put(",");
        try out.put_json(file.text(item));
    }
    try out.put("]");
}

/// Every edge, from what is needed to what needs it: in the nodes' order, then each node's
/// needs in the file's order; the image's are its adds, each step once.
fn json_edges(out: *Out, workspace: *const load_mod.Workspace) Error!void {
    const file = &workspace.file;
    const graph = &workspace.graph;
    var count: u32 = 0;
    for (graph.order_slice()) |index| {
        const step = &file.steps[index];
        for (graph.after_slice(index)) |before| {
            try edge(out, file.text(file.steps[before].name), file.text(step.name), count);
            count += 1;
        }
    }
    if (graph.image_base) |before| {
        try edge(out, file.text(file.steps[before].name), image_name, count);
        count += 1;
    }
    for (file.adds_slice(), 0..) |*add, index| {
        const earlier = for (file.adds_slice()[0..index]) |*before| {
            if (std.mem.eql(u8, file.text(before.from), file.text(add.from))) break true;
        } else false;
        if (earlier) continue;
        if (graph.image_base) |base| {
            if (std.mem.eql(u8, file.text(file.steps[base].name), file.text(add.from))) continue;
        }
        try edge(out, file.text(add.from), image_name, count);
        count += 1;
    }
    assert(count <= constants.build_steps_max * constants.build_step_edges_max +
        constants.build_image_adds_max + 1);
}

fn edge(out: *Out, from: []const u8, to: []const u8, count: u32) Error!void {
    assert(from.len > 0);
    assert(to.len > 0);
    try out.put(if (count == 0) "{\"from\":" else ",{\"from\":");
    try out.put_json(from);
    try out.put(",\"to\":");
    try out.put_json(to);
    try out.put("}");
}
