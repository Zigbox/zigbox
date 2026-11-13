//! `zigbox.dockerfile.translate`: a Dockerfile, its `.dockerignore`, the build arguments, the
//! target and the platform in; a build file, the image references it reached and a report out
//! (docs/briefs/M9-dockerfile-import.md, "`zbx import`" and "The mapping"). It is a pure
//! function: the only thing it asks of its caller is the resolver, which says what an image
//! reference's env and workdir are (the CLI pulls and locks it; a test answers from a table).
//!
//! The work, in order: `lines.zig` reads the logical lines; `stages.zig` splits the stages,
//! expands each `FROM` and finds the stages the target reaches; each reached stage is translated
//! in file order (`config.zig` for the instructions that change the image's settings,
//! `steps.zig` for `RUN`, `COPY` and `ADD`), writing a draft build file. The draft is read with
//! the builder's own parser, so whatever the builder would refuse is refused here, with the
//! Dockerfile line; then it is written in the canonical form with the header and a note before
//! each step, and that is read again and must be the same file.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const file_mod = @import("../build/file.zig");
const render = @import("../build/render.zig");
const glob = @import("../build/glob.zig");
const lines = @import("lines.zig");
const words = @import("words.zig");
const report_mod = @import("report.zig");
const refusal_mod = @import("refusal.zig");
const stages = @import("stages.zig");

const Refusal = refusal_mod.Refusal;
const Refused = refusal_mod.Refused;
const refuse = refusal_mod.refuse;
const Writer = std.Io.Writer;

pub const BuildArg = struct { name: []const u8, value: []const u8 };

/// The host's platform: `TARGETOS`, `TARGETARCH`, `BUILDPLATFORM` and the rest are made of it.
pub const Platform = struct { os: []const u8, architecture: []const u8, variant: []const u8 };

pub const NetworkRule = enum { detect, all, none };

/// What the translation needs to know of a base image: its env (`KEY=VALUE`), for `$PATH` and
/// the like, and its workdir ("" for none), for relative paths.
pub const ImageFacts = struct { env: []const []const u8, workdir: []const u8 };

pub const Resolver = struct {
    context: *anyopaque,
    /// `error.Unresolved` stops the translation; the resolver keeps its own reason.
    resolve: *const fn (context: *anyopaque, reference: []const u8) error{Unresolved}!ImageFacts,
};

pub const Options = struct {
    dockerfile: []const u8,
    /// As the header and the report name it: `Dockerfile`, `docker/app.Dockerfile`.
    dockerfile_name: []const u8,
    dockerignore: []const u8,
    build_args: []const BuildArg,
    /// Null: the last stage.
    target: ?[]const u8,
    platform: Platform,
    network: NetworkRule,
    /// Refuse (E0814) a translation with a step that has the network or a cache.
    hermetic: bool,
    resolver: Resolver,
};

pub const Error = error{ Refused, Unresolved };

/// A `KEY=VALUE` of the image's env, as the stage has it.
pub const Pair = struct {
    key: []const u8,
    value: []const u8,
    /// Set by an `ENV` of the Dockerfile (not inherited from the base image): it goes into the
    /// steps' env and the config's.
    ours: bool,
};

/// An `ARG` in scope; a null value is declared with no default and no `--build-arg`.
pub const Arg = struct { name: []const u8, value: ?[]const u8 };

pub const Argv = struct {
    items: [constants.build_config_argv_max][]const u8,
    count: u32,
    given: bool,

    pub fn slice(argv: *const Argv) []const []const u8 {
        assert(argv.count <= constants.build_config_argv_max);
        if (!argv.given) assert(argv.count == 0);
        return argv.items[0..argv.count];
    }
};

/// A stage's image settings as its instructions leave them; a stage built `FROM` another starts
/// from that one's.
pub const State = struct {
    /// What the next step is based on: an image reference or `step:<name>`; null for scratch.
    head: ?[]const u8,
    env: [constants.build_config_env_max]Pair,
    env_count: u32,
    image_workdir: []const u8,
    workdir: ?[]const u8,
    user: ?[]const u8,
    shell: Argv,
    entrypoint: Argv,
    cmd: Argv,
    /// `CMD` was given in this stage, so an `ENTRYPOINT` does not clear it.
    cmd_here: bool,
    labels: [constants.build_config_labels_max]Pair,
    labels_count: u32,

    pub fn env_slice(state: *const State) []const Pair {
        assert(state.env_count <= constants.build_config_env_max);
        return state.env[0..state.env_count];
    }

    pub fn labels_slice(state: *const State) []const Pair {
        assert(state.labels_count <= constants.build_config_labels_max);
        return state.labels[0..state.labels_count];
    }

    pub fn env_value(state: *const State, key: []const u8) ?[]const u8 {
        for (state.env_slice()) |pair| {
            if (std.mem.eql(u8, pair.key, key)) return pair.value;
        }
        return null;
    }

    /// The directory relative paths are against: the stage's `WORKDIR`, else the image's.
    pub fn directory(state: *const State) []const u8 {
        if (state.workdir) |workdir| return workdir;
        if (state.image_workdir.len > 0 and state.image_workdir[0] == '/') {
            return state.image_workdir;
        }
        return "/";
    }
};

pub const Base = union(enum) { scratch, image: []const u8, stage: u8 };

pub const Stage = struct {
    line: u32,
    /// As written after `AS`; stages are named case-insensitively, as Docker's are.
    name: ?[]const u8,
    base: Base,
    /// The instructions of the stage after its `FROM`, as indexes.
    begin: u32,
    end: u32,
    /// The stages this one uses (`FROM`, `COPY --from`, `--mount from`), one bit each.
    uses: u64,
    reached: bool,
    steps_count: u32,
    state: State,
};

pub const references_max = constants.import_stages_max;

pub const Workspace = struct {
    parsed: lines.Parsed,
    words: [constants.import_scratch_bytes_max]u8,
    stages: [constants.import_stages_max]Stage,
    stages_count: u32,
    globals: [constants.import_variables_max]Arg,
    globals_count: u32,
    /// The current stage's `ARG`s.
    args: [constants.import_variables_max]Arg,
    args_count: u32,
    platform_args: [8]Arg,
    /// The image references the translation reached, each once: what the lock must hold.
    references: [references_max][]const u8,
    references_count: u32,
    notes: [constants.build_steps_max][]const u8,
    /// For each step, the line of the draft it starts on, to name the Dockerfile line of a
    /// problem the builder's parser finds.
    draft_lines: [constants.build_steps_max]u32,
    header: [header_bytes_max]u8,
    header_len: u32,
    draft: [constants.build_render_bytes_max]u8,
    file: file_mod.BuildFile,
    check: file_mod.BuildFile,
    output: [constants.build_render_bytes_max]u8,
    report: report_mod.Report,
    refusal: Refusal,

    pub fn references_slice(ws: *const Workspace) []const []const u8 {
        assert(ws.references_count <= references_max);
        return ws.references[0..ws.references_count];
    }
};

const header_bytes_max = 1024;
pub const note_bytes_max = 96;

/// What one translation is doing: the workspace, the options, the stage being translated.
pub const Translator = struct {
    ws: *Workspace,
    options: *const Options,
    out: words.Out,
    draft: Writer,
    stage: u32,

    pub fn refusal(t: *Translator) *Refusal {
        return &t.ws.refusal;
    }

    pub fn text(t: *const Translator, range: lines.Range) []const u8 {
        return t.ws.parsed.slice(range);
    }

    pub fn state(t: *Translator) *State {
        assert(t.stage < t.ws.stages_count);
        return &t.ws.stages[t.stage].state;
    }

    /// The words context of the current stage: its env wins over its `ARG`s.
    pub fn stage_context(t: *const Translator, line: u32) words.Context {
        return .{
            .escape = t.ws.parsed.escape,
            .line = line,
            .lookup = .{ .context = t, .get = get_stage },
        };
    }

    /// The words context before the first stage and of a `FROM`: the global `ARG`s and the
    /// platform's.
    pub fn global_context(t: *const Translator, line: u32) words.Context {
        return .{
            .escape = t.ws.parsed.escape,
            .line = line,
            .lookup = .{ .context = t, .get = get_global },
        };
    }

    /// Copies `bytes` into the translation's own memory, so a slice of a caller's stays valid.
    pub fn keep(t: *Translator, line: u32, bytes: []const u8) Refused![]const u8 {
        const start = t.out.mark();
        try t.out.push(t.refusal(), line, bytes);
        return t.out.since(start);
    }

    pub fn put(t: *Translator, bytes: []const u8) Refused!void {
        t.draft.writeAll(bytes) catch return t.draft_full();
    }

    pub fn put_string(t: *Translator, value: []const u8) Refused!void {
        render.render_string(value, &t.draft) catch return t.draft_full();
    }

    /// `name = "value",` on a line of its own, at the step's depth.
    pub fn put_field(t: *Translator, name: []const u8, value: []const u8) Refused!void {
        try t.put("            .");
        try t.put(name);
        try t.put(" = ");
        try t.put_string(value);
        try t.put(",\n");
    }

    /// `.name = .{ "a", "b" },`, with `indent` before it.
    pub fn put_list(
        t: *Translator,
        indent: []const u8,
        name: []const u8,
        items: []const []const u8,
    ) Refused!void {
        try t.put(indent);
        try t.put(".");
        try t.put(name);
        try t.put(" = .{");
        for (items, 0..) |item, index| {
            try t.put(if (index == 0) " " else ", ");
            try t.put_string(item);
        }
        try t.put(if (items.len == 0) "},\n" else " },\n");
    }

    fn draft_full(t: *Translator) Refused {
        return refuse(t.refusal(), .E0815, 0, "the build file would be more than {d} bytes", .{
            constants.build_file_bytes_max,
        }, "import a smaller target with `--target`, or split the Dockerfile", .{});
    }

    /// Notes what did not carry over as an instruction (W0811).
    pub fn drop(t: *Translator, line: u32, what: []const u8, became: []const u8) void {
        t.ws.report.drop(line, what, became);
    }

    /// Records an image reference the build file uses, once, and asks the resolver about it.
    pub fn reach(t: *Translator, line: u32, reference: []const u8) Error!ImageFacts {
        const ws = t.ws;
        const known = for (ws.references_slice()) |seen| {
            if (std.mem.eql(u8, seen, reference)) break true;
        } else false;
        if (!known) {
            if (ws.references_count == references_max) {
                return refuse(t.refusal(), .E0815, line, "the Dockerfile names more than {d} " ++
                    "images", .{references_max}, "build the extra images first and copy from " ++
                    "one", .{});
            }
            ws.references[ws.references_count] = reference;
            ws.references_count += 1;
        }
        return t.options.resolver.resolve(t.options.resolver.context, reference);
    }
};

fn get_stage(context: *const anyopaque, name: []const u8) words.Value {
    const t: *const Translator = @ptrCast(@alignCast(context));
    const ws = t.ws;
    assert(t.stage < ws.stages_count);
    if (ws.stages[t.stage].state.env_value(name)) |value| return .{ .set = value };
    var index = ws.args_count;
    while (index > 0) {
        index -= 1;
        const arg = ws.args[index];
        if (!std.mem.eql(u8, arg.name, name)) continue;
        if (arg.value) |value| return .{ .set = value };
        return .missing;
    }
    return .unset;
}

fn get_global(context: *const anyopaque, name: []const u8) words.Value {
    const t: *const Translator = @ptrCast(@alignCast(context));
    const ws = t.ws;
    assert(ws.globals_count <= constants.import_variables_max);
    var index = ws.globals_count;
    while (index > 0) {
        index -= 1;
        const arg = ws.globals[index];
        if (!std.mem.eql(u8, arg.name, name)) continue;
        if (arg.value) |value| return .{ .set = value };
        return .missing;
    }
    for (ws.platform_args) |arg| {
        if (std.mem.eql(u8, arg.name, name)) return .{ .set = arg.value.? };
    }
    return .unset;
}

/// The `--build-arg` of that name, if one was given.
pub fn build_arg(options: *const Options, name: []const u8) ?[]const u8 {
    var found: ?[]const u8 = null;
    for (options.build_args) |arg| {
        if (std.mem.eql(u8, arg.name, name)) found = arg.value;
    }
    return found;
}

pub const proxy_names = [_][]const u8{
    "HTTP_PROXY", "HTTPS_PROXY", "FTP_PROXY", "NO_PROXY", "ALL_PROXY",
    "http_proxy", "https_proxy", "ftp_proxy", "no_proxy", "all_proxy",
};

pub fn is_proxy(name: []const u8) bool {
    for (proxy_names) |proxy| {
        if (std.mem.eql(u8, proxy, name)) return true;
    }
    return false;
}

/// Translates `options.dockerfile` into `ws`. On success the build file is the returned bytes,
/// `ws.references_slice()` the images it uses and `ws.report` what to tell the user. On
/// `error.Refused`, `ws.refusal` says why; on `error.Unresolved` the resolver does.
pub fn translate(ws: *Workspace, options: *const Options) Error![]const u8 {
    assert(options.dockerfile_name.len > 0);
    ws.stages_count = 0;
    ws.globals_count = 0;
    ws.args_count = 0;
    ws.references_count = 0;
    ws.report.dockerfile = options.dockerfile_name;
    ws.report.target = "";
    ws.report.stages_count = 0;
    ws.report.steps_count = 0;
    ws.report.dropped_count = 0;
    if (options.dockerfile.len > constants.import_dockerfile_bytes_max) {
        return refuse(&ws.refusal, .E0815, 0, "the Dockerfile is more than {d} bytes", .{
            constants.import_dockerfile_bytes_max,
        }, "split the Dockerfile", .{});
    }
    try lines.parse(options.dockerfile, &ws.parsed, &ws.refusal);
    var t: Translator = .{
        .ws = ws,
        .options = options,
        .out = .{ .bytes = &ws.words },
        .draft = .fixed(&ws.draft),
        .stage = 0,
    };
    try platform_args(&t);
    try directives(&t);
    try stages.split(&t);
    const target = try stages.reach(&t);
    try t.put(".{\n    .version = 1,\n");
    try exclude(&t);
    try t.put("    .steps = .{\n");
    for (0..ws.stages_count) |index| {
        if (!ws.stages[index].reached) continue;
        t.stage = @intCast(index);
        try stages.translate_stage(&t);
    }
    try t.put("    },\n");
    t.stage = target;
    try stages.image(&t);
    try t.put("}\n");
    return finish(&t);
}

fn platform_args(t: *Translator) Refused!void {
    const platform = t.options.platform;
    assert(platform.os.len > 0);
    assert(platform.architecture.len > 0);
    const start = t.out.mark();
    try t.out.push(t.refusal(), 0, platform.os);
    try t.out.push(t.refusal(), 0, "/");
    try t.out.push(t.refusal(), 0, platform.architecture);
    if (platform.variant.len > 0) {
        try t.out.push(t.refusal(), 0, "/");
        try t.out.push(t.refusal(), 0, platform.variant);
    }
    const whole = t.out.since(start);
    const names = [8][]const u8{
        "TARGETPLATFORM", "TARGETOS", "TARGETARCH", "TARGETVARIANT",
        "BUILDPLATFORM",  "BUILDOS",  "BUILDARCH",  "BUILDVARIANT",
    };
    const values = [4][]const u8{ whole, platform.os, platform.architecture, platform.variant };
    for (names, 0..) |name, index| {
        t.ws.platform_args[index] = .{ .name = name, .value = values[index % 4] };
    }
}

fn directives(t: *Translator) Refused!void {
    const parsed = &t.ws.parsed;
    if (parsed.syntax) |syntax| t.drop(syntax.line, "# syntax", "ignored: zbx reads the file");
    if (parsed.check) |check| t.drop(check.line, "# check", "ignored");
    assert(parsed.escape == '\\' or parsed.escape == '`');
}

/// The `.dockerignore`, as the file's `.exclude`: its lines but comments and blank ones.
fn exclude(t: *Translator) Refused!void {
    const text = t.options.dockerignore;
    if (text.len > constants.import_dockerignore_bytes_max) {
        return refuse(t.refusal(), .E0815, 0, ".dockerignore is more than {d} bytes", .{
            constants.import_dockerignore_bytes_max,
        }, "shorten .dockerignore", .{});
    }
    var count: u32 = 0;
    var number: u32 = 0;
    var parts = std.mem.splitScalar(u8, text, '\n');
    while (parts.next()) |raw| {
        number += 1;
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        if (glob.line_fault(line) != null) {
            return refuse(t.refusal(), .E0810, 0, ".dockerignore line {d}, `{s}`, is not a " ++
                "pattern zbx reads", .{ number, line }, "fix or remove that line", .{});
        }
        if (count == constants.build_exclude_lines_max) {
            return refuse(t.refusal(), .E0815, 0, ".dockerignore has more than {d} patterns", .{
                constants.build_exclude_lines_max,
            }, "merge patterns with `**`", .{});
        }
        try t.put(if (count == 0) "    .exclude = .{ " else ", ");
        try t.put_string(line);
        count += 1;
    }
    if (count > 0) try t.put(" },\n");
}

/// Reads the draft with the builder's parser, writes it canonically with the notes, and checks
/// that the result reads back to the same file.
fn finish(t: *Translator) Error![]const u8 {
    const ws = t.ws;
    var problem: file_mod.Problem = undefined;
    if (file_mod.parse(t.draft.buffered(), &ws.file, &problem) == .refused) {
        return refuse_problem(t, &problem);
    }
    assert(ws.file.steps_count == ws.report.steps_count);
    try header(t);
    const notes: render.Notes = .{
        .header = ws.header[0..ws.header_len],
        .steps = ws.notes[0..ws.file.steps_count],
    };
    var writer: Writer = .fixed(&ws.output);
    render.render_noted(&ws.file, &notes, &writer) catch return t.draft_full();
    const output = writer.buffered();
    if (output.len > constants.build_file_bytes_max) return t.draft_full();
    assert(file_mod.parse(output, &ws.check, &problem) == .parsed);
    assert(render.equal(&ws.file, &ws.check));
    if (t.options.hermetic) try hermetic(t);
    return output;
}

fn hermetic(t: *Translator) Refused!void {
    assert(t.options.hermetic);
    for (t.ws.report.steps_slice()) |*step| {
        if (!step.flagged()) continue;
        const why = if (step.network != null) "the network" else if (step.cache)
            "a cache mount"
        else
            "a bind mount";
        return refuse(t.refusal(), .E0814, step.line, "--hermetic: step {s} (Dockerfile:{d}) " ++
            "has {s}", .{ step.name_text(), step.line, why }, "drop --hermetic, or change " ++
            "Dockerfile:{d} so it needs neither the network nor a cache", .{step.line});
    }
}

/// The Dockerfile line of the step the draft's `line` is in; 0 past the steps.
fn step_line(t: *const Translator, draft_line: u32) u32 {
    const ws = t.ws;
    var found: u32 = 0;
    for (ws.draft_lines[0..ws.report.steps_count], 0..) |first, index| {
        if (first <= draft_line) found = ws.report.steps[index].line;
    }
    return found;
}

fn refuse_problem(t: *Translator, problem: *const file_mod.Problem) Refused {
    const line = step_line(t, problem.line);
    const field = if (problem.field) |field| @tagName(field) else @tagName(problem.level);
    const where = if (line == 0) "the image's settings" else "the step";
    switch (problem.kind) {
        .list_too_long, .text_too_long, .file_too_big, .string_too_long, .too_many_needs,
        .too_many_mounts,
        => return refuse(t.refusal(), .E0815, line, "{s} from Dockerfile:{d} goes past the " ++
            "builder's bound on .{s} ({t})", .{ where, line, field, problem.kind }, "split " ++
            "the instruction, or import a smaller --target", .{}),
        else => return refuse(t.refusal(), .E0811, line, "{s} from Dockerfile:{d} has .{s} " ++
            "`{s}`, which a build file cannot hold ({t})", .{
            where, line, field, problem.word_text(), problem.kind,
        }, "change the instruction at Dockerfile:{d}", .{line}),
    }
}

fn header(t: *Translator) Refused!void {
    const ws = t.ws;
    var writer: Writer = .fixed(&ws.header);
    write_header(t, &writer) catch {}; // A header too long for its buffer is cut.
    ws.header_len = @intCast(writer.buffered().len);
    sanitise(ws.header[0..ws.header_len]);
    if (ws.header_len > 0 and ws.header[ws.header_len - 1] != '\n') {
        ws.header[ws.header_len - 1] = '\n';
    }
    assert(ws.header_len <= header_bytes_max);
}

fn write_header(t: *Translator, writer: *Writer) Writer.Error!void {
    const options = t.options;
    try writer.print("// Imported by `zbx import` from {s}: target {s}, --network {t}", .{
        options.dockerfile_name, t.ws.report.target, options.network,
    });
    for (options.build_args) |arg| {
        if (is_proxy(arg.name)) {
            try writer.print(", --build-arg {s}", .{arg.name});
        } else try writer.print(", --build-arg {s}={s}", .{ arg.name, arg.value });
    }
    try writer.writeAll(".\n// Edit this file from here on: `zbx build` reads it, not the " ++
        "Dockerfile.\n");
}

/// Control bytes and bytes past ASCII become `?`, but line ends.
fn sanitise(bytes: []u8) void {
    for (bytes) |*byte| {
        if (byte.* == '\n') continue;
        if (byte.* < 0x20 or byte.* >= 0x7f) byte.* = '?';
    }
}

/// The note before the step that `instruction` makes: `Dockerfile:12  RUN apk add ...`.
pub fn note(t: *Translator, instruction: *const lines.Instruction) Refused![]const u8 {
    var buffer: [note_bytes_max]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    const text = t.text(instruction.text);
    const first = text[0 .. std.mem.indexOfScalar(u8, text, '\n') orelse text.len];
    writer.print("Dockerfile:{d}  {s} {s}", .{
        instruction.line, instruction.keyword.upper(), first,
    }) catch {
        @memcpy(buffer[buffer.len - 3 ..], "...");
        writer.end = buffer.len;
    };
    const kept = try t.keep(instruction.line, writer.buffered());
    const bytes = t.out.bytes[t.out.len - kept.len .. t.out.len];
    for (bytes) |*byte| {
        if (byte.* < 0x20 or byte.* >= 0x7f) byte.* = '?';
    }
    assert(bytes.len <= note_bytes_max);
    return bytes;
}

/// `path` made absolute against `directory` and cleaned: no `.`, `..` or empty parts. A
/// trailing `/` is kept when `keep_slash`, as a `COPY` destination needs it.
pub fn absolute(
    t: *Translator,
    line: u32,
    directory: []const u8,
    path: []const u8,
    keep_slash: bool,
) Refused![]const u8 {
    assert(directory.len > 0 and directory[0] == '/');
    var parts: [constants.path_bytes_max / 2 + 2][]const u8 = undefined;
    var count: usize = 0;
    const joined = [2][]const u8{ if (path.len > 0 and path[0] == '/') "" else directory, path };
    for (joined) |piece| {
        var it = std.mem.tokenizeScalar(u8, piece, '/');
        while (it.next()) |part| {
            if (std.mem.eql(u8, part, ".")) continue;
            if (std.mem.eql(u8, part, "..")) {
                count -|= 1;
                continue;
            }
            if (count == parts.len) return path_too_long(t, line);
            parts[count] = part;
            count += 1;
        }
    }
    const start = t.out.mark();
    for (parts[0..count]) |part| {
        try t.out.push(t.refusal(), line, "/");
        try t.out.push(t.refusal(), line, part);
    }
    const slash = keep_slash and path.len > 0 and path[path.len - 1] == '/';
    if (count == 0 or slash) try t.out.push(t.refusal(), line, "/");
    const result = t.out.since(start);
    if (result.len > constants.path_bytes_max) return path_too_long(t, line);
    return result;
}

fn path_too_long(t: *Translator, line: u32) Refused {
    return refuse(t.refusal(), .E0815, line, "Dockerfile:{d} names a path longer than {d} " ++
        "bytes", .{ line, constants.path_bytes_max }, "shorten the path", .{});
}
