//! The instructions that make a step: `RUN` (a root step), `COPY` and `ADD` (a copy step). Each
//! step is based on the stage's head and becomes its new head; each gets a note naming its
//! Dockerfile line and a line in the report (docs/briefs/M9-dockerfile-import.md, "The
//! mapping").

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const file_mod = @import("../build/file.zig");
const lines = @import("lines.zig");
const words = @import("words.zig");
const network = @import("network.zig");
const report_mod = @import("report.zig");
const refusal_mod = @import("refusal.zig");
const translate = @import("translate.zig");
const stages = @import("stages.zig");

const Translator = translate.Translator;
const Error = translate.Error;
const Refused = refusal_mod.Refused;
const refuse = refusal_mod.refuse;
const Instruction = lines.Instruction;
const indent = "            ";

/// The value of `key` in a mount's `key=value,...` list, as written.
pub fn mount_option(value: []const u8, key: []const u8) ?[]const u8 {
    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |part| {
        const equals = std.mem.indexOfScalar(u8, part, '=') orelse part.len;
        if (!std.mem.eql(u8, part[0..equals], key)) continue;
        return if (equals == part.len) "" else part[equals + 1 ..];
    }
    return null;
}

const Cache = struct {
    id: []const u8,
    path: []const u8,
    ro: bool,
    mode: ?[]const u8,
    uid: ?[]const u8,
    gid: ?[]const u8,
};

const Bind = struct { from: []const u8, source: []const u8, to: []const u8 };

const Mounts = struct {
    caches: [words.flags_max]Cache,
    caches_count: u32,
    binds: [words.flags_max]Bind,
    binds_count: u32,
};

/// The step's name, `<stage>-<n>`, and its note, report line and draft position; writes the
/// step's opening and its base.
fn begin(t: *Translator, instruction: *const Instruction, kind: report_mod.Kind) Error![]const u8 {
    const ws = t.ws;
    const line = instruction.line;
    const index = ws.report.steps_count;
    if (index == constants.build_steps_max) {
        return refuse(t.refusal(), .E0815, line, "the target makes more than {d} steps; " ++
            "Dockerfile:{d} would be one more", .{ constants.build_steps_max, line }, "import " ++
            "a smaller --target, or merge RUN lines", .{});
    }
    const state = t.state();
    const base = state.head orelse return refuse(t.refusal(), .E0811, line, "Dockerfile:{d} " ++
        "makes a step on FROM scratch, and the builder has no empty base", .{line}, "start " ++
        "the stage FROM an image, and copy what it builds into a scratch stage", .{});
    const stage = &ws.stages[t.stage];
    var buffer: [stages.slug_bytes_max]u8 = undefined;
    stage.steps_count += 1;
    const step = &ws.report.steps[index];
    const name = std.fmt.bufPrint(&step.name, "{s}-{d}", .{
        stages.slug(t, t.stage, &buffer), stage.steps_count,
    }) catch unreachable; // A slug and a step number fit the name buffer.
    step.name_len = @intCast(name.len);
    step.line = line;
    step.kind = kind;
    step.network = null;
    step.matched = false;
    step.cache = false;
    step.bind = false;
    ws.notes[index] = try translate.note(t, instruction);
    ws.draft_lines[index] = @intCast(std.mem.count(u8, t.draft.buffered(), "\n") + 1);
    ws.report.steps_count += 1;
    try t.put("        .{\n");
    try t.put_field("name", name);
    try t.put_field("base", base);
    return name;
}

fn end(t: *Translator, name: []const u8) Refused!void {
    try t.put("        },\n");
    const start = t.out.mark();
    try t.out.push(t.refusal(), t.line, "step:");
    try t.out.push(t.refusal(), t.line, name);
    t.state().head = t.out.since(start);
}

pub fn run(t: *Translator, instruction: *const Instruction) Error!void {
    const line = instruction.line;
    var flags: words.Flags = undefined;
    try words.flags_of(t.text(instruction.text), line, &flags, t.refusal());
    var mounts: Mounts = undefined;
    mounts.caches_count = 0;
    mounts.binds_count = 0;
    var no_network = false;
    for (flags.slice()) |flag| {
        const value = flag.value orelse "";
        if (std.mem.eql(u8, flag.name, "mount")) {
            try mount(t, line, value, &mounts);
        } else if (std.mem.eql(u8, flag.name, "network")) {
            if (std.mem.eql(u8, value, "none")) {
                no_network = true;
            } else if (!std.mem.eql(u8, value, "default")) {
                return unsupported(t, line, "RUN --network=", value, "remove the flag");
            }
        } else if (std.mem.eql(u8, flag.name, "security")) {
            if (!std.mem.eql(u8, value, "sandbox")) {
                return unsupported(t, line, "RUN --security=", value, "remove the flag");
            }
            t.drop(line, "RUN --security=sandbox", "ignored: every step is sandboxed");
        } else {
            return unsupported(t, line, "RUN --", flag.name, "remove the flag");
        }
    }
    var argv: words.WordList = undefined;
    const script = try command(t, instruction, flags.rest, &argv);
    const network_why: ?[]const u8 = if (no_network) null else switch (t.options.network) {
        .none => null,
        .all => "--network all",
        .detect => network.detect(script),
    };
    const name = try begin(t, instruction, .run);
    const step = &t.ws.report.steps[t.ws.report.steps_count - 1];
    step.network = network_why;
    step.matched = network_why != null and t.options.network == .detect;
    step.cache = mounts.caches_count > 0;
    step.bind = mounts.binds_count > 0;
    try step_env(t, network_why != null);
    try t.put_list(indent, "run", argv.slice());
    if (network_why != null) try t.put(indent ++ ".network = true,\n");
    try t.put(indent ++ ".output = .root,\n");
    const state = t.state();
    if (state.user) |user| try t.put_field("user", user);
    if (state.workdir) |workdir| try t.put_field("workdir", workdir);
    try put_mounts(t, &mounts);
    try end(t, name);
}

fn unsupported(
    t: *Translator,
    line: u32,
    what: []const u8,
    value: []const u8,
    comptime fix: []const u8,
) Refused {
    return refuse(t.refusal(), .E0811, line, "Dockerfile:{d} has {s}{s}, which zbx import " ++
        "does not translate", .{ line, what, value }, fix, .{});
}

/// The argv of a `RUN`, into `argv`; returns the text network detection reads.
fn command(
    t: *Translator,
    instruction: *const Instruction,
    rest: []const u8,
    argv: *words.WordList,
) Error![]const u8 {
    const line = instruction.line;
    const shell = t.state().shell.slice();
    if (instruction.heredocs_count > 1) {
        return unsupported(t, line, "RUN with ", "two heredocs", "write one heredoc, or a script");
    }
    if (instruction.heredocs_count == 0) {
        if (try words.exec_form(rest, line, &t.out, argv, t.refusal())) {
            if (argv.count == 0) return nothing(t, line);
            return rest;
        }
        if (rest.len == 0) return nothing(t, line);
        try shell_argv(t, line, shell, rest, argv);
        return rest;
    }
    const heredoc = &instruction.heredoc;
    const marker = t.text(heredoc.marker);
    const body = t.text(heredoc.body);
    const at = std.mem.indexOf(u8, rest, marker) orelse
        return unsupported(t, line, "RUN with ", "a heredoc after its flags", "write the " ++
            "heredoc marker after RUN's flags");
    const before = std.mem.trim(u8, rest[0..at], " \t");
    const after = std.mem.trim(u8, rest[at + marker.len ..], " \t");
    if (after.len > 0) {
        return unsupported(t, line, "RUN <<marker ", after, "put the command before the " ++
            "marker, as `RUN python3 <<EOF`");
    }
    if (before.len == 0) {
        if (std.mem.startsWith(u8, body, "#!")) {
            return unsupported(t, line, "RUN with ", "a heredoc that starts with #!", "write " ++
                "the interpreter before the marker, as `RUN python3 <<EOF`");
        }
        try shell_argv(t, line, shell, body, argv);
        return body;
    }
    // The command reads the heredoc: the shell runs the whole of it, terminator included.
    var name = marker[2..];
    if (name.len > 0 and name[0] == '-') name = name[1..];
    name = std.mem.trim(u8, name, "\"'");
    const start = t.out.mark();
    for ([_][]const u8{ rest, "\n", body, name, "\n" }) |piece| {
        try t.out.push(t.refusal(), line, piece);
    }
    const whole = t.out.since(start);
    try shell_argv(t, line, shell, whole, argv);
    return whole;
}

fn nothing(t: *Translator, line: u32) Refused {
    return refuse(t.refusal(), .E0810, line, "Dockerfile:{d} has RUN with nothing to run", .{
        line,
    }, "give RUN a command, or remove the line", .{});
}

fn shell_argv(
    t: *Translator,
    line: u32,
    shell: []const []const u8,
    text: []const u8,
    argv: *words.WordList,
) Refused!void {
    _ = t;
    _ = line;
    assert(shell.len + 1 <= constants.import_words_max);
    @memcpy(argv.items[0..shell.len], shell);
    argv.items[shell.len] = text;
    argv.count = @intCast(shell.len + 1);
}

/// `RUN --mount=...`: a cache becomes `.caches`, a bind from a stage `.binds`; the rest is
/// refused.
fn mount(t: *Translator, line: u32, written: []const u8, mounts: *Mounts) Error!void {
    const context = t.stage_context(line);
    const value = try words.word_of(written, &context, &t.out, t.refusal());
    const kind = mount_option(value, "type") orelse "bind";
    const target = mount_option(value, "target") orelse mount_option(value, "dst") orelse
        mount_option(value, "destination");
    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |part| {
        const key = part[0 .. std.mem.indexOfScalar(u8, part, '=') orelse part.len];
        const known = [_][]const u8{
            "type", "target",  "dst",      "destination", "source",    "src",  "from",
            "id",   "ro",      "readonly", "rw",          "readwrite", "mode", "uid",
            "gid",  "sharing",
        };
        for (known) |name| {
            if (std.mem.eql(u8, name, key)) break;
        } else return unsupported(t, line, "RUN --mount option ", key, "remove the option");
    }
    const state = t.state();
    if (std.mem.eql(u8, kind, "cache")) {
        if (mount_option(value, "from") != null) {
            return unsupported(t, line, "RUN --mount=type=cache,", "from=...", "remove from=, " ++
                "the cache starts empty");
        }
        const path = try translate.absolute(t, line, state.directory(), target orelse
            return no_target(t, line), false);
        const sharing = mount_option(value, "sharing") orelse "locked";
        if (!std.mem.eql(u8, sharing, "locked")) {
            t.drop(line, "RUN --mount=type=cache sharing", "became sharing=locked");
        }
        const ro = mount_option(value, "ro") orelse mount_option(value, "readonly");
        mounts.caches[mounts.caches_count] = .{
            .id = mount_option(value, "id") orelse path,
            .path = path,
            .ro = ro != null and !std.mem.eql(u8, ro.?, "false"),
            .mode = mount_option(value, "mode"),
            .uid = mount_option(value, "uid"),
            .gid = mount_option(value, "gid"),
        };
        mounts.caches_count += 1;
        return;
    }
    if (!std.mem.eql(u8, kind, "bind")) {
        return unsupported(t, line, "RUN --mount=type=", kind, "copy what the step needs " ++
            "into the stage, or pass it at run time");
    }
    if (mount_option(value, "rw") != null or mount_option(value, "readwrite") != null) {
        return unsupported(t, line, "RUN --mount=type=bind,", "rw", "copy the files into " ++
            "the stage with COPY instead");
    }
    const from_name = mount_option(value, "from") orelse
        return unsupported(t, line, "RUN --mount=type=bind ", "from the context", "COPY the " ++
            "files into the stage instead; the builder mounts only a stage's tree");
    const from = try stage_head(t, line, from_name) orelse
        return unsupported(t, line, "RUN --mount=type=bind,from=", from_name, "make a stage " ++
            "FROM the image and bind from it");
    const source = mount_option(value, "source") orelse mount_option(value, "src") orelse "/";
    mounts.binds[mounts.binds_count] = .{
        .from = from,
        .source = try translate.absolute(t, line, "/", source, false),
        .to = try translate.absolute(t, line, state.directory(), target orelse
            return no_target(t, line), false),
    };
    mounts.binds_count += 1;
}

fn no_target(t: *Translator, line: u32) Refused {
    return refuse(t.refusal(), .E0810, line, "Dockerfile:{d} has RUN --mount with no target", .{
        line,
    }, "add target=<path> to the mount", .{});
}

/// `step:<last step>` of the stage `name` names; null when it names an image. A stage with no
/// steps yet gives its own base.
fn stage_head(t: *Translator, line: u32, name: []const u8) Refused!?[]const u8 {
    const used = try stages.from_stage(t, line, name, t.stage) orelse return null;
    const stage = &t.ws.stages[used];
    assert(stage.reached);
    return stage.state.head orelse refuse(t.refusal(), .E0811, line, "Dockerfile:{d} uses " ++
        "stage `{s}`, which is FROM scratch with no steps", .{ line, name }, "copy from the " ++
        "stage that fills it", .{});
}

fn put_mounts(t: *Translator, mounts: *const Mounts) Refused!void {
    if (mounts.caches_count > 0) {
        try t.put(indent ++ ".caches = .{\n");
        for (mounts.caches[0..mounts.caches_count]) |cache| {
            try t.put(indent ++ "    .{ .id = ");
            try t.put_string(cache.id);
            try t.put(", .path = ");
            try t.put_string(cache.path);
            if (cache.ro) try t.put(", .ro = true");
            if (cache.mode) |mode| {
                try t.put(", .mode = ");
                try t.put_string(mode);
            }
            if (cache.uid) |uid| try number_field(t, "uid", uid);
            if (cache.gid) |gid| try number_field(t, "gid", gid);
            try t.put(" },\n");
        }
        try t.put(indent ++ "},\n");
    }
    if (mounts.binds_count > 0) {
        try t.put(indent ++ ".binds = .{\n");
        for (mounts.binds[0..mounts.binds_count]) |bind| {
            try t.put(indent ++ "    .{ .from = ");
            try t.put_string(bind.from);
            try t.put(", .source = ");
            try t.put_string(bind.source);
            try t.put(", .to = ");
            try t.put_string(bind.to);
            try t.put(" },\n");
        }
        try t.put(indent ++ "},\n");
    }
}

fn number_field(t: *Translator, field: []const u8, number: []const u8) Refused!void {
    const good = number.len > 0 and number.len <= 10 and
        for (number) |byte| {
            if (!std.ascii.isDigit(byte)) break false;
        } else true;
    if (!good or (std.fmt.parseInt(u32, number, 10) catch null) == null) {
        const what = "RUN --mount=type=cache with a non-numeric ";
        return unsupported(t, t.line, what, field, "write the id as a number");
    }
    try t.put(", .");
    try t.put(field);
    try t.put(" = ");
    try t.put(number);
}

/// The step's env: the stage's own `ENV`s but the fixed ones, then the `ARG`s in scope that
/// no `ENV` hides, then, for a step with the network, the proxy `--build-arg`s.
fn step_env(t: *Translator, with_network: bool) Refused!void {
    const ws = t.ws;
    const state = t.state();
    var count: u32 = 0;
    for (state.env_slice()) |pair| {
        if (!pair.ours or file_mod.is_fixed_env(pair.key)) continue;
        try env_item(t, &count, pair.key, pair.value);
    }
    for (ws.args[0..ws.args_count], 0..) |entry, index| {
        const value = entry.value orelse continue;
        if (state.env_value(entry.name) != null) continue;
        if (translate.is_proxy(entry.name) or file_mod.is_fixed_env(entry.name)) continue;
        const later = for (ws.args[index + 1 .. ws.args_count]) |other| {
            if (std.mem.eql(u8, other.name, entry.name)) break true;
        } else false;
        if (later) continue;
        try env_item(t, &count, entry.name, value);
    }
    if (with_network) {
        for (translate.proxy_names) |name| {
            const value = translate.build_arg(t.options, name) orelse continue;
            if (state.env_value(name) != null) continue;
            try env_item(t, &count, name, value);
        }
    }
    if (count > 0) try t.put(" },\n");
}

fn env_item(t: *Translator, count: *u32, key: []const u8, value: []const u8) Refused!void {
    try t.put(if (count.* == 0) indent ++ ".env = .{ " else ", ");
    try t.put_string(try t.join(key, value));
    count.* += 1;
}

const CopyFlags = struct {
    from: ?[]const u8 = null,
    chown: ?[]const u8 = null,
    chmod: ?[]const u8 = null,
    unpack: bool = true,
    excludes: [words.flags_max][]const u8 = undefined,
    excludes_count: u32 = 0,
    /// `ADD --checksum` or `--keep-git-dir`: refused after the sources, so that `ADD
    /// --checksum=... <url>` is refused for its URL.
    remote_flag: ?[]const u8 = null,
};

fn copy_flags(
    t: *Translator,
    instruction: *const Instruction,
    flags: *const words.Flags,
    context: *const words.Context,
) Error!CopyFlags {
    const line = instruction.line;
    const add = instruction.keyword == .add;
    var result: CopyFlags = .{};
    for (flags.slice()) |flag| {
        const value = try words.word_of(flag.value orelse "", context, &t.out, t.refusal());
        const name = flag.name;
        if (std.mem.eql(u8, name, "from")) {
            result.from = value;
        } else if (std.mem.eql(u8, name, "chown")) {
            result.chown = value;
        } else if (std.mem.eql(u8, name, "chmod")) {
            result.chmod = value;
        } else if (std.mem.eql(u8, name, "exclude")) {
            result.excludes[result.excludes_count] = value;
            result.excludes_count += 1;
        } else if (std.mem.eql(u8, name, "link")) {
            t.drop(line, "COPY --link", "ignored: a copy step has its meaning already");
        } else if (add and std.mem.eql(u8, name, "unpack") and std.mem.eql(u8, value, "false")) {
            result.unpack = false;
        } else if (add and (std.mem.eql(u8, name, "checksum") or
            std.mem.eql(u8, name, "keep-git-dir")))
        {
            if (result.remote_flag == null) result.remote_flag = name;
        } else {
            return unsupported(t, line, "--", name, "remove the flag");
        }
    }
    assert(result.excludes_count <= flags.count);
    return result;
}

/// `COPY` and `ADD`: one copy step with one entry.
pub fn copy(t: *Translator, instruction: *const Instruction) Error!void {
    const line = instruction.line;
    const keyword = instruction.keyword.upper();
    if (instruction.heredocs_count > 0) {
        return unsupported(t, line, keyword, " <<EOF", "write the file into the context and " ++
            "COPY it");
    }
    var flags: words.Flags = undefined;
    try words.flags_of(t.text(instruction.text), line, &flags, t.refusal());
    const context = t.stage_context(line);
    const given = try copy_flags(t, instruction, &flags, &context);
    var list: words.WordList = undefined;
    if (!try words.exec_form(flags.rest, line, &t.out, &list, t.refusal())) {
        try words.words_of(flags.rest, &context, &t.out, &list, t.refusal());
    }
    const items = list.slice();
    if (items.len < 2) {
        return refuse(t.refusal(), .E0810, line, "Dockerfile:{d} has {s} without a source " ++
            "and a destination", .{ line, keyword }, "write {s} <source>... <destination>", .{
            keyword,
        });
    }
    const sources = items[0 .. items.len - 1];
    if (instruction.keyword == .add) try add_sources(t, line, sources, given.unpack);
    if (given.remote_flag) |flag| return unsupported(t, line, "ADD --", flag, "remove the flag");
    const to = try translate.absolute(t, line, t.state().directory(), items[items.len - 1], true);
    var from_text: ?[]const u8 = null;
    if (given.from) |name| {
        from_text = try stage_head(t, line, name) orelse image: {
            _ = try t.reach(line, name);
            break :image name;
        };
    }
    const name = try begin(t, instruction, .copy);
    try put_copy(t, &given, from_text, sources, to);
    try end(t, name);
}

fn put_copy(
    t: *Translator,
    given: *const CopyFlags,
    from_text: ?[]const u8,
    sources: []const []const u8,
    to: []const u8,
) Refused!void {
    try t.put(indent ++ ".copy = .{\n" ++ indent ++ "    .{ ");
    if (from_text) |text| {
        try t.put(".from = ");
        try t.put_string(text);
        try t.put(", ");
    }
    try t.put(".src = .{");
    for (sources, 0..) |source, index| {
        try t.put(if (index == 0) " " else ", ");
        try t.put_string(if (from_text == null) project_path(source) else source);
    }
    try t.put(" }, .to = ");
    try t.put_string(to);
    if (given.chown) |chown| {
        try t.put(", .chown = ");
        try t.put_string(chown);
    }
    if (given.chmod) |chmod| {
        try t.put(", .chmod = ");
        try t.put_string(chmod);
    }
    if (given.excludes_count > 0) {
        try t.put(", .exclude = .{");
        for (given.excludes[0..given.excludes_count], 0..) |pattern, index| {
            try t.put(if (index == 0) " " else ", ");
            try t.put_string(pattern);
        }
        try t.put(" }");
    }
    try t.put(" },\n" ++ indent ++ "},\n");
}

/// A context source as the builder reads it: relative to the project (Docker reads `/x` there
/// as `x`, and `/` as the whole context).
fn project_path(source: []const u8) []const u8 {
    const trimmed = std.mem.trimStart(u8, source, "/");
    return if (trimmed.len == 0) "." else trimmed;
}

const archives = [_][]const u8{
    ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar.zst",
};

/// `ADD` of a URL, a git repository or a local archive is refused: zbx would fetch or unpack
/// at build time with no checksum.
fn add_sources(t: *Translator, line: u32, sources: []const []const u8, unpack: bool) Refused!void {
    for (sources) |source| {
        const remote = std.mem.indexOf(u8, source, "://") != null or
            std.mem.startsWith(u8, source, "git@");
        if (remote) {
            const fix = "fetch it in a RUN with a checksum: `RUN curl -fsSLo /f <url> && " ++
                "echo \"<sha256>  /f\" | sha256sum -c`";
            return refuse(t.refusal(), .E0811, line, "Dockerfile:{d} has ADD {s}, which " ++
                "fetches at build time", .{ line, source }, fix, .{});
        }
        if (!unpack) continue;
        for (archives) |suffix| {
            if (!std.ascii.endsWithIgnoreCase(source, suffix)) continue;
            return refuse(t.refusal(), .E0811, line, "Dockerfile:{d} has ADD {s}, an archive " ++
                "ADD would unpack", .{ line, source }, "write ADD --unpack=false, or COPY it " ++
                "and unpack it in a RUN", .{});
        }
    }
}
