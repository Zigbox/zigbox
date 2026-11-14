//! The stages of a Dockerfile: where each begins and ends, what it is built `FROM`, which other
//! stages it uses, and which ones the target reaches (docs/briefs/M9-dockerfile-import.md,
//! "`zbx import`"). Only reached stages are translated, so `--target` can skip a stage that
//! would be refused, and only their images are resolved.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const lines = @import("lines.zig");
const words = @import("words.zig");
const refusal_mod = @import("refusal.zig");
const translate = @import("translate.zig");
const config = @import("config.zig");
const steps = @import("steps.zig");

const Translator = translate.Translator;
const Error = translate.Error;
const Refused = refusal_mod.Refused;
const refuse = refusal_mod.refuse;

/// The longest stage part of a step name: the rest is `-` and the step's number in the stage.
pub const slug_bytes_max = constants.build_step_name_bytes_max - 4;

comptime {
    assert(constants.build_steps_max < 1000); // A step's number fits three digits.
    assert(constants.import_stages_max <= 64); // One bit each in `Stage.uses`.
}

/// Pass one: the global `ARG`s before the first `FROM`, then each `FROM` and the instructions
/// up to the next, and the stages each stage uses.
pub fn split(t: *Translator) Error!void {
    const ws = t.ws;
    const instructions = ws.parsed.instructions_slice();
    var index: u32 = 0;
    while (index < instructions.len and instructions[index].keyword != .from) : (index += 1) {
        const instruction = &instructions[index];
        if (instruction.keyword != .arg) {
            return refuse(t.refusal(), .E0810, instruction.line, "Dockerfile:{d} has {s} " ++
                "before the first FROM, where only ARG may come", .{
                instruction.line, instruction.keyword.upper(),
            }, "move it after a FROM", .{});
        }
        try config.arg(t, instruction, .global);
    }
    if (index == instructions.len) {
        return refuse(t.refusal(), .E0810, 0, "the Dockerfile has no FROM", .{}, "start the " ++
            "Dockerfile with `FROM <image>`", .{});
    }
    while (index < instructions.len) {
        assert(instructions[index].keyword == .from);
        try from(t, &instructions[index]);
        index += 1;
        const stage = &ws.stages[ws.stages_count - 1];
        stage.begin = index;
        while (index < instructions.len and instructions[index].keyword != .from) index += 1;
        stage.end = index;
    }
    for (0..ws.stages_count) |stage_index| try uses(t, @intCast(stage_index));
}

fn from(t: *Translator, instruction: *const lines.Instruction) Error!void {
    const ws = t.ws;
    const line = instruction.line;
    if (ws.stages_count == constants.import_stages_max) {
        return refuse(t.refusal(), .E0815, line, "the Dockerfile has more than {d} stages", .{
            constants.import_stages_max,
        }, "split the Dockerfile", .{});
    }
    var flags: words.Flags = undefined;
    try words.flags_of(t.text(instruction.text), line, &flags, t.refusal());
    const context = t.global_context(line);
    for (flags.slice()) |flag| {
        if (!std.mem.eql(u8, flag.name, "platform")) {
            return refuse(t.refusal(), .E0811, line, "Dockerfile:{d} has FROM --{s}, which " ++
                "zbx import does not read", .{ line, flag.name }, "remove the flag", .{});
        }
        const value = try words.word_of(flag.value orelse "", &context, &t.out, t.refusal());
        const host = ws.platform_args[0].value.?;
        if (!std.mem.eql(u8, value, host)) {
            return refuse(t.refusal(), .E0811, line, "Dockerfile:{d} has FROM --platform={s}, " ++
                "but zbx builds only for the host, {s}", .{ line, value, host }, "write " ++
                "--platform=$BUILDPLATFORM, or remove the flag", .{});
        }
    }
    var list: words.WordList = undefined;
    try words.words_of(flags.rest, &context, &t.out, &list, t.refusal());
    const items = list.slice();
    const named = items.len == 3 and std.ascii.eqlIgnoreCase(items[1], "as");
    if (!(items.len == 1 or named) or items[0].len == 0) {
        return refuse(t.refusal(), .E0810, line, "Dockerfile:{d} is not `FROM <image> " ++
            "[AS <name>]`", .{line}, "write `FROM <image> AS <name>`", .{});
    }
    const name: ?[]const u8 = if (named) items[2] else null;
    if (name) |text| {
        if (stage_named(t, text, ws.stages_count) != null) {
            return refuse(t.refusal(), .E0813, line, "Dockerfile:{d} names a second stage " ++
                "`{s}`", .{ line, text }, "give each stage its own name", .{});
        }
    }
    const base: translate.Base = if (std.mem.eql(u8, items[0], "scratch"))
        .scratch
    else if (stage_named(t, items[0], ws.stages_count)) |parent|
        .{ .stage = @intCast(parent) }
    else
        .{ .image = items[0] };
    const stage = &ws.stages[ws.stages_count];
    stage.* = .{
        .line = line,
        .name = name,
        .base = base,
        .begin = 0,
        .end = 0,
        .uses = 0,
        .reached = false,
        .steps_count = 0,
        .state = undefined,
    };
    if (base == .stage) stage.uses |= @as(u64, 1) << @intCast(base.stage);
    ws.stages_count += 1;
}

/// The stage named `name` (as Docker names them: any case) or numbered `name`, among the first
/// `before` stages.
pub fn stage_named(t: *const Translator, name: []const u8, before: u32) ?u32 {
    const ws = t.ws;
    assert(before <= ws.stages_count);
    for (ws.stages[0..before], 0..) |*stage, index| {
        const own = stage.name orelse continue;
        if (std.ascii.eqlIgnoreCase(own, name)) return @intCast(index);
    }
    if (name.len == 0 or name.len > 2) return null;
    for (name) |byte| if (!std.ascii.isDigit(byte)) return null;
    // One or two digits, checked above, always parse.
    const number = std.fmt.parseInt(u32, name, 10) catch unreachable;
    return if (number < before) number else null;
}

/// The stage a `--from` (or a mount's `from`) names, or null for an image. A stage named later
/// in the file is refused, as Docker refuses it.
pub fn from_stage(t: *const Translator, line: u32, name: []const u8, stage: u32) Refused!?u32 {
    if (stage_named(t, name, stage)) |found| return found;
    if (stage_named(t, name, t.ws.stages_count)) |later| {
        assert(later >= stage);
        return refuse(&t.ws.refusal, .E0813, line, "Dockerfile:{d} uses stage `{s}`, which " ++
            "is not before it", .{ line, name }, "move stage `{s}` above line {d}", .{
            name, line,
        });
    }
    return null;
}

/// Sets the bits of the stages a stage's `COPY --from` and `RUN --mount from` name.
fn uses(t: *Translator, stage_index: u32) Error!void {
    const ws = t.ws;
    const stage = &ws.stages[stage_index];
    const instructions = ws.parsed.instructions_slice()[stage.begin..stage.end];
    for (instructions) |*instruction| {
        if (instruction.keyword != .copy and instruction.keyword != .add and
            instruction.keyword != .run) continue;
        var flags: words.Flags = undefined;
        try words.flags_of(t.text(instruction.text), instruction.line, &flags, t.refusal());
        for (flags.slice()) |flag| {
            const value = flag.value orelse continue;
            const named = if (std.mem.eql(u8, flag.name, "from"))
                value
            else if (std.mem.eql(u8, flag.name, "mount"))
                steps.mount_option(value, "from") orelse continue
            else
                continue;
            const context = t.global_context(instruction.line);
            const expanded = try words.word_of(named, &context, &t.out, t.refusal());
            if (try from_stage(t, instruction.line, expanded, stage_index)) |used| {
                stage.uses |= @as(u64, 1) << @intCast(used);
            }
        }
    }
}

/// Marks the stages the target reaches and returns the target's index.
pub fn reach(t: *Translator) Error!u32 {
    const ws = t.ws;
    assert(ws.stages_count > 0);
    const target: u32 = if (t.options.target) |name|
        stage_named(t, name, ws.stages_count) orelse return refuse(
            t.refusal(),
            .E0813,
            0,
            "--target {s} names no stage of the Dockerfile",
            .{name},
            "name a stage given with `FROM ... AS <name>`",
            .{},
        )
    else
        ws.stages_count - 1;
    ws.stages[target].reached = true;
    var index = target + 1;
    while (index > 0) {
        index -= 1;
        const stage = &ws.stages[index];
        if (!stage.reached) continue;
        for (0..index) |used| {
            if (stage.uses & (@as(u64, 1) << @intCast(used)) != 0) ws.stages[used].reached = true;
        }
    }
    var count: u32 = 0;
    for (ws.stages[0..ws.stages_count], 0..) |*stage, at| {
        if (!stage.reached) continue;
        count += 1;
        try collision(t, @intCast(at));
    }
    var buffer: [slug_bytes_max]u8 = undefined;
    const shown = ws.stages[target].name orelse slug(t, target, &buffer);
    ws.report.target = try t.keep(0, shown);
    ws.report.stages_count = count;
    return target;
}

/// Refuses a reached stage whose step names would be another reached stage's.
fn collision(t: *Translator, index: u32) Refused!void {
    const ws = t.ws;
    var mine: [slug_bytes_max]u8 = undefined;
    const own = slug(t, index, &mine);
    for (ws.stages[0..index], 0..) |*other, other_index| {
        if (!other.reached) continue;
        var theirs: [slug_bytes_max]u8 = undefined;
        if (!std.mem.eql(u8, own, slug(t, @intCast(other_index), &theirs))) continue;
        const line = ws.stages[index].line;
        const what = "Dockerfile:{d} starts a stage whose steps would be named `{s}-<n>`, " ++
            "as the stage at Dockerfile:{d} names its own";
        const fix = "rename one of the stages so their names differ in [a-z0-9-]";
        return refuse(t.refusal(), .E0813, line, what, .{ line, own, other.line }, fix, .{});
    }
}

/// A stage's part of its step names: its name lowered and cut to `[a-z0-9-]`, or `stage<i>`.
pub fn slug(t: *const Translator, index: u32, buffer: *[slug_bytes_max]u8) []const u8 {
    const stage = &t.ws.stages[index];
    var length: usize = 0;
    if (stage.name) |name| {
        for (name) |byte| {
            const lower = std.ascii.toLower(byte);
            const kept = std.ascii.isDigit(lower) or std.ascii.isLower(lower) or lower == '-';
            if (!kept or length == buffer.len) continue;
            buffer[length] = lower;
            length += 1;
        }
    }
    if (length > 0) return buffer[0..length];
    // `stage` and at most two digits fit: there are at most import_stages_max stages.
    return std.fmt.bufPrint(buffer, "stage{d}", .{index}) catch unreachable;
}

/// Translates the current stage: its start state, then each instruction in order.
pub fn translate_stage(t: *Translator) Error!void {
    const ws = t.ws;
    const stage = &ws.stages[t.stage];
    assert(stage.reached);
    ws.args_count = 0;
    try start(t, stage);
    const instructions = ws.parsed.instructions_slice()[stage.begin..stage.end];
    for (instructions) |*instruction| {
        t.line = instruction.line;
        switch (instruction.keyword) {
            .run => try steps.run(t, instruction),
            .copy, .add => try steps.copy(t, instruction),
            .from => unreachable,
            else => try config.apply(t, instruction),
        }
    }
}

fn start(t: *Translator, stage: *translate.Stage) Error!void {
    const state = &stage.state;
    switch (stage.base) {
        .stage => |parent| {
            assert(parent < t.stage);
            assert(t.ws.stages[parent].reached);
            state.* = t.ws.stages[parent].state;
            state.cmd_here = false;
            return;
        },
        .scratch, .image => {},
    }
    state.head = null;
    state.env_count = 0;
    state.image_workdir = "";
    state.workdir = null;
    state.user = null;
    state.shell = .{ .items = undefined, .count = 2, .given = true };
    state.shell.items[0] = "/bin/sh";
    state.shell.items[1] = "-c";
    state.entrypoint = .{ .items = undefined, .count = 0, .given = false };
    state.cmd = .{ .items = undefined, .count = 0, .given = false };
    state.cmd_here = false;
    state.labels_count = 0;
    const reference = switch (stage.base) {
        .image => |reference| reference,
        else => return,
    };
    const facts = try t.reach(stage.line, reference);
    state.head = reference;
    state.image_workdir = try t.keep(stage.line, facts.workdir);
    for (facts.env) |entry| {
        const equals = std.mem.indexOfScalar(u8, entry, '=') orelse continue;
        if (equals == 0) continue;
        if (state.env_count == constants.build_config_env_max) {
            return refuse(t.refusal(), .E0815, stage.line, "the image {s} has more than {d} " ++
                "env entries", .{ reference, constants.build_config_env_max }, "use a base " ++
                "image with fewer", .{});
        }
        const kept = try t.keep(stage.line, entry);
        state.env[state.env_count] = .{
            .key = kept[0..equals],
            .value = kept[equals + 1 ..],
            .ours = false,
        };
        state.env_count += 1;
    }
}

/// The `.image` section, from the target stage's state.
pub fn image(t: *Translator) Error!void {
    const state = t.state();
    try t.put("    .image = .{\n");
    if (state.head) |head| {
        try t.put("        .base = ");
        try t.put_string(head);
        try t.put(",\n");
    }
    var ours = false;
    for (state.env_slice()) |pair| ours = ours or pair.ours;
    const any = state.entrypoint.given or state.cmd.given or ours or state.workdir != null or
        state.user != null or state.labels_count > 0;
    if (any) {
        try t.put("        .config = .{\n");
        const indent = "            ";
        if (state.entrypoint.given) try t.put_list(indent, "entrypoint", state.entrypoint.slice());
        if (state.cmd.given) try t.put_list(indent, "cmd", state.cmd.slice());
        if (ours) {
            try t.put(indent ++ ".env = .{");
            for (state.env_slice(), 0..) |pair, index| {
                try t.put(if (index == 0) " " else ", ");
                try t.put_string(try t.join(pair.key, pair.value));
            }
            try t.put(" },\n");
        }
        if (state.workdir) |workdir| try t.put_field("workdir", workdir);
        if (state.user) |user| try t.put_field("user", user);
        if (state.labels_count > 0) {
            try t.put(indent ++ ".labels = .{\n");
            for (state.labels_slice()) |label| {
                try t.put(indent ++ "    .{ ");
                try t.put_string(label.key);
                try t.put(", ");
                try t.put_string(label.value);
                try t.put(" },\n");
            }
            try t.put(indent ++ "},\n");
        }
        try t.put("        },\n");
    }
    try t.put("    },\n");
}
