//! The instructions that change a stage's settings and make no step: `ENV`, `ARG`, `LABEL`,
//! `WORKDIR`, `USER`, `SHELL`, `CMD`, `ENTRYPOINT`, and the ones kept only as labels
//! (`EXPOSE`, `VOLUME`, `HEALTHCHECK`, `STOPSIGNAL`, `MAINTAINER`). See "The mapping" in
//! docs/briefs/M9-dockerfile-import.md.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const file_mod = @import("../build/file.zig");
const lines = @import("lines.zig");
const words = @import("words.zig");
const refusal_mod = @import("refusal.zig");
const translate = @import("translate.zig");

const Translator = translate.Translator;
const Error = translate.Error;
const Refused = refusal_mod.Refused;
const refuse = refusal_mod.refuse;
const Instruction = lines.Instruction;

pub fn apply(t: *Translator, instruction: *const Instruction) Error!void {
    switch (instruction.keyword) {
        .env => try env(t, instruction),
        .arg => try arg(t, instruction, .stage),
        .label => try label(t, instruction),
        .workdir => try workdir(t, instruction),
        .user => try user(t, instruction),
        .shell => try shell(t, instruction),
        .cmd, .entrypoint => try command(t, instruction),
        .expose, .volume, .stopsignal, .healthcheck, .maintainer => try kept(t, instruction),
        .onbuild => return refuse(t.refusal(), .E0811, instruction.line, "Dockerfile:{d} has " ++
            "ONBUILD, which zbx import does not translate", .{instruction.line}, "remove it, " ++
            "and run its instruction in the stage that builds on this image", .{}),
        .from, .run, .copy, .add => unreachable,
    }
}

fn expect_no_heredoc(t: *Translator, instruction: *const Instruction) Refused!void {
    if (instruction.heredocs_count == 0) return;
    return refuse(t.refusal(), .E0811, instruction.line, "Dockerfile:{d} has a heredoc in {s}, " ++
        "which zbx import reads only in RUN", .{ instruction.line, instruction.keyword.upper() },
        "write the value on the line", .{});
}

/// The instruction's text with no flags; a flag is refused.
fn plain(t: *Translator, instruction: *const Instruction) Refused![]const u8 {
    try expect_no_heredoc(t, instruction);
    const text = t.text(instruction.text);
    var flags: words.Flags = undefined;
    try words.flags_of(text, instruction.line, &flags, t.refusal());
    if (flags.count > 0 and instruction.keyword != .healthcheck) {
        return refuse(t.refusal(), .E0811, instruction.line, "Dockerfile:{d} has {s} --{s}, " ++
            "which zbx import does not read", .{
            instruction.line, instruction.keyword.upper(), flags.items[0].name,
        }, "remove the flag", .{});
    }
    if (text.len == 0) {
        return refuse(t.refusal(), .E0810, instruction.line, "Dockerfile:{d} has {s} with " ++
            "nothing after it", .{ instruction.line, instruction.keyword.upper() }, "give it " ++
            "a value, or remove the line", .{});
    }
    return text;
}

/// `KEY=VALUE` words (or the legacy `KEY VALUE` when `legacy` and the first word has no `=`).
fn pairs(
    t: *Translator,
    instruction: *const Instruction,
    legacy: bool,
    list: *words.WordList,
    values: *[constants.import_words_max][]const u8,
) Error!u32 {
    const text = try plain(t, instruction);
    const context = t.stage_context(instruction.line);
    const first_end = std.mem.indexOfAny(u8, text, " \t") orelse text.len;
    const first = text[0..first_end];
    if (legacy and std.mem.indexOfScalar(u8, first, '=') == null) {
        const value = std.mem.trim(u8, text[first_end..], " \t");
        list.items[0] = try t.keep(instruction.line, first);
        values[0] = try words.word_of(value, &context, &t.out, t.refusal());
        list.count = 1;
        return 1;
    }
    try words.words_of(text, &context, &t.out, list, t.refusal());
    for (list.slice(), 0..) |word, index| {
        const equals = std.mem.indexOfScalar(u8, word, '=') orelse
            return refuse(t.refusal(), .E0810, instruction.line, "Dockerfile:{d} has `{s}` " ++
                "in {s}, which is not KEY=VALUE", .{
                instruction.line, word, instruction.keyword.upper(),
            }, "write KEY=VALUE, quoting a value with spaces", .{});
        list.items[index] = word[0..equals];
        values[index] = word[equals + 1 ..];
    }
    return list.count;
}

fn env(t: *Translator, instruction: *const Instruction) Error!void {
    var list: words.WordList = undefined;
    var values: [constants.import_words_max][]const u8 = undefined;
    const count = try pairs(t, instruction, true, &list, &values);
    const state = t.state();
    for (list.items[0..count], values[0..count]) |key, value| {
        if (file_mod.is_fixed_env(key)) {
            t.drop(instruction.line, "ENV of a fixed variable", "image config only; " ++
                "steps keep zbx's fixed value");
        }
        const slot = for (state.env[0..state.env_count], 0..) |pair, index| {
            if (std.mem.eql(u8, pair.key, key)) break index;
        } else slot: {
            if (state.env_count == constants.build_config_env_max) {
                return refuse(t.refusal(), .E0815, instruction.line, "Dockerfile:{d} sets more " ++
                    "than {d} env variables", .{ instruction.line, constants.build_config_env_max },
                    "set fewer variables with ENV", .{});
            }
            state.env_count += 1;
            break :slot state.env_count - 1;
        };
        state.env[slot] = .{ .key = key, .value = value, .ours = true };
    }
}

pub const Scope = enum { global, stage };

/// `ARG NAME[=default] ...`: the value is the `--build-arg`, else the default, else a global
/// `ARG`'s or the platform's of that name; none of them leaves it declared with no value.
pub fn arg(t: *Translator, instruction: *const Instruction, scope: Scope) Error!void {
    const ws = t.ws;
    const text = try plain(t, instruction);
    const context = switch (scope) {
        .global => t.global_context(instruction.line),
        .stage => t.stage_context(instruction.line),
    };
    var list: words.WordList = undefined;
    try words.words_of(text, &context, &t.out, &list, t.refusal());
    for (list.slice()) |word| {
        const equals = std.mem.indexOfScalar(u8, word, '=');
        const name = word[0 .. equals orelse word.len];
        if (name.len == 0) {
            return refuse(t.refusal(), .E0810, instruction.line, "Dockerfile:{d} has an ARG " ++
                "with no name", .{instruction.line}, "write ARG NAME or ARG NAME=default", .{});
        }
        if (std.mem.startsWith(u8, name, "BUILDKIT_") or
            std.mem.eql(u8, name, "SOURCE_DATE_EPOCH"))
        {
            t.drop(instruction.line, "ARG for BuildKit", "ignored: zbx keeps its fixed " ++
                "environment");
            continue;
        }
        var value: ?[]const u8 = if (equals) |at| word[at + 1 ..] else null;
        if (translate.build_arg(t.options, name)) |given| value = try t.keep(instruction.line, given);
        if (value == null and scope == .stage) value = inherited(t, name);
        if (value == null) value = platform(t, name);
        const list_args = switch (scope) {
            .global => &ws.globals,
            .stage => &ws.args,
        };
        const count = switch (scope) {
            .global => &ws.globals_count,
            .stage => &ws.args_count,
        };
        if (count.* == constants.import_variables_max) {
            return refuse(t.refusal(), .E0815, instruction.line, "Dockerfile:{d} declares more " ++
                "than {d} ARGs", .{ instruction.line, constants.import_variables_max }, "declare " ++
                "fewer ARGs", .{});
        }
        list_args[count.*] = .{ .name = name, .value = value };
        count.* += 1;
    }
}

fn inherited(t: *const Translator, name: []const u8) ?[]const u8 {
    const ws = t.ws;
    var index = ws.globals_count;
    while (index > 0) {
        index -= 1;
        if (std.mem.eql(u8, ws.globals[index].name, name)) return ws.globals[index].value;
    }
    return null;
}

fn platform(t: *const Translator, name: []const u8) ?[]const u8 {
    for (t.ws.platform_args) |entry| {
        if (std.mem.eql(u8, entry.name, name)) return entry.value;
    }
    return null;
}

fn label(t: *Translator, instruction: *const Instruction) Error!void {
    var list: words.WordList = undefined;
    var values: [constants.import_words_max][]const u8 = undefined;
    const count = try pairs(t, instruction, false, &list, &values);
    for (list.items[0..count], values[0..count]) |key, value| {
        try set_label(t, instruction.line, key, value);
    }
}

fn label_key_valid(key: []const u8) bool {
    if (key.len == 0) return false;
    for (key) |byte| {
        const good = std.ascii.isDigit(byte) or (byte >= 'a' and byte <= 'z') or
            std.mem.indexOfScalar(u8, "._/-", byte) != null;
        if (!good) return false;
    }
    return true;
}

fn set_label(t: *Translator, line: u32, key: []const u8, value: []const u8) Refused!void {
    if (!label_key_valid(key)) {
        return refuse(t.refusal(), .E0811, line, "Dockerfile:{d} has the label key `{s}`, " ++
            "and a label key is only [a-z0-9._/-]", .{ line, key }, "rename the label, or " ++
            "remove it", .{});
    }
    const state = t.state();
    for (state.labels[0..state.labels_count]) |*pair| {
        if (std.mem.eql(u8, pair.key, key)) {
            pair.value = value;
            return;
        }
    }
    if (state.labels_count == constants.build_config_labels_max) {
        return refuse(t.refusal(), .E0815, line, "Dockerfile:{d} makes more than {d} labels", .{
            line, constants.build_config_labels_max,
        }, "remove labels, or merge EXPOSE and VOLUME lines", .{});
    }
    state.labels[state.labels_count] = .{ .key = key, .value = value, .ours = true };
    state.labels_count += 1;
}

fn workdir(t: *Translator, instruction: *const Instruction) Error!void {
    const text = try plain(t, instruction);
    const context = t.stage_context(instruction.line);
    const path = try words.word_of(text, &context, &t.out, t.refusal());
    const state = t.state();
    state.workdir = try translate.absolute(t, instruction.line, state.directory(), path, false);
}

fn user(t: *Translator, instruction: *const Instruction) Error!void {
    const text = try plain(t, instruction);
    const context = t.stage_context(instruction.line);
    const name = try words.word_of(text, &context, &t.out, t.refusal());
    if (name.len == 0) {
        return refuse(t.refusal(), .E0810, instruction.line, "Dockerfile:{d} has USER with " ++
            "an empty value", .{instruction.line}, "name a user, or give the ARG a value", .{});
    }
    t.state().user = name;
}

/// Reads an exec form into `argv`; false when the text is not one.
fn exec_into(
    t: *Translator,
    line: u32,
    text: []const u8,
    argv: *translate.Argv,
) Refused!bool {
    var list: words.WordList = undefined;
    if (!try words.exec_form(text, line, &t.out, &list, t.refusal())) return false;
    try fill(t, line, argv, list.slice());
    return true;
}

fn fill(t: *Translator, line: u32, argv: *translate.Argv, items: []const []const u8) Refused!void {
    if (items.len > constants.build_config_argv_max) {
        return refuse(t.refusal(), .E0815, line, "Dockerfile:{d} has more than {d} words in " ++
            "its command", .{ line, constants.build_config_argv_max }, "move the command into " ++
            "a script", .{});
    }
    for (items, 0..) |item, index| argv.items[index] = item;
    argv.count = @intCast(items.len);
    argv.given = true;
}

fn shell(t: *Translator, instruction: *const Instruction) Error!void {
    const text = try plain(t, instruction);
    var argv: translate.Argv = undefined;
    if (!try exec_into(t, instruction.line, text, &argv) or argv.count == 0) {
        return refuse(t.refusal(), .E0810, instruction.line, "Dockerfile:{d} has SHELL not " ++
            "as a JSON array of strings", .{instruction.line}, "write SHELL [\"/bin/sh\", " ++
            "\"-c\"]", .{});
    }
    t.state().shell = argv;
}

/// `CMD` and `ENTRYPOINT`: the exec form as it is, the shell form after the stage's `SHELL`.
fn command(t: *Translator, instruction: *const Instruction) Error!void {
    const text = try plain(t, instruction);
    const state = t.state();
    var argv: translate.Argv = undefined;
    if (!try exec_into(t, instruction.line, text, &argv)) {
        const shell_argv = state.shell.slice();
        var items: [constants.build_config_argv_max + 1][]const u8 = undefined;
        const count = @min(shell_argv.len, constants.build_config_argv_max);
        @memcpy(items[0..count], shell_argv[0..count]);
        items[count] = text;
        try fill(t, instruction.line, &argv, items[0 .. count + 1]);
    }
    if (instruction.keyword == .cmd) {
        state.cmd = argv;
        state.cmd_here = true;
        return;
    }
    assert(instruction.keyword == .entrypoint);
    state.entrypoint = argv;
    if (!state.cmd_here) state.cmd = .{ .items = undefined, .count = 0, .given = true };
}

/// `EXPOSE`, `VOLUME`, `HEALTHCHECK`, `STOPSIGNAL` and `MAINTAINER` become labels, the value as
/// written (substituted where Docker substitutes), and are listed under W0811.
fn kept(t: *Translator, instruction: *const Instruction) Error!void {
    const text = try plain(t, instruction);
    const line = instruction.line;
    const key = switch (instruction.keyword) {
        .expose => "org.zigbox.import.expose",
        .volume => "org.zigbox.import.volume",
        .healthcheck => "org.zigbox.import.healthcheck",
        .stopsignal => "org.zigbox.import.stopsignal",
        .maintainer => "maintainer",
        else => unreachable,
    };
    const substitute = instruction.keyword != .healthcheck and instruction.keyword != .maintainer;
    var value = text;
    if (substitute) {
        // `VOLUME ["/a", "/b"]` and `VOLUME /a /b` are the same list: kept space-separated.
        var list: words.WordList = undefined;
        if (!try words.exec_form(text, line, &t.out, &list, t.refusal())) {
            const context = t.stage_context(line);
            try words.words_of(text, &context, &t.out, &list, t.refusal());
        }
        const start = t.out.mark();
        for (list.slice(), 0..) |word, index| {
            if (index > 0) try t.out.push(t.refusal(), line, " ");
            try t.out.push(t.refusal(), line, word);
        }
        value = t.out.since(start);
    }
    const state = t.state();
    // A second EXPOSE or VOLUME adds to the first, as Docker's lists do.
    const adds = instruction.keyword == .expose or instruction.keyword == .volume;
    if (adds) {
        for (state.labels_slice()) |pair| {
            if (!std.mem.eql(u8, pair.key, key)) continue;
            const start = t.out.mark();
            try t.out.push(t.refusal(), line, pair.value);
            try t.out.push(t.refusal(), line, " ");
            try t.out.push(t.refusal(), line, value);
            value = t.out.since(start);
        }
    }
    try set_label(t, line, key, value);
    var became: [64]u8 = undefined;
    const shown = std.fmt.bufPrint(&became, "label {s}", .{key}) catch unreachable;
    t.drop(line, instruction.keyword.upper(), shown);
}
