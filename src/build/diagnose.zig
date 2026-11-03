//! The diagnostics of a build file that cannot be used: `E0801` (it cannot be read or parsed),
//! `E0802` (its graph is invalid), `E0803` (an input is refused) and `E0807` (its
//! `image.config` is invalid). Each names the file as the project sees it, the place in it
//! (line and column, counting from 1), what is wrong in a sentence, and what to change. Values
//! from the file are echoed cut and with unprintable bytes as `?`.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const codes = @import("../diag/codes.zig");
const text_util = @import("../text.zig");
const file_mod = @import("file.zig");
const graph_mod = @import("graph.zig");
const inputs_mod = @import("inputs.zig");
const lexer_mod = @import("lexer.zig");
const fs_mod = @import("../store/fs.zig");
const Diag = @import("../diag/diag.zig").Diag;

const BuildFile = file_mod.BuildFile;
const Field = file_mod.Field;
const Level = file_mod.Level;
const ProblemKind = file_mod.ProblemKind;

/// The room a sentence is put together in before the diagnostic cuts it to its field.
const sentence_bytes_max = 512;
const Echo = [constants.arg_echo_bytes_max]u8;

comptime {
    assert(sentence_bytes_max > constants.diag_field_bytes_max);
    assert(constants.build_problem_word_bytes_max <= constants.arg_echo_bytes_max);
}

/// The code of a parse problem: the graph's and `image.config`'s are their own.
pub fn parse_code(kind: ProblemKind) codes.Code {
    assert(@tagName(kind).len > 0);
    const code: codes.Code = switch (kind) {
        .too_many_needs => .E0802,
        .config_workdir, .config_user, .config_env, .config_label_key => .E0807,
        .config_label_twice => .E0807,
        else => .E0801,
    };
    assert(switch (code) {
        .E0801, .E0802, .E0807 => true,
        else => false,
    });
    return code;
}

/// Why the build file itself could not be had.
pub const ReadFailure = enum {
    /// The project directory cannot be worked out (the working directory cannot be read).
    no_project,
    /// `-f` names a file outside the project directory (`resolved` is where it led).
    outside,
    /// The project directory is `/`, inside which every path is.
    root_project,
    missing,
    unreadable,
    /// Its links lead round, or its path is too long.
    bad_path,
    /// A directory, a FIFO or another thing that is not a file.
    not_file,
    /// Longer than `build_file_bytes_max`.
    too_large,
};

/// `E0801` for a file that could not be read. `shown` is its path as the user knows it;
/// `resolved` is where it led, for `outside`, and empty otherwise.
pub fn read_failure(
    diag: *Diag,
    shown: []const u8,
    project: []const u8,
    resolved: []const u8,
    failure: ReadFailure,
) void {
    assert(diag.code == null);
    assert(shown.len > 0);
    if (failure == .outside) assert(resolved.len > 0);
    var shown_echo: Echo = undefined;
    var project_echo: Echo = undefined;
    var resolved_echo: Echo = undefined;
    const path = text_util.sanitise(&shown_echo, shown);
    const directory = if (project.len > 0) text_util.sanitise(&project_echo, project) else "?";
    diag.raise(.E0801);
    diag.while_("reading the build file '{s}'", .{path});
    switch (failure) {
        .no_project => diag.cause("the working directory cannot be read", .{}),
        .outside => diag.cause("'{s}' leads to '{s}', outside the project directory '{s}'", .{
            path, text_util.sanitise(&resolved_echo, resolved), directory,
        }),
        .root_project => diag.cause("the project directory is /, and a build reads only " ++
            "inside its project", .{}),
        .missing => diag.cause("'{s}' is not there", .{path}),
        .unreadable => diag.cause("'{s}' cannot be read", .{path}),
        .not_file => diag.cause("'{s}' is not a file", .{path}),
        .bad_path => diag.cause("the path '{s}' leads round its links, or is too long", .{path}),
        .too_large => diag.cause("'{s}' is longer than {d} bytes", .{
            path, constants.build_file_bytes_max,
        }),
    }
    diag.context("path", "{s}", .{path});
    // The context keeps the whole path, up to the diagnostic's field; only prose is cut short.
    if (project.len > 0) diag.context("dir", "{s}", .{project});
    if (resolved.len > 0) diag.context("target", "{s}", .{resolved});
    switch (failure) {
        .no_project => diag.fix(.{ .sentence = "run zbx build from the project's directory" }),
        .outside => diag.fix(.{ .sentence = "name a build file inside the project with -f" }),
        .root_project => diag.fix(.{ .sentence = "run zbx build from the project, or create " ++
            "zbx.lock there" }),
        .missing => diag.fix(.{
            .sentence = "write zbx.build.zon in the project directory; its format is in:",
            .command = "zbx explain E0801",
        }),
        .unreadable => diag.fix(.{ .sentence = "make the file readable by you" }),
        .not_file => diag.fix(.{ .sentence = "name the build file itself with -f" }),
        .bad_path => diag.fix(.{ .sentence = "name the file by a path without a link loop" }),
        .too_large => fix_sentence(diag, "shorten the file; it may be at most {d} bytes", .{
            constants.build_file_bytes_max,
        }),
    }
    assert(diag.code.? == .E0801);
}

/// `E0801`, `E0802` or `E0807` for a file that the parser refused.
pub fn parse_problem(diag: *Diag, shown: []const u8, problem: *const file_mod.Problem) void {
    assert(diag.code == null);
    assert(problem.line > 0);
    var shown_echo: Echo = undefined;
    const path = text_util.sanitise(&shown_echo, shown);
    var sentence: [sentence_bytes_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&sentence);
    // A sentence longer than the room is cut, as the diagnostic would cut it anyway.
    describe(&writer, problem) catch {};
    const code = parse_code(problem.kind);
    diag.raise(code);
    diag.while_("reading the build file '{s}'", .{path});
    diag.cause("'{s}' line {d}, column {d}: {s}", .{
        path, problem.line, problem.column, writer.buffered(),
    });
    diag.context("path", "{s}", .{path});
    diag.context("at", "line {d}, column {d}", .{ problem.line, problem.column });
    parse_fix(diag, problem);
    assert(diag.code.? == code);
}

fn parse_fix(diag: *Diag, problem: *const file_mod.Problem) void {
    assert(diag.code != null);
    assert(problem.line > 0);
    const field = if (problem.field) |known| @tagName(known) else "?";
    const level = level_name(problem.level);
    switch (problem.kind) {
        .syntax => {
            fix_sentence(diag, "write {s} at line {d}, column {d}", .{
                expected_name(problem.expected), problem.line, problem.column,
            });
            diag.fix_with("see the format:", "zbx explain {t}", .{parse_code(problem.kind)});
        },
        .unknown_field => {
            var fields: [sentence_bytes_max]u8 = undefined;
            var writer = std.Io.Writer.fixed(&fields);
            // The longest list, a step's, is seven short names: it fits.
            write_fields(&writer, problem.level.allowed()) catch unreachable;
            fix_sentence(diag, "use a field that {s} takes: {s}", .{ level, writer.buffered() });
        },
        .duplicate_field => fix_sentence(diag, "keep one .{s} in {s} and remove the other", .{
            field, level,
        }),
        .missing_field => fix_sentence(diag, "add .{s} = ... to {s}", .{ field, level }),
        .bad_escape => diag.fix(.{ .sentence = "write the escape as one of \\n \\r \\t " ++
            "\\\\ \\' \\\" or \\x and two hex digits" }),
        .bad_string => if (file_mod.takes_control_bytes(problem.level, problem.field.?))
            diag.fix(.{ .sentence = "save the file as UTF-8, and write a control byte " ++
                "as \\n, \\t or \\xNN" })
        else
            fix_sentence(diag, "write .{s} as UTF-8 text without control bytes", .{field}),
        .nul_byte => diag.fix(.{ .sentence = "take the \\x00 out of the string" }),
        .string_too_long => fix_sentence(diag, "shorten the string to at most {d} bytes", .{
            constants.build_string_bytes_max,
        }),
        .list_too_long => fix_sentence(diag, "list at most {d} entries in .{s}", .{
            list_max(problem.level, problem.field), field,
        }),
        .text_too_long => fix_sentence(diag, "shorten the strings of the file to at most {d} " ++
            "bytes in all", .{constants.build_pool_bytes}),
        .bad_version => fix_sentence(diag, "write .version = {d}", .{file_mod.version}),
        .newer_version => diag.fix(.{
            .sentence = "use a newer zbx, or write the file for version 1",
        }),
        else => value_fix(diag, problem),
    }
}

/// The fixes of the problems of one value (`describe_value`'s).
fn value_fix(diag: *Diag, problem: *const file_mod.Problem) void {
    assert(diag.code != null);
    assert(problem.word_len <= problem.word.len);
    var word_echo: Echo = undefined;
    const word = text_util.sanitise(&word_echo, problem.word_text());
    switch (problem.kind) {
        .bad_step_name => fix_sentence(diag, "name the step with 1 to {d} of a-z, 0-9 and -, " ++
            "for example \"compile\"", .{constants.build_step_name_bytes_max}),
        .reserved_step_name => diag.fix(.{ .sentence = "give the step another name, such as " ++
            "\"assemble\"" }),
        .bad_reference => diag.fix(.{
            .sentence = "name an image as zbx pull takes it, for example alpine:3.20",
        }),
        .empty_run => diag.fix(.{ .sentence = "give .run the command and its arguments, " ++
            "for example .{ \"go\", \"build\" }" }),
        .bad_env, .config_env => diag.fix(.{ .sentence = "write the entry as KEY=VALUE, the key " ++
            "of A-Z, a-z, 0-9 and _ and not starting with a digit" }),
        .env_twice => fix_sentence(diag, "set \"{s}\" once in this .env", .{word}),
        .env_fixed => fix_sentence(diag, "take \"{s}\" out of the step's .env; every step " ++
            "is given its fixed value", .{word}),
        .bad_target => diag.fix(.{ .sentence = "write .to as an absolute path, for example " ++
            "\"/usr/local/bin\"" }),
        .too_many_needs => diag.fix(.{
            .sentence = "need fewer steps, and have one of them gather what the others make",
        }),
        .config_workdir => diag.fix(.{ .sentence = "write .workdir as an absolute path, for " ++
            "example \"/app\"" }),
        .config_user => diag.fix(.{ .sentence = "write .user as \"UID:GID\" in numbers, " ++
            "for example \"0:0\"" }),
        .config_label_key => diag.fix(.{ .sentence = "write the key with a-z, 0-9 and . _ / -, " ++
            "for example \"org.opencontainers.image.source\"" }),
        .config_label_twice => fix_sentence(diag, "give the label \"{s}\" once", .{word}),
        // `parse_fix` writes the others.
        else => unreachable,
    }
}

/// A fix in prose, put together from values; cut to the diagnostic's field.
fn fix_sentence(diag: *Diag, comptime format: []const u8, args: anytype) void {
    assert(diag.code != null);
    var sentence: [constants.diag_field_bytes_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&sentence);
    // A sentence longer than the field is cut, as the diagnostic would cut it anyway.
    writer.print(format, args) catch {};
    assert(writer.buffered().len > 0);
    diag.fix(.{ .sentence = writer.buffered() });
}

fn describe(writer: *std.Io.Writer, problem: *const file_mod.Problem) std.Io.Writer.Error!void {
    assert(problem.line > 0);
    assert(problem.word_len <= problem.word.len);
    var word_echo: Echo = undefined;
    const word = text_util.sanitise(&word_echo, problem.word_text());
    const field = if (problem.field) |known| @tagName(known) else "?";
    const level = level_name(problem.level);
    switch (problem.kind) {
        .syntax => try writer.print("expected {s}, found {s}", .{
            expected_name(problem.expected), found_name(problem.found),
        }),
        .unknown_field => try writer.print("{s} has no field .{s}", .{ level, word }),
        .duplicate_field => try writer.print(".{s} is given twice in {s}", .{ field, level }),
        .missing_field => try writer.print("{s} has no .{s}, which it needs", .{ level, field }),
        .bad_escape => try writer.writeAll("a string has an escape zbx does not read; " ++
            "the escapes are \\n \\r \\t \\\\ \\' \\\" and \\xNN"),
        .bad_string => try writer.print("a string in .{s} holds bytes that are not UTF-8, or " ++
            "a control byte, which only .run, .entrypoint, .cmd and .env values may hold", .{
            field,
        }),
        .nul_byte => try writer.writeAll("a string holds a NUL byte (\\x00), which no " ++
            "argument, path or variable can hold"),
        .string_too_long => try writer.print("a string is longer than {d} bytes", .{
            constants.build_string_bytes_max,
        }),
        .list_too_long => try writer.print(".{s} has more than {d} entries", .{
            field, list_max(problem.level, problem.field),
        }),
        .text_too_long => try writer.print("the strings of the file come to more than {d} bytes", .{
            constants.build_pool_bytes,
        }),
        else => try describe_value(writer, problem.kind, word),
    }
}

/// The problems of a value the parser read whole: `word` is the value, echoed.
fn describe_value(writer: *std.Io.Writer, kind: ProblemKind, word: []const u8) !void {
    assert(@tagName(kind).len > 0);
    assert(word.len <= constants.arg_echo_bytes_max);
    switch (kind) {
        .bad_version => try writer.writeAll(".version is not a whole number from 1"),
        .newer_version => try writer.print(".version is {s}, and this zbx reads version {d}", .{
            word, file_mod.version,
        }),
        .bad_step_name => try writer.print("the step name \"{s}\" is not 1 to {d} of a-z, 0-9 " ++
            "and -", .{ word, constants.build_step_name_bytes_max }),
        .reserved_step_name => try writer.writeAll("no step can be named \"image\": " ++
            "that name is the result's"),
        .bad_reference => try writer.print(".base \"{s}\" is not an image reference", .{word}),
        .empty_run => try writer.writeAll(".run needs a command, and its first word " ++
            "cannot be empty"),
        .bad_env => try writer.print("the env entry \"{s}\" is not NAME=VALUE with a plain " ++
            "NAME", .{word}),
        .env_twice => try writer.print("the env key \"{s}\" is set twice", .{word}),
        .env_fixed => try writer.print("the step's env sets \"{s}\", which is fixed for " ++
            "every step", .{word}),
        .bad_target => try writer.print(".to \"{s}\" is not an absolute path written plainly " ++
            "(no empty, . or .. part)", .{word}),
        .too_many_needs => try writer.print("a step needs more than {d} steps, the most " ++
            "that can be mounted at /in", .{constants.build_step_needs_max}),
        .config_workdir => try writer.print("image.config .workdir \"{s}\" is not an " ++
            "absolute path written plainly", .{word}),
        .config_user => try writer.print("image.config .user \"{s}\" is not UID:GID in " ++
            "numbers; names are not looked up in a build", .{word}),
        .config_env => try writer.print("image.config .env entry \"{s}\" is not NAME=VALUE " ++
            "with a plain NAME", .{word}),
        .config_label_key => try writer.print("the label key \"{s}\" is not 1 to {d} of " ++
            "a-z, 0-9 and . _ / -", .{ word, constants.build_label_key_bytes_max }),
        .config_label_twice => try writer.print("the label \"{s}\" is given twice", .{word}),
        // `describe` writes the others.
        else => unreachable,
    }
}

/// `E0802` for a file whose steps do not make a graph.
pub fn graph_problem(
    diag: *Diag,
    shown: []const u8,
    file: *const BuildFile,
    problem: *const graph_mod.Problem,
) void {
    assert(diag.code == null);
    assert(problem.at.line > 0);
    var shown_echo: Echo = undefined;
    const path = text_util.sanitise(&shown_echo, shown);
    var sentence: [sentence_bytes_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&sentence);
    // A cycle of 64 long names is cut, as the diagnostic would cut it anyway.
    describe_graph(&writer, file, problem) catch {};
    diag.raise(.E0802);
    diag.while_("ordering the steps of '{s}'", .{path});
    diag.cause("'{s}' line {d}, column {d}: {s}", .{
        path, problem.at.line, problem.at.column, writer.buffered(),
    });
    diag.context("path", "{s}", .{path});
    diag.context("at", "line {d}, column {d}", .{ problem.at.line, problem.at.column });
    graph_fix(diag, file, problem);
    assert(diag.code.? == .E0802);
}

fn describe_graph(
    writer: *std.Io.Writer,
    file: *const BuildFile,
    problem: *const graph_mod.Problem,
) std.Io.Writer.Error!void {
    assert(problem.at.len <= constants.build_string_bytes_max);
    var at_echo: Echo = undefined;
    var step_echo: Echo = undefined;
    const at = text_util.sanitise(&at_echo, file.text(problem.at));
    const step = if (problem.kind == .unknown_add)
        ""
    else
        step_text(&step_echo, file, problem.step);
    switch (problem.kind) {
        .duplicate_step => try writer.print(
            "two steps are named \"{s}\" (the first at line {d})",
            .{ at, file.steps[problem.other].name.line },
        ),
        .unknown_need => try writer.print("step \"{s}\" needs \"{s}\", and no step is named " ++
            "that", .{ step, at }),
        .need_twice => try writer.print(
            "step \"{s}\" lists \"{s}\" in .needs twice",
            .{ step, at },
        ),
        .unknown_add => try writer.print("image.add takes from \"{s}\", and no step is named " ++
            "that", .{at}),
        .cycle => {
            try writer.writeAll("the steps need each other round: ");
            for (problem.cycle_slice()) |index| {
                try writer.print("{s} -> ", .{step_text(&step_echo, file, index)});
            }
            try writer.writeAll(step_text(&step_echo, file, problem.cycle_slice()[0]));
        },
    }
}

fn graph_fix(diag: *Diag, file: *const BuildFile, problem: *const graph_mod.Problem) void {
    assert(diag.code != null);
    var at_echo: Echo = undefined;
    var step_echo: Echo = undefined;
    const at = text_util.sanitise(&at_echo, file.text(problem.at));
    switch (problem.kind) {
        .duplicate_step => diag.fix(.{ .sentence = "give each step a name of its own" }),
        .unknown_need, .unknown_add => diag.fix(.{
            .sentence = "name a step of the file, or add a step by that name",
        }),
        .need_twice => fix_sentence(diag, "list \"{s}\" once in step \"{s}\"'s .needs", .{
            at, step_text(&step_echo, file, problem.step),
        }),
        .cycle => fix_sentence(diag, "remove a need that closes the round, such as \"{s}\" " ++
            "from step \"{s}\"'s .needs", .{ at, step_text(&step_echo, file, problem.step) }),
    }
}

/// `E0803` for an input that the disk refused. `project` is the resolved project directory.
pub fn input_problem(
    diag: *Diag,
    project: []const u8,
    file: *const BuildFile,
    problem: *const inputs_mod.Problem,
) void {
    assert(diag.code == null);
    assert(project.len > 0);
    var input_echo: Echo = undefined;
    var step_echo: Echo = undefined;
    var project_echo: Echo = undefined;
    const input = text_util.sanitise(&input_echo, file.text(problem.input));
    const step = step_text(&step_echo, file, problem.step);
    const directory = text_util.sanitise(&project_echo, project);
    var sentence: [sentence_bytes_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&sentence);
    // A sentence longer than the room is cut, as the diagnostic would cut it anyway.
    describe_input(&writer, file, problem, directory) catch {};
    diag.raise(.E0803);
    diag.while_("checking the inputs of step \"{s}\"", .{step});
    diag.cause("input \"{s}\" of step \"{s}\" {s}", .{ input, step, writer.buffered() });
    diag.context("input", "{s}", .{input});
    diag.context("step", "{s}", .{step});
    // The context keeps the whole path, up to the diagnostic's field; only prose is cut short.
    diag.context("dir", "{s}", .{project});
    diag.context("at", "line {d}, column {d}", .{ problem.input.line, problem.input.column });
    input_fix(diag, problem.kind, step);
    assert(diag.code.? == .E0803);
}

fn describe_input(
    writer: *std.Io.Writer,
    file: *const BuildFile,
    problem: *const inputs_mod.Problem,
    directory: []const u8,
) std.Io.Writer.Error!void {
    assert(directory.len > 0);
    var resolved_echo: Echo = undefined;
    var other_echo: Echo = undefined;
    switch (problem.kind) {
        .not_plain => try writer.writeAll("is not a plain relative path: no leading /, no " ++
            "empty, . or .. part, no trailing /"),
        .outside => try writer.print("resolves to '{s}', outside the project directory '{s}'", .{
            text_util.sanitise(&resolved_echo, problem.resolved.text()), directory,
        }),
        .missing => try writer.print("is not there in the project directory '{s}'", .{directory}),
        .unreadable => try writer.writeAll("cannot be looked at"),
        .loop => try writer.writeAll("has links that lead round"),
        .too_long => try writer.print("resolves to a path longer than {d} bytes", .{
            constants.path_bytes_max,
        }),
        .bad_kind => try writer.print("is {s}; an input is a file or a directory", .{
            kind_name(problem.file_kind),
        }),
        .whole_project => try writer.writeAll("names the whole project directory"),
        .input_twice => try writer.print("overlaps input \"{s}\" of the same step: they " ++
            "name the same file, or one is inside the other", .{
            text_util.sanitise(&other_echo, file.text(problem.other)),
        }),
        .holds_bad_kind => try writer.print("holds '{s}', which is {s}; an input holds only " ++
            "files, directories and links", .{
            text_util.sanitise(&resolved_echo, problem.resolved.text()),
            kind_name(problem.file_kind),
        }),
        .changed => try writer.print("changed while the build read it, at '{s}'", .{
            text_util.sanitise(&resolved_echo, problem.resolved.text()),
        }),
    }
}

fn input_fix(diag: *Diag, kind: inputs_mod.ProblemKind, step: []const u8) void {
    assert(diag.code != null);
    assert(step.len > 0);
    switch (kind) {
        .not_plain => diag.fix(.{ .sentence = "write it from the project directory down, " ++
            "as src/main.go is written" }),
        .outside => diag.fix(.{ .sentence = "copy what it names into the project, and " ++
            "list the copy" }),
        .missing => fix_sentence(diag, "create it, or take it out of step \"{s}\"'s .inputs", .{
            step,
        }),
        .unreadable => diag.fix(.{ .sentence = "make it and the directories above it " ++
            "readable by you" }),
        .loop, .too_long => diag.fix(.{ .sentence = "list the file a link leads to, by " ++
            "its own path" }),
        .bad_kind => diag.fix(.{ .sentence = "list the files or directories the step " ++
            "reads instead" }),
        .whole_project => diag.fix(.{ .sentence = "list the files and directories the step " ++
            "reads, not the project itself" }),
        .input_twice => fix_sentence(diag, "list each file once in step \"{s}\"'s .inputs: " ++
            "a directory, or files inside it, not both", .{step}),
        .holds_bad_kind => diag.fix(.{ .sentence = "move it out of the input, or list the " ++
            "files beside it instead of the directory" }),
        .changed => diag.fix(.{ .sentence = "run the build again once nothing else is " ++
            "changing the project directory" }),
    }
}

fn step_text(storage: *Echo, file: *const BuildFile, step: u8) []const u8 {
    assert(step < file.steps_count);
    const name = file.text(file.steps[step].name);
    assert(name.len > 0);
    return text_util.sanitise(storage, name);
}

fn write_fields(writer: *std.Io.Writer, fields: []const Field) std.Io.Writer.Error!void {
    assert(fields.len > 0);
    assert(fields.len <= @typeInfo(Field).@"enum".field_names.len);
    for (fields, 0..) |field, index| {
        if (index > 0) try writer.writeByte(' ');
        try writer.print(".{t}", .{field});
    }
}

/// The most entries `field`'s list takes at `level`.
fn list_max(level: Level, field: ?Field) u32 {
    assert(@tagName(level).len > 0);
    const known = field orelse return 0;
    const result: u32 = switch (known) {
        .steps => constants.build_steps_max,
        .inputs => constants.build_step_inputs_max,
        .needs => constants.build_step_needs_max,
        .env => if (level == .config)
            constants.build_config_env_max
        else
            constants.build_step_env_max,
        .run => constants.build_step_argv_max,
        .add => constants.build_image_adds_max,
        .entrypoint, .cmd => constants.build_config_argv_max,
        .labels => constants.build_config_labels_max,
        else => 0,
    };
    assert(result <= constants.build_strings_max);
    return result;
}

fn level_name(level: Level) []const u8 {
    assert(@tagName(level).len > 0);
    const name = switch (level) {
        .file => "the file",
        .step => "a step",
        .image => "image",
        .add => "an image.add entry",
        .config => "image.config",
        .label => "a label",
    };
    assert(name.len > 0);
    return name;
}

fn expected_name(expected: file_mod.Expected) []const u8 {
    assert(@tagName(expected).len > 0);
    const name = switch (expected) {
        .open => ".{",
        .field_or_close => "a field (.name) or }",
        .equals => "=",
        .comma_or_close => ", or }",
        .string => "a string",
        .string_or_close => "a string or }",
        .string_list => ".{ for a list of strings",
        .step_list => ".{ for the list of steps",
        .add_list => ".{ for the list of adds",
        .label_list => ".{ for the list of labels",
        .step_or_close => ".{ for a step, or }",
        .add_or_close => ".{ for an add, or }",
        .label_or_close => ".{ for a label, or }",
        .integer => "a number",
        .boolean => "true or false",
        .end => "the end of the file",
        .comma => ",",
        .close => "}",
    };
    assert(name.len > 0);
    return name;
}

fn found_name(tag: lexer_mod.Tag) []const u8 {
    assert(@tagName(tag).len > 0);
    const name = switch (tag) {
        .open => ".{",
        .field => "a field name",
        .equals => "=",
        .comma => ",",
        .close => "}",
        .string => "a string",
        .integer => "a number",
        .true_word => "true",
        .false_word => "false",
        .end => "the end of the file",
        .invalid => "something that is not ZON",
    };
    assert(name.len > 0);
    return name;
}

fn kind_name(kind: fs_mod.FileKind) []const u8 {
    assert(@tagName(kind).len > 0);
    const name = switch (kind) {
        .file => "a file",
        .dir => "a directory",
        .symlink => "a link",
        .char_device => "a character device",
        .block_device => "a block device",
        .fifo => "a FIFO",
        .socket => "a socket",
    };
    assert(name.len > 0);
    return name;
}

// ---- A step (E0804 to E0806) ------------------------------------------------------------------

/// `E0804`: the base of a step is not in `zbx.lock` (`locked` false), or is there but its image
/// is not in the store (`locked` true). A build never resolves a tag itself.
pub fn base_not_locked(diag: *Diag, step: []const u8, reference: []const u8, locked: bool) void {
    assert(diag.code == null);
    assert(step.len > 0);
    assert(reference.len > 0);
    var reference_echo: Echo = undefined;
    const shown = text_util.sanitise(&reference_echo, reference);
    diag.raise(.E0804);
    diag.while_("resolving the base of build step \"{s}\"", .{step});
    if (locked) {
        diag.cause("base \"{s}\" of step \"{s}\" is in zbx.lock but its image is not in " ++
            "the store", .{ shown, step });
    } else {
        diag.cause("base \"{s}\" of step \"{s}\" is not in zbx.lock, and a build never " ++
            "resolves a tag itself", .{ shown, step });
    }
    diag.context("step", "{s}", .{step});
    diag.context("base", "{s}", .{shown});
    diag.fix_with("pull it, which pins it in zbx.lock", "zbx pull {s}", .{shown});
    assert(diag.code.? == .E0804);
}

/// How a step's container ended, when it did not exit 0.
pub const StepEnd = union(enum) {
    exited: u8,
    signaled: u8,
    /// The memory limit, if the step had one.
    oom: ?u64,
    pid_limit: ?u32,
    /// The step ran past its timeout, in milliseconds.
    timed_out: u32,
    /// zbx could not wait for it to the end.
    lost,
};

/// What `step_failed` says about the step besides how it ended.
pub const StepFailure = struct {
    step: []const u8,
    /// The build file as the project sees it (`zbx.build.zon`).
    file: []const u8,
    end: StepEnd,
    network: bool,
    /// The step's last line of output, empty for none.
    last_line: []const u8,
    /// The step's log, empty for none.
    log: []const u8,
};

/// `E0805`: a step's command failed. The first line says how, the causes in M2's words.
pub fn step_failed(diag: *Diag, failure: *const StepFailure) void {
    assert(diag.code == null);
    assert(failure.step.len > 0);
    assert(failure.file.len > 0);
    const step = failure.step;
    var short: [48]u8 = undefined;
    var long: [96]u8 = undefined;
    diag.raise(.E0805);
    diag.set_headline("build step \"{s}\" failed: {s}", .{ step, end_short(&short, failure.end) });
    diag.while_("running build step \"{s}\"", .{step});
    diag.cause("{s}", .{end_long(&long, failure.end)});
    // The newest cause is what the default view shows: the step's last line, as the brief's
    // example has it, and the missing network beside it.
    const no_network = "the step has no network: build steps run with network none unless they ask";
    if (failure.last_line.len > 0) {
        var line_echo: [constants.diag_field_bytes_max]u8 = undefined;
        const line = text_util.sanitise(&line_echo, failure.last_line);
        if (failure.network) {
            diag.cause("{s}", .{line});
        } else {
            diag.cause("{s}; " ++ no_network, .{line});
        }
    } else if (!failure.network) {
        diag.cause(no_network, .{});
    }
    diag.context("step", "{s}", .{step});
    diag.context("file", "{s}", .{failure.file});
    if (failure.log.len > 0) diag.context("log", "{s}", .{failure.log});
    if (!failure.network) {
        fix_sentence(diag, "if the step needs the network, add  .network = true  to step " ++
            "\"{s}\" in {s}", .{ step, failure.file });
    }
    if (failure.log.len > 0) {
        diag.fix_with("read the step's whole output in its log", "cat {s}", .{failure.log});
    } else {
        diag.fix(.{ .sentence = "run the step's command in its base with zbx run to see why" });
    }
    assert(diag.code.? == .E0805);
}

/// `E0805`: the step never started, because its environment (the base's, the file's and the
/// fixed one, merged) is more than a command can be given. `count` is the merged variables and
/// `key` the first one that does not fit (empty if the count itself is over the limit).
pub fn step_env_refused(
    diag: *Diag,
    step: []const u8,
    file: []const u8,
    count: u32,
    key: []const u8,
) void {
    assert(diag.code == null);
    assert(step.len > 0);
    assert(file.len > 0);
    diag.raise(.E0805);
    diag.set_headline("build step \"{s}\" failed: its environment is too large", .{step});
    diag.while_("starting build step \"{s}\"", .{step});
    if (count > constants.env_vars_count_max) {
        diag.cause("the base image's environment, the step's .env and the fixed variables make " ++
            "{d} variables; a container's command takes at most {d}", .{
            count, constants.env_vars_count_max,
        });
    } else {
        var key_echo: Echo = undefined;
        diag.cause("variable \"{s}\" of the step's environment, or the environment's total " ++
            "size, is more than a command can be given", .{text_util.sanitise(&key_echo, key)});
    }
    diag.context("step", "{s}", .{step});
    diag.context("file", "{s}", .{file});
    fix_sentence(diag, "remove variables from .env of step \"{s}\" in {s}, or use a base " ++
        "with a smaller environment", .{ step, file });
    assert(diag.code.? == .E0805);
}

fn end_short(buffer: *[48]u8, end: StepEnd) []const u8 {
    assert(buffer.len >= 48);
    // Cannot fail: a few words and two numbers fit 48 bytes.
    const text = switch (end) {
        .exited => |code| std.fmt.bufPrint(buffer, "exit {d}", .{code}),
        .signaled => |number| std.fmt.bufPrint(buffer, "signal {d} (SIG{s})", .{
            number, signal_name(number),
        }),
        .oom => std.fmt.bufPrint(buffer, "out of memory", .{}),
        .pid_limit => std.fmt.bufPrint(buffer, "process limit reached", .{}),
        .timed_out => std.fmt.bufPrint(buffer, "timed out", .{}),
        .lost => std.fmt.bufPrint(buffer, "lost", .{}),
    } catch unreachable; // Same bound as above.
    assert(text.len > 0);
    return text;
}

/// M2's words for how a container ended (`zbx run`'s note), without the `zbx:` prefix.
fn end_long(buffer: *[96]u8, end: StepEnd) []const u8 {
    assert(buffer.len >= 96);
    // Cannot fail: a sentence and two numbers fit 96 bytes.
    const text = switch (end) {
        .exited => |code| std.fmt.bufPrint(buffer, "the step's command exited with code {d}", .{
            code,
        }),
        .signaled => |number| std.fmt.bufPrint(buffer, "the container was killed by signal " ++
            "{d} (SIG{s})", .{ number, signal_name(number) }),
        .oom => |limit| if (limit) |bytes|
            std.fmt.bufPrint(buffer, "killed: out of memory (limit {d} MiB)", .{bytes >> 20})
        else
            std.fmt.bufPrint(buffer, "killed: out of memory", .{}),
        .pid_limit => |limit| if (limit) |count|
            std.fmt.bufPrint(buffer, "stopped: process limit reached (limit {d})", .{count})
        else
            std.fmt.bufPrint(buffer, "stopped: process limit reached", .{}),
        .timed_out => |ms| std.fmt.bufPrint(buffer, "stopped: timed out after {d} ms", .{ms}),
        .lost => std.fmt.bufPrint(buffer, "zbx lost the step's container before it ended", .{}),
    } catch unreachable; // Same bound as above.
    assert(text.len > 0);
    return text;
}

fn signal_name(number: u8) []const u8 {
    assert(number > 0);
    const code: std.os.linux.SIG = @fromBackingInt(number);
    const name = std.enums.tagName(std.os.linux.SIG, code) orelse "?";
    assert(name.len > 0);
    return name;
}

/// `E0806`: a step left in `/out` what an output cannot hold. `relative` is its path below
/// `/out`, starting with `/`; `kind` names it ("FIFO").
pub fn output_refused(diag: *Diag, step: []const u8, relative: []const u8, kind: []const u8) void {
    assert(diag.code == null);
    assert(step.len > 0);
    assert(relative.len > 0);
    var path_echo: Echo = undefined;
    const path = text_util.sanitise(&path_echo, relative);
    diag.raise(.E0806);
    diag.while_("importing the output of build step \"{s}\"", .{step});
    diag.cause("step \"{s}\" left a {s} at /out{s}; an output holds only files, directories " ++
        "and links", .{ step, kind, path });
    diag.context("step", "{s}", .{step});
    diag.context("path", "/out{s}", .{path});
    diag.fix(.{ .sentence = "have the step remove it, or make it somewhere other than /out" });
    assert(diag.code.? == .E0806);
}
