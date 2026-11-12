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
const assemble_mod = @import("assemble.zig");
const result_mod = @import("result.zig");
const tree_mod = @import("../store/tree.zig");
const Diag = @import("../diag/diag.zig").Diag;
const Digest = @import("../store/digest.zig").Digest;

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
        .too_many_needs, .too_many_mounts, .mount_twice => .E0802,
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
            // The longest list, a step's, is fourteen short names: it fits.
            write_fields(&writer, problem.level.allowed()) catch unreachable;
            fix_sentence(diag, "use a field that {s} takes: {s}", .{ level, writer.buffered() });
        },
        .duplicate_field => fix_sentence(diag, "keep one .{s} in {s} and remove the other", .{
            field, level,
        }),
        .missing_field => fix_sentence(diag, "add .{s} = ... to {s}", .{ field, level }),
        .empty_list => fix_sentence(diag, "list at least one entry in .{s}, or remove it", .{
            field,
        }),
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
        .config_user => diag.fix(.{ .sentence = "write .user as a name or a number, or " ++
            "as \"user:group\", for example \"app:app\" or \"0:0\"" }),
        .config_label_key => diag.fix(.{ .sentence = "write the key with a-z, 0-9 and . _ / -, " ++
            "for example \"org.opencontainers.image.source\"" }),
        .config_label_twice => fix_sentence(diag, "give the label \"{s}\" once", .{word}),
        .file_too_big => diag.fix(.{ .sentence = "list fewer copies, caches, binds and " ++
            "patterns in all: the file's lists have a shared limit" }),
        .bad_output => diag.fix(.{ .sentence = "write .output = .out, or .output = .root" }),
        .run_or_copy => diag.fix(.{ .sentence = "give the step .run or .copy, not both " ++
            "and not neither" }),
        .bad_user => diag.fix(.{ .sentence = "write the user as a name, \"UID\", \"UID:GID\" " ++
            "or \"name:group\", for example \"app:app\"" }),
        .bad_path => diag.fix(.{ .sentence = "write the path as an absolute path with no " ++
            "empty, . or .. part, for example \"/cache\"" }),
        .bad_copy_to => diag.fix(.{ .sentence = "write .to as an absolute path written " ++
            "plainly, ending in / for a directory, for example \"/app/\"" }),
        .bad_mode => diag.fix(.{ .sentence = "write the mode as 3 or 4 octal digits, for " ++
            "example \"0755\"" }),
        .bad_pattern => diag.fix(.{ .sentence = "write a glob: * ? [a-z] and ** work, a \\ " ++
            "quotes a byte, and no part is .." }),
        .bad_from => diag.fix(.{ .sentence = "write .from as step:<name> of a step, or as " ++
            "an image reference like alpine:3.20" }),
        .bad_source => diag.fix(.{ .sentence = "write .source as a path in the project, or " ++
            "an absolute path when .from names a step or an image" }),
        .bad_cache_id => diag.fix(.{ .sentence = "write the id with A-Z, a-z, 0-9 and . _ / -, " ++
            "for example \"go-build\"" }),
        .bad_number => diag.fix(.{ .sentence = "write a whole number from 0 to 4294967295, " ++
            "without leading zeros" }),
        .mount_twice => diag.fix(.{ .sentence = "mount each path once in a step: give the " ++
            "caches and binds different paths" }),
        .too_many_mounts => diag.fix(.{ .sentence = "need, bind and cache fewer things in " ++
            "the step, or gather them in one step first" }),
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
        .empty_list => try writer.print(".{s} in {s} has no entries, so it would copy nothing", .{
            field, level,
        }),
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
        .config_user => try writer.print("image.config .user \"{s}\" is not a name, a " ++
            "number, or user:group of those", .{word}),
        .file_too_big => try writer.writeAll("the file's copies, caches, binds and " ++
            "patterns come to more than the file's lists hold"),
        .bad_output => try writer.writeAll(".output is not .out or .root"),
        .run_or_copy => try writer.writeAll("a step has both .run and .copy, or neither"),
        .bad_user => try writer.print("the user \"{s}\" is not a name, a number, or " ++
            "user:group of those", .{word}),
        .bad_path => try writer.print("the path \"{s}\" is not an absolute path written " ++
            "plainly (no empty, . or .. part)", .{word}),
        .bad_copy_to => try writer.print(".to \"{s}\" is not an absolute path written " ++
            "plainly, which may end in /", .{word}),
        .bad_mode => try writer.print("the mode \"{s}\" is not 3 or 4 octal digits", .{word}),
        .bad_pattern => try writer.print("the pattern \"{s}\" is not a valid glob", .{word}),
        .bad_from => try writer.print(".from \"{s}\" is not step:<name> or an image " ++
            "reference", .{word}),
        .bad_source => try writer.print(".source \"{s}\" is not a path inside what it " ++
            "comes from", .{word}),
        .bad_cache_id => try writer.print("the cache id \"{s}\" is not 1 to {d} of A-Z, " ++
            "a-z, 0-9 and . _ / -", .{ word, constants.build_label_key_bytes_max }),
        .bad_number => try writer.print("\"{s}\" is not a whole number from 0 to " ++
            "4294967295 without leading zeros", .{word}),
        .mount_twice => try writer.print("the step mounts \"{s}\" twice", .{word}),
        .too_many_mounts => try writer.print("a step needs, binds and caches more than " ++
            "the {d} mounts a run holds", .{constants.mounts_max}),
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
    const step = if (problem.kind == .unknown_add or problem.kind == .unknown_image_base)
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
        .unknown_base => try writer.print("step \"{s}\" has base \"{s}\", and no step is " ++
            "named that", .{ step, at }),
        .unknown_from => try writer.print("step \"{s}\" takes from \"{s}\", and no step is " ++
            "named that", .{ step, at }),
        .unknown_image_base => try writer.print("image.base is \"{s}\", and no step is " ++
            "named that", .{at}),
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
        .unknown_need,
        .unknown_add,
        .unknown_base,
        .unknown_from,
        .unknown_image_base,
        => diag.fix(.{
            .sentence = "name a step of the file, or add a step by that name",
        }),
        .need_twice => fix_sentence(diag, "list \"{s}\" once in step \"{s}\"'s .needs", .{
            at, step_text(&step_echo, file, problem.step),
        }),
        .cycle => fix_sentence(diag, "remove a need that closes the round, such as \"{s}\" " ++
            "from step \"{s}\"'s .needs", .{ at, step_text(&step_echo, file, problem.step) }),
    }
}

/// `E0802` for a part of the file that parses but that `zbx build` cannot run yet.
pub fn unrunnable(
    diag: *Diag,
    shown: []const u8,
    file: *const BuildFile,
    found: graph_mod.Unrunnable,
) void {
    assert(diag.code == null);
    assert(found.field.len > 0);
    var shown_echo: Echo = undefined;
    var step_echo: Echo = undefined;
    const path = text_util.sanitise(&shown_echo, shown);
    diag.raise(.E0802);
    diag.while_("starting the build of '{s}'", .{path});
    if (found.step) |step| {
        diag.cause("'{s}': step \"{s}\" uses {s}, which this zbx reads but cannot build yet", .{
            path, step_text(&step_echo, file, step), found.field,
        });
    } else {
        diag.cause("'{s}': {s} is read but cannot be built yet", .{ path, found.field });
    }
    diag.context("path", "{s}", .{path});
    diag.fix(.{ .sentence = "remove it, or use a zbx that builds it; `zbx build --graph` " ++
        "still shows the file" });
    assert(diag.code.? == .E0802);
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
        .copy => constants.build_copy_entries_max,
        .caches => constants.build_step_caches_max,
        .binds => constants.build_step_binds_max,
        .exclude => constants.build_exclude_lines_max,
        .src => constants.build_copy_sources_max,
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
        .copy => "a copy entry",
        .cache => "a cache entry",
        .bind => "a bind entry",
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
        .copy_list => ".{ for the list of copies",
        .cache_list => ".{ for the list of caches",
        .bind_list => ".{ for the list of binds",
        .copy_or_close => ".{ for a copy, or }",
        .cache_or_close => ".{ for a cache, or }",
        .bind_or_close => ".{ for a bind, or }",
        .output_value => ".out or .root",
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

/// `E0804`: the base of a step (`step` null: of the image) is not in `zbx.lock` (`locked`
/// false), or is there but its image is not in the store (`locked` true). A build never
/// resolves a tag itself.
pub fn base_not_locked(diag: *Diag, step: ?[]const u8, reference: []const u8, locked: bool) void {
    assert(diag.code == null);
    assert(reference.len > 0);
    var reference_echo: Echo = undefined;
    const shown = text_util.sanitise(&reference_echo, reference);
    var while_storage: [constants.build_step_name_bytes_max + 16]u8 = undefined;
    var owner_storage: [constants.build_step_name_bytes_max + 16]u8 = undefined;
    const owner = if (step) |name|
        std.fmt.bufPrint(&owner_storage, "step \"{s}\"", .{name}) catch unreachable // Fits.
    else
        "the image";
    const doing = if (step) |name|
        std.fmt.bufPrint(&while_storage, "build step \"{s}\"", .{name}) catch unreachable // Fits.
    else
        "the image";
    assert(owner.len > 0);
    diag.raise(.E0804);
    diag.while_("resolving the base of {s}", .{doing});
    if (locked) {
        diag.cause("base \"{s}\" of {s} is in zbx.lock but its image is not in the store", .{
            shown, owner,
        });
    } else {
        diag.cause("base \"{s}\" of {s} is not in zbx.lock, and a build never resolves a " ++
            "tag itself", .{ shown, owner });
    }
    if (step) |name| diag.context("step", "{s}", .{name});
    diag.context("base", "{s}", .{shown});
    diag.fix_with("pull it, which pins it in zbx.lock", "zbx pull {s}", .{shown});
    assert(diag.code.? == .E0804);
}

/// A second fix on `E0804` when the unlocked base is the name of a step of the same file: a
/// bare `build` is an image reference, and a step's output is written `step:build`.
pub fn step_name_hint(diag: *Diag, name: []const u8) void {
    assert(diag.code.? == .E0804);
    assert(name.len > 0);
    var echo: Echo = undefined;
    const shown = text_util.sanitise(&echo, name);
    const sentence = "to use the output of the step of that name, write .from like this";
    diag.fix_with(sentence, ".from = \"step:{s}\"", .{shown});
    assert(diag.code.? == .E0804);
}

/// `E0422` or `E0423`: a build result record that cannot be used: it does not hash to its name
/// or does not parse (`newer` false: damaged), or a newer zbx wrote it (`newer` true).
pub fn result_unusable(diag: *Diag, digest: Digest, newer: bool) void {
    assert(diag.code == null);
    if (newer) {
        diag.raise(.E0423);
        diag.while_("reading the build result", .{});
        diag.cause("build result {s} was written by a newer zbx", .{digest.text()});
        diag.context("digest", "{s}", .{digest.text()});
        diag.fix(.{ .sentence = "upgrade zbx to read it, or build the project again" });
    } else {
        diag.raise(.E0422);
        diag.while_("reading the build result", .{});
        diag.cause("build result {s} is damaged", .{digest.text()});
        diag.context("digest", "{s}", .{digest.text()});
        diag.fix(.{ .sentence = "build the project again to write the record anew" });
    }
    assert(diag.code != null);
}

/// `E0804`: the registry answered a pull by the lock's digest with another manifest, so the
/// lock names an index (or a manifest of another platform) and not the image to build on.
pub fn locked_manifest_mismatch(
    diag: *Diag,
    reference: []const u8,
    returned: []const u8,
    locked: []const u8,
) void {
    assert(diag.code == null);
    assert(returned.len >= "sha256:".len + 12);
    assert(locked.len >= "sha256:".len + 12);
    var reference_echo: Echo = undefined;
    const shown = text_util.sanitise(&reference_echo, reference);
    diag.raise(.E0804);
    diag.while_("pulling the locked base \"{s}\"", .{shown});
    // The cause is cut at a line; the digests are whole in the context lines below it.
    const short = "sha256:".len + 12;
    diag.cause("locked base {s}: registry returned manifest {s}, lock says {s}", .{
        shown, returned[0..short], locked[0..short],
    });
    diag.context("base", "{s}", .{shown});
    diag.context("got", "{s}", .{returned});
    diag.context("lock", "{s}", .{locked});
    diag.fix_with("pin it again", "zbx pull {s}", .{shown});
    assert(diag.code.? == .E0804);
}

fn kind_word(kind: tree_mod.Kind) []const u8 {
    return switch (kind) {
        .file => "file",
        .dir => "directory",
        .symlink => "link",
    };
}

/// An add of `image.add`, as the build file writes it.
pub const AddText = struct { from: []const u8, to: []const u8 };

/// `E0807` for an `image.add` list that cannot make one image: two adds (or an add and the base)
/// want different things at one path, or the result passes the store's bounds. `index` is the
/// add that failed, `from` and `to` its fields. `earlier` is the add that put what is already
/// at a conflicting path there, null when the base did.
pub fn assembly_refused(
    diag: *Diag,
    failure: *const assemble_mod.Failure,
    index: u32,
    from: []const u8,
    to: []const u8,
    earlier: ?AddText,
) void {
    assert(diag.code == null);
    assert(failure.* != .io);
    assert(failure.* != .damaged);
    var from_echo: Echo = undefined;
    var to_echo: Echo = undefined;
    const from_shown = text_util.sanitise(&from_echo, from);
    const to_shown = text_util.sanitise(&to_echo, to);
    diag.raise(.E0807);
    diag.while_("assembling the image of the build file", .{});
    switch (failure.*) {
        .conflict => |conflict| conflict_refused(diag, conflict, from_shown, to_shown, earlier),
        .too_deep => {
            diag.cause("the image would be deeper than {d} directories at .image.add {s} -> {s}", .{
                constants.store_depth_max, from_shown, to_shown,
            });
            diag.fix(.{ .sentence = "shorten the destination in .image.add of zbx.build.zon" });
        },
        .too_large, .too_common => {
            diag.cause("the image is too large to assemble at .image.add {s} -> {s}", .{
                from_shown, to_shown,
            });
            diag.fix(.{ .sentence = "add fewer or smaller directories to .image.add" });
        },
        .io, .damaged => unreachable,
    }
    diag.context("add", "{d}", .{index + 1});
    assert(diag.code.? == .E0807);
}

fn conflict_refused(
    diag: *Diag,
    conflict: assemble_mod.Conflict,
    from_shown: []const u8,
    to_shown: []const u8,
    earlier: ?AddText,
) void {
    var path_echo: Echo = undefined;
    const path = text_util.sanitise(&path_echo, conflict.path[0..conflict.path_len]);
    var source_storage: [2 * constants.arg_echo_bytes_max + 32]u8 = undefined;
    var from_echo: Echo = undefined;
    var to_echo: Echo = undefined;
    const source = if (earlier) |add| std.fmt.bufPrint(&source_storage, ".image.add {s} -> {s}", .{
        text_util.sanitise(&from_echo, add.from),
        text_util.sanitise(&to_echo, add.to),
    }) catch unreachable else "the base image"; // The buffer holds two echoes.
    diag.cause("{s} has a {s} at {s}; .image.add {s} -> {s} brings a {s}", .{
        source,     kind_word(conflict.present), path,
        from_shown, to_shown,                    kind_word(conflict.brought),
    });
    diag.context("path", "{s}", .{path});
    diag.context("first", "{s}", .{source});
    if (earlier == null) {
        diag.fix(.{ .sentence = "give the add another destination in .image.add, " ++
            "or build on a base that does not have that path" });
    } else {
        diag.fix(.{ .sentence = "give the two adds different paths, or remove one of them " ++
            "in .image.add of zbx.build.zon" });
    }
}

/// `E0807` for an `image.config` that does not fit its record once the base's settings are
/// merged in: `field` is the one that is too large.
pub fn config_too_large(diag: *Diag, field: result_mod.Refusal) void {
    assert(diag.code == null);
    assert(@tagName(field).len > 0);
    diag.raise(.E0807);
    diag.while_("resolving the config of the image", .{});
    diag.cause("the image's {s} does not fit the image record once merged with the base's", .{
        @tagName(field),
    });
    diag.context("field", "{s}", .{@tagName(field)});
    diag.fix(.{ .sentence = "shorten .image.config in zbx.build.zon, or use a smaller base" });
    assert(diag.code.? == .E0807);
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

/// `W0901`: the provenance store holds `trust_records_max` records, so the result just built has
/// none. The build succeeded; a policy with `require_provenance` refuses this result.
pub fn provenance_store_full(diag: *Diag) void {
    assert(diag.code == null);
    diag.raise(.W0901);
    diag.while_("recording the provenance of the result", .{});
    diag.cause(
        "the store holds {d} provenance records, the most it keeps (trust_records_max), so " ++
            "this result has none and require_provenance refuses it",
        .{constants.trust_records_max},
    );
    diag.fix(.{ .sentence = "remove records of results you no longer need, then build again" });
    assert(diag.code.? == .W0901);
}

/// The start of W0801's last cause; the names follow it, so they have the field less this.
pub const network_label = "steps that use the network: ";

/// `W0801`: the build has steps with `network = true`. `names` is their names in the build's
/// order, joined by `, ` and cut to fit (`network_names`); `count` is how many there are.
pub fn network_steps(diag: *Diag, names: []const u8, count: u32) void {
    assert(diag.code == null);
    assert(count > 0);
    assert(names.len > 0);
    diag.raise(.W0801);
    diag.while_("planning the build", .{});
    // The newest cause is what the default view shows, so it is the one that names the steps.
    diag.cause("their output depends on what the network returns, not only on the inputs", .{});
    diag.cause(network_label ++ "{s}", .{names});
    diag.context("steps", "{d}", .{count});
    diag.fix(.{
        .sentence = "pin what they fetch, or fetch it once outside the build as an input",
    });
    assert(diag.code.? == .W0801);
}

/// `E0817`: a `.user` or `.group` name is not in the `/etc/passwd` or `/etc/group` the step (or
/// `.image.config`) is looked up in. `where` is what named it, already written, such as
/// `step "a"`; `name` is the name as written.
pub fn user_not_found(diag: *Diag, where: []const u8, name: []const u8) void {
    assert(diag.code == null);
    assert(where.len > 0);
    var echo: Echo = undefined;
    const shown = text_util.sanitise(&echo, name);
    diag.raise(.E0817);
    diag.while_("planning the build", .{});
    diag.cause("{s} .user \"{s}\" is not in /etc/passwd of its base", .{ where, shown });
    diag.context("name", "{s}", .{shown});
    diag.fix(.{
        .sentence = "add the user in an earlier step and base this step on it with " ++
            ".base = \"step:NAME\", or write the id as a number",
    });
    assert(diag.code.? == .E0817);
}

/// `E0818`: the paths the globs of a build matched are more than `build_glob_matches_max`, or
/// their names more than `build_glob_pool_bytes_max`. `input` is the glob being matched.
pub fn glob_pool_full(diag: *Diag, input: []const u8) void {
    assert(diag.code == null);
    assert(input.len > 0);
    var echo: Echo = undefined;
    const shown = text_util.sanitise(&echo, input);
    diag.raise(.E0818);
    diag.while_("matching a glob against the project", .{});
    diag.cause("\"{s}\" matched more than {d} paths in this build", .{
        shown,
        constants.build_glob_matches_max,
    });
    diag.context("input", "{s}", .{shown});
    diag.context("limit", "{d} paths", .{constants.build_glob_matches_max});
    diag.fix(.{
        .sentence = "match a directory instead of the files in it, narrow the glob, or " ++
            ".exclude what you do not need",
    });
    assert(diag.code.? == .E0818);
}

/// `W0802`: the build has steps with `.caches`. `names` is their names in the build's order,
/// already quoted and joined by `, `; `count` is how many there are.
pub fn cache_steps(diag: *Diag, names: []const u8, count: u32) void {
    assert(diag.code == null);
    assert(count > 0);
    assert(names.len > 0);
    diag.raise(.W0802);
    diag.while_("planning the build", .{});
    diag.cause("their output can depend on what a cache held, not only on the inputs", .{});
    diag.cause("steps with cache mounts: {s}", .{names});
    diag.context("steps", "{d}", .{count});
    diag.fix(.{
        .sentence = "keep each cache to what the command verifies or rebuilds, and do not " ++
            "let its output depend on what was in it",
    });
    assert(diag.code.? == .W0802);
}

/// The names of the network steps, joined by `, ` into `out`; when they do not fit, the ones
/// that do and `, ...`. Returns the used prefix, empty for no names.
pub fn network_names(out: []u8, names: []const []const u8) []const u8 {
    assert(out.len >= 8);
    const more = ", ...";
    var length: usize = 0;
    for (names, 0..) |name, at| {
        assert(name.len > 0);
        const separator: usize = if (at == 0) 0 else 2;
        const last = at + 1 == names.len;
        const reserve: usize = if (last) 0 else more.len;
        if (length + separator + name.len + reserve > out.len) {
            if (at == 0) {
                // Not even the first name fits: cut the name itself.
                const dots = "...";
                const kept = @min(out.len - dots.len, name.len);
                @memcpy(out[0..kept], name[0..kept]);
                @memcpy(out[kept..][0..dots.len], dots);
                return out[0 .. kept + dots.len];
            }
            if (length + more.len > out.len) length = out.len - more.len;
            @memcpy(out[length..][0..more.len], more);
            return out[0 .. length + more.len];
        }
        if (at > 0) {
            out[length] = ',';
            out[length + 1] = ' ';
        }
        @memcpy(out[length + separator ..][0..name.len], name);
        length += separator + name.len;
    }
    return out[0..length];
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

/// ZBX-E0005: `inspect --provenance` of a build result that has no provenance record: it was
/// built before provenance was written, or the store lost the record.
pub fn provenance_absent(diag: *Diag, operand: []const u8) void {
    assert(diag.code == null);
    var storage: Echo = undefined;
    const echo = text_util.sanitise(&storage, operand);
    diag.raise(.E0005);
    diag.while_("reading the command line", .{});
    diag.cause("the store has no provenance record for build result '{s}'", .{echo});
    diag.fix(.{ .sentence = "build the project again to write one:", .command = "zbx build" });
    diag.context("cmd", "inspect --provenance", .{});
    diag.context("arg", "{s}", .{echo});
}

/// ZBX-E0005: the operand of `inspect` is no build result: not a full digest, or no record of
/// that name in the store.
pub fn result_operand(diag: *Diag, operand: []const u8, absent: bool) void {
    assert(diag.code == null);
    var storage: Echo = undefined;
    const echo = text_util.sanitise(&storage, operand);
    diag.raise(.E0005);
    diag.while_("reading the command line", .{});
    if (absent) {
        diag.cause("the store has no build result '{s}'", .{echo});
        diag.fix(.{
            .sentence = "build the project, and use the digest it prints:",
            .command = "zbx build",
        });
    } else {
        diag.cause("'{s}' is not the digest of a build result: b3: and 64 hex digits", .{echo});
        diag.fix(.{
            .sentence = "give the digest `zbx build` printed:",
            .command = "zbx inspect b3:<64 hex>",
            .template = true,
        });
    }
    diag.context("cmd", "inspect", .{});
    diag.context("arg", "{s}", .{echo});
}

test "network_names joins the names and cuts what does not fit with an ellipsis" {
    // Goal: the W0801 cause always fits its field, names the steps in order, and says when it
    // left some out. Method: names that fit exactly, one past, and a single name too long.
    var out: [20]u8 = undefined;
    try std.testing.expectEqualStrings("a", network_names(&out, &.{"a"}));
    try std.testing.expectEqualStrings("fetch, other", network_names(&out, &.{ "fetch", "other" }));
    const exact = network_names(&out, &.{ "aaaaaaaa", "bbbbbbbb" }); // 18 bytes.
    try std.testing.expectEqualStrings("aaaaaaaa, bbbbbbbb", exact);
    const cut = network_names(&out, &.{ "aaaaaaaa", "bbbbbbbb", "c" });
    try std.testing.expectEqualStrings("aaaaaaaa, ...", cut);
    const long = network_names(&out, &.{&@as([25]u8, @splat('x'))});
    try std.testing.expectEqualStrings("xxxxxxxxxxxxxxxxx...", long);
    try std.testing.expect(long.len <= out.len);
    // The boundary: the first name fits alone but not with the `, ...` that a later name needs,
    // and is shorter than the room for a cut name. It is kept whole, then the dots.
    var small: [8]u8 = @splat('#');
    const short_first = network_names(&small, &.{ "abcd", "e" });
    try std.testing.expectEqualStrings("abcd...", short_first);
    const same = network_names(&small, &.{ "abcde", "f" }); // kept == out.len - 3 == 5.
    try std.testing.expectEqualStrings("abcde...", same);
}

test "a bare step name as a base gets a second fix that writes step:<name>" {
    // Goal: `.from = "build"` (an image reference) is refused with the way to spell the step.
    // Method: raise E0804, add the hint, and read the fixes back: the pull first, the hint last.
    var diag: Diag = undefined;
    diag.reset();
    base_not_locked(&diag, "pack", "build", false);
    step_name_hint(&diag, "build");
    try std.testing.expectEqual(@as(u32, 2), diag.fixes.count);
    try std.testing.expect(std.mem.indexOf(u8, diag.fixes.items[1].command.slice(), "step:build") != null);
    try std.testing.expect(std.mem.indexOf(u8, diag.fixes.items[0].command.slice(), "zbx pull") != null);
}
