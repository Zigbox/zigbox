//! A Dockerfile's logical lines: parser directives, then one `Instruction` per instruction with
//! its keyword, first line, argument text and heredoc bodies.
//!
//! Docker's rules, as its parser applies them: directives (`# syntax=`, `# escape=`,
//! `# check=`) are read only before the first comment, empty line or instruction. A line whose
//! last byte (trailing whitespace dropped) is the escape character continues on the next one;
//! the escape character is dropped and the lines are joined with nothing between them. Comment
//! lines and empty lines inside a continuation are skipped. A `RUN`, `COPY` or `ADD` in shell
//! form may name heredocs (`<<NAME`, `<<-NAME`, `<<"NAME"`); their bodies are the lines that
//! follow, up to a line that is the name alone (with `<<-`, after leading tabs are dropped).
//!
//! The joined text and the bodies are copied into the caller's scratch buffer. Nothing
//! allocates; every count is bounded by `constants.zig`.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const refusal_mod = @import("refusal.zig");

const Refusal = refusal_mod.Refusal;
const Refused = refusal_mod.Refused;
const refuse = refusal_mod.refuse;

pub const Keyword = enum {
    from,
    run,
    cmd,
    label,
    maintainer,
    expose,
    env,
    add,
    copy,
    entrypoint,
    volume,
    user,
    workdir,
    arg,
    onbuild,
    stopsignal,
    healthcheck,
    shell,

    /// The keyword as Docker's reference writes it.
    pub fn upper(keyword: Keyword) []const u8 {
        return switch (keyword) {
            inline else => |tag| comptime upper_comptime(@tagName(tag)),
        };
    }
};

fn upper_comptime(comptime name: []const u8) []const u8 {
    comptime var out: [name.len]u8 = undefined;
    inline for (name, 0..) |byte, index| out[index] = comptime std.ascii.toUpper(byte);
    const final = out;
    return &final;
}

/// A range of the scratch buffer.
pub const Range = struct {
    at: u32,
    len: u32,
};

pub const Heredoc = struct {
    /// The marker as written in the text, from `<<` to the end of the name (and its quote).
    marker: Range,
    /// The body: every line up to the terminator, each with its `\n`.
    body: Range,
    strip_tabs: bool,
    quoted: bool,
};

pub const Instruction = struct {
    keyword: Keyword,
    /// The 1-based line the instruction starts on.
    line: u32,
    /// Everything after the keyword, the continuation lines joined, trimmed at both ends.
    text: Range,
    heredocs_count: u8,
    heredoc: Heredoc,
};

pub const Directive = struct {
    line: u32,
    value: Range,
};

pub const Parsed = struct {
    escape: u8,
    syntax: ?Directive,
    check: ?Directive,
    instructions: [constants.import_instructions_max]Instruction,
    instructions_count: u32,
    scratch: [constants.import_scratch_bytes_max]u8,
    scratch_len: u32,

    pub fn slice(parsed: *const Parsed, range: Range) []const u8 {
        assert(range.at + range.len <= parsed.scratch_len);
        return parsed.scratch[range.at..][0..range.len];
    }

    pub fn instructions_slice(parsed: *const Parsed) []const Instruction {
        assert(parsed.instructions_count <= constants.import_instructions_max);
        return parsed.instructions[0..parsed.instructions_count];
    }

    fn append(parsed: *Parsed, refusal: *Refusal, line: u32, bytes: []const u8) Refused!void {
        if (bytes.len > parsed.scratch.len - parsed.scratch_len) {
            return refuse(refusal, .E0815, line, "the Dockerfile's text is more than the " ++
                "import holds ({d} bytes)", .{constants.import_scratch_bytes_max}, "split " ++
                "the Dockerfile, or shorten its longest instructions", .{});
        }
        @memcpy(parsed.scratch[parsed.scratch_len..][0..bytes.len], bytes);
        parsed.scratch_len += @intCast(bytes.len);
    }
};

/// The physical lines of a text, each without its line end (`\n` or `\r\n`).
const Lines = struct {
    text: []const u8,
    at: usize = 0,
    number: u32 = 0,

    fn next(lines: *Lines) ?[]const u8 {
        if (lines.at >= lines.text.len) return null;
        const rest = lines.text[lines.at..];
        const end = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
        lines.at += end + 1;
        lines.number += 1;
        assert(lines.number <= lines.text.len);
        const line = rest[0..end];
        if (line.len > 0 and line[line.len - 1] == '\r') return line[0 .. line.len - 1];
        return line;
    }
};

const whitespace = " \t\r\x0b\x0c";

/// Reads `text`, a whole Dockerfile, into `parsed`. Refuses with E0810 (what cannot be read)
/// or E0815 (a bound).
pub fn parse(text: []const u8, parsed: *Parsed, refusal: *Refusal) Refused!void {
    if (text.len > constants.import_dockerfile_bytes_max) {
        return refuse(refusal, .E0815, 0, "the Dockerfile is {d} bytes, more than the {d} " ++
            "the import reads", .{ text.len, constants.import_dockerfile_bytes_max }, "split " ++
            "the Dockerfile", .{});
    }
    parsed.escape = '\\';
    parsed.syntax = null;
    parsed.check = null;
    parsed.instructions_count = 0;
    parsed.scratch_len = 0;
    var lines: Lines = .{ .text = text };
    try read_directives(&lines, parsed, refusal);
    while (try next_instruction(&lines, parsed, refusal)) {}
    assert(parsed.instructions_count <= constants.import_instructions_max);
    assert(parsed.scratch_len <= constants.import_scratch_bytes_max);
}

/// Reads the directives; leaves `lines` at the first line that is not one.
fn read_directives(lines: *Lines, parsed: *Parsed, refusal: *Refusal) Refused!void {
    var escape_seen = false;
    while (true) {
        const saved = lines.*;
        const line = lines.next() orelse return;
        const directive = directive_of(line) orelse {
            lines.* = saved;
            return;
        };
        const number = lines.number;
        if (std.ascii.eqlIgnoreCase(directive.name, "escape")) {
            if (escape_seen) return refuse_directive_twice(refusal, number, "escape");
            escape_seen = true;
            parsed.escape = try escape_of(directive.value, number, refusal);
        } else if (std.ascii.eqlIgnoreCase(directive.name, "syntax")) {
            if (parsed.syntax != null) return refuse_directive_twice(refusal, number, "syntax");
            parsed.syntax = try store_directive(parsed, refusal, number, directive.value);
        } else if (std.ascii.eqlIgnoreCase(directive.name, "check")) {
            if (parsed.check != null) return refuse_directive_twice(refusal, number, "check");
            parsed.check = try store_directive(parsed, refusal, number, directive.value);
        } else {
            // Docker reads an unknown directive as a comment, which ends the directives.
            lines.* = saved;
            return;
        }
    }
}

fn refuse_directive_twice(refusal: *Refusal, line: u32, name: []const u8) Refused {
    return refuse(refusal, .E0810, line, "Dockerfile:{d} gives the `{s}` directive twice", .{
        line, name,
    }, "keep one `# {s}=` line", .{name});
}

fn escape_of(value: []const u8, line: u32, refusal: *Refusal) Refused!u8 {
    if (value.len == 1) {
        if (value[0] == '\\') return '\\';
        if (value[0] == '`') return '`';
    }
    return refuse(refusal, .E0810, line, "Dockerfile:{d} sets the escape character to `{s}`, " ++
        "not `\\` or a backtick", .{ line, value }, "write `# escape=\\` or `# escape=``", .{});
}

fn store_directive(
    parsed: *Parsed,
    refusal: *Refusal,
    line: u32,
    value: []const u8,
) Refused!Directive {
    const at = parsed.scratch_len;
    try parsed.append(refusal, line, value);
    return .{ .line = line, .value = .{ .at = at, .len = @intCast(value.len) } };
}

const DirectiveText = struct { name: []const u8, value: []const u8 };

/// `# name=value`, with spaces allowed around each part; null for any other line.
fn directive_of(line: []const u8) ?DirectiveText {
    const trimmed = std.mem.trim(u8, line, whitespace);
    if (trimmed.len < 2) return null;
    if (trimmed[0] != '#') return null;
    const body = std.mem.trim(u8, trimmed[1..], whitespace);
    const equals = std.mem.indexOfScalar(u8, body, '=') orelse return null;
    const name = std.mem.trim(u8, body[0..equals], whitespace);
    if (name.len == 0) return null;
    for (name) |byte| {
        if (!std.ascii.isAlphabetic(byte)) return null;
    }
    return .{ .name = name, .value = std.mem.trim(u8, body[equals + 1 ..], whitespace) };
}

fn is_comment(line: []const u8) bool {
    const trimmed = std.mem.trimStart(u8, line, whitespace);
    return trimmed.len > 0 and trimmed[0] == '#';
}

fn is_blank(line: []const u8) bool {
    return std.mem.trim(u8, line, whitespace).len == 0;
}

/// Reads the next instruction into `parsed`; false at the end of the text.
fn next_instruction(lines: *Lines, parsed: *Parsed, refusal: *Refusal) Refused!bool {
    const first = while (lines.next()) |line| {
        if (!is_comment(line) and !is_blank(line)) break line;
    } else return false;
    const number = lines.number;
    if (parsed.instructions_count == constants.import_instructions_max) {
        return refuse(refusal, .E0815, number, "the Dockerfile has more than {d} instructions", .{
            constants.import_instructions_max,
        }, "split the Dockerfile", .{});
    }
    const start = parsed.scratch_len;
    try join_continued(lines, parsed, refusal, first);
    const joined = parsed.scratch[start..parsed.scratch_len];
    const keyword_end = std.mem.indexOfAny(u8, joined, whitespace) orelse joined.len;
    const keyword = keyword_of(joined[0..keyword_end]) orelse {
        const shown = joined[0..@min(keyword_end, 64)];
        return refuse(refusal, .E0810, number, "Dockerfile:{d} starts with `{s}`, which is " ++
            "not an instruction", .{ number, shown }, "start the line with an instruction " ++
            "such as RUN or COPY, or end the line before it with `{c}`", .{parsed.escape});
    };
    const rest = std.mem.trim(u8, joined[keyword_end..], whitespace);
    const offset: u32 = @intCast(rest.ptr - parsed.scratch[0..].ptr);
    const instruction = &parsed.instructions[parsed.instructions_count];
    instruction.* = .{
        .keyword = keyword,
        .line = number,
        .text = .{ .at = offset, .len = @intCast(rest.len) },
        .heredocs_count = 0,
        .heredoc = undefined,
    };
    parsed.instructions_count += 1;
    if (takes_heredocs(keyword, rest)) try read_heredocs(lines, parsed, refusal, instruction);
    return true;
}

fn takes_heredocs(keyword: Keyword, rest: []const u8) bool {
    switch (keyword) {
        .run, .copy, .add => {},
        else => return false,
    }
    if (rest.len > 0 and rest[0] == '[') return false;
    return std.mem.indexOf(u8, rest, "<<") != null;
}

/// Appends `first` and every line it continues onto, the escape characters dropped.
fn join_continued(lines: *Lines, parsed: *Parsed, refusal: *Refusal, first: []const u8) !void {
    const number = lines.number;
    var line = std.mem.trimStart(u8, first, whitespace);
    var count: u32 = 0;
    while (true) : (count += 1) {
        assert(count <= lines.text.len);
        const trimmed = std.mem.trimEnd(u8, line, whitespace);
        const continues = trimmed.len > 0 and trimmed[trimmed.len - 1] == parsed.escape;
        if (!continues) return parsed.append(refusal, number, line);
        try parsed.append(refusal, number, trimmed[0 .. trimmed.len - 1]);
        line = while (lines.next()) |next| {
            if (!is_comment(next) and !is_blank(next)) break next;
        } else return;
    }
}

fn keyword_of(word: []const u8) ?Keyword {
    if (word.len == 0) return null;
    if (word.len > 16) return null;
    var lower: [16]u8 = undefined;
    for (word, 0..) |byte, index| lower[index] = std.ascii.toLower(byte);
    return std.meta.stringToEnum(Keyword, lower[0..word.len]);
}

const Marker = struct { start: usize, end: usize, name: []const u8, strip: bool, quoted: bool };

/// The heredoc marker at or after `from` in `text`, or null.
fn marker_after(text: []const u8, from: usize) ?Marker {
    var at = from;
    while (std.mem.indexOfPos(u8, text, at, "<<")) |found| {
        at = found + 2;
        var index = at;
        const strip = index < text.len and text[index] == '-';
        if (strip) index += 1;
        var quote: u8 = 0;
        if (index < text.len and (text[index] == '"' or text[index] == '\'')) {
            quote = text[index];
            index += 1;
        }
        const name_start = index;
        while (index < text.len and is_name_byte(text[index], index == name_start)) index += 1;
        if (index == name_start) continue;
        const name = text[name_start..index];
        if (quote != 0) {
            if (index >= text.len or text[index] != quote) continue;
            index += 1;
        }
        return .{ .start = found, .end = index, .name = name, .strip = strip, .quoted = quote != 0 };
    }
    return null;
}

fn is_name_byte(byte: u8, first: bool) bool {
    if (std.ascii.isAlphabetic(byte) or byte == '_') return true;
    return !first and std.ascii.isDigit(byte);
}

/// Reads the body of each heredoc the instruction's text names, in order. The instruction keeps
/// the first; `heredocs_count` says how many there were (the translator refuses two).
fn read_heredocs(
    lines: *Lines,
    parsed: *Parsed,
    refusal: *Refusal,
    instruction: *Instruction,
) Refused!void {
    const text = parsed.slice(instruction.text);
    var at: usize = 0;
    while (marker_after(text, at)) |marker| {
        at = marker.end;
        const body_at = parsed.scratch_len;
        try read_body(lines, parsed, refusal, instruction.line, marker);
        if (instruction.heredocs_count == 0) {
            instruction.heredoc = .{
                .marker = .{
                    .at = instruction.text.at + @as(u32, @intCast(marker.start)),
                    .len = @intCast(marker.end - marker.start),
                },
                .body = .{ .at = body_at, .len = parsed.scratch_len - body_at },
                .strip_tabs = marker.strip,
                .quoted = marker.quoted,
            };
        }
        instruction.heredocs_count +|= 1;
    }
    assert(instruction.heredocs_count > 0);
}

fn read_body(
    lines: *Lines,
    parsed: *Parsed,
    refusal: *Refusal,
    line: u32,
    marker: Marker,
) Refused!void {
    while (lines.next()) |body_line| {
        const shown = if (marker.strip) std.mem.trimStart(u8, body_line, "\t") else body_line;
        if (std.mem.eql(u8, shown, marker.name)) return;
        try parsed.append(refusal, line, shown);
        try parsed.append(refusal, line, "\n");
    }
    return refuse(refusal, .E0810, line, "Dockerfile:{d} opens the heredoc `{s}` and the " ++
        "file ends before a line `{s}` closes it", .{ line, marker.name, marker.name }, "end " ++
        "the heredoc with a line holding only `{s}`", .{marker.name});
}

const testing = std.testing;

fn parse_test(text: []const u8) !*Parsed {
    const parsed = try testing.allocator.create(Parsed);
    errdefer testing.allocator.destroy(parsed);
    var refusal: Refusal = undefined;
    parse(text, parsed, &refusal) catch {
        std.debug.print("refused: {s}\n", .{refusal.what_text()});
        return error.TestUnexpectedResult;
    };
    return parsed;
}

test "directives, comments, continuations and keywords" {
    // Goal: Docker's line rules. Method: a file with each rule once, read back instruction by
    // instruction.
    const parsed = try parse_test(
        \\# syntax=docker/dockerfile:1
        \\#  Escape = `
        \\# check=skip=all
        \\FROM alpine
        \\# a comment
        \\run echo a `
        \\  # a comment inside
        \\
        \\  && echo b
        \\Copy ["a", `
        \\ "b"]
        \\
    );
    defer testing.allocator.destroy(parsed);
    try testing.expectEqual(@as(u8, '`'), parsed.escape);
    try testing.expectEqualStrings("docker/dockerfile:1", parsed.slice(parsed.syntax.?.value));
    try testing.expectEqual(@as(u32, 3), parsed.check.?.line);
    const all = parsed.instructions_slice();
    try testing.expectEqual(@as(usize, 3), all.len);
    try testing.expectEqual(Keyword.run, all[1].keyword);
    try testing.expectEqual(@as(u32, 6), all[1].line);
    try testing.expectEqualStrings("echo a   && echo b", parsed.slice(all[1].text));
    try testing.expectEqualStrings("[\"a\",  \"b\"]", parsed.slice(all[2].text));
    try testing.expectEqualStrings("COPY", all[2].keyword.upper());
}

test "a directive after an instruction is a comment" {
    // Goal: directives are read only at the top. Method: `# escape=` after a comment.
    const parsed = try parse_test("# hello\n# escape=`\nFROM a \\\n  AS b\n");
    defer testing.allocator.destroy(parsed);
    try testing.expectEqual(@as(u8, '\\'), parsed.escape);
    try testing.expectEqualStrings("a   AS b", parsed.slice(parsed.instructions[0].text));
}

test "heredocs: bodies, tab stripping, quotes and a missing end" {
    // Goal: each heredoc form is read, and a missing terminator is E0810. Method: two RUNs
    // and one unterminated body.
    const parsed = try parse_test("FROM a\nRUN <<-\"EOF\"\n\techo $x\nEOF\nRUN <<A cat <<B\n" ++
        "1\nA\n2\nB\nCMD x\n");
    defer testing.allocator.destroy(parsed);
    const all = parsed.instructions_slice();
    try testing.expectEqual(@as(usize, 4), all.len);
    try testing.expectEqualStrings("echo $x\n", parsed.slice(all[1].heredoc.body));
    try testing.expect(all[1].heredoc.strip_tabs);
    try testing.expect(all[1].heredoc.quoted);
    try testing.expectEqualStrings("<<-\"EOF\"", parsed.slice(all[1].heredoc.marker));
    try testing.expectEqual(@as(u8, 2), all[2].heredocs_count);
    try testing.expectEqualStrings("1\n", parsed.slice(all[2].heredoc.body));
    try testing.expectEqual(Keyword.cmd, all[3].keyword);

    const missing = try testing.allocator.create(Parsed);
    defer testing.allocator.destroy(missing);
    var refusal: Refusal = undefined;
    try testing.expectEqual(error.Refused, parse("FROM a\nRUN <<EOF\necho\n", missing, &refusal));
    try testing.expectEqual(refusal_mod.Code.E0810, refusal.code);
    try testing.expectEqual(@as(u32, 2), refusal.line);
}

test "an unknown instruction and a bad escape are E0810" {
    // Goal: the two parse refusals of this module. Method: each alone.
    const parsed = try testing.allocator.create(Parsed);
    defer testing.allocator.destroy(parsed);
    var refusal: Refusal = undefined;
    try testing.expectEqual(error.Refused, parse("FROM a\nFETCH x\n", parsed, &refusal));
    try testing.expectEqual(refusal_mod.Code.E0810, refusal.code);
    try testing.expect(std.mem.indexOf(u8, refusal.what_text(), "`FETCH`") != null);
    try testing.expectEqual(error.Refused, parse("# escape=x\nFROM a\n", parsed, &refusal));
    try testing.expectEqual(@as(u32, 1), refusal.line);
    try testing.expectEqual(error.Refused, parse("# escape=`\n# escape=`\n", parsed, &refusal));
}

test "the instruction bound is E0815, one past it" {
    // Goal: `import_instructions_max` is checked at the bound and one past it. Method: files
    // with exactly the bound and one more.
    const parsed = try testing.allocator.create(Parsed);
    defer testing.allocator.destroy(parsed);
    var refusal: Refusal = undefined;
    const line = "ENV A=1\n";
    const count = constants.import_instructions_max;
    var text: [(count + 1) * line.len]u8 = undefined;
    for (0..count + 1) |index| @memcpy(text[index * line.len ..][0..line.len], line);
    try parse(text[0 .. count * line.len], parsed, &refusal);
    try testing.expectEqual(count, parsed.instructions_count);
    try testing.expectEqual(error.Refused, parse(&text, parsed, &refusal));
    try testing.expectEqual(refusal_mod.Code.E0815, refusal.code);
}
