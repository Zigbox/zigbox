//! A build file, `zbx.build.zon` (docs/briefs/M7-build.md, "The build file"): what it holds and
//! how it is read. The file is a restricted ZON subset: structs, strings, string lists, booleans
//! and one integer, with `//` comments, in a fixed schema:
//!
//!   .{
//!       .version = 1,
//!       .steps = .{ .{ .name, .base, .run, [.inputs, .needs, .env, .network] }, ... },
//!       .image = .{ [.base], [.add = .{ .{ .from, .to }, ... }], [.config = .{ ... }] },
//!   }
//!
//! The parser is written by hand, bounded and not recursive: the schema has a fixed depth, and
//! each level is its own function, so the call depth is fixed too. Every bound is in
//! `constants.zig`; a file past one is refused with the line and column where it went past.
//! Nothing allocates: strings are decoded into the file's pool, lists are fixed arrays.
//!
//! The parser checks everything that one value can tell on its own: a step's name, a reference,
//! an env entry, an absolute path, `image.config`'s fields. What needs the whole file (unknown
//! `needs`, cycles) is `graph.zig`; what needs the disk (inputs) is `inputs.zig`.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const lexer_mod = @import("lexer.zig");
const reference_mod = @import("../registry/reference.zig");
const glob = @import("glob.zig");

const Lexer = lexer_mod.Lexer;
const Token = lexer_mod.Token;

pub const file_name = "zbx.build.zon";
pub const version: u32 = 1;

/// A decoded string: its bytes in the file's pool, and where it was written.
pub const Text = struct {
    at: u32,
    len: u32,
    line: u32,
    column: u32,
};

/// A bounded list of strings. `given` tells an empty list written as `.{}` from no list, which
/// matters in `image.config`: an empty `entrypoint` given clears the base's.
pub fn List(comptime capacity: u32) type {
    return struct {
        items: [capacity]Text,
        count: u32,
        given: bool,

        const Self = @This();
        pub const max = capacity;

        pub fn slice(list: *const Self) []const Text {
            assert(list.count <= capacity);
            if (!list.given) assert(list.count == 0);
            return list.items[0..list.count];
        }
    };
}

/// A run of entries in one of the file's shared arrays (`list_texts`, `copies`, `caches`,
/// `binds`): the file holds them all, so a step carries three numbers, not an array. `given`
/// tells an empty list written from none, as `List`'s does.
pub const Span = struct {
    begin: u32,
    count: u32,
    given: bool,

    pub const none: Span = .{ .begin = 0, .count = 0, .given = false };
};

/// What a step keeps: M7's `/out`, or (M9) its whole root.
pub const Output = enum { out, root };

/// One entry of a `copy` step.
pub const CopyEntry = struct {
    /// Absent: the project. Otherwise `step:<name>` or a locked image reference.
    from: ?Text,
    /// Paths or globs, in `list_texts`.
    src: Span,
    to: Text,
    chown: ?Text,
    chmod: ?Text,
    exclude: Span,
    line: u32,
    column: u32,
};

/// A cache directory of a step (M9 `.caches`).
pub const Cache = struct {
    id: Text,
    path: Text,
    ro: bool,
    mode: ?Text,
    uid: ?u32,
    gid: ?u32,
    line: u32,
    column: u32,
};

/// A read-only mount of a step (M9 `.binds`).
pub const Bind = struct {
    /// Absent: the project. Otherwise `step:<name>` or a locked image reference.
    from: ?Text,
    source: Text,
    to: Text,
    line: u32,
    column: u32,
};

pub const Step = struct {
    name: Text,
    base: Text,
    inputs: List(constants.build_step_inputs_max),
    needs: List(constants.build_step_needs_max),
    env: List(constants.build_step_env_max),
    run: List(constants.build_step_argv_max),
    network: bool,
    output: Output,
    user: ?Text,
    workdir: ?Text,
    /// A step with `copy` given has no `run` (`copy.given`), and the other way round.
    copy: Span,
    caches: Span,
    binds: Span,
    exclude: Span,
    /// Where the step's `.{` is.
    line: u32,
    column: u32,
};

pub const Add = struct {
    from: Text,
    to: Text,
    line: u32,
    column: u32,
};

pub const Label = struct {
    key: Text,
    value: Text,
};

/// `image.config`: every field optional; `present` is whether `.config` was written at all.
pub const Config = struct {
    present: bool,
    entrypoint: List(constants.build_config_argv_max),
    cmd: List(constants.build_config_argv_max),
    env: List(constants.build_config_env_max),
    workdir: ?Text,
    user: ?Text,
    labels: [constants.build_config_labels_max]Label,
    labels_count: u32,
    labels_given: bool,
};

pub const Image = struct {
    /// Absent means an empty tree.
    base: ?Text,
    adds: [constants.build_image_adds_max]Add,
    adds_count: u32,
    config: Config,
    line: u32,
    column: u32,
};

pub const BuildFile = struct {
    version: u32,
    steps: [constants.build_steps_max]Step,
    steps_count: u32,
    image: Image,
    /// The file's `.exclude`, in `list_texts`.
    exclude: Span,
    list_texts: [constants.build_file_list_texts_max]Text,
    list_texts_count: u32,
    copies: [constants.build_file_copies_max]CopyEntry,
    copies_count: u32,
    caches: [constants.build_file_caches_max]Cache,
    caches_count: u32,
    binds: [constants.build_file_binds_max]Bind,
    binds_count: u32,
    pool: [constants.build_pool_bytes]u8,
    pool_len: u32,

    pub fn text(file: *const BuildFile, value: Text) []const u8 {
        assert(value.at + value.len <= file.pool_len);
        assert(file.pool_len <= file.pool.len);
        return file.pool[value.at..][0..value.len];
    }

    pub fn steps_slice(file: *const BuildFile) []const Step {
        assert(file.steps_count <= constants.build_steps_max);
        return file.steps[0..file.steps_count];
    }

    pub fn texts(file: *const BuildFile, span: Span) []const Text {
        assert(span.begin + span.count <= file.list_texts_count);
        assert(file.list_texts_count <= constants.build_file_list_texts_max);
        return file.list_texts[span.begin..][0..span.count];
    }

    pub fn copy_entries(file: *const BuildFile, step: *const Step) []const CopyEntry {
        assert(step.copy.begin + step.copy.count <= file.copies_count);
        assert(file.copies_count <= constants.build_file_copies_max);
        return file.copies[step.copy.begin..][0..step.copy.count];
    }

    pub fn step_caches(file: *const BuildFile, step: *const Step) []const Cache {
        assert(step.caches.begin + step.caches.count <= file.caches_count);
        assert(file.caches_count <= constants.build_file_caches_max);
        return file.caches[step.caches.begin..][0..step.caches.count];
    }

    pub fn step_binds(file: *const BuildFile, step: *const Step) []const Bind {
        assert(step.binds.begin + step.binds.count <= file.binds_count);
        assert(file.binds_count <= constants.build_file_binds_max);
        return file.binds[step.binds.begin..][0..step.binds.count];
    }

    pub fn adds_slice(file: *const BuildFile) []const Add {
        assert(file.image.adds_count <= constants.build_image_adds_max);
        return file.image.adds[0..file.image.adds_count];
    }

    pub fn labels_slice(file: *const BuildFile) []const Label {
        const config = &file.image.config;
        assert(config.labels_count <= constants.build_config_labels_max);
        if (!config.labels_given) assert(config.labels_count == 0);
        return config.labels[0..config.labels_count];
    }
};

/// The fields of every level, by name. Which level takes which is `allowed`.
pub const Field = enum {
    version,
    steps,
    image,
    name,
    base,
    inputs,
    needs,
    env,
    run,
    network,
    add,
    config,
    from,
    to,
    entrypoint,
    cmd,
    workdir,
    user,
    labels,
    // M9.
    output,
    copy,
    caches,
    binds,
    exclude,
    src,
    chown,
    chmod,
    id,
    path,
    source,
    ro,
    mode,
    uid,
    gid,
};

/// Where in the schema a problem is.
pub const Level = enum {
    file,
    step,
    image,
    add,
    config,
    label,
    copy,
    cache,
    bind,

    /// The fields this level takes, in the order the canonical printer writes them.
    pub fn allowed(level: Level) []const Field {
        return switch (level) {
            .file => &.{ .version, .exclude, .steps, .image },
            .step => &.{
                .name,   .base, .inputs,  .needs, .env,    .run,   .network,
                .output, .user, .workdir, .copy,  .caches, .binds, .exclude,
            },
            .image => &.{ .base, .add, .config },
            .add => &.{ .from, .to },
            .config => &.{ .entrypoint, .cmd, .env, .workdir, .user, .labels },
            .label => &.{},
            .copy => &.{ .from, .src, .to, .chown, .chmod, .exclude },
            .cache => &.{ .id, .path, .ro, .mode, .uid, .gid },
            .bind => &.{ .from, .source, .to },
        };
    }
};

/// What the parser wanted where it found something else.
pub const Expected = enum {
    open,
    field_or_close,
    equals,
    comma_or_close,
    string,
    string_or_close,
    string_list,
    step_list,
    add_list,
    label_list,
    copy_list,
    cache_list,
    bind_list,
    copy_or_close,
    cache_or_close,
    bind_or_close,
    output_value,
    step_or_close,
    add_or_close,
    label_or_close,
    integer,
    boolean,
    end,
    comma,
    close,
};

pub const ProblemKind = enum {
    // E0801: the file cannot be parsed.
    /// The token is not what the grammar allows here (`expected`).
    syntax,
    /// A field that this level does not take (`word` is its name).
    unknown_field,
    duplicate_field,
    /// A required field is not there (`field`); the position is the struct's `.{`.
    missing_field,
    /// A `\` escape that is not one of `\n \r \t \\ \' \" \xNN`.
    bad_escape,
    /// A control byte in a string, or bytes that are not UTF-8.
    bad_string,
    /// A NUL byte, decoded from `\x00`: no argv, path or variable can hold one.
    nul_byte,
    string_too_long,
    /// More entries than `field`'s list holds (more steps, adds or labels for those levels).
    list_too_long,
    /// Every string together is more than the pool holds.
    text_too_long,
    /// `.version` is 0 or has too many digits.
    bad_version,
    /// `.version` is newer than this zbx reads.
    newer_version,
    /// A list holds more than the file's shared arrays have room for in all (`field` says which).
    file_too_big,
    /// A step name that is empty, too long, or not `[a-z0-9-]`.
    bad_step_name,
    /// The step name `image`, which names the result in the report and the graph.
    reserved_step_name,
    /// `base` is not an image reference.
    bad_reference,
    /// `run` is empty, or its first word is.
    empty_run,
    /// A step's env entry is not `KEY=VALUE` with a key `[A-Za-z_][A-Za-z0-9_]*`.
    bad_env,
    /// An env list sets a key twice (`word` is the key).
    env_twice,
    /// A step's env sets a key of the fixed environment (`word` is the key).
    env_fixed,
    /// `add.to` is not an absolute path written plainly (no `.`, `..` or empty parts).
    bad_target,
    /// `.output` is not `.out` or `.root`.
    bad_output,
    /// A step with both `run` and `copy`, or with neither.
    run_or_copy,
    /// `.user` (a step's or a copy's `.chown`) is not `uid`, `uid:gid`, `name` or `name:group`.
    bad_user,
    /// `.workdir`, a cache's `.path` or a bind's `.to` is not an absolute path written plainly.
    bad_path,
    /// A copy's `.to`: absolute, plain, and it may end in `/`.
    bad_copy_to,
    /// `.chmod` or a cache's `.mode` is not 3 or 4 octal digits.
    bad_mode,
    /// A `.src` or `.exclude` entry is not a pattern (`word` is the entry).
    bad_pattern,
    /// A copy's or a bind's `.from` is not `step:<name>` or an image reference.
    bad_from,
    /// A bind's `.source` is not a path inside what it comes from.
    bad_source,
    /// A cache's `.id` is empty, too long, or has a byte outside `[A-Za-z0-9._/-]`.
    bad_cache_id,
    /// A cache's `.uid` or `.gid` is not a number that fits 32 bits.
    bad_number,
    /// Two caches or binds of one step mount at one path (`word` is it).
    mount_twice,
    // E0802: the graph.
    /// More `needs` than a step can mount.
    too_many_needs,
    /// `needs` and `binds` (and `/src` and `/out`) come to more mounts than a run holds.
    too_many_mounts,
    // E0807: `image.config`.
    config_workdir,
    config_user,
    config_env,
    config_label_key,
    config_label_twice,
};

pub const Problem = struct {
    kind: ProblemKind,
    /// Counting from 1; the column counts bytes.
    line: u32,
    column: u32,
    level: Level,
    field: ?Field,
    expected: Expected,
    /// For `syntax`: what was found instead.
    found: lexer_mod.Tag,
    /// The offending word, cut to its first bytes: an unknown field's name, or the value that
    /// a value check refused.
    word: [constants.build_problem_word_bytes_max]u8,
    word_len: u8,

    fn set_word(problem: *Problem, word: []const u8) void {
        const length = @min(word.len, problem.word.len);
        @memcpy(problem.word[0..length], word[0..length]);
        problem.word_len = @intCast(length);
        assert(problem.word_len <= problem.word.len);
    }

    pub fn word_text(problem: *const Problem) []const u8 {
        assert(problem.word_len <= problem.word.len);
        return problem.word[0..problem.word_len];
    }
};

const Refused = error{Refused};

const Parser = struct {
    lexer: Lexer,
    file: *BuildFile,
    problem: *Problem,

    fn fail(
        parser: *Parser,
        kind: ProblemKind,
        at: anytype,
        level: Level,
        field: ?Field,
    ) Refused {
        assert(at.line >= 1);
        assert(at.column >= 1);
        parser.problem.* = .{
            .kind = kind,
            .line = at.line,
            .column = at.column,
            .level = level,
            .field = field,
            .expected = .end,
            .found = .end,
            .word = undefined,
            .word_len = 0,
        };
        @memset(&parser.problem.word, 0);
        return error.Refused;
    }

    fn syntax(parser: *Parser, token: Token, level: Level, expected: Expected) Refused {
        assert(token.line >= 1);
        const result = parser.fail(.syntax, token, level, null);
        parser.problem.expected = expected;
        parser.problem.found = token.tag;
        return result;
    }

    /// A refusal of a value, which the problem keeps (cut to its first bytes).
    fn fail_value(
        parser: *Parser,
        kind: ProblemKind,
        value: Text,
        level: Level,
        field: ?Field,
    ) Refused {
        const result = parser.fail(kind, value, level, field);
        parser.problem.set_word(parser.file.text(value));
        return result;
    }

    fn expect(parser: *Parser, tag: lexer_mod.Tag, level: Level, expected: Expected) !Token {
        const token = parser.lexer.next();
        if (token.tag != tag) return parser.syntax(token, level, expected);
        if (tag != .end) assert(token.end > token.start);
        return token;
    }
};

/// Walks the fields of one struct: `next` returns each field (after its `=`) or null at the
/// struct's `}`; it refuses a field twice and one the level does not take.
const Fields = struct {
    level: Level,
    after_value: bool = false,
    seen: u64 = 0,

    fn next(fields: *Fields, parser: *Parser) !?Field {
        comptime assert(@typeInfo(Field).@"enum".field_names.len <= 64);
        var token = parser.lexer.next();
        if (fields.after_value) {
            if (token.tag == .close) return null;
            if (token.tag != .comma) return parser.syntax(token, fields.level, .comma_or_close);
            token = parser.lexer.next();
        }
        if (token.tag == .close) return null;
        if (token.tag != .field) return parser.syntax(token, fields.level, .field_or_close);
        const name = parser.lexer.text[token.start + 1 .. token.end];
        const field = field_named(fields.level, name) orelse {
            const result = parser.fail(.unknown_field, token, fields.level, null);
            parser.problem.set_word(name);
            return result;
        };
        const bit = @as(u64, 1) << @intCast(@backingInt(field));
        if (fields.seen & bit != 0) {
            return parser.fail(.duplicate_field, token, fields.level, field);
        }
        fields.seen |= bit;
        fields.after_value = true;
        _ = try parser.expect(.equals, fields.level, .equals);
        return field;
    }

    fn has(fields: *const Fields, field: Field) bool {
        return fields.seen & (@as(u64, 1) << @intCast(@backingInt(field))) != 0;
    }
};

fn field_named(level: Level, name: []const u8) ?Field {
    assert(name.len > 0);
    for (level.allowed()) |field| {
        if (std.mem.eql(u8, @tagName(field), name)) return field;
    }
    return null;
}

/// Walks the items of one list after its `.{`: `next` returns each item's first token, or null
/// at the list's `}`.
const Items = struct {
    level: Level,
    after_item: bool = false,
    count: u32 = 0,

    fn next(items: *Items, parser: *Parser) !?Token {
        var token = parser.lexer.next();
        if (items.after_item) {
            if (token.tag == .close) return null;
            if (token.tag != .comma) return parser.syntax(token, items.level, .comma_or_close);
            token = parser.lexer.next();
        }
        if (token.tag == .close) return null;
        items.after_item = true;
        items.count += 1;
        // The end of the text is the one token with no bytes; the caller refuses it.
        if (token.tag != .end) assert(token.end > token.start);
        return token;
    }
};

pub const ParseResult = enum { parsed, refused };

/// Reads `text` into `file`. On a refusal `problem` says what and where, and `file` holds what
/// was read before it (never read it then).
pub fn parse(text: []const u8, file: *BuildFile, problem: *Problem) ParseResult {
    assert(text.len <= constants.build_render_bytes_max);
    clear(file);
    var parser: Parser = .{ .lexer = Lexer.init(text), .file = file, .problem = problem };
    parse_file(&parser) catch |err| {
        assert(err == error.Refused);
        assert(problem.line >= 1);
        return .refused;
    };
    assert(file.version == version);
    assert(file.steps_count <= constants.build_steps_max);
    return .parsed;
}

fn clear(file: *BuildFile) void {
    assert(file.pool.len == constants.build_pool_bytes);
    file.version = 0;
    file.steps_count = 0;
    file.pool_len = 0;
    file.image.base = null;
    file.image.adds_count = 0;
    file.image.line = 0;
    file.image.column = 0;
    file.exclude = Span.none;
    file.list_texts_count = 0;
    file.copies_count = 0;
    file.caches_count = 0;
    file.binds_count = 0;
    clear_config(&file.image.config);
}

fn clear_config(config: *Config) void {
    config.present = false;
    config.entrypoint.count = 0;
    config.entrypoint.given = false;
    config.cmd.count = 0;
    config.cmd.given = false;
    config.env.count = 0;
    config.env.given = false;
    config.workdir = null;
    config.user = null;
    config.labels_count = 0;
    config.labels_given = false;
}

fn parse_file(parser: *Parser) Refused!void {
    const open = try parser.expect(.open, .file, .open);
    var fields: Fields = .{ .level = .file };
    while (try fields.next(parser)) |field| {
        switch (field) {
            .version => try parse_version(parser),
            .steps => try parse_steps(parser),
            .image => try parse_image(parser),
            .exclude => try parse_exclude(parser, .file, &parser.file.exclude),
            else => unreachable, // `Fields.next` returns only the fields of the level.
        }
    }
    _ = try parser.expect(.end, .file, .end);
    if (!fields.has(.version)) return parser.fail(.missing_field, open, .file, .version);
    if (!fields.has(.image)) return parser.fail(.missing_field, open, .file, .image);
}

fn parse_version(parser: *Parser) Refused!void {
    const token = try parser.expect(.integer, .file, .integer);
    const digits = parser.lexer.text[token.start..token.end];
    if (digits.len > constants.build_version_digits_max) {
        return parser.fail(.bad_version, token, .file, .version);
    }
    // Parse accepts only what render writes, and render writes no leading zero.
    if (digits.len > 1) {
        if (digits[0] == '0') return parser.fail(.bad_version, token, .file, .version);
    }
    const value = std.fmt.parseInt(u32, digits, 10) catch unreachable; // Four digits at most.
    if (value == 0) return parser.fail(.bad_version, token, .file, .version);
    if (value > version) {
        const result = parser.fail(.newer_version, token, .file, .version);
        parser.problem.set_word(digits);
        return result;
    }
    parser.file.version = value;
}

fn parse_steps(parser: *Parser) Refused!void {
    _ = try parser.expect(.open, .file, .step_list);
    var items: Items = .{ .level = .step };
    while (try items.next(parser)) |token| {
        if (token.tag != .open) return parser.syntax(token, .step, .step_or_close);
        if (parser.file.steps_count == constants.build_steps_max) {
            return parser.fail(.list_too_long, token, .file, .steps);
        }
        const step = &parser.file.steps[parser.file.steps_count];
        try parse_step(parser, step, token);
        parser.file.steps_count += 1;
    }
    assert(parser.file.steps_count == items.count);
}

fn parse_step(parser: *Parser, step: *Step, open: Token) Refused!void {
    assert(open.tag == .open);
    step.line = open.line;
    step.column = open.column;
    step.network = false;
    step.inputs = .{ .items = undefined, .count = 0, .given = false };
    step.needs = .{ .items = undefined, .count = 0, .given = false };
    step.env = .{ .items = undefined, .count = 0, .given = false };
    step.run = .{ .items = undefined, .count = 0, .given = false };
    step.output = .out;
    step.user = null;
    step.workdir = null;
    step.copy = Span.none;
    step.caches = Span.none;
    step.binds = Span.none;
    step.exclude = Span.none;
    var fields: Fields = .{ .level = .step };
    while (try fields.next(parser)) |field| {
        switch (field) {
            .name => {
                step.name = try parse_string(parser, .step, field);
                try check_step_name(parser, step.name);
            },
            .base => step.base = try parse_base(parser, .step),
            .inputs => try parse_list(parser, .step, field, &step.inputs, .list_too_long),
            .needs => try parse_list(parser, .step, field, &step.needs, .too_many_needs),
            .env => {
                try parse_list(parser, .step, field, &step.env, .list_too_long);
                try check_env_list(parser, step.env.slice(), .bad_env, .step);
            },
            .run => {
                try parse_list(parser, .step, field, &step.run, .list_too_long);
                try check_run(parser, step);
            },
            .network => step.network = try parse_boolean(parser, .step),
            else => try parse_step_more(parser, step, field),
        }
    }
    const required = [_]Field{ .name, .base };
    for (required) |field| {
        if (!fields.has(field)) return parser.fail(.missing_field, open, .step, field);
    }
    if (fields.has(.run) == fields.has(.copy)) return parser.fail(.run_or_copy, open, .step, null);
    try check_mounts(parser, step, open);
}

/// The fields M9 added to a step.
fn parse_step_more(parser: *Parser, step: *Step, field: Field) Refused!void {
    switch (field) {
        .output => step.output = try parse_output(parser),
        .user => {
            const user = try parse_string(parser, .step, field);
            if (!is_user_text(parser.file.text(user))) {
                return parser.fail_value(.bad_user, user, .step, field);
            }
            step.user = user;
        },
        .workdir => {
            const workdir = try parse_string(parser, .step, field);
            if (!is_absolute_plain(parser.file.text(workdir))) {
                return parser.fail_value(.bad_path, workdir, .step, field);
            }
            step.workdir = workdir;
        },
        .copy => try parse_copies(parser, step),
        .caches => try parse_caches(parser, step),
        .binds => try parse_binds(parser, step),
        .exclude => try parse_exclude(parser, .step, &step.exclude),
        else => unreachable, // `Fields.next` returns only the fields of the level.
    }
}

/// `.output = .root` or `.out`: an enum literal, which the lexer reads as a field name.
fn parse_output(parser: *Parser) Refused!Output {
    const token = parser.lexer.next();
    if (token.tag != .field) return parser.syntax(token, .step, .output_value);
    const name = parser.lexer.text[token.start + 1 .. token.end];
    if (std.mem.eql(u8, name, "root")) return .root;
    if (std.mem.eql(u8, name, "out")) return .out;
    const result = parser.fail(.bad_output, token, .step, .output);
    parser.problem.set_word(name);
    return result;
}

/// `needs` and `binds` take a mount each, and `/src` and `/out` take two unless the step keeps
/// its root: all of them in the run's `mounts_max` (the brief leaves caches out of the count).
fn check_mounts(parser: *Parser, step: *const Step, open: Token) Refused!void {
    assert(step.needs.count <= constants.build_step_needs_max);
    assert(step.binds.count <= constants.build_step_binds_max);
    const fixed: u32 = if (step.output == .root) 0 else 2;
    const total = step.needs.count + step.binds.count + fixed;
    if (total > constants.mounts_max) return parser.fail(.too_many_mounts, open, .step, .binds);
}

/// A list of exclude lines (`.dockerignore` syntax), into the file's `list_texts`.
fn parse_exclude(parser: *Parser, level: Level, span: *Span) Refused!void {
    try parse_texts(parser, level, .exclude, span, constants.build_exclude_lines_max);
    for (parser.file.texts(span.*)) |line| {
        if (glob.line_fault(parser.file.text(line)) != null) {
            return parser.fail_value(.bad_pattern, line, level, .exclude);
        }
    }
}

/// A list of strings appended to the file's `list_texts`, at most `max` of them.
fn parse_texts(
    parser: *Parser,
    level: Level,
    field: Field,
    span: *Span,
    max: u32,
) Refused!void {
    _ = try parser.expect(.open, level, .string_list);
    const file = parser.file;
    span.* = .{ .begin = file.list_texts_count, .count = 0, .given = true };
    var items: Items = .{ .level = level };
    while (try items.next(parser)) |token| {
        if (token.tag != .string) return parser.syntax(token, level, .string_or_close);
        if (span.count == max) return parser.fail(.list_too_long, token, level, field);
        if (file.list_texts_count == constants.build_file_list_texts_max) {
            return parser.fail(.file_too_big, token, level, field);
        }
        file.list_texts[file.list_texts_count] = try decode(parser, token, level, field);
        file.list_texts_count += 1;
        span.count += 1;
    }
    assert(span.count == items.count);
}

fn parse_copies(parser: *Parser, step: *Step) Refused!void {
    _ = try parser.expect(.open, .step, .copy_list);
    const file = parser.file;
    step.copy = .{ .begin = file.copies_count, .count = 0, .given = true };
    var items: Items = .{ .level = .copy };
    while (try items.next(parser)) |open| {
        if (open.tag != .open) return parser.syntax(open, .copy, .copy_or_close);
        if (step.copy.count == constants.build_copy_entries_max) {
            return parser.fail(.list_too_long, open, .step, .copy);
        }
        if (file.copies_count == constants.build_file_copies_max) {
            return parser.fail(.file_too_big, open, .step, .copy);
        }
        try parse_copy(parser, &file.copies[file.copies_count], open);
        file.copies_count += 1;
        step.copy.count += 1;
    }
}

fn parse_copy(parser: *Parser, entry: *CopyEntry, open: Token) Refused!void {
    entry.* = .{
        .from = null,
        .src = Span.none,
        .to = undefined,
        .chown = null,
        .chmod = null,
        .exclude = Span.none,
        .line = open.line,
        .column = open.column,
    };
    var fields: Fields = .{ .level = .copy };
    while (try fields.next(parser)) |field| {
        switch (field) {
            .from => entry.from = try parse_from(parser, .copy),
            .src => try parse_texts(parser, .copy, field, &entry.src, constants.build_copy_sources_max),
            .to => {
                entry.to = try parse_string(parser, .copy, field);
                if (!is_copy_to(parser.file.text(entry.to))) {
                    return parser.fail_value(.bad_copy_to, entry.to, .copy, field);
                }
            },
            .chown => {
                const user = try parse_string(parser, .copy, field);
                if (!is_user_text(parser.file.text(user))) {
                    return parser.fail_value(.bad_user, user, .copy, field);
                }
                entry.chown = user;
            },
            .chmod => entry.chmod = try parse_mode(parser, .copy, field),
            .exclude => try parse_exclude(parser, .copy, &entry.exclude),
            else => unreachable, // `Fields.next` returns only the fields of the level.
        }
    }
    if (!fields.has(.src)) return parser.fail(.missing_field, open, .copy, .src);
    if (!fields.has(.to)) return parser.fail(.missing_field, open, .copy, .to);
    try check_sources(parser, entry);
}

/// Each `.src` entry is a pattern with no `..` part, and rooted (`/`) only for a tree.
fn check_sources(parser: *Parser, entry: *const CopyEntry) Refused!void {
    assert(entry.src.given);
    for (parser.file.texts(entry.src)) |source| {
        const text = parser.file.text(source);
        const rooted = text.len > 0 and text[0] == '/';
        const bad = glob.valid(text) != null or has_parent_part(text) or
            (rooted and entry.from == null);
        if (bad) return parser.fail_value(.bad_pattern, source, .copy, .src);
    }
}

fn parse_caches(parser: *Parser, step: *Step) Refused!void {
    _ = try parser.expect(.open, .step, .cache_list);
    const file = parser.file;
    step.caches = .{ .begin = file.caches_count, .count = 0, .given = true };
    var items: Items = .{ .level = .cache };
    while (try items.next(parser)) |open| {
        if (open.tag != .open) return parser.syntax(open, .cache, .cache_or_close);
        if (step.caches.count == constants.build_step_caches_max) {
            return parser.fail(.list_too_long, open, .step, .caches);
        }
        if (file.caches_count == constants.build_file_caches_max) {
            return parser.fail(.file_too_big, open, .step, .caches);
        }
        try parse_cache(parser, &file.caches[file.caches_count], open);
        file.caches_count += 1;
        step.caches.count += 1;
    }
    try check_mount_paths(parser, step);
}

fn parse_cache(parser: *Parser, entry: *Cache, open: Token) Refused!void {
    entry.* = .{
        .id = undefined,
        .path = undefined,
        .ro = false,
        .mode = null,
        .uid = null,
        .gid = null,
        .line = open.line,
        .column = open.column,
    };
    var fields: Fields = .{ .level = .cache };
    while (try fields.next(parser)) |field| {
        switch (field) {
            .id => {
                entry.id = try parse_string(parser, .cache, field);
                if (!is_cache_id(parser.file.text(entry.id))) {
                    return parser.fail_value(.bad_cache_id, entry.id, .cache, field);
                }
            },
            .path => {
                entry.path = try parse_string(parser, .cache, field);
                if (!is_absolute_plain(parser.file.text(entry.path))) {
                    return parser.fail_value(.bad_path, entry.path, .cache, field);
                }
            },
            .ro => entry.ro = try parse_boolean(parser, .cache),
            .mode => entry.mode = try parse_mode(parser, .cache, field),
            .uid => entry.uid = try parse_number(parser, .cache, field),
            .gid => entry.gid = try parse_number(parser, .cache, field),
            else => unreachable, // `Fields.next` returns only the fields of the level.
        }
    }
    if (!fields.has(.id)) return parser.fail(.missing_field, open, .cache, .id);
    if (!fields.has(.path)) return parser.fail(.missing_field, open, .cache, .path);
}

fn parse_binds(parser: *Parser, step: *Step) Refused!void {
    _ = try parser.expect(.open, .step, .bind_list);
    const file = parser.file;
    step.binds = .{ .begin = file.binds_count, .count = 0, .given = true };
    var items: Items = .{ .level = .bind };
    while (try items.next(parser)) |open| {
        if (open.tag != .open) return parser.syntax(open, .bind, .bind_or_close);
        if (step.binds.count == constants.build_step_binds_max) {
            return parser.fail(.list_too_long, open, .step, .binds);
        }
        if (file.binds_count == constants.build_file_binds_max) {
            return parser.fail(.file_too_big, open, .step, .binds);
        }
        try parse_bind(parser, &file.binds[file.binds_count], open);
        file.binds_count += 1;
        step.binds.count += 1;
    }
    try check_mount_paths(parser, step);
}

fn parse_bind(parser: *Parser, entry: *Bind, open: Token) Refused!void {
    entry.* = .{ .from = null, .source = undefined, .to = undefined, .line = open.line, .column = open.column };
    var fields: Fields = .{ .level = .bind };
    while (try fields.next(parser)) |field| {
        switch (field) {
            .from => entry.from = try parse_from(parser, .bind),
            .source => entry.source = try parse_string(parser, .bind, field),
            .to => {
                entry.to = try parse_string(parser, .bind, field);
                if (!is_absolute_plain(parser.file.text(entry.to))) {
                    return parser.fail_value(.bad_path, entry.to, .bind, field);
                }
            },
            else => unreachable, // `Fields.next` returns only the fields of the level.
        }
    }
    if (!fields.has(.source)) return parser.fail(.missing_field, open, .bind, .source);
    if (!fields.has(.to)) return parser.fail(.missing_field, open, .bind, .to);
    const source = parser.file.text(entry.source);
    const rooted = source.len > 0 and source[0] == '/';
    // From a tree a source is absolute inside it; from the project it is relative.
    const good = if (entry.from == null)
        is_project_path(source)
    else
        rooted and is_absolute_plain(source);
    if (!good) return parser.fail_value(.bad_source, entry.source, .bind, .source);
}

/// A step mounts each path once, caches and binds together.
fn check_mount_paths(parser: *Parser, step: *const Step) Refused!void {
    const file = parser.file;
    const caches = file.step_caches(step);
    const binds = file.step_binds(step);
    for (caches, 0..) |cache, index| {
        const text = file.text(cache.path);
        for (caches[0..index]) |earlier| {
            if (std.mem.eql(u8, file.text(earlier.path), text)) {
                return parser.fail_value(.mount_twice, cache.path, .cache, .path);
            }
        }
        for (binds) |bind| {
            if (std.mem.eql(u8, file.text(bind.to), text)) {
                return parser.fail_value(.mount_twice, cache.path, .cache, .path);
            }
        }
    }
    for (binds, 0..) |bind, index| {
        const text = file.text(bind.to);
        for (binds[0..index]) |earlier| {
            if (std.mem.eql(u8, file.text(earlier.to), text)) {
                return parser.fail_value(.mount_twice, bind.to, .bind, .to);
            }
        }
    }
}

/// A `.from`: `step:<name>` or a locked image reference.
fn parse_from(parser: *Parser, level: Level) Refused!Text {
    const value = try parse_string(parser, level, .from);
    return check_image_or_step(parser, value, .bad_from, level, .from);
}

/// An octal mode of three or four digits, as text.
fn parse_mode(parser: *Parser, level: Level, field: Field) Refused!Text {
    const value = try parse_string(parser, level, field);
    if (!is_mode(parser.file.text(value))) return parser.fail_value(.bad_mode, value, level, field);
    return value;
}

fn parse_number(parser: *Parser, level: Level, field: Field) Refused!u32 {
    const token = try parser.expect(.integer, level, .integer);
    const digits = parser.lexer.text[token.start..token.end];
    const bad = digits.len > 10 or (digits.len > 1 and digits[0] == '0');
    const value = if (bad) null else std.fmt.parseInt(u32, digits, 10) catch null;
    if (value) |number| return number;
    const result = parser.fail(.bad_number, token, level, field);
    parser.problem.set_word(digits);
    return result;
}

fn parse_image(parser: *Parser) Refused!void {
    const open = try parser.expect(.open, .image, .open);
    const image = &parser.file.image;
    image.line = open.line;
    image.column = open.column;
    var fields: Fields = .{ .level = .image };
    while (try fields.next(parser)) |field| {
        switch (field) {
            .base => image.base = try parse_base(parser, .image),
            .add => try parse_adds(parser),
            .config => try parse_config(parser),
            else => unreachable, // `Fields.next` returns only the fields of the level.
        }
    }
}

fn parse_adds(parser: *Parser) Refused!void {
    _ = try parser.expect(.open, .image, .add_list);
    const image = &parser.file.image;
    var items: Items = .{ .level = .add };
    while (try items.next(parser)) |open| {
        if (open.tag != .open) return parser.syntax(open, .add, .add_or_close);
        if (image.adds_count == constants.build_image_adds_max) {
            return parser.fail(.list_too_long, open, .image, .add);
        }
        const add = &image.adds[image.adds_count];
        add.line = open.line;
        add.column = open.column;
        var fields: Fields = .{ .level = .add };
        while (try fields.next(parser)) |field| {
            switch (field) {
                .from => add.from = try parse_string(parser, .add, field),
                .to => {
                    add.to = try parse_string(parser, .add, field);
                    if (!is_absolute_plain(parser.file.text(add.to))) {
                        return parser.fail_value(.bad_target, add.to, .add, .to);
                    }
                },
                else => unreachable, // `Fields.next` returns only the fields of the level.
            }
        }
        if (!fields.has(.from)) return parser.fail(.missing_field, open, .add, .from);
        if (!fields.has(.to)) return parser.fail(.missing_field, open, .add, .to);
        image.adds_count += 1;
    }
}

fn parse_config(parser: *Parser) Refused!void {
    _ = try parser.expect(.open, .config, .open);
    const config = &parser.file.image.config;
    config.present = true;
    var fields: Fields = .{ .level = .config };
    while (try fields.next(parser)) |field| {
        switch (field) {
            .entrypoint => {
                try parse_list(parser, .config, field, &config.entrypoint, .list_too_long);
            },
            .cmd => try parse_list(parser, .config, field, &config.cmd, .list_too_long),
            .env => {
                try parse_list(parser, .config, field, &config.env, .list_too_long);
                try check_env_list(parser, config.env.slice(), .config_env, .config);
            },
            .workdir => {
                const workdir = try parse_string(parser, .config, field);
                if (!is_absolute_plain(parser.file.text(workdir))) {
                    return parser.fail_value(.config_workdir, workdir, .config, .workdir);
                }
                config.workdir = workdir;
            },
            .user => {
                const user = try parse_string(parser, .config, field);
                if (!is_user_text(parser.file.text(user))) {
                    return parser.fail_value(.config_user, user, .config, .user);
                }
                config.user = user;
            },
            .labels => try parse_labels(parser, config),
            else => unreachable, // `Fields.next` returns only the fields of the level.
        }
    }
}

fn parse_labels(parser: *Parser, config: *Config) Refused!void {
    _ = try parser.expect(.open, .config, .label_list);
    config.labels_given = true;
    var items: Items = .{ .level = .label };
    while (try items.next(parser)) |open| {
        if (open.tag != .open) return parser.syntax(open, .label, .label_or_close);
        if (config.labels_count == constants.build_config_labels_max) {
            return parser.fail(.list_too_long, open, .config, .labels);
        }
        const key = try parse_string(parser, .label, .labels);
        _ = try parser.expect(.comma, .label, .comma);
        const value = try parse_string(parser, .label, .labels);
        var token = parser.lexer.next();
        if (token.tag == .comma) token = parser.lexer.next();
        if (token.tag != .close) return parser.syntax(token, .label, .close);
        const key_text = parser.file.text(key);
        if (!is_label_key(key_text)) {
            return parser.fail_value(.config_label_key, key, .config, .labels);
        }
        for (config.labels[0..config.labels_count]) |*other| {
            if (std.mem.eql(u8, parser.file.text(other.key), key_text)) {
                return parser.fail_value(.config_label_twice, key, .config, .labels);
            }
        }
        config.labels[config.labels_count] = .{ .key = key, .value = value };
        config.labels_count += 1;
    }
}

/// A list of strings: `.{ "a", "b" }`, possibly empty, a trailing comma allowed.
fn parse_list(
    parser: *Parser,
    level: Level,
    field: Field,
    list: anytype,
    too_long: ProblemKind,
) Refused!void {
    const List_ = @TypeOf(list.*);
    _ = try parser.expect(.open, level, .string_list);
    list.given = true;
    list.count = 0;
    var items: Items = .{ .level = level };
    while (try items.next(parser)) |token| {
        if (token.tag != .string) return parser.syntax(token, level, .string_or_close);
        if (list.count == List_.max) return parser.fail(too_long, token, level, field);
        list.items[list.count] = try decode(parser, token, level, field);
        list.count += 1;
    }
    assert(list.count == items.count);
}

fn parse_string(parser: *Parser, level: Level, field: Field) Refused!Text {
    const token = try parser.expect(.string, level, .string);
    return decode(parser, token, level, field);
}

fn parse_boolean(parser: *Parser, level: Level) Refused!bool {
    const token = parser.lexer.next();
    if (token.tag == .true_word) return true;
    if (token.tag == .false_word) return false;
    return parser.syntax(token, level, .boolean);
}

/// A `.base`: an image reference, or `step:<name>` (a step's root output).
fn parse_base(parser: *Parser, level: Level) Refused!Text {
    const value = try parse_string(parser, level, .base);
    return check_image_or_step(parser, value, .bad_reference, level, .base);
}

/// `value` is `step:<valid name>` or an image reference; else `kind` refuses it.
fn check_image_or_step(
    parser: *Parser,
    value: Text,
    kind: ProblemKind,
    level: Level,
    field: Field,
) Refused!Text {
    const text = parser.file.text(value);
    if (step_ref(text)) |name| {
        if (is_step_name(name)) return value;
        return parser.fail_value(kind, value, level, field);
    }
    var reference: reference_mod.Reference = undefined;
    if (text.len == 0) return parser.fail_value(kind, value, level, field);
    if (text.len > constants.reference_bytes_max) {
        return parser.fail_value(kind, value, level, field);
    }
    reference_mod.parse(text, &reference) catch {
        return parser.fail_value(kind, value, level, field);
    };
    return value;
}

/// Decodes a string token's escapes into the pool. The pool is filled byte by byte, so a
/// string is never longer in the pool than in the text.
fn decode(parser: *Parser, token: Token, level: Level, field: Field) Refused!Text {
    assert(token.tag == .string);
    const file = parser.file;
    const raw = parser.lexer.text[token.start + 1 .. token.end - 1];
    const at = file.pool_len;
    var index: usize = 0;
    while (index < raw.len) {
        var byte = raw[index];
        index += 1;
        if (byte == '\\') {
            const escape = escape_at(raw, &index) orelse {
                return parser.fail(.bad_escape, token, level, field);
            };
            byte = escape;
            if (byte == 0) return parser.fail(.nul_byte, token, level, field);
        } else if (is_control(byte)) {
            return parser.fail(.bad_string, token, level, field);
        } else if (byte >= 0x80) {
            // A raw byte over 127 starts a UTF-8 sequence, copied whole once it is checked.
            const length = utf8_length(raw[index - 1 ..]) orelse {
                return parser.fail(.bad_string, token, level, field);
            };
            if (file.pool_len - at + length > constants.build_string_bytes_max) {
                return parser.fail(.string_too_long, token, level, field);
            }
            if (file.pool_len + length > file.pool.len) {
                return parser.fail(.text_too_long, token, level, field);
            }
            @memcpy(file.pool[file.pool_len..][0..length], raw[index - 1 ..][0..length]);
            file.pool_len += length;
            index += length - 1;
            continue;
        }
        if (file.pool_len - at == constants.build_string_bytes_max) {
            return parser.fail(.string_too_long, token, level, field);
        }
        if (file.pool_len == file.pool.len) return parser.fail(.text_too_long, token, level, field);
        file.pool[file.pool_len] = byte;
        file.pool_len += 1;
    }
    assert(file.pool_len - at <= constants.build_string_bytes_max);
    // Escapes can make bytes that are not UTF-8 (`\xff`) or control bytes (`\n`): check what
    // the string decoded to, not only how it was written.
    const decoded = file.pool[at..file.pool_len];
    if (!std.unicode.utf8ValidateSlice(decoded)) {
        return parser.fail(.bad_string, token, level, field);
    }
    if (!takes_control_bytes(level, field)) {
        for (decoded) |byte| {
            if (is_control(byte)) return parser.fail(.bad_string, token, level, field);
        }
    }
    return .{ .at = at, .len = file.pool_len - at, .line = token.line, .column = token.column };
}

/// Whether a string of `field` may hold control bytes: an argument (a `sh -c` script has line
/// ends) and an env entry's value may; a name, a reference, a path or a label may not. An env
/// entry's key is held to `[A-Za-z_][A-Za-z0-9_]*` by `check_env`.
pub fn takes_control_bytes(level: Level, field: Field) bool {
    assert(@tagName(level).len > 0);
    return switch (level) {
        .step => field == .run or field == .env,
        .config => field == .entrypoint or field == .cmd or field == .env,
        .file, .image, .add, .label, .copy, .cache, .bind => false,
    };
}

pub fn is_control(byte: u8) bool {
    return byte < 0x20 or byte == 0x7f;
}

/// The byte an escape stands for, `index` just past the `\`; null if it is not one.
fn escape_at(raw: []const u8, index: *usize) ?u8 {
    assert(index.* > 0);
    assert(raw[index.* - 1] == '\\');
    if (index.* == raw.len) return null;
    const letter = raw[index.*];
    index.* += 1;
    switch (letter) {
        'n' => return '\n',
        'r' => return '\r',
        't' => return '\t',
        '\\', '\'', '"' => return letter,
        'x' => {
            if (index.* + 2 > raw.len) return null;
            const high = raw[index.*];
            const low = raw[index.* + 1];
            // `parseInt` would take `+f` and `-0`; an escape is exactly two hex digits.
            if (!std.ascii.isHex(high)) return null;
            if (!std.ascii.isHex(low)) return null;
            index.* += 2;
            const value = 16 * hex_value(high) + hex_value(low);
            return @intCast(value);
        },
        else => return null,
    }
}

fn hex_value(digit: u8) u8 {
    assert(std.ascii.isHex(digit));
    const value = std.fmt.charToDigit(digit, 16) catch unreachable; // A hex digit, just checked.
    assert(value < 16);
    return value;
}

/// The length of the valid UTF-8 sequence at the start of `bytes`, or null.
pub fn utf8_length(bytes: []const u8) ?u3 {
    assert(bytes.len > 0);
    const length = std.unicode.utf8ByteSequenceLength(bytes[0]) catch return null;
    if (length > bytes.len) return null;
    _ = std.unicode.utf8Decode(bytes[0..length]) catch return null;
    assert(length >= 1);
    return length;
}

fn check_step_name(parser: *Parser, name: Text) Refused!void {
    const text = parser.file.text(name);
    if (text.len == 0) return parser.fail_value(.bad_step_name, name, .step, .name);
    if (text.len > constants.build_step_name_bytes_max) {
        return parser.fail_value(.bad_step_name, name, .step, .name);
    }
    for (text) |byte| {
        const good = (byte >= 'a' and byte <= 'z') or (byte >= '0' and byte <= '9') or
            byte == '-';
        if (!good) return parser.fail_value(.bad_step_name, name, .step, .name);
    }
    if (std.mem.eql(u8, text, "image")) {
        return parser.fail_value(.reserved_step_name, name, .step, .name);
    }
}

/// The variables every step is given after the build file's, which a step's `.env` cannot set
/// (docs/briefs/M7-build.md, "A fixed environment").
pub const fixed_env = [_][]const u8{
    "HOME", "TZ", "LC_ALL", "TERM", "SOURCE_DATE_EPOCH", "ZBX_BUILD_STEP",
};

/// An env list: each entry `KEY=VALUE` with a plain key, no key twice, and in a step no key of
/// the fixed environment (it would be overridden, and a silent override is a surprise).
fn check_env_list(
    parser: *Parser,
    entries: []const Text,
    kind: ProblemKind,
    level: Level,
) Refused!void {
    assert(entries.len <= constants.build_config_env_max);
    assert(switch (level) {
        .step, .config => true,
        .file, .image, .add, .label, .copy, .cache, .bind => false,
    });
    for (entries, 0..) |entry, index| {
        const key = env_key(parser.file.text(entry)) orelse {
            return parser.fail_value(kind, entry, level, .env);
        };
        for (entries[0..index]) |earlier| {
            const earlier_key = env_key(parser.file.text(earlier)).?;
            if (std.mem.eql(u8, earlier_key, key)) {
                return fail_key(parser, .env_twice, entry, key, level);
            }
        }
        if (level == .step) {
            if (is_fixed_env(key)) return fail_key(parser, .env_fixed, entry, key, level);
        }
    }
}

/// A refusal naming an env entry's key, which is all of it the message needs.
fn fail_key(
    parser: *Parser,
    kind: ProblemKind,
    entry: Text,
    key: []const u8,
    level: Level,
) Refused {
    assert(key.len > 0);
    const result = parser.fail(kind, entry, level, .env);
    parser.problem.set_word(key);
    return result;
}

/// The key of `KEY=VALUE`, or null if the entry has no `=` or its key is not
/// `[A-Za-z_][A-Za-z0-9_]*` (what a shell can name).
pub fn env_key(entry: []const u8) ?[]const u8 {
    const equals = std.mem.indexOfScalar(u8, entry, '=') orelse return null;
    const key = entry[0..equals];
    if (key.len == 0) return null;
    if (std.ascii.isDigit(key[0])) return null;
    for (key) |byte| {
        if (byte != '_') {
            if (!std.ascii.isAlphanumeric(byte)) return null;
        }
    }
    assert(key.len < entry.len);
    return key;
}

pub fn is_fixed_env(key: []const u8) bool {
    assert(key.len > 0);
    for (fixed_env) |name| {
        if (std.mem.eql(u8, name, key)) return true;
    }
    return false;
}

fn check_run(parser: *Parser, step: *const Step) Refused!void {
    assert(step.run.given);
    if (step.run.count == 0) {
        // Point at the list itself: the position after the last string read is not known, so
        // the step's `.{` it is.
        return parser.fail(.empty_run, step.*, .step, .run);
    }
    const first = step.run.items[0];
    if (first.len == 0) return parser.fail(.empty_run, first, .step, .run);
}

/// An absolute path written plainly: `/`, or `/a/b` with no empty, `.` or `..` part and no
/// trailing slash.
pub fn is_absolute_plain(text: []const u8) bool {
    if (text.len == 0) return false;
    if (text[0] != '/') return false;
    if (text.len == 1) return true;
    var parts = std.mem.splitScalar(u8, text[1..], '/');
    while (parts.next()) |part| {
        if (part.len == 0) return false;
        if (std.mem.eql(u8, part, ".")) return false;
        if (std.mem.eql(u8, part, "..")) return false;
    }
    return true;
}

/// A user for `.user`, `.chown` and `config.user`: `uid`, `uid:gid`, `name` or `name:group`. A
/// part of digits is a number that fits 32 bits; anything else is a name of `[A-Za-z0-9_.-]`,
/// not starting with `-`, at most 32 bytes. Names are looked up in a tree later.
pub fn is_user_text(text: []const u8) bool {
    if (text.len == 0) return false;
    var parts = std.mem.splitScalar(u8, text, ':');
    var count: u32 = 0;
    while (parts.next()) |part| {
        count += 1;
        if (count > 2) return false;
        if (!is_user_part(part)) return false;
    }
    assert(count >= 1);
    return true;
}

fn is_user_part(part: []const u8) bool {
    if (part.len == 0) return false;
    if (part.len > 32) return false;
    if (part[0] == '-') return false;
    var digits = true;
    for (part) |byte| {
        const good = std.ascii.isAlphanumeric(byte) or byte == '_' or byte == '.' or byte == '-';
        if (!good) return false;
        if (!std.ascii.isDigit(byte)) digits = false;
    }
    if (!digits) return true;
    _ = std.fmt.parseInt(u32, part, 10) catch return false;
    return true;
}

/// A copy's destination: an absolute path written plainly, which may end in one `/`.
pub fn is_copy_to(text: []const u8) bool {
    if (text.len == 0) return false;
    if (text.len == 1) return text[0] == '/';
    if (text[text.len - 1] == '/') return is_absolute_plain(text[0 .. text.len - 1]);
    return is_absolute_plain(text);
}

/// An octal mode: three or four digits of 0 to 7.
pub fn is_mode(text: []const u8) bool {
    if (text.len < 3 or text.len > 4) return false;
    for (text) |byte| {
        if (byte < '0' or byte > '7') return false;
    }
    return true;
}

/// A cache id: `[A-Za-z0-9._/-]`, not empty, at most `build_label_key_bytes_max` bytes.
pub fn is_cache_id(text: []const u8) bool {
    if (text.len == 0) return false;
    if (text.len > constants.build_label_key_bytes_max) return false;
    for (text) |byte| {
        const good = std.ascii.isAlphanumeric(byte) or byte == '.' or byte == '_' or
            byte == '/' or byte == '-';
        if (!good) return false;
    }
    return true;
}

/// The name of `step:<name>`, or null if `text` is not written that way (it may be an image).
pub fn step_ref(text: []const u8) ?[]const u8 {
    const prefix = "step:";
    if (!std.mem.startsWith(u8, text, prefix)) return null;
    return text[prefix.len..];
}

/// A step name: 1 to `build_step_name_bytes_max` of `[a-z0-9-]`, and not `image`.
pub fn is_step_name(text: []const u8) bool {
    if (text.len == 0) return false;
    if (text.len > constants.build_step_name_bytes_max) return false;
    for (text) |byte| {
        const good = (byte >= 'a' and byte <= 'z') or (byte >= '0' and byte <= '9') or byte == '-';
        if (!good) return false;
    }
    return !std.mem.eql(u8, text, "image");
}

/// A path in the project: relative, written plainly (`.` alone is the project's root).
pub fn is_project_path(text: []const u8) bool {
    if (text.len == 0) return false;
    if (text[0] == '/') return false;
    if (std.mem.eql(u8, text, ".")) return true;
    return !has_parent_part(text) and !has_dot_or_empty_part(text);
}

fn has_dot_or_empty_part(text: []const u8) bool {
    var parts = std.mem.splitScalar(u8, text, '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".")) return true;
    }
    return false;
}

/// Whether some part of `text` is `..`.
pub fn has_parent_part(text: []const u8) bool {
    var parts = std.mem.splitScalar(u8, text, '/');
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, "..")) return true;
    }
    return false;
}

/// `uid:gid`, both decimal and within 32 bits.
pub fn is_numeric_user(text: []const u8) bool {
    const colon = std.mem.indexOfScalar(u8, text, ':') orelse return false;
    const ids = [_][]const u8{ text[0..colon], text[colon + 1 ..] };
    for (ids) |id| {
        if (id.len == 0) return false;
        if (id.len > 10) return false;
        for (id) |byte| {
            if (!std.ascii.isDigit(byte)) return false;
        }
        _ = std.fmt.parseInt(u32, id, 10) catch return false;
    }
    return true;
}

/// A label key: `[a-z0-9._/-]`, not empty, at most `build_label_key_bytes_max` bytes.
pub fn is_label_key(text: []const u8) bool {
    if (text.len == 0) return false;
    if (text.len > constants.build_label_key_bytes_max) return false;
    for (text) |byte| {
        const good = (byte >= 'a' and byte <= 'z') or (byte >= '0' and byte <= '9') or
            byte == '.' or byte == '_' or byte == '/' or byte == '-';
        if (!good) return false;
    }
    return true;
}
