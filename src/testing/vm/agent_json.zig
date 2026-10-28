//! What the scripted agent of the M4 demo (agent_m4.zig) reads: zbx's JSON and nothing else.
//! The agent drives the demo with `--output json`, `zbx schema <command>`, `zbx explain` and
//! `zbx lock show`, all as JSON; this
//! file holds its pure parts, each unit-tested with right and wrong input: a checker for the
//! subset of JSON Schema that zbx's schemas use, the diagnostics zbx prints as JSON lines on
//! stderr, the `container_exit` line of a run, and the rewrite of a fix's command.
//!
//! The rule of the agent test: what the agent needs and cannot read from these is a finding, not
//! something to guess (docs/demos/m4.md, "The agent test").

const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const checks = @import("checks.zig");

const Streams = checks.Streams;

pub const Error = error{
    /// The text is not JSON, or not the JSON the step expects.
    JsonWrong,
    ExitCodeWrong,
    /// A schema or a document nests deeper than the checker's stack.
    TooDeep,
    /// The document breaks its schema.
    SchemaViolated,
    /// No diagnostic, or not the one the step expects.
    DiagnosticWrong,
    /// The `container_exit` line is missing or says another thing.
    ExitLineWrong,
    /// A fix has no command to run, or one that is not a `zbx` command.
    FixWrong,
    /// `zbx explain --output json` printed something other than the code's entry.
    ExplainWrong,
    /// `zbx lock show` or the `ran` of a run says something other than what happened.
    LockWrong,
    OutOfMemory,
};

fn parse_value(arena: Allocator, text: []const u8) Error!Value {
    // Copies: the text is the session's scratch buffer, which the next command overwrites.
    const options: std.json.ParseOptions = .{ .allocate = .alloc_always };
    return std.json.parseFromSliceLeaky(Value, arena, text, options) catch return error.JsonWrong;
}

// ---- A checker for the schemas zbx prints -------------------------------------------------

/// The deepest schema/document pair the checker follows. The schemas zbx prints nest four or five
/// levels; the bound exists so that a hostile document cannot make it loop.
pub const depth_max: u32 = 32;
const work_max: u32 = 4096;

const Work = struct { schema: Value, document: Value, depth: u32 };

fn type_matches(name: []const u8, document: Value) bool {
    if (std.mem.eql(u8, name, "object")) return document == .object;
    if (std.mem.eql(u8, name, "array")) return document == .array;
    if (std.mem.eql(u8, name, "string")) return document == .string;
    if (std.mem.eql(u8, name, "boolean")) return document == .bool;
    if (std.mem.eql(u8, name, "null")) return document == .null;
    if (std.mem.eql(u8, name, "integer")) return document == .integer;
    if (std.mem.eql(u8, name, "number")) return document == .integer or document == .float;
    return false;
}

fn same_scalar(left: Value, right: Value) bool {
    if (left == .string and right == .string) return std.mem.eql(u8, left.string, right.string);
    if (left == .bool and right == .bool) return left.bool == right.bool;
    if (left == .integer and right == .integer) return left.integer == right.integer;
    return left == .null and right == .null;
}

fn has_all_required(required: Value, document: Value) bool {
    if (required != .array) return true;
    if (document != .object) return false;
    for (required.array.items) |name| {
        if (name != .string) return false;
        if (document.object.get(name.string) == null) return false;
    }
    return true;
}

/// Checks `schema` against one document node: `type`, `const`, `enum`, `required`, and
/// `oneOf` whose alternatives are `required` lists. Returns a reason, or null if it holds. The
/// children (`properties`, `items`) are pushed on `stack` for the caller's loop.
fn check_node(
    arena: Allocator,
    work: Work,
    stack: *std.ArrayList(Work),
) Error!?[]const u8 {
    if (work.schema != .object) return null;
    const schema = work.schema.object;
    if (schema.get("type")) |kind| {
        var good = false;
        if (kind == .string) good = type_matches(kind.string, work.document);
        if (kind == .array) {
            for (kind.array.items) |each| {
                if (each == .string and type_matches(each.string, work.document)) good = true;
            }
        }
        if (!good) return try std.fmt.allocPrint(arena, "a value of the wrong type", .{});
    }
    if (schema.get("const")) |wanted| {
        if (!same_scalar(wanted, work.document)) {
            return try std.fmt.allocPrint(arena, "a value that is not the constant", .{});
        }
    }
    if (schema.get("enum")) |options| {
        var found = false;
        if (options == .array) {
            for (options.array.items) |option| found = found or same_scalar(option, work.document);
        }
        if (!found) return try std.fmt.allocPrint(arena, "a value that is not in its enum", .{});
    }
    if (schema.get("required")) |required| {
        // As in JSON Schema, `required` constrains objects only; `type` says what else is allowed.
        if (work.document == .object) {
            for (required.array.items) |name| {
                if (work.document.object.get(name.string) == null) {
                    const format = "the member '{s}' is missing";
                    return try std.fmt.allocPrint(arena, format, .{name.string});
                }
            }
        }
    }
    if (schema.get("oneOf")) |alternatives| {
        var matching: u32 = 0;
        for (alternatives.array.items) |alternative| {
            const required = alternative.object.get("required") orelse continue;
            if (has_all_required(required, work.document)) matching += 1;
        }
        if (matching != 1) return try std.fmt.allocPrint(arena, "{d} oneOf matches", .{matching});
    }
    try push_children(work, stack, arena);
    return null;
}

fn push_children(work: Work, stack: *std.ArrayList(Work), arena: Allocator) Error!void {
    const schema = work.schema.object;
    if (work.depth >= depth_max) return error.TooDeep;
    if (schema.get("properties")) |properties| {
        if (work.document == .object and properties == .object) {
            var iterator = properties.object.iterator();
            while (iterator.next()) |entry| {
                const child = work.document.object.get(entry.key_ptr.*) orelse continue;
                const item: Work = .{
                    .schema = entry.value_ptr.*,
                    .document = child,
                    .depth = work.depth + 1,
                };
                stack.append(arena, item) catch return error.OutOfMemory;
            }
        }
    }
    if (schema.get("items")) |items| {
        if (work.document == .array) {
            for (work.document.array.items) |element| {
                const item: Work = .{
                    .schema = items,
                    .document = element,
                    .depth = work.depth + 1,
                };
                stack.append(arena, item) catch return error.OutOfMemory;
            }
        }
    }
    if (stack.items.len > work_max) return error.TooDeep;
}

/// Checks `document_text` against `schema_text` (the output of `zbx schema <command>`). Returns
/// null if it conforms, or a reason. `pattern`, `minimum` and `$ref` are not checked: the agent
/// checks the shapes of the digests it uses itself. No recursion: an explicit stack of
/// pairs, bounded by `depth_max` and `work_max`.
pub fn violation(
    arena: Allocator,
    schema_text: []const u8,
    document_text: []const u8,
) Error!?[]const u8 {
    const schema = try parse_value(arena, schema_text);
    const document = try parse_value(arena, document_text);
    var stack: std.ArrayList(Work) = .empty;
    try stack.append(arena, .{ .schema = schema, .document = document, .depth = 0 });
    var steps: u32 = 0;
    while (stack.pop()) |work| {
        steps += 1;
        if (steps > work_max) return error.TooDeep;
        if (try check_node(arena, work, &stack)) |reason| return reason;
    }
    return null;
}

/// `zbx schema <command>` printed a JSON schema that names `schema_id` as the `schema` member's
/// constant, so that an agent can tell which documents it describes.
pub fn schema_names(arena: Allocator, schema_text: []const u8, schema_id: []const u8) Error!void {
    const schema = try parse_value(arena, schema_text);
    if (schema != .object) return error.JsonWrong;
    const properties = schema.object.get("properties") orelse return error.JsonWrong;
    if (properties != .object) return error.JsonWrong;
    const member = properties.object.get("schema") orelse return error.JsonWrong;
    if (member != .object) return error.JsonWrong;
    const constant = member.object.get("const") orelse return error.JsonWrong;
    if (constant != .string) return error.JsonWrong;
    if (!std.mem.eql(u8, constant.string, schema_id)) return error.JsonWrong;
}

// ---- Diagnostics and the exit line, on stderr ----------------------------------------------

pub const Fix = struct {
    sentence: []const u8,
    command: ?[]const u8 = null,
    /// M6: only present, and true, when the command needs root. A fix of an older zbx has neither.
    needs_root: bool = false,
    /// M6: only present, and true, when the command is an example to adapt, not to run.
    template: bool = false,
};

pub const Diagnostic = struct {
    code: []const u8,
    severity: []const u8,
    blame: []const u8,
    summary: []const u8,
    context: Value,
    fixes: []const Fix,
    docs: []const u8,
};

/// Every diagnostic among the lines of `stderr`: each is one JSON object with a `code`.
pub fn diagnostics(arena: Allocator, stderr: []const u8) Error![]const Diagnostic {
    var found: std.ArrayList(Diagnostic) = .empty;
    var lines = std.mem.splitScalar(u8, stderr, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (!std.mem.startsWith(u8, line, "{\"code\":")) continue;
        const options: std.json.ParseOptions = .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        };
        const one = std.json.parseFromSliceLeaky(Diagnostic, arena, line, options) catch {
            return error.JsonWrong;
        };
        try found.append(arena, one);
    }
    return found.items;
}

fn context_text(diagnostic: Diagnostic, key: []const u8) ?[]const u8 {
    if (diagnostic.context != .object) return null;
    const member = diagnostic.context.object.get(key) orelse return null;
    if (member != .string) return null;
    return member.string;
}

/// A refusal as an agent reads it: exit 125 and nothing on stdout; the first error diagnostic has
/// `code`, and its context names `expect` and `actual` as members, so no message is parsed; the
/// first fix has a command, `zbx ...`, to run; and the docs link ends with the code's page.
pub fn check_refusal(
    arena: Allocator,
    streams: Streams,
    status: u8,
    code: []const u8,
    expect: []const u8,
    actual: []const u8,
) Error!Diagnostic {
    if (status != 125) return error.ExitCodeWrong;
    if (streams.stdout.len != 0) return error.DiagnosticWrong;
    const all = try diagnostics(arena, streams.stderr);
    if (all.len == 0) return error.DiagnosticWrong;
    const first = all[0];
    if (!std.mem.eql(u8, first.code, code)) return error.DiagnosticWrong;
    if (!std.mem.eql(u8, first.severity, "error")) return error.DiagnosticWrong;
    const said_expect = context_text(first, "expect") orelse return error.DiagnosticWrong;
    const said_actual = context_text(first, "actual") orelse return error.DiagnosticWrong;
    if (!std.mem.eql(u8, said_expect, expect)) return error.DiagnosticWrong;
    if (!std.mem.eql(u8, said_actual, actual)) return error.DiagnosticWrong;
    if (first.fixes.len == 0) return error.FixWrong;
    const command = first.fixes[0].command orelse return error.FixWrong;
    if (!std.mem.startsWith(u8, command, "zbx ")) return error.FixWrong;
    const page = try std.fmt.allocPrint(arena, "/errors/{s}.html", .{code[4..]});
    if (!std.mem.endsWith(u8, first.docs, page)) return error.DiagnosticWrong;
    return first;
}

pub const Exit = struct { reason: []const u8, code: u32 };

const ExitLine = struct { container_exit: Exit };

/// The `container_exit` line of a foreground run that started: reason `exited` and a code. The
/// program's own stdout is its own; this line is how zbx says how it ended.
pub fn container_exit(arena: Allocator, stderr: []const u8) Error!Exit {
    var lines = std.mem.splitScalar(u8, stderr, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (!std.mem.startsWith(u8, line, "{\"container_exit\":")) continue;
        const options: std.json.ParseOptions = .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        };
        const parsed = std.json.parseFromSliceLeaky(ExitLine, arena, line, options) catch {
            return error.JsonWrong;
        };
        return parsed.container_exit;
    }
    return error.ExitLineWrong;
}

/// A run that ended with `wanted` as the program's exit code: the process status and the line
/// agree, and the reason is `exited`.
pub fn check_exited(arena: Allocator, streams: Streams, status: u8, wanted: u8) Error!void {
    if (status != wanted) return error.ExitCodeWrong;
    const line = try container_exit(arena, streams.stderr);
    if (!std.mem.eql(u8, line.reason, "exited")) return error.ExitLineWrong;
    if (line.code != wanted) return error.ExitLineWrong;
}

/// The command line that runs a fix: the fix's command is `zbx <arguments>`; `wrapper` stands
/// for `zbx` in the guest, and the agent's global option goes in front of the arguments.
pub fn fix_command(buffer: []u8, wrapper: []const u8, command: []const u8) Error![]const u8 {
    if (!std.mem.startsWith(u8, command, "zbx ")) return error.FixWrong;
    return std.fmt.bufPrint(buffer, "{s} --output json {s}", .{ wrapper, command[4..] }) catch {
        return error.FixWrong;
    };
}

const ExplainDoc = struct {
    schema: []const u8,
    code: []const u8,
    severity: []const u8,
    blame: []const u8,
    summary: []const u8,
    explanation: []const u8,
    docs: []const u8,
};

/// `zbx explain <code> --output json` printed the code's entry as `zbx.explain/1`: the code, the
/// severity, the blame, the summary and the docs link the diagnostic carried, and a long text.
pub fn check_explain(
    arena: Allocator,
    streams: Streams,
    status: u8,
    diagnostic: Diagnostic,
) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (streams.stderr.len != 0) return error.ExplainWrong;
    const options: std.json.ParseOptions = .{ .allocate = .alloc_always };
    const doc = std.json.parseFromSliceLeaky(ExplainDoc, arena, streams.stdout, options) catch {
        return error.JsonWrong;
    };
    if (!std.mem.eql(u8, doc.schema, "zbx.explain/1")) return error.ExplainWrong;
    if (!std.mem.eql(u8, doc.code, diagnostic.code)) return error.ExplainWrong;
    if (!std.mem.eql(u8, doc.severity, diagnostic.severity)) return error.ExplainWrong;
    if (!std.mem.eql(u8, doc.blame, diagnostic.blame)) return error.ExplainWrong;
    if (!std.mem.eql(u8, doc.summary, diagnostic.summary)) return error.ExplainWrong;
    if (!std.mem.eql(u8, doc.docs, diagnostic.docs)) return error.ExplainWrong;
    if (doc.explanation.len == 0) return error.ExplainWrong;
}

pub const LockEntry = struct {
    reference: []const u8,
    manifest: []const u8,
    platform: []const u8,
    tree: []const u8,
};

const LockDoc = struct { schema: []const u8, path: []const u8, images: []const LockEntry };

pub const LockShown = struct { path: []const u8, entry: LockEntry };

/// `zbx lock show --output json` is `zbx.lock/1`, and has an entry for `reference`. The agent
/// reads the lock's path and the entry's digests from here, not from the file.
pub fn check_lock_show(
    arena: Allocator,
    streams: Streams,
    status: u8,
    reference: []const u8,
) Error!LockShown {
    if (status != 0) return error.ExitCodeWrong;
    if (streams.stderr.len != 0) return error.LockWrong;
    const options: std.json.ParseOptions = .{ .allocate = .alloc_always };
    const doc = std.json.parseFromSliceLeaky(LockDoc, arena, streams.stdout, options) catch {
        return error.JsonWrong;
    };
    if (!std.mem.eql(u8, doc.schema, "zbx.lock/1")) return error.LockWrong;
    if (doc.path.len == 0 or doc.path[0] != '/') return error.LockWrong;
    for (doc.images) |entry| {
        if (!std.mem.eql(u8, entry.reference, reference)) continue;
        return .{ .path = doc.path, .entry = entry };
    }
    return error.LockWrong;
}

pub const Ran = struct {
    kind: []const u8,
    reference: ?[]const u8 = null,
    manifest: ?[]const u8 = null,
    tree: ?[]const u8 = null,
};

const RanLine = struct { container_exit: Exit, ran: Ran };

/// The `ran` of the run's last line says an image ran: the name as typed, the manifest and the
/// tree the pull reported, so the agent need not remember them.
pub fn check_ran_image(
    arena: Allocator,
    stderr: []const u8,
    reference: []const u8,
    manifest: []const u8,
    tree: []const u8,
) Error!void {
    var lines = std.mem.splitScalar(u8, stderr, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (!std.mem.startsWith(u8, line, "{\"container_exit\":")) continue;
        const options: std.json.ParseOptions = .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        };
        const parsed = std.json.parseFromSliceLeaky(RanLine, arena, line, options) catch {
            return error.LockWrong;
        };
        const ran = parsed.ran;
        if (!std.mem.eql(u8, ran.kind, "image")) return error.LockWrong;
        if (!equal_optional(ran.reference, reference)) return error.LockWrong;
        if (!equal_optional(ran.manifest, manifest)) return error.LockWrong;
        if (!equal_optional(ran.tree, tree)) return error.LockWrong;
        return;
    }
    return error.ExitLineWrong;
}

fn equal_optional(found: ?[]const u8, wanted: []const u8) bool {
    const text = found orelse return false;
    return std.mem.eql(u8, text, wanted);
}

const testing = std.testing;

const pull_schema_text =
    \\{"$id":"x","type":"object","required":["schema","tree","layers"],
    \\"properties":{"schema":{"const":"zbx.pull/1"},"tree":{"type":"string"},
    \\"platform":{"enum":["linux/amd64","linux/arm64"]},
    \\"layers":{"type":"array","items":{"type":"object","required":["digest","size"],
    \\"properties":{"size":{"type":"integer"}}}},
    \\"lock":{"type":["object","null"],"required":["path"]}}}
;

test "a document that follows its schema has no violation" {
    // Goal: the checker passes what zbx prints. Method: one document that uses every keyword.
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const document =
        \\{"schema":"zbx.pull/1","tree":"b3:00","platform":"linux/amd64",
        \\"layers":[{"digest":"sha256:1","size":5}],"lock":null}
    ;
    const reason = try violation(arena, pull_schema_text, document);
    try testing.expectEqual(@as(?[]const u8, null), reason);
}

test "each keyword catches its own breach" {
    // Goal: a checker that cannot fail proves nothing. One wrong document per keyword: a missing
    // member (two levels down), a wrong constant, a wrong enum, a wrong type, a wrong item, and
    // a type list that excludes the value.
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const bad = [_][]const u8{
        \\{"schema":"zbx.pull/1","layers":[]}
        ,
        \\{"schema":"zbx.pull/2","tree":"b3:00","layers":[]}
        ,
        \\{"schema":"zbx.pull/1","tree":"b3:00","platform":"linux/riscv","layers":[]}
        ,
        \\{"schema":"zbx.pull/1","tree":7,"layers":[]}
        ,
        \\{"schema":"zbx.pull/1","tree":"b3:00","layers":[{"digest":"d"}]}
        ,
        \\{"schema":"zbx.pull/1","tree":"b3:00","layers":[{"digest":"d","size":"5"}]}
        ,
        \\{"schema":"zbx.pull/1","tree":"b3:00","layers":[],"lock":"x"}
        ,
        \\{"schema":"zbx.pull/1","tree":"b3:00","layers":[],"lock":{}}
        ,
        \\[]
    };
    for (bad) |document| {
        const reason = try violation(arena, pull_schema_text, document);
        try testing.expect(reason != null);
    }
    try testing.expectError(error.JsonWrong, violation(arena, pull_schema_text, "not json"));
    try testing.expectError(error.JsonWrong, violation(arena, "{", "{}"));
}

test "oneOf of required lists needs exactly one of them" {
    // Goal: `zbx schema store-du` says a document has the store, a tree or images.
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const schema =
        \\{"type":"object","oneOf":[{"required":["store"]},{"required":["tree"]},
        \\{"required":["images"]}]}
    ;
    const images = try violation(arena, schema, "{\"images\":[]}");
    try testing.expectEqual(@as(?[]const u8, null), images);
    try testing.expect(try violation(arena, schema, "{}") != null);
    try testing.expect(try violation(arena, schema, "{\"store\":1,\"tree\":2}") != null);
}

test "a document nested past the bound is refused, not followed" {
    // Goal: a bound on everything. A schema that nests 40 levels deep (a hostile `schema` output)
    // stops with TooDeep.
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    var schema: std.ArrayList(u8) = .empty;
    var document: std.ArrayList(u8) = .empty;
    for (0..40) |_| {
        try schema.appendSlice(arena, "{\"properties\":{\"a\":");
        try document.appendSlice(arena, "{\"a\":");
    }
    try schema.appendSlice(arena, "{}");
    try document.appendSlice(arena, "1");
    for (0..40) |_| {
        try schema.appendSlice(arena, "}}");
        try document.appendSlice(arena, "}");
    }
    try testing.expectError(error.TooDeep, violation(arena, schema.items, document.items));
}

test "a schema names the documents it describes" {
    // Goal: the agent picks the schema by command and checks that it is the right one.
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    try schema_names(arena, pull_schema_text, "zbx.pull/1");
    try testing.expectError(error.JsonWrong, schema_names(arena, pull_schema_text, "zbx.pull/2"));
    try testing.expectError(error.JsonWrong, schema_names(arena, "{}", "zbx.pull/1"));
}

const hex_0: [64]u8 = @splat('0');
const hex_a: [64]u8 = @splat('a');
const tree_expected = "b3:" ++ hex_0;
const tree_actual = "b3:" ++ hex_a;

const refusal_line = "{\"code\":\"ZBX-E0519\",\"severity\":\"error\",\"blame\":\"user\"," ++
    "\"summary\":\"zbx.lock and the store disagree about an image\",\"causes\":[\"c\"]," ++
    "\"while\":[\"w\"],\"context\":{\"ref\":\"alpine:3.20\",\"expect\":\"" ++ tree_expected ++
    "\",\"actual\":\"" ++ tree_actual ++ "\",\"path\":\"/p/zbx.lock\"},\"fixes\":[{\"sentence\":" ++
    "\"to take the store's image:\",\"command\":\"zbx pull 'alpine:3.20'\"},{\"sentence\":" ++
    "\"or restore\",\"command\":null}],\"docs\":\"https://z.example/errors/E0519.html\"}\n";

test "a refusal is read from its members: code, both digests, the fix's command" {
    // Goal: step 5 without parsing a message. Right: exit 125, empty stdout, E0519 with the two
    // trees in the context. Wrong: another code, swapped digests, no fix command, a fix that is
    // not a zbx command, stdout not empty, another exit.
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const ok: Streams = .{ .stdout = "", .stderr = refusal_line };
    const found = try check_refusal(arena, ok, 125, "ZBX-E0519", tree_expected, tree_actual);
    try testing.expectEqualStrings("zbx pull 'alpine:3.20'", found.fixes[0].command.?);
    const swapped = check_refusal(arena, ok, 125, "ZBX-E0519", tree_actual, tree_expected);
    try testing.expectError(error.DiagnosticWrong, swapped);
    const other = check_refusal(arena, ok, 125, "ZBX-E0520", tree_expected, tree_actual);
    try testing.expectError(error.DiagnosticWrong, other);
    try testing.expectError(
        error.ExitCodeWrong,
        check_refusal(arena, ok, 1, "ZBX-E0519", tree_expected, tree_actual),
    );
    const noisy: Streams = .{ .stdout = "x", .stderr = refusal_line };
    try testing.expectError(
        error.DiagnosticWrong,
        check_refusal(arena, noisy, 125, "ZBX-E0519", tree_expected, tree_actual),
    );
    const nothing: Streams = .{ .stdout = "", .stderr = "error[ZBX-E0519]: text\n" };
    try testing.expectError(
        error.DiagnosticWrong,
        check_refusal(arena, nothing, 125, "ZBX-E0519", tree_expected, tree_actual),
    );
    const rm = "\"command\":\"zbx pull";
    const no_fix = try std.mem.replaceOwned(u8, arena, refusal_line, rm, "\"command\":\"rm");
    const text_fix: Streams = .{ .stdout = "", .stderr = no_fix };
    try testing.expectError(
        error.FixWrong,
        check_refusal(arena, text_fix, 125, "ZBX-E0519", tree_expected, tree_actual),
    );
}

test "the exit line says how the container ended, and agrees with the status" {
    // Goal: a run's outcome from JSON. Right: exited with 0 and with 3. Wrong: no line, a
    // signal, a code that differs from the status.
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const warning = "{\"code\":\"ZBX-W0301\",\"severity\":\"warning\"}\n";
    const zero_line = "{\"container_exit\":{\"reason\":\"exited\",\"code\":0}}\n";
    const zero: Streams = .{ .stdout = "out\n", .stderr = warning ++ zero_line };
    try check_exited(arena, zero, 0, 0);
    const three_line = "{\"container_exit\":{\"reason\":\"exited\",\"code\":3}}";
    const three: Streams = .{ .stdout = "", .stderr = three_line };
    try check_exited(arena, three, 3, 3);
    try testing.expectError(error.ExitCodeWrong, check_exited(arena, three, 0, 3));
    const differs: Streams = .{
        .stdout = "",
        .stderr = "{\"container_exit\":{\"reason\":\"exited\",\"code\":4}}",
    };
    try testing.expectError(error.ExitLineWrong, check_exited(arena, differs, 3, 3));
    const killed_line = "{\"container_exit\":{\"reason\":\"signal\",\"code\":137,\"signal\":9}}";
    const killed: Streams = .{ .stdout = "", .stderr = killed_line };
    try testing.expectError(error.ExitLineWrong, check_exited(arena, killed, 137, 137));
    const none: Streams = .{ .stdout = "", .stderr = warning };
    try testing.expectError(error.ExitLineWrong, check_exited(arena, none, 0, 0));
}

test "a fix's command runs through the wrapper with the agent's option, or is refused" {
    // Goal: no guessing which program a fix means: only `zbx` is replaced.
    var buffer: [128]u8 = undefined;
    const text = try fix_command(&buffer, "/home/demo/za", "zbx pull 'alpine:3.20'");
    try testing.expectEqualStrings("/home/demo/za --output json pull 'alpine:3.20'", text);
    try testing.expectError(error.FixWrong, fix_command(&buffer, "/home/demo/za", "rm -rf /"));
    try testing.expectError(error.FixWrong, fix_command(&buffer, "/home/demo/za", "zbxpull x"));
    var tiny: [8]u8 = undefined;
    try testing.expectError(error.FixWrong, fix_command(&tiny, "/home/demo/za", "zbx pull x"));
}

test "explain is the document with the code, summary and docs the diagnostic carried" {
    // Goal: the registry and the diagnostic agree, from JSON. Wrong: another summary, exit 1,
    // stderr noise, another schema, an empty long text, text instead of JSON.
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const all = try diagnostics(arena, refusal_line);
    try testing.expectEqual(@as(usize, 1), all.len);
    const entry = "{\"schema\":\"zbx.explain/1\",\"code\":\"ZBX-E0519\",\"severity\":\"error\"," ++
        "\"blame\":\"user\",\"summary\":\"zbx.lock and the store disagree about an image\"," ++
        "\"explanation\":\"prose\\nmore\",\"docs\":\"https://z.example/errors/E0519.html\"}\n";
    const right: Streams = .{ .stdout = entry, .stderr = "" };
    try check_explain(arena, right, 0, all[0]);
    const other = try std.mem.replaceOwned(u8, arena, entry, "disagree", "agree");
    const wrong: Streams = .{ .stdout = other, .stderr = "" };
    try testing.expectError(error.ExplainWrong, check_explain(arena, wrong, 0, all[0]));
    try testing.expectError(error.ExitCodeWrong, check_explain(arena, right, 1, all[0]));
    const noisy: Streams = .{ .stdout = entry, .stderr = "e" };
    try testing.expectError(error.ExplainWrong, check_explain(arena, noisy, 0, all[0]));
    const schema = try std.mem.replaceOwned(u8, arena, entry, "explain/1", "explain/2");
    const moved: Streams = .{ .stdout = schema, .stderr = "" };
    try testing.expectError(error.ExplainWrong, check_explain(arena, moved, 0, all[0]));
    const bare = try std.mem.replaceOwned(u8, arena, entry, "prose\\nmore", "");
    const empty: Streams = .{ .stdout = bare, .stderr = "" };
    try testing.expectError(error.ExplainWrong, check_explain(arena, empty, 0, all[0]));
    const text: Streams = .{ .stdout = "ZBX-E0519: x\n", .stderr = "" };
    try testing.expectError(error.JsonWrong, check_explain(arena, text, 0, all[0]));
}

const lock_json = "{\"schema\":\"zbx.lock/1\",\"path\":\"/home/demo/project/zbx.lock\"," ++
    "\"images\":[{\"reference\":\"alpine:3.20\",\"manifest\":\"sha256:aa\"," ++
    "\"platform\":\"linux/amd64\",\"tree\":\"b3:bb\"}]}\n";

test "lock show gives the lock's path and the entry of a reference, or is refused" {
    // Goal: the agent reads the lock from JSON. Wrong: another reference, a relative path,
    // another schema, stderr noise, exit 1, text.
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const right: Streams = .{ .stdout = lock_json, .stderr = "" };
    const shown = try check_lock_show(arena, right, 0, "alpine:3.20");
    try testing.expectEqualStrings("/home/demo/project/zbx.lock", shown.path);
    try testing.expectEqualStrings("b3:bb", shown.entry.tree);
    try testing.expectEqualStrings("sha256:aa", shown.entry.manifest);
    try testing.expectError(error.LockWrong, check_lock_show(arena, right, 0, "alpine:3.19"));
    try testing.expectError(error.ExitCodeWrong, check_lock_show(arena, right, 1, "alpine:3.20"));
    const relative = try std.mem.replaceOwned(u8, arena, lock_json, "\"/home", "\"home");
    const bad_path: Streams = .{ .stdout = relative, .stderr = "" };
    try testing.expectError(error.LockWrong, check_lock_show(arena, bad_path, 0, "alpine:3.20"));
    const moved = try std.mem.replaceOwned(u8, arena, lock_json, "lock/1", "lock/2");
    const other: Streams = .{ .stdout = moved, .stderr = "" };
    try testing.expectError(error.LockWrong, check_lock_show(arena, other, 0, "alpine:3.20"));
    const noisy: Streams = .{ .stdout = lock_json, .stderr = "x" };
    try testing.expectError(error.LockWrong, check_lock_show(arena, noisy, 0, "alpine:3.20"));
    const text: Streams = .{ .stdout = "alpine:3.20\n", .stderr = "" };
    try testing.expectError(error.JsonWrong, check_lock_show(arena, text, 0, "alpine:3.20"));
}

test "a run says what it ran: the name as typed, the manifest and the tree" {
    // Goal: step 2 without remembering the pull. Wrong: another manifest, another tree, a
    // directory, no `ran`, no exit line.
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const exited = "{\"container_exit\":{\"reason\":\"exited\",\"code\":0},";
    const line = exited ++ "\"ran\":{\"kind\":\"image\"," ++
        "\"reference\":\"alpine:3.20\",\"manifest\":\"sha256:aa\",\"tree\":\"b3:bb\"}}\n";
    try check_ran_image(arena, line, "alpine:3.20", "sha256:aa", "b3:bb");
    const wrong_tree = check_ran_image(arena, line, "alpine:3.20", "sha256:aa", "b3:cc");
    try testing.expectError(error.LockWrong, wrong_tree);
    const wrong_manifest = check_ran_image(arena, line, "alpine:3.20", "sha256:ab", "b3:bb");
    try testing.expectError(error.LockWrong, wrong_manifest);
    const wrong_name = check_ran_image(arena, line, "alpine:3.19", "sha256:aa", "b3:bb");
    try testing.expectError(error.LockWrong, wrong_name);
    const path = exited ++ "\"ran\":{\"kind\":\"rootfs\"," ++
        "\"path\":\"/r\"}}\n";
    const rootfs = check_ran_image(arena, path, "alpine:3.20", "sha256:aa", "b3:bb");
    try testing.expectError(error.LockWrong, rootfs);
    const bare = "{\"container_exit\":{\"reason\":\"exited\",\"code\":0}}\n";
    const none = check_ran_image(arena, bare, "alpine:3.20", "sha256:aa", "b3:bb");
    try testing.expectError(error.LockWrong, none);
    const missing = check_ran_image(arena, "", "alpine:3.20", "sha256:aa", "b3:bb");
    try testing.expectError(error.ExitLineWrong, missing);
}
