//! The `build_file` fuzzer: `zig build fuzz -- build_file`. A person writes `zbx.build.zon` by
//! hand, and `zbx build` reads it before anything runs. Each iteration writes a random valid
//! file in a random layout (field order, spacing, comments, trailing commas), reads it, prints
//! it canonically, then damages the text and reads that.
//!
//! Properties, every iteration:
//!   1. A valid file is read: what the generator wrote is accepted, with its counts.
//!   2. The canonical form reads back to an equal file and is a fixed point (printed again, the
//!      same bytes).
//!   3. A file whose needs point only at earlier steps is ordered, and the order puts every
//!      need before the step that needs it; a need back to a later step that closes a round is
//!      refused as a cycle.
//!   4. Damaged text and noise never crash the reader. A refusal maps to a registered E08xx
//!      code, and its diagnostic is built without tripping an assertion, with a cause. A file
//!      that still reads prints, reads back equal, and is ordered or refused by the graph,
//!      whose refusal is E0802 with a cause.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const codes = @import("diag/codes.zig");
const Diag = @import("diag/diag.zig").Diag;
const file_mod = @import("build/file.zig");
const render = @import("build/render.zig");
const graph_mod = @import("build/graph.zig");
const diagnose = @import("build/diagnose.zig");

const BuildFile = file_mod.BuildFile;
const Writer = std.Io.Writer;

var generated: [constants.build_file_bytes_max]u8 = undefined;
var canonical: [constants.build_render_bytes_max]u8 = undefined;
var again: [constants.build_render_bytes_max]u8 = undefined;
var damaged: [constants.build_file_bytes_max]u8 = undefined;
var first: BuildFile = undefined;
var second: BuildFile = undefined;
var graph: graph_mod.Graph = undefined;
var diag: Diag = undefined;

/// The most steps a generated file has: enough for every graph shape, small enough to stay far
/// inside the file's bound with every list at its longest generated length.
const steps_generated_max = 12;
/// The longest list a generated file writes.
const list_generated_max = 5;

const words = [_][]const u8{
    "go",       "build",    "-o",        "/out/hello", "sh -c 'echo hi'", "a b",
    "quote\"d", "back\\sl", "tab\there", "line\nfeed",
    "ünï",
    "x",        "=",        "--flag=on", "/usr/bin/a", "",
};

/// Each with its own key, so that `distinct_list` never sets a key twice.
const env_entries = [_][]const u8{
    "CGO_ENABLED=0", "GOFLAGS=-trimpath -buildvcs=false", "A=", "PATH=/usr/bin:/bin",
    "Q=\"x\"",       "K=v=w",
    "_u=1\tü",
};

comptime {
    assert(env_entries.len >= list_generated_max);
}

/// Label values: no control bytes, which only arguments and env values may hold.
const label_values = [_][]const u8{ "https://example.test/a", "", "a b", "ünï", "quote\"d" };

const references = [_][]const u8{
    "alpine:3.20",            "golang:1.23-alpine",     "docker.io/library/busybox",
    "ghcr.io/owner/image:v1", "registry.test:5000/a/b", "debian:bookworm-slim",
};

const inputs = [_][]const u8{ "go.mod", "main.go", "src", "src/a.c", "VERSION", "a b", "ü" };

const targets = [_][]const u8{ "/", "/usr/local/bin", "/out", "/etc/hello", "/a/b/c" };

const users = [_][]const u8{
    "0:0", "1000:1000", "65534:65534", "4294967295:0", "app", "app:app", "0", "nobody:65534",
};

const excludes = [_][]const u8{ ".git", "*.log", "**/*_test.go", "!keep.log", "a/**/b", "[ab]?" };


const label_keys = [_][]const u8{
    "org.opencontainers.image.source", "a", "x/y", "b-c_d", "org.opencontainers.image.version",
};

const step_names = [_][]const u8{
    "compile", "notice", "test", "lint", "a", "b-2", "fetch", "gen", "docs", "x9", "pack",
    "z",       "sign",   "copy",
};

/// The generator's choices, kept so the reader's result can be checked against them.
const Shape = struct {
    steps: u32,
    needs: [steps_generated_max]u32,
    adds: u32,
    config: bool,
    /// A need from the first step back to the last, which closes a round.
    round: bool,
};

/// Writes the parts of a file in a random layout: spacing, comments and trailing commas.
const Gen = struct {
    writer: Writer,
    random: std.Random,

    fn put(gen: *Gen, bytes: []const u8) void {
        assert(bytes.len > 0);
        // Cannot fail: the generator's largest file is far below the buffer (see steps and
        // lists generated max).
        gen.writer.writeAll(bytes) catch unreachable; // Bounded as above.
    }

    fn space(gen: *Gen) void {
        assert(gen.writer.end <= generated.len);
        switch (gen.random.uintLessThan(u8, 8)) {
            0 => gen.put("\n    "),
            1 => gen.put("  "),
            2 => gen.put(" // a comment, with \"quotes\" and .{ braces }\n"),
            3 => gen.put("\t"),
            else => gen.put(" "),
        }
    }

    fn string(gen: *Gen, text: []const u8) void {
        assert(text.len <= constants.build_string_bytes_max);
        // Cannot fail: as `put`.
        render.render_string(text, &gen.writer) catch unreachable; // Bounded as in `put`.
    }

    fn field(gen: *Gen, name: []const u8) void {
        assert(name.len > 0);
        assert(name[0] == '.');
        gen.space();
        gen.put(name);
        gen.put(" = ");
    }

    /// The comma after an item: always between items, sometimes after the last.
    fn comma(gen: *Gen, index: u32, count: u32) void {
        assert(index < count);
        if (index + 1 < count) {
            gen.put(",");
        } else if (gen.random.boolean()) {
            gen.put(",");
        }
    }

    fn list(gen: *Gen, pool: []const []const u8, count: u32) void {
        assert(count <= list_generated_max);
        assert(pool.len > 0);
        gen.put(".{");
        for (0..count) |index| {
            gen.space();
            gen.string(pool[gen.random.uintLessThan(usize, pool.len)]);
            gen.comma(@intCast(index), count);
        }
        gen.put(" }");
    }

    /// A list of `count` different entries of `pool`: consecutive from a random start.
    fn distinct_list(gen: *Gen, pool: []const []const u8, count: u32) void {
        assert(count <= list_generated_max);
        assert(count <= pool.len);
        const start = gen.random.uintLessThan(usize, pool.len);
        gen.put(".{");
        for (0..count) |index| {
            gen.space();
            gen.string(pool[(start + index) % pool.len]);
            gen.comma(@intCast(index), count);
        }
        gen.put(" }");
    }
};

const StepField = enum { name, base, inputs, needs, env, run, network };

fn gen_step(gen: *Gen, shape: *const Shape, index: u32) void {
    assert(index < shape.steps);
    assert(shape.needs[index] <= index);
    var order: [7]StepField = std.enums.values(StepField)[0..7].*;
    gen.random.shuffle(StepField, &order);
    gen.put(".{");
    gen_builder_fields(gen, shape, index);
    for (order, 0..) |which, at| {
        gen.field(switch (which) {
            inline else => |tag| "." ++ @tagName(tag),
        });
        switch (which) {
            .name => gen.string(step_names[index]),
            .base => gen_step_base(gen, index),
            .inputs => gen.list(&inputs, gen.random.uintAtMost(u32, list_generated_max)),
            .needs => gen_needs(gen, shape, index),
            .env => gen.distinct_list(&env_entries, gen.random.uintAtMost(u32, list_generated_max)),
            .run => {
                gen.put(".{ ");
                gen.string(step_names[gen.random.uintLessThan(usize, step_names.len)]);
                gen.put(", ");
                gen.string(words[gen.random.uintLessThan(usize, words.len)]);
                gen.put(" }");
            },
            .network => gen.put(if (gen.random.boolean()) "true" else "false"),
        }
        gen.comma(@intCast(at), order.len);
    }
    gen.put(" }");
}

/// An image, or sometimes an earlier step, so a base never closes a round.
fn gen_step_base(gen: *Gen, index: u32) void {
    assert(index < step_names.len);
    if (index > 0 and gen.random.uintLessThan(u8, 4) == 0) {
        gen.put("\"step:");
        gen.put(step_names[gen.random.uintLessThan(u32, index)]);
        gen.put("\"");
        return;
    }
    gen.string(references[gen.random.uintLessThan(usize, references.len)]);
}

/// The builder's additions, each written or not at random, before a step's other fields. Each is
/// followed by a comma. The mounts stay within the bound: a bind only when the needs leave room.
fn gen_builder_fields(gen: *Gen, shape: *const Shape, index: u32) void {
    assert(index < shape.steps);
    assert(shape.needs[index] <= constants.build_step_needs_max);
    if (gen.random.boolean()) {
        gen.field(".user");
        gen.string(users[gen.random.uintLessThan(usize, users.len)]);
        gen.put(",");
    }
    if (gen.random.boolean()) {
        gen.field(".workdir");
        gen.string(targets[1 + gen.random.uintLessThan(usize, targets.len - 1)]);
        gen.put(",");
    }
    if (gen.random.boolean()) {
        gen.field(".exclude");
        gen.list(&excludes, gen.random.uintAtMost(u32, 3));
        gen.put(",");
    }
    if (gen.random.boolean()) {
        gen.field(".caches");
        gen.put(".{ .{ .id = \"cache-a\", .path = \"/cache/a\", .mode = \"0755\" } },");
    }
    if (index > 0 and shape.needs[index] <= 5 and gen.random.boolean()) {
        gen.field(".binds");
        gen.put(".{ .{ .from = \"step:");
        gen.put(step_names[gen.random.uintLessThan(u32, index)]);
        gen.put("\", .source = \"/usr/bin\", .to = \"/bound\" } },");
    }
}

/// The needs of step `index`: distinct earlier steps, and the last step for the first step
/// when the shape closes a round.
fn gen_needs(gen: *Gen, shape: *const Shape, index: u32) void {
    const count = shape.needs[index];
    assert(count <= index);
    assert(count <= constants.build_step_needs_max);
    const round = shape.round and index == 0;
    gen.put(".{");
    if (round) gen.string(step_names[shape.steps - 1]);
    for (0..count) |need| {
        if (round) gen.put(",");
        gen.space();
        // The `need` steps just before this one: distinct by construction.
        gen.string(step_names[index - 1 - need]);
        gen.comma(@intCast(need), count);
    }
    gen.put(" }");
}

fn gen_image(gen: *Gen, shape: *const Shape) void {
    assert(shape.adds <= shape.steps);
    gen.put(".{");
    gen.field(".base");
    gen.string(references[gen.random.uintLessThan(usize, references.len)]);
    gen.put(",");
    gen.field(".add");
    gen.put(".{");
    for (0..shape.adds) |index| {
        gen.put(" .{ .from = ");
        gen.string(step_names[index]);
        gen.put(", .to = ");
        gen.string(targets[gen.random.uintLessThan(usize, targets.len)]);
        gen.put(" }");
        gen.comma(@intCast(index), shape.adds);
    }
    gen.put(" }");
    if (shape.config) {
        gen.put(",");
        gen_config(gen);
    }
    gen.put(" }");
}

fn gen_config(gen: *Gen) void {
    assert(gen.writer.end > 0);
    gen.field(".config");
    gen.put(".{");
    gen.field(".entrypoint");
    gen.list(&targets, gen.random.uintAtMost(u32, 2));
    gen.put(",");
    gen.field(".cmd");
    gen.list(&words, gen.random.uintAtMost(u32, list_generated_max));
    gen.put(",");
    gen.field(".env");
    gen.distinct_list(&env_entries, gen.random.uintAtMost(u32, list_generated_max));
    gen.put(",");
    gen.field(".workdir");
    gen.string(targets[gen.random.uintLessThan(usize, targets.len)]);
    gen.put(",");
    gen.field(".user");
    gen.string(users[gen.random.uintLessThan(usize, users.len)]);
    gen.put(",");
    gen.field(".labels");
    gen.put(".{");
    const labels = gen.random.uintAtMost(u32, 3);
    for (0..labels) |index| {
        gen.put(" .{ ");
        // Distinct keys: a key twice is refused.
        gen.string(label_keys[index]);
        gen.put(", ");
        gen.string(label_values[gen.random.uintLessThan(usize, label_values.len)]);
        gen.put(" }");
        gen.comma(@intCast(index), labels);
    }
    gen.put(" } }");
    assert(labels <= label_keys.len);
}

fn random_shape(random: std.Random) Shape {
    var shape: Shape = undefined;
    shape.steps = random.uintAtMost(u32, steps_generated_max);
    for (0..shape.steps) |index| {
        const most = @min(index, constants.build_step_needs_max);
        shape.needs[index] = random.uintAtMost(u32, @intCast(most));
    }
    shape.round = shape.steps > 1 and random.uintLessThan(u8, 8) == 0;
    // A round needs a chain from the last step back to the first: each step needs the one
    // before it.
    if (shape.round) {
        for (1..shape.steps) |index| shape.needs[index] = @max(shape.needs[index], 1);
    }
    shape.adds = random.uintAtMost(u32, shape.steps);
    shape.config = random.boolean();
    assert(shape.steps <= step_names.len);
    assert(shape.adds <= shape.steps);
    return shape;
}

/// A whole file of `shape`, its top-level fields in a random order.
fn gen_file(random: std.Random, shape: *const Shape) []const u8 {
    assert(shape.steps <= steps_generated_max);
    var gen: Gen = .{ .writer = .fixed(&generated), .random = random };
    if (random.boolean()) gen.put("// zbx.build.zon\n");
    gen.put(".{");
    var order = [_]u8{ 0, 1, 2 };
    random.shuffle(u8, &order);
    for (order, 0..) |which, at| {
        switch (which) {
            0 => {
                gen.field(".version");
                gen.put("1");
            },
            1 => {
                gen.field(".steps");
                gen.put(".{");
                for (0..shape.steps) |index| {
                    gen.space();
                    gen_step(&gen, shape, @intCast(index));
                    gen.comma(@intCast(index), shape.steps);
                }
                gen.put(" }");
            },
            else => {
                gen.field(".image");
                gen_image(&gen, shape);
            },
        }
        gen.comma(@intCast(at), order.len);
    }
    gen.put("\n}\n");
    assert(gen.writer.end <= generated.len);
    return gen.writer.buffered();
}

fn print_canonical(file: *const BuildFile, out: []u8) []const u8 {
    assert(out.len == constants.build_render_bytes_max);
    var writer: Writer = .fixed(out);
    // Cannot fail: the render bound covers every file the parser accepts (constants.zig).
    render.render(file, &writer) catch unreachable; // build_render_bytes_max bounds it.
    assert(writer.end <= out.len);
    return writer.buffered();
}

/// Property 2: printed, read back equal, printed again the same.
fn check_round_trip(file: *const BuildFile) void {
    assert(file.version == file_mod.version);
    const printed = print_canonical(file, &canonical);
    var problem: file_mod.Problem = undefined;
    assert(file_mod.parse(printed, &second, &problem) == .parsed);
    assert(render.equal(file, &second));
    assert(std.mem.eql(u8, printed, print_canonical(&second, &again)));
}

/// Property 3: every need comes before the step that needs it.
fn check_order(file: *const BuildFile) void {
    assert(graph.count == file.steps_count);
    var position: [constants.build_steps_max]u32 = undefined;
    for (graph.order_slice(), 0..) |step, at| position[step] = @intCast(at);
    for (file.steps_slice(), 0..) |*step, index| {
        for (step.needs.slice()) |need| {
            const needed = for (file.steps_slice(), 0..) |*other, other_index| {
                if (std.mem.eql(u8, file.text(other.name), file.text(need))) break other_index;
            } else unreachable; // The graph refuses an unknown need.
            assert(position[needed] < position[index]);
        }
    }
}

fn fuzz_valid(random: std.Random) void {
    const shape = random_shape(random);
    const text = gen_file(random, &shape);
    var problem: file_mod.Problem = undefined;
    // 1. Read, with what was written.
    if (file_mod.parse(text, &first, &problem) == .refused) {
        std.debug.print("refused: {t} at {d}:{d}\n{s}\n", .{
            problem.kind, problem.line, problem.column, text,
        });
        unreachable; // A generated file is valid by construction.
    }
    assert(first.steps_count == shape.steps);
    assert(first.image.adds_count == shape.adds);
    assert(first.image.config.present == shape.config);
    // 2. Canonical, and a fixed point.
    check_round_trip(&first);
    // 3. Ordered, unless a round was closed.
    var graph_problem: graph_mod.Problem = undefined;
    const result = graph_mod.order(&first, &graph, &graph_problem);
    if (shape.round) {
        assert(result == .refused);
        assert(graph_problem.kind == .cycle);
        check_graph_refusal(&first, &graph_problem);
    } else {
        assert(result == .ordered);
        check_order(&first);
    }
    // 4. Damaged.
    for (0..8) |_| fuzz_damaged(random, text);
}

/// The diagnostic of a refused file: a registered E08xx code, and a cause.
fn check_parse_refusal(problem: *const file_mod.Problem) void {
    const code = diagnose.parse_code(problem.kind);
    assert(codes.entry(code).code == code);
    const name = @tagName(code);
    assert(std.mem.startsWith(u8, name, "E08"));
    diag.reset();
    diagnose.parse_problem(&diag, "zbx.build.zon", problem);
    assert(diag.code == code);
    assert(diag.causes.count > 0);
}

fn check_graph_refusal(file: *const BuildFile, problem: *const graph_mod.Problem) void {
    // A cycle or a duplicate needs steps; an add from a step that is not there may have none.
    if (file.steps_count == 0) assert(problem.kind == .unknown_add);
    diag.reset();
    diagnose.graph_problem(&diag, "zbx.build.zon", file, problem);
    assert(diag.code == .E0802);
    assert(diag.causes.count > 0);
}

const pieces = [_][]const u8{
    ".{",
    "}",
    ",",
    "\"",
    "\\",
    "//",
    "\n",
    "=",
    ".name = \"x\"",
    ".needs = .{ \"compile\" }",
    "\x00",
    "\xff",
    ".version = 99999",
    ".colour",
    "true",
    "\\u{0}",
    "\\x7f",
    ".image = .{}",
    "0:0",
    "\"image\"",
    "\"..\"",
    "\"/a/../b\"",
    "\\x+f",
    "\\x80",
    "\\n",
    "\"HOME=/\"",
    "\"A=1\", \"A=2\"",
    ".version = 01",
};

/// Damages `text` into `damaged` one of several ways, and returns the damaged length.
fn damage(random: std.Random, text: []const u8) usize {
    assert(text.len <= damaged.len);
    @memcpy(damaged[0..text.len], text);
    var length = text.len;
    const edits = 1 + random.uintLessThan(u32, 4);
    for (0..edits) |_| {
        const at = if (length == 0) 0 else random.uintLessThan(usize, length);
        switch (random.uintLessThan(u8, 5)) {
            0 => if (length > 0) {
                damaged[at] = random.int(u8);
            },
            1 => length = at, // Cut short.
            2 => {
                // Remove a short run.
                const run = @min(length - at, random.uintAtMost(usize, 16));
                std.mem.copyForwards(u8, damaged[at .. length - run], damaged[at + run .. length]);
                length -= run;
            },
            else => {
                const piece = pieces[random.uintLessThan(usize, pieces.len)];
                if (length + piece.len > damaged.len) continue;
                const tail = damaged[at..length];
                std.mem.copyBackwards(u8, damaged[at + piece.len ..][0..tail.len], tail);
                @memcpy(damaged[at..][0..piece.len], piece);
                length += piece.len;
            },
        }
    }
    assert(length <= damaged.len);
    return length;
}

/// Property 4.
fn fuzz_damaged(random: std.Random, text: []const u8) void {
    const length = damage(random, text);
    var problem: file_mod.Problem = undefined;
    if (file_mod.parse(damaged[0..length], &first, &problem) == .refused) {
        assert(problem.line >= 1);
        check_parse_refusal(&problem);
        return;
    }
    check_round_trip(&first);
    var graph_problem: graph_mod.Problem = undefined;
    if (graph_mod.order(&first, &graph, &graph_problem) == .refused) {
        check_graph_refusal(&first, &graph_problem);
    } else {
        check_order(&first);
    }
}

/// Noise of any bytes: never a crash, and a refusal is registered.
fn fuzz_noise(random: std.Random) void {
    const length = random.uintAtMost(usize, 512);
    random.bytes(damaged[0..length]);
    var problem: file_mod.Problem = undefined;
    const result = file_mod.parse(damaged[0..length], &first, &problem);
    if (result == .refused) check_parse_refusal(&problem) else check_round_trip(&first);
    assert(length <= damaged.len);
}

pub fn fuzz_build_file(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    fuzz_valid(random);
    fuzz_noise(random);
}
