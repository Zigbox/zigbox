//! The `cdi` fuzzer: `zig build fuzz -- cdi`. A CDI spec is a JSON file anyone with write access
//! to /etc/cdi can leave, and `zbx run --device vendor/class=name` turns what it says into mounts,
//! device nodes and environment variables of a container (`src/runtime/cdi.zig`). Each iteration
//! writes a random valid spec and asks for some of its devices, then damages the text and reads
//! that, and reads random bytes too.
//!
//! Properties, every iteration:
//!   1. A valid spec whose devices are all asked, and which has no edit Zigbox refuses, resolves
//!      (no refusal); a device the spec lacks is `unknown`, never another refusal, and an
//!      `unknown` names a device the spec does not have.
//!   2. What resolved is within the run's bounds and valid: every node and mount path is a
//!      clean absolute path, every variable has a name, every directory is a path, each text
//!      lies inside the string table and ends in a zero byte, and no container path is mounted
//!      twice.
//!   3. Damaged or random bytes never crash the resolver: the file is noted as a problem (at
//!      most `cdi_spec_files_max` of them) or it resolves under property 2.
//!   4. Reading the same bytes twice gives the same answer.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const cdi = @import("runtime/cdi.zig");

const text_bytes_max: usize = 16 * 1024;
const kind = "vendor.example/gpu";
const names = [_][]const u8{ "0", "1", "2", "all", "GPU-ab:1" };

/// The heap holds what is too big for a static: the test binary's static data is near its bound.
const Work = struct {
    parsed: cdi.Parsed,
    resolver: cdi.Resolver,
    resolved: cdi.Resolved,
};

var work_pointer: ?*Work = null;
var text_buffer: [text_bytes_max]u8 = undefined;
var damaged_buffer: [text_bytes_max]u8 = undefined;

fn work() *Work {
    if (work_pointer == null) {
        work_pointer = std.heap.page_allocator.create(Work) catch @panic("out of memory");
    }
    return work_pointer.?;
}

/// What a generated spec has, to compare with what the resolver says.
const Made = struct {
    text: []const u8,
    has: [names.len]bool,
    refused_edit: bool,

    /// Whether asking `names[pick]` finds a device: `all` finds every device of a spec that has
    /// none of that name.
    fn finds(made: *const Made, pick: usize) bool {
        const any = std.mem.indexOfScalar(bool, &made.has, true) != null;
        return made.has[pick] or (std.mem.eql(u8, names[pick], "all") and any);
    }
};

fn append(length: *usize, comptime format: []const u8, arguments: anytype) void {
    assert(length.* < text_buffer.len);
    const written = std.fmt.bufPrint(text_buffer[length.*..], format, arguments) catch {
        unreachable; // The generator's output is far below the buffer.
    };
    length.* += written.len;
}

fn append_edits(random: std.Random, length: *usize, refused: *bool) void {
    append(length, "{{\"deviceNodes\":[", .{});
    const nodes = random.uintLessThan(u32, 3);
    for (0..nodes) |index| {
        if (index > 0) append(length, ",", .{});
        append(length, "{{\"path\":\"/dev/fake{d}\"}}", .{random.uintLessThan(u32, 8)});
    }
    append(length, "],\"env\":[\"V{d}=x\"],\"mounts\":[", .{random.uintLessThan(u32, 4)});
    const mounts = random.uintLessThan(u32, 3);
    for (0..mounts) |index| {
        if (index > 0) append(length, ",", .{});
        const lib = random.uintLessThan(u32, 6);
        append(length, "{{\"hostPath\":\"/usr/lib/lib{d}.so\",", .{lib});
        append(length, "\"containerPath\":\"/usr/lib/lib{d}.so\"}}", .{lib});
    }
    append(length, "]", .{});
    if (random.uintLessThan(u32, 3) == 0) {
        append(length, ",\"hooks\":[{{\"hookName\":\"createContainer\",", .{});
        append(length, "\"path\":\"/usr/bin/nvidia-cdi-hook\",\"args\":[", .{});
        append(length, "\"nvidia-cdi-hook\",\"update-ldcache\",", .{});
        append(length, "\"--folder\",\"/usr/lib/d{d}\"]}}]", .{random.uintLessThan(u32, 3)});
    }
    if (random.uintLessThan(u32, 12) == 0) {
        append(length, ",\"intelRdt\":{{\"closID\":\"a\"}}", .{});
        refused.* = true;
    }
    append(length, "}}", .{});
}

/// A valid spec: some of the `names`, each with edits, and edits common to all of them.
fn generate(random: std.Random) Made {
    var length: usize = 0;
    var made: Made = .{ .text = "", .has = @splat(false), .refused_edit = false };
    append(&length, "{{\"cdiVersion\":\"0.6.0\",\"kind\":\"{s}\",\"devices\":[", .{kind});
    for (&made.has) |*slot| slot.* = random.boolean();
    if (std.mem.indexOfScalar(bool, &made.has, true) == null) {
        made.has[random.uintLessThan(usize, names.len)] = true;
    }
    var first = true;
    for (names, 0..) |name, index| {
        if (!made.has[index]) continue;
        if (!first) append(&length, ",", .{});
        first = false;
        append(&length, "{{\"name\":\"{s}\",\"containerEdits\":", .{name});
        append_edits(random, &length, &made.refused_edit);
        append(&length, "}}", .{});
    }
    append(&length, "],\"containerEdits\":", .{});
    append_edits(random, &length, &made.refused_edit);
    append(&length, "}}", .{});
    made.text = text_buffer[0..length];
    assert(made.text.len < text_bytes_max);
    return made;
}

/// The devices to ask for, as `kind=name` strings in `storage`; the index of each name.
fn choose(random: std.Random, storage: *[3][64]u8, asked: *[3][]const u8, picks: *[3]usize) usize {
    const count = random.intRangeAtMost(usize, 1, 3);
    var taken: usize = 0;
    while (taken < count) {
        const pick = random.uintLessThan(usize, names.len);
        var again = false;
        for (picks[0..taken]) |earlier| again = again or earlier == pick;
        if (again) continue;
        const text = std.fmt.bufPrint(&storage[taken], "{s}={s}", .{ kind, names[pick] }) catch {
            unreachable; // A name is far shorter than the storage.
        };
        asked[taken] = text;
        picks[taken] = pick;
        taken += 1;
    }
    return count;
}

/// Property 2.
fn check_resolved(resolved: *const cdi.Resolved) void {
    assert(resolved.strings_len <= constants.cdi_run_strings_bytes_max);
    assert(resolved.nodes_count <= constants.cdi_run_nodes_max);
    assert(resolved.mounts_count <= constants.cdi_run_mounts_max);
    assert(resolved.env_count <= constants.cdi_run_env_max);
    assert(resolved.dirs_count <= constants.cdi_run_dirs_max);
    for (resolved.nodes[0..resolved.nodes_count]) |node| {
        assert(cdi.path_valid(resolved.text(node)));
    }
    for (resolved.mounts[0..resolved.mounts_count], 0..) |mount, index| {
        assert(cdi.path_valid(resolved.text(mount.host)));
        const target = resolved.text(mount.container);
        assert(cdi.path_valid(target));
        for (resolved.mounts[0..index]) |earlier| {
            assert(!std.mem.eql(u8, resolved.text(earlier.container), target));
        }
    }
    for (resolved.env[0..resolved.env_count]) |item| assert(cdi.env_valid(resolved.text(item)));
    for (resolved.dirs[0..resolved.dirs_count]) |item| {
        assert(cdi.path_valid(resolved.text(item)));
    }
}

const Outcome = struct {
    refusal: ?cdi.Refusal,
    problems: u32,
    nodes: u32,
    mounts: u32,
    env: u32,
    dirs: u32,
};

fn resolve(asked: []const []const u8, content: []const u8) Outcome {
    const state = work();
    state.resolver.init(asked, &state.parsed, &state.resolved);
    var refusal = state.resolver.add_file("fuzz.json", content);
    if (refusal == null) refusal = state.resolver.finish();
    assert(state.resolver.problems_count <= constants.cdi_spec_files_max);
    if (refusal == null) check_resolved(&state.resolved);
    return .{
        .refusal = refusal,
        .problems = state.resolver.problems_count,
        .nodes = state.resolved.nodes_count,
        .mounts = state.resolved.mounts_count,
        .env = state.resolved.env_count,
        .dirs = state.resolved.dirs_count,
    };
}

fn same(first: Outcome, second: Outcome) bool {
    const a = first.refusal;
    const b = second.refusal;
    if ((a == null) != (b == null)) return false;
    if (a != null and std.meta.activeTag(a.?) != std.meta.activeTag(b.?)) return false;
    return first.problems == second.problems and first.nodes == second.nodes and
        first.mounts == second.mounts and first.env == second.env and first.dirs == second.dirs;
}

/// Property 1, and 4 on the same bytes.
fn check_valid(random: std.Random) []const u8 {
    const made = generate(random);
    var storage: [3][64]u8 = undefined;
    var asked: [3][]const u8 = undefined;
    var picks: [3]usize = undefined;
    const count = choose(random, &storage, &asked, &picks);
    const outcome = resolve(asked[0..count], made.text);
    assert(same(outcome, resolve(asked[0..count], made.text))); // Property 4.
    var all_there = true;
    for (picks[0..count]) |pick| all_there = all_there and made.finds(pick);
    if (outcome.refusal) |refusal| {
        switch (refusal) {
            .unknown => |index| assert(!made.finds(picks[index])),
            .unsupported => |found| assert(made.refused_edit and found.edit != .none),
            .too_big => assert(false), // The generator makes far less than the bounds.
        }
        assert(!all_there or made.refused_edit);
    } else {
        assert(all_there);
    }
    assert(outcome.problems == 0);
    return made.text;
}

/// Flips, drops and inserts bytes of `text` into `damaged_buffer`.
fn damage(random: std.Random, text: []const u8) []const u8 {
    assert(text.len <= damaged_buffer.len);
    @memcpy(damaged_buffer[0..text.len], text);
    var length = text.len;
    const edits = random.intRangeAtMost(u32, 1, 6);
    for (0..edits) |_| {
        if (length == 0) break;
        const at = random.uintLessThan(usize, length);
        switch (random.uintLessThan(u32, 3)) {
            0 => damaged_buffer[at] = random.int(u8),
            1 => length = at, // A truncated file.
            else => {
                if (length == damaged_buffer.len) continue;
                std.mem.copyBackwards(u8, damaged_buffer[at + 1 .. length + 1], damaged_buffer[at..length]);
                damaged_buffer[at] = "{}[]\",:\\/".*[random.uintLessThan(usize, 9)];
                length += 1;
            },
        }
    }
    return damaged_buffer[0..length];
}

/// Properties 3 and 4.
fn check_hostile(random: std.Random, content: []const u8) void {
    const asked = [_][]const u8{kind ++ "=0"};
    const first = resolve(&asked, content);
    assert(same(first, resolve(&asked, content)));
    if (first.refusal) |refusal| {
        switch (refusal) {
            .unknown => |index| assert(index < asked.len),
            .unsupported => |found| assert(found.edit != .none),
            .too_big => |index| assert(index < asked.len),
        }
    }
    const size = random.uintLessThan(usize, 600);
    for (damaged_buffer[0..size]) |*byte| byte.* = random.int(u8);
    _ = resolve(&asked, damaged_buffer[0..size]);
}

pub fn fuzz_cdi(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    const text = check_valid(random);
    var round: u32 = 0;
    while (round < 4) : (round += 1) {
        // `damage` copies `text` first, so the buffers do not overlap.
        const hurt = damage(random, text);
        var copy: [text_bytes_max]u8 = undefined;
        @memcpy(copy[0..hurt.len], hurt);
        check_hostile(random, copy[0..hurt.len]);
    }
}

test "the fuzzer's properties hold on fixed seeds" {
    // Goal: the fuzzer's properties run under `zig build test`. Method: a few seeds.
    var seed: u64 = 1;
    while (seed <= 64) : (seed += 1) fuzz_cdi(seed);
}
