//! The host settings fuzzer: `zig build fuzz -- host_settings` (M2b, `--require-host`). Each
//! iteration does three things:
//!
//! - **Requirement text.** It builds a requirement, either well-formed from a chosen setting and
//!   value (it must parse to exactly that, and render back to text that parses the same) or
//!   from pieces of the syntax and junk (it must be survived: a requirement is well-formed, and a
//!   refusal names a setting only once it found one).
//! - **The files.** It writes the four files' contents, either as the kernel does or damaged,
//!   and reads them through the simulated host with faults: a value read is the one written; a
//!   missing file is absent; nothing else comes back as a value.
//! - **The check.** It checks a list of requirements against the values read, against an oracle
//!   written here: no miss passes; the first miss, in the list's order, is ZBX-E0319 with its
//!   value or ZBX-E0321 when the host has none; a required setting that could not be read is
//!   ZBX-E0321. Some lists carry a repeated setting or a malformed entry: both checks refuse
//!   those with ZBX-E0320, whatever the files hold.
//!
//! Every refused requirement text is also rendered as ZBX-E0320, as the flag's reader does, and
//! the rendering must be one non-empty, bounded line.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const Diag = @import("diag/diag.zig").Diag;
const render = @import("diag/render.zig");
const HostSim = @import("host_sim.zig").HostSim;
const sim_file = @import("host_sim.zig").File;
const host_settings = @import("runtime/host_settings.zig");
const check = @import("runtime/host_settings_check.zig");

const HostSetting = host_settings.HostSetting;
const HostRequirement = host_settings.HostRequirement;
const settings_count = host_settings.settings_count;

const text_bytes_max = 96;
const file_bytes_max = 48;
/// A list holds one requirement per setting, and one more when a repeat is injected.
const list_count_max = settings_count + 1;

pub fn fuzz_host_settings(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    for (0..4) |_| fuzz_requirement_text(random);
    var reads: check.Reads = undefined;
    read_files(random, &reads);
    var requirements: [list_count_max]HostRequirement = undefined;
    const list = random_requirements(random, &requirements);
    check_requirements(&reads, requirements[0..list.count], list.invalid);
    assert(list.count <= list_count_max);
    assert(reads.len == settings_count);
}

fn random_setting(random: std.Random) HostSetting {
    const setting: HostSetting = @fromBackingInt(@intCast(random.uintLessThan(u8, settings_count)));
    assert(setting.key().len <= host_settings.setting_key_bytes_max);
    assert(setting.path().len < host_settings.path_bytes_max);
    return setting;
}

/// A well-formed requirement of a random setting, with an edge-weighted minimum or a non-empty
/// set of values.
fn random_requirement(random: std.Random, setting: HostSetting) HostRequirement {
    if (setting.is_minimum()) {
        const minimum: u64 = switch (random.uintLessThan(u8, 4)) {
            0 => 0,
            1 => std.math.maxInt(u64),
            2 => random.uintAtMost(u64, 1 << 20),
            else => random.int(u64),
        };
        return .{ .setting = setting, .minimum = minimum };
    }
    var allowed: host_settings.HostValueSet = .{ .bits = random.uintLessThan(u8, 8) };
    if (allowed.empty()) allowed = allowed.with(random.uintLessThan(u64, 3));
    const requirement: HostRequirement = .{ .setting = setting, .allowed = allowed };
    assert(requirement.well_formed());
    assert(!allowed.empty());
    return requirement;
}

fn fuzz_requirement_text(random: std.Random) void {
    var storage: [text_bytes_max]u8 = undefined;
    if (random.boolean()) {
        const wanted = random_requirement(random, random_setting(random));
        var rendered: [host_settings.text_bytes_max]u8 = undefined;
        const text = written_requirement(random, wanted, &rendered, &storage);
        const parsed = host_settings.parse_requirement(text);
        assert(parsed == .ok);
        assert(std.meta.eql(parsed.ok, wanted));
        round_trip(parsed.ok);
    } else {
        const text = junk_requirement(random, &storage);
        switch (host_settings.parse_requirement(text)) {
            .ok => |requirement| round_trip(requirement),
            .problem => |refused| {
                survive_problem(refused.kind, refused.setting);
                render_problem(text, refused.kind, refused.setting);
            },
        }
    }
    // The flag's reader finds a repeat across flags and renders it the same way.
    const repeated = random_setting(random);
    var rendered: [host_settings.text_bytes_max]u8 = undefined;
    const text = host_settings.render_requirement(random_requirement(random, repeated), &rendered);
    render_problem(text, .repeated, repeated);
}

/// A refused text, rendered as the flag's reader renders it: ZBX-E0320, with one cause that
/// is one non-empty, bounded line, and a text rendering whose first line names the code.
fn render_problem(
    text: []const u8,
    kind: host_settings.RequirementProblem,
    setting: ?HostSetting,
) void {
    var diag: Diag = undefined;
    diag.reset();
    check.requirement_invalid(&diag, text, kind, setting);
    assert(diag.code.? == .E0320);
    const cause = diag.last_cause().?;
    assert(cause.len > 0);
    assert(cause.len <= constants.diag_field_bytes_max);
    assert(std.mem.indexOfScalar(u8, cause, '\n') == null);
    assert(diag.fixes.count == 1);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const output = render.render(&diag, .text, false, &buffer);
    const first = output[0 .. std.mem.indexOfScalar(u8, output, '\n') orelse output.len];
    assert(first.len > 0);
    assert(std.mem.indexOf(u8, first, "ZBX-E0320") != null);
}

/// The requirement as a user writes it: the canonical text, or its values in another order
/// and repeated (a set is a set).
fn written_requirement(
    random: std.Random,
    wanted: HostRequirement,
    rendered: *[host_settings.text_bytes_max]u8,
    storage: *[text_bytes_max]u8,
) []const u8 {
    const canonical = host_settings.render_requirement(wanted, rendered);
    if (wanted.setting.is_minimum() or random.boolean()) return canonical;
    var writer: std.Io.Writer = .fixed(storage);
    // Cannot fail: a key, `=` and at most nine words of at most 7 bytes and a comma: 93 bytes.
    writer.print("{s}=", .{wanted.setting.key()}) catch unreachable; // Same bound.
    const words = wanted.setting.words();
    var written: u32 = 0;
    while (written == 0 or (written < 6 and random.boolean())) {
        const index = random.uintLessThan(u8, 3);
        if (!wanted.allowed.contains(index)) continue;
        if (written > 0) writer.writeByte(',') catch unreachable; // Same bound.
        writer.writeAll(words[index]) catch unreachable; // Same bound.
        written += 1;
    }
    // Every allowed value appears at least once, so the set parses back the same.
    for (words, 0..) |word, index| {
        if (!wanted.allowed.contains(index)) continue;
        writer.print(",{s}", .{word}) catch unreachable; // Same bound.
    }
    assert(written > 0);
    assert(writer.end <= storage.len);
    return writer.buffered();
}

const pieces = [_][]const u8{
    "vm.max_map_count", "fs.aio-max-nr",        "vm.overcommit_memory", "transparent_hugepage",
    "vm.max_map",       "kernel.pid_max",       ">=",                   "=",
    ">",                "<=",                   "==",                   ",",
    "0",                "1",                    "2",                    "3",
    "262144",           "18446744073709551615", "18446744073709551616", "-1",
    "always",           "madvise",              "never",                "[never]",
    " ",                "\n",                   "+5",                   "0x10",
};

fn junk_requirement(random: std.Random, storage: *[text_bytes_max]u8) []const u8 {
    var length: u32 = 0;
    const count = random.uintAtMost(u32, 6);
    var byte: [1]u8 = undefined;
    for (0..count) |_| {
        byte[0] = random.int(u8);
        const piece: []const u8 = if (random.uintLessThan(u8, 8) == 0)
            &byte
        else
            pieces[random.uintLessThan(usize, pieces.len)];
        if (length + piece.len > storage.len) break;
        @memcpy(storage[length..][0..piece.len], piece);
        length += @intCast(piece.len);
    }
    assert(length <= storage.len);
    assert(length <= constants.arg_bytes_max);
    return storage[0..length];
}

fn round_trip(requirement: HostRequirement) void {
    assert(requirement.well_formed());
    var rendered: [host_settings.text_bytes_max]u8 = undefined;
    const text = host_settings.render_requirement(requirement, &rendered);
    const again = host_settings.parse_requirement(text);
    assert(again == .ok);
    assert(std.meta.eql(again.ok, requirement));
}

fn survive_problem(kind: host_settings.RequirementProblem, setting: ?HostSetting) void {
    // Only the flag's reader finds a repeat, across flags.
    assert(kind != .repeated);
    const names_setting = switch (kind) {
        .no_operator, .unknown_setting => false,
        .wrong_operator, .value_empty, .not_a_number, .unknown_value => true,
        .repeated => unreachable, // Asserted above.
    };
    assert(names_setting == (setting != null));
}

/// What a file was written as: the value it holds, or why it holds none.
const Written = union(enum) { value: u64, missing, damaged, unreadable };

fn read_files(random: std.Random, reads: *check.Reads) void {
    var contents: [settings_count][file_bytes_max]u8 = undefined;
    var files: [settings_count]sim_file = undefined;
    var written: [settings_count]Written = undefined;
    var files_count: u32 = 0;
    for (std.enums.values(HostSetting), 0..) |setting, index| {
        written[index] = write_file(random, setting, &contents[index]);
        if (written[index] == .missing) continue;
        files[files_count] = .{
            .path = setting.path(),
            .content = std.mem.sliceTo(&contents[index], 0),
            .readable = written[index] != .unreadable,
        };
        files_count += 1;
    }
    var sim: HostSim = undefined;
    sim.init(random.int(u64), files[0..files_count]);
    const faulty = random.uintLessThan(u8, 4) == 0;
    if (faulty) sim.faults.read_error_per_mille = random.uintAtMost(u16, 1000);
    for (std.enums.values(HostSetting), 0..) |setting, index| {
        reads[index] = check.read_one(sim.interface(), setting);
        check_read(setting, written[index], reads[index], faulty);
    }
    assert(sim.open_count() == 0);
    assert(files_count <= settings_count);
}

/// The file's contents, zero-terminated in `storage`, and what they are.
fn write_file(random: std.Random, setting: HostSetting, storage: *[file_bytes_max]u8) Written {
    @memset(storage, 0);
    var writer: std.Io.Writer = .fixed(storage[0 .. file_bytes_max - 1]);
    // Cannot fail: a count or THP's three words in 47 bytes.
    const result: Written = switch (random.uintLessThan(u8, 8)) {
        0 => return .missing,
        1 => return .unreadable,
        2 => damaged: {
            random.bytes(storage[0..random.uintLessThan(u32, 8)]);
            for (storage[0 .. file_bytes_max - 1]) |*byte| {
                if (byte.* == 0) byte.* = ' ';
            }
            storage[random.uintLessThan(u32, file_bytes_max - 1)] = 0;
            break :damaged .damaged;
        },
        else => good: {
            const value = random_value(random, setting);
            write_value(&writer, setting, value);
            break :good .{ .value = value };
        },
    };
    assert(storage[file_bytes_max - 1] == 0);
    return result;
}

fn random_value(random: std.Random, setting: HostSetting) u64 {
    if (!setting.is_minimum()) return random.uintLessThan(u64, 3);
    const value: u64 = switch (random.uintLessThan(u8, 3)) {
        0 => std.math.maxInt(u64),
        1 => 65530,
        else => random.int(u64),
    };
    assert(setting.is_minimum());
    return value;
}

fn write_value(writer: *std.Io.Writer, setting: HostSetting, value: u64) void {
    assert(writer.end == 0);
    if (setting != .transparent_hugepage) {
        writer.print("{d}\n", .{value}) catch unreachable; // 20 digits and a newline fit.
        return;
    }
    assert(value < 3);
    for (setting.words(), 0..) |word, index| {
        const separator: []const u8 = if (index == 0) "" else " ";
        if (index == value) {
            writer.print("{s}[{s}]", .{ separator, word }) catch unreachable; // Fits.
        } else {
            writer.print("{s}{s}", .{ separator, word }) catch unreachable; // Fits.
        }
    }
    writer.writeAll("\n") catch unreachable; // Fits.
}

fn check_read(setting: HostSetting, written: Written, read: check.Read, faulty: bool) void {
    switch (read) {
        .value => |value| {
            if (!setting.is_minimum()) assert(value < 3);
            // A file the kernel wrote reads as its value; damage reads as a value only when the
            // damage is itself a value.
            if (written == .value) assert(value == written.value);
            assert(written != .missing);
            assert(written != .unreadable);
        },
        .absent => if (!faulty) assert(written == .missing),
        .unreadable => if (!faulty) assert(written == .unreadable),
        .malformed => {
            assert(written != .missing);
            assert(written != .unreadable);
            if (!faulty) assert(written == .damaged);
        },
    }
}

const List = struct {
    count: u32,
    /// The list has a repeated setting or a malformed entry: ZBX-E0320 whatever the reads.
    invalid: bool,
};

/// Up to one well-formed requirement per setting, in a random order; one list in eight then
/// gets a repeat of one of its settings or a malformed entry, at a random place.
fn random_requirements(random: std.Random, out: *[list_count_max]HostRequirement) List {
    var order: [settings_count]HostSetting = undefined;
    @memcpy(&order, std.enums.values(HostSetting));
    random.shuffle(HostSetting, &order);
    const count = random.uintAtMost(u32, settings_count);
    for (order[0..count], out[0..count]) |setting, *requirement| {
        requirement.* = random_requirement(random, setting);
    }
    assert(count <= settings_count);
    assert(host_settings.list_problem(out[0..count]) == null);
    if (random.uintLessThan(u8, 8) != 0) return .{ .count = count, .invalid = false };
    const injected = if (count > 0 and random.boolean())
        random_requirement(random, out[random.uintLessThan(u32, count)].setting)
    else
        malformed_requirement(random);
    const place = random.uintAtMost(u32, count);
    var index = count;
    while (index > place) : (index -= 1) out[index] = out[index - 1];
    out[place] = injected;
    assert(host_settings.list_problem(out[0 .. count + 1]) != null);
    return .{ .count = count + 1, .invalid = true };
}

/// A library caller's requirement whose fields do not fit its setting.
fn malformed_requirement(random: std.Random) HostRequirement {
    const setting = random_setting(random);
    var requirement: HostRequirement = .{ .setting = setting };
    if (setting.is_minimum()) {
        requirement.allowed = .{ .bits = random.intRangeAtMost(u8, 1, 255) };
    } else switch (random.uintLessThan(u8, 3)) {
        0 => {}, // No allowed values.
        1 => requirement.allowed = .{ .bits = random.intRangeAtMost(u8, 8, 255) },
        else => {
            requirement.allowed = .{ .bits = random.intRangeAtMost(u8, 1, 7) };
            requirement.minimum = random.intRangeAtMost(u64, 1, std.math.maxInt(u64));
        },
    }
    assert(!requirement.well_formed());
    return requirement;
}

const Expected = union(enum) { pass, not_met, not_read };

/// The oracle: a required setting that read unreadable or malformed refuses first, whatever
/// its place; then the first requirement, in order, whose read is absent or a value that misses.
fn expected_outcome(reads: *const check.Reads, requirements: []const HostRequirement) Expected {
    assert(requirements.len <= settings_count);
    for (requirements) |requirement| {
        switch (reads[@backingInt(requirement.setting)]) {
            .unreadable, .malformed => return .not_read,
            .value, .absent => {},
        }
    }
    for (requirements) |requirement| {
        const read = reads[@backingInt(requirement.setting)];
        switch (read) {
            .value => |value| {
                const meets = if (requirement.setting.is_minimum())
                    value >= requirement.minimum
                else
                    ((requirement.allowed.bits >> @intCast(value)) & 1) == 1;
                if (!meets) return .not_met;
            },
            .absent, .unreadable, .malformed => return .not_read,
        }
    }
    assert(requirements.len <= reads.len);
    return .pass;
}

fn check_requirements(
    reads: *const check.Reads,
    requirements: []const HostRequirement,
    invalid: bool,
) void {
    if (invalid) return check_invalid(reads, requirements);
    var diag: Diag = undefined;
    diag.reset();
    const expected = expected_outcome(reads, requirements);
    if (check.check_reads(reads, requirements, &diag)) {
        assert(expected == .pass);
        assert(diag.code == null);
        return;
    } else |_| {}
    switch (expected) {
        .pass => unreachable, // The check refused what the oracle passes.
        .not_met => {
            assert(diag.code.? == .E0319);
            assert(diag.headline.len > 0);
        },
        .not_read => assert(diag.code.? == .E0321),
    }
    assert(diag.causes.count > 0);
    assert(diag.fixes.count > 0);
}

/// A list with a repeat or a malformed entry: both checks refuse it with ZBX-E0320 before they
/// look at any value, so the reads (or a library caller's settings) never matter.
fn check_invalid(reads: *const check.Reads, requirements: []const HostRequirement) void {
    assert(requirements.len > 0);
    assert(requirements.len <= list_count_max);
    var diag: Diag = undefined;
    diag.reset();
    const refused_reads = if (check.check_reads(reads, requirements, &diag)) false else |_| true;
    assert(refused_reads);
    assert(diag.code.? == .E0320);
    assert(diag.causes.count == 1);
    var settings: host_settings.HostSettings = .{};
    for (std.enums.values(HostSetting), reads) |setting, read| {
        if (read == .value) settings.set(setting, read.value);
    }
    diag.reset();
    const checked = check.host_requirements_check(&settings, requirements, &diag);
    const refused_settings = if (checked) false else |_| true;
    assert(refused_settings);
    assert(diag.code.? == .E0320);
    assert(diag.fixes.count == 1);
}
