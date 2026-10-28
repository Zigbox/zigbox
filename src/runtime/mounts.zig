//! The other mounts of a run (M6, docs/briefs/M6-state.md, "Other mounts"): `--tmpfs`, `--bind`
//! and `--secret`. This file holds what is true of them without a kernel: how a flag's value is
//! read, the text a run record keeps for each, the rules their targets share with `--state`, and
//! how a source on the host is looked at before a container is made. The steps that mount them
//! are the plan's (`plan.zig`, `is_mount`).
//!
//! - `--tmpfs PATH[:SIZE]`: an empty tmpfs, gone at exit. Its size is a ceiling
//!   (`constants.tmpfs_mount_bytes_default` without one); its pages are charged to the memory of
//!   the container's cgroup, so `--memory` bounds it too.
//! - `--bind HOST:PATH`: the host's directory or file, read-only, always. A source that is not
//!   there is refused and never made: what a container writes belongs in a state volume.
//! - `--secret HOST_FILE:PATH`: a copy of one host file, read-only, mode 0400, owned by the
//!   container's root. The copy is made inside the container's own /dev (memory), so the file
//!   on the host is not shared, not changed, and not read again; its bytes are never in a run
//!   record, a bundle, a log or any output. Its path is (the record keeps it, `zbx commit`
//!   leaves the mount point out).
//!
//! A host path and a target hold no ':' (that is what makes `HOST:PATH` and the record's
//! `kind:HOST:PATH` unambiguous), no space and no control byte; every part is a name.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const spec_mod = @import("spec.zig");
const plan_mod = @import("plan.zig");
const volume = @import("../state/volume.zig");
const Diag = @import("../diag/diag.zig").Diag;
const diagnose = @import("mounts_diagnose.zig");

const Host = host_mod.Host;

pub const Kind = enum {
    tmpfs,
    bind,
    secret,

    /// The flag that asks for it, as `help` and the diagnostics spell it.
    pub fn flag(kind: Kind) []const u8 {
        assert(@tagName(kind).len > 0);
        return switch (kind) {
            .tmpfs => "--tmpfs",
            .bind => "--bind",
            .secret => "--secret",
        };
    }
};

/// One other mount. The strings point into the argument or record they were read from.
pub const Mount = struct {
    kind: Kind,
    /// The host's path (a bind or a secret); empty for a tmpfs.
    source: []const u8,
    /// Where it is in the container.
    target: []const u8,
    /// A tmpfs's size in bytes; zero for the others.
    size_bytes: u64,
};

pub const Problem = union(enum) {
    /// A bind or a secret without the colon that separates its two paths.
    no_target,
    source: volume.TargetProblem,
    target: volume.TargetProblem,
    size: spec_mod.LimitProblem,

    /// The reason, as a sentence after "--flag 'value': ".
    pub fn sentence(problem: Problem) []const u8 {
        return switch (problem) {
            .no_target => "it needs the host's path and the container's: HOST:PATH",
            .source => |found| volume.host_sentence(found),
            .target => |found| found.sentence(),
            .size => |found| size_sentence(found),
        };
    }
};

fn size_sentence(problem: spec_mod.LimitProblem) []const u8 {
    return switch (problem) {
        error.Empty => "the size is empty; give bytes, or a number with k, m or g",
        error.NotANumber => "the size is not a number; give bytes, or a number with k, m or g",
        error.Zero => "the size is zero",
        error.TooSmall => "the size is under 4096 bytes",
        error.TooLarge => "the size is over 1 TiB",
        error.TooPrecise => "the size is not a whole number",
    };
}

comptime {
    // The sentences above say so.
    assert(constants.tmpfs_mount_bytes_min == 4096);
    assert(constants.tmpfs_mount_bytes_max == 1 << 40);
}

pub const Parsed = union(enum) {
    ok: Mount,
    problem: Problem,
};

/// Reads the value of a flag. A tmpfs is `PATH` or `PATH:SIZE`; a bind and a secret are
/// `HOST:PATH` (the host's path ends at the first colon, which neither holds).
pub fn parse(kind: Kind, value: []const u8) Parsed {
    assert(value.len <= constants.arg_bytes_max);
    const colon = std.mem.indexOfScalar(u8, value, ':');
    if (kind == .tmpfs) {
        const target = if (colon) |at| value[0..at] else value;
        if (volume.target_problem(target)) |problem| return .{ .problem = .{ .target = problem } };
        var size: u64 = constants.tmpfs_mount_bytes_default;
        if (colon) |at| {
            size = parse_tmpfs_size(value[at + 1 ..]) catch |err| {
                return .{ .problem = .{ .size = err } };
            };
        }
        return .{ .ok = .{ .kind = .tmpfs, .source = "", .target = target, .size_bytes = size } };
    }
    const at = colon orelse return .{ .problem = .no_target };
    const source = value[0..at];
    const target = value[at + 1 ..];
    if (volume.path_problem(source)) |problem| return .{ .problem = .{ .source = problem } };
    if (volume.target_problem(target)) |problem| return .{ .problem = .{ .target = problem } };
    assert(std.mem.indexOfScalar(u8, target, ':') == null);
    return .{ .ok = .{ .kind = kind, .source = source, .target = target, .size_bytes = 0 } };
}

fn parse_tmpfs_size(digits: []const u8) spec_mod.LimitProblem!u64 {
    return spec_mod.parse_size(
        digits,
        constants.tmpfs_mount_bytes_min,
        constants.tmpfs_mount_bytes_max,
    );
}

/// The rules of one mount that a library caller must meet as the flags do: null if `mount` could
/// have come from `parse`.
pub fn mount_problem(mount: *const Mount) ?Problem {
    if (mount.kind == .tmpfs) {
        if (mount.source.len != 0) return .no_target;
        if (volume.target_problem(mount.target)) |problem| return .{ .target = problem };
        if (mount.size_bytes < constants.tmpfs_mount_bytes_min) return .{ .size = error.TooSmall };
        if (mount.size_bytes > constants.tmpfs_mount_bytes_max) return .{ .size = error.TooLarge };
        return null;
    }
    if (mount.size_bytes != 0) return .no_target;
    if (volume.path_problem(mount.source)) |problem| return .{ .source = problem };
    if (volume.target_problem(mount.target)) |problem| return .{ .target = problem };
    return null;
}

// ---- Several mounts together ----------------------------------------------------------------

/// How a target meets the others of its run.
pub const Conflict = enum {
    /// The same path as another mount's.
    same,
    /// Inside another mount's path, or holding it: the inner one would be made in the outer one.
    nested,
};

pub fn conflict_sentence(found: Conflict) []const u8 {
    return switch (found) {
        .same => "another mount of this run is on that path; two mounts cannot share one",
        .nested => "that path is inside, or holds, another mount's path",
    };
}

pub const too_many_sentence = "--tmpfs, --bind and --secret together are given more than 8 times";

comptime {
    assert(constants.mounts_max == 8); // `too_many_sentence` says so.
}

/// Whether `target` meets the target of a state volume or of an earlier mount. The rule is the
/// state volumes': no path at, in or over another's.
pub fn conflict(
    target: []const u8,
    state: []const volume.Mount,
    others: []const Mount,
) ?Conflict {
    assert(volume.target_problem(target) == null);
    for (state) |volume_mount| {
        if (meets(target, volume_mount.target)) |found| return found;
    }
    for (others) |other| {
        if (meets(target, other.target)) |found| return found;
    }
    return null;
}

fn meets(target: []const u8, other: []const u8) ?Conflict {
    if (std.mem.eql(u8, target, other)) return .same;
    if (volume.under(target, other) or volume.under(other, target)) return .nested;
    return null;
}

pub const ListProblem = union(enum) {
    too_many,
    /// The index of the mount that meets an earlier one (or a state volume), and how.
    meets: struct { index: u32, found: Conflict },
};

/// Null if the other mounts of one run go together, and with the state volumes: at most
/// `mounts_max`, every one valid, and no target at, in or over another's.
pub fn list_problem(state: []const volume.Mount, mounts: []const Mount) ?ListProblem {
    if (mounts.len > constants.mounts_max) return .too_many;
    for (mounts, 0..) |*mount, index| {
        assert(mount_problem(mount) == null);
        if (conflict(mount.target, state, mounts[0..index])) |found| {
            return .{ .meets = .{ .index = @intCast(index), .found = found } };
        }
    }
    return null;
}

// ---- The text a run record keeps ------------------------------------------------------------

/// `tmpfs:/scratch:67108864`, `bind:/srv/data:/data`, `secret:/run/key:/run/secrets/key`: the
/// kind, then the two paths (a tmpfs's size in bytes comes last). No path holds a colon.
pub fn text(mount: *const Mount, buffer: *[constants.mount_value_bytes_max]u8) []const u8 {
    assert(mount_problem(mount) == null);
    const written = if (mount.kind == .tmpfs)
        std.fmt.bufPrint(buffer, "tmpfs:{s}:{d}", .{ mount.target, mount.size_bytes })
    else
        std.fmt.bufPrint(buffer, "{s}:{s}:{s}", .{
            @tagName(mount.kind), mount.source, mount.target,
        });
    // Cannot fail: the kind, two bounded paths and the separators fit the buffer, and so does a
    // target with the size's twenty digits (a comptime relation in constants.zig).
    const result = written catch unreachable; // Same bound.
    assert(result.len > 0);
    return result;
}

comptime {
    const tmpfs_value = "tmpfs:".len + constants.mount_path_bytes_max + 1 + 20;
    assert(constants.mount_value_bytes_max >= tmpfs_value);
}

/// The mount a record's text names, or null if it is not one `text` could have written. The
/// strings point into `value`.
pub fn parse_text(value: []const u8) ?Mount {
    if (value.len > constants.mount_value_bytes_max) return null;
    const first = std.mem.indexOfScalar(u8, value, ':') orelse return null;
    const kind = std.meta.stringToEnum(Kind, value[0..first]) orelse return null;
    const rest = value[first + 1 ..];
    const second = std.mem.indexOfScalar(u8, rest, ':') orelse return null;
    const middle = rest[0..second];
    const last = rest[second + 1 ..];
    if (std.mem.indexOfScalar(u8, last, ':') != null) return null;
    var found: Mount = undefined;
    if (kind == .tmpfs) {
        if (last.len == 0 or last.len > 13) return null;
        if (last.len > 1 and last[0] == '0') return null; // One spelling per number.
        const size = std.fmt.parseInt(u64, last, 10) catch return null;
        found = .{ .kind = .tmpfs, .source = "", .target = middle, .size_bytes = size };
    } else {
        found = .{ .kind = kind, .source = middle, .target = last, .size_bytes = 0 };
    }
    if (mount_problem(&found) != null) return null;
    return found;
}

// ---- Looking at the host --------------------------------------------------------------------

pub const SourceProblem = enum {
    missing,
    unreadable,
    /// Not a directory or a regular file (a socket, a device, a fifo).
    not_a_file_or_directory,
    /// A secret is one regular file.
    not_a_file,

    pub fn sentence(problem: SourceProblem) []const u8 {
        assert(@tagName(problem).len > 0);
        return switch (problem) {
            .missing => "it does not exist",
            .unreadable => "it cannot be looked at",
            .not_a_file_or_directory => "it is not a directory or a regular file",
            .not_a_file => "a secret is one regular file",
        };
    }
};

pub const Looked = union(enum) {
    shape: plan_mod.MountShape,
    problem: SourceProblem,
};

const type_mask: u32 = 0o170000;
const type_directory: u32 = 0o040000;
const type_file: u32 = 0o100000;

/// What the plan needs to know of a mount: its shape. A bind of a directory and of a file are
/// different sequences of steps, so the host's path is looked at (`stat`, following links, as
/// the kernel does when it binds). Nothing is made, whatever is found. `errno` is the last call's.
pub fn look(host: Host, mount: *const Mount) Looked {
    assert(mount_problem(mount) == null);
    if (mount.kind == .tmpfs) return .{ .shape = .tmpfs };
    var path: [constants.mount_path_bytes_max + 1:0]u8 = undefined;
    @memcpy(path[0..mount.source.len], mount.source);
    path[mount.source.len] = 0;
    const found = host.stat(path[0..mount.source.len]) catch |err| {
        return .{ .problem = if (err == error.NotFound) .missing else .unreadable };
    };
    const kind = found.mode & type_mask;
    if (mount.kind == .secret) {
        if (kind != type_file) return .{ .problem = .not_a_file };
        return .{ .shape = .secret };
    }
    if (kind == type_directory) return .{ .shape = .bind_dir };
    if (kind == type_file) return .{ .shape = .bind_file };
    return .{ .problem = .not_a_file_or_directory };
}

pub const ResolveError = error{StartFailed};

/// A library caller's mounts, held to the rules the flags apply and looked at on the host, in
/// order: the plan's inputs, or a diagnostic for the first that is wrong. Nothing is made.
pub fn resolve(
    host: Host,
    state: []const volume.Mount,
    mounts: []const Mount,
    inputs: *[constants.mounts_max]plan_mod.MountInput,
    diag: *Diag,
) ResolveError!void {
    assert(diag.code == null);
    if (mounts.len > constants.mounts_max) {
        diagnose.conflict(diag, "--tmpfs", "", too_many_sentence);
        return error.StartFailed;
    }
    for (mounts) |*mount| {
        var value: [constants.mount_value_bytes_max]u8 = undefined;
        if (mount_problem(mount)) |problem| {
            diagnose.bad_value(diag, mount.kind, value_of(mount, &value), problem.sentence());
            return error.StartFailed;
        }
    }
    if (list_problem(state, mounts)) |problem| {
        const index = problem.meets.index; // Too many was refused above.
        var value: [constants.mount_value_bytes_max]u8 = undefined;
        const mount = &mounts[index];
        const shown = value_of(mount, &value);
        diagnose.conflict(diag, mount.kind.flag(), shown, conflict_sentence(problem.meets.found));
        return error.StartFailed;
    }
    for (mounts, 0..) |*mount, index| {
        switch (look(host, mount)) {
            .shape => |shape| inputs[index] = .{
                .shape = shape,
                .source = mount.source,
                .target = mount.target,
                .size_bytes = mount.size_bytes,
            },
            .problem => |problem| {
                diagnose.bad_source(diag, mount.kind, mount.source, problem);
                return error.StartFailed;
            },
        }
    }
}

/// The value as the flag took it, for a message.
pub fn value_of(mount: *const Mount, buffer: *[constants.mount_value_bytes_max]u8) []const u8 {
    if (mount.kind == .tmpfs) return mount.target;
    // Cannot fail: two bounded paths and a colon fit the buffer.
    return std.fmt.bufPrint(buffer, "{s}:{s}", .{ mount.source, mount.target }) catch unreachable;
}

const testing = std.testing;
const TargetProblem = volume.TargetProblem;

fn bad_target(kind: Kind, value: []const u8) TargetProblem {
    return parse(kind, value).problem.target;
}

fn bad_source(kind: Kind, value: []const u8) TargetProblem {
    return parse(kind, value).problem.source;
}

const repeat = @import("../test_util.zig").repeat;

test "a --tmpfs value: a path, a size with units, the default, and what is refused" {
    // Goal: the value's two parts are read and each bound holds. Method: good values with their
    // sizes, then one value per problem, and the size at both ends of its bound.
    const plain = parse(.tmpfs, "/scratch").ok;
    try testing.expectEqualStrings("/scratch", plain.target);
    try testing.expectEqual(constants.tmpfs_mount_bytes_default, plain.size_bytes);
    try testing.expectEqual(@as(u64, 128 << 20), parse(.tmpfs, "/s:128m").ok.size_bytes);
    try testing.expectEqual(@as(u64, 4096), parse(.tmpfs, "/s:4096").ok.size_bytes);
    try testing.expectEqual(@as(u64, 1 << 40), parse(.tmpfs, "/s:1048576m").ok.size_bytes);
    try testing.expectEqual(error.TooSmall, parse(.tmpfs, "/s:4095").problem.size);
    try testing.expectEqual(error.TooLarge, parse(.tmpfs, "/s:1048577m").problem.size);
    try testing.expectEqual(error.Zero, parse(.tmpfs, "/s:0").problem.size);
    try testing.expectEqual(error.Empty, parse(.tmpfs, "/s:").problem.size);
    try testing.expectEqual(error.NotANumber, parse(.tmpfs, "/s:big").problem.size);
    try testing.expectEqual(TargetProblem.relative, bad_target(.tmpfs, "s"));
    try testing.expectEqual(TargetProblem.protected, bad_target(.tmpfs, "/dev/shm"));
    try testing.expectEqual(TargetProblem.bad_part, bad_target(.tmpfs, "/a/../b"));
    try testing.expectEqual(TargetProblem.empty, bad_target(.tmpfs, ":1m"));
}

test "a --bind or --secret value: two paths, each held to its rules" {
    // Goal: HOST:PATH splits at the first colon and each side is checked by its own rules.
    // Method: good values, then one per problem.
    const bind = parse(.bind, "/srv/data:/data").ok;
    try testing.expectEqualStrings("/srv/data", bind.source);
    try testing.expectEqualStrings("/data", bind.target);
    try testing.expectEqual(@as(u64, 0), bind.size_bytes);
    const secret = parse(.secret, "/run/key:/run/secrets/key").ok;
    try testing.expectEqual(Kind.secret, secret.kind);
    try testing.expectEqual(Problem.no_target, parse(.bind, "/srv/data").problem);
    try testing.expectEqual(TargetProblem.relative, bad_source(.bind, "data:/d"));
    try testing.expectEqual(TargetProblem.root, bad_source(.bind, "/:/d"));
    try testing.expectEqual(TargetProblem.empty, bad_source(.bind, ":/d"));
    try testing.expectEqual(TargetProblem.bad_part, bad_source(.bind, "/a/../b:/d"));
    try testing.expectEqual(TargetProblem.empty, bad_target(.bind, "/a:"));
    try testing.expectEqual(TargetProblem.bad_character, bad_target(.bind, "/a:/d:ro"));
    try testing.expectEqual(TargetProblem.protected, bad_target(.secret, "/k:/proc/k"));
    try testing.expectEqual(TargetProblem.protected, bad_target(.bind, "/k:/etc/hosts"));
    try testing.expectEqual(TargetProblem.protected, bad_target(.bind, "/k:/sys"));
    const longest = "/" ++ repeat('a', constants.mount_path_bytes_max - 1);
    try testing.expect(parse(.bind, longest ++ ":/d") == .ok);
    try testing.expectEqual(TargetProblem.too_long, bad_source(.bind, longest ++ "a:/d"));
    try testing.expectEqual(TargetProblem.too_long, bad_target(.bind, "/s:" ++ longest ++ "a"));
}

test "targets of one run: no two at, in or over each other, and at most eight" {
    // Goal: the rule `--state` has, across all four flags. Method: each conflict, in both
    // orders, with a state volume and with another mount, and the count at its bound.
    const state = [_]volume.Mount{.{ .name = "pg", .target = "/var/lib/pg", .read_only = false }};
    const a: Mount = .{ .kind = .tmpfs, .source = "", .target = "/scratch", .size_bytes = 4096 };
    const b: Mount = .{ .kind = .bind, .source = "/srv", .target = "/scratch/in", .size_bytes = 0 };
    const c: Mount = .{ .kind = .secret, .source = "/k", .target = "/var/lib/pg", .size_bytes = 0 };
    const d: Mount = .{ .kind = .bind, .source = "/srv", .target = "/scratchy", .size_bytes = 0 };
    try testing.expect(list_problem(&state, &.{ a, d }) == null);
    try testing.expectEqual(Conflict.nested, list_problem(&state, &.{ a, b }).?.meets.found);
    try testing.expectEqual(@as(u32, 1), list_problem(&state, &.{ a, b }).?.meets.index);
    try testing.expectEqual(Conflict.nested, list_problem(&state, &.{ b, a }).?.meets.found);
    try testing.expectEqual(Conflict.same, list_problem(&state, &.{c}).?.meets.found);
    try testing.expectEqual(Conflict.same, list_problem(&.{}, &.{ a, a }).?.meets.found);
    try testing.expectEqual(Conflict.nested, conflict("/var/lib", &state, &.{}).?);
    try testing.expectEqual(Conflict.nested, conflict("/var/lib/pg/x", &state, &.{}).?);
    try testing.expect(conflict("/var/libx", &state, &.{}) == null);
    var many: [constants.mounts_max + 1]Mount = undefined;
    const targets = [_][]const u8{ "/t0", "/t1", "/t2", "/t3", "/t4", "/t5", "/t6", "/t7", "/t8" };
    for (&many, targets) |*slot, target| {
        slot.* = .{ .kind = .tmpfs, .source = "", .target = target, .size_bytes = 4096 };
    }
    try testing.expect(list_problem(&.{}, many[0..constants.mounts_max]) == null);
    try testing.expectEqual(ListProblem.too_many, list_problem(&.{}, &many).?);
}

test "the record's text round-trips and nothing else reads as a mount" {
    // Goal: `parse_text` accepts only what `text` writes (REVIEW.md: parse accepts only what
    // render can write). Method: each kind, then damaged texts.
    var buffer: [constants.mount_value_bytes_max]u8 = undefined;
    const mounts = [_]Mount{
        .{ .kind = .tmpfs, .source = "", .target = "/scratch", .size_bytes = 64 << 20 },
        .{ .kind = .bind, .source = "/srv/data", .target = "/data", .size_bytes = 0 },
        .{ .kind = .secret, .source = "/run/key", .target = "/run/secrets/key", .size_bytes = 0 },
    };
    const expected = [_][]const u8{
        "tmpfs:/scratch:67108864",
        "bind:/srv/data:/data",
        "secret:/run/key:/run/secrets/key",
    };
    for (&mounts, expected) |*mount, line| {
        try testing.expectEqualStrings(line, text(mount, &buffer));
        const again = parse_text(line).?;
        try testing.expectEqual(mount.kind, again.kind);
        try testing.expectEqualStrings(mount.source, again.source);
        try testing.expectEqualStrings(mount.target, again.target);
        try testing.expectEqual(mount.size_bytes, again.size_bytes);
    }
    const damaged = [_][]const u8{
        "",                "tmpfs",                  "tmpfs:/s",
        "tmpfs:/s:",       "tmpfs:/s:0",             "tmpfs:/s:4095",
        "tmpfs:/s:004096", "tmpfs:/s:1099511627777", "tmpfs:/s:x",
        "tmpfs:s:4096",    "tmpfs:/dev:4096",        "bind:/a",
        "bind:/a:b",       "bind:/a:/b:/c",          "bind:/a:/b/../c",
        "bind:/:/b",       "secret:a:/b",            "secret:/a:/proc",
        "other:/a:/b",     "bind::/b",               "tmpfs:/s:4096:1",
    };
    for (damaged) |value| try testing.expect(parse_text(value) == null);
}

test "a bind of a directory, a bind of a file, a secret, and what is refused" {
    // Goal: the shape the plan is given follows what the host has. Method: a simulated host with
    // a file and a directory, and a missing path.
    const HostSim = @import("../host_sim.zig").HostSim;
    var sim: HostSim = undefined;
    sim.init(1, &.{
        .{ .path = "/srv/file", .content = "x", .mode = 0o100644 },
        .{ .path = "/srv/dir", .content = "", .mode = 0o040755 },
        .{ .path = "/srv/socket", .content = "", .mode = 0o140755 },
    });
    const host = sim.interface();
    const bind_file: Mount = .{
        .kind = .bind,
        .source = "/srv/file",
        .target = "/f",
        .size_bytes = 0,
    };
    const bind_dir: Mount = .{
        .kind = .bind,
        .source = "/srv/dir",
        .target = "/d",
        .size_bytes = 0,
    };
    try testing.expectEqual(plan_mod.MountShape.bind_file, look(host, &bind_file).shape);
    try testing.expectEqual(plan_mod.MountShape.bind_dir, look(host, &bind_dir).shape);
    var secret = bind_file;
    secret.kind = .secret;
    try testing.expectEqual(plan_mod.MountShape.secret, look(host, &secret).shape);
    secret.source = "/srv/dir";
    try testing.expectEqual(SourceProblem.not_a_file, look(host, &secret).problem);
    var missing = bind_file;
    missing.source = "/srv/nothing";
    try testing.expectEqual(SourceProblem.missing, look(host, &missing).problem);
    missing.source = "/srv/socket";
    try testing.expectEqual(SourceProblem.not_a_file_or_directory, look(host, &missing).problem);
    const tmpfs: Mount = .{ .kind = .tmpfs, .source = "", .target = "/t", .size_bytes = 4096 };
    try testing.expectEqual(plan_mod.MountShape.tmpfs, look(host, &tmpfs).shape);
}
