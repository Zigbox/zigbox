//! What a state volume is called, where it is mounted, and where it lives on the host: the rules
//! for a name and for a `--state NAME:PATH[:ro]` value, and the paths of the layout (the module
//! doc of `state.zig`). Pure: nothing here touches the host but `Root.locate`, which reads the
//! environment.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");

const Host = host_mod.Host;

pub const NameProblem = union(enum) {
    empty,
    too_long,
    /// The first byte that is not a lowercase letter, a digit, `.`, `-` or `_`.
    bad_character: u8,
    /// A name starts with a letter or a digit, so it is never `.`, `..` or a hidden name.
    bad_start,

    /// The reason, as a sentence part after "the name ... ".
    pub fn sentence(problem: NameProblem) []const u8 {
        assert(@tagName(problem).len > 0);
        return switch (problem) {
            .empty => "is empty",
            .too_long => "is longer than 63 bytes",
            .bad_character => "may hold only lowercase letters, digits, '.', '-' and '_'",
            .bad_start => "must start with a lowercase letter or a digit",
        };
    }
};

comptime {
    assert(constants.state_name_bytes_max == 63); // `NameProblem.sentence` says so.
}

/// Null if `name` can name a volume.
pub fn name_problem(name: []const u8) ?NameProblem {
    if (name.len == 0) return .empty;
    if (name.len > constants.state_name_bytes_max) return .too_long;
    for (name, 0..) |byte, index| {
        const allowed = std.ascii.isLower(byte) or std.ascii.isDigit(byte) or
            byte == '.' or byte == '-' or byte == '_';
        if (!allowed) return .{ .bad_character = @intCast(index) };
    }
    const first = name[0];
    if (!std.ascii.isLower(first) and !std.ascii.isDigit(first)) return .bad_start;
    assert(std.mem.indexOfScalar(u8, name, '/') == null); // A name is never a path.
    return null;
}

pub const TargetProblem = enum {
    empty,
    relative,
    too_long,
    /// A part that is empty (`//`, a trailing `/`), `.` or `..`.
    bad_part,
    /// A colon (it would make `NAME:PATH:ro` ambiguous), a space or a control byte (a run record
    /// keeps a run's volumes in one string, separated by spaces).
    bad_character,
    /// `/` itself: the root is the container's tree, not a volume.
    root,
    /// `/proc`, `/sys`, `/dev` or below them, or a file zbx generates in `/etc`.
    protected,

    pub fn sentence(problem: TargetProblem) []const u8 {
        assert(@tagName(problem).len > 0);
        return switch (problem) {
            .empty => "the path in the container is empty",
            .relative => "the path in the container must be absolute",
            .too_long => "the path in the container is longer than 256 bytes",
            .bad_part => "the path in the container may not have an empty, '.' or '..' part",
            .bad_character => "the path in the container may not hold a ':', a space or a " ++
                "control character",
            .root => "a volume cannot be mounted on the container's root",
            .protected => "zbx mounts /proc, /sys, /dev and /etc/hosts, /etc/hostname and " ++
                "/etc/resolv.conf itself",
        };
    }
};

comptime {
    assert(constants.state_target_bytes_max == 256); // `TargetProblem.sentence` says so.
}

/// The same reasons for a path on the host (the source of a `--bind` or `--secret`).
pub fn host_sentence(problem: TargetProblem) []const u8 {
    assert(@tagName(problem).len > 0);
    return switch (problem) {
        .empty => "the path on the host is empty",
        .relative => "the path on the host must be absolute",
        .too_long => "the path on the host is longer than 256 bytes",
        .bad_part => "the path on the host may not have an empty, '.' or '..' part",
        .bad_character => "the path on the host may not hold a ':', a space or a " ++
            "control character",
        .root => "the host's root directory cannot be mounted in a container",
        // `path_problem` protects nothing; a host path is never refused for this.
        .protected => "the path on the host is one zbx mounts itself",
    };
}

const protected_trees = [_][]const u8{ "/proc", "/sys", "/dev" };
const protected_files = [_][]const u8{ "/etc/hosts", "/etc/hostname", "/etc/resolv.conf" };

/// Null if `path` is a path zbx can mount from or onto: absolute, every part a name, short, and
/// without a byte that would make a value ambiguous. The rules of a host path (a `--bind` or
/// `--secret` source) and of a target in the container, before the target's own protections.
pub fn path_problem(path: []const u8) ?TargetProblem {
    if (path.len == 0) return .empty;
    if (path[0] != '/') return .relative;
    if (path.len > constants.state_target_bytes_max) return .too_long;
    for (path) |byte| {
        if (byte <= ' ' or byte == ':' or byte == 0x7f) return .bad_character;
    }
    if (path.len == 1) return .root;
    var parts = std.mem.splitScalar(u8, path[1..], '/');
    while (parts.next()) |part| {
        if (part.len == 0) return .bad_part;
        if (std.mem.eql(u8, part, ".")) return .bad_part;
        if (std.mem.eql(u8, part, "..")) return .bad_part;
    }
    assert(path[path.len - 1] != '/');
    return null;
}

/// Null if `target` can be a mount point in the container. The rules are the ones the child
/// that makes it applies (`child.zig`, `make_state_target`): it splits at `/` and makes each
/// part, so a part that would mean something else to the kernel is refused here. The same for
/// every kind of mount (`--state`, `--tmpfs`, `--bind`, `--secret`).
pub fn target_problem(target: []const u8) ?TargetProblem {
    if (path_problem(target)) |problem| return problem;
    for (protected_trees) |tree| {
        if (under(target, tree)) return .protected;
    }
    for (protected_files) |file| {
        if (std.mem.eql(u8, target, file)) return .protected;
    }
    return null;
}

/// `path` is `prefix` or below it, part by part (`/devices` is not below `/dev`).
pub fn under(path: []const u8, prefix: []const u8) bool {
    assert(prefix.len > 1);
    assert(prefix[0] == '/');
    if (!std.mem.startsWith(u8, path, prefix)) return false;
    return path.len == prefix.len or path[prefix.len] == '/';
}

/// One `--state`: the volume, where it is mounted, and whether read-only.
pub const Mount = struct {
    name: []const u8,
    target: []const u8,
    read_only: bool,
};

pub const MountProblem = union(enum) {
    /// No colon: a name alone says nowhere to mount it.
    no_target,
    name: NameProblem,
    target: TargetProblem,
};

pub const Parsed = union(enum) {
    ok: Mount,
    problem: MountProblem,
};

pub const read_only_suffix = ":ro";

/// Reads `NAME:PATH` or `NAME:PATH:ro`. The name ends at the first colon; a path holds none.
pub fn parse_mount(value: []const u8) Parsed {
    assert(value.len <= constants.arg_bytes_max);
    const colon = std.mem.indexOfScalar(u8, value, ':') orelse return .{ .problem = .no_target };
    const name = value[0..colon];
    if (name_problem(name)) |problem| return .{ .problem = .{ .name = problem } };
    var target = value[colon + 1 ..];
    var read_only = false;
    if (std.mem.endsWith(u8, target, read_only_suffix)) {
        target = target[0 .. target.len - read_only_suffix.len];
        read_only = true;
    }
    if (target_problem(target)) |problem| return .{ .problem = .{ .target = problem } };
    assert(std.mem.indexOfScalar(u8, target, ':') == null);
    return .{ .ok = .{ .name = name, .target = target, .read_only = read_only } };
}

/// The text of a mount as `--state` takes it, and the run record keeps it.
pub fn mount_text(mount: *const Mount, buffer: *[constants.state_value_bytes_max]u8) []const u8 {
    assert(name_problem(mount.name) == null);
    assert(target_problem(mount.target) == null);
    const suffix = if (mount.read_only) read_only_suffix else "";
    // Cannot fail: the name, the target and the suffix are bounded by the buffer's size.
    const text = std.fmt.bufPrint(buffer, "{s}:{s}{s}", .{ mount.name, mount.target, suffix }) catch
        unreachable; // Same bound.
    assert(text.len > mount.name.len + 1);
    return text;
}

pub const ListProblem = union(enum) {
    too_many,
    /// The index of the second mount of a volume one run already names.
    same_name: u32,
    /// The index of a mount whose target is another's, or inside it, or holds it.
    same_target: u32,
};

/// Null if the mounts of one run go together: at most `state_volumes_max`, a volume once, and
/// no target at or below another (a volume mounted inside another would make a directory in it).
pub fn list_problem(mounts: []const Mount) ?ListProblem {
    if (mounts.len > constants.state_volumes_max) return .too_many;
    for (mounts, 0..) |mount, index| {
        assert(name_problem(mount.name) == null);
        assert(target_problem(mount.target) == null);
        for (mounts[0..index]) |earlier| {
            if (std.mem.eql(u8, earlier.name, mount.name)) return .{ .same_name = @intCast(index) };
            const nested = under(mount.target, earlier.target) or
                under(earlier.target, mount.target);
            if (nested) return .{ .same_target = @intCast(index) };
        }
    }
    return null;
}

// ---- The layout -----------------------------------------------------------------------------

pub const state_suffix = "/zbx/state";
pub const trash_name = ".trash";
pub const data_name = "data";
pub const record_name = "state.zon";
pub const lock_name = "lock";

/// A path of the state directory, NUL-terminated.
pub const Path = struct {
    bytes: [constants.state_volume_path_bytes_max + 1]u8,
    len: u32,

    pub fn text(path: *const Path) [:0]const u8 {
        assert(path.len > 0);
        assert(path.bytes[path.len] == 0);
        return path.bytes[0..path.len :0];
    }
};

/// The state directory: `$XDG_DATA_HOME/zbx/state`, or `~/.local/share/zbx/state`, beside the
/// store and never inside it.
pub const Root = struct {
    path: Path,
    /// Bytes of `path` that must already exist (HOME, or XDG_DATA_HOME): directories are made
    /// from there on.
    existing_len: u32,

    /// False if neither XDG_DATA_HOME nor HOME names an absolute directory that fits.
    pub fn locate(root: *Root, host: Host) bool {
        assert(@intFromPtr(host.vtable) != 0);
        const limit: u32 = constants.store_data_base_bytes_max;
        var base: []const u8 = "";
        if (host.environment("XDG_DATA_HOME", limit)) |data| {
            if (data.len > 0 and data[0] == '/') base = std.mem.trimEnd(u8, data, "/");
        }
        if (base.len > 0) {
            root.set(&.{ base, state_suffix }, @intCast(base.len));
            return true;
        }
        const found = host.environment("HOME", limit - "/.local/share".len) orelse return false;
        if (found.len == 0 or found[0] != '/') return false;
        const home = std.mem.trimEnd(u8, found, "/");
        root.set(&.{ home, "/.local/share", state_suffix }, @intCast(home.len));
        return true;
    }

    /// A root at exactly `path` (absolute, without a trailing slash), whose parent exists.
    pub fn at(root: *Root, path: []const u8) void {
        assert(path.len > 1);
        assert(path[0] == '/');
        root.set(&.{path}, @intCast(std.mem.lastIndexOfScalar(u8, path, '/').?));
    }

    fn set(root: *Root, parts: []const []const u8, existing_len: u32) void {
        join(&root.path, parts);
        root.existing_len = existing_len;
        assert(root.existing_len < root.path.len);
    }

    pub fn text(root: *const Root) [:0]const u8 {
        return root.path.text();
    }

    /// `<root>/<name>`, or `<root>/<name>/<leaf>` when a leaf is given.
    pub fn volume(root: *const Root, out: *Path, name: []const u8, leaf: ?[]const u8) void {
        assert(name.len > 0);
        assert(name.len <= constants.state_name_bytes_max);
        if (leaf) |part| {
            join(out, &.{ root.text(), "/", name, "/", part });
        } else {
            join(out, &.{ root.text(), "/", name });
        }
    }

    /// `<root>/.trash`, or `<root>/.trash/<entry>`.
    pub fn trash(root: *const Root, out: *Path, entry: ?[]const u8) void {
        if (entry) |name| {
            assert(name.len > 0);
            join(out, &.{ root.text(), "/", trash_name, "/", name });
        } else {
            join(out, &.{ root.text(), "/", trash_name });
        }
    }
};

/// Joins `parts` into `out`. The parts are bounded by the caller (a base of at most
/// `store_data_base_bytes_max`, names and fixed words), and the sum fits: a comptime relation in
/// constants.zig.
fn join(out: *Path, parts: []const []const u8) void {
    var length: u32 = 0;
    for (parts) |part| {
        assert(length + part.len <= constants.state_volume_path_bytes_max);
        @memcpy(out.bytes[length..][0..part.len], part);
        length += @intCast(part.len);
    }
    out.bytes[length] = 0;
    out.len = length;
    assert(out.len > 0);
}

// ---- Trash entries --------------------------------------------------------------------------

/// A trash entry's name: the volume's name, `@`, and the second it was removed. `@` is not a
/// name's byte, so the split is never ambiguous.
pub const TrashName = struct {
    bytes: [constants.state_name_bytes_max + 1 + 20]u8,
    len: u32,

    pub fn text(name: *const TrashName) []const u8 {
        assert(name.len > 0);
        return name.bytes[0..name.len];
    }
};

pub fn trash_name_of(name: []const u8, removed: u64, out: *TrashName) void {
    assert(name_problem(name) == null);
    assert(removed < constants.state_time_max);
    // Cannot fail: a name of at most 63 bytes, "@" and at most 20 digits fit the buffer.
    const text = std.fmt.bufPrint(&out.bytes, "{s}@{d}", .{ name, removed }) catch
        unreachable; // Same bound.
    out.len = @intCast(text.len);
}

pub const TrashEntry = struct {
    name: []const u8,
    removed: u64,
};

/// The volume and the time of a trash entry's name; null for anything else in the trash.
pub fn parse_trash_name(entry: []const u8) ?TrashEntry {
    const at = std.mem.lastIndexOfScalar(u8, entry, '@') orelse return null;
    const name = entry[0..at];
    if (name_problem(name) != null) return null;
    const digits = entry[at + 1 ..];
    if (digits.len == 0 or digits.len > 20) return null;
    if (digits[0] == '0' and digits.len > 1) return null; // One spelling per time.
    for (digits) |byte| {
        if (!std.ascii.isDigit(byte)) return null;
    }
    const removed = std.fmt.parseInt(u64, digits, 10) catch return null;
    if (removed >= constants.state_time_max) return null;
    return .{ .name = name, .removed = removed };
}

/// Whether a trash entry removed at `removed` has expired at `now`: the store's expiry.
pub fn expired(removed: u64, now: u64) bool {
    assert(removed < constants.state_time_max);
    return now >= removed + constants.store_trash_seconds;
}

const testing = std.testing;
const repeat = @import("../test_util.zig").repeat;

test "a volume name: the bytes allowed, the first byte, and the length at the bound" {
    // Goal: the boundary where a name stops being one. Method: names at and past each rule.
    try testing.expect(name_problem("pgdata") == null);
    try testing.expect(name_problem("0") == null);
    try testing.expect(name_problem("a.b-c_d9") == null);
    try testing.expect(name_problem(repeat('a', constants.state_name_bytes_max)) == null);
    try testing.expectEqual(NameProblem.too_long, name_problem(repeat('a', 64)).?);
    try testing.expectEqual(NameProblem.empty, name_problem("").?);
    try testing.expectEqual(NameProblem.bad_start, name_problem(".hidden").?);
    try testing.expectEqual(NameProblem.bad_start, name_problem("-x").?);
    try testing.expectEqual(NameProblem.bad_start, name_problem("_x").?);
    try testing.expectEqual(NameProblem.bad_start, name_problem("..").?);
    const slash = name_problem("a/b").?;
    try testing.expectEqual(@as(u8, 1), slash.bad_character);
    try testing.expectEqual(@as(u8, 0), name_problem("Pg").?.bad_character);
    try testing.expectEqual(@as(u8, 1), name_problem("a@1").?.bad_character);
    try testing.expectEqual(@as(u8, 2), name_problem("ab ").?.bad_character);
}

test "a target: absolute, parts that are names, short, and not one zbx mounts itself" {
    // Goal: the rules the child relies on. Method: one target per rule, and the bound.
    try testing.expect(target_problem("/var/lib/postgresql/data") == null);
    try testing.expect(target_problem("/devices") == null);
    try testing.expect(target_problem("/etc/hosts.d") == null);
    try testing.expect(target_problem("/a" ++ repeat('b', 254)) == null);
    try testing.expectEqual(TargetProblem.too_long, target_problem("/a" ++ repeat('b', 255)).?);
    try testing.expectEqual(TargetProblem.empty, target_problem("").?);
    try testing.expectEqual(TargetProblem.relative, target_problem("data").?);
    try testing.expectEqual(TargetProblem.root, target_problem("/").?);
    try testing.expectEqual(TargetProblem.bad_part, target_problem("/a/").?);
    try testing.expectEqual(TargetProblem.bad_part, target_problem("//a").?);
    try testing.expectEqual(TargetProblem.bad_part, target_problem("/a/./b").?);
    try testing.expectEqual(TargetProblem.bad_part, target_problem("/a/../b").?);
    try testing.expectEqual(TargetProblem.bad_character, target_problem("/a:b").?);
    try testing.expectEqual(TargetProblem.bad_character, target_problem("/a\x00b").?);
    try testing.expectEqual(TargetProblem.bad_character, target_problem("/a b").?);
    try testing.expectEqual(TargetProblem.bad_character, target_problem("/a\tb").?);
    try testing.expectEqual(TargetProblem.bad_character, target_problem("/a\x7fb").?);
    try testing.expect(target_problem("/caf\xc3\xa9/\"q\"") == null);
    try testing.expectEqual(TargetProblem.protected, target_problem("/proc").?);
    try testing.expectEqual(TargetProblem.protected, target_problem("/dev/shm").?);
    try testing.expectEqual(TargetProblem.protected, target_problem("/sys/fs").?);
    try testing.expectEqual(TargetProblem.protected, target_problem("/etc/resolv.conf").?);
}

test "a --state value: the name, the target, and a read-only suffix" {
    // Goal: the parse names the part that is wrong. Method: good and bad values.
    const plain = parse_mount("pgdata:/var/lib/postgresql/data").ok;
    try testing.expectEqualStrings("pgdata", plain.name);
    try testing.expectEqualStrings("/var/lib/postgresql/data", plain.target);
    try testing.expect(!plain.read_only);
    const shared = parse_mount("cfg:/etc/app:ro").ok;
    try testing.expect(shared.read_only);
    try testing.expectEqualStrings("/etc/app", shared.target);
    try testing.expectEqual(MountProblem.no_target, parse_mount("pgdata").problem);
    try testing.expectEqual(NameProblem.empty, parse_mount(":/x").problem.name);
    try testing.expectEqual(TargetProblem.empty, parse_mount("a:").problem.target);
    try testing.expectEqual(TargetProblem.empty, parse_mount("a::ro").problem.target);
    try testing.expectEqual(TargetProblem.bad_character, parse_mount("a:/x:rw").problem.target);
    try testing.expectEqual(TargetProblem.relative, parse_mount("a:x").problem.target);
    var buffer: [constants.state_value_bytes_max]u8 = undefined;
    try testing.expectEqualStrings("cfg:/etc/app:ro", mount_text(&shared, &buffer));
    const again = parse_mount(mount_text(&plain, &buffer)).ok;
    try testing.expectEqualStrings(plain.target, again.target);
}

test "the mounts of one run: a volume once, targets apart, and at most eight" {
    // Goal: the list rules. Method: each conflict, and the bound and one past it.
    const a: Mount = .{ .name = "a", .target = "/data", .read_only = false };
    const b: Mount = .{ .name = "b", .target = "/data/sub", .read_only = true };
    const c: Mount = .{ .name = "c", .target = "/database", .read_only = false };
    const a_again: Mount = .{ .name = "a", .target = "/other", .read_only = true };
    try testing.expect(list_problem(&.{ a, c }) == null);
    try testing.expectEqual(@as(u32, 1), list_problem(&.{ a, b }).?.same_target);
    try testing.expectEqual(@as(u32, 1), list_problem(&.{ b, a }).?.same_target);
    try testing.expectEqual(@as(u32, 1), list_problem(&.{ a, a_again }).?.same_name);
    var many: [constants.state_volumes_max + 1]Mount = undefined;
    const names = [_][]const u8{ "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8" };
    const targets = [_][]const u8{ "/t0", "/t1", "/t2", "/t3", "/t4", "/t5", "/t6", "/t7", "/t8" };
    for (&many, 0..) |*mount, index| {
        mount.* = .{ .name = names[index], .target = targets[index], .read_only = false };
    }
    try testing.expect(list_problem(many[0..constants.state_volumes_max]) == null);
    try testing.expectEqual(ListProblem.too_many, list_problem(&many).?);
}

test "the layout follows XDG_DATA_HOME, else HOME, and names every path" {
    // Goal: where a volume lives. Method: both environments and each path.
    const HostSim = @import("../host_sim.zig").HostSim;
    var sim: HostSim = undefined;
    sim.init(1, &.{});
    sim.environment_variables = &.{.{ .name = "HOME", .value = "/home/alice/" }};
    var root: Root = undefined;
    try testing.expect(root.locate(sim.interface()));
    try testing.expectEqualStrings("/home/alice/.local/share/zbx/state", root.text());
    try testing.expectEqual(@as(u32, "/home/alice".len), root.existing_len);
    var path: Path = undefined;
    root.volume(&path, "pgdata", data_name);
    try testing.expectEqualStrings("/home/alice/.local/share/zbx/state/pgdata/data", path.text());
    root.trash(&path, "pgdata@5");
    const trash = "/home/alice/.local/share/zbx/state/.trash/pgdata@5";
    try testing.expectEqualStrings(trash, path.text());
    sim.environment_variables = &.{.{ .name = "XDG_DATA_HOME", .value = "/data" }};
    try testing.expect(root.locate(sim.interface()));
    try testing.expectEqualStrings("/data/zbx/state", root.text());
    sim.environment_variables = &.{.{ .name = "HOME", .value = "relative" }};
    try testing.expect(!root.locate(sim.interface()));
}

test "trash names: one spelling per entry, and the store's expiry" {
    // Goal: a name and a time round-trip, and nothing else reads as an entry. Method: each.
    var name: TrashName = undefined;
    trash_name_of("pg.data", 1_700_000_000, &name);
    try testing.expectEqualStrings("pg.data@1700000000", name.text());
    const entry = parse_trash_name(name.text()).?;
    try testing.expectEqualStrings("pg.data", entry.name);
    try testing.expectEqual(@as(u64, 1_700_000_000), entry.removed);
    try testing.expect(parse_trash_name("pgdata") == null);
    try testing.expect(parse_trash_name("pgdata@") == null);
    try testing.expect(parse_trash_name("pgdata@01") == null);
    try testing.expect(parse_trash_name("pgdata@1x") == null);
    try testing.expect(parse_trash_name("@1") == null);
    try testing.expect(parse_trash_name("pgdata@1099511627776") == null); // 2^40.
    try testing.expect(parse_trash_name("pgdata@1099511627775") != null);
    try testing.expect(!expired(100, 100 + constants.store_trash_seconds - 1));
    try testing.expect(expired(100, 100 + constants.store_trash_seconds));
}
