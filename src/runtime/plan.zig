//! The plan: everything a container run does, as a fixed list of steps built by a pure function
//! from the run's input (docs/briefs/M1-shell.md, "Setup as a plan").
//!
//! The list interleaves the two processes in the order things happen: the parent creates the
//! pipes and the child (`spawn`), writes the id maps and lets the child go; the child sets up the
//! container and runs the command; the parent collects the child's report and waits. Each step
//! belongs to one side (`side_of`) and is one call into `host.zig` (a few are two tiny ones), so
//! the simulator can fail exactly one step and the diagnostic can name it by its index and kind.
//!
//! Everything the child needs is made here, in the parent, before `spawn`: every path, the map
//! lines, the hostname, and the whole exec image (argv, environment and the path candidates).
//! The child therefore never allocates or formats text. The plan holds pointers into itself
//! (the exec image), so it is built in place and never moved or copied.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const spec = @import("spec.zig");

pub const Side = enum { parent, child };

/// What a step does. Parent steps first in the declaration, then the child's.
pub const Kind = enum {
    // The parent.
    make_pipes,
    spawn,
    deny_setgroups,
    write_gid_map,
    write_uid_map,
    release_child,
    await_report,
    reap,
    // The child.
    die_with_parent,
    await_release,
    set_hostname,
    make_mounts_private,
    bind_rootfs,
    make_proc_dir,
    mount_proc,
    make_dev_dir,
    mount_dev,
    create_device_file,
    bind_device,
    make_shm_dir,
    mount_shm,
    make_pts_dir,
    mount_pts,
    link_dev,
    enter_rootfs,
    pivot_root,
    detach_old_root,
    enter_new_root,
    seal_descriptors,
    exec,
};

pub fn side_of(kind: Kind) Side {
    const side: Side = switch (kind) {
        .make_pipes, .spawn, .deny_setgroups, .write_gid_map, .write_uid_map => .parent,
        .release_child, .await_report, .reap => .parent,
        else => .child,
    };
    // The kinds are declared parent first, so the order of the enum says which side a kind is.
    assert((side == .parent) == (@backingInt(kind) <= @backingInt(Kind.reap)));
    return side;
}

/// The devices bound from the host into the container's `/dev`.
pub const devices = [constants.container_devices_count][]const u8{
    "null", "zero", "full", "random", "urandom", "tty",
};

pub const Link = struct {
    name: []const u8,
    target: []const u8,
};

/// The symlinks of the container's `/dev`. `ptmx` points into the private devpts.
pub const links = [constants.container_links_count]Link{
    .{ .name = "fd", .target = "/proc/self/fd" },
    .{ .name = "stdin", .target = "/proc/self/fd/0" },
    .{ .name = "stdout", .target = "/proc/self/fd/1" },
    .{ .name = "stderr", .target = "/proc/self/fd/2" },
    .{ .name = "ptmx", .target = "pts/ptmx" },
};

/// Steps of every plan: the eight of the parent, nineteen of the child that happen once, and
/// two per device and one per link.
pub const steps_count: u32 = 8 + 19 + 2 * constants.container_devices_count +
    constants.container_links_count;

/// A string stored in the plan's text area. NUL-terminated there, `len` without the NUL.
pub const Text = struct {
    offset: u32,
    len: u32,
};

pub const Step = struct {
    kind: Kind,
    /// The step's main text: a path, or for the map steps the bytes to write.
    target: Text,
    /// A second text: the source of a bind, the destination of a link.
    source: Text,
    /// Which device or link the step is about.
    index: u8,
    /// A failure of this step is noted and the run goes on (the devpts mount).
    tolerant: bool,
};

pub const Input = struct {
    rootfs: []const u8,
    name: []const u8,
    command: []const []const u8,
    term: ?[]const u8,
    /// The user and group ids of zbx itself, the ones the container's root maps to.
    uid: u32,
    gid: u32,
};

const empty_text: Text = .{ .offset = 0, .len = 0 };

pub const Plan = struct {
    steps: [constants.plan_steps_max]Step,
    count: u32,
    paths: [constants.plan_paths_bytes_max]u8,
    paths_len: u32,
    name: Text,
    /// Where the command is looked for: its own path if it has a slash, else one path per
    /// directory of the container's PATH.
    candidates: [constants.container_path_dirs_count]Text,
    candidates_count: u32,
    strings: [constants.exec_strings_bytes_max]u8,
    strings_len: u32,
    argv: [constants.command_words_count_max + 1]?[*:0]const u8,
    envp: [constants.environment_count_max + 1]?[*:0]const u8,

    /// Builds the plan in place. The input must have passed the checks in `spec.zig`.
    pub fn build(plan: *Plan, input: *const Input) void {
        assert(spec.rootfs_problem(input.rootfs) == null);
        assert(spec.name_problem(input.name) == null);
        assert(spec.command_problem(input.command) == null);
        plan.count = 0;
        plan.paths_len = 0;
        plan.strings_len = 0;
        plan.candidates_count = 0;
        // Offset 0 is the empty text, so a step with nothing to say has a valid reference.
        assert(plan.add_text(&.{""}).offset == 0);
        plan.name = plan.add_text(&.{input.name});
        plan.build_exec_image(input);
        plan.push_parent_start(input);
        plan.push_child_steps(input.rootfs);
        plan.push(.await_report, empty_text, empty_text, 0);
        plan.push(.reap, empty_text, empty_text, 0);
        assert(plan.count == steps_count);
        plan.check();
    }

    /// Structural invariants of a built plan, also checked by the tests and the fuzzer.
    pub fn check(plan: *const Plan) void {
        assert(plan.count == steps_count);
        assert(plan.count <= constants.plan_steps_max);
        assert(plan.steps[0].kind == .make_pipes);
        assert(plan.steps[1].kind == .spawn);
        assert(plan.steps[plan.count - 1].kind == .reap);
        assert(plan.steps[plan.count - 2].kind == .await_report);
        // The child's steps are one contiguous run, between `release_child` and `await_report`.
        const first_child = 6;
        assert(plan.steps[first_child - 1].kind == .release_child);
        for (plan.steps[0..first_child]) |step| assert(side_of(step.kind) == .parent);
        for (plan.steps[first_child .. plan.count - 2]) |step| assert(side_of(step.kind) == .child);
        assert(plan.steps[plan.count - 3].kind == .exec);
        // The exec image points into the plan itself: a copy of the plan would break it.
        const first_argument = plan.argv[0].?;
        assert(@intFromPtr(first_argument) >= @intFromPtr(&plan.strings[0]));
        assert(@intFromPtr(first_argument) < @intFromPtr(&plan.strings[0]) + plan.strings.len);
        assert(plan.candidates_count > 0);
    }

    pub fn text(plan: *const Plan, ref: Text) [:0]const u8 {
        assert(ref.offset + ref.len < plan.paths_len);
        assert(plan.paths[ref.offset + ref.len] == 0);
        return plan.paths[ref.offset..][0..ref.len :0];
    }

    pub fn hostname(plan: *const Plan) []const u8 {
        const name = plan.text(plan.name);
        assert(name.len > 0);
        assert(name.len <= constants.container_name_bytes_max);
        return name;
    }

    pub fn candidate_slice(plan: *const Plan) []const Text {
        assert(plan.candidates_count > 0);
        assert(plan.candidates_count <= plan.candidates.len);
        return plan.candidates[0..plan.candidates_count];
    }

    /// Appends the parts as one NUL-terminated text. There is always room: the inputs are
    /// bounded by `spec.zig` and the arena by a comptime relationship in `constants.zig`.
    fn add_text(plan: *Plan, parts: []const []const u8) Text {
        var length: u32 = 0;
        for (parts) |part| length += @intCast(part.len);
        assert(plan.paths_len + length + 1 <= plan.paths.len);
        const offset = plan.paths_len;
        var at = offset;
        for (parts) |part| {
            @memcpy(plan.paths[at..][0..part.len], part);
            at += @intCast(part.len);
        }
        plan.paths[at] = 0;
        plan.paths_len = at + 1;
        assert(at - offset == length);
        return .{ .offset = offset, .len = length };
    }

    fn push(plan: *Plan, kind: Kind, target: Text, source: Text, index: u8) void {
        assert(plan.count < constants.plan_steps_max);
        assert(target.offset + target.len < plan.paths_len);
        assert(source.offset + source.len < plan.paths_len);
        plan.steps[plan.count] = .{
            .kind = kind,
            .target = target,
            .source = source,
            .index = index,
            .tolerant = kind == .mount_pts,
        };
        plan.count += 1;
    }

    fn push_parent_start(plan: *Plan, input: *const Input) void {
        var line: [constants.id_map_line_bytes_max]u8 = undefined;
        plan.push(.make_pipes, empty_text, empty_text, 0);
        plan.push(.spawn, empty_text, empty_text, 0);
        plan.push(.deny_setgroups, plan.add_text(&.{"deny"}), empty_text, 0);
        // Cannot fail: "0 4294967295 1\n" is 15 bytes and the buffer is 32.
        const gid_line = std.fmt.bufPrint(&line, "0 {d} 1\n", .{input.gid}) catch unreachable;
        plan.push(.write_gid_map, plan.add_text(&.{gid_line}), empty_text, 0);
        // Cannot fail: same bound as above.
        const uid_line = std.fmt.bufPrint(&line, "0 {d} 1\n", .{input.uid}) catch unreachable;
        plan.push(.write_uid_map, plan.add_text(&.{uid_line}), empty_text, 0);
        plan.push(.release_child, empty_text, empty_text, 0);
        assert(plan.count == 6);
        assert(side_of(plan.steps[plan.count - 1].kind) == .parent);
    }

    fn push_child_steps(plan: *Plan, rootfs_text: []const u8) void {
        assert(plan.count == 6); // After the parent's start.
        assert(rootfs_text.len > 0);
        const rootfs = plan.add_text(&.{rootfs_text});
        const dev = plan.add_text(&.{ rootfs_text, "/dev" });
        const proc = plan.add_text(&.{ rootfs_text, "/proc" });
        plan.push(.die_with_parent, empty_text, empty_text, 0);
        plan.push(.await_release, empty_text, empty_text, 0);
        plan.push(.set_hostname, plan.name, empty_text, 0);
        plan.push(.make_mounts_private, plan.add_text(&.{"/"}), empty_text, 0);
        plan.push(.bind_rootfs, rootfs, rootfs, 0);
        plan.push(.make_proc_dir, proc, empty_text, 0);
        plan.push(.mount_proc, proc, empty_text, 0);
        plan.push(.make_dev_dir, dev, empty_text, 0);
        plan.push(.mount_dev, dev, empty_text, 0);
        plan.push_devices(rootfs_text);
        plan.push_dev_mounts(rootfs_text);
        plan.push_links(rootfs_text);
        const here = plan.add_text(&.{"."});
        plan.push(.enter_rootfs, rootfs, empty_text, 0);
        plan.push(.pivot_root, here, here, 0);
        plan.push(.detach_old_root, here, empty_text, 0);
        plan.push(.enter_new_root, plan.add_text(&.{"/"}), empty_text, 0);
        plan.push(.seal_descriptors, empty_text, empty_text, 0);
        plan.push(.exec, empty_text, empty_text, 0);
        assert(plan.steps[plan.count - 1].kind == .exec);
        assert(plan.count == steps_count - 2); // Only the parent's two last steps remain.
    }

    fn push_devices(plan: *Plan, rootfs: []const u8) void {
        const start = plan.count;
        defer assert(plan.count == start + 2 * constants.container_devices_count);
        for (devices, 0..) |name, index| {
            const inside = plan.add_text(&.{ rootfs, "/dev/", name });
            const outside = plan.add_text(&.{ "/dev/", name });
            plan.push(.create_device_file, inside, empty_text, @intCast(index));
            plan.push(.bind_device, inside, outside, @intCast(index));
        }
    }

    fn push_dev_mounts(plan: *Plan, rootfs: []const u8) void {
        const start = plan.count;
        defer assert(plan.count == start + 4);
        const shm = plan.add_text(&.{ rootfs, "/dev/shm" });
        const pts = plan.add_text(&.{ rootfs, "/dev/pts" });
        plan.push(.make_shm_dir, shm, empty_text, 0);
        plan.push(.mount_shm, shm, empty_text, 0);
        plan.push(.make_pts_dir, pts, empty_text, 0);
        plan.push(.mount_pts, pts, empty_text, 0);
    }

    fn push_links(plan: *Plan, rootfs: []const u8) void {
        const start = plan.count;
        defer assert(plan.count == start + constants.container_links_count);
        for (links, 0..) |link, index| {
            const inside = plan.add_text(&.{ rootfs, "/dev/", link.name });
            const target = plan.add_text(&.{link.target});
            plan.push(.link_dev, inside, target, @intCast(index));
        }
    }

    // ---- The exec image ----

    fn add_string(plan: *Plan, parts: []const []const u8) [*:0]const u8 {
        var length: u32 = 0;
        for (parts) |part| length += @intCast(part.len);
        assert(length <= constants.exec_strings_bytes_max);
        assert(plan.strings_len + length + 1 <= plan.strings.len);
        const start = plan.strings_len;
        var at = start;
        for (parts) |part| {
            @memcpy(plan.strings[at..][0..part.len], part);
            at += @intCast(part.len);
        }
        plan.strings[at] = 0;
        plan.strings_len = at + 1;
        assert(at - start == length);
        return @ptrCast(&plan.strings[start]);
    }

    fn build_exec_image(plan: *Plan, input: *const Input) void {
        for (input.command, 0..) |word, index| plan.argv[index] = plan.add_string(&.{word});
        plan.argv[input.command.len] = null;
        var count: usize = 0;
        const path_variable = "PATH=" ++ constants.container_path;
        plan.envp[count] = plan.add_string(&.{path_variable});
        count += 1;
        plan.envp[count] = plan.add_string(&.{"HOME=/root"});
        count += 1;
        plan.envp[count] = plan.add_string(&.{ "HOSTNAME=", input.name });
        count += 1;
        if (input.term) |term| {
            assert(term.len <= constants.term_bytes_max);
            plan.envp[count] = plan.add_string(&.{ "TERM=", term });
            count += 1;
        }
        plan.envp[count] = null;
        assert(count <= constants.environment_count_max);
        plan.build_candidates(input.command[0]);
    }

    /// A program with a slash in its name is run as named; any other is looked up in the
    /// container's PATH, in order, as a shell does.
    fn build_candidates(plan: *Plan, program: []const u8) void {
        assert(program.len > 0);
        if (std.mem.indexOfScalar(u8, program, '/') != null) {
            plan.candidates[0] = plan.add_text(&.{program});
            plan.candidates_count = 1;
            return;
        }
        var directories = std.mem.splitScalar(u8, constants.container_path, ':');
        while (directories.next()) |directory| {
            plan.candidates[plan.candidates_count] = plan.add_text(&.{ directory, "/", program });
            plan.candidates_count += 1;
        }
        assert(plan.candidates_count == constants.container_path_dirs_count);
    }
};

// ---- Naming a step ----

/// A short phrase for the step, for the cause line of a diagnostic: "mounting a fresh /proc".
/// Formats into `buffer`, so it is for the parent only.
pub fn describe(step: *const Step, buffer: []u8) []const u8 {
    assert(buffer.len >= 128);
    const name = switch (step.kind) {
        .create_device_file, .bind_device => devices[step.index],
        .link_dev => links[step.index].name,
        else => "",
    };
    const phrase: []const u8 = switch (step.kind) {
        .make_pipes => "creating the pipes between zbx and the container",
        .spawn => "creating the container's namespaces",
        .deny_setgroups => "denying setgroups in the container's user namespace",
        .write_gid_map => "writing the container's gid map",
        .write_uid_map => "writing the container's uid map",
        .release_child => "letting the container continue",
        .await_report => "waiting for the container to start its command",
        .reap => "waiting for the container to end",
        .die_with_parent => "asking the kernel to end the container if zbx dies",
        .await_release => "waiting for zbx to write the container's id maps",
        .set_hostname => "setting the container's hostname",
        .make_mounts_private => "making the container's mounts private",
        .bind_rootfs => "bind-mounting the rootfs onto itself",
        .make_proc_dir => "creating /proc in the rootfs",
        .mount_proc => "mounting a fresh /proc",
        .make_dev_dir => "creating /dev in the rootfs",
        .mount_dev => "mounting a tmpfs on /dev",
        .make_shm_dir => "creating /dev/shm",
        .mount_shm => "mounting a tmpfs on /dev/shm",
        .make_pts_dir => "creating /dev/pts",
        .mount_pts => "mounting devpts on /dev/pts",
        .enter_rootfs => "entering the rootfs directory",
        .pivot_root => "pivot_root into the rootfs",
        .detach_old_root => "unmounting the old root",
        .enter_new_root => "changing to the new root",
        .seal_descriptors => "closing the descriptors the command must not inherit",
        .exec => "starting the command",
        .create_device_file => "creating the mount point /dev/",
        .bind_device => "bind-mounting /dev/",
        .link_dev => "creating the link /dev/",
    };
    return std.fmt.bufPrint(buffer, "{s}{s}", .{ phrase, name }) catch phrase;
}

comptime {
    assert(steps_count <= constants.plan_steps_max);
    assert(devices.len == constants.container_devices_count);
    assert(links.len == constants.container_links_count);
    // The failure record names a step in one byte, and a step's kind must be nameable too.
    assert(steps_count <= std.math.maxInt(u8));
    assert(std.meta.fieldNames(Kind).len <= 64);
}

const testing = std.testing;

fn test_input(command: []const []const u8) Input {
    return .{
        .rootfs = "/srv/alpine",
        .name = "web-1",
        .command = command,
        .term = "xterm",
        .uid = 1000,
        .gid = 1001,
    };
}

test "the plan has the steps in order, parent and child interleaved, and all within bounds" {
    // Goal: the shape every other module relies on. Method: build once and walk it; each step
    // belongs to the side the order says, the device and link steps repeat per device and link,
    // and only the devpts mount is tolerant.
    var plan: Plan = undefined;
    const input = test_input(&.{ "/bin/sh", "-c", "true" });
    plan.build(&input);
    try testing.expectEqual(steps_count, plan.count);
    try testing.expectEqual(@as(u32, 44), plan.count);
    var tolerant: u32 = 0;
    var devices_seen: u32 = 0;
    var links_seen: u32 = 0;
    for (plan.steps[0..plan.count]) |step| {
        if (step.tolerant) {
            tolerant += 1;
            try testing.expectEqual(Kind.mount_pts, step.kind);
        }
        if (step.kind == .bind_device) devices_seen += 1;
        if (step.kind == .link_dev) links_seen += 1;
    }
    try testing.expectEqual(@as(u32, 1), tolerant);
    try testing.expectEqual(constants.container_devices_count, devices_seen);
    try testing.expectEqual(constants.container_links_count, links_seen);
    // The mounts come in the order the kernel needs: private, bind, proc, dev, ... pivot, exec.
    const order = [_]Kind{
        .make_mounts_private, .bind_rootfs, .mount_proc, .mount_dev,
        .mount_shm,           .mount_pts,   .pivot_root, .exec,
    };
    var at: usize = 0;
    for (plan.steps[0..plan.count]) |step| {
        if (at < order.len and step.kind == order[at]) at += 1;
    }
    try testing.expectEqual(order.len, at);
}

test "the plan's paths and texts are what the kernel will be given" {
    // Goal: every derived path, the map lines with the right ids, and the hostname.
    var plan: Plan = undefined;
    const input = test_input(&.{"sh"});
    plan.build(&input);
    try testing.expectEqualStrings("web-1", plan.hostname());
    var seen_bind = false;
    for (plan.steps[0..plan.count]) |step| {
        switch (step.kind) {
            .deny_setgroups => try testing.expectEqualStrings("deny", plan.text(step.target)),
            .write_gid_map => try testing.expectEqualStrings("0 1001 1\n", plan.text(step.target)),
            .write_uid_map => try testing.expectEqualStrings("0 1000 1\n", plan.text(step.target)),
            .mount_proc => {
                try testing.expectEqualStrings("/srv/alpine/proc", plan.text(step.target));
            },
            .mount_pts => {
                try testing.expectEqualStrings("/srv/alpine/dev/pts", plan.text(step.target));
            },
            .bind_device => {
                if (step.index == 0) {
                    try testing.expectEqualStrings("/srv/alpine/dev/null", plan.text(step.target));
                    try testing.expectEqualStrings("/dev/null", plan.text(step.source));
                    seen_bind = true;
                }
            },
            .pivot_root => {
                try testing.expectEqualStrings(".", plan.text(step.target));
                try testing.expectEqualStrings(".", plan.text(step.source));
            },
            .link_dev => {
                if (step.index == 4) {
                    try testing.expectEqualStrings("/srv/alpine/dev/ptmx", plan.text(step.target));
                    try testing.expectEqualStrings("pts/ptmx", plan.text(step.source));
                }
            },
            else => {},
        }
    }
    try testing.expect(seen_bind);
}

test "the exec image is a clean environment, and a bare program is looked up in PATH" {
    // Goal: the command gets exactly PATH, HOME, HOSTNAME and TERM, and the candidates are the
    // PATH directories in order for a bare name, or the one path for a name with a slash.
    var plan: Plan = undefined;
    var input = test_input(&.{ "ls", "-l" });
    plan.build(&input);
    try testing.expectEqualStrings("ls", std.mem.span(plan.argv[0].?));
    try testing.expectEqualStrings("-l", std.mem.span(plan.argv[1].?));
    try testing.expect(plan.argv[2] == null);
    const path_variable = "PATH=" ++ constants.container_path;
    try testing.expectEqualStrings(path_variable, std.mem.span(plan.envp[0].?));
    try testing.expectEqualStrings("HOME=/root", std.mem.span(plan.envp[1].?));
    try testing.expectEqualStrings("HOSTNAME=web-1", std.mem.span(plan.envp[2].?));
    try testing.expectEqualStrings("TERM=xterm", std.mem.span(plan.envp[3].?));
    try testing.expect(plan.envp[4] == null);
    try testing.expectEqual(constants.container_path_dirs_count, plan.candidates_count);
    try testing.expectEqualStrings("/usr/local/sbin/ls", plan.text(plan.candidates[0]));
    try testing.expectEqualStrings("/bin/ls", plan.text(plan.candidates[5]));

    input.term = null;
    input.command = &.{"./tool"};
    plan.build(&input);
    try testing.expect(plan.envp[3] == null);
    try testing.expectEqual(@as(u32, 1), plan.candidates_count);
    try testing.expectEqualStrings("./tool", plan.text(plan.candidates[0]));
}

test "the longest rootfs, name, command and ids still build a valid plan" {
    // Goal: the bounds in constants.zig are enough for the worst case at once, and every path
    // derived from the longest rootfs is a valid path.
    const repeat = @import("../test_util.zig").repeat;
    var plan: Plan = undefined;
    const word = repeat('w', constants.command_word_bytes_max);
    const words: [8][]const u8 = @splat(word);
    const input: Input = .{
        .rootfs = repeat('r', constants.rootfs_bytes_max),
        .name = repeat('n', constants.container_name_bytes_max),
        .command = &words,
        .term = repeat('t', constants.term_bytes_max),
        .uid = std.math.maxInt(u32) - 1,
        .gid = std.math.maxInt(u32) - 1,
    };
    plan.build(&input);
    for (plan.steps[0..plan.count]) |step| {
        try testing.expect(plan.text(step.target).len <= constants.path_bytes_max);
        try testing.expect(plan.text(step.source).len <= constants.path_bytes_max);
    }
    try testing.expect(plan.paths_len <= constants.plan_paths_bytes_max);
    try testing.expect(plan.strings_len <= constants.exec_strings_bytes_max);
}

test "describe names every step and adds the device or link" {
    // Goal: no step lacks a phrase for its diagnostic, and the indexed ones say which device.
    var plan: Plan = undefined;
    const input = test_input(&.{"sh"});
    plan.build(&input);
    var buffer: [160]u8 = undefined;
    for (plan.steps[0..plan.count]) |*step| {
        const phrase = describe(step, &buffer);
        try testing.expect(phrase.len > 10);
        if (step.kind == .bind_device and step.index == 5) {
            try testing.expectEqualStrings("bind-mounting /dev/tty", phrase);
        }
        if (step.kind == .link_dev and step.index == 1) {
            try testing.expectEqualStrings("creating the link /dev/stdin", phrase);
        }
    }
}
