//! The plan of `zbx exec` (docs/briefs/M6b-dev-loop.md, slice 3): a fixed list of steps built by
//! a pure function, like a run's (`plan.zig`), over three processes.
//!
//!   - The parent (`zbx`) opens the container's namespace files, makes the pipes and, with a
//!     terminal, the pseudo-terminal, and forks the joiner. It learns the command's pid from the
//!     joiner, reaps the joiner, puts the command in the container's cgroup while the command
//!     waits, lets it go, and reads its report.
//!   - The joiner, a plain fork of the parent, joins the container's namespaces with `setns`:
//!     user first (zbx owns it, so this needs no privilege, and it gives the capabilities the
//!     others need), then IPC, UTS, network, PID and mount last (it changes the root that paths
//!     are read from). Joining a PID namespace changes only where children are born, so it forks
//!     the command (`CLONE_PARENT`: the command is the parent's child, which waits for it) and
//!     reports the command's pid.
//!   - The command, born in all the container's namespaces, waits for the go-ahead, takes the
//!     terminal, enters the working directory, and then in the order the brief and the kernel
//!     need: the container's capability set, the user, `no_new_privs`, the container's seccomp
//!     filter, and `execve`.
//!
//! Everything the joiner and the command need (the exec image, the working directory) is made
//! here, in the parent, before the fork: they never allocate or format text. A failure is a
//! four-byte record (`sync.zig`) that names the step.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const spec = @import("spec.zig");

pub const Side = enum { parent, joiner, command };

pub const Kind = enum {
    // The parent.
    make_pipes,
    /// One per namespace (`Step.namespace`); a namespace that is the host's has no step.
    open_namespace,
    /// With a terminal: the pseudo-terminal, and its window size copied from zbx's.
    open_terminal,
    spawn_joiner,
    /// Reads the joiner's first record: the command's pid, or why the joiner failed.
    await_forked,
    reap_joiner,
    /// With a cgroup: the command is put in it before it may run.
    join_cgroup,
    release_command,
    await_report,
    reap,
    // The joiner.
    joiner_die_with_parent,
    /// One per namespace, in `host_mod.NamespaceKind` order (`Step.namespace`).
    join_namespace,
    fork_command,
    // The command.
    die_with_parent,
    await_release,
    /// With a terminal: a session of its own on the peer, which is its three streams.
    attach_terminal,
    enter_workdir,
    seal_descriptors,
    restrict_capabilities,
    clear_ambient,
    /// With a user: becomes it, then asks again to die with zbx (a change of user clears it).
    set_user,
    rearm_death_signal,
    set_no_new_privs,
    install_seccomp,
    exec,
};

pub fn side_of(kind: Kind) Side {
    const side: Side = switch (kind) {
        .make_pipes, .open_namespace, .open_terminal, .spawn_joiner, .await_forked => .parent,
        .reap_joiner, .join_cgroup, .release_command, .await_report, .reap => .parent,
        .joiner_die_with_parent, .join_namespace, .fork_command => .joiner,
        else => .command,
    };
    // The kinds are declared by side, in this order.
    if (side == .parent) assert(@backingInt(kind) <= @backingInt(Kind.reap));
    if (side == .command) assert(@backingInt(kind) > @backingInt(Kind.fork_command));
    return side;
}

pub const Step = struct {
    kind: Kind,
    /// For the namespace steps.
    namespace: host_mod.NamespaceKind,
};

/// A string in the plan's text area, NUL-terminated there; `len` without the NUL.
pub const Text = struct {
    offset: u32,
    len: u32,
};

/// The steps the plan can have: the parent's seven, six namespaces, the terminal and the cgroup;
/// the joiner's two and six namespaces; the command's nine, the terminal and two for a user.
pub const steps_max: u32 = (7 + 6 + 2) + (2 + 6) + (9 + 1 + 2);

/// The variables the command's environment can hold: the container's (its defaults and the
/// image's and the run's), the `-e` of the exec, and TERM.
pub const env_count_max: u32 = constants.environment_count_max + constants.env_vars_count_max +
    constants.run_env_count_max + 1;

/// The container's environment as `/proc/<pid>/environ` gives it: what a run could start with.
pub const environ_bytes_max: u32 = constants.exec_strings_bytes_max;

/// Room for the exec image: the command, the container's environment, the `-e` of the exec and
/// TERM.
pub const strings_bytes_max: u32 = constants.exec_strings_bytes_max + environ_bytes_max +
    constants.run_env_count_max * (constants.env_name_bytes_max + constants.env_value_bytes_max +
        2) + constants.term_bytes_max + 8;

/// Room for the candidates of the program's path and the working directory.
pub const paths_bytes_max: u32 = 32 * 1024;

pub const Input = struct {
    command: []const []const u8,
    /// The container's environment, `NAME=VALUE` strings each ended by a NUL, as read.
    environ: []const u8,
    /// The `-e` of the exec: each replaces a variable of the same name.
    env: []const spec.Label,
    /// TERM for a command with a terminal whose environment has none; null: none added.
    term: ?[]const u8,
    /// The directory the command starts in, absolute; empty: the container's own
    /// (`container_workdir`).
    workdir: []const u8,
    /// The user and group the command runs as; null (or 0 and 0) leaves it root.
    user: ?spec.User,
    /// Which namespaces are joined (one bit per `host_mod.NamespaceKind`; the user namespace's
    /// is always set).
    namespaces: u8,
    terminal: bool,
    /// The command is put in the container's cgroup.
    cgroup: bool,
};

pub const Plan = struct {
    steps: [steps_max]Step,
    count: u32,
    namespaces: u8,
    terminal: bool,
    cgroup: bool,
    has_user: bool,
    user_uid: u32,
    user_gid: u32,
    workdir: Text,
    paths: [paths_bytes_max]u8,
    paths_len: u32,
    candidates: [constants.candidates_max]Text,
    candidates_count: u32,
    strings: [strings_bytes_max]u8,
    strings_len: u32,
    argv: [constants.command_words_count_max + 1]?[*:0]const u8,
    envp: [env_count_max + 1]?[*:0]const u8,
    envp_count: u32,

    /// Builds the plan in place. The input must have passed `check_input`.
    pub fn build(plan: *Plan, input: *const Input) void {
        assert(check_input(input) == null);
        assert(input.namespaces & namespace_bit(.user) != 0);
        plan.count = 0;
        plan.namespaces = input.namespaces;
        plan.terminal = input.terminal;
        plan.cgroup = input.cgroup;
        plan.has_user = if (input.user) |user| user.uid != 0 or user.gid != 0 else false;
        plan.user_uid = if (input.user) |user| user.uid else 0;
        plan.user_gid = if (input.user) |user| user.gid else 0;
        plan.paths_len = 0;
        plan.strings_len = 0;
        plan.candidates_count = 0;
        assert(plan.add_text(&.{""}).offset == 0);
        const workdir = if (input.workdir.len > 0) input.workdir else container_workdir;
        plan.workdir = plan.add_text(&.{workdir});
        plan.build_exec_image(input);
        plan.push_parent();
        plan.push_joiner();
        plan.push_command();
        plan.push(.await_report, .user);
        plan.push(.reap, .user);
        plan.check();
    }

    /// Structural invariants of a built plan, also checked by the tests.
    pub fn check(plan: *const Plan) void {
        assert(plan.count <= steps_max);
        assert(plan.count == plan.steps_expected());
        assert(plan.steps[0].kind == .make_pipes);
        assert(plan.steps[plan.count - 1].kind == .reap);
        assert(plan.steps[plan.count - 2].kind == .await_report);
        assert(plan.steps[plan.count - 3].kind == .exec);
        var previous: Side = .parent;
        for (plan.steps[0 .. plan.count - 2]) |step| {
            const side = side_of(step.kind);
            // The sides come in one run each: the parent's start, the joiner's, the command's.
            assert(@backingInt(side) >= @backingInt(previous));
            previous = side;
        }
        assert(plan.argv[0] != null);
        assert(plan.candidates_count > 0);
        assert(plan.envp[plan.envp_count] == null);
    }

    pub fn steps_expected(plan: *const Plan) u32 {
        assert(plan.count <= steps_max);
        assert(plan.namespaces & namespace_bit(.user) != 0);
        const joined: u32 = @popCount(plan.namespaces);
        const terminal: u32 = @intFromBool(plan.terminal);
        const parent: u32 = 5 + joined + terminal + @intFromBool(plan.cgroup) + 2;
        const joiner: u32 = 2 + joined;
        const user: u32 = 2 * @as(u32, @intFromBool(plan.has_user));
        const command: u32 = 9 + terminal + user;
        return parent + joiner + command;
    }

    /// The index of the joiner's first step.
    pub fn first_of(plan: *const Plan, side: Side) u32 {
        assert(plan.count > 0);
        assert(plan.count <= steps_max);
        for (plan.steps[0..plan.count], 0..) |step, index| {
            if (side_of(step.kind) == side) return @intCast(index);
        }
        unreachable; // Every plan has steps of all three sides.
    }

    pub fn text(plan: *const Plan, ref: Text) [:0]const u8 {
        assert(ref.offset + ref.len < plan.paths_len);
        assert(plan.paths[ref.offset + ref.len] == 0);
        return plan.paths[ref.offset..][0..ref.len :0];
    }

    pub fn candidate_slice(plan: *const Plan) []const Text {
        assert(plan.candidates_count > 0);
        assert(plan.candidates_count <= plan.candidates.len);
        return plan.candidates[0..plan.candidates_count];
    }

    pub fn program(plan: *const Plan) []const u8 {
        assert(plan.argv[0] != null);
        const name = std.mem.span(plan.argv[0].?);
        assert(name.len > 0);
        return name;
    }

    fn push(plan: *Plan, kind: Kind, namespace: host_mod.NamespaceKind) void {
        assert(plan.count < steps_max);
        if (kind != .open_namespace and kind != .join_namespace) assert(namespace == .user);
        plan.steps[plan.count] = .{ .kind = kind, .namespace = namespace };
        plan.count += 1;
    }

    fn push_parent(plan: *Plan) void {
        assert(plan.count == 0);
        plan.push(.make_pipes, .user);
        for (std.enums.values(host_mod.NamespaceKind)) |kind| {
            if (plan.namespaces & namespace_bit(kind) != 0) plan.push(.open_namespace, kind);
        }
        if (plan.terminal) plan.push(.open_terminal, .user);
        plan.push(.spawn_joiner, .user);
        plan.push(.await_forked, .user);
        plan.push(.reap_joiner, .user);
        if (plan.cgroup) plan.push(.join_cgroup, .user);
        plan.push(.release_command, .user);
        assert(side_of(plan.steps[plan.count - 1].kind) == .parent);
    }

    fn push_joiner(plan: *Plan) void {
        assert(plan.count > 0);
        const start = plan.count;
        plan.push(.joiner_die_with_parent, .user);
        for (std.enums.values(host_mod.NamespaceKind)) |kind| {
            if (plan.namespaces & namespace_bit(kind) != 0) plan.push(.join_namespace, kind);
        }
        plan.push(.fork_command, .user);
        assert(plan.count - start == 2 + @popCount(plan.namespaces));
    }

    /// The command's steps, in the order the brief and the kernel need: the capabilities are
    /// dropped while CAP_SETPCAP is still held, the user is taken while CAP_SETUID is, the death
    /// signal is asked for again (a change of user clears it), then `no_new_privs`, which the
    /// filter needs, and the filter last but `execve`.
    fn push_command(plan: *Plan) void {
        const start = plan.count;
        plan.push(.die_with_parent, .user);
        plan.push(.await_release, .user);
        if (plan.terminal) plan.push(.attach_terminal, .user);
        plan.push(.enter_workdir, .user);
        plan.push(.seal_descriptors, .user);
        plan.push(.restrict_capabilities, .user);
        plan.push(.clear_ambient, .user);
        if (plan.has_user) plan.push(.set_user, .user);
        if (plan.has_user) plan.push(.rearm_death_signal, .user);
        plan.push(.set_no_new_privs, .user);
        plan.push(.install_seccomp, .user);
        plan.push(.exec, .user);
        assert(plan.steps[plan.count - 1].kind == .exec);
        assert(plan.count - start <= 12);
    }

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

    fn add_string(plan: *Plan, parts: []const []const u8) [*:0]const u8 {
        var length: u32 = 0;
        for (parts) |part| length += @intCast(part.len);
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

    /// The command, and its environment: the container's variables in their order, less those
    /// an `-e` replaces, then the `-e` ones, then TERM when the command has a terminal and no
    /// TERM. Nothing here is kept after the command starts, or printed.
    fn build_exec_image(plan: *Plan, input: *const Input) void {
        assert(input.command.len > 0);
        assert(plan.strings_len == 0);
        for (input.command, 0..) |word, index| plan.argv[index] = plan.add_string(&.{word});
        plan.argv[input.command.len] = null;
        var count: u32 = 0;
        var has_term = false;
        var variables = environ_iterator(input.environ);
        while (variables.next()) |variable| {
            const name = variable_name(variable);
            if (overridden(input.env, name)) continue;
            has_term = has_term or std.mem.eql(u8, name, "TERM");
            plan.envp[count] = plan.add_string(&.{variable});
            count += 1;
        }
        for (input.env) |variable| {
            has_term = has_term or std.mem.eql(u8, variable.key, "TERM");
            plan.envp[count] = plan.add_string(&.{ variable.key, "=", variable.value });
            count += 1;
        }
        if (input.term) |term| {
            if (!has_term) {
                plan.envp[count] = plan.add_string(&.{ "TERM=", term });
                count += 1;
            }
        }
        assert(count <= env_count_max);
        plan.envp[count] = null;
        plan.envp_count = count;
        plan.build_candidates(input.command[0], plan.search_path());
    }

    /// The PATH the program is looked for in: the command's own, else the default.
    fn search_path(plan: *const Plan) []const u8 {
        assert(plan.envp_count <= env_count_max);
        assert(plan.envp[plan.envp_count] == null);
        for (plan.envp[0..plan.envp_count]) |entry| {
            const variable = std.mem.span(entry.?);
            if (std.mem.startsWith(u8, variable, "PATH=") and variable.len > "PATH=".len) {
                return variable["PATH=".len..];
            }
        }
        return constants.container_path;
    }

    /// A program with a slash is run as named; any other is looked for in PATH, in order.
    fn build_candidates(plan: *Plan, name: []const u8, path: []const u8) void {
        assert(name.len > 0);
        assert(plan.candidates_count == 0);
        if (std.mem.indexOfScalar(u8, name, '/') != null) {
            plan.candidates[0] = plan.add_text(&.{name});
            plan.candidates_count = 1;
            return;
        }
        var directories = std.mem.splitScalar(u8, path, ':');
        while (directories.next()) |directory| {
            if (directory.len == 0 or directory[0] != '/') continue;
            if (plan.candidates_count == constants.candidates_max) break;
            const room = plan.paths.len - plan.paths_len;
            if (directory.len + 1 + name.len + 1 > room) break;
            plan.candidates[plan.candidates_count] = plan.add_text(&.{ directory, "/", name });
            plan.candidates_count += 1;
        }
        // A PATH with no absolute directory finds nothing: the default's are tried instead.
        if (plan.candidates_count == 0) {
            var defaults = std.mem.splitScalar(u8, constants.container_path, ':');
            while (defaults.next()) |directory| {
                plan.candidates[plan.candidates_count] = plan.add_text(&.{ directory, "/", name });
                plan.candidates_count += 1;
            }
        }
        assert(plan.candidates_count > 0);
    }
};

/// The container's working directory: its PID 1's, read in the container's own /proc once the
/// command is in its mount and PID namespaces. A run starts PID 1 in the image's (or the run's)
/// working directory, so this is that one, unless PID 1 has moved since.
pub const container_workdir = "/proc/1/cwd";

pub fn namespace_bit(kind: host_mod.NamespaceKind) u8 {
    const bit = @as(u8, 1) << @intCast(@backingInt(kind));
    assert(bit != 0);
    assert(@popCount(bit) == 1);
    return bit;
}

/// The `NAME=VALUE` strings of an environ, each ended by a NUL. A string without `=` or with an
/// empty name is passed over: it names no variable.
pub fn environ_iterator(environ: []const u8) std.mem.TokenIterator(u8, .scalar) {
    assert(environ_bytes_max > 0);
    assert(environ.len <= environ_bytes_max);
    return std.mem.tokenizeScalar(u8, environ, 0);
}

pub fn variable_name(variable: []const u8) []const u8 {
    assert(std.mem.indexOfScalar(u8, variable, 0) == null);
    assert(variable.len > 0);
    const equals = std.mem.indexOfScalar(u8, variable, '=') orelse variable.len;
    return variable[0..equals];
}

fn overridden(env: []const spec.Label, name: []const u8) bool {
    assert(name.len > 0);
    assert(env.len <= constants.run_env_count_max);
    for (env) |variable| {
        if (std.mem.eql(u8, variable.key, name)) return true;
    }
    return false;
}

/// Why an input cannot be built into a plan, or null. The library refuses each with a coded
/// diagnostic before anything is created.
pub const InputProblem = enum {
    command_empty,
    command_too_big,
    environ_too_big,
    environ_too_many,
    env_too_many,
    env_too_big,
    workdir,
};

pub fn check_input(input: *const Input) ?InputProblem {
    assert(input.command.len <= constants.args_count_max);
    assert(input.namespaces != 0);
    if (input.command.len == 0 or input.command[0].len == 0) return .command_empty;
    if (spec.command_problem(input.command) != null) return .command_too_big;
    if (input.environ.len > environ_bytes_max) return .environ_too_big;
    var count: u32 = 0;
    var variables = environ_iterator(input.environ);
    while (variables.next()) |_| count += 1;
    if (count > constants.environment_count_max + constants.env_vars_count_max) {
        return .environ_too_many;
    }
    if (input.env.len > constants.run_env_count_max) return .env_too_many;
    for (input.env) |variable| {
        if (!spec.env_name_valid(variable.key)) return .env_too_big;
        if (variable.value.len > constants.env_value_bytes_max) return .env_too_big;
        if (std.mem.indexOfScalar(u8, variable.value, 0) != null) return .env_too_big;
    }
    if (input.term) |term| {
        if (term.len > constants.term_bytes_max) return .env_too_big;
    }
    if (spec.workdir_problem(input.workdir)) return .workdir;
    return null;
}

/// A short phrase for the step, for the cause line of a diagnostic.
pub fn describe(step: Step) []const u8 {
    const phrase: []const u8 = switch (step.kind) {
        .make_pipes => "creating the pipes between zbx and the command",
        .open_namespace => "opening the container's namespace",
        .open_terminal => "opening a pseudo-terminal for the command",
        .spawn_joiner => "starting the process that joins the container",
        .await_forked => "waiting for the command to be started in the container",
        .reap_joiner => "waiting for the process that joined the container",
        .join_cgroup => "putting the command in the container's cgroup",
        .release_command => "letting the command continue",
        .await_report => "waiting for the command to start",
        .reap => "waiting for the command to end",
        .joiner_die_with_parent, .die_with_parent, .rearm_death_signal => "asking the kernel " ++
            "to end the command if zbx dies",
        .join_namespace => "joining the container's namespace",
        .fork_command => "starting the command in the container's PID namespace",
        .await_release => "waiting for zbx to put the command in the container's cgroup",
        .attach_terminal => "making the pseudo-terminal the command's terminal",
        .enter_workdir => "entering the working directory",
        .seal_descriptors => "closing the descriptors the command must not inherit",
        .restrict_capabilities => "dropping the capabilities the container does not keep",
        .clear_ambient => "clearing the ambient capabilities",
        .set_user => "becoming the user",
        .set_no_new_privs => "setting no_new_privs",
        .install_seccomp => "installing the container's seccomp filter",
        .exec => "starting the command",
    };
    assert(phrase.len > 0);
    assert(phrase.len < 120);
    return phrase;
}

comptime {
    assert(steps_max <= std.math.maxInt(u8)); // A failure record names a step in a byte.
    assert(std.enums.values(host_mod.NamespaceKind).len == 6);
    assert(paths_bytes_max >= 2 * (constants.arg_bytes_max + constants.command_word_bytes_max));
    assert(strings_bytes_max > constants.exec_strings_bytes_max + environ_bytes_max);
}

const testing = std.testing;

const all_namespaces: u8 = 0x3f;

fn test_input(command: []const []const u8) Input {
    return .{
        .command = command,
        .environ = "PATH=/usr/bin:/bin\x00HOME=/root\x00HOSTNAME=web\x00APP=1\x00",
        .env = &.{},
        .term = null,
        .workdir = "",
        .user = null,
        .namespaces = all_namespaces,
        .terminal = false,
        .cgroup = true,
    };
}

test "the plan joins user first and mount last, then the order the kernel needs" {
    // Goal: the order of the joins and of the command's hardening, which the brief and the
    // kernel fix. Method: build the fullest plan and read its steps in order.
    var plan: Plan = undefined;
    var input = test_input(&.{ "sh", "-c", "true" });
    input.terminal = true;
    input.user = .{ .uid = 1000, .gid = 1000 };
    plan.build(&input);
    try testing.expectEqual(steps_max, plan.count);
    var joins: [6]host_mod.NamespaceKind = undefined;
    var joined: u32 = 0;
    for (plan.steps[0..plan.count]) |step| {
        if (step.kind != .join_namespace) continue;
        joins[joined] = step.namespace;
        joined += 1;
    }
    try testing.expectEqual(@as(u32, 6), joined);
    try testing.expectEqual(host_mod.NamespaceKind.user, joins[0]);
    try testing.expectEqual(host_mod.NamespaceKind.pid, joins[4]);
    try testing.expectEqual(host_mod.NamespaceKind.mount, joins[5]);
    const order = [_]Kind{
        .spawn_joiner,       .await_forked,     .reap_joiner,           .join_cgroup,
        .release_command,    .join_namespace,   .fork_command,          .await_release,
        .attach_terminal,    .enter_workdir,    .restrict_capabilities, .set_user,
        .rearm_death_signal, .set_no_new_privs, .install_seccomp,       .exec,
    };
    var at: usize = 0;
    for (plan.steps[0..plan.count]) |step| {
        if (at < order.len and step.kind == order[at]) at += 1;
    }
    try testing.expectEqual(order.len, at);
}

test "a namespace that is the host's, no terminal, no cgroup and root leave their steps out" {
    // Goal: the counts of the smallest plan, and the joiner's steps without the network.
    var plan: Plan = undefined;
    var input = test_input(&.{"ls"});
    input.namespaces = all_namespaces & ~namespace_bit(.net);
    input.cgroup = false;
    plan.build(&input);
    try testing.expectEqual(plan.steps_expected(), plan.count);
    for (plan.steps[0..plan.count]) |step| {
        try testing.expect(step.kind != .open_terminal);
        try testing.expect(step.kind != .join_cgroup);
        try testing.expect(step.kind != .set_user);
        if (step.kind == .join_namespace) try testing.expect(step.namespace != .net);
    }
    try testing.expectEqual(Side.joiner, side_of(plan.steps[plan.first_of(.joiner)].kind));
    try testing.expectEqual(Kind.die_with_parent, plan.steps[plan.first_of(.command)].kind);
}

test "the environment is the container's, with -e replacing a name, and TERM only if absent" {
    // Goal: the container's variables in order, an override in place of the one it replaces,
    // TERM added for a terminal when the container has none, and PATH from the container.
    var plan: Plan = undefined;
    var input = test_input(&.{"ls"});
    input.env = &.{.{ .key = "APP", .value = "2" }};
    input.term = "xterm";
    input.terminal = true;
    plan.build(&input);
    try testing.expectEqual(@as(u32, 5), plan.envp_count);
    try testing.expectEqualStrings("PATH=/usr/bin:/bin", std.mem.span(plan.envp[0].?));
    try testing.expectEqualStrings("HOSTNAME=web", std.mem.span(plan.envp[2].?));
    try testing.expectEqualStrings("APP=2", std.mem.span(plan.envp[3].?));
    try testing.expectEqualStrings("TERM=xterm", std.mem.span(plan.envp[4].?));
    try testing.expectEqual(@as(u32, 2), plan.candidates_count);
    try testing.expectEqualStrings("/usr/bin/ls", plan.text(plan.candidates[0]));
    try testing.expectEqualStrings("/proc/1/cwd", plan.text(plan.workdir));
    input.environ = "TERM=dumb\x00";
    plan.build(&input);
    try testing.expectEqualStrings("TERM=dumb", std.mem.span(plan.envp[0].?));
    try testing.expectEqual(@as(u32, 2), plan.envp_count);
    try testing.expectEqual(constants.container_path_dirs_count, plan.candidates_count);
}

test "check_input refuses what the plan could not hold, at the bounds" {
    // Goal: every refusal, and the boundary of the counts. Method: one input at a time.
    var input = test_input(&.{"ls"});
    try testing.expect(check_input(&input) == null);
    input.workdir = "relative";
    try testing.expectEqual(InputProblem.workdir, check_input(&input).?);
    input.workdir = "/a/../b";
    try testing.expectEqual(InputProblem.workdir, check_input(&input).?);
    input.workdir = "/srv";
    var env: [constants.run_env_count_max + 1]spec.Label = undefined;
    for (&env) |*variable| variable.* = .{ .key = "X", .value = "1" };
    input.env = env[0..constants.run_env_count_max];
    try testing.expect(check_input(&input) == null);
    input.env = env[0 .. constants.run_env_count_max + 1];
    try testing.expectEqual(InputProblem.env_too_many, check_input(&input).?);
    input.env = &.{.{ .key = "BAD NAME", .value = "1" }};
    try testing.expectEqual(InputProblem.env_too_big, check_input(&input).?);
    input.env = &.{};
    var environ: [environ_bytes_max + 1]u8 = @splat('a');
    input.environ = &environ;
    try testing.expectEqual(InputProblem.environ_too_big, check_input(&input).?);
    const most = constants.environment_count_max + constants.env_vars_count_max;
    var many: [(most + 1) * 4]u8 = undefined;
    for (0..most + 1) |at| @memcpy(many[at * 4 ..][0..4], "A=1\x00");
    input.environ = many[0 .. most * 4];
    try testing.expect(check_input(&input) == null);
    input.environ = &many;
    try testing.expectEqual(InputProblem.environ_too_many, check_input(&input).?);
}
