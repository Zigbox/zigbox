//! The diagnostics of a run: where a refusal or a failed step becomes a coded `Diag` (E0201,
//! E0202, E0203, E0205, E0206; E0008 for a command that does not fit). Only the parent calls
//! this, so it may format text; the child sends a step and an errno (`sync.zig`) and nothing
//! else. Nothing here prints: the CLI renders the `Diag`.
//!
//! Each constructor names the real cause, not the last symptom (DIAGNOSTICS.md, principle 4):
//! the symptom is the failed call with its errno, and where the host's facts say why, the cause
//! that comes last is that reason.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const doctor = @import("../doctor.zig");
const errors = @import("../diag/errors.zig");
const Diag = @import("../diag/diag.zig").Diag;
const client = @import("../dbus/client.zig");
const codes = @import("../diag/codes.zig");
const plan_mod = @import("plan.zig");
const records = @import("records.zig");
const scope_mod = @import("scope.zig");
const scope_text = @import("scope_text.zig");
const spec = @import("spec.zig");

const linux = std.os.linux;
const Host = host_mod.Host;
const Plan = plan_mod.Plan;

/// What the diagnostics say about the run they belong to.
pub const RunInfo = struct {
    name: []const u8,
    rootfs: []const u8,
    /// The digest of the tree the run started from; empty for a run of a directory.
    tree: []const u8 = "",
};

/// What a failed step's diagnostic may need besides the step: how a helper ended, and why a
/// scope could not be had.
pub const Details = struct {
    helper: ?HelperEnd = null,
    scope: ?*const scope_mod.Problem = null,
    /// The caller's room for the doctor's facts, which a refused namespace is explained with.
    facts: *doctor.Facts,
};

/// A failed step: its index in the plan, the coarse error and the errno the kernel returned.
pub const Failure = struct {
    step: u8,
    err: host_mod.Error,
    errno: u16,
};

const dmesg_policy = "sudo dmesg | grep -iE 'apparmor|seccomp|selinux|userns'";

fn starting(diag: *Diag, info: RunInfo) void {
    assert(info.name.len > 0);
    assert(info.rootfs.len > 0);
    diag.while_("starting container {s}", .{info.name});
    diag.context("name", "{s}", .{info.name});
    diag.context("rootfs", "{s}", .{info.rootfs});
}

// ---- The user's input ----------------------------------------------------------------------

pub const RootfsFault = union(enum) {
    problem: spec.RootfsProblem,
    /// `stat` failed.
    unreadable: Failure,
    not_a_directory,
};

/// ZBX-E0201: the rootfs is missing or not a directory.
pub fn rootfs_unusable(diag: *Diag, rootfs: []const u8, fault: RootfsFault) void {
    assert(diag.code == null);
    diag.raise(.E0201);
    diag.while_("checking the rootfs", .{});
    diag.context("rootfs", "{s}", .{rootfs});
    switch (fault) {
        .problem => |problem| switch (problem) {
            .empty => diag.cause("the rootfs path is empty", .{}),
            .too_long => diag.cause("the rootfs path is longer than {d} bytes", .{
                constants.rootfs_bytes_max,
            }),
        },
        .not_a_directory => diag.cause("'{s}' exists but is not a directory", .{rootfs}),
        .unreadable => |failure| switch (failure.err) {
            error.NotFound => diag.cause("'{s}' does not exist", .{rootfs}),
            else => errors.cause_host_error(diag, "stat of the rootfs", failure.err, failure.errno),
        },
    }
    diag.fix(.{
        .sentence = "unpack a root filesystem into a directory:",
        .command = "mkdir alpine && tar -xzf alpine-minirootfs-*.tar.gz -C alpine",
    });
    diag.fix(.{
        .sentence = "then name that directory:",
        .command = "zbx run --rootfs ./alpine -- /bin/sh",
    });
    assert(diag.code.? == .E0201);
    assert(diag.fixes.count == 2);
}

/// ZBX-E0206: the container name is not a valid hostname label.
pub fn name_invalid(diag: *Diag, name: []const u8, problem: spec.NameProblem) void {
    assert(diag.code == null);
    diag.raise(.E0206);
    diag.while_("reading the container name", .{});
    switch (problem) {
        .empty => diag.cause("the name is empty", .{}),
        .too_long => diag.cause("the name is longer than {d} characters, the limit for a " ++
            "hostname label", .{constants.container_name_bytes_max}),
        .bad_character => |index| diag.cause("'{s}' has a character at position {d} that is " ++
            "not a lowercase letter, a digit or '-'", .{ name, index + 1 }),
        .hyphen_at_edge => diag.cause("'{s}' starts or ends with '-', which a hostname label " ++
            "cannot", .{name}),
    }
    if (name.len > 0) diag.context("name", "{s}", .{name});
    diag.fix(.{
        .sentence = "a valid name looks like this:",
        .command = "zbx run --name web-1 --rootfs ./alpine -- /bin/sh",
    });
    assert(diag.code.? == .E0206);
    assert(diag.causes.count == 1);
}

/// ZBX-E0008: the command does not fit the bounds of the plan.
pub fn command_too_big(diag: *Diag, problem: spec.CommandProblem) void {
    assert(diag.code == null);
    diag.raise(.E0008);
    diag.while_("reading the command to run", .{});
    switch (problem) {
        .empty => unreachable, // The command line parser refuses an empty command first.
        .too_many_words => diag.cause("the command has more than {d} words", .{
            constants.command_words_count_max,
        }),
        .word_too_long => |index| diag.cause("word {d} of the command is longer than {d} bytes", .{
            index + 1, constants.command_word_bytes_max,
        }),
        .too_many_bytes => diag.cause("the command and its environment need more than {d} bytes", .{
            constants.exec_strings_bytes_max,
        }),
    }
    diag.fix(.{ .sentence = "put the work in a script in the rootfs and run that" });
    assert(diag.code.? == .E0008);
}

// ---- A failed step -------------------------------------------------------------------------

/// How a helper program ended, when it ran at all.
pub const HelperEnd = struct {
    status: host_mod.ExitStatus,
    output: []const u8,
};

/// Classifies a failed step and fills `diag`: ZBX-E0203 for the namespaces and their id maps,
/// ZBX-E0204 for the helpers that write them, ZBX-E0202 for the command, ZBX-E0205 for every
/// other step. `helper` says how a helper ended, if the step ran one and it did run.
pub fn step_failed(
    host: Host,
    diag: *Diag,
    plan: *const Plan,
    info: RunInfo,
    failure: Failure,
    details: Details,
) void {
    assert(diag.code == null);
    assert(failure.step < plan.count);
    const helper = details.helper;
    const step = &plan.steps[failure.step];
    var buffer: [160]u8 = undefined;
    const operation = plan_mod.describe(step, &buffer);
    switch (step.kind) {
        .spawn => namespaces_failed(host, details.facts, diag, failure),
        .deny_setgroups, .write_gid_map, .write_uid_map => map_failed(diag, operation, failure),
        .run_newuidmap, .run_newgidmap => helper_failed(
            diag,
            plan,
            step,
            operation,
            failure,
            helper,
        ),
        .start_scope => scope_step_failed(diag, plan.text(step.target), details.scope),
        .exec => command_failed(diag, plan, info, failure),
        .mount_overlay => overlay_failed(diag, operation, failure),
        .restrict_capabilities,
        .clear_ambient,
        => hardening_failed(diag, .E0207, operation, failure),
        .set_no_new_privs,
        .install_seccomp,
        => hardening_failed(diag, .E0208, operation, failure),
        .make_tmp_dir,
        .mount_tmp,
        .make_run_dir,
        .mount_run,
        .remount_readonly,
        => read_only_failed(diag, step, operation, failure, info),
        else => setup_failed(diag, step, operation, failure, info),
    }
    starting(diag, info);
    step_context(diag, plan, failure.step);
    assert(diag.code != null);
    assert(diag.causes.count > 0);
}

fn step_context(diag: *Diag, plan: *const Plan, index: u8) void {
    assert(index < plan.count);
    assert(diag.code != null);
    const step = &plan.steps[index];
    diag.context("step", "{s} ({d} of {d})", .{ @tagName(step.kind), index + 1, plan.count });
}

/// ZBX-E0425: the kernel refused the container's overlay mount.
fn overlay_failed(diag: *Diag, operation: []const u8, failure: Failure) void {
    assert(diag.code == null);
    diag.raise(.E0425);
    errors.cause_host_error(diag, operation, failure.err, failure.errno);
    diag.cause("overlayfs needs Linux 5.11 or newer with the overlay module, and an upper layer " ++
        "on a file system that keeps user.* extended attributes", .{});
    if (failure.err == error.AccessDenied) {
        diag.fix(.{ .sentence = "look for the policy that denies it:", .command = dmesg_policy });
    }
    diag.fix(.{ .sentence = "see what this host allows:", .command = "zbx doctor" });
    diag.fix(
        .{
            .sentence = "or run a directory instead:",
            .command = "zbx run --rootfs ./alpine -- sh",
        },
    );
    assert(diag.code.? == .E0425);
}

fn namespaces_failed(host: Host, facts: *doctor.Facts, diag: *Diag, failure: Failure) void {
    assert(diag.code == null);
    assert(failure.errno < 4096);
    diag.raise(.E0203);
    const call = "clone3 with new user, mount, PID, UTS, IPC and network namespaces";
    errors.cause_host_error(diag, call, failure.err, failure.errno);
    if (spawn_reason(failure.errno)) |reason| diag.cause("{s}", .{reason});
    if (failure.err == error.WouldBlock) {
        diag.fix(.{ .sentence = "check the process limits:", .command = "ulimit -u" });
    }
    // The doctor's user-namespace check knows the host's real reason when there is one: it is
    // the newest cause, which is the one the default output shows.
    doctor.explain_userns(host, facts, diag);
    diag.fix(.{ .sentence = "check this host (ZBX-E0101):", .command = "zbx doctor" });
    assert(diag.code.? == .E0203);
}

fn spawn_reason(errno: u16) ?[]const u8 {
    assert(errno < 4096);
    if (errno == 0) return null;
    const code: linux.E = @fromBackingInt(errno);
    const reason: ?[]const u8 = switch (code) {
        .PERM, .ACCES => "the kernel or a security policy refused to create the namespaces for " ++
            "this process",
        .NOSPC => "a limit on namespaces was reached (user.max_user_namespaces or " ++
            "user.max_pid_namespaces)",
        .AGAIN => "a limit on processes or on nested user namespaces was reached",
        .NOMEM => "the kernel has no memory for a new process",
        .INVAL => "this kernel does not support one of the namespaces zbx asked for",
        .NOSYS => "clone3 is not available: the kernel is older than 5.3, or a seccomp filter " ++
            "around zbx blocks it",
        else => null,
    };
    return reason;
}

fn map_failed(diag: *Diag, operation: []const u8, failure: Failure) void {
    assert(diag.code == null);
    assert(operation.len > 0);
    diag.raise(.E0203);
    errors.cause_host_error(diag, operation, failure.err, failure.errno);
    diag.cause("the kernel created the user namespace but refused to let it be mapped: an " ++
        "unprivileged user may map only its own id, and a security policy can forbid even " ++
        "that", .{});
    diag.fix(.{ .sentence = "look for the policy that denies it:", .command = dmesg_policy });
    diag.fix(.{ .sentence = "check this host (ZBX-E0101):", .command = "zbx doctor" });
    assert(diag.code.? == .E0203);
}

fn helper_failed(
    diag: *Diag,
    plan: *const Plan,
    step: *const plan_mod.Step,
    operation: []const u8,
    failure: Failure,
    helper: ?HelperEnd,
) void {
    assert(diag.code == null);
    const path = plan.text(step.target);
    const program = std.fs.path.basename(path);
    diag.raise(.E0204);
    // The general reason first; the helper's own words last, since they are the real cause and
    // default output shows only the newest.
    diag.cause("a full id map is written by the setuid helpers, which refuse unless " ++
        "their ranges in /etc/subuid and /etc/subgid cover the ids zbx asks for " ++
        "and they are setuid root", .{});
    if (helper) |end| {
        switch (end.status) {
            .exited => |code| helper_exited(diag, program, path, code, end.output),
            .signaled => |number| diag.cause("{s} was killed by signal {d}", .{ program, number }),
        }
    } else {
        errors.cause_host_error(diag, operation, failure.err, failure.errno);
    }
    diag.context("helper", "{s}", .{path});
    diag.fix(.{ .sentence = "check the helpers and the ranges:", .command = "zbx doctor" });
    diag.fix_with("look at the helper:", "ls -l {s}", .{path});
    assert(diag.code.? == .E0204);
    assert(diag.fixes.count == 2);
}

fn helper_exited(
    diag: *Diag,
    program: []const u8,
    path: []const u8,
    code: u8,
    output: []const u8,
) void {
    assert(program.len > 0);
    // The shell convention a failed exec in the helper's child ends with.
    if (code == 127) {
        diag.cause("{s} could not be run ({s})", .{ program, path });
        return;
    }
    const trimmed = std.mem.trim(u8, output, " \t\r\n");
    if (trimmed.len == 0) {
        diag.cause("{s} exited with status {d}", .{ program, code });
    } else {
        diag.cause("{s} exited with status {d}: {s}", .{ program, code, trimmed });
    }
}

fn setup_failed(
    diag: *Diag,
    step: *const plan_mod.Step,
    operation: []const u8,
    failure: Failure,
    info: RunInfo,
) void {
    assert(diag.code == null);
    assert(operation.len > 0);
    diag.raise(.E0205);
    errors.cause_host_error(diag, operation, failure.err, failure.errno);
    if (setup_reason(step.kind, failure.err)) |reason| diag.cause("{s}", .{reason});
    switch (step.kind) {
        // The directories zbx makes in the user's own rootfs: a problem with that directory,
        // not with the host.
        .make_proc_dir, .make_dev_dir => if (info.tree.len > 0) {
            diag.fix(.{ .sentence = "the tree has no such directory and a read-only run can't " ++
                "make it: import a root filesystem that has /proc and /dev" });
        } else {
            diag.fix_with("make the directories as the rootfs's owner:", "mkdir -p \"{s}/proc\" " ++
                "\"{s}/dev\"", .{ info.rootfs, info.rootfs });
            diag.fix(.{ .sentence = "or unpack the rootfs as the user who runs zbx" });
        },
        else => {
            if (failure.err == error.AccessDenied) {
                const sentence = "look for the policy that denies it:";
                diag.fix(.{ .sentence = sentence, .command = dmesg_policy });
            }
            diag.fix(.{ .sentence = "check what this host allows:", .command = "zbx doctor" });
        },
    }
    assert(diag.code.? == .E0205);
    assert(diag.fixes.count > 0);
}

/// ZBX-E0207 and ZBX-E0208: the capabilities, `no_new_privs` or the seccomp filter could not be
/// applied. The container is never started without them.
fn hardening_failed(diag: *Diag, code: codes.Code, operation: []const u8, failure: Failure) void {
    assert(diag.code == null);
    assert(@backingInt(code) >= @backingInt(codes.Code.E0207));
    assert(@backingInt(code) <= @backingInt(codes.Code.E0208));
    diag.raise(code);
    errors.cause_host_error(diag, operation, failure.err, failure.errno);
    if (code == .E0207) {
        diag.cause("the container's root should hold these capabilities in its own user " ++
            "namespace; a security module or an old kernel is the usual reason they cannot " ++
            "be changed", .{});
    } else {
        diag.cause("the kernel may lack seccomp filters, or a policy forbids installing one", .{});
    }
    if (failure.err == error.AccessDenied) {
        diag.fix(.{ .sentence = "look for the policy that denies it:", .command = dmesg_policy });
    }
    diag.fix(.{ .sentence = "check what this host allows:", .command = "zbx doctor" });
    assert(diag.code.? == code);
    assert(diag.fixes.count > 0);
}

/// ZBX-E0209: `--read-only` could not make its mount points, mount its tmpfs or remount.
fn read_only_failed(
    diag: *Diag,
    step: *const plan_mod.Step,
    operation: []const u8,
    failure: Failure,
    info: RunInfo,
) void {
    assert(diag.code == null);
    assert(operation.len > 0);
    diag.raise(.E0209);
    errors.cause_host_error(diag, operation, failure.err, failure.errno);
    const makes = step.kind == .make_tmp_dir or step.kind == .make_run_dir;
    if (makes and info.tree.len > 0) {
        diag.cause("the tree has no such directory and a read-only run can't make it", .{});
        diag.fix(.{ .sentence = "import a root filesystem that has /tmp and /run, or run it " ++
            "without --read-only" });
    } else if (makes) {
        diag.cause("the rootfs has no such directory and is not writable by this user, so it " ++
            "cannot be made; a read-only rootfs needs /tmp and /run before it is made " ++
            "read-only", .{});
        diag.fix_with("make them as the rootfs's owner:", "mkdir -p \"{s}/tmp\" \"{s}/run\"", .{
            info.rootfs, info.rootfs,
        });
        diag.fix(.{ .sentence = "or unpack the rootfs as the user who runs zbx" });
    } else {
        diag.fix(.{ .sentence = "check what this host allows:", .command = "zbx doctor" });
    }
    assert(diag.code.? == .E0209);
    assert(diag.fixes.count > 0);
}

/// Why a step is refused, when the step and the error say so. Null leaves the symptom as the
/// cause: guessing a reason is worse than not giving one.
fn setup_reason(kind: plan_mod.Kind, err: host_mod.Error) ?[]const u8 {
    assert(kind != .spawn); // The namespaces and the command have diagnostics of their own.
    assert(kind != .exec);
    const denied = err == error.AccessDenied;
    const reason: ?[]const u8 = switch (kind) {
        .mount_proc => if (denied)
            "the host refuses a fresh /proc here; running inside another container, which hides " ++
                "parts of /proc, or a security policy, is the usual reason"
        else
            null,
        .make_mounts_private, .bind_rootfs, .mount_dev, .mount_shm => if (denied)
            "the host does not let this user namespace make mounts; a security policy is the " ++
                "usual reason"
        else
            null,
        .make_proc_dir,
        .make_dev_dir,
        .make_shm_dir,
        .make_pts_dir,
        .create_device_file,
        => switch (err) {
            error.NotFound => "a directory of the rootfs is missing, so the mount point cannot " ++
                "be made",
            error.AccessDenied => "the rootfs is not writable by this user",
            else => null,
        },
        .bind_device => if (err == error.NotFound)
            "the host has no such device to bind into the container"
        else
            null,
        .pivot_root => "the rootfs is not a mount point the kernel accepts as a new root, or " ++
            "the tree is still shared with the host",
        else => null,
    };
    return reason;
}

fn command_failed(diag: *Diag, plan: *const Plan, info: RunInfo, failure: Failure) void {
    assert(diag.code == null);
    assert(plan.argv[0] != null);
    diag.raise(.E0202);
    const program = std.mem.span(plan.argv[0].?);
    const by_path = plan.candidates_count == 1;
    // A container run exits 127 for a command that is not there and 126 for one that cannot run.
    if (failure.err == error.NotFound) diag.mark_command_missing();
    switch (failure.err) {
        error.NotFound => if (by_path) {
            // The note comes first, so default output (the newest cause) is the plain statement.
            diag.cause("a dynamically linked program also needs its loader and libc inside the " ++
                "rootfs; a missing loader is reported as a missing file", .{});
            diag.cause("'{s}' is missing from the rootfs", .{program});
        } else {
            diag.cause("no file named '{s}' in the container's PATH ({s})", .{
                program, constants.container_path,
            });
        },
        error.AccessDenied => if (by_path) {
            diag.cause("'{s}' is not executable (permission denied)", .{program});
        } else {
            diag.cause("a file named '{s}' in the container's PATH is not executable " ++
                "(permission denied)", .{program});
        },
        else => {
            if (failure.errno == @backingInt(linux.E.NOEXEC)) {
                diag.cause("'{s}' is not a program this machine can run (exec format error)", .{
                    program,
                });
            } else {
                errors.cause_host_error(diag, "execve", failure.err, failure.errno);
            }
        },
    }
    diag.context("cmd", "{s}", .{program});
    if (info.tree.len > 0) {
        diag.fix_with("look in the tree:", "zbx run {s} -- /bin/busybox ls /bin", .{info.tree});
        diag.fix_with("or use the program's full path:", "zbx run {s} -- /bin/sh", .{info.tree});
        assert(diag.code.? == .E0202);
        return;
    }
    diag.fix_with("look in the rootfs:", "ls -l \"{s}/bin\"", .{info.rootfs});
    diag.fix_with("or use the program's full path:", "zbx run --rootfs {s} -- /bin/sh", .{
        info.rootfs,
    });
    assert(diag.code.? == .E0202);
}

// ---- The scope and the limits ---------------------------------------------------------------

/// ZBX-E0306: a limit's value is not accepted. `value` is what the user wrote (or the number a
/// library caller gave), `flag` the option it belongs to.
pub fn limit_invalid(
    diag: *Diag,
    kind: spec.LimitKind,
    value: []const u8,
    problem: spec.LimitProblem,
) void {
    assert(value.len <= constants.arg_bytes_max);
    assert(diag.code == null);
    const flag = switch (kind) {
        .memory => "--memory",
        .pids => "--pids",
        .cpus => "--cpus",
    };
    diag.raise(.E0306);
    diag.while_("reading the {s} limit", .{flag});
    diag.context("limit", "{s} {s}", .{ flag, value });
    limit_cause(diag, kind, flag, value, problem);
    const example = switch (kind) {
        .memory => "zbx run --rootfs ./alpine --memory 128m -- /bin/sh",
        .pids => "zbx run --rootfs ./alpine --pids 64 -- /bin/sh",
        .cpus => "zbx run --rootfs ./alpine --cpus 0.5 -- /bin/sh",
    };
    diag.fix(.{ .sentence = "a valid limit looks like this:", .command = example });
    assert(diag.code.? == .E0306);
    assert(diag.causes.count == 1);
}

fn limit_cause(
    diag: *Diag,
    kind: spec.LimitKind,
    flag: []const u8,
    value: []const u8,
    problem: spec.LimitProblem,
) void {
    assert(diag.code.? == .E0306);
    assert(flag.len > 2);
    switch (problem) {
        error.Empty => diag.cause("{s} needs a value", .{flag}),
        error.NotANumber => switch (kind) {
            .memory => diag.cause(
                "'{s}' is not a size: use digits and k, m or g, as in 128m",
                .{value},
            ),
            .pids => diag.cause("'{s}' is not a count: use digits only, as in 64", .{value}),
            .cpus => diag.cause("'{s}' is not a number of CPUs: use a decimal like 0.5", .{value}),
        },
        error.Zero => diag.cause("a limit of zero would stop the container before it starts", .{}),
        error.TooPrecise => diag.cause("{s} takes at most three decimals", .{flag}),
        error.TooSmall => switch (kind) {
            .memory => diag.cause("{s} is below the smallest limit, {d} MiB", .{
                value, constants.limit_memory_bytes_min >> 20,
            }),
            .pids => diag.cause("{s} is below the smallest limit, {d}", .{
                value, constants.limit_pids_min,
            }),
            .cpus => diag.cause("{s} is below the smallest limit, 0.01 CPU", .{value}),
        },
        error.TooLarge => switch (kind) {
            .memory => diag.cause("{s} is above the largest limit, {d} GiB", .{
                value, constants.limit_memory_bytes_max >> 30,
            }),
            .pids => diag.cause("{s} is above the largest limit, {d}", .{
                value, constants.limit_pids_max,
            }),
            .cpus => diag.cause("{s} is above the largest limit, {d} CPUs", .{
                value, constants.limit_cpu_millis_max / 1000,
            }),
        },
    }
}

fn problem_fixes(diag: *Diag, code: codes.Code, scope_name: []const u8) void {
    assert(diag.code.? == code);
    assert(diag.fixes.count == 0);
    switch (code) {
        .E0301 => {
            diag.fix(.{ .sentence = "check this host (ZBX-E0103):", .command = "zbx doctor" });
            diag.fix(.{
                .sentence = "keep the user manager running:",
                .command = "loginctl enable-linger $USER",
            });
        },
        .E0302 => {
            diag.fix(.{
                .sentence = "see which bus this process uses:",
                .command = "echo $DBUS_SESSION_BUS_ADDRESS",
            });
            diag.fix(.{ .sentence = "or log in again through a systemd session" });
        },
        .E0305 => {
            diag.fix(.{
                .sentence = "choose another name:",
                .command = "zbx run --name <other-name> ...",
            });
            diag.fix_with("or stop the other unit:", "systemctl --user stop {s}", .{scope_name});
        },
        .E0304 => diag.fix(.{
            .sentence = "see what the manager logged:",
            .command = "journalctl --user -n 20",
        }),
        else => diag.fix(.{ .sentence = "check this host (ZBX-E0103):", .command = "zbx doctor" }),
    }
}

/// A failed `start_scope` step: the problem the scope module recorded, or (when a fault stopped
/// the step before any problem was recorded) the failed call itself.
fn scope_step_failed(diag: *Diag, unit: []const u8, problem: ?*const scope_mod.Problem) void {
    assert(unit.len > constants.scope_suffix.len);
    assert(diag.code == null);
    assert(std.mem.endsWith(u8, unit, constants.scope_suffix));
    const found = problem.?; // The session records one whenever the step fails.
    const code = scope_text.problem_code(found);
    diag.raise(code);
    diag.while_("starting the container's scope {s}", .{unit});
    scope_text.problem_causes(diag, found);
    diag.context("scope", "{s}", .{unit});
    problem_fixes(diag, code, unit);
    assert(diag.code.? == code);
}

/// ZBX-E0307: a limit was asked for and no scope can be made, found before anything was created.
pub fn limit_without_cgroup(
    diag: *Diag,
    problem: *const scope_mod.Problem,
    limits: spec.Limits,
) void {
    assert(diag.code == null);
    assert(limits.any());
    diag.raise(.E0307);
    diag.while_("preparing the container's cgroup", .{});
    if (limits.memory_bytes) |bytes| diag.context("memory", "{d} bytes", .{bytes});
    if (limits.pids) |pids| diag.context("pids", "{d}", .{pids});
    if (limits.cpu_millis) |millis| diag.context("cpus", "{d} thousandths", .{millis});
    diag.cause("--memory, --pids and --cpus are enforced by a cgroup scope from the user's " ++
        "systemd manager, and one cannot be made", .{});
    scope_text.problem_causes(diag, problem);
    diag.fix(.{ .sentence = "check this host (ZBX-E0103):", .command = "zbx doctor" });
    diag.fix(.{ .sentence = "or run without the limit flags, which needs no scope" });
    assert(diag.code.? == .E0307);
}

/// ZBX-W0301: no limits were asked for and no scope can be made, so the run goes on without.
pub fn running_without_scope(diag: *Diag, problem: *const scope_mod.Problem) void {
    assert(diag.code == null);
    diag.raise(.W0301);
    diag.while_("preparing the container's cgroup", .{});
    scope_text.problem_causes(diag, problem);
    diag.fix(.{ .sentence = "check this host (ZBX-E0103):", .command = "zbx doctor" });
    assert(diag.code.? == .W0301);
    assert(diag.causes.count >= 1);
}

/// ZBX-W0302: the container ended and its scope is still there, or could not be checked.
pub fn scope_not_cleaned(diag: *Diag, unit: []const u8, problem: *const scope_mod.Problem) void {
    assert(diag.code == null);
    assert(unit.len <= constants.scope_name_bytes_max);
    assert(std.mem.endsWith(u8, unit, constants.scope_suffix));
    diag.raise(.W0302);
    diag.while_("making sure the container's scope {s} is gone", .{unit});
    scope_text.problem_causes(diag, problem);
    diag.context("scope", "{s}", .{unit});
    diag.fix_with("remove it by hand:", "systemctl --user stop {s}", .{unit});
    assert(diag.code.? == .W0302);
    assert(diag.causes.count >= 1);
}

// ---- The lifecycle commands ---------------------------------------------------------------

/// ZBX-E0401: `--timeout` or `--grace` is not a number of milliseconds in range.
pub fn time_invalid(diag: *Diag, flag: []const u8, text: []const u8) void {
    assert(diag.code == null);
    assert(flag.len > 2);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = @import("../text.zig").sanitise(&storage, text);
    diag.raise(.E0401);
    diag.while_("reading {s}", .{flag});
    diag.cause("'{s}' is not a whole number of milliseconds from 0 to {d}", .{
        echo, constants.wait_timeout_ms_max,
    });
    diag.context("value", "{s}", .{echo});
    diag.fix(.{
        .sentence = "give a time in milliseconds:",
        .command = "zbx stop web-1 --grace 5000",
    });
    assert(diag.code.? == .E0401);
}

pub const NoContainer = enum { no_record, unreadable_record, no_state, unreadable_state };

/// ZBX-E0402: no container of that name (or no state directory to look in: ZBX-E0701).
pub fn no_such_container(diag: *Diag, name: []const u8, why: NoContainer) void {
    assert(diag.code == null);
    if (why == .no_state) {
        diag.raise(.E0701);
        diag.while_("looking for the state directory", .{});
        diag.cause("neither XDG_STATE_HOME nor HOME names an absolute directory", .{});
        diag.fix(.{
            .sentence = "name one:",
            .command = "export XDG_STATE_HOME=$HOME/.local/state",
        });
        return;
    }
    if (why == .unreadable_state) {
        diag.raise(.E0701);
        diag.while_("looking for the containers", .{});
        diag.cause("the runs directory under the state directory cannot be read", .{});
        diag.fix(.{
            .sentence = "look at it:",
            .command = "ls -ld \"${XDG_STATE_HOME:-$HOME/.local/state}/zbx/runs\"",
        });
        return;
    }
    // The name is what the user typed: no escape reaches the terminal, no line is too long.
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = @import("../text.zig").sanitise(&storage, name);
    diag.raise(.E0402);
    diag.while_("looking for the container {s}", .{echo});
    switch (why) {
        .no_record => diag.cause("no run record is called '{s}'; zbx keeps the newest {d}", .{
            echo, constants.runs_max,
        }),
        .unreadable_record => diag.cause("the run record of '{s}' cannot be read or is from a " ++
            "newer zbx", .{echo}),
        .no_state, .unreadable_state => unreachable, // Handled above.
    }
    diag.context("name", "{s}", .{echo});
    diag.fix(.{ .sentence = "see the containers:", .command = "zbx ps --all" });
    assert(diag.code.? == .E0402);
}

/// ZBX-E0403: the container's PID 1 cannot be signalled.
pub fn cannot_signal(diag: *Diag, name: []const u8, pid: u32, failure: Failure) void {
    assert(diag.code == null);
    diag.raise(.E0403);
    diag.while_("stopping the container {s}", .{name});
    errors.cause_host_error(diag, "signalling the container's PID 1", failure.err, failure.errno);
    diag.cause(
        "the record names pid {d}; it belongs to another user, or the number was reused",
        .{pid},
    );
    diag.context("name", "{s}", .{name});
    diag.context("pid", "{d}", .{pid});
    diag.fix(.{
        .sentence = "look at the process:",
        .command = "ps -o pid,user,stat,args -p <pid>",
    });
    assert(diag.code.? == .E0403);
}

/// ZBX-E0404: the container was still there when the time was up.
pub fn did_not_stop(diag: *Diag, name: []const u8, pid: u32, waited_ms: u32) void {
    assert(diag.code == null);
    diag.raise(.E0404);
    diag.while_("stopping the container {s}", .{name});
    diag.cause("pid {d} was still there {d} ms after SIGKILL was sent; a process in " ++
        "uninterruptible sleep cannot be killed until the kernel lets it go", .{ pid, waited_ms });
    diag.context("name", "{s}", .{name});
    diag.context("pid", "{d}", .{pid});
    diag.fix(.{
        .sentence = "see what it is waiting for:",
        .command = "ps -o pid,stat,wchan -p <pid>",
    });
    assert(diag.code.? == .E0404);
}

pub const SupervisorFault = union(enum) {
    /// The kernel refused to create the process.
    fork: Failure,
    /// The supervisor ended without saying whether the container started.
    ended_early,
};

/// ZBX-E0405: the supervisor of a detached run could not be had.
pub fn supervisor_failed(diag: *Diag, fault: SupervisorFault) void {
    assert(diag.code == null);
    diag.raise(.E0405);
    diag.while_("starting the supervisor of a detached run", .{});
    switch (fault) {
        .fork => |failure| errors.cause_host_error(
            diag,
            "creating the supervisor process",
            failure.err,
            failure.errno,
        ),
        .ended_early => diag.cause("the supervisor ended before it said whether the container " ++
            "started; its output is on /dev/null", .{}),
    }
    diag.fix(.{ .sentence = "check the process limit:", .command = "ulimit -u" });
    diag.fix(.{
        .sentence = "run it in the foreground to see the failure:",
        .command = "zbx run ...",
    });
    assert(diag.code.? == .E0405);
}

/// ZBX-E0406: no schema for that command.
pub fn no_schema(diag: *Diag, topic: []const u8) void {
    assert(diag.code == null);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = @import("../text.zig").sanitise(&storage, topic);
    diag.raise(.E0406);
    diag.while_("looking up a schema", .{});
    diag.cause(
        "'{s}' has no JSON schema; the commands with one are run, bundle, ps, stop, doctor, and " ++
            "store-import, store-ls, store-du and store-rm",
        .{echo},
    );
    diag.context("arg", "{s}", .{echo});
    diag.fix(.{ .sentence = "print one:", .command = "zbx schema ps" });
    assert(diag.code.? == .E0406);
}

// ---- Warnings ------------------------------------------------------------------------------

/// ZBX-W0202: the run record could not be saved, or there is nowhere to save it.
pub fn record_not_saved(diag: *Diag, directory: ?[]const u8, failure: ?Failure) void {
    assert(diag.code == null);
    diag.raise(.W0202);
    diag.while_("saving the run record", .{});
    if (failure) |failed| {
        errors.cause_host_error(diag, "writing the run record", failed.err, failed.errno);
        if (directory) |where| diag.context("path", "{s}", .{where});
        diag.fix_with("free space, or choose another state directory:", "df -h \"{s}\"", .{
            directory orelse "/",
        });
    } else {
        diag.cause(
            "neither XDG_STATE_HOME nor HOME names an absolute directory to keep it in",
            .{},
        );
        diag.fix(
            .{ .sentence = "name one:", .command = "export XDG_STATE_HOME=$HOME/.local/state" },
        );
    }
    assert(diag.code.? == .W0202);
    assert(diag.fixes.count > 0);
}

/// ZBX-W0203: records that could not be used were skipped.
pub fn records_skipped(diag: *Diag, directory: []const u8, skipped: *const records.Skipped) void {
    assert(diag.code == null);
    assert(skipped.count > 0);
    diag.raise(.W0203);
    diag.while_("looking through the run records", .{});
    const reason: []const u8 = switch (skipped.first_reason) {
        .unreadable => "cannot be read",
        .damaged => "is not a valid record",
        .newer => "was written by a newer zbx",
    };
    if (skipped.count == 1) {
        diag.cause("run record '{s}' {s}, so it was skipped", .{ skipped.first(), reason });
    } else {
        diag.cause("{d} run records were skipped; the first, '{s}', {s}", .{
            skipped.count, skipped.first(), reason,
        });
    }
    diag.context("path", "{s}", .{directory});
    diag.fix_with("look at them:", "ls -l \"{s}\"", .{directory});
    assert(diag.code.? == .W0203);
    assert(diag.fixes.count == 1);
}

/// ZBX-E0008: a label does not fit.
pub fn label_too_big(diag: *Diag, index: u32) void {
    assert(diag.code == null);
    diag.raise(.E0008);
    diag.while_("reading the labels", .{});
    diag.cause("label {d} is empty, too long, or there are more than {d} labels " ++
        "(a key is at most " ++
        "{d} bytes, a value {d})", .{
        index + 1,                     constants.labels_count_max,
        constants.label_key_bytes_max, constants.label_value_bytes_max,
    });
    diag.fix(.{ .sentence = "use fewer or shorter labels" });
    assert(diag.code.? == .E0008);
}

/// ZBX-E0008: a variable of `Spec.env` does not fit.
pub fn env_too_big(diag: *Diag, index: u32) void {
    assert(diag.code == null);
    diag.raise(.E0008);
    diag.while_("reading the environment", .{});
    diag.cause("variable {d} has an empty or unusable name, is too long, or there are more than " ++
        "{d} variables (a name is at most {d} bytes, a value {d}, and with the command they " ++
        "must fit {d} bytes)", .{
        index + 1,                        constants.env_vars_count_max,
        constants.env_name_bytes_max,     constants.env_value_bytes_max,
        constants.exec_strings_bytes_max,
    });
    diag.fix(.{ .sentence = "pass fewer or shorter variables" });
    assert(diag.code.? == .E0008);
}

/// ZBX-E0008: the working directory of a `Spec` is not an absolute path without "..".
pub fn workdir_unusable(diag: *Diag) void {
    assert(diag.code == null);
    diag.raise(.E0008);
    diag.while_("reading the working directory", .{});
    diag.cause("the working directory is not an absolute path of at most {d} bytes without " ++
        "'..' parts", .{constants.rootfs_bytes_max});
    diag.fix(.{ .sentence = "give an absolute directory such as /srv/app" });
    assert(diag.code.? == .E0008);
}

/// The note for a step that was allowed to fail and did, for `--verbose` and the run record.
pub fn skipped_note(plan: *const Plan, step_index: u8, errno: u16, buffer: []u8) []const u8 {
    assert(step_index < plan.count);
    assert(plan.steps[step_index].tolerant);
    var operation_buffer: [160]u8 = undefined;
    const operation = plan_mod.describe(&plan.steps[step_index], &operation_buffer);
    var reason_buffer: [96]u8 = undefined;
    const reason = errno_words(errno, &reason_buffer);
    return std.fmt.bufPrint(buffer, "skipped {s}: {s}", .{ operation, reason }) catch buffer[0..0];
}

fn errno_words(errno: u16, buffer: []u8) []const u8 {
    assert(errno > 0);
    assert(errno < 4096);
    const code: linux.E = @fromBackingInt(errno);
    const name = std.enums.tagName(linux.E, code) orelse "unknown";
    return std.fmt.bufPrint(buffer, "refused by the kernel (E{s})", .{name}) catch "refused";
}
