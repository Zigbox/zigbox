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
const plan_mod = @import("plan.zig");
const spec = @import("spec.zig");

const linux = std.os.linux;
const Host = host_mod.Host;
const Plan = plan_mod.Plan;

/// What the diagnostics say about the run they belong to.
pub const RunInfo = struct {
    name: []const u8,
    rootfs: []const u8,
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

/// Classifies a failed step and fills `diag`: ZBX-E0203 for the namespaces and their id maps,
/// ZBX-E0202 for the command, ZBX-E0205 for every other step.
pub fn step_failed(
    host: Host,
    diag: *Diag,
    plan: *const Plan,
    info: RunInfo,
    failure: Failure,
) void {
    assert(diag.code == null);
    assert(failure.step < plan.count);
    const step = &plan.steps[failure.step];
    var buffer: [160]u8 = undefined;
    const operation = plan_mod.describe(step, &buffer);
    switch (step.kind) {
        .spawn => namespaces_failed(host, diag, failure),
        .deny_setgroups, .write_gid_map, .write_uid_map => map_failed(diag, operation, failure),
        .exec => command_failed(diag, plan, info, failure),
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

fn namespaces_failed(host: Host, diag: *Diag, failure: Failure) void {
    assert(diag.code == null);
    assert(failure.errno < 4096);
    diag.raise(.E0203);
    const call = "clone3 with new user, mount, PID, UTS and IPC namespaces";
    errors.cause_host_error(diag, call, failure.err, failure.errno);
    if (spawn_reason(failure.errno)) |reason| diag.cause("{s}", .{reason});
    if (failure.err == error.WouldBlock) {
        diag.fix(.{ .sentence = "check the process limits:", .command = "ulimit -u" });
    }
    // The doctor's user-namespace check knows the host's real reason when there is one: it is
    // the newest cause, which is the one the default output shows.
    doctor.explain_userns(host, diag);
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
        .make_proc_dir, .make_dev_dir => {
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
    switch (failure.err) {
        error.NotFound => if (by_path) {
            diag.cause("'{s}' does not exist in the rootfs, or its program interpreter (the " ++
                "dynamic loader of a dynamically linked program) does not", .{program});
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
    diag.fix_with("look in the rootfs:", "ls -l \"{s}/bin\"", .{info.rootfs});
    diag.fix_with("or use the program's full path:", "zbx run --rootfs {s} -- /bin/sh", .{
        info.rootfs,
    });
    assert(diag.code.? == .E0202);
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
