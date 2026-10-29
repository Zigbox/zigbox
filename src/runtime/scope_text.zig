//! The words for why a container could not have its cgroup scope: the code a `scope.Problem` is,
//! and its causes, symptom first and the reason last (default output shows only the last).
//! Shared by the diagnostics of a run (`diagnose.zig`) and by the doctor's cgroup check, which
//! tells the same story about the same bus.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const auth = @import("../dbus/auth.zig");
const client = @import("../dbus/client.zig");
const wire = @import("../dbus/wire.zig");
const codes = @import("../diag/codes.zig");
const errors = @import("../diag/errors.zig");
const Diag = @import("../diag/diag.zig").Diag;
const scope_mod = @import("scope.zig");

/// A few words for the doctor's one-line report: what is wrong with the bus.
pub fn problem_short(problem: *const scope_mod.Problem) []const u8 {
    assert(@intFromPtr(problem) != 0);
    return switch (problem_code(problem)) {
        .E0301 => "no systemd user manager answers on the user bus",
        .E0302 => "the user bus does not accept this user",
        .E0303 => "the user bus answers in a way zbx cannot use",
        .E0304 => "the systemd user manager refuses requests",
        else => "the cgroup of a scope cannot be found",
    };
}

/// The code a problem with the scope is, by what went wrong (the table in the E03xx pages).
pub fn problem_code(problem: *const scope_mod.Problem) codes.Code {
    assert(@intFromPtr(problem) != 0);
    switch (problem.*) {
        .no_address, .bad_address => return .E0301,
        .no_cgroup_path, .cgroup_write => return .E0308,
        .bus => |failure| return bus_code(&failure),
        // The inherited address is the user's mistake to fix, but what decides the code is
        // whether the user's own bus can be had.
        .bus_retried => |retried| return bus_code(&retried.failure),
        .scope_left => return .W0302,
        .cgroupfs => |failure| return if (failure.step == .remove) .W0302 else .E0309,
    }
}

fn bus_code(failure: *const client.Failure) codes.Code {
    assert(failure.name.len <= constants.dbus_error_text_bytes_max);
    assert(failure.errno < 4096);
    const name = failure.name.slice();
    switch (failure.kind) {
        .no_bus => return .E0301,
        .auth_refused => return .E0302,
        .protocol, .io => return .E0303,
        .timeout => return if (failure.stage == .job) .E0304 else .E0303,
        .remote => {
            if (failure.stage == .hello) return .E0302;
            if (failure.stage == .job) return .E0304;
            if (std.mem.endsWith(u8, name, "ServiceUnknown")) return .E0301;
            if (std.mem.endsWith(u8, name, "NameHasNoOwner")) return .E0301;
            if (std.mem.eql(u8, name, "org.freedesktop.systemd1.UnitExists")) return .E0305;
            return .E0304;
        },
    }
}

/// Adds the causes of a problem, symptom first and the reason last (the reason is what default
/// output shows).
pub fn problem_causes(diag: *Diag, problem: *const scope_mod.Problem) void {
    assert(diag.code != null);
    assert(diag.causes.count <= constants.diag_causes_count_max);
    switch (problem.*) {
        .no_address => diag.cause(
            "neither DBUS_SESSION_BUS_ADDRESS nor XDG_RUNTIME_DIR is set, so there is no " ++
                "user bus to ask: this is not a systemd user session",
            .{},
        ),
        .bad_address => |reason| diag.cause(
            "DBUS_SESSION_BUS_ADDRESS is not an address zbx can use ({s}); only " ++
                "unix:path= is supported",
            .{address_reason(reason)},
        ),
        .bus => |failure| bus_causes(diag, &failure),
        .bus_retried => |retried| {
            diag.cause("the inherited bus at {s} turned this user away ({s}), so " ++
                "zbx tried {s}, this user's own bus", .{
                retried.refused.path.slice(),
                refusal_words(&retried.refused.failure),
                retried.own_path.slice(),
            });
            bus_causes(diag, &retried.failure);
        },
        .scope_left => diag.cause("the scope's cgroup is still there after the manager was " ++
            "asked to stop the scope", .{}),
        .no_cgroup_path => |io| {
            const operation = "reading the scope's cgroup from /proc";
            errors.cause_host_error(diag, operation, io.err, io.errno);
            diag.cause("the scope started but its cgroup could not be found, so a limit " ++
                "this systemd cannot set itself was not applied", .{});
        },
        .cgroupfs => |failure| cgroupfs_causes(diag, &failure),
        .cgroup_write => |written| {
            var operation: [64]u8 = undefined;
            const text = std.fmt.bufPrint(&operation, "writing {s} in the scope", .{
                written.file.slice(),
            }) catch "writing a cgroup file";
            errors.cause_host_error(diag, text, written.io.err, written.io.errno);
            diag.cause("this systemd is too old to set the limit itself, and the cgroup " ++
                "controller is not delegated to this user", .{});
        },
    }
}

/// What the cleanup of the scope found, for `--verbose`.
pub fn cleanup_note(name: []const u8, how: scope_mod.Cleaned, buffer: []u8) []const u8 {
    assert(std.mem.endsWith(u8, name, constants.scope_suffix));
    assert(buffer.len >= 160);
    const result = switch (how) {
        .already_gone => std.fmt.bufPrint(buffer, "scope {s} was gone when the run ended", .{name}),
        .manager_done => std.fmt.bufPrint(
            buffer,
            "scope {s} went by itself just after the run ended",
            .{name},
        ),
        .stopped => std.fmt.bufPrint(
            buffer,
            "scope {s} was still there at the end; stopped with StopUnit",
            .{name},
        ),
        .removed => std.fmt.bufPrint(buffer, "cgroup {s} removed when the run ended", .{name}),
    };
    return result catch buffer[0..0];
}

/// How the first bus turned the user away, in a few words.
fn refusal_words(failure: *const client.Failure) []const u8 {
    assert(failure.errno < 4096);
    assert(failure.kind != .remote);
    return switch (failure.kind) {
        .auth_refused => "it did not accept this user's authentication",
        else => if (failure.errno == 1) "permission denied" else "access denied",
    };
}

/// The note `--verbose` shows when the inherited bus did not work and the user's own did.
pub fn fallback_note(via: *const scope_mod.Via, buffer: []u8) []const u8 {
    const refused = via.refused orelse return buffer[0..0];
    assert(via.own_path.len > 0);
    const format = "the bus at {s} turned this user away ({s}); connected to {s} instead";
    return std.fmt.bufPrint(buffer, format, .{
        refused.path.slice(),
        refusal_words(&refused.failure),
        via.own_path.slice(),
    }) catch buffer[0..0];
}

fn address_reason(reason: auth.AddressError) []const u8 {
    assert(@intFromError(reason) != 0);
    return switch (reason) {
        error.Empty => "it is empty",
        error.Unsupported => "it names another transport",
        error.TooLong => "it is too long",
        error.BadEscape => "it has a bad % escape",
    };
}

fn bus_causes(diag: *Diag, failure: *const client.Failure) void {
    assert(diag.code != null);
    assert(failure.errno < 4096);
    const name = failure.name.slice();
    const text = failure.text.slice();
    switch (failure.kind) {
        .no_bus => {
            errors.cause_host_error(diag, "connecting to the user bus", failure.err, failure.errno);
            diag.cause("{s}", .{no_bus_reason(failure.errno)});
        },
        .auth_refused => {
            diag.cause("authenticating to the user bus failed at the {s} step", .{
                @tagName(failure.stage),
            });
            diag.cause("the bus answered '{s}' to EXTERNAL authentication as this user: the " ++
                "socket may belong to another user (an inherited " ++
                "DBUS_SESSION_BUS_ADDRESS after su or sudo)", .{name});
        },
        .protocol => diag.cause("the user bus sent something zbx cannot use while {s}: {s}", .{
            stage_phrase(failure.stage),
            wire_phrase(failure.wire),
        }),
        .timeout => diag.cause("the user bus gave no answer in time while {s}", .{
            stage_phrase(failure.stage),
        }),
        .io => errors.cause_host_error(diag, "talking to the user bus", failure.err, failure.errno),
        .remote => remote_cause(diag, failure, name, text),
    }
}

fn remote_cause(
    diag: *Diag,
    failure: *const client.Failure,
    name: []const u8,
    text: []const u8,
) void {
    assert(diag.code != null);
    assert(name.len <= constants.dbus_error_text_bytes_max);
    if (failure.stage == .job) {
        diag.cause("systemd started the job for the scope and it ended with result '{s}'", .{name});
    } else if (text.len > 0) {
        diag.cause("{s} answered {s}: {s}", .{ remote_party(failure), name, text });
    } else {
        diag.cause("{s} answered {s}", .{ remote_party(failure), name });
    }
}

fn remote_party(failure: *const client.Failure) []const u8 {
    assert(failure.kind == .remote);
    return switch (failure.stage) {
        .hello => "the user bus",
        else => "systemd",
    };
}

fn wire_phrase(problem: ?wire.WireError) []const u8 {
    if (problem) |found| assert(@intFromError(found) != 0);
    const found = problem orelse return "an answer it did not expect";
    return switch (found) {
        error.Truncated => "the reply was cut short, or the bus hung up",
        error.BadPadding, error.BadValue, error.BadHeader => "the reply is malformed",
        error.TooLong => "the reply is bigger than zbx accepts",
        error.BadSignature => "the reply does not have the shape zbx expects",
        error.Unsupported => "the reply is of a kind zbx does not read",
    };
}

fn stage_phrase(stage: client.Stage) []const u8 {
    assert(@backingInt(stage) <= 5);
    return switch (stage) {
        .connect => "connecting",
        .auth => "authenticating",
        .hello => "saying Hello",
        .add_match => "subscribing to job results",
        .call => "asking systemd",
        .job => "waiting for the scope's job",
    };
}

fn no_bus_reason(errno: u16) []const u8 {
    assert(errno < 4096);
    return switch (errno) {
        2 => "the bus socket does not exist: this login has no systemd user session",
        111 => "nothing is listening on the bus socket: the systemd user manager is not running",
        13, 1 => "the bus socket is not accessible to this user: an address inherited through " ++
            "su or sudo may name another user's bus",
        else => "the user bus cannot be reached from this process",
    };
}

/// The cgroupfs driver's failure: what it was doing and the kernel's reason last, then why the
/// reason is likely.
fn cgroupfs_causes(diag: *Diag, failure: *const scope_mod.Cgroupfs) void {
    assert(diag.code != null);
    assert(failure.path.len > 0);
    var operation: [constants.cgroup_path_bytes_max + 64]u8 = undefined;
    const doing = switch (failure.step) {
        .make => "making the container's cgroup",
        .join => "moving the container into its cgroup",
        .limit => "writing a limit in the container's cgroup",
        .remove => "removing the container's cgroup",
    };
    const where = failure.path.slice();
    const text = std.fmt.bufPrint(&operation, "{s}: {s}", .{ doing, where }) catch doing;
    errors.cause_host_error(diag, text, failure.io.err, failure.io.errno);
    if (failure.step == .remove) return;
    const errno_exists: u16 = 17;
    if (failure.step == .make and failure.io.errno == errno_exists) {
        diag.cause("a cgroup of this name is there already, left by a run that did not end " ++
            "cleanly, or by another container with the same name", .{});
        return;
    }
    diag.cause("the cgroup directory in ZBX_CGROUP_ROOT is not one this user can make cgroups " ++
        "in, or its controllers are not enabled for them", .{});
}
