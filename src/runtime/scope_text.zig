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
        .no_cgroup_path => |io| {
            const operation = "reading the scope's cgroup from /proc";
            errors.cause_host_error(diag, operation, io.err, io.errno);
            diag.cause("the scope started but its cgroup could not be found, so a limit " ++
                "this systemd cannot set itself was not applied", .{});
        },
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
