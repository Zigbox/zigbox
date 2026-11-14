//! The diagnostics of `container_socket` (E0610, E0611). The lookup's own refusals (no state
//! directory, no such container, not running) are `exec`'s E0701, E0402 and E0220: the same
//! container lookup. Only the parent calls this; the helper sends a step and an errno.

const std = @import("std");
const assert = std.debug.assert;
const errors = @import("../diag/errors.zig");
const host_mod = @import("../host.zig");
const Diag = @import("../diag/diag.zig").Diag;

/// The steps of the helper, in order; the parent reads the failed one from the report.
pub const Step = enum(u8) {
    join_user,
    join_net,
    make_socket,
    send_socket,

    pub fn describe(step: Step) []const u8 {
        return switch (step) {
            .join_user => "joining the container's user namespace",
            .join_net => "joining the container's network namespace",
            .make_socket => "making the socket",
            .send_socket => "handing the socket back",
        };
    }
};

pub const Failure = struct {
    err: host_mod.Error,
    errno: u16,
};

/// ZBX-E0610: the container shares the host's network, so a socket made in it would be the
/// host's.
pub fn shares_host_network(diag: *Diag, name: []const u8) void {
    assert(diag.code == null);
    assert(name.len > 0);
    diag.raise(.E0610);
    diag.while_("making a socket in the container {s}", .{name});
    diag.cause("the container {s} has no network of its own: it shares the host's", .{name});
    diag.context("name", "{s}", .{name});
    diag.fix(.{
        .sentence = "start the container with a network of its own:",
        .command = "zbx run -d --name web --net none alpine -- sleep 1000",
        .template = true,
    });
    assert(diag.code.? == .E0610);
}

/// ZBX-E0611: a step of making the socket failed, in the helper or in the caller's wait for it.
pub fn step_failed(diag: *Diag, name: []const u8, step: Step, failure: Failure) void {
    assert(diag.code == null);
    assert(name.len > 0);
    diag.raise(.E0611);
    diag.while_("making a socket in the container {s}", .{name});
    // The real cause last: the default output shows the newest one.
    if (failure.err == error.AccessDenied) {
        diag.cause("a security policy, or another user's container, refuses it", .{});
    }
    errors.cause_host_error(diag, step.describe(), failure.err, failure.errno);
    diag.context("name", "{s}", .{name});
    diag.context("step", "{s}", .{@tagName(step)});
    if (failure.err == error.AccessDenied) {
        diag.fix(.{
            .sentence = "run as the user that started the container, then check the host:",
            .command = "zbx doctor",
        });
    } else {
        diag.fix(.{
            .sentence = "see whether the container still runs:",
            .command = "zbx ps --all",
        });
    }
    assert(diag.code.? == .E0611);
}
