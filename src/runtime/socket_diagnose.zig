//! The diagnostics of `container_socket` (E0610, E0611). The lookup's own refusals (no state
//! directory, no such container, not running) are `exec`'s E0701, E0402 and E0220: the same
//! container lookup. Only the parent calls this; the helper sends a step and an errno.

const std = @import("std");
const assert = std.debug.assert;
const errors = @import("../diag/errors.zig");
const host_mod = @import("../host.zig");
const Diag = @import("../diag/diag.zig").Diag;

/// The steps of making a socket. The first four are the helper's, in order (`helper_steps`);
/// the parent reads the failed one from the report. The last two are the caller's own: starting
/// the helper (its pipes and the fork) and reaping it.
pub const Step = enum(u8) {
    join_user,
    join_net,
    make_socket,
    send_socket,
    start_helper,
    reap_helper,

    pub fn describe(step: Step) []const u8 {
        return switch (step) {
            .join_user => "joining the container's user namespace",
            .join_net => "joining the container's network namespace",
            .make_socket => "making the socket",
            .send_socket => "handing the socket back",
            .start_helper => "starting the helper process",
            .reap_helper => "waiting for the helper process",
        };
    }
};

/// The helper's steps, in the order it runs them.
pub const helper_steps = [_]Step{ .join_user, .join_net, .make_socket, .send_socket };

comptime {
    for (helper_steps, 0..) |step, index| assert(@backingInt(step) == index);
}

/// Why a container has no network a socket may be made in (ZBX-E0610).
pub const NoNetwork = enum {
    /// `--net host`: its network namespace is the host's.
    host,
    /// `--net user`: pasta's network, which the brief leaves out (Non-goals).
    user,
};

pub const Failure = struct {
    err: host_mod.Error,
    errno: u16,
};

/// ZBX-E0610: the container's network is not `--net none`: with `--net host` a socket made in
/// it would be the host's, and pasta's network (`--net user`) is not offered.
pub fn no_socket_network(diag: *Diag, name: []const u8, why: NoNetwork) void {
    assert(diag.code == null);
    assert(name.len > 0);
    diag.raise(.E0610);
    diag.while_("making a socket in the container {s}", .{name});
    switch (why) {
        .host => diag.cause("the container {s} has no network of its own: it shares the " ++
            "host's", .{name}),
        .user => diag.cause("the container {s} uses pasta's network (--net user); sockets " ++
            "are made only in a --net none container", .{name}),
    }
    diag.context("name", "{s}", .{name});
    diag.context("net", "{s}", .{@tagName(why)});
    diag.fix(.{
        .sentence = "start the container with --net none (the default):",
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
