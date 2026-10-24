//! What to do with a signal zbx has received for the container (docs/briefs/M1-shell.md,
//! "Ctrl-C on PID 1"). A PID 1 ignores every signal it has no handler for, so forwarding SIGINT
//! to a plain `sleep` would leave it running. When the container's PID 1 neither catches nor
//! ignores the signal, zbx sends SIGKILL instead, which reproduces what the signal would have
//! done to an ordinary process. A shell, which catches SIGINT, gets the SIGINT.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");

pub const Action = enum {
    /// Send the signal itself: PID 1 has a handler, or ignores it on purpose.
    forward,
    /// Send SIGKILL in its place.
    kill,
};

/// The signals zbx catches and forwards, in the order it names them.
pub const forwarded = [constants.forwarded_signals_count]u8{ 1, 2, 3, 15 }; // HUP, INT, QUIT, TERM

/// True for a signal whose default action ends the process: all four forwarded ones.
pub fn terminates_by_default(number: u8) bool {
    assert(number > 0);
    assert(number < constants.signal_number_max);
    return std.mem.indexOfScalar(u8, &forwarded, number) != null;
}

/// `state` is what the kernel says about the container's PID 1 (null: it could not be read, and
/// then the signal is forwarded as it is: guessing wrongly would kill a process that handles it).
pub fn decide(state: ?host_mod.SignalState, number: u8) Action {
    assert(terminates_by_default(number));
    const known = state orelse return .forward;
    if (host_mod.SignalState.has(known.caught, number)) return .forward;
    if (host_mod.SignalState.has(known.ignored, number)) return .forward;
    return .kill;
}

const testing = std.testing;

test "a signal PID 1 handles or ignores is forwarded; one it has no answer for is killed" {
    // Goal: the SigCgt rule at its edges. Method: every forwarded signal against a state that
    // catches it, ignores it, catches a different one, has nothing, and is unknown.
    for (forwarded) |number| {
        const bit: u64 = @as(u64, 1) << @intCast(number - 1);
        const other: u64 = @as(u64, 1) << @intCast(number % 60 + 1);
        try testing.expectEqual(Action.forward, decide(.{ .caught = bit, .ignored = 0 }, number));
        try testing.expectEqual(Action.forward, decide(.{ .caught = 0, .ignored = bit }, number));
        try testing.expectEqual(Action.kill, decide(.{ .caught = other, .ignored = 0 }, number));
        try testing.expectEqual(Action.kill, decide(.{ .caught = 0, .ignored = 0 }, number));
        try testing.expectEqual(Action.forward, decide(null, number));
    }
    try testing.expect(terminates_by_default(2));
    try testing.expect(!terminates_by_default(10));
}
