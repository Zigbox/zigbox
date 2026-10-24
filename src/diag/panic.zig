//! What a panic looks like to a user (DIAGNOSTICS.md: "A panic handler turns panics into a `bug`
//! diagnostic"). A panic is a broken invariant, so this code assumes as little as possible: it
//! uses no `Host`, no allocation and no state but one small struct, and it never fails.
//!
//! The root panic function in `main.zig` calls `respond`, writes the bytes to stderr with a raw
//! write, and exits 70 (125 for `zbx run`). The stack trace is not printed: it goes nowhere a user
//! sees it. No bundle is written from the handler either, and a panic has no `saved` line:
//! bundle.zig says why.
//! The panic message is shown only in verbose and json output, because it is internal text.
//!
//! `respond` is pure so the whole output can be tested; the wiring around it is a few lines.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const codes = @import("codes.zig");
const render = @import("render.zig");
const Diag = @import("diag.zig").Diag;

pub const State = struct {
    /// The output mode the command line asked for, once parsed. Before that, plain text.
    mode: render.Mode = .text,
    /// Which family of exit codes the command line uses: a `run` exits 125 for a bug, not 70.
    scope: codes.ExitScope = .standard,
    /// Set when a panic is being reported, so a panic while reporting exits at once.
    entered: bool = false,
};

/// The process-wide state. Single-threaded by design (AGENTS.md: namespace work happens in a
/// single-threaded child, thread pools only in the parent), and written once per run.
pub var state: State = .{};

pub fn configure(target: *State, mode: render.Mode, scope: codes.ExitScope) void {
    assert(!target.entered);
    target.mode = mode;
    target.scope = scope;
    assert(target.mode == mode);
    assert(target.scope == scope);
}

/// The exit code of a panic: a bug's code in the command's scope (70, or 125 for `run`).
pub fn exit_code(target: *const State) u8 {
    const result = codes.exit_code_in(target.scope, .B0001, false);
    assert(result != constants.exit_ok);
    if (target.scope == .standard) assert(result == constants.exit_internal);
    if (target.scope == .container_run) assert(result == constants.exit_run_failed);
    return result;
}

/// The bytes to write to stderr for a panic with `message`, or null if a panic is already being
/// reported (the caller then exits without writing). Never colours: the panic path does not
/// query the terminal.
pub fn respond(target: *State, message: []const u8, buffer: []u8) ?[]const u8 {
    assert(buffer.len >= constants.output_bytes_max);
    if (target.entered) return null;
    target.entered = true;
    var diag: Diag = undefined;
    diag.reset();
    diag.raise(.B0001);
    diag.cause("{s}", .{if (message.len > 0) message else "(no message)"});
    const output = render.render(&diag, target.mode, false, buffer);
    assert(output.len > 0);
    return output;
}

const testing = std.testing;

test "a panic renders as a bug block and a second panic renders nothing" {
    // Goal: the three modes of a panic report, and re-entrancy. Method: call respond directly.
    var buffer: [constants.output_bytes_max]u8 = undefined;
    var local: State = .{};
    const first = respond(&local, "index out of bounds: index 5, len 3", &buffer).?;
    const header = "bug[ZBX-B0001]: zbx hit an internal error\n";
    try testing.expect(std.mem.startsWith(u8, first, header));
    try testing.expect(std.mem.indexOf(u8, first, "index out of bounds") == null);
    try testing.expect(respond(&local, "again", &buffer) == null);
}
