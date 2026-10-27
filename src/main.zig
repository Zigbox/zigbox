//! zbx entry point. Deliberately thin: wire the real host to the CLI and exit with its code.
//! Uses `Init.Minimal` rather than `Init` so that no allocator or arena exists at all: the
//! "no allocation after startup" rule is then true by construction.

const std = @import("std");
const assert = std.debug.assert;
const cli = @import("cli.zig");
const constants = @import("constants.zig");
const host_real = @import("host_real.zig");
const panic_report = @import("diag/panic.zig");
const HostReal = host_real.HostReal;

/// A panic is a `bug[ZBX-B0001]` block and exit 70, never a stack trace (DIAGNOSTICS.md).
pub const panic = std.debug.FullPanic(panic_handler);

pub const std_options: std.Options = .{
    // The std handler for SIGSEGV prints a stack trace. A segmentation fault in this program
    // can only be a stack overflow or a kernel-level surprise; the process dies by the signal
    // instead, which is at least not a trace shown to the user.
    .enable_segfault_handler = false,
};

fn panic_handler(message: []const u8, first_trace_addr: ?usize) noreturn {
    // The trace address is deliberately unused: nothing prints a trace.
    _ = first_trace_addr;
    var buffer: [constants.output_bytes_max]u8 = undefined;
    if (panic_report.respond(&panic_report.state, message, &buffer)) |bytes| {
        host_real.write_stderr_best_effort(bytes);
    }
    host_real.exit_now(panic_report.exit_code(&panic_report.state));
}

/// The command line's big working memory (a run's handle, the bundle workspace), the program's
/// own: static, because it is over a megabyte and the stack is not the place; one command line
/// runs per process.
var storage: cli.Storage = undefined;

pub fn main(init: std.process.Init.Minimal) u8 {
    var real: HostReal = .{ .environ = init.environ };
    var iterator = init.args.iterate();
    const code = cli.run_with(real.interface(), &iterator, &storage);
    assert(real.open_count == 0); // Every file the CLI opened was closed.
    return code;
}

test {
    // Pull every module's tests into this test binary.
    _ = @import("constants.zig");
    _ = @import("host.zig");
    _ = @import("host_real.zig");
    _ = @import("host_sim.zig");
    _ = @import("cli.zig");
    _ = @import("parse.zig");
    _ = @import("text.zig");
    _ = @import("doctor.zig");
    _ = @import("doctor_fixtures.zig");
    _ = @import("test_util.zig");
    _ = @import("diag/codes.zig");
    _ = @import("diag/diag.zig");
    _ = @import("diag/render.zig");
    _ = @import("diag/errors.zig");
    _ = @import("diag/explain.zig");
    _ = @import("diag/diagnostic.zig");
    _ = @import("diag/product.zig");
    _ = @import("diag_foreign.zig");
    _ = @import("diag/panic.zig");
    _ = @import("diag_golden.zig");
    _ = @import("sim_world.zig");
    _ = @import("runtime/spec.zig");
    _ = @import("runtime/plan.zig");
    _ = @import("runtime/sync.zig");
    _ = @import("runtime/child.zig");
    _ = @import("runtime/diagnose.zig");
    _ = @import("zigbox.zig");
    _ = @import("redact.zig");
    _ = @import("bundle.zig");
    _ = @import("bundle_tests.zig");
    _ = @import("runtime/session.zig");
    _ = @import("runtime/ids.zig");
    _ = @import("runtime/records.zig");
    _ = @import("runtime/signals.zig");
    _ = @import("runtime/run.zig");
    _ = @import("runtime/sim_run.zig");
    _ = @import("runtime/run_tests.zig");
    _ = @import("runtime/scope.zig");
    _ = @import("runtime/scope_text.zig");
    _ = @import("runtime/scope_tests.zig");
    _ = @import("runtime/bpf.zig");
    _ = @import("runtime/seccomp.zig");
    _ = @import("runtime/capabilities.zig");
    _ = @import("runtime/lifecycle.zig");
    _ = @import("commands.zig");
    _ = @import("store_commands.zig");
    _ = @import("store/materialize.zig");
    _ = @import("store/remove.zig");
    _ = @import("store/commit_tests.zig");
    _ = @import("runtime/image.zig");
    _ = @import("runtime/image_tests.zig");
    _ = @import("runtime/image.zig");
    _ = @import("runtime/image_tests.zig");
    _ = @import("store_commands_tests.zig");
    _ = @import("schemas.zig");
    _ = @import("runtime/lifecycle_tests.zig");
    _ = @import("runtime/exit_tests.zig");
    _ = @import("dbus/wire.zig");
    _ = @import("dbus/message.zig");
    _ = @import("dbus/auth.zig");
    _ = @import("dbus/client.zig");
    _ = @import("dbus/systemd.zig");
    _ = @import("dbus/client_tests.zig");
    _ = @import("sim_bus.zig");
    _ = @import("fuzz_dbus.zig");
}
