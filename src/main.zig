//! zbx entry point. Deliberately thin: wire the real host to the CLI and exit with its code.
//! Uses `Init.Minimal` rather than `Init` so that no allocator or arena exists at all: the
//! "no allocation after startup" rule is then true by construction.

const std = @import("std");
const assert = std.debug.assert;
const cli = @import("cli.zig");
const constants = @import("constants.zig");
const guest_serve = @import("guest_serve.zig");
const host_real = @import("host_real.zig");
const host_real_net = @import("host_real_net.zig");
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

/// The room gc keeps its sets in: static and zero, so it is in bss and costs nothing in the
/// program's file or in memory until a gc sizes the sets to its store. About 1.5 million
/// objects fit.
var gc_tables: [constants.store_gc_tables_bytes]u8 align(8) = @splat(0);

/// The real network's memory (`host_real_net.Memory`, about 2.4 MiB): static, so it is in bss.
var network_memory: host_real_net.Memory = undefined;

pub fn main(init: std.process.Init.Minimal) u8 {
    if (guest_command(init)) |code| return code;
    network_memory.init();
    var real: HostReal = .{ .environ = init.environ, .network_memory = &network_memory };
    var iterator = init.args.iterate();
    storage.gc_tables = &gc_tables;
    const code = cli.run_with(real.interface(), &iterator, &storage);
    assert(real.open_count == 0); // Every file the CLI opened was closed.
    return code;
}

/// `zbx guest serve`, the forwarding mode the macOS VM's init starts (guest_serve.zig). It is not
/// a command a user types, so it is not in `help`, and it is decided here, before the command
/// line parser: it takes no part in the container runtime.
fn guest_command(init: std.process.Init.Minimal) ?u8 {
    var iterator = init.args.iterate();
    _ = iterator.next();
    const first = iterator.next() orelse return null;
    if (!std.mem.eql(u8, first, "guest")) return null;
    var words: [4][]const u8 = undefined;
    words[0] = first;
    var count: usize = 1;
    while (iterator.next()) |word| {
        if (count == words.len) return 2;
        words[count] = word;
        count += 1;
    }
    if (count < 2) return 2;
    return guest_serve.main(words[0..count], init.environ);
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
    _ = @import("store/store.zig"); // Its test block brings in import_tests and usage_tests.
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
    _ = @import("fuzz_layer.zig");
}

test {
    _ = @import("registry/digest.zig");
    _ = @import("registry/blobs.zig");
    _ = @import("store/images.zig");
    _ = @import("pull_unpack.zig");
    _ = @import("pull.zig");
    _ = @import("pull_report.zig");
    _ = @import("layer/reader.zig");
    _ = @import("layer/tar.zig");
    _ = @import("layer/apply.zig");
    _ = @import("layer/diagnose.zig");
    _ = @import("registry/reference.zig");
    _ = @import("registry/net.zig");
    _ = @import("registry/net_sim.zig");
    _ = @import("registry/auth.zig");
    _ = @import("registry/manifest.zig");
    _ = @import("registry/client.zig");
    _ = @import("registry/client_tests.zig");
    _ = @import("registry/test_registry.zig");
    _ = @import("registry/proxy.zig");
    _ = @import("registry/diagnose.zig");
    _ = @import("pull_commands.zig");
    _ = @import("pull_tests.zig");
    _ = @import("pull_library_tests.zig");
    _ = @import("host_real_net.zig");
    _ = @import("testing/vm/registry_server.zig");
    _ = @import("testing/vm/registry_fixture.zig");
}

test {
    // The images: settings, the lock, running by name.
    _ = @import("registry/config.zig");
    _ = @import("lock_file.zig");
    _ = @import("image_user.zig");
    _ = @import("run_image.zig");
    _ = @import("image_diagnose.zig");
    _ = @import("store/image_find.zig");
    _ = @import("testing/vm/checks_m4.zig");
}

test {
    // M5's user-mode network (`--net user`, `--publish`): pasta's command line and its readiness,
    // and the runs that use it, in the simulator.
    _ = @import("runtime/pasta.zig");
    _ = @import("runtime/net_tests.zig");
}

test {
    // State volumes (M6).
    _ = @import("runtime/volumes.zig");
    _ = @import("runtime/volume_tests.zig");
    _ = @import("state/state.zig");
    _ = @import("state_commands.zig");
    _ = @import("state_commands_tests.zig");
    _ = @import("state/export.zig");
    _ = @import("state/export_tests.zig");
}

test {
    // The other mounts (M6 slice 3).
    _ = @import("runtime/mounts.zig");
    _ = @import("runtime/mounts_diagnose.zig");
    _ = @import("runtime/mount_tests.zig");
    _ = @import("runtime/project.zig");
    _ = @import("runtime/writable_tests.zig");
    _ = @import("runtime/logfile.zig");
    _ = @import("runtime/logs_tests.zig");
    _ = @import("logs_commands.zig");
}

test {
    // `zbx exec` (M6b slice 3).
    _ = @import("runtime/exec.zig");
    _ = @import("runtime/exec_plan.zig");
    _ = @import("runtime/exec_child.zig");
    _ = @import("runtime/exec_diagnose.zig");
    _ = @import("runtime/exec_history.zig");
    _ = @import("runtime/exec_tests.zig");
}

test {
    // The macOS VM layer's portable parts (M4b): the settings record, the control and guest
    // protocols, the diagnostics and their goldens. They run on Linux CI too, so a change to
    // the shared registry cannot break them unseen; the macOS-only parts (the Objective-C
    // bridge, Virtualization.framework) are tested by `zig build test` on a Mac.
    _ = @import("mac/settings.zig");
    _ = @import("mac/control.zig");
    _ = @import("mac/paths.zig");
    _ = @import("mac/diagnose.zig");
    _ = @import("mac/vm_golden.zig");
    _ = @import("vm_protocol.zig");
    _ = @import("forward_protocol.zig");
    _ = @import("vm_dhcp.zig");
    _ = @import("vm_guest_storage.zig");
    _ = @import("vm_ports.zig");
    _ = @import("vm_image/cpio.zig");
}
