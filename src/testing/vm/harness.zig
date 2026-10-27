//! The parts of the VM demos that do not depend on the milestone: options, the accelerator
//! choice, the release-binary checks, booting and provisioning the guest, installing zbx, and
//! running a command with its two streams kept apart. `demo_name` (`demo-m0`, `demo-m1`) is set
//! once by the demo's `main` and prefixes every line the harness prints.

const std = @import("std");
const Io = std.Io;
const checks = @import("checks.zig");
const cloud_init = @import("cloud_init.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");

const Session = session_mod.Session;

// ---- Running programs as the demo user ----
//
// `runuser` and `setpriv` start no login session: they keep root's environment, whose
// `DBUS_SESSION_BUS_ADDRESS` names root's bus, and set no `XDG_RUNTIME_DIR`. zbx needs the
// user's bus to give a container its cgroup scope, so every command that runs zbx as the demo
// user goes through one of these prefixes. The test at the end of this file fails if a demo
// source names `/home/demo/zbx` without one.

/// The variables a login session of the demo user would set.
pub const demo_env = "HOME=/home/demo XDG_RUNTIME_DIR=/run/user/1000 " ++
    "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus";

/// The front of a command line that runs a program as the demo user: `as_demo ++ "/home/demo/zbx
/// doctor"`.
pub const as_demo = "runuser -u demo -- env " ++ demo_env ++ " ";

/// The same for a command that must be started in its own session (`setsid`), inside `sh -c '`;
/// the caller closes the quote.
pub const as_demo_setsid = "runuser -u demo -- sh -c 'setsid env " ++ demo_env ++ " ";

/// The same for a command on a terminal, by user and group id; `setpriv` execs, so nothing sits
/// between the terminal and the program.
pub const as_demo_setpriv = "setpriv --reuid=1000 --regid=1000 --init-groups env " ++
    demo_env ++ " ";

/// The demo's name, which prefixes every line the harness prints. Set once by the demo.
pub var demo_name: []const u8 = "demo-m0";

pub const Options = struct {
    accel: []const u8 = "auto",
    zbx_x86_64: []const u8 = "",
    zbx_aarch64: []const u8 = "",
    /// demo-m3 only: the older `zbx` of the upgrade test (x86_64).
    old_zbx: []const u8 = "",
    cache_dir: []const u8 = ".zig-cache/zbx-vm",
    delegate_dropin: bool = false,
    /// Development aids: keep the overlay after the run, and boot an existing, already
    /// provisioned overlay instead of making a new one.
    keep_overlay: bool = false,
    reuse_overlay: bool = false,
    /// A development aid: a CA bundle the guest's `zbx` is told to trust (SSL_CERT_FILE), for a
    /// host behind a network that inspects TLS. CI runs on a direct network and sets none.
    ca_file: []const u8 = "",
    /// The top-20 run only: a registry mirror for docker.io (ZBX_REGISTRY_MIRRORS). Empty means
    /// the real Docker Hub, which is what the weekly workflow uses.
    mirror: []const u8 = "",
    /// The top-20 run only, a development aid: image names (before the tag), comma separated.
    only: []const u8 = "",
};

pub fn parse_options(init: std.process.Init) !Options {
    var options: Options = .{};
    var arguments = init.minimal.args.iterate();
    _ = arguments.next();
    while (arguments.next()) |name| {
        if (std.mem.eql(u8, name, "--delegate-dropin")) {
            options.delegate_dropin = true;
            continue;
        }
        if (std.mem.eql(u8, name, "--keep-overlay")) {
            options.keep_overlay = true;
            continue;
        }
        if (std.mem.eql(u8, name, "--reuse-overlay")) {
            options.reuse_overlay = true;
            options.keep_overlay = true;
            continue;
        }
        const value = arguments.next() orelse return error.MissingValue;
        if (std.mem.eql(u8, name, "--accel")) {
            options.accel = value;
        } else if (std.mem.eql(u8, name, "--zbx-x86_64")) {
            options.zbx_x86_64 = value;
        } else if (std.mem.eql(u8, name, "--zbx-aarch64")) {
            options.zbx_aarch64 = value;
        } else if (std.mem.eql(u8, name, "--old-zbx")) {
            options.old_zbx = value;
        } else if (std.mem.eql(u8, name, "--ca-file")) {
            options.ca_file = value;
        } else if (std.mem.eql(u8, name, "--mirror")) {
            options.mirror = value;
        } else if (std.mem.eql(u8, name, "--only")) {
            options.only = value;
        } else if (std.mem.eql(u8, name, "--cache-dir")) {
            options.cache_dir = value;
        } else {
            return error.UnknownOption;
        }
    }
    if (options.zbx_x86_64.len == 0 or options.zbx_aarch64.len == 0) return error.MissingBinary;
    return options;
}

/// Opens /dev/kvm read-write: usable means the accelerator will work.
pub fn kvm_usable(io: Io) bool {
    const options: Io.Dir.OpenFileOptions = .{ .mode = .read_write };
    const file = Io.Dir.openFileAbsolute(io, "/dev/kvm", options) catch return false;
    file.close(io);
    return true;
}

pub const Timer = struct {
    began: u64,

    pub fn start() Timer {
        return .{ .began = session_mod.now_ms() };
    }

    pub fn lap(timer: *Timer, out: *Io.Writer, name: []const u8) !void {
        const now = session_mod.now_ms();
        try out.print(
            "\n{s}: [{s}] done in {d} s\n",
            .{ demo_name, name, (now - timer.began) / 1000 },
        );
        timer.began = now;
    }
};

/// Reads both release binaries and checks them: static ELF for the right machine, under
/// 4 MiB. Returns the x86_64 binary, which is the one the guest runs.
pub fn check_binaries(init: std.process.Init, out: *Io.Writer, options: Options) ![]const u8 {
    const arena = init.arena.allocator();
    const pairs = [_]struct { path: []const u8, machine: checks.Machine }{
        .{ .path = options.zbx_x86_64, .machine = .x86_64 },
        .{ .path = options.zbx_aarch64, .machine = .aarch64 },
    };
    var first: []const u8 = "";
    for (pairs) |pair| {
        const limit: Io.Limit = .limited(limits.elf_bytes_max);
        const bytes = try Io.Dir.cwd().readFileAlloc(init.io, pair.path, arena, limit);
        checks.check_static_elf(bytes, pair.machine) catch |err| {
            try out.print("{s}: {s} is not a static {s} ELF under 4 MiB: {s}\n", .{
                demo_name,
                pair.path,
                @tagName(pair.machine),
                @errorName(err),
            });
            return err;
        };
        try out.print("{s}: {s}: static {s} ELF, {d} bytes (limit {d})\n", .{
            demo_name,
            pair.path,
            @tagName(pair.machine),
            bytes.len,
            limits.binary_bytes_max,
        });
        if (first.len == 0) first = bytes;
    }
    return first;
}

pub fn provision(session: *Session, out: *Io.Writer, timer: *Timer, reuse: bool) !void {
    try out.print("\n{s}: booting and provisioning the guest (cloud-init)...\n", .{demo_name});
    // A reused overlay is already provisioned: cloud-init does not run again.
    const boot_s = limits.boot_timeout_kvm_s;
    const ready = if (reuse) 0 else try session.wait_for(cloud_init.ready_marker, 0, boot_s);
    _ = try session.wait_for("root@zigbox-demo:~#", ready, limits.command_timeout_kvm_s);
    try session.send("stty -echo; bind 'set enable-bracketed-paste off'; PS1=''\n");
    // The first command's output still contains the echo of the line above; discard it.
    _ = try session.run("true", limits.command_timeout_kvm_s);
    // Wait for the guest to finish booting, so late service chatter (cloud-init prints key
    // fingerprints, for one) cannot land in the middle of a command's output.
    const settle = "cloud-init status --wait; systemctl is-system-running --wait; true";
    _ = try session.run(settle, limits.boot_timeout_kvm_s);
    const probe = try session.run("echo shell-ok", limits.command_timeout_kvm_s);
    if (!std.mem.eql(u8, probe.output, "shell-ok")) return error.ShellNotReady;
    try timer.lap(out, "boot and provision");
}

pub fn show(out: *Io.Writer, title: []const u8, result: Session.Result) !void {
    try out.print(
        "\n{s}: $ {s}   (exit {d})\n{s}\n",
        .{ demo_name, title, result.status, result.output },
    );
}

/// A `zbx` run with its two streams kept apart.
pub const SplitResult = struct {
    streams: checks.Streams,
    status: u8,
};

/// Runs `command` in the guest with stderr redirected to a file and printed after a marker
/// (checks.zig), and cuts the console text into the two streams. The slices live in the
/// session's scratch buffer, which the next command overwrites.
pub fn run_split(session: *Session, command: []const u8) !SplitResult {
    var buffer: [limits.command_bytes_max]u8 = undefined;
    const typed = try checks.split_command(&buffer, command);
    const result = try session.run(typed, limits.command_timeout_kvm_s);
    const streams = try checks.split_streams(result.output);
    return .{ .streams = streams, .status = result.status };
}

pub fn show_split(out: *Io.Writer, title: []const u8, result: SplitResult) !void {
    try out.print("\n{s}: $ {s}   (exit {d})\n", .{ demo_name, title, result.status });
    try out.print("--- stdout\n{s}\n--- stderr\n{s}\n", .{
        std.mem.trimEnd(u8, result.streams.stdout, "\n"),
        std.mem.trimEnd(u8, result.streams.stderr, "\n"),
    });
}

pub fn install_binary(session: *Session, out: *Io.Writer, timer: *Timer) !void {
    const command = try std.fmt.allocPrint(
        session.scratch_allocator(),
        "curl -fsS -o /home/demo/zbx http://10.0.2.2:{d}/zbx && " ++
            "chown demo:demo /home/demo/zbx && chmod 755 /home/demo/zbx && ls -l /home/demo/zbx",
        .{session.server.port},
    );
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try show(out, "install zbx", result);
    if (result.status != 0) return error.InstallFailed;
    const manager = "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service";
    const gather = "uname -r; id demo; " ++
        "sysctl kernel.apparmor_restrict_unprivileged_userns user.max_user_namespaces; " ++
        "systemctl is-active user@1000.service; cat " ++ manager ++ "/cgroup.controllers; " ++
        "stat -c '%U %a' " ++ manager;
    const facts = try session.run(gather, limits.command_timeout_kvm_s);
    try show(out, "guest facts", facts);
    try timer.lap(out, "install");
}

pub const AccelError = error{ BadAccel, NoKvm };

pub fn choose_accel(requested: []const u8, kvm_available: bool) AccelError!session_mod.Accel {
    if (std.mem.eql(u8, requested, "tcg")) return .tcg;
    if (std.mem.eql(u8, requested, "kvm")) return if (kvm_available) .kvm else error.NoKvm;
    if (!std.mem.eql(u8, requested, "auto")) return error.BadAccel;
    return if (kvm_available) .kvm else error.NoKvm;
}

test "accelerator choice: KVM when usable, TCG only when asked, otherwise a clear error" {
    // Goal: software emulation is never silently chosen, and KVM is never requested without it.
    try std.testing.expectEqual(session_mod.Accel.kvm, try choose_accel("auto", true));
    try std.testing.expectError(error.NoKvm, choose_accel("auto", false));
    try std.testing.expectEqual(session_mod.Accel.tcg, try choose_accel("tcg", false));
    try std.testing.expectEqual(session_mod.Accel.tcg, try choose_accel("tcg", true));
    try std.testing.expectEqual(session_mod.Accel.kvm, try choose_accel("kvm", true));
    try std.testing.expectError(error.NoKvm, choose_accel("kvm", false));
    try std.testing.expectError(error.BadAccel, choose_accel("hvf", true));
}

test "every demo command that runs zbx as the demo user goes through the session prefix" {
    // Goal: a later demo cannot forget the user's bus (it would run without a cgroup scope, or
    // with root's bus). Method: scan the demo sources for a line that names the binary and
    // check that the line, or one of the three before it, uses one of the prefixes, or says
    // why not with `no-bus-env:`.
    const sources = [_][]const u8{
        @embedFile("main.zig"),
        @embedFile("main_m1.zig"),
        @embedFile("main_m2.zig"),
        @embedFile("main_m3.zig"),
    };
    const allowed = [_][]const u8{ "H.as_demo", "H.demo_env", "no-bus-env:", "z=/home/demo/zbx" };
    for (sources) |source| {
        var lines = std.mem.splitScalar(u8, source, '\n');
        var recent: [4][]const u8 = .{ "", "", "", "" };
        while (lines.next()) |line| {
            recent[0] = recent[1];
            recent[1] = recent[2];
            recent[2] = recent[3];
            recent[3] = line;
            const names_binary = std.mem.indexOf(u8, line, "\"") != null and
                std.mem.indexOf(u8, line, "/home/demo/zbx ") != null;
            if (!names_binary) continue;
            if (std.mem.indexOf(u8, line, "file /home/demo/zbx") != null) continue; // Not a run.
            var found = false;
            for (recent) |earlier| {
                for (allowed) |word| {
                    if (std.mem.indexOf(u8, earlier, word) != null) found = true;
                }
            }
            try std.testing.expect(found);
        }
    }
}

/// Writes `text` to `path` in the guest through base64 in short pieces (a typed line is at most
/// 1 KiB, and the text has quotes in it), and makes it executable.
pub fn put_file(session: *Session, path: []const u8, text: []const u8) !void {
    const encoder = std.base64.standard.Encoder;
    var encoded: [2048]u8 = undefined;
    if (encoder.calcSize(text.len) > encoded.len) return error.ScriptTooBig;
    const whole = encoder.encode(&encoded, text);
    const piece = 600;
    var at: usize = 0;
    var command_buffer: [900]u8 = undefined;
    _ = try session.run("rm -f /tmp/put.b64", limits.command_timeout_kvm_s);
    while (at < whole.len) : (at += piece) {
        const end = @min(at + piece, whole.len);
        const command = try std.fmt.bufPrint(
            &command_buffer,
            "printf %s {s} >> /tmp/put.b64",
            .{whole[at..end]},
        );
        const result = try session.run(command, limits.command_timeout_kvm_s);
        if (result.status != 0) return error.ScriptNotWritten;
    }
    const decode = try std.fmt.bufPrint(
        &command_buffer,
        "base64 -d /tmp/put.b64 > {s} && chmod 755 {s}",
        .{ path, path },
    );
    const result = try session.run(decode, limits.command_timeout_kvm_s);
    if (result.status != 0) return error.ScriptNotWritten;
}
