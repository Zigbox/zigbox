//! A running test VM: QEMU with the guest's serial console on its stdin/stdout, plus the HTTP
//! server that feeds it. Everything happens in one poll loop (no threads), so a timeout is
//! always honoured and a failure always has the full console in the log above it.
//!
//! Why the serial console and not SSH: the harness may only use external programs the style
//! guide names (QEMU). The console needs nothing else, and cloud-init gives it a passwordless
//! root shell (cloud_init.zig). SSH would add a host `ssh` client and a per-run key for no
//! benefit in a throwaway VM. The console is the guest's exec channel (`run`), and files reach
//! the guest over the same HTTP server that serves the seed (`copy_in`) or typed on the console
//! (`put_file`).

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const Io = std.Io;
const limits = @import("limits.zig");
const http_server = @import("http_server.zig");
const cloud_init = @import("cloud_init.zig");
const accel_mod = @import("accel.zig");
const forward_mod = @import("forward.zig");

pub const Accel = accel_mod.Accel;
pub const Route = http_server.Route;
pub const Forward = forward_mod.Forward;

pub fn now_ms() u64 {
    var stamp: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &stamp);
    return @as(u64, @intCast(stamp.sec)) * 1000 + @as(u64, @intCast(stamp.nsec)) / 1_000_000;
}

/// What the guest is given at boot.
pub const Seed = struct {
    /// The rendered cloud-init seed (`cloud_init.render_user_data`, `render_meta_data`).
    user_data: []const u8,
    meta_data: []const u8,
    /// Files served to the guest at `http://10.0.2.2:<port><path>`, for `copy_in`. Bodies are
    /// borrowed and must outlive the session.
    files: []const Route = &.{},
    /// Raw disk images the guest sees as extra disks, in order (`/dev/vdb`, `/dev/vdc`, ...).
    disks: []const []const u8 = &.{},
    /// TCP forwards from the host into the guest (`forward.zig`), at most `limits.forwards_max`.
    /// A bad list is refused with a coded line on `out` before anything starts. None: the
    /// guest's network is exactly what it always was.
    forwards: []const Forward = &.{},
};

pub const Session = struct {
    io: Io,
    child: std.process.Child,
    input: i32,
    output: i32,
    console: []u8,
    console_len: u32,
    at_line_start: bool,
    server: http_server.Server,
    out: *Io.Writer,
    nonce: u32,
    qemu_exited: bool,
    scale: u32,
    scratch: []u8,
    arena: std.mem.Allocator,

    /// Starts the HTTP server and QEMU. `session` must not move afterwards (the server borrows
    /// from it).
    pub fn start(
        session: *Session,
        init: std.process.Init,
        out: *Io.Writer,
        overlay: []const u8,
        accel: Accel,
        seed: Seed,
    ) !void {
        assert(seed.user_data.len > 0);
        assert(seed.meta_data.len > 0);
        if (seed.files.len + limits.seed_routes > limits.http_routes_max) return error.TooManyFiles;
        if (seed.disks.len > limits.disks_max) return error.TooManyDisks;
        if (forward_mod.validate(seed.forwards)) |refusal| {
            var message: [limits.forward_message_bytes_max]u8 = undefined;
            try out.print("vm: {s}\n", .{forward_mod.describe(refusal, seed.forwards, &message)});
            try out.flush();
            return error.BadForward;
        }
        const arena = init.arena.allocator();
        session.* = .{
            .io = init.io,
            .child = undefined,
            .input = -1,
            .output = -1,
            .console = try arena.alloc(u8, limits.console_bytes_max),
            .console_len = 0,
            .at_line_start = true,
            .server = .{},
            .out = out,
            .nonce = 0,
            .qemu_exited = false,
            .scale = if (accel == .tcg) limits.tcg_timeout_factor else 1,
            .scratch = try arena.alloc(u8, limits.command_output_bytes_max),
            .arena = arena,
        };
        try session.server.start();
        session.server.add_route("/user-data", seed.user_data);
        session.server.add_route("/meta-data", seed.meta_data);
        session.server.add_route("/vendor-data", "");
        for (seed.files) |file| session.server.add_route(file.path, file.body);
        const argv = try qemu_argv(arena, overlay, accel, session.server.port, .{
            .disks = seed.disks,
            .forwards = seed.forwards,
        });
        try out.print("vm: starting qemu ({s}), seed at http://10.0.2.2:{d}/\n", .{
            @tagName(accel), session.server.port,
        });
        try out.flush();
        session.child = try std.process.spawn(session.io, .{
            .argv = argv,
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .inherit,
        });
        session.input = session.child.stdin.?.handle;
        session.output = session.child.stdout.?.handle;
    }

    pub fn scratch_allocator(session: *Session) std.mem.Allocator {
        return session.arena;
    }

    /// Kills QEMU if it is still running and stops the server. Safe to call twice.
    pub fn deinit(session: *Session) void {
        session.server.stop();
        if (session.child.id != null) session.child.kill(session.io);
    }

    /// One round of the poll loop: console output, new HTTP connections, HTTP progress.
    pub fn pump(session: *Session, timeout_ms: u32) !void {
        var entries: [2 + limits.http_connections_max]linux.pollfd = undefined;
        entries[0] = .{ .fd = session.output, .events = linux.POLL.IN };
        const served = session.server.poll_entries(entries[1..]);
        const ready = linux.poll(&entries, 1 + served, @intCast(timeout_ms));
        if (linux.errno(ready) != .SUCCESS and linux.errno(ready) != .INTR) return error.PollFailed;
        if (entries[0].revents != 0) try session.read_console();
        session.server.handle(entries[1 .. 1 + served], session.out);
        try session.out.flush();
    }

    fn read_console(session: *Session) !void {
        const room = session.console[session.console_len..];
        if (room.len == 0) return error.ConsoleOverflow;
        const got = linux.read(session.output, room.ptr, room.len);
        if (linux.errno(got) == .INTR or linux.errno(got) == .AGAIN) return;
        if (linux.errno(got) != .SUCCESS or got == 0) {
            session.qemu_exited = true;
            return;
        }
        const fresh = room[0..got];
        session.console_len += @intCast(got);
        try session.echo(fresh);
    }

    /// Copies console bytes to our stdout, prefixing each line so the guest's lines are
    /// distinguishable from the harness's own.
    fn echo(session: *Session, bytes: []const u8) !void {
        for (bytes) |byte| {
            if (byte == '\r') continue;
            if (session.at_line_start) try session.out.writeAll("  vm| ");
            try session.out.writeByte(byte);
            session.at_line_start = byte == '\n';
        }
    }

    /// Waits until `needle` appears in the console at or after `from`; returns the position
    /// just past it. Fails with a one-line reason on timeout or if QEMU exits.
    pub fn wait_for(session: *Session, needle: []const u8, from: u32, timeout_s: u32) !u32 {
        const deadline = now_ms() + @as(u64, timeout_s) * session.scale * 1000;
        while (true) {
            const text = session.console[from..session.console_len];
            if (std.mem.indexOf(u8, text, needle)) |at| {
                return from + @as(u32, @intCast(at + needle.len));
            }
            if (session.qemu_exited) return error.QemuExited;
            if (now_ms() > deadline) {
                try session.out.print("\nvm: timed out after {d} s waiting for \"{s}\"\n", .{
                    timeout_s * session.scale, needle,
                });
                return error.Timeout;
            }
            try session.pump(limits.poll_step_ms);
        }
    }

    pub const Result = struct {
        output: []const u8,
        status: u8,
    };

    /// Runs `command` in the guest root shell and returns its combined output and exit status.
    /// The output goes through `$( )` so the command sees a pipe, not a terminal (no colour).
    pub fn run(session: *Session, command: []const u8, timeout_s: u32) !Result {
        assert(command.len < limits.command_bytes_max);
        session.nonce += 1;
        var line: [limits.command_bytes_max + 256]u8 = undefined;
        // The output is taken from the line after a begin marker of its own, never from where
        // the command was typed: bash's line editor redraws a long typed line even with echo
        // off, and its padding can land in front of the first output line (CI runs 40378288342
        // and 40417118406).
        const format = "ZBX_OUT=$( {s} 2>&1 ); ZBX_ST=$?; echo \"ZBXBEGIN\"\"{d}:\"; " ++
            "printf '%s\\n' \"$ZBX_OUT\"; echo \"ZBXDONE\"\"{d}:$ZBX_ST\"\n";
        const nonce = session.nonce;
        const text = try std.fmt.bufPrint(&line, format, .{ command, nonce, nonce });
        const mark = session.console_len;
        try session.send(text);
        var begin_buffer: [32]u8 = undefined;
        const begin = try std.fmt.bufPrint(&begin_buffer, "ZBXBEGIN{d}:", .{session.nonce});
        const begun = try session.wait_for(begin, mark, timeout_s);
        const output_start = try session.wait_for("\n", begun, timeout_s);
        var sentinel_buffer: [32]u8 = undefined;
        const sentinel = try std.fmt.bufPrint(&sentinel_buffer, "ZBXDONE{d}:", .{session.nonce});
        const after = try session.wait_for(sentinel, output_start, timeout_s);
        const end = try session.wait_for("\n", after, timeout_s);
        const status_text = std.mem.trim(u8, session.console[after..end], " \r\n");
        const status = std.fmt.parseInt(u8, status_text, 10) catch return error.BadStatus;
        assert(output_start <= after - sentinel.len);
        const raw = session.console[output_start .. after - sentinel.len];
        const length = try clean_output(raw, session.scratch);
        return .{ .output = std.mem.trim(u8, session.scratch[0..length], "\n"), .status = status };
    }

    /// Types `text` on the guest console.
    pub fn send(session: *Session, text: []const u8) !void {
        var offset: usize = 0;
        while (offset < text.len) {
            const wrote = linux.write(session.input, text[offset..].ptr, text.len - offset);
            if (linux.errno(wrote) == .INTR or linux.errno(wrote) == .AGAIN) continue;
            if (linux.errno(wrote) != .SUCCESS) return error.ConsoleWriteFailed;
            offset += wrote;
        }
    }

    /// Waits for cloud-init to finish (not when `reuse`: an overlay already provisioned boots
    /// without it), then readies the root shell on the console: no echo, no bracketed paste, no
    /// prompt, and the guest's boot finished, so late service chatter (cloud-init prints key
    /// fingerprints, for one) cannot land in the middle of a command's output.
    pub fn provision(session: *Session, hostname: []const u8, reuse: bool) !void {
        var prompt_buffer: [limits.hostname_bytes_max + 8]u8 = undefined;
        const prompt = try cloud_init.prompt(&prompt_buffer, hostname);
        const boot_s = limits.boot_timeout_kvm_s;
        const ready = if (reuse) 0 else try session.wait_for(cloud_init.ready_marker, 0, boot_s);
        _ = try session.wait_for(prompt, ready, limits.command_timeout_kvm_s);
        try session.send("stty -echo; bind 'set enable-bracketed-paste off'; PS1=''\n");
        // The first command's output still contains the echo of the line above; discard it.
        _ = try session.run("true", limits.command_timeout_kvm_s);
        const settle = "cloud-init status --wait; systemctl is-system-running --wait; true";
        _ = try session.run(settle, limits.boot_timeout_kvm_s);
        const probe = try session.run("echo shell-ok", limits.command_timeout_kvm_s);
        if (!std.mem.eql(u8, probe.output, "shell-ok")) return error.ShellNotReady;
    }

    pub const CopyIn = struct {
        /// A path the session serves (one of `Seed.files`).
        route: []const u8,
        guest_path: []const u8,
        /// `user:group` for `chown`; empty keeps root's.
        owner: []const u8 = "",
        /// Octal, for `chmod`.
        mode: []const u8 = "644",
    };

    /// Fetches a served file into the guest with `curl`, sets its owner and mode, and lists it.
    /// Returns the command's result: on success, the `ls -l` line of the file.
    pub fn copy_in(session: *Session, copy: CopyIn) !Result {
        if (!session.server.serves(copy.route)) return error.NotServed;
        try cloud_init.check_word(copy.guest_path, false);
        try cloud_init.check_word(copy.owner, true);
        try cloud_init.check_word(copy.mode, false);
        var buffer: [limits.command_bytes_max]u8 = undefined;
        var writer: Io.Writer = .fixed(&buffer);
        writer.print("curl -fsS -o {s} http://10.0.2.2:{d}{s} && ", .{
            copy.guest_path, session.server.port, copy.route,
        }) catch return error.CommandTooLong;
        if (copy.owner.len > 0) {
            writer.print("chown {s} {s} && ", .{ copy.owner, copy.guest_path }) catch
                return error.CommandTooLong;
        }
        writer.print("chmod {s} {s} && ls -l {s}", .{
            copy.mode, copy.guest_path, copy.guest_path,
        }) catch return error.CommandTooLong;
        const command = writer.buffered();
        if (command.len >= limits.command_bytes_max) return error.CommandTooLong;
        return session.run(command, limits.command_timeout_kvm_s);
    }

    /// Writes `text` to `path` in the guest through base64 in short pieces (a typed line is at
    /// most 1 KiB, and the text may have quotes in it), and makes it executable. For small
    /// files only (`put_file_bytes_max`); a larger one is served and fetched with `copy_in`.
    pub fn put_file(session: *Session, path: []const u8, text: []const u8) !void {
        const encoder = std.base64.standard.Encoder;
        var encoded: [encoder.calcSize(limits.put_file_bytes_max)]u8 = undefined;
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

    /// Powers the guest off and waits for QEMU to exit.
    pub fn shutdown(session: *Session) !void {
        try session.send("poweroff\n");
        const deadline = now_ms() + @as(u64, limits.shutdown_timeout_s) * session.scale * 1000;
        while (!session.qemu_exited and now_ms() < deadline) try session.pump(limits.poll_step_ms);
        if (!session.qemu_exited) return error.ShutdownTimeout;
        _ = try session.child.wait(session.io);
    }
};

/// Copies `raw` console bytes to `out`, dropping carriage returns and terminal escape sequences
/// (bash prints bracketed-paste switches around prompts). Returns the length.
pub fn clean_output(raw: []const u8, out: []u8) !usize {
    var length: usize = 0;
    var index: usize = 0;
    while (index < raw.len) : (index += 1) {
        const byte = raw[index];
        if (byte == '\r') continue;
        if (byte == 0x1b) {
            // CSI: ESC [ parameters, ended by a byte in 0x40..0x7e.
            if (index + 1 < raw.len and raw[index + 1] == '[') index += 1;
            while (index + 1 < raw.len) {
                index += 1;
                if (raw[index] >= 0x40 and raw[index] <= 0x7e) break;
            }
            continue;
        }
        if (length == out.len) return error.OutputTooLong;
        out[length] = byte;
        length += 1;
    }
    return length;
}

test "clean_output drops carriage returns and escape sequences, keeps text" {
    // Goal: the guest's bracketed-paste switches and colours never reach an assertion.
    var out: [64]u8 = undefined;
    const raw = "\x1b[?2004lshell-ok\r\n\x1b[0;32mOK\x1b[0m done";
    const length = try clean_output(raw, &out);
    try std.testing.expectEqualStrings("shell-ok\nOK done", out[0..length]);
    var tiny: [3]u8 = undefined;
    try std.testing.expectError(error.OutputTooLong, clean_output("abcdef", &tiny));
}

/// What `qemu_argv` adds to the fixed command line.
pub const Extras = struct {
    disks: []const []const u8 = &.{},
    forwards: []const Forward = &.{},
};

pub fn qemu_argv(
    arena: std.mem.Allocator,
    overlay: []const u8,
    accel: Accel,
    port: u16,
    extras: Extras,
) ![]const []const u8 {
    const disks = extras.disks;
    assert(overlay.len > 0);
    assert(disks.len <= limits.disks_max);
    const netdev = try forward_mod.netdev_argument(arena, extras.forwards);
    const drive = try std.fmt.allocPrint(arena, "if=virtio,format=qcow2,file={s}", .{overlay});
    const seed = "type=1,serial=ds=nocloud;s=http://10.0.2.2:{d}/";
    const smbios = try std.fmt.allocPrint(arena, seed, .{port});
    const memory = try std.fmt.allocPrint(arena, "{d}", .{limits.guest_memory_mib});
    const cpus = try std.fmt.allocPrint(arena, "{d}", .{limits.guest_cpus});
    const accelerator: []const u8 = if (accel == .kvm) "kvm" else "tcg,thread=multi";
    const cpu: []const u8 = if (accel == .kvm) "host" else "max";
    const items = [_][]const u8{
        "qemu-system-x86_64",         "-machine",                     "q35",
        "-accel",                     accelerator,                    "-cpu",
        cpu,                          "-smp",                         cpus,
        "-m",                         memory,                         "-display",
        "none",                       "-monitor",                     "none",
        "-chardev",                   "stdio,id=console0,signal=off", "-serial",
        "chardev:console0",           "-drive",                       drive,
        "-netdev",                    netdev,                         "-device",
        "virtio-net-pci,netdev=net0", "-smbios",                      smbios,
        "-no-reboot",
    };
    const all = try arena.alloc([]const u8, items.len + 2 * disks.len);
    @memcpy(all[0..items.len], &items);
    for (disks, 0..) |disk, index| {
        assert(disk.len > 0);
        const format = "if=virtio,format=raw,file={s}";
        all[items.len + 2 * index] = "-drive";
        all[items.len + 2 * index + 1] = try std.fmt.allocPrint(arena, format, .{disk});
    }
    return all;
}

test "qemu arguments select the accelerator and point cloud-init at the host" {
    // Goal: KVM and TCG differ exactly where intended, and the seed URL uses the given port.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const kvm = try qemu_argv(arena, "o.qcow2", .kvm, 4242, .{});
    const tcg = try qemu_argv(arena, "o.qcow2", .tcg, 4242, .{});
    try std.testing.expectEqualStrings("qemu-system-x86_64", kvm[0]);
    try std.testing.expect(contains(kvm, "kvm") and contains(kvm, "host"));
    try std.testing.expect(contains(tcg, "tcg,thread=multi") and contains(tcg, "max"));
    try std.testing.expect(contains(kvm, "type=1,serial=ds=nocloud;s=http://10.0.2.2:4242/"));
    try std.testing.expect(contains(kvm, "if=virtio,format=qcow2,file=o.qcow2"));
    try std.testing.expectEqual(kvm.len, tcg.len);
    // An extra disk is a raw virtio drive, and only when one is named, in the order given.
    const cached = try qemu_argv(arena, "o.qcow2", .kvm, 4242, .{ .disks = &.{"blobs.img"} });
    try std.testing.expectEqual(kvm.len + 2, cached.len);
    try std.testing.expect(contains(cached, "if=virtio,format=raw,file=blobs.img"));
    try std.testing.expect(!contains(kvm, "if=virtio,format=raw,file=blobs.img"));
    const two = try qemu_argv(arena, "o.qcow2", .kvm, 4242, .{ .disks = &.{ "a.img", "b.img" } });
    try std.testing.expectEqual(kvm.len + 4, two.len);
    try std.testing.expectEqualStrings("if=virtio,format=raw,file=a.img", two[kvm.len + 1]);
    try std.testing.expectEqualStrings("if=virtio,format=raw,file=b.img", two[kvm.len + 3]);
}

fn contains(argv: []const []const u8, wanted: []const u8) bool {
    for (argv) |argument| {
        if (std.mem.eql(u8, argument, wanted)) return true;
    }
    return false;
}

test "qemu arguments: no forwards is the command line of before, forwards change one argument" {
    // Goal: the whole argv with no forwards is a frozen snapshot (it must stay byte-identical to
    // what the harness always ran), and forwards alter only the -netdev value.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const plain = try qemu_argv(arena, "o.qcow2", .kvm, 4242, .{});
    const drive = "if=virtio,format=qcow2,file=o.qcow2";
    const smbios = "type=1,serial=ds=nocloud;s=http://10.0.2.2:4242/";
    const expected = [_][]const u8{
        "qemu-system-x86_64",         "-machine",                     "q35",
        "-accel",                     "kvm",                          "-cpu",
        "host",                       "-smp",                         "2",
        "-m",                         "2048",                         "-display",
        "none",                       "-monitor",                     "none",
        "-chardev",                   "stdio,id=console0,signal=off", "-serial",
        "chardev:console0",           "-drive",                       drive,
        "-netdev",                    "user,id=net0",                 "-device",
        "virtio-net-pci,netdev=net0", "-smbios",                      smbios,
        "-no-reboot",
    };
    try std.testing.expectEqual(expected.len, plain.len);
    for (expected, plain) |want, got| try std.testing.expectEqualStrings(want, got);
    const forwarded = try qemu_argv(arena, "o.qcow2", .kvm, 4242, .{
        .forwards = &.{.{ .host_port = 2222, .guest_port = 22 }},
    });
    try std.testing.expectEqual(plain.len, forwarded.len);
    for (plain, forwarded, 0..) |want, got, index| {
        if (std.mem.eql(u8, want, "user,id=net0")) {
            try std.testing.expectEqualStrings("user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22", got);
            try std.testing.expectEqualStrings("-netdev", forwarded[index - 1]);
        } else try std.testing.expectEqualStrings(want, got);
    }
}
