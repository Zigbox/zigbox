//! The Z7 check, run in a real Ubuntu 24.04 VM: a TCP forward from the host into the guest
//! (`Seed.forwards`, docs/vm-module.md). A listener in the guest sends one line; the host
//! connects to the forwarded port on 127.0.0.1 and must read that line. It needs no zbx: it
//! boots the module's own guest and nothing else. `zig build demo-z7` (KVM) or with
//! `-Daccel=tcg`. The build passes the release binaries too, which this check ignores.

const std = @import("std");
const Io = std.Io;
const linux = std.os.linux;
const harness = @import("harness.zig");
const image = @import("image.zig");
const vm = @import("zigbox_vm");

const H = harness;
const Session = vm.Session;

const host_port: u16 = 18_729;
const guest_port: u16 = 9_000;
const greeting = "zigbox-z7-hostfwd-ok";
const hostname = "zigbox-z7";

const config: vm.Config = .{
    .hostname = hostname,
    .instance_id = "iid-zigbox-z7",
    .user = .{ .name = "demo", .uid = 1000 },
};

pub fn main(init: std.process.Init) !u8 {
    harness.demo_name = "demo-z7";
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const options = H.parse_options(init) catch |err| {
        try out.print("demo-z7: bad arguments ({s})\n", .{@errorName(err)});
        return 2;
    };
    const started = vm.now_ms();
    demo(init, out, options) catch |err| {
        if (err == error.NoKvm) {
            try out.print("demo-z7: /dev/kvm is not usable here; add -Daccel=tcg\n", .{});
            return 1;
        }
        try out.print("\ndemo-z7: FAILED ({s})\n", .{@errorName(err)});
        return 1;
    };
    try out.print("\ndemo-z7: PASSED in {d} s\n", .{(vm.now_ms() - started) / 1000});
    return 0;
}

fn demo(init: std.process.Init, out: *Io.Writer, options: H.Options) !void {
    const arena = init.arena.allocator();
    const accel = try vm.accel.choose(options.accel, vm.accel.kvm_usable(init.io));
    const base = try image.ensure(init, options.cache_dir, out);
    const format = "{s}/overlay-demo-z7.qcow2";
    const overlay = try std.fmt.allocPrint(arena, format, .{options.cache_dir});
    try image.make_overlay(init, base, overlay);
    defer Io.Dir.cwd().deleteFile(init.io, overlay) catch {};

    var user_data: [vm.limits.user_data_bytes_max]u8 = undefined;
    var meta_data: [vm.limits.meta_data_bytes_max]u8 = undefined;
    var session: Session = undefined;
    try session.start(init, out, overlay, accel, .{
        .user_data = try vm.cloud_init.render_user_data(&config, &user_data),
        .meta_data = try vm.cloud_init.render_meta_data(&config, &meta_data),
        .forwards = &.{.{ .host_port = host_port, .guest_port = guest_port }},
    });
    defer session.deinit();
    try session.provision(hostname, false);
    try listen_in_guest(&session, out);
    try read_through_forward(&session, out);
    try session.shutdown();
}

/// A one-shot listener in the guest: accepts one connection, sends the greeting, closes.
fn listen_in_guest(session: *Session, out: *Io.Writer) !void {
    try out.print("\ndemo-z7: a listener in the guest on port {d}\n", .{guest_port});
    const command = "nohup python3 -c \"import socket;s=socket.socket();" ++
        "s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',9000));" ++
        "s.listen(1);c,_=s.accept();c.sendall(b'" ++ greeting ++ "\\\\n');c.close()\" " ++
        ">/tmp/listener.log 2>&1 & sleep 1; ss -ltn | grep -c ':9000 '";
    const result = try session.run(command, vm.limits.command_timeout_kvm_s);
    try H.show(out, "start the guest listener", result);
    if (result.status != 0) return error.ListenerNotRunning;
}

/// Connects to the forwarded host port until the greeting arrives, driving the console meanwhile.
/// QEMU accepts on the host port before the guest answers, so a first try may see a reset.
fn read_through_forward(session: *Session, out: *Io.Writer) !void {
    try out.print("demo-z7: host connects to 127.0.0.1:{d}\n", .{host_port});
    const deadline = vm.now_ms() + 20_000 * @as(u64, session.scale);
    var line: [64]u8 = undefined;
    while (vm.now_ms() < deadline) {
        const length = try connect_and_read(&line);
        if (length > 0) {
            const text = std.mem.trimEnd(u8, line[0..length], "\r\n");
            try out.print("demo-z7: host read: {s}\n", .{text});
            if (!std.mem.eql(u8, text, greeting)) return error.WrongGreeting;
            return;
        }
        try session.pump(vm.limits.poll_step_ms);
    }
    return error.NoGreeting;
}

/// One attempt: connect to the forward and read what the guest sends. Returns 0 on a reset, a
/// refusal or an empty close, so the caller tries again.
fn connect_and_read(line: []u8) !usize {
    const created = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(created) != .SUCCESS) return error.SocketFailed;
    const client: i32 = @intCast(created);
    defer _ = linux.close(client);
    var address: linux.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, host_port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    const connected = linux.connect(client, @ptrCast(&address), @sizeOf(@TypeOf(address)));
    if (linux.errno(connected) != .SUCCESS) return 0;
    var entry = [1]linux.pollfd{.{ .fd = client, .events = linux.POLL.IN, .revents = 0 }};
    const ready = linux.poll(&entry, 1, 2_000);
    if (linux.errno(ready) != .SUCCESS or ready == 0) return 0;
    const got = linux.read(client, line.ptr, line.len);
    if (linux.errno(got) != .SUCCESS) return 0;
    return got;
}
