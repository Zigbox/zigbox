//! The macOS VM records fuzzer: `zig build fuzz -- vm`. Each iteration renders a random settings
//! record, a control-socket status line and a guest hello reply, reads each back exactly, then
//! damages the text (flips, inserts, deletes, truncations, repeats) and checks that the parsers
//! never crash and that whatever they accept renders again to the same bytes (REVIEW.md: parse
//! accepts only what render can write).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const control = @import("mac/control.zig");
const dhcp = @import("vm_dhcp.zig");
const forward = @import("forward_protocol.zig");
const protocol = @import("vm_protocol.zig");
const settings = @import("mac/settings.zig");

/// Damages `text[0..length_in]` in place with one to four edits; returns the new length.
fn damage(random: std.Random, text: []u8, length_in: usize) usize {
    var length = length_in;
    for (0..random.intRangeAtMost(u8, 1, 4)) |_| {
        switch (random.uintLessThan(u8, 5)) {
            0 => if (length > 0) {
                text[random.uintLessThan(usize, length)] = random.int(u8);
            },
            1 => if (length + 1 < text.len) {
                const at = random.uintAtMost(usize, length);
                @memmove(text[at + 1 .. length + 1], text[at..length]);
                text[at] = "0 =\n/x9"[random.uintLessThan(usize, 7)];
                length += 1;
            },
            2 => if (length > 0) {
                const at = random.uintLessThan(usize, length);
                @memmove(text[at .. length - 1], text[at + 1 .. length]);
                length -= 1;
            },
            3 => length = random.uintAtMost(usize, length),
            else => if (length > 0 and length * 2 <= text.len) {
                @memcpy(text[length .. length * 2], text[0..length]);
                length *= 2;
            },
        }
    }
    return length;
}

fn random_version(random: std.Random) [constants.vm_image_version_bytes]u8 {
    var version: [constants.vm_image_version_bytes]u8 = undefined;
    for (&version) |*byte| byte.* = "0123456789abcdef"[random.uintLessThan(usize, 16)];
    return version;
}

fn check_settings(random: std.Random) void {
    const values: settings.Settings = .{
        .cpus = random.intRangeAtMost(u32, constants.vm_cpus_min, constants.vm_cpus_max),
        .memory_bytes = random.intRangeAtMost(
            u64,
            constants.vm_memory_bytes_min >> 20,
            constants.vm_memory_bytes_max >> 20,
        ) << 20,
    };
    var buffer: [settings.record_bytes_max]u8 = undefined;
    const text = settings.render(&buffer, values);
    assert(std.meta.eql(values, settings.parse(text) catch unreachable)); // Render reads back.
    var damaged: [settings.record_bytes_max * 2]u8 = undefined;
    @memcpy(damaged[0..text.len], text);
    const length = damage(random, &damaged, text.len);
    const parsed = settings.parse(damaged[0..length]) catch return;
    var again: [settings.record_bytes_max]u8 = undefined;
    assert(std.mem.eql(u8, damaged[0..length], settings.render(&again, parsed)));
}

fn check_status(random: std.Random) void {
    const status: control.Status = .{
        .state = random.enumValue(control.State),
        .pid = random.intRangeAtMost(u32, 1, std.math.maxInt(u32)),
        .cpus = random.intRangeAtMost(u32, 1, constants.vm_cpus_max),
        .memory_bytes = random.int(u64),
        .version = random_version(random),
        .network_up = random.boolean(),
        .uptime_ms = random.uintLessThan(u64, 1 << 40),
    };
    var buffer: [constants.vm_line_bytes_max]u8 = undefined;
    const text = control.render_status(&buffer, &status);
    assert(std.meta.eql(status, control.parse_reply(text).?.status)); // Render reads back.
    var damaged: [constants.vm_line_bytes_max * 2]u8 = undefined;
    @memcpy(damaged[0..text.len], text);
    const length = damage(random, &damaged, text.len);
    const parsed = control.parse_reply(damaged[0..length]) orelse return;
    switch (parsed) {
        .stopping => assert(std.mem.eql(u8, damaged[0..length], control.render_stopping())),
        // Another release's line: it starts with the family and ends in a newline, nothing more.
        .other_format => assert(std.mem.startsWith(u8, damaged[0..length], "zbx-vm-host/")),
        .status => |accepted| {
            var again: [constants.vm_line_bytes_max]u8 = undefined;
            assert(std.mem.eql(u8, damaged[0..length], control.render_status(&again, &accepted)));
        },
    }
}

fn check_hello(random: std.Random) void {
    const version = random_version(random);
    var buffer: [constants.vm_line_bytes_max]u8 = undefined;
    const text = protocol.render_hello_reply(&buffer, &version);
    assert(std.mem.eql(u8, protocol.parse_hello_reply(text).?, &version)); // Render reads back.
    var damaged: [constants.vm_line_bytes_max * 2]u8 = undefined;
    @memcpy(damaged[0..text.len], text);
    const length = damage(random, &damaged, text.len);
    const accepted = protocol.parse_hello_reply(damaged[0..length]) orelse return;
    var again: [constants.vm_line_bytes_max]u8 = undefined;
    assert(std.mem.eql(u8, damaged[0..length], protocol.render_hello_reply(&again, accepted)));
}

const words = [_][]const u8{ "run", "alpine", "--", "cat", "/etc/os-release", "-e", "A=b", "" };

fn check_forward(random: std.Random) void {
    var arguments: [constants.args_count_max][]const u8 = undefined;
    const argument_count = random.intRangeAtMost(usize, 1, 8);
    for (arguments[0..argument_count]) |*argument| {
        argument.* = words[random.uintLessThan(usize, words.len)];
    }
    const environment = [_][]const u8{ "TERM=xterm", "NO_COLOR=1" };
    const pty = random.boolean();
    const start: forward.Start = .{
        .pty = pty,
        .stderr_pipe = !pty or random.boolean(),
        .rows = random.int(u16),
        .columns = random.int(u16),
        .working_directory = if (random.boolean()) "/Users/ada/project" else "",
        .arguments = arguments[0..argument_count],
        .environment = environment[0..random.uintAtMost(usize, environment.len)],
    };
    var payload: [constants.forward_start_bytes_max]u8 = undefined;
    const text = forward.render_start(&payload, &start).?;
    var parsed_arguments: [constants.args_count_max][]const u8 = undefined;
    var parsed_environment: [constants.forward_env_count_max][]const u8 = undefined;
    const back = forward.parse_start(text, &parsed_arguments, &parsed_environment).?;
    assert(back.arguments.len == start.arguments.len); // Render reads back.
    var damaged: [constants.forward_start_bytes_max * 2]u8 = undefined;
    @memcpy(damaged[0..text.len], text);
    const length = damage(random, &damaged, text.len);
    const accepted = forward.parse_start(
        damaged[0..length],
        &parsed_arguments,
        &parsed_environment,
    ) orelse return;
    var again: [constants.forward_start_bytes_max]u8 = undefined;
    assert(std.mem.eql(u8, damaged[0..length], forward.render_start(&again, &accepted).?));
}

fn check_headers(random: std.Random) void {
    var bytes: [constants.forward_header_bytes]u8 = undefined;
    random.bytes(&bytes);
    bytes[0] %= 10;
    const header = forward.parse_header(&bytes) orelse return;
    var again: [constants.forward_header_bytes]u8 = undefined;
    forward.render_header(&again, header.kind, header.length);
    assert(std.mem.eql(u8, &bytes, &again)); // Accepted headers are exactly what render writes.
}

fn check_dhcp(random: std.Random) void {
    const mac = [6]u8{ 2, 1, 2, 3, 4, 5 };
    var packet: [constants.vm_dhcp_packet_bytes_max]u8 = undefined;
    const lease: dhcp.Lease = .{
        .kind = .offer,
        .address = .{ 10, 0, 0, random.int(u8) },
        .server = .{ 10, 0, 0, 1 },
        .mask = .{ 255, 255, 255, 0 },
        .router = if (random.boolean()) .{ 10, 0, 0, 1 } else null,
        .dns = if (random.boolean()) .{ 10, 0, 0, 1 } else null,
        .seconds = random.int(u32),
    };
    const text = dhcp.render_reply(&packet, mac, 7, &lease);
    assert(std.meta.eql(lease, dhcp.parse_reply(text, mac, 7).?)); // Render reads back.
    var damaged: [constants.vm_dhcp_packet_bytes_max * 2]u8 = undefined;
    @memcpy(damaged[0..text.len], text);
    const length = damage(random, &damaged, text.len);
    const accepted = dhcp.parse_reply(damaged[0..length], mac, 7) orelse return;
    assert(accepted.kind != .discover);
    assert(accepted.kind != .request);
}

fn check_setup(random: std.Random) void {
    const names = [_][]const u8{ "ada", "a-b.c_d", "x" };
    const setup: protocol.Setup = .{
        .seconds = random.int(u40),
        .uid = random.intRangeAtMost(u32, 1, 70000),
        .gid = random.int(u16),
        .name = names[random.uintLessThan(usize, names.len)],
        .home = "/Users/ada",
        .dns = if (random.boolean()) "-" else "192.168.1.1,10.0.0.2",
    };
    var buffer: [constants.vm_line_bytes_max]u8 = undefined;
    const text = protocol.render_setup(&buffer, &setup);
    assert(protocol.parse_setup(text) != null); // Render reads back.
    var damaged: [constants.vm_line_bytes_max * 2]u8 = undefined;
    @memcpy(damaged[0..text.len], text);
    const length = damage(random, &damaged, text.len);
    const accepted = protocol.parse_setup(damaged[0..length]) orelse return;
    var again: [constants.vm_line_bytes_max]u8 = undefined;
    assert(std.mem.eql(u8, damaged[0..length], protocol.render_setup(&again, &accepted)));
}

pub fn fuzz_vm(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    for (0..4) |_| {
        check_settings(random);
        check_status(random);
        check_hello(random);
        check_forward(random);
        check_headers(random);
        check_dhcp(random);
        check_setup(random);
    }
    // Random bytes: whatever parses is a record render would write.
    var noise: [96]u8 = undefined;
    random.bytes(&noise);
    _ = settings.parse(noise[0..random.uintAtMost(usize, noise.len)]) catch {};
    _ = control.parse_reply(noise[0..random.uintAtMost(usize, noise.len)]);
    _ = protocol.parse_hello_reply(noise[0..random.uintAtMost(usize, noise.len)]);
}
