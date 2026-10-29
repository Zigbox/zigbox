//! The macOS VM records fuzzer: `zig build fuzz -- vm`. Each iteration renders a random settings
//! record, a control-socket status line and a guest hello reply, reads each back exactly, then
//! damages the text (flips, inserts, deletes, truncations, repeats) and checks that the parsers
//! never crash and that whatever they accept renders again to the same bytes (REVIEW.md: parse
//! accepts only what render can write).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const control = @import("mac/control.zig");
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

pub fn fuzz_vm(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    for (0..4) |_| {
        check_settings(random);
        check_status(random);
        check_hello(random);
    }
    // Random bytes: whatever parses is a record render would write.
    var noise: [96]u8 = undefined;
    random.bytes(&noise);
    _ = settings.parse(noise[0..random.uintAtMost(usize, noise.len)]) catch {};
    _ = control.parse_reply(noise[0..random.uintAtMost(usize, noise.len)]);
    _ = protocol.parse_hello_reply(noise[0..random.uintAtMost(usize, noise.len)]);
}
