//! The D-Bus fuzzer: `zig build fuzz -- dbus`. One iteration does five things, all from the seed.
//!
//!   1. Builds a message whose body is a random run of values, written by the marshaller with the
//!      signature recorded beside it, and checks that the parser and a reader following the
//!      signature give back exactly what was written (the recorded values are the oracle).
//!   2. Damages that message the ways a peer can: cuts it, flips bytes, flips the byte order,
//!      writes huge lengths into the header, misaligns a field, nests a signature too deep,
//!      appends junk. The parser must return, and when it accepts the bytes the message must
//!      satisfy what its readers rely on (slices inside the input, lengths that add up).
//!   3. Feeds the parser and the frame check bytes with no structure at all.
//!   4. Reads random bus addresses and SASL lines.
//!   5. Runs the client's whole conversation (connect, auth, Hello, Version, scope) against the
//!      simulated bus with a random model, a random misbehaviour and random socket faults, and
//!      checks the outcome against what the model says it must be, that a failure is recorded,
//!      and that nothing is left open or running.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const auth = @import("dbus/auth.zig");
const client = @import("dbus/client.zig");
const host_mod = @import("host.zig");
const HostSim = @import("host_sim.zig").HostSim;
const message_mod = @import("dbus/message.zig");
const sim_bus = @import("sim_bus.zig");
const systemd = @import("dbus/systemd.zig");
const wire = @import("dbus/wire.zig");

pub fn fuzz_dbus(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    check_round_trip(random);
    check_damaged(random);
    check_soup(random);
    check_text(random);
    check_conversation(random);
}

// ---- 1. The round trip ---------------------------------------------------------------------

const Value = union(enum) {
    byte: u8,
    boolean: bool,
    uint16: u16,
    uint32: u32,
    uint64: u64,
    string: []const u8,
    path: []const u8,
    signature: []const u8,
};

const values_max: u32 = 12;
const words = [_][]const u8{ "", "a", "org.freedesktop.systemd1", "zbx-web.scope", "done", "x y" };
const paths = [_][]const u8{ "/", "/org", "/org/freedesktop/systemd1/job/9", "/a_b/c1" };
const signatures = [_][]const u8{ "", "s", "a(sv)", "uoss", "au", "a(sa(sv))" };

fn random_values(random: std.Random, values: *[values_max]Value) u32 {
    const count = random.uintAtMost(u32, values_max);
    for (values[0..count]) |*value| {
        value.* = switch (random.uintLessThan(u8, 8)) {
            0 => .{ .byte = random.int(u8) },
            1 => .{ .boolean = random.boolean() },
            2 => .{ .uint16 = random.int(u16) },
            3 => .{ .uint32 = random.int(u32) },
            4 => .{ .uint64 = random.int(u64) },
            5 => .{ .string = words[random.uintLessThan(usize, words.len)] },
            6 => .{ .path = paths[random.uintLessThan(usize, paths.len)] },
            else => .{ .signature = signatures[random.uintLessThan(usize, signatures.len)] },
        };
    }
    return count;
}

fn marshal_values(writer: *wire.Writer, signature: *[values_max]u8, values: []const Value) void {
    for (values, 0..) |value, index| {
        switch (value) {
            .byte => |item| {
                writer.byte(item);
                signature[index] = 'y';
            },
            .boolean => |item| {
                writer.boolean(item);
                signature[index] = 'b';
            },
            .uint16 => |item| {
                writer.uint16(item);
                signature[index] = 'q';
            },
            .uint32 => |item| {
                writer.uint32(item);
                signature[index] = 'u';
            },
            .uint64 => |item| {
                writer.uint64(item);
                signature[index] = 't';
            },
            .string => |item| {
                writer.string(item);
                signature[index] = 's';
            },
            .path => |item| {
                writer.object_path(item);
                signature[index] = 'o';
            },
            .signature => |item| {
                writer.signature(item);
                signature[index] = 'g';
            },
        }
    }
}

fn read_back(reader: *wire.Reader, value: Value) !void {
    switch (value) {
        .byte => |item| assert(try reader.byte() == item),
        .boolean => |item| assert(try reader.boolean() == item),
        .uint16 => |item| assert(try reader.uint16() == item),
        .uint32 => |item| assert(try reader.uint32() == item),
        .uint64 => |item| assert(try reader.uint64() == item),
        .string => |item| assert(std.mem.eql(u8, try reader.string(), item)),
        .path => |item| assert(std.mem.eql(u8, try reader.object_path(), item)),
        .signature => |item| assert(std.mem.eql(u8, try reader.signature(), item)),
    }
}

/// Builds the message bytes of iteration into `buffer`; the values are kept for the oracle.
fn build_message(
    random: std.Random,
    buffer: []u8,
    values: *[values_max]Value,
    count: *u32,
) []const u8 {
    count.* = random_values(random, values);
    var body_buffer: [1024]u8 = undefined;
    var writer = wire.Writer.init(&body_buffer);
    var signature: [values_max]u8 = undefined;
    marshal_values(&writer, &signature, values[0..count.*]);
    const body = writer.finish() catch unreachable; // Twelve short values in 1 KiB.
    const kind: message_mod.Kind = switch (random.uintLessThan(u8, 4)) {
        0 => .method_call,
        1 => .method_return,
        2 => .error_reply,
        else => .signal,
    };
    return message_mod.encode(buffer, .{
        .kind = kind,
        .serial = random.intRangeAtMost(u32, 1, std.math.maxInt(u32)),
        .path = if (kind == .method_call or kind == .signal) "/org/zbx" else null,
        .interface = if (kind == .signal) "org.zbx.Test" else null,
        .member = if (kind == .method_call or kind == .signal) "Go" else null,
        .error_name = if (kind == .error_reply) "org.zbx.Error.Test" else null,
        .reply_serial = if (kind == .method_return or kind == .error_reply) 7 else null,
        .destination = if (random.boolean()) ":1.5" else null,
        .signature = signature[0..count.*],
        .body = body,
    }) catch unreachable; // A short message in the buffer.
}

fn check_round_trip(random: std.Random) void {
    var values: [values_max]Value = undefined;
    var count: u32 = 0;
    var buffer: [constants.dbus_message_bytes_max]u8 = undefined;
    const bytes = build_message(random, &buffer, &values, &count);
    const message = message_mod.parse(bytes) catch unreachable; // Our own encoding.
    assert(message.signature.len == count);
    wire.check_signature(message.signature) catch unreachable; // Same.
    var reader = message.body_reader();
    for (values[0..count]) |value| read_back(&reader, value) catch unreachable; // Same.
    assert(reader.remaining() == 0);
    const header_bytes = message_mod.fixed_header_bytes;
    const prefix: *const [header_bytes]u8 = bytes[0..header_bytes];
    assert((message_mod.frame_length(prefix) catch unreachable) == bytes.len); // Same.
}

// ---- 2. Damaged messages -------------------------------------------------------------------

fn damage(random: std.Random, bytes: []u8, length_in: usize) usize {
    var length = length_in;
    for (0..random.intRangeAtMost(u8, 1, 4)) |_| {
        switch (random.uintLessThan(u8, 8)) {
            0 => length = random.uintAtMost(usize, length), // Cut.
            1 => if (length > 0) {
                bytes[random.uintLessThan(usize, length)] ^= @as(u8, 1) << random.int(u3);
            },
            2 => if (length > 0) {
                bytes[0] = if (bytes[0] == 'l') 'B' else 'l'; // The wrong byte order.
            },
            3 => if (length >= message_mod.fixed_header_bytes) {
                const at: usize = if (random.boolean()) 4 else 12; // A huge length.
                std.mem.writeInt(u32, bytes[at..][0..4], random.int(u32), .little);
            },
            4 => if (length > 0) {
                // The values that sit on the edges of the format: NUL, the longest counts, 'l'.
                const edge = [_]u8{ 0, 1, 7, 8, 0x7f, 0xff, 'l', 'B' };
                bytes[random.uintLessThan(usize, length)] = edge[random.uintLessThan(usize, 8)];
            },
            5 => if (length + 8 <= bytes.len) {
                @memset(bytes[length..][0..8], random.int(u8)); // Junk after the message.
                length += 8;
            },
            6 => if (length > message_mod.fixed_header_bytes) {
                // A misaligned message: drop one byte from the middle.
                const at = random.intRangeLessThan(usize, 1, length);
                @memmove(bytes[at .. length - 1], bytes[at + 1 .. length]);
                length -= 1;
            },
            else => if (length > 0) {
                const at = random.uintLessThan(usize, length);
                bytes[at] = 0xff;
            },
        }
    }
    return length;
}

/// What a reader may rely on in a message the parser accepted.
fn check_accepted(message: *const message_mod.Message, input: []const u8) void {
    assert(message.serial != 0);
    wire.check_signature(message.signature) catch unreachable; // `signature()` checked it.
    assert(message.body.len <= input.len);
    const input_start = @intFromPtr(input.ptr);
    const input_end = input_start + input.len;
    const body_start = @intFromPtr(message.body.ptr);
    if (message.body.len > 0) {
        assert(body_start >= input_start);
        assert(body_start + message.body.len == input_end);
    }
    inline for (.{ "path", "interface", "member", "error_name", "destination", "sender" }) |name| {
        if (@field(message, name)) |text| {
            if (text.len > 0) {
                assert(@intFromPtr(text.ptr) >= input_start);
                assert(@intFromPtr(text.ptr) + text.len <= input_end);
            }
            assert(std.mem.indexOfScalar(u8, text, 0) == null);
        }
    }
    walk_body(message);
}

/// Reads the body by its signature as far as the basic types go: never past the body.
fn walk_body(message: *const message_mod.Message) void {
    var reader = message.body_reader();
    for (message.signature) |code| {
        const ok = switch (code) {
            'y' => if (reader.byte()) |_| true else |_| false,
            'b' => if (reader.boolean()) |_| true else |_| false,
            'q', 'n' => if (reader.uint16()) |_| true else |_| false,
            'u', 'i' => if (reader.uint32()) |_| true else |_| false,
            't', 'x' => if (reader.uint64()) |_| true else |_| false,
            's' => if (reader.string()) |_| true else |_| false,
            'o' => if (reader.object_path()) |_| true else |_| false,
            'g' => if (reader.signature()) |_| true else |_| false,
            else => false, // Containers: not walked here.
        };
        assert(reader.at <= message.body.len);
        if (!ok) return;
    }
}

fn check_damaged(random: std.Random) void {
    var values: [values_max]Value = undefined;
    var count: u32 = 0;
    var buffer: [constants.dbus_message_bytes_max]u8 = undefined;
    const bytes = build_message(random, &buffer, &values, &count);
    var work: [constants.dbus_message_bytes_max]u8 = undefined;
    @memcpy(work[0..bytes.len], bytes);
    const length = damage(random, &work, bytes.len);
    const input = work[0..length];
    if (message_mod.parse(input)) |message| {
        check_accepted(&message, input);
    } else |_| {}
}

// ---- 3 and 4. Soup, addresses, SASL lines --------------------------------------------------

fn check_soup(random: std.Random) void {
    var bytes: [constants.dbus_message_bytes_max + 64]u8 = undefined;
    const length = random.uintAtMost(usize, bytes.len);
    random.bytes(bytes[0..length]);
    const looks_right = [_]u8{ 'l', 1, 0, 1 };
    if (random.boolean() and length >= 4) @memcpy(bytes[0..4], &looks_right);
    if (length >= message_mod.fixed_header_bytes) {
        _ = message_mod.frame_length(bytes[0..message_mod.fixed_header_bytes]) catch {};
    }
    if (length <= constants.dbus_message_bytes_max) {
        if (message_mod.parse(bytes[0..length])) |message| {
            check_accepted(&message, bytes[0..length]);
        } else |_| {}
    }
    var signature: [48]u8 = undefined;
    const signature_length = random.uintAtMost(usize, signature.len);
    const codes = "ybnqiuxtsogav()a{}d";
    for (signature[0..signature_length]) |*code| {
        code.* = codes[random.uintLessThan(usize, codes.len)];
    }
    _ = wire.check_signature(signature[0..signature_length]) catch {};
}

const address_pieces = [_][]const u8{
    "unix:",       "path=",  "/run/user/1000/bus", ",",   ";",
    "guid=ab",     "%2",     "%20",                "%zz", "abstract=",
    "tcp:",        "host=x", "/",                  "a",   "%00",
    "runtime=yes", "",
};

fn check_text(random: std.Random) void {
    var text: [constants.dbus_address_bytes_max + 32]u8 = undefined;
    var length: usize = 0;
    for (0..random.uintAtMost(u8, 8)) |_| {
        const piece = address_pieces[random.uintLessThan(usize, address_pieces.len)];
        if (length + piece.len > text.len) break;
        @memcpy(text[length..][0..piece.len], piece);
        length += piece.len;
    }
    if (random.uintLessThan(u8, 16) == 0) {
        length = random.uintAtMost(usize, text.len);
        random.bytes(text[0..length]);
    }
    var path_buffer: [constants.dbus_socket_path_bytes_max]u8 = undefined;
    if (auth.socket_path(&path_buffer, text[0..length])) |path| {
        assert(path.len > 0);
        assert(path.len <= constants.dbus_socket_path_bytes_max);
        assert(std.mem.indexOfScalar(u8, path, 0) == null);
        // Only a unix:path address gets this far.
        assert(std.mem.startsWith(u8, text[0..length], "unix:"));
    } else |_| {}
    var line: [constants.dbus_auth_line_bytes_max]u8 = undefined;
    const line_length = random.uintAtMost(usize, line.len);
    random.bytes(line[0..line_length]);
    for (line[0..line_length]) |*byte| {
        if (byte.* == '\n') byte.* = ' ';
    }
    const reply = auth.parse_reply(line[0..line_length]);
    if (reply == .ok) assert(std.mem.startsWith(u8, line[0..line_length], "OK"));
}

// ---- 5. The conversation -------------------------------------------------------------------

const fault_errors = [_]host_mod.Error{ error.IoFailed, error.AccessDenied, error.NoSpace };

const errors_named = [_][]const u8{
    "org.freedesktop.DBus.Error.AccessDenied",
    "org.freedesktop.DBus.Error.NoReply",
    "org.freedesktop.systemd1.UnitExists",
};

fn random_model(random: std.Random, model: *sim_bus.Model) void {
    model.* = .{};
    model.present = random.uintLessThan(u8, 8) != 0;
    model.refuses = random.uintLessThan(u8, 12) == 0;
    model.auth = switch (random.uintLessThan(u8, 8)) {
        0 => .reject,
        1 => .other,
        else => .accept,
    };
    if (random.uintLessThan(u8, 10) == 0) model.hello_error = errors_named[0];
    model.systemd_present = random.uintLessThan(u8, 8) != 0;
    model.unit_taken = random.uintLessThan(u8, 8) == 0;
    if (random.uintLessThan(u8, 10) == 0) {
        model.start_error = errors_named[random.uintLessThan(usize, errors_named.len)];
    }
    if (random.uintLessThan(u8, 8) == 0) model.job_result = "failed";
    model.job_removed = random.uintLessThan(u8, 10) != 0;
    if (random.uintLessThan(u8, 5) == 0) {
        model.misbehave = .{
            .at_call = random.uintLessThan(u32, 4),
            .how = std.enums.values(sim_bus.Misbehaviour)[random.uintLessThan(usize, 6)],
        };
    }
}

/// Whether the model lets the whole conversation succeed.
fn model_succeeds(model: *const sim_bus.Model) bool {
    if (!model.present or model.refuses) return false;
    if (model.auth != .accept) return false;
    if (model.hello_error != null) return false;
    if (!model.systemd_present or model.unit_taken or model.start_error != null) return false;
    if (!std.mem.eql(u8, model.job_result, "done") or !model.job_removed) return false;
    return model.misbehave == null;
}

fn check_conversation(random: std.Random) void {
    var sim: HostSim = undefined;
    sim.init(random.int(u64), &.{});
    random_model(random, &sim.world.bus.model);
    const faulted = random.uintLessThan(u8, 4) == 0;
    if (faulted) {
        sim.faults.fail_call_index = random.uintLessThan(u32, 12);
        sim.faults.fail_call_error = fault_errors[random.uintLessThan(usize, fault_errors.len)];
    }
    if (random.boolean()) sim.faults.short_read_per_mille = random.uintAtMost(u16, 1000);
    if (random.uintLessThan(u8, 8) == 0) {
        sim.faults.interrupt_per_mille = random.uintAtMost(u16, 300);
    }
    var conn: client.Connection = undefined;
    conn.init(sim.interface());
    const succeeded = converse(&conn);
    conn.close();
    assert(sim.open_count() == 0);
    if (succeeded) {
        assert(sim.world.bus.scope_count() == 1);
        assert(model_succeeds(&sim.world.bus.model));
        return;
    }
    assert(sim.world.bus.scope_count() <= 1);
    if (!faulted) {
        // Without injected faults the model alone decides, and the failure says what and where.
        assert(!model_succeeds(&sim.world.bus.model));
        check_failure_kind(&conn, &sim.world.bus.model);
    }
    assert(conn.failure.errno < 4096);
}

fn converse(conn: *client.Connection) bool {
    conn.connect("/run/user/1000/bus") catch return false;
    conn.authenticate(1000) catch return false;
    conn.hello() catch return false;
    var version: systemd.Version = undefined;
    systemd.read_version(conn, &version) catch return false;
    const request: systemd.ScopeRequest = .{
        .name = "zbx-fuzz.scope",
        .description = "zbx: fuzz",
        .pid = 600,
        .keeper_pid = 601,
        .slice = "app.slice",
        .memory_max = 1 << 28,
        .memory_swap_zero = true,
        .tasks_max = 64,
        .cpu_quota_usec = 250_000,
    };
    systemd.start_scope(conn, &request) catch return false;
    return true;
}

/// The failure of a conversation with no injected fault, from the model alone.
fn check_failure_kind(conn: *const client.Connection, model: *const sim_bus.Model) void {
    const failure = &conn.failure;
    if (!model.present or model.refuses) {
        assert(failure.kind == .no_bus);
        assert(failure.stage == .connect);
        return;
    }
    if (model.auth != .accept) {
        assert(failure.kind == .auth_refused);
        return;
    }
    if (model.misbehave != null) {
        // Which call it hits decides the stage; any kind but a socket error can result.
        assert(failure.kind != .no_bus);
        assert(failure.kind != .auth_refused);
        return;
    }
    if (model.hello_error != null) {
        assert(failure.kind == .remote);
        assert(failure.stage == .hello);
        return;
    }
    if (!model.systemd_present) {
        assert(failure.kind == .remote);
        assert(std.mem.endsWith(u8, failure.name.slice(), "ServiceUnknown"));
        return;
    }
    if (model.unit_taken or model.start_error != null) {
        assert(failure.kind == .remote);
        assert(failure.stage == .call);
        return;
    }
    // The job: a result other than done is remote, a signal that never comes is a timeout.
    if (!std.mem.eql(u8, model.job_result, "done") and model.job_removed) {
        assert(failure.kind == .remote);
        assert(failure.stage == .job);
    } else {
        assert(failure.kind == .timeout);
        assert(failure.stage == .job);
    }
}
