//! The redaction fuzzer: `zig build fuzz -- redact`. Each iteration builds text out of junk and of
//! secrets planted in the shapes redact.zig claims to cover (assignments, flags, JSON and ZON
//! pairs, quoted and escaped values, bearer headers, private keys, token shapes, labels, and
//! values zbx was told to scrub), sometimes escaped once or twice the way a run record escapes a
//! command. The property: no planted secret is in the output, whatever the size of the output
//! buffer (a full buffer stops, it never copies the rest). The oracle is the planting itself, so
//! it does not share code with the redactor. Damaged and random text only has to be survived:
//! no crash, the output within its buffer, and the same answer twice.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const redact = @import("redact.zig");

const input_bytes_max = 4096;
const secrets_per_input_max = 6;

const names = [_][]const u8{
    "TOKEN",          "GITHUB_TOKEN", "api_key", "API-KEY",        "client_secret",
    "DB_PASSWORD",    "passwd",       "MyKey",   "ssh_passphrase", "aws_credentials",
    "SECRET_TOKEN_X", "monkey",
};

const junk = [_][]const u8{
    "echo",
    "hello",
    "/bin/sh",
    "-c",
    "--verbose",
    "x=1",
    "PATH=/bin",
    "{",
    "}",
    "[",
    "]",
    ",",
    ":",
    ";",
    "&&",
    "|",
    "$HOME",
    "a.b.c",
    "--rootfs",
    "bearer",
    "Authorization",
    "-----",
    "BEGIN",
    "END",
    "key",
    "token",
    "\"",
    "'",
    "\\",
    "=",
    "\n",
    "\t",
    "ghp_",
    "sk-",
    "eyJ",
};

const pem_format = "-----BEGIN PRIVATE KEY-----\n{s}\n-----END PRIVATE KEY-----";

const Planted = struct {
    values: [secrets_per_input_max][64]u8 = undefined,
    lengths: [secrets_per_input_max]u8 = @splat(0),
    count: u32 = 0,
    /// Values handed to the redactor as literals.
    literals: [secrets_per_input_max][]const u8 = undefined,
    literals_count: u32 = 0,

    fn slice(planted: *const Planted, index: u32) []const u8 {
        return planted.values[index][0..planted.lengths[index]];
    }
};

const Builder = struct {
    bytes: [input_bytes_max]u8 = undefined,
    len: u32 = 0,

    fn add(builder: *Builder, piece: []const u8) void {
        if (builder.len + piece.len > builder.bytes.len) return;
        @memcpy(builder.bytes[builder.len..][0..piece.len], piece);
        builder.len += @intCast(piece.len);
    }

    fn text(builder: *const Builder) []const u8 {
        return builder.bytes[0..builder.len];
    }
};

/// A fresh secret: a recognisable prefix and random letters and digits. With `space`, a space
/// in the middle (for contexts that quote their value).
fn plant(random: std.Random, planted: *Planted, space: bool, min: u32) []const u8 {
    assert(planted.count < secrets_per_input_max);
    const index = planted.count;
    planted.count += 1;
    const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    var length: u32 = 0;
    const buffer = &planted.values[index];
    @memcpy(buffer[0..2], "ZQ");
    length = 2;
    const body = random.intRangeAtMost(u32, @max(min, 6), 24);
    for (0..body) |at| {
        const middle = space and at == body / 2;
        buffer[length] = if (middle) ' ' else letters[random.uintLessThan(usize, letters.len)];
        length += 1;
    }
    planted.lengths[index] = @intCast(length);
    return planted.slice(index);
}

fn pick_name(random: std.Random) []const u8 {
    return names[random.uintLessThan(usize, names.len)];
}

fn add_context(random: std.Random, builder: *Builder, planted: *Planted) void {
    var scratch: [256]u8 = undefined;
    const choice = random.uintLessThan(u8, 12);
    const name = pick_name(random);
    // A token shape is only recognised from its real length up (a GitHub token is 40).
    const secret = plant(random, planted, choice == 5 or choice == 11, if (choice == 9) 20 else 8);
    const text = switch (choice) {
        0 => std.fmt.bufPrint(&scratch, "{s}={s}", .{ name, secret }),
        1 => std.fmt.bufPrint(&scratch, "--{s} {s}", .{ name, secret }),
        2 => std.fmt.bufPrint(&scratch, "--{s}={s}", .{ name, secret }),
        3 => std.fmt.bufPrint(&scratch, "{{\"{s}\": \"{s}\"}}", .{ name, secret }),
        4 => std.fmt.bufPrint(&scratch, "\"{s}\", \"{s}\"", .{ name, secret }),
        5 => std.fmt.bufPrint(&scratch, "{s}='{s}'", .{ name, secret }),
        6 => std.fmt.bufPrint(&scratch, "Authorization: Bearer {s}", .{secret}),
        7 => std.fmt.bufPrint(&scratch, "bearer {s}", .{secret}),
        8 => std.fmt.bufPrint(&scratch, pem_format, .{secret}),
        9 => std.fmt.bufPrint(&scratch, "ghp_{s}", .{secret}),
        10 => blk: {
            planted.literals[planted.literals_count] = secret;
            planted.literals_count += 1;
            break :blk std.fmt.bufPrint(&scratch, "use {s} here", .{secret});
        },
        else => std.fmt.bufPrint(&scratch, "{s}=\"{s}\"", .{ name, secret }),
    } catch return;
    builder.add(text);
}

fn add_junk(random: std.Random, builder: *Builder) void {
    for (0..random.intRangeAtMost(u32, 0, 4)) |_| {
        builder.add(junk[random.uintLessThan(usize, junk.len)]);
        builder.add(if (random.boolean()) " " else "\n");
    }
}

/// `text` escaped the way a ZON string literal escapes it, inside quotes.
fn zon_escape(text: []const u8, out: *Builder) void {
    out.add("\"");
    for (text) |byte| {
        switch (byte) {
            '"' => out.add("\\\""),
            '\\' => out.add("\\\\"),
            '\n' => out.add("\\n"),
            else => out.add(&.{byte}),
        }
    }
    out.add("\"");
}

fn check_planted(random: std.Random) void {
    var planted: Planted = .{};
    var raw: Builder = .{};
    for (0..random.intRangeAtMost(u32, 1, 4)) |_| {
        add_junk(random, &raw);
        if (planted.count < secrets_per_input_max) add_context(random, &raw, &planted);
        raw.add(if (random.boolean()) " " else "\n");
    }
    // The labels line is a line of the record itself: it is never inside an escaped string.
    const escapes = random.uintLessThan(u8, 3);
    const labelled = escapes == 0 and random.uintLessThan(u8, 3) == 0;
    if (labelled and planted.count < secrets_per_input_max) {
        raw.add("\n.labels = .{ .{ \"k\", \"");
        raw.add(plant(random, &planted, false, 6));
        raw.add("\" } },\n");
    }
    var escaped: Builder = .{};
    var escaped_twice: Builder = .{};
    var input = raw.text();
    if (escapes >= 1) {
        zon_escape(input, &escaped);
        input = escaped.text();
    }
    if (escapes == 2) {
        zon_escape(input, &escaped_twice);
        input = escaped_twice.text();
    }
    // An escaped input that no longer fits was cut by the builder: leave it, the planted
    // values are checked against whatever was built, and only whole ones count.
    check_output(random, input, &planted);
}

fn check_output(random: std.Random, input: []const u8, planted: *const Planted) void {
    var storage: [input_bytes_max * 4]u8 = undefined;
    const room = random.intRangeAtMost(usize, 1, storage.len);
    const literals = planted.literals[0..planted.literals_count];
    const result = redact_shared(input, storage[0..room], literals);
    assert(result.len <= room);
    const output = storage[0..result.len];
    for (0..planted.count) |index| {
        const secret = planted.slice(@intCast(index));
        // A secret that did not make it whole into the input was cut by the builder.
        if (std.mem.indexOf(u8, input, secret) == null) continue;
        assert(std.mem.indexOf(u8, output, secret) == null);
    }
    if (result.truncated) assert(result.len <= room);
}

fn check_damaged(random: std.Random) void {
    var bytes: [input_bytes_max]u8 = undefined;
    const length = random.uintAtMost(usize, bytes.len);
    random.bytes(bytes[0..length]);
    // Bias toward the bytes the redactor looks at.
    const special = "=:\"'\\\n -_.,;&|)`";
    for (bytes[0..length]) |*byte| {
        if (random.uintLessThan(u8, 3) != 0) continue;
        byte.* = special[random.uintLessThan(usize, special.len)];
    }
    if (length > 40 and random.boolean()) {
        @memcpy(bytes[5..16], "-----BEGIN ");
        @memcpy(bytes[20..32], "PRIVATE KEY-");
    }
    var first: [input_bytes_max * 4]u8 = undefined;
    var second: [input_bytes_max * 4]u8 = undefined;
    const a = redact_shared(bytes[0..length], &first, &.{});
    const b = redact_shared(bytes[0..length], &second, &.{});
    assert(a.len == b.len); // Deterministic.
    assert(std.mem.eql(u8, first[0..a.len], second[0..b.len]));
}

/// The fuzzer runs one iteration at a time, so one mask of its own serves them all.
var shared_mask: redact.Mask = undefined;

fn redact_shared(input: []const u8, output: []u8, secrets: []const []const u8) redact.Result {
    return redact.redact_with(&shared_mask, input, output, secrets);
}

pub fn fuzz_redact(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    check_planted(random);
    check_damaged(random);
}
