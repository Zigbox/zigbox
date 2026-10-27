//! The M4 demo's assertions as pure functions over the text the guest printed, each unit-tested
//! with right and wrong input. The commands that print the text are in main_m4.zig.

const std = @import("std");
const checks = @import("checks.zig");

const Streams = checks.Streams;

pub const Error = error{
    ExitCodeWrong,
    /// The digest a pull prints is missing or is not one.
    DigestWrong,
    /// A line the step must print is missing.
    LineMissing,
    /// A refusal that should name both digests does not, or has another code.
    RefusalWrong,
    StderrNotEmpty,
};

fn contains(text: []const u8, part: []const u8) bool {
    return std.mem.indexOf(u8, text, part) != null;
}

/// `sha256:` and 64 lowercase hex digits.
pub fn is_manifest_digest(text: []const u8) bool {
    if (text.len != 71) return false;
    if (!std.mem.startsWith(u8, text, "sha256:")) return false;
    for (text[7..]) |byte| {
        const hex = (byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f');
        if (!hex) return false;
    }
    return true;
}

/// `zbx pull` prints the manifest digest alone on stdout and exits 0. Warnings may be on stderr.
pub fn check_pull(streams: Streams, status: u8) Error![]const u8 {
    if (status != 0) return error.ExitCodeWrong;
    const digest = std.mem.trim(u8, streams.stdout, " \r\n\t");
    if (!is_manifest_digest(digest)) return error.DigestWrong;
    return digest;
}

/// A run's stdout holds `wanted`, and it ended with 0.
pub fn check_output_has(streams: Streams, status: u8, wanted: []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!contains(streams.stdout, wanted)) return error.LineMissing;
}

/// A run's stdout is exactly the line `wanted`.
pub fn check_output_is(streams: Streams, status: u8, wanted: []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!std.mem.eql(u8, std.mem.trim(u8, streams.stdout, " \r\n\t"), wanted)) {
        return error.LineMissing;
    }
}

/// The run was refused by `code` (exit 125, nothing on stdout), and its message names each of
/// `digests`.
pub fn check_refusal(
    streams: Streams,
    status: u8,
    code: []const u8,
    digests: []const []const u8,
) Error!void {
    if (status != 125) return error.ExitCodeWrong;
    if (streams.stdout.len != 0) return error.RefusalWrong;
    if (!contains(streams.stderr, code)) return error.RefusalWrong;
    for (digests) |digest| {
        if (!contains(streams.stderr, digest)) return error.RefusalWrong;
    }
}

const testing = std.testing;

const hex_a: [64]u8 = @splat('a');
const hex_0: [64]u8 = @splat('0');
const hex_1: [64]u8 = @splat('1');
const hex_upper: [64]u8 = @splat('A');

test "a pull prints the manifest digest and nothing else" {
    // Goal: right and wrong input of the first step.
    const good = "sha256:" ++ hex_a ++ "\n";
    const ok = try check_pull(.{ .stdout = good, .stderr = "warning[ZBX-W0201]: x\n" }, 0);
    try testing.expectEqualStrings("sha256:" ++ hex_a, ok);
    try testing.expectError(error.ExitCodeWrong, check_pull(.{ .stdout = good, .stderr = "" }, 3));
    try testing.expectError(
        error.DigestWrong,
        check_pull(.{ .stdout = "b3:" ++ hex_a, .stderr = "" }, 0),
    );
    try testing.expectError(
        error.DigestWrong,
        check_pull(.{ .stdout = "sha256:abc\n", .stderr = "" }, 0),
    );
    try testing.expectError(error.DigestWrong, check_pull(.{ .stdout = "", .stderr = "" }, 0));
    const upper = "sha256:" ++ hex_upper;
    try testing.expectError(error.DigestWrong, check_pull(.{ .stdout = upper, .stderr = "" }, 0));
}

test "a run's output is checked as a whole or in part" {
    // Goal: the second and fourth steps.
    const os_release = "NAME=\"Alpine Linux\"\nID=alpine\n";
    try check_output_has(.{ .stdout = os_release, .stderr = "" }, 0, "ID=alpine");
    try testing.expectError(
        error.LineMissing,
        check_output_has(.{ .stdout = os_release, .stderr = "" }, 0, "ID=debian"),
    );
    try testing.expectError(
        error.ExitCodeWrong,
        check_output_has(.{ .stdout = os_release, .stderr = "" }, 1, "ID=alpine"),
    );
    try check_output_is(
        .{ .stdout = "1267650600228229401496703205376\n", .stderr = "" },
        0,
        "1267650600228229401496703205376",
    );
    try testing.expectError(
        error.LineMissing,
        check_output_is(
            .{ .stdout = "126765060022822940149670320537\n", .stderr = "" },
            0,
            "1267650600228229401496703205376",
        ),
    );
}

test "the refusal of a lock that disagrees names the code and both digests" {
    // Goal: step 5. Right: 125, empty stdout, the code and both digests in the message.
    const expected = "b3:" ++ hex_0;
    const actual = "b3:" ++ hex_1;
    const message = "error[ZBX-E0519]: zbx.lock and the store disagree\n" ++
        "  cause  zbx.lock has tree " ++ expected ++ "; the store has tree " ++ actual ++ "\n";
    const digests = [_][]const u8{ expected, actual };
    try check_refusal(.{ .stdout = "", .stderr = message }, 125, "ZBX-E0519", &digests);
    try testing.expectError(
        error.ExitCodeWrong,
        check_refusal(.{ .stdout = "", .stderr = message }, 1, "ZBX-E0519", &digests),
    );
    try testing.expectError(
        error.RefusalWrong,
        check_refusal(.{ .stdout = "output", .stderr = message }, 125, "ZBX-E0519", &digests),
    );
    try testing.expectError(
        error.RefusalWrong,
        check_refusal(.{ .stdout = "", .stderr = message }, 125, "ZBX-E0520", &digests),
    );
    const one = "error[ZBX-E0519]: x\n  cause  " ++ expected ++ "\n";
    try testing.expectError(
        error.RefusalWrong,
        check_refusal(.{ .stdout = "", .stderr = one }, 125, "ZBX-E0519", &digests),
    );
}
