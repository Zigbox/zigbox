//! The M10 demo's assertions (docs/briefs/M10-gpu.md) as pure functions over what the guest
//! printed, each with a unit test fed wrong text: a check that cannot fail proves nothing. The
//! commands that print the text are in main_m10.zig; the fake vendor is `zigbox.test/gpu`.

const std = @import("std");
const checks = @import("checks.zig");

const Streams = checks.Streams;

pub const Error = error{
    ExitCodeWrong,
    /// A line the step must print is missing, or one it must not print is there.
    OutputWrong,
    /// A refusal is not one coded line, or names too little.
    RefusalWrong,
};

fn has_line(text: []const u8, wanted: []const u8) bool {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        if (std.mem.eql(u8, std.mem.trim(u8, raw, " \r\t"), wanted)) return true;
    }
    return false;
}

fn has_line_starting(text: []const u8, prefix: []const u8) bool {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        if (std.mem.startsWith(u8, std.mem.trimStart(u8, raw, " \r\t"), prefix)) return true;
    }
    return false;
}

fn has(text: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, text, needle) != null;
}

/// A refusal: stdout empty, exit 125, stderr opens with the code and has no errno.
fn expect_refusal(streams: Streams, status: u8, code: []const u8) Error!void {
    if (status != 125) return error.ExitCodeWrong;
    if (std.mem.trim(u8, streams.stdout, " \r\n").len != 0) return error.RefusalWrong;
    if (!std.mem.startsWith(u8, streams.stderr, "error[ZBX-")) return error.RefusalWrong;
    if (!has(streams.stderr[0..@min(streams.stderr.len, 24)], code)) return error.RefusalWrong;
    if (has(streams.stderr, "errno")) return error.RefusalWrong;
}

/// Step 1: doctor lists the spec and its device (openable by you), and nothing is a gap.
pub fn check_doctor(streams: Streams) Error!void {
    const text = streams.stdout;
    if (!has_line_starting(text, "gpu  ok  spec /etc/cdi/zbx-gpu.json")) return error.OutputWrong;
    if (!has_line_starting(text, "gpu  ok  device zigbox.test/gpu=0")) return error.OutputWrong;
    if (has_line_starting(text, "gpu  gap")) return error.OutputWrong;
}

/// Step 2: the device brings its node (opened), its variable and its library, exit 0, no error.
pub fn check_device_run(streams: Streams, status: u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!has_line(streams.stdout, "ZBXGPU=on")) return error.OutputWrong;
    if (!has_line(streams.stdout, "NODE-OPEN")) return error.OutputWrong;
    if (!has_line(streams.stdout, "libzbxgpu")) return error.OutputWrong;
    if (has(streams.stderr, "ZBX-E")) return error.OutputWrong;
}

/// Step 4: a user not in the node's group is refused with E0225 naming the node and the group.
pub fn check_not_in_group(streams: Streams, status: u8) Error!void {
    try expect_refusal(streams, status, "E0225");
    if (!has(streams.stderr, "/dev/zbx-gpu")) return error.RefusalWrong;
    if (!has(streams.stderr, "group")) return error.RefusalWrong;
}

/// Step 5, doctor: the YAML spec is refused with the JSON fix, and the JSON spec's device is fine.
pub fn check_yaml_doctor(streams: Streams) Error!void {
    const text = streams.stdout;
    if (!has_line_starting(text, "gpu  gap spec /etc/cdi/zbx-yaml.yaml")) return error.OutputWrong;
    if (!has(text, "YAML")) return error.OutputWrong;
    if (!has(text, "--format=json")) return error.OutputWrong;
    if (!has_line_starting(text, "gpu  ok  device zigbox.test/gpu=0")) return error.OutputWrong;
}

/// Step 5, a name only the refused file might have: E0226 naming that file.
pub fn check_yaml_run(streams: Streams, status: u8) Error!void {
    try expect_refusal(streams, status, "E0226");
    if (!has(streams.stderr, "zbx-yaml.yaml")) return error.RefusalWrong;
}

/// Step 6: an image with no ldconfig runs, with W0208 and the libraries on LD_LIBRARY_PATH.
pub fn check_no_ldconfig(streams: Streams, status: u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!has(streams.stderr, "ZBX-W0208")) return error.OutputWrong;
    if (!has_line_starting(streams.stdout, "LDP=")) return error.OutputWrong;
    if (!has(streams.stdout, "/opt/zbx-gpu-lib")) return error.OutputWrong;
    if (has(streams.stderr, "ZBX-E")) return error.OutputWrong;
}

/// Step 7: a run without devices is as before: no node of the demo in /dev, no note, exit 0.
pub fn check_baseline(streams: Streams, status: u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (has(streams.stdout, "zbx-gpu")) return error.OutputWrong;
    if (!has_line(streams.stdout, "UID=0")) return error.OutputWrong;
    if (std.mem.trim(u8, streams.stderr, " \r\n").len != 0) return error.OutputWrong;
}

const testing = std.testing;

fn quiet(stdout: []const u8) Streams {
    return .{ .stdout = stdout, .stderr = "" };
}

fn loud(stderr: []const u8) Streams {
    return .{ .stdout = "", .stderr = stderr };
}

fn both(stdout: []const u8, stderr: []const u8) Streams {
    return .{ .stdout = stdout, .stderr = stderr };
}

test "check_doctor wants the spec and the device, and no gap" {
    const good = "ok   kernel  x\n" ++
        "gpu  ok  spec /etc/cdi/zbx-gpu.json  zigbox.test/gpu, 1 devices\n" ++
        "gpu  ok  device zigbox.test/gpu=0  every node can be opened by you\n";
    try check_doctor(quiet(good));
    try testing.expectError(error.OutputWrong, check_doctor(quiet("ok  kernel  x\n")));
    const gap = good ++ "gpu  gap node /dev/x  closed\n";
    try testing.expectError(error.OutputWrong, check_doctor(quiet(gap)));
}

test "check_device_run wants the node open, the variable and the library" {
    const out = "ZBXGPU=on\nNODE-OPEN\nlibzbxgpu\n";
    try check_device_run(both(out, "warning[ZBX-W0209]: x\n"), 0);
    try testing.expectError(error.ExitCodeWrong, check_device_run(quiet(out), 1));
    const unopened = quiet("ZBXGPU=on\nlibzbxgpu\n");
    try testing.expectError(error.OutputWrong, check_device_run(unopened, 0));
    const refused = both(out, "error[ZBX-E0225]: x\n");
    try testing.expectError(error.OutputWrong, check_device_run(refused, 0));
}

test "check_not_in_group wants one coded line naming the node and the group" {
    const text = "error[ZBX-E0225]: can't bind that device\n" ++
        "  cause  you cannot open /dev/zbx-gpu: group 44\n";
    try check_not_in_group(loud(text), 125);
    try testing.expectError(error.ExitCodeWrong, check_not_in_group(loud(text), 1));
    const other_code = loud("error[ZBX-E0226]: x /dev/zbx-gpu group\n");
    try testing.expectError(error.RefusalWrong, check_not_in_group(other_code, 125));
    const no_names = loud("error[ZBX-E0225]: x\n");
    try testing.expectError(error.RefusalWrong, check_not_in_group(no_names, 125));
}

test "the YAML checks want the fix and the file named" {
    const doctor = "gpu  gap spec /etc/cdi/zbx-yaml.yaml  refused: a YAML spec\n" ++
        "gpu  ok  device zigbox.test/gpu=0  x\n" ++
        "gpu  gap fix a YAML spec  nvidia-ctk cdi generate --format=json\n";
    try check_yaml_doctor(quiet(doctor));
    const bare = quiet("gpu  ok  device zigbox.test/gpu=0\n");
    try testing.expectError(error.OutputWrong, check_yaml_doctor(bare));
    const run = "error[ZBX-E0226]: can't use a CDI spec\n" ++
        "  cause  /etc/cdi/zbx-yaml.yaml is refused\n";
    try check_yaml_run(loud(run), 125);
    const unnamed = loud("error[ZBX-E0226]: x\n");
    try testing.expectError(error.RefusalWrong, check_yaml_run(unnamed, 125));
    try testing.expectError(error.ExitCodeWrong, check_yaml_run(loud(run), 0));
}

test "check_no_ldconfig wants W0208 and the path" {
    const out = "LDP=/opt/zbx-gpu-lib:\n";
    const note = "warning[ZBX-W0208]: x\n";
    try check_no_ldconfig(both(out, note), 0);
    try testing.expectError(error.OutputWrong, check_no_ldconfig(quiet(out), 0));
    try testing.expectError(error.OutputWrong, check_no_ldconfig(both("LDP=\n", note), 0));
    try testing.expectError(error.ExitCodeWrong, check_no_ldconfig(both(out, note), 3));
}

test "check_baseline wants a quiet run with no demo node" {
    try check_baseline(quiet("null\nUID=0\n"), 0);
    const node = quiet("zbx-gpu\nUID=0\n");
    try testing.expectError(error.OutputWrong, check_baseline(node, 0));
    const noted = both("UID=0\n", "warning[ZBX-W0209]: x\n");
    try testing.expectError(error.OutputWrong, check_baseline(noted, 0));
    try testing.expectError(error.OutputWrong, check_baseline(quiet("null\n"), 0));
}
