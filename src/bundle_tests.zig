//! Tests of bundles, through the command line against the simulator: what a bundle holds, that
//! nothing planted as a secret survives redaction (the CI redaction check the diagnostics
//! standard asks for), the golden manifest, the automatic bundle on a bug, and the failures.

const std = @import("std");
const assert = std.debug.assert;
const build_options = @import("build_options");
const bundle = @import("bundle.zig");
const cli = @import("cli.zig");
const constants = @import("constants.zig");
const host_sim = @import("host_sim.zig");
const test_util = @import("test_util.zig");
const render = @import("diag/render.zig");
const Diag = @import("diag/diag.zig").Diag;
const sim_run = @import("runtime/sim_run.zig");

const testing = std.testing;
const HostSim = host_sim.HostSim;
const flate = std.compress.flate;

// ---- Reading a bundle back -----------------------------------------------------------------

/// The tar inside the gzip, decompressed with std's decompressor into `plain`.
fn gunzip(gz: []const u8, plain: []u8) ![]const u8 {
    var input: std.Io.Reader = .fixed(gz);
    var window: [flate.max_window_len]u8 = undefined;
    var decompress: flate.Decompress = .init(&input, .gzip, &window);
    var output = std.Io.Writer.fixed(plain);
    _ = try decompress.reader.streamRemaining(&output);
    return output.buffered();
}

/// The content of the member called `name` (a path inside the archive) of a tar in memory.
fn member(tar: []const u8, name: []const u8) ?[]const u8 {
    var at: usize = 0;
    while (at + 512 <= tar.len) {
        const header = tar[at..][0..512];
        if (header[0] == 0) return null;
        const path = std.mem.sliceTo(header[0..100], 0);
        const size_text = std.mem.trim(u8, header[124..136], " \x00");
        const size = std.fmt.parseInt(usize, size_text, 8) catch return null;
        const body = tar[at + 512 ..][0..size];
        if (std.mem.endsWith(u8, path, name)) return body;
        at += 512 + std.mem.alignForward(usize, size, 512);
    }
    return null;
}

/// The path `zbx bundle` printed, without its newline.
fn printed_path(sim: *const HostSim) []const u8 {
    return std.mem.trimEnd(u8, sim.stdout(), "\n");
}

fn run_args(sim: *HostSim, args: []const [:0]const u8) u8 {
    var iterator: sim_run.SliceIterator = .{ .items = args };
    return cli.run_from_iterator(sim.interface(), &iterator);
}

// ---- The planted secrets -------------------------------------------------------------------

const env_secrets = [_]host_sim.EnvironmentVariable{
    .{ .name = "HOME", .value = sim_run.home_path },
    .{ .name = "GITHUB_TOKEN", .value = "ghp_FAKEenvtoken0123456789abcd" },
    .{ .name = "DB_PASSWORD", .value = "FAKEenvpassw0rd!" },
    .{ .name = "PLAIN_SETTING", .value = "FAKEenvplainvalue" },
};

const pem = "-----BEGIN PRIVATE KEY-----\nFAKEPEMBODY0123\n-----END PRIVATE KEY-----";
const command_text = "curl -H 'Authorization: Bearer FAKEbearer123' --password=FAKEcmdpass " ++
    "API_TOKEN=FAKEcmdtoken; echo FAKEenvpassw0rd!";
const diagnostic_text =
    "{\"code\":\"ZBX-E0204\",\"causes\":[\"the helper said api_key=FAKEdiagkey\"]}";

/// Everything that must not be in any bundle made with redaction on.
const planted = [_][]const u8{
    "ghp_FAKEenvtoken0123456789abcd", "FAKEenvpassw0rd!", "FAKEenvplainvalue",
    "FAKEbearer123",                  "FAKEcmdpass",      "FAKEcmdtoken",
    "FAKEPEMBODY0123",                "FAKElabelvalue",   "FAKEdiagkey",
};

fn prepare_secrets(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim.world.now = 1_792_873_384;
    sim.environment_variables = &env_secrets;
    var view = sim_run.sample_view("web-1", 1_792_873_000);
    view.command = &.{ "sh", "-c", command_text, pem };
    view.labels = &.{.{ .key = "owner", .value = "FAKElabelvalue" }};
    view.diagnostic = diagnostic_text;
    sim_run.put_record(sim, &view);
}

fn bundle_bytes(sim: *HostSim, plain: []u8) ![]const u8 {
    const stored = sim.world.read_written(printed_path(sim)) orelse return error.NotWritten;
    return gunzip(stored, plain);
}

test "redaction: no planted secret survives in a bundle, in any file" {
    // Goal: the CI redaction check of DIAGNOSTICS.md. Method: plant fake secrets in the
    // environment, in a run record's command, its labels and its diagnostic, make the bundle
    // through the command line, read it back with std's gzip and tar, and search every byte.
    var sim: HostSim = undefined;
    sim.init(1, &.{});
    prepare_secrets(&sim);
    try testing.expectEqual(@as(u8, 0), run_args(&sim, &.{ "zbx", "bundle", "--last" }));
    var plain: [constants.bundle_stage_bytes_max * 2]u8 = undefined;
    const tar = try bundle_bytes(&sim, &plain);
    for (planted) |secret| try testing.expect(std.mem.indexOf(u8, tar, secret) == null);
    const record = member(tar, "run-record.zon").?;
    try testing.expect(std.mem.indexOf(u8, record, "[redacted:private-key]") != null);
    try testing.expect(std.mem.indexOf(u8, record, "[redacted:label]") != null);
    try testing.expect(std.mem.indexOf(u8, record, "--password=[redacted:password]") != null);
    try testing.expect(std.mem.indexOf(u8, record, "[redacted:authorization]") != null);
    try testing.expect(std.mem.indexOf(u8, record, "echo [redacted:env]") != null);
    const diagnostic = member(tar, "diagnostic.json").?;
    try testing.expect(std.mem.indexOf(u8, diagnostic, "api_key=[redacted:key]") != null);
    const names = member(tar, "environment.txt").?;
    try testing.expect(std.mem.indexOf(u8, names, "GITHUB_TOKEN=[redacted:env]") != null);
    try testing.expect(std.mem.indexOf(u8, names, "PLAIN_SETTING=[redacted:env]") != null);
    try testing.expect(std.mem.indexOf(u8, record, "/srv/alpine") != null); // Not over-redacted.
}

test "redaction: the check can fail, because --no-redact leaves the secrets in" {
    // Goal: the detector above is not vacuous. Method: the same run with --no-redact must
    // contain every planted secret, and must warn.
    var sim: HostSim = undefined;
    sim.init(1, &.{});
    prepare_secrets(&sim);
    const args = [_][:0]const u8{ "zbx", "bundle", "--last", "--no-redact" };
    try testing.expectEqual(@as(u8, 0), run_args(&sim, &args));
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "warning[ZBX-W0701]: "));
    var plain: [constants.bundle_stage_bytes_max * 2]u8 = undefined;
    const tar = try bundle_bytes(&sim, &plain);
    for (planted) |secret| try testing.expect(std.mem.indexOf(u8, tar, secret) != null);
    try testing.expect(
        std.mem.indexOf(u8, member(tar, "MANIFEST.txt").?, "redaction: OFF") != null,
    );
}

// ---- The golden manifest -------------------------------------------------------------------

/// `text` with the version of this build replaced, so a release does not change the golden.
fn unversioned(text: []const u8, storage: []u8) []const u8 {
    const size = std.mem.replacementSize(u8, text, build_options.version, "<version>");
    assert(size <= storage.len);
    _ = std.mem.replace(u8, text, build_options.version, "<version>", storage);
    return storage[0..size];
}

fn prepare_golden(sim: *HostSim) void {
    sim_run.init(sim, 1);
    golden_state(sim);
}

/// The clock, the environment and one finished run, on a host that is already set up.
fn golden_state(sim: *HostSim) void {
    sim.world.now = 1_792_873_384;
    sim.environment_variables = &env_secrets;
    const view = sim_run.sample_view("web-1", 1_792_873_000);
    sim_run.put_record(sim, &view);
}

test "golden: the manifest, with redaction on and off" {
    // Goal: the manifest is the user's map of the bundle, so its text is part of the product.
    var sim: HostSim = undefined;
    const goldens = [_][]const u8{
        @embedFile("testdata/bundle/manifest.txt"),
        @embedFile("testdata/bundle/manifest.no_redact.txt"),
    };
    const flags = [_][]const [:0]const u8{
        &.{ "zbx", "bundle", "web-1" },
        &.{ "zbx", "bundle", "web-1", "--no-redact" },
    };
    for (goldens, flags) |golden, args| {
        sim.init(1, &.{});
        prepare_golden(&sim);
        try testing.expectEqual(@as(u8, 0), run_args(&sim, args));
        var plain: [constants.bundle_stage_bytes_max * 2]u8 = undefined;
        const tar = try bundle_bytes(&sim, &plain);
        var storage: [constants.bundle_file_bytes_max]u8 = undefined;
        const manifest = unversioned(member(tar, "MANIFEST.txt").?, &storage);
        try testing.expectEqualStrings(golden, manifest);
    }
}

test "the bundle's name and layout" {
    // Goal: <state>/zbx/bundles/<UTC timestamp>-<name>.tar.gz, one directory inside, and every
    // file the brief lists is there.
    var sim: HostSim = undefined;
    sim.init(1, &.{});
    prepare_golden(&sim);
    try testing.expectEqual(@as(u8, 0), run_args(&sim, &.{ "zbx", "bundle", "--last" }));
    const expected = sim_run.bundles_path ++ "/2026-10-24T20-23-04Z-web-1.tar.gz";
    try testing.expectEqualStrings(expected, printed_path(&sim));
    var plain: [constants.bundle_stage_bytes_max * 2]u8 = undefined;
    const tar = try bundle_bytes(&sim, &plain);
    const names = [_][]const u8{
        "MANIFEST.txt", "run-record.zon", "version.txt", "mapping.txt",     "doctor.json",
        "uname.txt",    "os-release.txt", "cgroup.txt",  "environment.txt",
    };
    for (names) |name| try testing.expect(member(tar, name) != null);
    try testing.expect(std.mem.startsWith(u8, tar, "2026-10-24T20-23-04Z-web-1\x00"));
    try testing.expect(member(tar, "diagnostic.json") == null); // The run did not fail.
    try testing.expectEqualStrings(
        "ids: full\nuid: 1000\ngid: 1000\n",
        member(tar, "mapping.txt").?,
    );
    const doctor = member(tar, "doctor.json").?;
    try testing.expect(std.mem.startsWith(u8, doctor, "{\"check\":\"kernel\",\"status\":"));
}

test "bundle --json prints the path as an object" {
    var sim: HostSim = undefined;
    sim.init(1, &.{});
    prepare_golden(&sim);
    const args = [_][:0]const u8{ "zbx", "--output", "json", "bundle", "--last" };
    try testing.expectEqual(@as(u8, 0), run_args(&sim, &args));
    try testing.expect(try test_util.json_is_valid(std.mem.trimEnd(u8, sim.stdout(), "\n")));
    try testing.expect(std.mem.startsWith(u8, sim.stdout(), "{\"bundle\":\"/home/alice/"));
}

test "--last takes the newest record, a name takes that one" {
    var sim: HostSim = undefined;
    sim.init(1, &.{});
    prepare_golden(&sim);
    const newer = sim_run.sample_view("db-2", 1_792_873_200);
    sim_run.put_record(&sim, &newer);
    try testing.expectEqual(@as(u8, 0), run_args(&sim, &.{ "zbx", "bundle", "--last" }));
    try testing.expect(std.mem.endsWith(u8, printed_path(&sim), "-db-2.tar.gz"));
    try testing.expectEqual(@as(u8, 0), run_args(&sim, &.{ "zbx", "bundle", "web-1" }));
    try testing.expect(std.mem.endsWith(u8, printed_path(&sim), "-web-1.tar.gz"));
}

// ---- Bounds and failures -------------------------------------------------------------------

const huge_os_release = test_util.repeat('x', 40_000);

test "a source over its bound is cut, and the manifest says so" {
    var sim: HostSim = undefined;
    const files = sim_run.files ++ [_]host_sim.File{
        .{ .path = "/etc/os-release", .content = huge_os_release },
    };
    sim_run.start(&sim, 1, &files);
    golden_state(&sim);
    try testing.expectEqual(@as(u8, 0), run_args(&sim, &.{ "zbx", "bundle", "--last" }));
    var plain: [constants.bundle_stage_bytes_max * 2]u8 = undefined;
    const tar = try bundle_bytes(&sim, &plain);
    try testing.expectEqual(
        @as(usize, constants.bundle_file_bytes_max),
        member(tar, "os-release.txt").?.len,
    );
    const manifest = member(tar, "MANIFEST.txt").?;
    try testing.expect(std.mem.indexOf(u8, manifest, "cut at a bound") != null);
}

test "a missing system file is named, not fatal" {
    var sim: HostSim = undefined;
    sim.init(1, &.{});
    prepare_golden(&sim);
    try testing.expectEqual(@as(u8, 0), run_args(&sim, &.{ "zbx", "bundle", "--last" }));
    var plain: [constants.bundle_stage_bytes_max * 2]u8 = undefined;
    const tar = try bundle_bytes(&sim, &plain);
    const text = member(tar, "os-release.txt").?;
    try testing.expectEqualStrings("unavailable: /etc/os-release could not be read\n", text);
}

fn expect_failure(sim: *HostSim, args: []const [:0]const u8, tag: []const u8, exit: u8) !void {
    try testing.expectEqual(exit, run_args(sim, args));
    var expected: [32]u8 = undefined;
    const header = try std.fmt.bufPrint(&expected, "error[ZBX-{s}]: ", .{tag});
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), header));
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
}

test "failures: no state directory, unknown name, no runs, a full disk" {
    var sim: HostSim = undefined;
    sim.init(1, &.{});
    prepare_golden(&sim);
    sim.environment_variables = &.{};
    try expect_failure(&sim, &.{ "zbx", "bundle", "--last" }, "E0701", 2);
    sim.init(1, &.{});
    prepare_golden(&sim);
    try expect_failure(&sim, &.{ "zbx", "bundle", "nothere" }, "E0703", 1);
    sim.init(1, &.{});
    prepare_golden(&sim);
    try expect_failure(&sim, &.{ "zbx", "bundle", "../x" }, "E0703", 1); // Never a path.
    // Found by the cli fuzzer: an empty name used to trip an assertion (a bug block, exit 70).
    sim.init(1, &.{});
    prepare_golden(&sim);
    try expect_failure(&sim, &.{ "zbx", "bundle", "" }, "E0703", 1);
    sim.init(1, &.{});
    sim_run.init(&sim, 1);
    try expect_failure(&sim, &.{ "zbx", "bundle", "--last" }, "E0704", 1);
    sim.init(1, &.{});
    prepare_golden(&sim);
    sim.world.disk_full = true;
    try expect_failure(&sim, &.{ "zbx", "bundle", "--last" }, "E0702", 2);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "no space left on the device") != null);
    try testing.expectEqual(
        @as(u32, 1),
        sim.world.written_count,
    ); // Only the record: no stray temp.
}

test "usage: --last or one name, never both or neither, and the flags are bundle's" {
    var sim: HostSim = undefined;
    const cases = [_]struct { args: []const [:0]const u8, tag: []const u8 }{
        .{ .args = &.{ "zbx", "bundle" }, .tag = "E0006" },
        .{ .args = &.{ "zbx", "bundle", "--last", "web-1" }, .tag = "E0003" },
        .{ .args = &.{ "zbx", "bundle", "a", "b" }, .tag = "E0003" },
        .{ .args = &.{ "zbx", "--last", "doctor" }, .tag = "E0004" },
        .{ .args = &.{ "zbx", "doctor", "--no-redact" }, .tag = "E0004" },
    };
    for (cases) |case| {
        sim.init(1, &.{});
        try expect_failure(&sim, case.args, case.tag, 1);
    }
}

// ---- The automatic bundle ------------------------------------------------------------------

test "a bug from a run gets a bundle and a saved line; other diagnostics do not" {
    // Goal: DIAGNOSTICS.md's bug block, with its `saved` line. Method: raise a B0001 for a
    // recorded run, attach, and render in text and JSON.
    var sim: HostSim = undefined;
    sim.init(1, &.{});
    prepare_secrets(&sim);
    var bug: Diag = undefined;
    bug.reset();
    bug.raise(.B0001);
    bug.cause("an invariant broke", .{});
    bundle.attach_to_bug(sim.interface(), "web-1", &bug);
    const path = sim_run.bundles_path ++ "/2026-10-24T20-23-04Z-web-1.tar.gz";
    try testing.expectEqualStrings(path, bug.saved.slice());
    try testing.expect(sim.world.read_written(path) != null);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const text = render.render(&bug, .text, false, &buffer);
    try testing.expect(std.mem.indexOf(u8, text, "  saved  diagnostic bundle:") != null);
    try testing.expect(std.mem.indexOf(u8, text, path) != null); // Wrapped, but whole.
    const json = render.render(&bug, .json, false, &buffer);
    try testing.expect(try test_util.json_is_valid(std.mem.trimEnd(u8, json, "\n")));
    try testing.expect(std.mem.indexOf(u8, json, "\"saved\":\"" ++ path ++ "\"") != null);
}

test "a bug with no record or no room just has no saved line" {
    var sim: HostSim = undefined;
    sim.init(1, &.{});
    sim_run.init(&sim, 1);
    var bug: Diag = undefined;
    bug.reset();
    bug.raise(.B0001);
    bundle.attach_to_bug(sim.interface(), "web-1", &bug); // No record.
    try testing.expectEqual(@as(u32, 0), bug.saved.len);
    prepare_golden(&sim);
    sim.world.disk_full = true;
    bundle.attach_to_bug(sim.interface(), "web-1", &bug); // No room.
    try testing.expectEqual(@as(u32, 0), bug.saved.len);
}

test "timestamp: the form in DIAGNOSTICS.md" {
    var buffer: [constants.timestamp_bytes]u8 = undefined;
    try testing.expectEqualStrings("1970-01-01T00-00-00Z", bundle.timestamp(0, &buffer));
    try testing.expectEqualStrings(
        "2001-09-09T01-46-40Z",
        bundle.timestamp(1_000_000_000, &buffer),
    );
    try testing.expectEqualStrings(
        "2024-02-29T23-59-59Z",
        bundle.timestamp(1_709_251_199, &buffer),
    );
}
