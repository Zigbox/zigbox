//! The trust steps of the M8 demo (docs/briefs/M8-trust.md, "The demo", steps 1 to 4 and the
//! ACCEPT checks that need no registry), on the Go hello-world that HELLO7 built. It runs in the
//! first VM, as the ordinary user, after `hello_m7.step_first`:
//!
//!   1. `key new` with a passphrase file, `build` (the golden digest), `sign`, and
//!      `inspect --provenance` as JSON and as text.
//!   2. A policy that requires a signature: the signed result runs, `alpine` is refused with
//!      E0905 and no container, run record or scope is made.
//!   3. One byte appended to the hello binary's object: E0907 naming the path, `store verify`
//!      naming the object; truncated again, the run works.
//!   4. `verify` with no network at all (a network namespace with no link): six links ok.
//!   5. ACCEPT: `policy check` agrees, a missing and a wrong passphrase are E0911 and write no
//!      record, and `trust export` is one in-toto envelope per line.
//!
//! Every assertion is a function of checks_m8.zig with a unit test; this file runs the commands.

const std = @import("std");
const Io = std.Io;
const accept_m8 = @import("accept_m8.zig");
const checks = @import("checks_m8.zig");
const checks_m7 = @import("checks_m7.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const hello = @import("hello_m7.zig");
const session_mod = @import("session.zig");
const state = @import("state_m6.zig");

const Session = session_mod.Session;
const H = harness;
const fail_step = common.fail_step;
const zh = hello.zh;
const step = "TRUST8";
const short_s: u32 = 120;
const golden = @embedFile("m7_expected.zon");
const home = "/home/demo";
const pass_file = home ++ "/pass";
const policy_dir = home ++ "/.config/zbx";
const policy_file = policy_dir ++ "/policy.zon";
const greeting = "hello from zigbox";
const nobody = " </dev/null";
/// `zh` with no network: the same command in a network namespace with nothing in it.
const zh_offline = "unshare -n " ++ zh;

/// The result digest of the first build, kept between the checks of the part.
var digest_storage: [67]u8 = undefined;
/// The release `--version` printed, copied because the next command reuses the output buffer.
var version_storage: [32]u8 = undefined;

fn run(session: *Session, out: *Io.Writer, command: []const u8, want: u8) !H.SplitResult {
    return state.expect_long_split(session, out, command, want, short_s);
}

fn fmt(session: *Session, comptime pattern: []const u8, args: anytype) ![]const u8 {
    return common.format(session, pattern, args);
}

pub fn step_trust(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: TRUST8: keys, signatures, policy, tamper and verify\n", .{H.demo_name});
    const digest = try build_and_sign(session, out);
    try policy_refuses(session, out, digest);
    try tamper(session, out, digest);
    try verify_offline(session, out, digest);
    try accept(session, out, digest);
    try timer.lap(out, "trust8");
}

/// Step 1.
fn build_and_sign(session: *Session, out: *Io.Writer) ![]const u8 {
    const arena = session.scratch_allocator();
    try hello.put_text(session, pass_file, "correct horse battery\n");
    _ = try common.expect_exit(session, out, step, "chmod 600 " ++ pass_file, 0);
    const made = try run(session, out, zh ++ " key new demo --passphrase-file " ++ pass_file, 0);
    _ = checks.check_key_new(made.streams.stdout, "demo") catch |err| {
        return fail_step(out, step, "expected key new to print the key and its encryption", err);
    };
    const report = try hello.json_report(session, out, step);
    checks_m7.check_golden(golden, report.digest) catch |err| {
        return fail_step(out, step, "expected the golden result digest", err);
    };
    @memcpy(digest_storage[0..report.digest.len], report.digest);
    const digest = digest_storage[0..report.digest.len];
    const signed = zh ++ " sign {s} --passphrase-file " ++ pass_file;
    _ = try run(session, out, try fmt(session, signed, .{digest}), 0);
    const shown = try run(session, out, zh ++ " --version", 0);
    const printed = checks.version_of(shown.streams.stdout) catch |err| {
        return fail_step(out, step, "expected --version to print the release", err);
    };
    if (printed.len > version_storage.len) {
        return fail_step(out, step, "version too long", error.ProvenanceWrong);
    }
    @memcpy(version_storage[0..printed.len], printed);
    const version = version_storage[0..printed.len];
    try H.put_file(session, accept_m8.digest_file, digest);
    const as_json = try fmt(session, "{s} inspect --provenance {s} --output json", .{ zh, digest });
    const prov = try run(session, out, as_json, 0);
    checks.check_provenance(arena, prov.streams.stdout, digest, version) catch |err| {
        return fail_step(out, step, "expected the signed provenance record", err);
    };
    const as_text = try fmt(session, "{s} inspect --provenance {s}", .{ zh, digest });
    const text = try run(session, out, as_text, 0);
    checks.check_provenance_text(text.streams.stdout, version) catch |err| {
        return fail_step(out, step, "expected the text form's base, step and builder lines", err);
    };
    return digest;
}

fn listing(session: *Session, out: *Io.Writer) ![]const u8 {
    const command = H.as_demo ++ "sh -c 'ls " ++ common.state_dir ++ "/runs " ++
        common.state_dir ++ "/scopes 2>&1; /home/demo/zh ps --all --output json'";
    const result = try run(session, out, command, 0);
    return session.scratch_allocator().dupe(u8, result.streams.stdout);
}

/// Step 2: `require_signature`; the signed result runs and alpine does not.
fn policy_refuses(session: *Session, out: *Io.Writer, digest: []const u8) !void {
    const shown = try run(session, out, zh ++ " --output json key show demo", 0);
    const public = checks.public_of_key_show(shown.streams.stdout) orelse {
        return fail_step(out, step, "expected key show to print the public key", error.KeyWrong);
    };
    const policy = try fmt(
        session,
        ".{{ .version = 1, .keys = .{{ .{{ .name = \"demo\", .public = \"{s}\" }} }},\n" ++
            "   .require_signature = true }}\n",
        .{public},
    );
    _ = try common.expect_exit(session, out, step, H.as_demo ++ "mkdir -p " ++ policy_dir, 0);
    try hello.put_text(session, policy_file, policy);
    const ran = try fmt(session, "{s} run {s}", .{ zh, digest });
    const ok = try run(session, out, ran, 0);
    checks_m7.check_stdout_is(ok.streams.stdout, greeting) catch |err| {
        return fail_step(out, step, "expected the signed result to print its greeting", err);
    };
    _ = try run(session, out, zh ++ " pull alpine:3.20", 0);
    const before = try listing(session, out);
    const refused = try run(session, out, zh ++ " run alpine:3.20 true", 125);
    checks.check_policy_refusal(refused.streams.stderr, refused.status, policy_file) catch |err| {
        return fail_step(out, step, "expected E0905 naming the policy and the rule", err);
    };
    const after = try listing(session, out);
    checks.check_unchanged(before, after) catch |err| {
        return fail_step(out, step, "expected no container, run record or scope", err);
    };
}

/// Step 3: the hello binary's object gets one more byte.
fn tamper(session: *Session, out: *Io.Writer, digest: []const u8) !void {
    const find = H.as_demo ++ "sh -c 'for f in $(grep -rl \"" ++ greeting ++ "\" " ++
        common.store_dir ++ "); do [ \"$(head -c4 $f | tail -c3)\" = ELF ] && " ++
        "echo \"$(stat -c %s $f) $f\"; done'";
    const found = try run(session, out, find, 0);
    const path = checks.largest_object(found.streams.stdout) catch |err| {
        return fail_step(out, step, "expected the hello binary among the store's objects", err);
    };
    const id = checks.object_id_of_path(path) catch |err| {
        return fail_step(out, step, "expected an object path", err);
    };
    const object = try session.scratch_allocator().dupe(u8, path);
    const mode_command = try fmt(session, H.as_demo ++ "stat -c %a {s}", .{object});
    const mode_result = try run(session, out, mode_command, 0);
    const mode = std.mem.trim(u8, mode_result.streams.stdout, " \r\n");
    const mode_copy = try session.scratch_allocator().dupe(u8, mode);
    const append = try fmt(session, H.as_demo ++ "sh -c 'chmod u+w {s} && printf x >> {s}'", .{
        object, object,
    });
    _ = try common.expect_exit(session, out, step, append, 0);
    const ran = try fmt(session, "{s} run {s}", .{ zh, digest });
    const refused = try run(session, out, ran, 125);
    const binary = "/usr/local/bin/hello";
    checks.check_tamper_refusal(refused.streams.stderr, refused.status, binary) catch |err| {
        return fail_step(out, step, "expected E0907 naming " ++ binary, err);
    };
    const verify = try run(session, out, zh ++ " store verify 2>&1", 1);
    checks.check_store_verify_names(verify.streams.stdout, id) catch |err| {
        return fail_step(out, step, "expected store verify to name the same object", err);
    };
    const back = try fmt(session, H.as_demo ++ "sh -c 'truncate -s -1 {s} && chmod {s} {s}'", .{
        object, mode_copy, object,
    });
    _ = try common.expect_exit(session, out, step, back, 0);
    const again = try run(session, out, ran, 0);
    checks_m7.check_stdout_is(again.streams.stdout, greeting) catch |err| {
        return fail_step(out, step, "expected the run to work again", err);
    };
}

/// Step 4: no network at all.
fn verify_offline(session: *Session, out: *Io.Writer, digest: []const u8) !void {
    const command = try fmt(session, "{s} verify {s} --output json", .{ zh_offline, digest });
    const result = try run(session, out, command, 0);
    const arena = session.scratch_allocator();
    checks.check_verify_ok(arena, result.streams.stdout, result.status) catch |err| {
        return fail_step(out, step, "expected six links ok with no network", err);
    };
}

/// ACCEPT, the parts that need no registry.
fn accept(session: *Session, out: *Io.Writer, digest: []const u8) !void {
    const check = try fmt(session, "{s} policy check {s} --output json", .{ zh, digest });
    const checked = try run(session, out, check, 0);
    if (std.mem.indexOf(u8, checked.streams.stdout, "\"allowed\":true") == null) {
        return fail_step(out, step, "expected policy check to agree with run", error.RefusalWrong);
    }
    const no_file = try fmt(session, "{s} sign {s}" ++ nobody, .{ zh, digest });
    const missing = try run(session, out, no_file, 1);
    checks.check_exit1_code(missing.streams.stderr, missing.status, "E0911") catch |err| {
        return fail_step(out, step, "expected E0911 at once with no passphrase file", err);
    };
    try hello.put_text(session, home ++ "/wrong", "not the passphrase\n");
    const wrong_cmd = try fmt(
        session,
        "{s} sign {s} --passphrase-file " ++ home ++ "/wrong" ++ nobody,
        .{ zh, digest },
    );
    const wrong = try run(session, out, wrong_cmd, 1);
    checks.check_exit1_code(wrong.streams.stderr, wrong.status, "E0911") catch |err| {
        return fail_step(out, step, "expected E0911 for a wrong passphrase", err);
    };
    const export_cmd = try fmt(session, "{s} trust export {s}", .{ zh, digest });
    const bundle = try run(session, out, export_cmd, 0);
    checks.check_bundle(bundle.streams.stdout) catch |err| {
        return fail_step(out, step, "expected one in-toto envelope per line", err);
    };
    const prune = try run(session, out, zh ++ " trust prune --output json", 0);
    checks.check_prune_dry(session.scratch_allocator(), prune.streams.stdout, 0) catch |err| {
        return fail_step(out, step, "expected a dry run with no orphans", err);
    };
    // The policy is removed so that the parts after this one run without it.
    _ = try common.expect_exit(session, out, step, "rm -f " ++ policy_file, 0);
}

test "the part's commands fit the harness's command size" {
    const limits = @import("limits.zig");
    try std.testing.expect(zh_offline.len < limits.command_bytes_max);
    try std.testing.expect(zh.len < limits.command_bytes_max);
}
