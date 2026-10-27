//! The top-20 check (docs/demos/m4.md, "The top-20 check"): pull each of the twenty images in
//! `top20.zon` and run its default command in the harness's Ubuntu 24.04 VM, rootless, with a
//! timeout. One line per image says whether it pulled, whether it ran, the exit code, a verdict
//! and the reason. A seccomp refusal is told apart: the image runs again under
//! `strace`, and every syscall that returned EPERM and is not on the allowlist is named in the
//! `seccomp=` field. The weekly workflow runs this against the real Docker Hub; locally, name a
//! mirror with `-Dmirror=mirror.gcr.io`. `zig build top20 -Daccel=tcg` for software emulation.

const std = @import("std");
const Io = std.Io;
const checks = @import("checks.zig");
const checks_top20 = @import("checks_top20.zig");
const harness = @import("harness.zig");
const image = @import("image.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");
const list = @import("top20.zon");
const policy = @import("seccomp_policy");

const Session = session_mod.Session;
const H = harness;

const z = H.as_demo ++ "/home/demo/z";
const project = "/home/demo/project";
/// How long an image's default command may run before zbx stops it: a server that is still up
/// has run. Milliseconds, as `--timeout` takes them.
const run_timeout_ms = "45000";
/// How long the probe keeps asking a server that is not answering yet, in 2 s steps.
const probe_steps_max = 22;
const probe_file = "/tmp/top20-probe";
/// A pull or run of a large image under TCG needs far more than the demos' 60 s.
const image_timeout_s: u32 = 900;
const strace_log = "/tmp/top20-strace.log";

const Entry = struct { ref: []const u8, known: []const u8, probe: []const u8 };

const images = blk: {
    var all: [list.images.len]Entry = undefined;
    for (list.images, 0..) |entry, index| {
        all[index] = .{ .ref = entry.ref, .known = entry.known, .probe = entry.probe };
    }
    break :blk all;
};

/// Every syscall the allowlist names outright; a name with a rule is left out, so an EPERM from
/// `clone` or `socket` counts as a seccomp suspect.
const allowed = blk: {
    @setEvalBranchQuota(100_000);
    var count: usize = 0;
    for (policy.groups) |group| count += group.syscalls.len;
    var names: [count][]const u8 = undefined;
    var index: usize = 0;
    for (policy.groups) |group| {
        for (group.syscalls) |name| {
            names[index] = name;
            index += 1;
        }
    }
    break :blk names;
};

comptime {
    std.debug.assert(images.len == 20);
    std.debug.assert(allowed.len > 200);
}

pub fn main(init: std.process.Init) !u8 {
    harness.demo_name = "top20";
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const options = H.parse_options(init) catch |err| {
        try out.print("top20: bad arguments ({s}); see docs/demos/m4.md\n", .{@errorName(err)});
        return 2;
    };
    const started = session_mod.now_ms();
    const code = check(init, out, options) catch |err| {
        if (err == error.NoKvm) return 1;
        try out.print("\ntop20: FAILED ({s})\n", .{@errorName(err)});
        return 1;
    };
    try out.print("\ntop20: finished in {d} s\n", .{(session_mod.now_ms() - started) / 1000});
    return code;
}

fn check(init: std.process.Init, out: *Io.Writer, options: H.Options) !u8 {
    const io = init.io;
    const accel = harness.choose_accel(options.accel, H.kvm_usable(io)) catch |err| switch (err) {
        error.NoKvm => {
            try out.print("top20: /dev/kvm is not usable here; for software emulation " ++
                "(slow) add -Daccel=tcg\n", .{});
            return error.NoKvm;
        },
        error.BadAccel => return error.BadAccel,
    };
    const binary = try H.check_binaries(init, out, options);
    const arena = init.arena.allocator();
    const base = try image.ensure(init, options.cache_dir, out);
    const overlay = try std.fmt.allocPrint(arena, "{s}/overlay-top20.qcow2", .{options.cache_dir});
    if (!options.reuse_overlay) try image.make_overlay(init, base, overlay);
    defer if (!options.keep_overlay) Io.Dir.cwd().deleteFile(io, overlay) catch {};

    var ca_file: []const u8 = "";
    if (options.ca_file.len > 0) {
        const limit: Io.Limit = .limited(limits.http_body_bytes_max);
        ca_file = try Io.Dir.cwd().readFileAlloc(io, options.ca_file, arena, limit);
    }
    var session: Session = undefined;
    try session.start(init, out, overlay, accel, .{
        .user_data = @import("cloud_init.zig").user_data,
        .binary = binary,
        .ca_file = ca_file,
    });
    defer session.deinit();
    var timer = H.Timer.start();
    try H.provision(&session, out, &timer, options.reuse_overlay);
    try H.install_binary(&session, out, &timer);
    try write_wrapper(&session, out, options.mirror, ca_file.len > 0);
    try make_output_files(&session);
    const traced = try install_strace(&session, out);
    const failures = try run_all(&session, out, arena, traced, options.only);
    try session.shutdown();
    return if (failures == 0) 0 else 1;
}

fn write_wrapper(session: *Session, out: *Io.Writer, mirror: []const u8, with_ca: bool) !void {
    const made = try session.run(
        "runuser -u demo -- mkdir -p " ++ project,
        limits.command_timeout_kvm_s,
    );
    if (made.status != 0) return error.PrepareFailed;
    const arena = session.scratch_allocator();
    var text: std.ArrayList(u8) = .empty;
    try text.appendSlice(arena, "#!/bin/sh\ncd " ++ project ++ " || exit 125\n");
    if (mirror.len > 0) {
        try text.print(arena, "export ZBX_REGISTRY_MIRRORS={s}\n", .{mirror});
    }
    if (with_ca) {
        try text.appendSlice(arena, "export SSL_CERT_FILE=/home/demo/ca.crt\n");
        const fetch = try std.fmt.allocPrint(
            arena,
            "curl -fsS -o /home/demo/ca.crt http://10.0.2.2:{d}/ca.crt",
            .{session.server.port},
        );
        const fetched = try session.run(fetch, limits.command_timeout_kvm_s);
        if (fetched.status != 0) return error.PrepareFailed;
    }
    try text.appendSlice(arena, "exec /home/demo/zbx \"$@\"\n");
    try H.put_file(session, "/home/demo/z", text.items);
    const owned = try session.run(
        "chown demo:demo /home/demo/z && cat /home/demo/z",
        limits.command_timeout_kvm_s,
    );
    try H.show(out, "the wrapper that runs zbx in the project directory", owned);
    if (owned.status != 0) return error.PrepareFailed;
}

/// strace tells which syscalls a failed image was refused. Without it the run still gives every
/// verdict; the `seccomp=` field then says `unchecked`.
fn install_strace(session: *Session, out: *Io.Writer) !bool {
    const result = try session.run(
        "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends strace " ++
            ">/tmp/strace-install.log 2>&1; command -v strace",
        limits.command_timeout_kvm_s * 10,
    );
    try H.show(out, "install strace, to name a syscall that seccomp refused", result);
    return result.status == 0;
}

/// A development aid (`-Donly=redis,nginx`): with a list, only the images it names run. The
/// weekly workflow names none, so all twenty run.
fn is_selected(only: []const u8, ref: []const u8) bool {
    if (only.len == 0) return true;
    const name = ref[0..std.mem.indexOfScalar(u8, ref, ':').?];
    var names = std.mem.splitScalar(u8, only, ',');
    while (names.next()) |wanted| {
        if (std.mem.eql(u8, wanted, name)) return true;
    }
    return false;
}

fn run_all(
    session: *Session,
    out: *Io.Writer,
    arena: std.mem.Allocator,
    traced: bool,
    only: []const u8,
) !u32 {
    try out.print("\ntop20: {d} images from {s} ({s})\n", .{ images.len, list.date, list.source });
    var lines: [images.len][]const u8 = undefined;
    var failures: u32 = 0;
    var known: u32 = 0;
    var selected: u32 = 0;
    for (images, 0..) |entry, index| {
        if (!is_selected(only, entry.ref)) {
            lines[index] = "";
            continue;
        }
        selected += 1;
        const result = try try_image(session, out, entry, traced);
        var buffer: [1024]u8 = undefined;
        const line = try checks_top20.format_line(&buffer, result);
        lines[index] = try arena.dupe(u8, line);
        try out.print("\ntop20-result: {s}\n", .{lines[index]});
        if (result.seccomp.len > 0 and result.verdict == .fail) {
            try out.print("top20: SECCOMP: {s} was refused {s}\n", .{ entry.ref, result.seccomp });
        }
        switch (result.verdict) {
            .pass => if (entry.known.len > 0) {
                const note = "top20: NOTE: {s} passes; its known reason no longer holds\n";
                try out.print(note, .{entry.ref});
            },
            .known => known += 1,
            .fail => failures += 1,
        }
    }
    try out.print("\ntop20: results ({s})\n", .{list.date});
    for (lines) |line| {
        if (line.len > 0) try out.print("top20-result: {s}\n", .{line});
    }
    const passed = selected - failures - known;
    const summary = "top20: {d} passed, {d} known not to run, {d} failed\n";
    try out.print(summary, .{ passed, known, failures });
    return failures;
}

/// The two files the container's output goes to. They are the demo user's, as a terminal or a
/// pipe the user opened would be: an image that logs to /dev/stdout opens it again through
/// /proc, and the kernel refuses that for a file whose owner is not mapped in the container
/// (a root-owned console or pipe), so root's own redirects would fail such images for a reason
/// that is the harness's.
const out_file = "/tmp/top20-out";
const err_file = "/tmp/top20-err";

fn make_output_files(session: *Session) !void {
    const made = try session.run(
        "install -o demo -g demo -m 600 /dev/null " ++ out_file ++
            " && install -o demo -g demo -m 600 /dev/null " ++ err_file,
        limits.command_timeout_kvm_s,
    );
    if (made.status != 0) return error.PrepareFailed;
}

/// Runs `command` with stdout and stderr in the demo user's files, then prints the end of the
/// first, the marker (checks.zig) and the second, so `split_streams` cuts them apart.
fn split_long(session: *Session, command: []const u8) !H.SplitResult {
    var buffer: [limits.command_bytes_max]u8 = undefined;
    const format = "{s} >" ++ out_file ++ " 2>" ++ err_file ++ "; ZBX_S=$?; tail -c 8192 " ++
        out_file ++ "; echo ZBX-STDERR\"\"-FOLLOWS; tail -c 8192 " ++ err_file ++ "; exit $ZBX_S";
    const typed = try std.fmt.bufPrint(&buffer, format, .{command});
    const result = try session.run(typed, image_timeout_s);
    const streams = try checks.split_streams(result.output);
    return .{ .streams = streams, .status = result.status };
}

fn try_image(
    session: *Session,
    out: *Io.Writer,
    entry: Entry,
    traced: bool,
) !checks_top20.Result {
    const arena = session.scratch_allocator();
    const pull = try std.fmt.allocPrint(arena, z ++ " pull {s} </dev/null", .{entry.ref});
    const pulled = try split_long(session, pull);
    try H.show_split(out, pull, pulled);
    var result: checks_top20.Result = .{
        .ref = entry.ref,
        .pulled = pulled.status == 0,
        .ran = false,
        .status = pulled.status,
        .verdict = .fail,
        .seccomp = "",
        .reason = "-",
    };
    if (!result.pulled) {
        const stderr = try arena.dupe(u8, pulled.streams.stderr);
        const missing: checks_top20.Observed = .{ .pulled = false, .status = 0, .stderr = stderr };
        result.verdict = checks_top20.judge(missing, entry.known);
        result.reason = reason_of(entry, result.verdict, stderr, "error[");
        return result;
    }
    const probe = checks_top20.parse_probe(entry.probe);
    const run = try run_command(arena, entry.ref, probe);
    const ran = try split_long(session, run);
    try H.show_split(out, run, ran);
    const stderr = try arena.dupe(u8, ran.streams.stderr);
    const probe_result = if (probe != null and checks_top20.stopped_by_timeout(stderr))
        try read_probe(session)
    else
        checks_top20.Probe.none;
    const observed: checks_top20.Observed = .{
        .pulled = true,
        .status = ran.status,
        .stderr = stderr,
        .probe = probe_result,
    };
    result.probe = probe_result;
    result.status = ran.status;
    result.ran = checks_top20.command_started(ran.status);
    result.verdict = checks_top20.judge(observed, entry.known);
    const refused = !checks_top20.command_started(ran.status);
    result.reason = reason_of(entry, result.verdict, stderr, if (refused) "error[" else "");
    // Only a failure is looked at again under strace: a pass needs no explanation.
    if (result.verdict != .pass) result.seccomp = try find_seccomp(session, out, entry, traced);
    return result;
}

/// The command for one image's default run. A server with a probe runs in the background while
/// the guest asks it, as root on 127.0.0.1 (the container shares the host's network), every 2 s
/// until it answers, the container ends or `probe_steps_max` steps pass. The answer goes to
/// `probe_file`; the run's own exit code stays the command's.
fn run_command(
    arena: std.mem.Allocator,
    ref: []const u8,
    probe: ?checks_top20.ProbeSpec,
) ![]const u8 {
    const plain = z ++ " run --timeout " ++ run_timeout_ms ++ " {s} </dev/null";
    const spec = probe orelse return std.fmt.allocPrint(arena, plain, .{ref});
    var text: std.ArrayList(u8) = .empty;
    try text.print(arena, "rm -f " ++ probe_file ++ "; {{ " ++ plain ++ " & ZP=$!; ZI=0; " ++
        "while [ $ZI -lt {d} ] && kill -0 $ZP 2>/dev/null; do sleep 2; ZI=$((ZI+1)); ", .{
        ref, probe_steps_max,
    });
    if (spec.expect.len == 0) {
        try text.print(arena, "if timeout 6 bash -c 'exec 3<>/dev/tcp/127.0.0.1/{d}' " ++
            "2>/dev/null; then echo ok >" ++ probe_file ++ "; break; fi; done; wait $ZP; }}", .{
            spec.port,
        });
    } else {
        try text.print(arena, "ZR=$(timeout 6 bash -c 'exec 3<>/dev/tcp/127.0.0.1/{d} && " ++
            "printf \"{s}\" >&3 && timeout 3 head -c 300 <&3' 2>/dev/null); " ++
            "case \"$ZR\" in *{s}*) echo ok >" ++ probe_file ++ "; break;; esac; " ++
            "done; wait $ZP; }}", .{ spec.port, spec.send, spec.expect });
    }
    return text.items;
}

/// What the probe wrote: `ok`, or nothing (it never got its answer).
fn read_probe(session: *Session) !checks_top20.Probe {
    const command = "cat " ++ probe_file ++ " 2>/dev/null";
    const read = try session.run(command, limits.command_timeout_kvm_s);
    const text = std.mem.trim(u8, read.output, " \r\n");
    return if (std.mem.eql(u8, text, "ok")) .ok else .failed;
}

fn reason_of(
    entry: Entry,
    verdict: checks_top20.Verdict,
    stderr: []const u8,
    prefix: []const u8,
) []const u8 {
    if (verdict == .pass) return "-";
    if (verdict == .known) return entry.known;
    if (prefix.len > 0) {
        if (checks_top20.first_line_with(stderr, prefix)) |line| return line;
    }
    return checks_top20.last_line(stderr);
}

/// Runs the image again under strace and returns the syscalls that were refused with
/// EPERM and are not on the allowlist: the filter's own refusals. "unchecked" without strace.
fn find_seccomp(session: *Session, out: *Io.Writer, entry: Entry, traced: bool) ![]const u8 {
    if (!traced) return "unchecked";
    const arena = session.scratch_allocator();
    const command = try std.fmt.allocPrint(
        arena,
        "strace -f -o " ++ strace_log ++ " -e status=failed " ++ z ++
            " run --timeout " ++ run_timeout_ms ++ " {s} </dev/null >/dev/null 2>&1; " ++
            "grep -h ' = -1 EPERM' " ++ strace_log ++
            " | sed -E 's/^[0-9]+ +//; s/\\(.*//' | sort -u | tr '\\n' ' '",
        .{entry.ref},
    );
    const traced_run = try session.run(command, image_timeout_s * 2);
    try H.show(out, "strace: the syscalls that returned EPERM", traced_run);
    const out_buffer = try arena.alloc(u8, 256);
    const names = checks_top20.seccomp_suspects(traced_run.output, &allowed, out_buffer);
    return names;
}

test {
    _ = @import("checks_top20.zig");
    _ = @import("harness.zig");
}
