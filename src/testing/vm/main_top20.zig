//! The top-20 check (docs/demos/m4.md, "The top-20 check"): pull each of the twenty images in
//! `top20.zon` and run its default command in the harness's Ubuntu 24.04 VM, rootless, with a
//! timeout. One line per image says whether it pulled, whether it ran, the exit code, a verdict
//! and the reason. A seccomp refusal is told apart: the image runs again under
//! `strace`, and every syscall that returned EPERM and is not on the allowlist is named in the
//! `seccomp=` field. Each image runs twice, by its floating tag and by its pinned digest, in the
//! same VM; a `top20-compare:` line per image tells an image that moved upstream from a runtime
//! regression. The weekly workflow runs this against the real Docker Hub; locally, name a
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

const Entry = struct {
    ref: []const u8,
    known: []const u8,
    probe: []const u8,
    env: []const u8,
    /// The same image by the index digest its tag named on `list.pinned_date`.
    pinned: []const u8,
};

const images = blk: {
    @setEvalBranchQuota(100_000);
    var all: [list.images.len]Entry = undefined;
    for (list.images, 0..) |entry, index| {
        if (!checks_top20.pinned_matches(entry.ref, entry.pinned)) {
            @compileError("top20.zon: the pin of " ++ entry.ref ++ " is not its name by digest");
        }
        all[index] = .{
            .ref = entry.ref,
            .known = entry.known,
            .probe = entry.probe,
            .env = entry.env,
            .pinned = entry.pinned,
        };
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
    // Two entries pinned to one digest would be one image listed twice.
    @setEvalBranchQuota(100_000);
    for (images, 0..) |entry, index| {
        for (images[index + 1 ..]) |later| {
            std.debug.assert(!std.mem.eql(u8, entry.pinned, later.pinned));
        }
    }
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
    try session_mod.start(&session, init, out, overlay, accel, .{
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

/// The guest's disk holds one image at a time: the largest of the twenty is several times its
/// compressed size once pulled, unpacked and run, and twenty of them do not fit in the overlay.
/// So the store and the lock are removed after each image (as root: a container's layer can hold
/// ids mapped from the demo user's subuid range).
fn clear_store(session: *Session, out: *Io.Writer) !void {
    const command = "rm -rf /home/demo/.local/share/zbx " ++ project ++ "/zbx.lock; " ++
        "df -h / | tail -n 1";
    const cleared = try session.run(command, limits.command_timeout_kvm_s * 5);
    try H.show(out, "remove the store before the next image (free space follows)", cleared);
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

/// The verdicts of one list, floating or pinned.
const Counts = struct {
    passed: u32 = 0,
    known: u32 = 0,
    failed: u32 = 0,

    fn add(counts: *Counts, verdict: checks_top20.Verdict) void {
        switch (verdict) {
            .pass => counts.passed += 1,
            .known => counts.known += 1,
            .fail => counts.failed += 1,
        }
    }
};

/// Both runs of every selected image, then every result line again, the comparison lines and a
/// count per list. The run fails when either list has a failure: a pin that fails is a
/// regression, and a floating tag that fails still fails the canary, as before the pins.
fn run_all(
    session: *Session,
    out: *Io.Writer,
    arena: std.mem.Allocator,
    traced: bool,
    only: []const u8,
) !u32 {
    try out.print("\ntop20: {d} images from {s} ({s}), pinned on {s}\n", .{
        images.len, list.date, list.source, list.pinned_date,
    });
    var pairs: [images.len]?Pair = @splat(null);
    var floating: Counts = .{};
    var pinned: Counts = .{};
    for (images, 0..) |entry, index| {
        if (!is_selected(only, entry.ref)) continue;
        const pair = try try_both(session, out, arena, entry, traced);
        floating.add(pair.floating.verdict);
        pinned.add(pair.pinned.verdict);
        pairs[index] = pair;
    }
    try out.print("\ntop20: results ({s}, pinned on {s})\n", .{ list.date, list.pinned_date });
    for (pairs) |maybe| {
        const pair = maybe orelse continue;
        try out.print("top20-result: {s}\ntop20-result: {s}\n", .{
            pair.floating.line, pair.pinned.line,
        });
    }
    for (pairs) |maybe| {
        if (maybe) |pair| try out.print("top20-compare: {s}\n", .{pair.compare});
    }
    const summary = "top20: {s}{d} passed, {d} known not to run, {d} failed\n";
    try out.print(summary, .{ "", floating.passed, floating.known, floating.failed });
    try out.print(summary, .{ "pinned: ", pinned.passed, pinned.known, pinned.failed });
    return floating.failed + pinned.failed;
}

/// One run of an image: its result line and verdict.
const Outcome = struct { line: []const u8, verdict: checks_top20.Verdict };

/// Both runs of one image and the line that compares them.
const Pair = struct { floating: Outcome, pinned: Outcome, compare: []const u8 };

/// Asks where the floating tag points now, runs the tag, then the pin. When the tag still names
/// the pinned index the content is the same, so the store is kept between the two runs and the
/// pinned pull finds every blob there (fewer downloads, and the same anonymous pull count);
/// otherwise it is cleared first, as the guest's disk holds one image at a time.
fn try_both(
    session: *Session,
    out: *Io.Writer,
    arena: std.mem.Allocator,
    entry: Entry,
    traced: bool,
) !Pair {
    const now = try resolve_tag(session, out, arena, entry.ref);
    const tag = checks_top20.tag_of(now, entry.pinned);
    const floating = try try_one(session, out, arena, entry, entry.ref, traced);
    if (tag != .same) try clear_store(session, out);
    const pinned = try try_one(session, out, arena, entry, entry.pinned, traced);
    try clear_store(session, out);
    var buffer: [512]u8 = undefined;
    const line = try checks_top20.format_compare(&buffer, .{
        .ref = entry.ref,
        .floating = floating.verdict,
        .pinned = pinned.verdict,
        .tag = tag,
        .now = now,
    });
    const compare = try arena.dupe(u8, line);
    try out.print("\ntop20-compare: {s}\n", .{compare});
    return .{ .floating = floating, .pinned = pinned, .compare = compare };
}

/// The index digest the floating tag names now, from `zbx pull --resolve-only --output json`
/// (no layer is fetched); null when the resolve fails or names a single manifest.
fn resolve_tag(
    session: *Session,
    out: *Io.Writer,
    arena: std.mem.Allocator,
    ref: []const u8,
) !?[]const u8 {
    std.debug.assert(std.mem.indexOfScalar(u8, ref, '@') == null);
    const format = z ++ " pull --resolve-only --output json {s} </dev/null";
    const command = try std.fmt.allocPrint(session.scratch_allocator(), format, .{ref});
    const resolved = try split_long(session, command);
    try H.show_split(out, command, resolved);
    if (resolved.status != 0) return null;
    const digest = checks_top20.index_digest_of(resolved.streams.stdout) orelse return null;
    std.debug.assert(checks_top20.is_digest(digest));
    return try arena.dupe(u8, digest);
}

/// Pulls and runs `pulled_as` (the entry's tag or its pin) and prints its result line.
fn try_one(
    session: *Session,
    out: *Io.Writer,
    arena: std.mem.Allocator,
    entry: Entry,
    pulled_as: []const u8,
    traced: bool,
) !Outcome {
    const result = try try_image(session, out, entry, pulled_as, traced);
    std.debug.assert(std.mem.eql(u8, result.ref, pulled_as));
    var buffer: [1024]u8 = undefined;
    const line = try arena.dupe(u8, try checks_top20.format_line(&buffer, result));
    try out.print("\ntop20-result: {s}\n", .{line});
    if (result.seccomp.len > 0 and result.verdict == .fail) {
        try out.print("top20: SECCOMP: {s} was refused {s}\n", .{ pulled_as, result.seccomp });
    }
    if (result.verdict == .pass) {
        if (entry.known.len > 0) {
            const note = "top20: NOTE: {s} passes; its known reason no longer holds\n";
            try out.print(note, .{pulled_as});
        }
    }
    return .{ .line = line, .verdict = result.verdict };
}

/// The two files the container's output goes to. They are the demo user's, as a terminal or a
/// pipe the user opened would be: an image that logs to /dev/stdout opens it again through
/// /proc, and the kernel refuses that for a file whose owner is not mapped in the container
/// (a root-owned console or pipe), so root's own redirects would fail such images for a reason
/// that is the harness's. They are in the demo user's home, not in /tmp: root may not open
/// another user's file in a sticky directory (fs.protected_regular).
const out_file = "/home/demo/top20-out";
const err_file = "/home/demo/top20-err";

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
    // The `echo` ends a last line that has no newline (jshell's prompt), so the marker is
    // always on a line of its own.
    const format = "{s} >" ++ out_file ++ " 2>" ++ err_file ++ "; ZBX_S=$?; tail -c 8192 " ++
        out_file ++ "; echo; echo ZBX-STDERR\"\"-FOLLOWS; tail -c 8192 " ++ err_file ++
        "; exit $ZBX_S";
    const typed = try std.fmt.bufPrint(&buffer, format, .{command});
    const result = try session.run(typed, image_timeout_s);
    const streams = try checks.split_streams(result.output);
    return .{ .streams = streams, .status = result.status };
}

/// Pulls `result.ref` and returns the reference to run it by (`checks_top20.run_reference`), or
/// null when there is none: the pull failed, or a pin's pull printed no manifest digest. `result`
/// then holds the verdict and the reason.
fn pull_image(
    session: *Session,
    out: *Io.Writer,
    entry: Entry,
    result: *checks_top20.Result,
) !?[]const u8 {
    std.debug.assert(result.verdict == .fail);
    const arena = session.scratch_allocator();
    const pull = try std.fmt.allocPrint(arena, z ++ " pull {s} </dev/null", .{result.ref});
    const pulled = try split_long(session, pull);
    try H.show_split(out, pull, pulled);
    result.pulled = pulled.status == 0;
    result.status = pulled.status;
    if (result.pulled) {
        const buffer = try arena.alloc(u8, 256);
        const stdout = pulled.streams.stdout;
        if (checks_top20.run_reference(buffer, result.ref, stdout)) |run_ref| return run_ref;
        result.reason = "the pull printed no manifest digest to run the pin by";
        return null;
    }
    const stderr = try arena.dupe(u8, pulled.streams.stderr);
    const missing: checks_top20.Observed = .{ .pulled = false, .status = 0, .stderr = stderr };
    result.verdict = checks_top20.judge(missing, entry.known);
    result.reason = reason_of(entry, result.verdict, stderr, "error[");
    return null;
}

/// Pulls `pulled_as` and runs the image's default command. The entry gives the known reason,
/// the probe and the environment; the result line names `pulled_as`.
fn try_image(
    session: *Session,
    out: *Io.Writer,
    entry_given: Entry,
    pulled_as: []const u8,
    traced: bool,
) !checks_top20.Result {
    const arena = session.scratch_allocator();
    var result: checks_top20.Result = .{
        .ref = pulled_as,
        .pulled = false,
        .ran = false,
        .status = 0,
        .verdict = .fail,
        .seccomp = "",
        .reason = "-",
    };
    // A pin runs by another reference than it was pulled by; every later command uses that one.
    var entry = entry_given;
    entry.ref = try pull_image(session, out, entry_given, &result) orelse return result;
    std.debug.assert(result.pulled);
    const probe = checks_top20.parse_probe(entry.probe);
    const run = try run_command(arena, entry, probe);
    const ran = try split_long(session, run);
    try H.show_split(out, run, ran);
    const stderr = try arena.dupe(u8, ran.streams.stderr);
    const answer: ProbeAnswer = if (probe != null and checks_top20.stopped_by_timeout(stderr))
        try read_probe(session)
    else
        .{ .probe = .none, .text = "" };
    const probe_result = answer.probe;
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
    if (result.verdict == .fail and probe_result == .failed) {
        result.reason = try arena.dupe(u8, answer.text);
    }
    // Only a failure is looked at again under strace: a pass needs no explanation.
    if (result.verdict != .pass) result.seccomp = try find_seccomp(session, out, entry, traced);
    return result;
}

/// The flags and reference of a run: `-e NAME=VALUE` when the entry has an `env`, then the image.
fn image_with_env(arena: std.mem.Allocator, entry: Entry) ![]const u8 {
    if (entry.env.len == 0) return entry.ref;
    return std.fmt.allocPrint(arena, "-e {s} {s}", .{ entry.env, entry.ref });
}

/// The command for one image's default run. A server with a probe runs in the background with its
/// port published on a high host port (`checks_top20.published_port`, M5's `--publish`), and the
/// guest asks it there, on 127.0.0.1, every 2 s until it answers, the container ends or
/// `probe_steps_max` steps pass. The answer goes to `probe_file`; the run's own exit code stays
/// the command's. An image without a probe shares the host's network, as in M5 slice 2.
fn run_command(
    arena: std.mem.Allocator,
    entry: Entry,
    probe: ?checks_top20.ProbeSpec,
) ![]const u8 {
    const ref = try image_with_env(arena, entry);
    const plain = z ++ " run --net host --timeout " ++ run_timeout_ms ++ " {s} </dev/null";
    const spec = probe orelse return std.fmt.allocPrint(arena, plain, .{ref});
    const host_port = checks_top20.published_port(spec.port);
    const published = z ++ " run --publish {d}:{d} --timeout " ++ run_timeout_ms ++
        " {s} </dev/null";
    var text: std.ArrayList(u8) = .empty;
    try text.print(arena, "rm -f " ++ probe_file ++ "; {{ " ++ published ++ " & ZP=$!; ZI=0; " ++
        "while [ $ZI -lt {d} ] && kill -0 $ZP 2>/dev/null; do sleep 2; ZI=$((ZI+1)); ", .{
        host_port, spec.port, ref, probe_steps_max,
    });
    // `read` rather than `head`: a killed `head` loses what it buffered.
    const connect = "exec 3<>/dev/tcp/127.0.0.1/{d}";
    if (spec.expect.len == 0) {
        try text.print(arena, "ZR=$(timeout 6 bash -c '" ++ connect ++ "' 2>&1); " ++
            "if [ -z \"$ZR\" ]; then echo ok >" ++ probe_file ++ "; break; fi; ", .{host_port});
    } else {
        try text.print(arena, "ZR=$(timeout 6 bash -c '" ++ connect ++ " && printf \"{s}\" >&3 " ++
            "&& read -t 3 -r -n 300 L <&3; echo \"$L\"' 2>&1); " ++
            "case \"$ZR\" in *{s}*) echo ok >" ++ probe_file ++ "; break;; esac; ", .{
            host_port, spec.send, spec.expect,
        });
    }
    // Without an answer the file says what the last try got.
    try text.print(arena, "done; [ -e " ++ probe_file ++ " ] || echo \"no answer on port {d}: " ++
        "$ZR\" >" ++ probe_file ++ "; wait $ZP; }}", .{host_port});
    return text.items;
}

/// What the probe wrote: `ok`, or why it got no answer.
const ProbeAnswer = struct { probe: checks_top20.Probe, text: []const u8 };

fn read_probe(session: *Session) !ProbeAnswer {
    const command = "cat " ++ probe_file ++ " 2>/dev/null";
    const read = try session.run(command, limits.command_timeout_kvm_s);
    const text = std.mem.trim(u8, read.output, " \r\n");
    if (std.mem.eql(u8, text, "ok")) return .{ .probe = .ok, .text = "" };
    const arena = session.scratch_allocator();
    const kept = try arena.dupe(u8, if (text.len == 0) "the probe wrote nothing" else text);
    return .{ .probe = .failed, .text = kept };
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
    const last = checks_top20.last_line(stderr);
    return if (std.mem.eql(u8, last, "-")) "failed with nothing on stderr" else last;
}

/// Runs the image again under strace and returns the syscalls that were refused with
/// EPERM and are not on the allowlist: the filter's own refusals. "unchecked" without strace.
fn find_seccomp(session: *Session, out: *Io.Writer, entry: Entry, traced: bool) ![]const u8 {
    if (!traced) return "unchecked";
    const arena = session.scratch_allocator();
    const ref = try image_with_env(arena, entry);
    const command = try std.fmt.allocPrint(
        arena,
        "strace -f -o " ++ strace_log ++ " -e status=failed " ++ z ++
            " run --net host --timeout " ++ run_timeout_ms ++ " {s} </dev/null >/dev/null 2>&1; " ++
            "grep -h ' = -1 EPERM' " ++ strace_log ++
            " | sed -E 's/^[0-9]+ +//; s/\\(.*//' | sort -u | tr '\\n' ' '",
        .{ref},
    );
    const traced_run = try session.run(command, image_timeout_s * 2);
    try H.show(out, "strace: the syscalls that returned EPERM", traced_run);
    const out_buffer = try arena.alloc(u8, 256);
    const names = checks_top20.seccomp_suspects(traced_run.output, &allowed, out_buffer);
    return names;
}

test "the three databases get their password variable, and the others none" {
    // Goal: the entrypoints of postgres, mysql and mariadb refuse to start without a root
    // password, so the run must carry `-e NAME=VALUE`; no other entry has one. Method: the
    // command text of each entry.
    var state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    var with_env: u32 = 0;
    for (images) |entry| {
        const text = try image_with_env(arena, entry);
        if (entry.env.len == 0) {
            try std.testing.expectEqualStrings(entry.ref, text);
            continue;
        }
        with_env += 1;
        try std.testing.expect(std.mem.startsWith(u8, text, "-e "));
        try std.testing.expect(std.mem.endsWith(u8, text, entry.ref));
        try std.testing.expect(std.mem.indexOf(u8, entry.env, "PASSWORD=") != null);
        try std.testing.expect(entry.probe.len > 0); // A database is asked on its port.
    }
    try std.testing.expectEqual(@as(u32, 3), with_env);
}

test {
    _ = @import("checks_top20.zig");
    _ = @import("harness.zig");
}
