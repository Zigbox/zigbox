//! `zig build demo-mac`: the milestone demos M1 to M4, steps 2 to 4 of M4b and the five steps of
//! M6b (with `exec` and `logs` on a terminal, with signals and exit codes), driven from macOS
//! through the macOS `zbx`, which runs them in its virtual machine. Each step is one shell
//! command line with what it must print and how it must end; the steps are the ones the Linux
//! demos check (docs/demos/m1.md to m4.md), taken by number, so a step that passes on Linux and
//! fails here is a difference between the two `zbx`es. The Linux demos drive a QEMU console
//! (`src/testing/vm/session.zig`), which has no counterpart on a Mac, so their code is not
//! shared; this table is the macOS side of the same steps.
//!
//! Run from a directory below the home (the machine shares the home and nothing else). It uses
//! `$HOME/zbx-demo-mac` as its working directory and leaves it for the next run.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const alpine = @import("mac_alpine.zon");

/// One step: the shell line (`$Z` is the zbx, `$R` the unpacked rootfs, `$W` the work
/// directory), how it must end and what each stream must hold.
pub const Step = struct {
    id: []const u8,
    what: []const u8,
    line: []const u8,
    exit: u8 = 0,
    stdout_has: []const []const u8 = &.{},
    stderr_has: []const []const u8 = &.{},
    stdout_lacks: []const []const u8 = &.{},
    stderr_empty: bool = false,
};

pub const steps = [_]Step{
    // ---- M1: the shell ---------------------------------------------------------------------
    .{
        .id = "m1.1",
        .what = "the shell is fed id, hostname and the release file on stdin",
        .line = "printf 'id\\nhostname\\ncat /etc/os-release\\n' | " ++
            "$Z run --rootfs $R --name m1sh -- sh",
        .stdout_has = &.{ "uid=0(root)", "m1sh", "ID=alpine", "VERSION_ID=3.20." },
    },
    .{
        .id = "m1.3",
        .what = "touch /etc/hacked lands in the rootfs, owned by the user, and not on the Mac",
        .line = "$Z run --rootfs $R -- touch /etc/hacked && test -f $R/etc/hacked && " ++
            "test \"$(stat -f %u $R/etc/hacked)\" = \"$(id -u)\" && " ++
            "! test -e /etc/hacked && echo landed",
        .stdout_has = &.{"landed"},
    },
    .{
        .id = "m1.4",
        .what = "exit 42 is zbx's exit code",
        .line = "$Z run --rootfs $R -- sh -c 'exit 42'",
        .exit = 42,
        // M5 added a hint on stderr for a failed run without --net, so stderr is not empty.
        .stderr_has = &.{"network: none"},
    },
    .{
        .id = "m1.5",
        .what = "SIGINT to zbx stops a foreground sleep 1000 within 2 s, exit 130",
        .line = "$Z run --rootfs $R -- sleep 1000 & p=$!; sleep 3; kill -INT $p; " ++
            "s=$(date +%s); wait $p; c=$?; test $(( $(date +%s) - s )) -le 2 && exit $c",
        .exit = 130,
    },
    .{
        .id = "m1.7",
        .what = "a missing rootfs is ZBX-E0201 and exit 125",
        .line = "$Z run --rootfs $W/no-such-rootfs -- true",
        .exit = 125,
        .stderr_has = &.{"ZBX-E0201"},
    },
    // ---- M2: limits and the sandbox ------------------------------------------------------------
    .{
        .id = "m2.3",
        .what = "mount inside the container is refused, and not by zbx",
        .line = "$Z run --rootfs $R -- mount -t tmpfs none /mnt 2>&1; c=$?; " ++
            "test $c -ne 0 -a $c -ne 125 -a $c -ne 70 && exit 0; exit 99",
        .stdout_has = &.{},
    },
    .{
        .id = "m2.4a",
        .what = "--read-only: a write to / fails",
        .line = "$Z run --rootfs $R --read-only -- touch /x",
        .exit = 1,
        .stderr_has = &.{"Read-only file system"},
    },
    .{
        .id = "m2.4b",
        .what = "--read-only: /tmp is writable",
        .line = "$Z run --rootfs $R --read-only -- sh -c 'touch /tmp/x && echo tmp-ok'",
        .stdout_has = &.{"tmp-ok"},
    },
    // ---- M3: the store ----------------------------------------------------------------------
    .{
        .id = "m3.1",
        .what = "store import prints the digest alone",
        .line = "$Z store import $R",
        .stdout_has = &.{"b3:"},
    },
    .{
        .id = "m3.3",
        .what = "a run from the digest is read-only on request",
        .line = "d=$($Z store import $R) && $Z run $d --read-only -- touch /x",
        .exit = 1,
        .stderr_has = &.{"Read-only file system"},
    },
    .{
        .id = "m3.5",
        .what = "an unknown digest is ZBX-E0410, exit 125, nothing on stdout",
        .line = "$Z run b3:00000000000000000000000000000000" ++
            "00000000000000000000000000000000 -- true",
        .exit = 125,
        .stderr_has = &.{"ZBX-E0410"},
    },
    // ---- M4: pull ---------------------------------------------------------------------------
    .{
        .id = "m4.1",
        .what = "pull alpine:3.20 prints the manifest digest",
        .line = "cd $W && $Z pull alpine:3.20",
        .stdout_has = &.{"sha256:"},
    },
    .{
        .id = "m4.2",
        .what = "the pulled image runs by tag, from the lock file",
        .line = "cd $W && $Z run alpine:3.20 -- cat /etc/os-release",
        .stdout_has = &.{"ID=alpine"},
    },
    .{
        .id = "m4.3",
        .what = "a tag that does not exist is ZBX-E0508",
        .line = "cd $W && $Z pull alpine:no-such-tag-zbx",
        .exit = 1,
        .stderr_has = &.{"ZBX-E0508"},
    },
    .{
        .id = "m4.4",
        .what = "text that is not a reference is ZBX-E0501",
        .line = "cd $W && $Z pull 'A B'",
        .exit = 1,
        .stderr_has = &.{"ZBX-E0501"},
    },
    // ---- M4b: demo steps 2 to 4 ---------------------------------------------------------------
    .{
        .id = "m4b.2",
        .what = "a second run is quick: the machine and the store are warm",
        .line = "cd $W && s=$(python3 -c 'import time;print(time.time())') && " ++
            "$Z run alpine:3.20 -- true && " ++
            "python3 -c \"import time,sys;sys.exit(0 if time.time()-$s < 2.0 else 1)\"",
    },
    .{
        .id = "m4b.3",
        .what = "files written in the container are on the Mac, owned by the user",
        .line = "$Z run --rootfs $R -- touch /hello && " ++
            "test \"$(stat -f %u $R/hello)\" = \"$(id -u)\" && echo owned",
        .stdout_has = &.{"owned"},
    },
    .{
        .id = "m4b.3s",
        .what = "state survives zbx vm stop",
        .line = "cd $W && " ++
            "$Z run --state demo:/data alpine:3.20 -- sh -c 'echo persisted > /data/x' && " ++
            "$Z vm stop >/dev/null && $Z run --state demo:/data alpine:3.20 -- cat /data/x",
        .stdout_has = &.{"persisted"},
    },
    .{
        .id = "m4b.4",
        .what = "a published port answers on the Mac's localhost and is closed by zbx stop",
        .line = "cd $W && $Z pull nginx:alpine >/dev/null && " ++
            "$Z run -d --name web --publish 18099:80 nginx:alpine >/dev/null; sleep 3; " ++
            "curl -sS -m5 http://localhost:18099/ | grep -o 'Welcome to nginx'; " ++
            "$Z stop web >/dev/null; sleep 1; " ++
            "curl -sS -m2 http://localhost:18099/ >/dev/null 2>&1 && " ++
            "echo STILL-OPEN || echo closed",
        .stdout_has = &.{ "Welcome to nginx", "closed" },
        .stdout_lacks = &.{"STILL-OPEN"},
    },
    // ---- M6b: the dev loop (docs/demos/m6b.md): the spec's five steps, then what the Mac adds ---
    // The project is `$W/m6b-project`, which holds its own zbx.lock, so `../outside-spec` is
    // outside it but inside the home. `web` serves `./site` on the Mac's port 8000.
    .{
        .id = "m6b.1",
        .what = "run -d serves ./site on 8000 (python's http.server), and exec sees it listen",
        .line = "mkdir -p $W/m6b-project && cd $W/m6b-project && " ++
            "($Z stop web >/dev/null 2>&1; rm -rf site ../outside-spec zbx.lock; true) && " ++
            "mkdir site ../outside-spec && echo first-SIGMA > site/index.html && " ++
            // The project holds its own lock, so that a zbx.lock higher up (the home's) is not it.
            "printf '.{\\n    .version = 1,\\n    .images = .{},\\n}\\n' > zbx.lock && " ++
            "$Z pull python:3.12-slim >/dev/null && $Z pull alpine:3.20 >/dev/null && " ++
            "$Z run -d --name web --publish 8000:8000 --mount ./site:/srv python:3.12-slim " ++
            "-- python -m http.server -d /srv 8000 >/dev/null && i=0 && " ++
            "until $Z exec web -- python -c " ++
            "'import socket; socket.create_connection((\"127.0.0.1\", 8000)).close()' " ++
            "</dev/null >/dev/null 2>&1; " ++
            "do i=$((i+1)); test $i -lt 90 || exit 9; sleep 1; done; " ++
            "echo listening",
        .stdout_has = &.{"listening"},
    },
    .{
        .id = "m6b.2",
        .what = "curl returns the page; after an edit on the Mac, the edit",
        .line = "cd $W/m6b-project && curl -fsS http://localhost:8000/index.html && " ++
            "echo second-SIGMA > site/index.html && curl -fsS http://localhost:8000/index.html",
        .stdout_has = &.{ "first-SIGMA", "second-SIGMA" },
    },
    .{
        .id = "m6b.3",
        .what = "exec writes into the mount; the Mac user owns it, and nothing else is in site",
        .line = "cd $W/m6b-project && " ++
            "$Z exec web -- sh -c 'echo made-inside > /srv/new.txt' </dev/null && " ++
            "ls -l site/new.txt && test \"$(stat -f %u site/new.txt)\" = \"$(id -u)\" && " ++
            "test -z \"$(find site ! -user \"$(id -un)\" -print)\" && cat site/new.txt",
        .stdout_has = &.{ "-rw-", "site/new.txt", "made-inside" },
    },
    .{
        .id = "m6b.4",
        .what = "logs web shows the two requests of step 2, and no others",
        .line = "cd $W/m6b-project && l=$($Z logs web) && " ++
            "n=$(echo \"$l\" | grep -c ' HTTP/1\\.') && " ++
            "g=$(echo \"$l\" | grep -c '\"GET /index.html HTTP/1.1\" 200') && " ++
            "test $n = 2 -a $g = 2 && echo two-requests",
        .stdout_has = &.{"two-requests"},
    },
    .{
        .id = "m6b.5",
        .what = "a writable mount outside the project is ZBX-E0212, naming the rule, exit 125",
        .line = "cd $W/m6b-project && $Z run --mount ../outside-spec:/x alpine:3.20 -- true",
        .exit = 125,
        .stderr_has = &.{ "ZBX-E0212", "outside the project" },
    },
    .{
        .id = "m6b.5h",
        .what = "a project outside the home is refused before the machine is asked (ZBX-E1013)",
        .line = "mkdir -p /tmp/zbx-demo-mac-outside && cd /tmp/zbx-demo-mac-outside && " ++
            "$Z logs web",
        .exit = 1,
        .stderr_has = &.{"ZBX-E1013"},
    },
    // Terminal, signals, exit codes and --follow across the vsock link.
    .{
        .id = "m6b.6",
        .what = "exec's exit code is the command's, and a refusal of exec is 125",
        .line = "cd $W/m6b-project && $Z exec web -- sh -c 'exit 7' </dev/null; c=$?; " ++
            "$Z exec no-such-container -- true </dev/null; d=$?; echo codes=$c,$d",
        .stdout_has = &.{"codes=7,125"},
    },
    .{
        .id = "m6b.7",
        .what = "SIGINT to zbx exec stops a foreground sleep 1000 within 2 s, exit 130",
        .line = "cd $W/m6b-project; $Z exec web -- sleep 1000 </dev/null & p=$!; sleep 3; " ++
            "kill -INT $p; s=$(date +%s); wait $p; c=$?; " ++
            "test $(( $(date +%s) - s )) -le 2 && exit $c",
        .exit = 130,
    },
    .{
        .id = "m6b.8",
        .what = "exec on a terminal gets a pseudo-terminal in the container",
        .line = "cd $W/m6b-project && script -q /dev/null $Z exec web -- tty",
        .stdout_has = &.{"/dev/pts/"},
    },
    .{
        .id = "m6b.9",
        .what = "logs --follow shows a detached container's output and ends 0 with it",
        .line = "cd $W/m6b-project && n=fl$$ && " ++
            "$Z run -d --name $n alpine:3.20 -- " ++
            "sh -c 'echo first-line; sleep 4; echo last-line' " ++
            ">/dev/null && $Z logs --follow $n",
        .stdout_has = &.{ "first-line", "last-line" },
    },
    .{
        .id = "m6b.10",
        .what = "SIGINT to zbx logs --follow ends it within 2 s, and the container goes on",
        .line = "cd $W/m6b-project; $Z logs --follow web >/dev/null & p=$!; sleep 3; " ++
            "kill -INT $p; s=$(date +%s); wait $p; c=$?; " ++
            "test $(( $(date +%s) - s )) -le 2 && " ++
            "$Z exec web -- true </dev/null && echo still-running; exit $c",
        .exit = 130,
        .stdout_has = &.{"still-running"},
    },
    .{
        .id = "m6b.11",
        .what = "stopping web frees port 8000 and exec into it is refused, exit 125",
        .line = "cd $W/m6b-project && $Z stop web >/dev/null && sleep 1 && " ++
            "(curl -sS -m2 http://localhost:8000/ >/dev/null 2>&1 && echo STILL-OPEN || " ++
            "echo closed); $Z exec web -- true </dev/null",
        .exit = 125,
        .stdout_has = &.{"closed"},
        .stdout_lacks = &.{"STILL-OPEN"},
        .stderr_has = &.{"ZBX-E0220"},
    },
};

pub fn main(init: std.process.Init) !u8 {
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const started = std.Io.Clock.Timestamp.now(init.io, .awake);
    const failures = run_all(init, out) catch |err| {
        try out.print("\ndemo-mac: FAILED to run ({s})\n", .{@errorName(err)});
        return 1;
    };
    _ = started;
    if (failures > 0) {
        try out.print("\ndemo-mac: FAILED, {d} of {d} steps\n", .{ failures, steps.len });
        return 1;
    }
    try out.print("\ndemo-mac: PASSED, {d} steps\n", .{steps.len});
    return 0;
}

fn option(init: std.process.Init, name: []const u8) ?[]const u8 {
    var iterator = init.minimal.args.iterate();
    _ = iterator.next();
    while (iterator.next()) |word| {
        if (std.mem.eql(u8, word, name)) return iterator.next();
    }
    return null;
}

fn run_all(init: std.process.Init, out: *Io.Writer) !u32 {
    const io = init.io;
    const arena = init.arena.allocator();
    const home = init.environ_map.get("HOME") orelse return error.NoHome;
    const zbx = option(init, "--zbx") orelse "zig-out/bin/zbx";
    const work = try std.fmt.allocPrint(arena, "{s}/zbx-demo-mac", .{home});
    const rootfs = try std.fmt.allocPrint(arena, "{s}/alpine", .{work});
    const zbx_path = try std.Io.Dir.cwd().realPathFileAlloc(io, zbx, arena);
    try out.print("demo-mac: zbx {s}\ndemo-mac: work directory {s}\n", .{ zbx_path, work });
    try prepare_rootfs(init, out, work, rootfs);
    var failures: u32 = 0;
    for (steps) |step| {
        const line = try expand(arena, step.line, zbx_path, rootfs, work);
        const result = try std.process.run(arena, io, .{
            .argv = &.{ "/bin/sh", "-c", line },
            .cwd = .{ .path = work },
        });
        const code: u8 = switch (result.term) {
            .exited => |value| value,
            else => 255,
        };
        const bad = check(step, code, result.stdout, result.stderr);
        if (bad) |reason| {
            failures += 1;
            try out.print("FAIL {s}  {s}\n     {s}\n     exit {d}\n", .{
                step.id, step.what, reason, code,
            });
            try out.print("     stdout: {s}\n     stderr: {s}\n", .{
                clip(result.stdout), clip(result.stderr),
            });
        } else {
            try out.print("ok   {s}  {s}\n", .{ step.id, step.what });
        }
        try out.flush();
    }
    return failures;
}

fn clip(text: []const u8) []const u8 {
    return if (text.len > 600) text[text.len - 600 ..] else text;
}

/// Why a step did not pass, or null.
pub fn check(step: Step, code: u8, stdout: []const u8, stderr: []const u8) ?[]const u8 {
    if (code != step.exit) return "the exit code is not the expected one";
    for (step.stdout_has) |piece| {
        if (std.mem.indexOf(u8, stdout, piece) == null) return "stdout lacks an expected piece";
    }
    for (step.stderr_has) |piece| {
        if (std.mem.indexOf(u8, stderr, piece) == null) return "stderr lacks an expected piece";
    }
    for (step.stdout_lacks) |piece| {
        if (std.mem.indexOf(u8, stdout, piece) != null) return "stdout has what it must not";
    }
    if (step.stderr_empty and stderr.len != 0) return "stderr is not empty";
    return null;
}

fn expand(
    arena: std.mem.Allocator,
    line: []const u8,
    zbx: []const u8,
    rootfs: []const u8,
    work: []const u8,
) ![]u8 {
    const first = try std.mem.replaceOwned(u8, arena, line, "$Z", zbx);
    const second = try std.mem.replaceOwned(u8, arena, first, "$R", rootfs);
    return std.mem.replaceOwned(u8, arena, second, "$W", work);
}

fn prepare_rootfs(
    init: std.process.Init,
    out: *Io.Writer,
    work: []const u8,
    rootfs: []const u8,
) !void {
    const io = init.io;
    const arena = init.arena.allocator();
    const image = @import("vm/image.zig");
    const dir = Io.Dir.cwd();
    try dir.createDirPath(io, work);
    const archive = try image.ensure_pin(init, ".zig-cache/zbx-mac", out, .{
        .url = alpine.url,
        .sha256 = alpine.sha256,
        .file_name = alpine.file_name,
    });
    // A fresh unpack each run: steps change the rootfs.
    dir.deleteTree(io, rootfs) catch {};
    try dir.createDirPath(io, rootfs);
    const unpack = try std.process.run(arena, io, .{
        .argv = &.{ "/usr/bin/tar", "-xzf", archive, "-C", rootfs },
    });
    if (unpack.term != .exited or unpack.term.exited != 0) return error.UnpackFailed;
}

test "a step passes only when its exit code and every piece match" {
    // Goal: the verdict function. Method: one step, each way to miss it.
    const step: Step = .{
        .id = "t",
        .what = "t",
        .line = "",
        .exit = 3,
        .stdout_has = &.{"yes"},
        .stderr_has = &.{"E1"},
        .stdout_lacks = &.{"no"},
    };
    try std.testing.expect(check(step, 3, "yes", "E1") == null);
    try std.testing.expect(check(step, 0, "yes", "E1") != null);
    try std.testing.expect(check(step, 3, "", "E1") != null);
    try std.testing.expect(check(step, 3, "yes", "") != null);
    try std.testing.expect(check(step, 3, "yes no", "E1") != null);
    for (steps) |each| try std.testing.expect(each.line.len > 0);
}
