//! `zig build demo-mac`: the milestone demos M1 to M4, steps 2 to 4 of M4b, the five steps of
//! M6b (with `exec` and `logs` on a terminal, with signals and exit codes) and M9's import and
//! build of its demo project, driven from macOS through the macOS `zbx`, which runs them in its
//! virtual machine. Each step is one shell command line with what it must print and how it must
//! end; the steps are the ones the Linux demos check (docs/demos/m1.md to m9.md), taken by
//! number, so a step that passes on Linux and fails here is a difference between the two
//! `zbx`es. The Linux demos drive a QEMU console (`src/testing/vm/session.zig`), which has no
//! counterpart on a Mac, so their code is not shared; this table is the macOS side of the same
//! steps.
//!
//! Run from a directory below the home (the machine shares the home and nothing else). It uses
//! `$HOME/zbx-demo-mac` as its working directory and leaves it for the next run. Steps m9.1 to
//! m9.4 need Rosetta: the demo project's lock pins `linux/amd64`, as `demo-m9`'s does, so that
//! its digest is `demo-m9`'s golden. Without it they fail with one line naming ZBX-E1016; m9.5
//! builds a project of its own natively, for linux/arm64.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Io = std.Io;
const alpine = @import("mac_alpine.zon");
const m9_golden = @import("vm/m9_expected.zon");

/// M9's demo project (`vm/m9_project/`, the files `demo-m9` writes, `hello_m9.project_files`),
/// written afresh under the work directory for each run, with no build file.
pub const m9_project_files = [_]struct { name: []const u8, text: []const u8 }{
    .{ .name = "Dockerfile", .text = @embedFile("vm/m9_project/Dockerfile") },
    .{ .name = ".dockerignore", .text = @embedFile("vm/m9_project/.dockerignore") },
    .{ .name = "zbx.lock", .text = @embedFile("vm/m9_project/zbx.lock") },
    .{ .name = "go.mod", .text = @embedFile("vm/m9_project/go.mod") },
    .{ .name = "main.go", .text = @embedFile("vm/m9_project/main.go") },
    .{ .name = "VERSION", .text = @embedFile("vm/m9_project/VERSION") },
    .{ .name = "LICENSE", .text = @embedFile("vm/m9_project/LICENSE") },
    .{ .name = "README.md", .text = @embedFile("vm/m9_project/README.md") },
};
/// The build file `zbx import` must write for the project, `demo-m9`'s golden. Written beside the
/// project (not in it) for `cmp`.
const m9_golden_build = @embedFile("vm/m9_expected.build.zon");
/// The project's lock, which neither import nor build may change. Written beside the project.
const m9_project_lock = @embedFile("vm/m9_project/zbx.lock");
const m9_project = "m9-project";
/// m9.5's project: a base of this machine's platform (linux/arm64), locked by `zbx pull` into an
/// empty lock of its own, and a step that records the architecture it ran on.
const m9_native = "m9-native";
const m9_native_dockerfile = "FROM alpine:3.20\nRUN uname -m > /arch\n";
const empty_lock = ".{\n    .version = 1,\n    .images = .{},\n}\n";
/// The golden digest's image tree as `m9_tree_list` prints it inside a container of that tree
/// (path, mode, owner, type, and a regular file's SHA-256 prefix or a link's target): tree
/// b3:4ee34d3f7f35640ee5f63d31f04592c4fb240287db222b8bea780945536f9ae8, recorded rootless on
/// x86_64 Linux from a `zbx build` of the demo project that printed the golden digest. The
/// listing is a function of the tree alone. When the Mac's digest is not the golden, m9.4 prints
/// how its tree differs from this one, so the failure names the files, not only the digest.
const m9_golden_tree = @embedFile("vm/m9_expected.tree.txt");
/// Lists the tree a container runs on, one line a path, sorted: fed to `sh` on stdin. What the
/// runtime mounts (`/proc`, `/sys`, `/dev`, and the host and name files it writes) is left out,
/// and so is a directory's size, which is the file system's.
const m9_tree_list =
    \\find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /etc/hosts \
    \\  -o -path /etc/hostname -o -path /etc/resolv.conf \) -prune -o -print | sort |
    \\while IFS= read -r f; do
    \\  if [ -L "$f" ]; then x="-> $(readlink "$f")"
    \\  elif [ -f "$f" ]; then x="$(sha256sum "$f" | cut -c1-16)"
    \\  else x=-; fi
    \\  echo "$f $(stat -c '%a %u:%g %F' "$f") $x"
    \\done
    \\
;
/// The one-line reason the Rosetta steps fail on a Mac without it.
const rosetta_missing = "ZBX-E1016: Rosetta is not installed, and the M9 project's lock pins " ++
    "linux/amd64; install it with softwareupdate --install-rosetta --agree-to-license, " ++
    "then zbx vm stop";
/// What `zbx doctor` says on its `rosetta` line when Rosetta is installed (`check_rosetta`).
const rosetta_installed = "rosetta  installed: linux/amd64 images can run";

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

/// A `sed` that prints the digest of `zbx build`'s `built b3:... (...)` line.
const digest_of_build = "sed -n 's/^built \\(b3:[0-9a-f]*\\) .*/\\1/p'";

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
            "do i=$((i+1)); test $i -lt 90 || exit 9; sleep 1; done && " ++
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
    // ---- M9: the demo project imported from its Dockerfile and built (docs/demos/m9.md) ---------
    // `$W/m9-project` is written afresh by `prepare_m9_project`; `$W/m9.digest` carries step 2's
    // digest to the steps after it. Steps m9.1 to m9.4 need Rosetta (`needs_rosetta`).
    .{
        .id = "m9.1",
        .what = "import writes demo-m9's golden build file, owned by the Mac user, with W0811",
        .line = "cd $W/m9-project && $Z import && cmp zbx.lock ../m9_expected.lock && " ++
            "cmp zbx.build.zon ../m9_expected.build.zon && " ++
            "test \"$(stat -f %u zbx.build.zon)\" = \"$(id -u)\" && echo imported",
        .stdout_has = &.{"imported"},
        .stderr_has = &.{"ZBX-W0811"},
    },
    .{
        .id = "m9.2",
        .what = "build prints the digest, keeps the lock; the image greets, --whoami is 10001",
        .line = "cd $W/m9-project && rm -f ../m9.digest && o=$($Z build) && " ++
            "cmp zbx.lock ../m9_expected.lock && " ++
            "d=$(echo \"$o\" | " ++ digest_of_build ++ ") && test -n \"$d\" && " ++
            "echo \"$d\" > ../m9.digest && $Z run $d && " ++
            "w=$($Z run $d -- /usr/local/bin/hello --whoami) && test \"$w\" = 10001 && " ++
            "echo whoami-10001",
        .stdout_has = &.{ "hello from zigbox", "whoami-10001" },
    },
    .{
        .id = "m9.3",
        .what = "a new extra.go misses and changes the digest; removed, all hits, the first digest",
        // The Mac's store outlives a run, so extra.go is new each run (its time and the
        // shell's pid in a comment): an extra.go a run before built would be all hits.
        .line = "cd $W/m9-project && sed 's/func main/func init/' main.go > extra.go && " ++
            "echo \"// $(date +%s)-$$\" >> extra.go && " ++
            "o=$($Z build) && d=$(echo \"$o\" | " ++ digest_of_build ++ ") && " ++
            "test -n \"$d\" && test \"$d\" != \"$(cat ../m9.digest)\" && " ++
            "echo \"$o\" | grep -q ', [1-9][0-9]* miss' && echo new-digest && " ++
            "rm extra.go && o=$($Z build) && echo \"$o\" && " ++
            "test \"$(echo \"$o\" | " ++ digest_of_build ++ ")\" = \"$(cat ../m9.digest)\" && " ++
            "echo same-digest",
        .stdout_has = &.{ "new-digest", " 0 misses", "same-digest" },
    },
    .{
        .id = "m9.4",
        .what = "the digest is demo-m9's golden, recorded in a Linux VM (m9_expected.zon)",
        // A digest that is not the golden prints, after it, the lines of the tree listing that
        // differ from the golden tree's (`<` the golden's, `>` the Mac's) and what `inspect` says.
        .line = "d=$(cat $W/m9.digest) && echo \"$d\" && " ++
            "if test \"$d\" != \"" ++ m9_golden.digest ++ "\"; then " ++
            "t=$($Z inspect \"$d\" | awk '/^tree/ {print $2}') && " ++
            "$Z run \"$t\" -- sh < $W/m9-tree-list.sh > $W/m9.tree.txt; " ++
            "diff $W/m9_expected.tree.txt $W/m9.tree.txt | grep '^[<>]'; " ++
            "$Z inspect \"$d\" | grep -v '^result'; fi",
        .stdout_has = &.{m9_golden.digest},
    },
    .{
        .id = "m9.5",
        .what = "a project locked to linux/arm64 builds natively, and its step ran on aarch64",
        .line = "cd $W/m9-native && $Z pull alpine:3.20 >/dev/null && " ++
            "grep -q '\"linux/arm64\"' zbx.lock && ! grep -q 'linux/amd64' zbx.lock && " ++
            "$Z import && o=$($Z build) && d=$(echo \"$o\" | " ++ digest_of_build ++ ") && " ++
            "test -n \"$d\" && $Z run $d -- cat /arch",
        .stdout_has = &.{"aarch64"},
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
    try prepare_m9_project(init, work);
    const rosetta = try rosetta_ready(init, zbx_path);
    var failures: u32 = 0;
    for (steps) |step| {
        if (needs_rosetta(step) and !rosetta) {
            failures += 1;
            try out.print("FAIL {s}  {s}\n     {s}\n", .{ step.id, step.what, rosetta_missing });
            try out.flush();
            continue;
        }
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

/// The end of a failing step's stream: enough for m9.4's differing lines and `inspect` after them.
fn clip(text: []const u8) []const u8 {
    const kept = 2400;
    return if (text.len > kept) text[text.len - kept ..] else text;
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
    try dir.deleteTree(io, rootfs); // A rootfs that is not there is no error.
    try dir.createDirPath(io, rootfs);
    const unpack = try std.process.run(arena, io, .{
        .argv = &.{ "/usr/bin/tar", "-xzf", archive, "-C", rootfs },
    });
    if (unpack.term != .exited or unpack.term.exited != 0) return error.UnpackFailed;
}

/// Writes M9's projects afresh under `work` (steps edit them, and import writes into them), and
/// the golden build file and lock beside the first, for `cmp`.
fn prepare_m9_project(init: std.process.Init, work: []const u8) !void {
    const io = init.io;
    const arena = init.arena.allocator();
    var dir = try Io.Dir.cwd().openDir(io, work, .{});
    defer dir.close(io);
    try dir.deleteTree(io, m9_project); // A project that is not there is no error.
    try dir.createDirPath(io, m9_project);
    for (m9_project_files) |file| {
        const path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ m9_project, file.name });
        try dir.writeFile(io, .{ .sub_path = path, .data = file.text });
    }
    try dir.writeFile(io, .{ .sub_path = "m9_expected.build.zon", .data = m9_golden_build });
    try dir.writeFile(io, .{ .sub_path = "m9_expected.lock", .data = m9_project_lock });
    try dir.writeFile(io, .{ .sub_path = "m9_expected.tree.txt", .data = m9_golden_tree });
    try dir.writeFile(io, .{ .sub_path = "m9-tree-list.sh", .data = m9_tree_list });
    // The native project holds its own lock, so that a zbx.lock higher up (the work
    // directory's, which M4's pull wrote) is not it.
    try dir.deleteTree(io, m9_native);
    try dir.createDirPath(io, m9_native);
    const dockerfile = m9_native ++ "/Dockerfile";
    try dir.writeFile(io, .{ .sub_path = dockerfile, .data = m9_native_dockerfile });
    try dir.writeFile(io, .{ .sub_path = m9_native ++ "/zbx.lock", .data = empty_lock });
}

/// True if `zbx doctor` says Rosetta is installed. Steps m9.1 to m9.4 need it.
fn rosetta_ready(init: std.process.Init, zbx: []const u8) !bool {
    const result = try std.process.run(init.arena.allocator(), init.io, .{
        .argv = &.{ zbx, "doctor" },
    });
    return std.mem.indexOf(u8, result.stdout, rosetta_installed) != null;
}

/// True for the steps that build the M9 project, whose lock pins linux/amd64.
fn needs_rosetta(step: Step) bool {
    return std.mem.startsWith(u8, step.id, "m9.") and !std.mem.eql(u8, step.id, "m9.5");
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

test "the M9 project is demo-m9's, file for file" {
    // Goal: the Mac builds the same project as `demo-m9`, so its digest can be that golden.
    // Method: both lists embed the same files, so their bytes agree by construction; what this
    // checks is that the two lists name the same files in the same order, so a file added to
    // `demo-m9`'s project and not here (or the other way) fails. `hello_m9` is the Linux
    // harness, so the comparison is compiled on Linux only.
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const hello_m9 = @import("vm/hello_m9.zig");
    try std.testing.expectEqual(hello_m9.project_files.len, m9_project_files.len);
    for (hello_m9.project_files, m9_project_files) |linux, mac| {
        try std.testing.expectEqualStrings(linux.name, mac.name);
        try std.testing.expectEqualStrings(linux.text, mac.text);
    }
    try std.testing.expectEqualStrings(hello_m9.golden_build, m9_golden_build);
    for (steps) |step| {
        if (!std.mem.startsWith(u8, step.id, "m9.")) continue;
        try std.testing.expect(std.mem.indexOf(u8, step.line, "$W") != null);
    }
}

test "the Rosetta steps are m9.1 to m9.4, and m9.5 is native" {
    // Goal: a Mac without Rosetta fails the amd64 steps with one line naming E1016 and still
    // runs the native one. Method: the steps' ids against `needs_rosetta`.
    var count: u32 = 0;
    for (steps) |step| {
        if (needs_rosetta(step)) count += 1;
    }
    try std.testing.expectEqual(@as(u32, 4), count);
    for (steps) |step| {
        if (!std.mem.eql(u8, step.id, "m9.5")) continue;
        try std.testing.expect(!needs_rosetta(step));
        try std.testing.expect(std.mem.indexOf(u8, step.line, "$W/" ++ m9_native) != null);
    }
    try std.testing.expect(std.mem.indexOf(u8, rosetta_missing, "ZBX-E1016") != null);
    try std.testing.expect(std.mem.indexOf(u8, rosetta_missing, "softwareupdate") != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, rosetta_missing, '\n') == null);
}

test "m9.4 compares the Mac's tree with the golden tree's listing" {
    // Goal: a failing m9.4 names the files that differ. Method: the line lists the tree with the
    // script `prepare_m9_project` writes and diffs it with the golden listing it writes; that
    // listing holds what the final stage made, and none of what the runtime mounts in a run.
    for (steps) |step| {
        if (!std.mem.eql(u8, step.id, "m9.4")) continue;
        try std.testing.expect(std.mem.indexOf(u8, step.line, "$W/m9-tree-list.sh") != null);
        try std.testing.expect(std.mem.indexOf(u8, step.line, "$W/m9_expected.tree.txt") != null);
        try std.testing.expect(std.mem.indexOf(u8, step.line, m9_golden.digest) != null);
    }
    const made = [_][]const u8{
        "/usr/local/bin/hello 755 0:0 regular file ",
        "/home/app 755 10001:10001 directory -\n",
        "/etc/hello/VERSION 644 10001:10001 regular file ",
        "/etc/shadow 640 0:42 regular file ",
    };
    for (made) |line| try std.testing.expect(std.mem.indexOf(u8, m9_golden_tree, line) != null);
    const mounted = [_][]const u8{
        "\n/proc", "\n/sys", "\n/dev", "\n/etc/hosts ", "\n/etc/hostname ", "\n/etc/resolv.conf ",
    };
    for (mounted) |path| try std.testing.expect(std.mem.indexOf(u8, m9_golden_tree, path) == null);
    try std.testing.expect(std.mem.endsWith(u8, m9_golden_tree, "\n"));
}
