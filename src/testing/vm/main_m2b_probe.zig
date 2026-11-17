//! The M2b probe (docs/briefs/M2b-workload-knobs.md, slice 1), run in the M0 harness's Ubuntu
//! 24.04 VM. It measures what slice 1 must record before any code, and later shows the slice's
//! knobs by hand:
//!   1. NUMA: `strace` over the start of `mariadbd --innodb-numa-interleave=1`,
//!      `numactl --interleave=all mongod` and `clickhouse server`, on the VM host, outside zbx:
//!      which of the six memory-policy calls each makes.
//!   2. Sysctls: each candidate key of `sysctls.zon`, written by the ordinary user inside a fresh
//!      user, network and IPC namespace, read back there, and the host's value checked unchanged;
//!      then what `pasta`, attached to such a namespace after the writes, changes.
//!   3. Runtimes: Java 21, Go 1.25, .NET 8 and Node under the installed `zbx run --memory 256m
//!      --cpus 1`, with the default network, `--net host` and `--net user`: what each sizes
//!      itself to, and which cgroup files it opens. Slice 2 runs only this part, as the after
//!      of slice 1's table (which ran `--cpus 1.5` with parts 1, 2 and 4 too).
//!   4. The slice's knobs by hand (`--ulimit`, `--shm-size`, `--sysctl`, NUMA), as the brief's
//!      demo steps 1, 2, 3 and 6 run them. Under a binary without the knobs, the flags are
//!      refused; that output is the "before".
//! Every line the guest prints starts with `probe:`. The probe judges whether its scripts ran,
//! whether each `zbx run` of part 3 succeeded, and that the view is the container's own
//! (`0::/`) and read-only; the rest is evidence for docs/decisions/, read by a person.
//! Throwaway: the demo is slice 3's `demo-m2b`. `zig build demo-m2b-probe` (KVM) or `-Daccel=tcg`.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;
const alpine = @import("alpine.zon");
const harness = @import("harness.zig");
const image = @import("image.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");

const Session = session_mod.Session;
const H = harness;

/// The probe's longest part: apt, the 500 MiB ClickHouse binary, and `apk add` of the runtimes.
const part_timeout_s: u32 = 1200;
/// What each part gives itself, in seconds: less than `part_timeout_s`, so a part that hangs
/// is stopped in the guest and its output up to then still reaches the log.
const part_inner_timeout = "1100";
comptime {
    std.debug.assert(std.fmt.parseInt(u32, part_inner_timeout, 10) catch 0 > 0);
    std.debug.assert((std.fmt.parseInt(u32, part_inner_timeout, 10) catch 0) + 60 <
        part_timeout_s);
}

pub fn main(init: std.process.Init) !u8 {
    harness.demo_name = "demo-m2b-probe";
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const options = H.parse_options(init) catch |err| {
        try out.print("demo-m2b-probe: bad arguments ({s})\n", .{@errorName(err)});
        return 2;
    };
    const started = session_mod.now_ms();
    demo(init, out, options) catch |err| {
        if (err == error.NoKvm) return 1;
        try out.print("\ndemo-m2b-probe: FAILED ({s})\n", .{@errorName(err)});
        return 1;
    };
    const elapsed_s = @divFloor(session_mod.now_ms() - started, 1000);
    try out.print("\ndemo-m2b-probe: PASSED in {d} s\n", .{elapsed_s});
    return 0;
}

fn demo(init: std.process.Init, out: *Io.Writer, options: H.Options) !void {
    const io = init.io;
    const accel = harness.choose_accel(options.accel, H.kvm_usable(io)) catch |err| switch (err) {
        error.NoKvm => {
            try out.print("demo-m2b-probe: /dev/kvm is not usable here; add -Daccel=tcg\n", .{});
            return error.NoKvm;
        },
        error.BadAccel => return error.BadAccel,
    };
    const binary = try H.check_binaries(init, out, options);
    const arena = init.arena.allocator();
    const rootfs_path = try image.ensure_pin(init, options.cache_dir, out, .{
        .url = alpine.url,
        .sha256 = alpine.sha256,
        .file_name = alpine.file_name,
    });
    const limit: Io.Limit = .limited(limits.http_body_bytes_max);
    const rootfs = try Io.Dir.cwd().readFileAlloc(io, rootfs_path, arena, limit);
    const base = try image.ensure(init, options.cache_dir, out);
    const format = "{s}/overlay-demo-m2b-probe.qcow2";
    const overlay = try std.fmt.allocPrint(arena, format, .{options.cache_dir});
    if (!options.reuse_overlay) try image.make_overlay(init, base, overlay);
    defer if (!options.keep_overlay) Io.Dir.cwd().deleteFile(io, overlay) catch {};

    var session: Session = undefined;
    const extra = [_]@import("zigbox_vm").Route{
        .{ .path = "/m2b/numa.sh", .body = numa_script },
        .{ .path = "/m2b/sysctl.sh", .body = sysctl_script },
        .{ .path = "/m2b/runtimes.sh", .body = runtimes_with_measure },
    };
    // The seed routes, the binary and the rootfs share `http_routes_max` with these.
    const vm_limits = @import("zigbox_vm").limits;
    comptime assert(vm_limits.seed_routes + 2 + extra.len <= vm_limits.http_routes_max);
    try session_mod.start(&session, init, out, overlay, accel, .{
        .binary = binary,
        .rootfs = rootfs,
        .extra = &extra,
    });
    defer session.deinit();
    var timer = H.Timer.start();
    try H.provision(&session, out, &timer, options.reuse_overlay);
    try H.install_binary(&session, out, &timer);
    try fetch_scripts(&session, out);
    // Every part measures something of its own, so a failed part does not skip the rest.
    var failed: u32 = 0;
    inline for (parts) |p| failed += try part(&session, out, &timer, p[0], p[1]);
    assert(failed <= parts_count);
    try session.shutdown();
    if (failed > 0) return error.PartFailed;
}

fn fetch_scripts(session: *Session, out: *Io.Writer) !void {
    const names = [_][]const u8{ "numa", "sysctl", "runtimes" };
    for (names) |name| {
        const command = try std.fmt.allocPrint(
            session.scratch_allocator(),
            "mkdir -p /tmp/m2b && curl -fsS -o /tmp/m2b/{s}.sh " ++
                "http://10.0.2.2:{d}/m2b/{s}.sh && chmod 755 /tmp/m2b/{s}.sh && " ++
                "curl -fsS -o /tmp/rootfs.tar.gz http://10.0.2.2:{d}/rootfs.tar.gz",
            .{ name, session.server.port, name, name, session.server.port },
        );
        assert(command.len < limits.command_bytes_max);
        const result = try session.run(command, limits.command_timeout_kvm_s);
        if (result.status != 0) {
            try H.show(out, "fetch the probe scripts", result);
            return error.FetchFailed;
        }
    }
}

/// Runs one part and prints what it said; returns 1 when it exited non-zero, 0 otherwise. A
/// failed part fails the probe at the end: its output is then incomplete evidence.
fn part(
    session: *Session,
    out: *Io.Writer,
    timer: *H.Timer,
    comptime name: []const u8,
    comptime command: []const u8,
) !u32 {
    comptime assert(command.len < limits.command_bytes_max);
    // The harness shows output only once a command exits, so the part stops itself first.
    const bounded = "timeout -k 20 " ++ part_inner_timeout ++ " " ++ command ++ " </dev/null";
    const result = try session.run(bounded ++ " 2>&1", part_timeout_s);
    try H.show(out, name, result);
    try timer.lap(out, name);
    if (result.status == 0) return 0;
    try out.print("demo-m2b-probe: part \"{s}\" exited {d}\n", .{ name, result.status });
    return 1;
}

/// Slice 2 runs only the runtime parts again, the after of slice 1's table (the NUMA and sysctl
/// measurements stand as recorded), and adds `--net user`, so all three network modes are seen.
const parts = [_][2][]const u8{
    .{ "runtimes: provisioning", "sh /tmp/m2b/runtimes.sh setup" },
    .{ "runtimes: default network", "sh /tmp/m2b/runtimes.sh none" },
    .{ "runtimes: --net host", "sh /tmp/m2b/runtimes.sh host" },
    .{ "runtimes: --net user", "sh /tmp/m2b/runtimes.sh user" },
};
const parts_count: u32 = parts.len;

/// Part 1, as root on the VM host: the memory-policy calls three NUMA-aware servers make while
/// they start. Each server runs for a fixed time under `strace -f` and is then stopped.
const numa_script =
    \\set -u
    \\T=mbind,set_mempolicy,set_mempolicy_home_node,get_mempolicy,move_pages,migrate_pages
    \\export DEBIAN_FRONTEND=noninteractive
    \\echo "probe: kernel: $(uname -r)"
    \\echo "probe: [$(date +%T)] apt"
    \\apt-get update -qq >/tmp/apt.log 2>&1
    \\apt-get install -y -qq strace numactl mariadb-server >>/tmp/apt.log 2>&1 ||
    \\  { tail -5 /tmp/apt.log | sed 's/^/probe: apt: /'; }
    \\systemctl stop mariadb >/dev/null 2>&1
    \\echo "probe: numactl --hardware: $(numactl --hardware | head -2 | tr '\n' ';')"
    \\summary() {
    \\  echo "probe: $1: calls (count name): $(sed -E 's/^[0-9]+ +//' $2 |
    \\    grep -oE '^(<\.\.\. )?[a-z_]+' | sed 's/^<\.\.\. //' | sort | uniq -c | tr -s ' \n' ' ')"
    \\  sed -E 's/^[0-9]+ +//' $2 | grep -v '^+++\|^---' | sort | uniq -c | sort -rn | head -8 |
    \\    sed "s/^/probe: $1: /"
    \\}
    \\echo "probe: mariadbd: $(mariadbd --version 2>&1)"
    \\rm -rf /tmp/mdb && mkdir -p /tmp/mdb
    \\mariadb-install-db --no-defaults --datadir=/tmp/mdb --user=root >/tmp/mdbi.log 2>&1 ||
    \\  tail -3 /tmp/mdbi.log | sed 's/^/probe: mariadb-install-db: /'
    \\echo "probe: [$(date +%T)] mariadbd"
    \\strace -f -qq -o /tmp/mariadb.trace -e trace=$T timeout -k 5 30 mariadbd --no-defaults \
    \\  --datadir=/tmp/mdb --user=root --skip-networking --socket=/tmp/mdb.sock \
    \\  --innodb-numa-interleave=1 >/tmp/mariadbd.log 2>&1
    \\grep -iE 'numa|interleave|error' /tmp/mariadbd.log | head -5 |
    \\  sed 's/^/probe: mariadbd log: /'
    \\summary mariadbd /tmp/mariadb.trace
    \\M=https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-ubuntu2404-8.0.12.tgz
    \\echo "probe: [$(date +%T)] mongod download"
    \\curl -fsSL --max-time 300 -o /tmp/mongo.tgz $M && tar -xzf /tmp/mongo.tgz -C /tmp &&
    \\  ln -sf /tmp/mongodb-linux-*/bin/mongod /tmp/mongod || echo "probe: mongod: download FAILED"
    \\echo "probe: mongod: $(/tmp/mongod --version 2>&1 | head -1)"
    \\strace -f -qq -o /tmp/mongov.trace -e trace=$T \
    \\  numactl --interleave=all /tmp/mongod --version \
    \\  >/dev/null 2>&1
    \\summary "numactl --interleave=all mongod --version" /tmp/mongov.trace
    \\rm -rf /tmp/mongodata && mkdir -p /tmp/mongodata
    \\echo "probe: [$(date +%T)] mongod"
    \\strace -f -qq -o /tmp/mongod.trace -e trace=$T timeout -k 5 30 numactl --interleave=all \
    \\  /tmp/mongod --dbpath /tmp/mongodata --port 27999 --bind_ip 127.0.0.1 >/tmp/mongod.log 2>&1
    \\grep -io 'numa[^"]*' /tmp/mongod.log | head -3 | sed 's/^/probe: mongod log: /'
    \\summary "numactl --interleave=all mongod (30 s)" /tmp/mongod.trace
    \\C=https://builds.clickhouse.com/master/amd64/clickhouse
    \\echo "probe: [$(date +%T)] clickhouse download"
    \\curl -fsSL --max-time 400 -o /tmp/clickhouse $C && chmod 755 /tmp/clickhouse ||
    \\  echo "probe: clickhouse: download FAILED"
    \\echo "probe: clickhouse: $(/tmp/clickhouse local --version 2>&1 | head -1)"
    \\rm -rf /tmp/ch && mkdir -p /tmp/ch && cd /tmp/ch
    \\echo "probe: [$(date +%T)] clickhouse"
    \\strace -f -qq -o /tmp/ch.trace -e trace=$T timeout -k 5 40 /tmp/clickhouse server -- \
    \\  --path=/tmp/ch/ --tcp_port=19000 --http_port=18123 >/tmp/ch.log 2>&1
    \\grep -i 'numa' /tmp/ch.log | head -3 | sed 's/^/probe: clickhouse log: /'
    \\summary "clickhouse server (40 s)" /tmp/ch.trace
    \\rm -f /tmp/clickhouse /tmp/mongo.tgz; rm -rf /tmp/ch /tmp/mongodata /tmp/mdb
    \\echo "probe: [$(date +%T)] numa: done"
    \\
;

/// Part 2, as the ordinary user: each candidate key with the namespace it should belong to and a
/// value that differs from Ubuntu 24.04's default, so that "unchanged on the host" means
/// something. The script re-runs itself inside the namespaces (`inner`), and once more under a
/// network namespace that `pasta` then attaches to (`pasta`).
const sysctl_script =
    \\set -u
    \\K="ipc kernel.shmmax 1073741824
    \\ipc kernel.shmall 1048576
    \\ipc kernel.shmmni 8192
    \\ipc kernel.shm_rmid_forced 1
    \\ipc kernel.msgmax 16384
    \\ipc kernel.msgmnb 32768
    \\ipc kernel.msgmni 16000
    \\ipc kernel.sem 250 32000 32 128
    \\ipc fs.mqueue.msg_max 20
    \\ipc fs.mqueue.msgsize_max 16384
    \\ipc fs.mqueue.queues_max 512
    \\ipc fs.mqueue.msg_default 5
    \\ipc fs.mqueue.msgsize_default 4096
    \\net net.ipv4.ip_local_port_range 40000 50000
    \\net net.ipv4.ip_local_reserved_ports 8080
    \\net net.ipv4.ip_unprivileged_port_start 80
    \\net net.ipv4.ping_group_range 0 0
    \\net net.ipv4.tcp_syncookies 0
    \\net net.ipv4.tcp_keepalive_time 600
    \\net net.ipv4.tcp_keepalive_intvl 30
    \\net net.ipv4.tcp_keepalive_probes 5
    \\net net.ipv4.tcp_fin_timeout 30
    \\net net.ipv4.tcp_rmem 4096 87380 6291456
    \\net net.ipv4.tcp_wmem 4096 65536 4194304
    \\net net.core.somaxconn 8192
    \\net net.ipv4.tcp_max_syn_backlog 3000
    \\net net.ipv4.tcp_tw_reuse 1
    \\net net.ipv6.conf.all.disable_ipv6 1"
    \\p() { echo "/proc/sys/$(echo $1 | tr . /)"; }
    \\norm() { tr -s ' \t' '  ' < "$1" 2>&1; }
    \\if [ "${1:-}" = inner ]; then
    \\  echo "$K" | while read ns key value; do
    \\    f=$(p $key); before=$(norm $f)
    \\    if err=$(echo "$value" 2>&1 > $f); then w=ok; else w="FAIL $err"; fi
    \\    after=$(norm $f)
    \\    [ "$after" = "$value" ] && r=ok || r="FAIL read $after"
    \\    echo "probe: $ns $key: in ns: before '$before' write $w, read back $r"
    \\  done; exit 0
    \\fi
    \\if [ "${1:-}" = pasta ]; then
    \\  echo "$K" | grep '^net' | while read ns key value; do echo "$value" > $(p $key); done
    \\  sleep 6
    \\  echo "$K" | grep '^net' | while read ns key value; do
    \\    now=$(norm $(p $key)); [ "$now" = "$value" ] && r=kept || r="CHANGED to '$now'"
    \\    echo "probe: pasta: $key: $r"
    \\  done
    \\  ip -o addr | sed 's/^/probe: pasta: /'
    \\  exit 0
    \\fi
    \\echo "probe: user: $(id -un), kernel $(uname -r)"
    \\echo "$K" | while read ns key value; do echo "$key $(norm $(p $key))"; done > /tmp/host1.txt
    \\unshare --user --map-root-user --net --ipc sh "$0" inner
    \\echo "$K" | while read ns key value; do echo "$key $(norm $(p $key))"; done > /tmp/host2.txt
    \\cmp -s /tmp/host1.txt /tmp/host2.txt && echo "probe: host values unchanged: ok" ||
    \\  { echo "probe: host values CHANGED:"; diff /tmp/host1.txt /tmp/host2.txt; }
    \\sed 's/^/probe: host value: /' /tmp/host1.txt
    \\echo "probe: pasta: $(command -v pasta) $(pasta --version 2>&1 | head -1)"
    \\unshare --user --map-root-user --net sh "$0" pasta &
    \\P=$!; sleep 2
    \\pasta --config-net --quiet --no-map-gw --tcp-ns none --udp-ns none $P ||
    \\  echo "probe: pasta: attach FAILED"
    \\wait $P
    \\echo "probe: sysctl: done"
    \\
;

/// Part 3, as root, driving `zbx` as the demo user: `setup` makes a rootfs with the runtimes
/// (the Alpine packages, Go 1.25 from go.dev because Alpine 3.20 has 1.22, and a .NET program
/// published inside a run); `none` and `host` measure under the two network modes.
const runtimes_script =
    \\set -u
    \\Z="runuser -u demo -- env HOME=/home/demo XDG_RUNTIME_DIR=/run/user/1000 \
    \\DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus /home/demo/zbx"
    \\R=/home/demo/alpine-rt
    \\A=http://dl-cdn.alpinelinux.org/alpine/v3.20
    \\if [ "$1" = setup ]; then
    \\  echo "probe: zbx: $($Z --version 2>&1 | head -1)"
    \\  runuser -u demo -- sh -c "rm -rf $R && mkdir -p $R && tar -xzf /tmp/rootfs.tar.gz -C $R"
    \\  printf '%s/main\n%s/community\n' $A $A > $R/etc/apk/repositories
    \\  mkdir -p $R/m2b && cp /tmp/m2b/measure.sh $R/m2b/ && chown -R demo:demo $R/m2b
    \\  $Z run --net host --rootfs $R -- apk add --no-cache -q openjdk21-jre-headless nodejs \
    \\    dotnet8-sdk strace numactl-tools 2>&1 | tail -3 | sed 's/^/probe: apk: /'
    \\  curl -fsSL --max-time 300 -o /tmp/go.tgz https://go.dev/dl/go1.25.0.linux-amd64.tar.gz &&
    \\    tar -C /tmp -xzf /tmp/go.tgz || echo "probe: go: download FAILED"
    \\  mkdir -p /tmp/gp && cd /tmp/gp && printf '%s\n' 'package main' \
    \\    'import ("fmt"; "runtime"; "runtime/debug")' \
    \\    'func main() { fmt.Println("GOMAXPROCS", runtime.GOMAXPROCS(0), "NumCPU",' \
    \\    '  runtime.NumCPU(), "GOMEMLIMIT", debug.SetMemoryLimit(-1)) }' > main.go
    \\  HOME=/root GOPATH=/tmp/gopath GOCACHE=/tmp/gocache \
    \\    /tmp/go/bin/go mod init gp >/dev/null 2>&1
    \\  CGO_ENABLED=0 HOME=/root GOPATH=/tmp/gopath GOCACHE=/tmp/gocache \
    \\    /tmp/go/bin/go build -o $R/m2b/gomaxprocs . 2>&1 | sed 's/^/probe: go build: /'
    \\  chown demo:demo $R/m2b/gomaxprocs
    \\  printf '%s\n' 'System.GC.Collect();' 'var i = System.GC.GetGCMemoryInfo();' \
    \\    'System.Console.WriteLine($"TotalAvailableMemoryBytes {i.TotalAvailableMemoryBytes}");' \
    \\    'System.Console.WriteLine($"ProcessorCount {System.Environment.ProcessorCount}");' \
    \\    > $R/m2b/Program.cs
    \\  chown demo:demo $R/m2b/Program.cs
    \\  $Z run --net host --rootfs $R -e HOME=/tmp -e DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    \\    -e DOTNET_NOLOGO=1 -- sh -c 'dotnet new console -o /app/src -n probe >/dev/null &&
    \\    cp /m2b/Program.cs /app/src/Program.cs && dotnet publish /app/src -c Release -o /app/out \
    \\    2>&1 | tail -2' 2>&1 | sed 's/^/probe: dotnet publish: /'
    \\  ls $R/app/out/probe.dll >/dev/null 2>&1 || echo "probe: dotnet: publish FAILED"
    \\  echo "probe: setup: done"; exit 0
    \\fi
    \\N=""; [ "$1" = host ] && N="--net host"; [ "$1" = user ] && N="--net user"
    \\F=0
    \\for rt in view java go dotnet node; do
    \\  echo "probe: [$1] $rt:"
    \\  o=$($Z run $N --rootfs $R --memory 256m --cpus 1 -e HOME=/tmp -e DOTNET_NOLOGO=1 \
    \\    -- sh /m2b/measure.sh $rt 2>&1); s=$?
    \\  echo "$o" | head -45 | sed "s/^/probe: [$1] $rt: /"
    \\  [ $s -eq 0 ] || { echo "probe: [$1] $rt: FAILED, the run exited $s"; F=1; }
    \\done
    \\echo "probe: runtimes $1: done"; exit $F
    \\
;

/// Part 3's half inside the container: what one runtime reports, then the cgroup files it opens.
/// The harness serves eight routes in all, three of them extra here, so `runtimes.sh` writes
/// `measure.sh` and `knobs.sh` itself from quoted here-documents before it does anything else.
const runtimes_with_measure = "cat > /tmp/m2b/measure.sh <<'M2B_MEASURE'\n" ++
    measure_script ++ "M2B_MEASURE\n" ++
    "cat > /tmp/m2b/knobs.sh <<'M2B_KNOBS'\n" ++ knobs_script ++ "M2B_KNOBS\n" ++
    runtimes_script;

const measure_script =
    \\set -u
    \\NODE='const os=require("os"),v8=require("v8");console.log("constrainedMemory",
    \\process.constrainedMemory(),"availableParallelism",os.availableParallelism(),
    \\"heap_size_limit",v8.getHeapStatistics().heap_size_limit)'
    \\case $1 in
    \\view) echo "/proc/self/cgroup: $(cat /proc/self/cgroup)"
    \\  grep -E ' - cgroup2? ' /proc/self/mountinfo || echo "mountinfo: no cgroup mount"
    \\  echo "/sys/fs/cgroup: $(ls /sys/fs/cgroup 2>&1 | head -8 | tr '\n' ' ')"
    \\  for f in memory.max cpu.max pids.max; do echo "$f: $(cat /sys/fs/cgroup/$f 2>&1)"; done
    \\  grep -qx '0::/' /proc/self/cgroup || { echo "view: FAILED, not 0::/"; exit 1; }
    \\  t=$(touch /sys/fs/cgroup/probe 2>&1); echo "touch: $t"
    \\  echo "$t" | grep -q 'Read-only file system' || { echo "view: FAILED, writable"; exit 1; }
    \\  exit 0 ;;
    \\java) java -XshowSettings:system -version 2>&1 | head -20
    \\  java -XX:+PrintFlagsFinal -version 2>/dev/null |
    \\    grep -E ' (MaxHeapSize|ActiveProcessorCount|UseContainerSupport) '
    \\  set -- java -version ;;
    \\go) /m2b/gomaxprocs; set -- /m2b/gomaxprocs ;;
    \\dotnet) dotnet /app/out/probe.dll; set -- dotnet /app/out/probe.dll ;;
    \\node) node -e "$NODE"; set -- node -e "$NODE" ;;
    \\esac
    \\strace -f -qq -e trace=openat,open,statfs,readlinkat -o /tmp/trace "$@" >/dev/null 2>&1
    \\echo "files: $(wc -l < /tmp/trace) calls traced; the cgroup ones:"
    \\sed -E 's/^[0-9]+ +//' /tmp/trace | grep -E 'cgroup|mountinfo|memory\.|cpu\.max|cpuset' |
    \\  cut -c1-150 | sort | uniq -c | head -20
    \\
;

/// Part 4: the brief's demo steps 1, 2, 3 and 6, typed by hand. Nothing here is judged.
const knobs_script =
    \\set -u
    \\Z="runuser -u demo -- env HOME=/home/demo XDG_RUNTIME_DIR=/run/user/1000 \
    \\DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus /home/demo/zbx"
    \\R=/home/demo/alpine-rt
    \\show() { echo "probe: \$ zbx $*"; o=$($Z "$@" 2>&1); s=$?
    \\  echo "$o" | head -8 | sed 's/^/probe:   /'; echo "probe:   (exit $s)"; }
    \\H=$(runuser -u demo -- sh -c 'ulimit -Hn')
    \\echo "probe: demo's limits: nofile $H/$(runuser -u demo -- sh -c 'ulimit -n')," \
    \\  "nproc $(runuser -u demo -- sh -c 'ulimit -Hu'), memlock" \
    \\  "$(runuser -u demo -- sh -c 'ulimit -Hl') KiB," \
    \\  "stack $(runuser -u demo -- sh -c 'ulimit -Hs')"
    \\show run --rootfs $R -- sh -c 'cat /proc/self/limits'
    \\show run --rootfs $R --ulimit nofile=4096:8192 -- sh -c 'ulimit -n; ulimit -Hn'
    \\show run --rootfs $R --ulimit nofile=$((H + 1)) -- true
    \\show run --rootfs $R --ulimit memlock=64m -- sh -c 'ulimit -l; ulimit -Hl'
    \\show run --rootfs $R --ulimit stack=16m:unlimited -- sh -c 'ulimit -s'
    \\show run --rootfs $R --ulimit core=1 -- true
    \\show run --rootfs $R -- df -k /dev/shm
    \\show run --rootfs $R --shm-size 256m -- df -k /dev/shm
    \\show run --rootfs $R --memory 128m --shm-size 256m -- true
    \\show run --rootfs $R --sysctl net.core.somaxconn=8192 -- cat /proc/sys/net/core/somaxconn
    \\show run --rootfs $R --sysctl kernel.shmmni=8192 --sysctl kernel.sem='250 32000 32 128' \
    \\  -- sh -c 'cat /proc/sys/kernel/shmmni /proc/sys/kernel/sem'
    \\show run --rootfs $R --net user --sysctl net.ipv4.tcp_keepalive_time=600 \
    \\  -- cat /proc/sys/net/ipv4/tcp_keepalive_time
    \\show run --rootfs $R --sysctl vm.max_map_count=262144 -- true
    \\show run --rootfs $R --net host --sysctl net.core.somaxconn=4096 -- true
    \\show run --rootfs $R --sysctl net.ipv4.tcp_syncookies=7 -- true
    \\show run --rootfs $R -- numactl --interleave=all true
    \\show run --rootfs $R -- numactl --membind=0 true
    \\show run --rootfs $R -- numactl --preferred=0 numactl --show
    \\echo "probe: knobs: done"
    \\
;
