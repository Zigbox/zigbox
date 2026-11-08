//! The packages check of M8 slice 7, run in four real guests: Ubuntu 24.04 and Debian 12 (apt),
//! Fedora and Rocky 9 (dnf). For each guest it serves the package trees that
//! `zig build packages -Dtest-key` wrote, installs `zigbox` from them with the guest's own
//! package manager, and runs `zbx --version` and `zbx doctor`. On the way it probes whether the
//! guest accepts the test key's Ed25519 signature on the repository metadata and on an rpm
//! (`apt-get update`, `dnf makecache`, `rpm -K`); the verdicts are the key-type evidence of
//! docs/decisions/2026-11-08-archive-key-type.md. It is not the milestone demo (slice 8): it
//! uses no `zbx` of its own, only what the packages contain.
//!
//! `zig build demo-m8-packages` (KVM) or with `-Daccel=tcg`; `--only ubuntu|debian|fedora|rocky`
//! runs one guest. The guest trusts the test key's public half and every check is signed: a refused
//! signature FAILS the check (never an unsigned retry, which would hide an unchecked signature),
//! and is recorded in the summary. A failing guest does not stop the others.

const std = @import("std");
const Io = std.Io;
const checks = @import("checks_m8_packages.zig");
const harness = @import("harness.zig");
const vm = @import("zigbox_vm");
const image = vm.image;

const H = harness;
const Session = vm.Session;
const Family = checks.Family;
const Verdict = checks.Verdict;

const demo_name = "demo-m8-packages";
const tar_route = "/repo.tar";
const repo_dir = "/srv/zigbox";
const repo_port = 8081;
const overlay_size = "12G";
const install_timeout_s: u32 = 240;
const guests_max = 4;
const tar_entries_max = 64;

const Guest = struct {
    name: []const u8,
    family: Family,
    pin: image.Pin,
    hostname: []const u8,
    /// Fedora and Rocky prompt differently from the module's default; see `Config.console_prompt`.
    console_prompt: bool,
    /// Ubuntu 24.04 restricts unprivileged user namespaces; the others do not.
    userns_sysctl: bool,
    /// Debian 12's cloud-init 22.4 needs `nocloud-net` (see `Seed.seed_id`).
    seed_id: []const u8 = "nocloud",
};

const guests = [guests_max]Guest{
    .{
        .name = "ubuntu",
        .family = .apt,
        .pin = image.ubuntu_noble,
        .hostname = "zigbox-ubuntu",
        .console_prompt = false,
        .userns_sysctl = true,
    },
    .{
        .name = "debian",
        .family = .apt,
        .pin = image.debian_12,
        .hostname = "zigbox-debian",
        .console_prompt = false,
        .userns_sysctl = false,
        .seed_id = "nocloud-net",
    },
    .{
        .name = "fedora",
        .family = .dnf,
        .pin = image.fedora_45,
        .hostname = "zigbox-fedora",
        .console_prompt = true,
        .userns_sysctl = false,
    },
    .{
        .name = "rocky",
        .family = .dnf,
        .pin = image.rocky_9,
        .hostname = "zigbox-rocky",
        .console_prompt = true,
        .userns_sysctl = false,
    },
};

const Args = struct {
    accel: []const u8 = "auto",
    cache_dir: []const u8 = ".zig-cache/zbx-vm",
    packages: []const u8 = "",
    version: []const u8 = "",
    only: []const u8 = "",
};

/// What one guest showed: the signature verdicts, whether the signed install worked, and whether
/// `zbx` then ran.
const Report = struct {
    guest: *const Guest,
    metadata: Verdict = .refused,
    package: Verdict = .refused,
    installed: bool = false,
    version_ok: bool = false,
    doctor_ran: bool = false,
    /// The harness error that stopped this guest before its checks finished, if any.
    stopped: ?anyerror = null,
};

pub fn main(init: std.process.Init) !u8 {
    harness.demo_name = demo_name;
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const args = parse_args(init) catch |err| {
        try out.print("{s}: bad arguments ({s})\n", .{ demo_name, @errorName(err) });
        return 2;
    };
    const started = vm.now_ms();
    const passed = run_all(init, out, args) catch |err| {
        if (err == error.NoKvm) {
            try out.print("{s}: /dev/kvm is not usable here; add -Daccel=tcg\n", .{demo_name});
            return 1;
        }
        try out.print("\n{s}: FAILED ({s})\n", .{ demo_name, @errorName(err) });
        return 1;
    };
    const seconds = (vm.now_ms() - started) / 1000;
    if (!passed) {
        try out.print("\n{s}: FAILED after {d} s\n", .{ demo_name, seconds });
        return 1;
    }
    try out.print("\n{s}: PASSED in {d} s\n", .{ demo_name, seconds });
    return 0;
}

fn parse_args(init: std.process.Init) !Args {
    var args: Args = .{};
    var iterator = init.minimal.args.iterate();
    _ = iterator.next();
    while (iterator.next()) |name| {
        const value = iterator.next() orelse return error.MissingValue;
        if (std.mem.eql(u8, name, "--accel")) {
            args.accel = value;
        } else if (std.mem.eql(u8, name, "--cache-dir")) {
            args.cache_dir = value;
        } else if (std.mem.eql(u8, name, "--packages")) {
            args.packages = value;
        } else if (std.mem.eql(u8, name, "--version")) {
            args.version = value;
        } else if (std.mem.eql(u8, name, "--only")) {
            args.only = value;
        } else {
            return error.UnknownArgument;
        }
    }
    if (args.packages.len == 0) return error.MissingPackages;
    if (args.version.len == 0) return error.MissingVersion;
    return args;
}

/// Runs every chosen guest and prints the table of verdicts. True when every guest accepted both
/// signatures, installed from the signed repository and ran `zbx` (`checks.guest_passed`).
fn run_all(init: std.process.Init, out: *Io.Writer, args: Args) !bool {
    const arena = init.arena.allocator();
    const tar = try pack_tree(init, arena, args.packages);
    var reports: [guests_max]Report = undefined;
    var count: usize = 0;
    for (&guests) |*guest| {
        if (args.only.len > 0 and !std.mem.eql(u8, args.only, guest.name)) continue;
        reports[count] = run_guest(init, out, args, guest, tar) catch |err| stopped: {
            try out.print("{s}: {s}: stopped: {s}\n", .{ demo_name, guest.name, @errorName(err) });
            break :stopped .{ .guest = guest, .stopped = err };
        };
        count += 1;
    }
    return try summarize(out, reports[0..count]);
}

fn summarize(out: *Io.Writer, reports: []const Report) !bool {
    std.debug.assert(reports.len <= guests_max);
    const title = "summary (metadata/package = the guest's verdict on Ed25519)";
    try out.print("\n{s}: {s}\n", .{ demo_name, title });
    var passed = reports.len > 0;
    for (reports) |report| {
        const ran = report.version_ok and report.doctor_ran;
        const good = checks.guest_passed(.{
            .metadata = report.metadata,
            .package = report.package,
            .installed = report.installed,
            .zbx_ran = ran,
        });
        try out.print("{s}:   {s: <7} metadata {s: <8} package {s: <8} {s}  zbx {s}\n", .{
            demo_name,
            report.guest.name,
            @tagName(report.metadata),
            @tagName(report.package),
            if (report.installed) "installed    " else "NOT INSTALLED",
            if (ran) "ran" else "DID NOT RUN",
        });
        if (report.stopped) |err| {
            try out.print("{s}:   {s: <7} stopped early: {s}\n", .{
                demo_name, report.guest.name, @errorName(err),
            });
        }
        if (!good) passed = false;
    }
    return passed;
}

/// The whole package tree (everything but `to-sign/`) as one tar, served to each guest.
fn pack_tree(init: std.process.Init, arena: std.mem.Allocator, root: []const u8) ![]const u8 {
    var dir = try Io.Dir.cwd().openDir(init.io, root, .{ .iterate = true });
    defer dir.close(init.io);
    var body: Io.Writer.Allocating = .init(arena);
    var tar: std.tar.Writer = .{ .underlying_writer = &body.writer };
    var walker = try dir.walk(arena);
    var entries: usize = 0;
    while (try walker.next(init.io)) |entry| {
        if (entry.kind != .file) continue;
        if (std.mem.startsWith(u8, entry.path, "to-sign")) continue;
        entries += 1;
        if (entries > tar_entries_max) return error.TooManyFiles;
        const limit: Io.Limit = .limited(vm.limits.http_body_bytes_max);
        const content = try dir.readFileAlloc(init.io, entry.path, arena, limit);
        try tar.writeFileBytes(entry.path, content, .{ .mode = 0o644 });
    }
    try tar.finishPedantically();
    const bytes = body.written();
    if (bytes.len > vm.limits.http_body_bytes_max) return error.TarTooBig;
    if (entries == 0) return error.EmptyPackageTree;
    return bytes;
}

fn run_guest(
    init: std.process.Init,
    out: *Io.Writer,
    args: Args,
    guest: *const Guest,
    tar: []const u8,
) !Report {
    const arena = init.arena.allocator();
    const family = @tagName(guest.family);
    try out.print("\n{s}: ===== {s} ({s}) =====\n", .{ demo_name, guest.name, family });
    const accel = try vm.accel.choose(args.accel, vm.accel.kvm_usable(init.io));
    const base = try image.ensure_pin(init, args.cache_dir, out, guest.pin);
    const format = "{s}/overlay-m8-{s}.qcow2";
    const overlay = try std.fmt.allocPrint(arena, format, .{ args.cache_dir, guest.name });
    try image.make_overlay_sized(init, base, overlay, overlay_size);
    defer Io.Dir.cwd().deleteFile(init.io, overlay) catch {};

    const config = config_of(guest);
    var user_data: [vm.limits.user_data_bytes_max]u8 = undefined;
    var meta_data: [vm.limits.meta_data_bytes_max]u8 = undefined;
    var session: Session = undefined;
    try session.start(init, out, overlay, accel, .{
        .user_data = try vm.cloud_init.render_user_data(&config, &user_data),
        .meta_data = try vm.cloud_init.render_meta_data(&config, &meta_data),
        .files = &.{.{ .path = tar_route, .body = tar }},
        .seed_id = guest.seed_id,
    });
    defer session.deinit();
    try session.provision(guest.hostname, false);
    var report: Report = .{ .guest = guest };
    try serve_repository(&session, out);
    switch (guest.family) {
        .apt => try install_apt(&session, out, &report),
        .dnf => try install_dnf(&session, out, &report),
    }
    if (report.installed) try check_installed(&session, out, args.version, &report);
    try session.shutdown();
    return report;
}

fn config_of(guest: *const Guest) vm.Config {
    return .{
        .hostname = guest.hostname,
        .instance_id = guest.hostname,
        .user = .{
            .name = "demo",
            .uid = 1000,
            .subid_start = 100000,
            .subid_count = 65536,
            .linger = true,
        },
        .packages = &.{"curl"},
        .sysctls = if (guest.userns_sysctl) &.{.{
            .key = "kernel.apparmor_restrict_unprivileged_userns",
            .value = "0",
        }} else &.{},
        .sysctl_path = "/etc/sysctl.d/60-zigbox-userns.conf",
        .console_prompt = guest.console_prompt,
    };
}

/// Unpacks the tree into the guest and serves it over HTTP on the loopback, the way a mirror
/// would; the package managers fetch from `http://127.0.0.1:8081`.
fn serve_repository(session: *Session, out: *Io.Writer) !void {
    const copied = try session.copy_in(.{ .route = tar_route, .guest_path = "/root/repo.tar" });
    try H.show(out, "fetch the package trees", copied);
    if (copied.status != 0) return error.CopyFailed;
    const unpack = "mkdir -p " ++ repo_dir ++ " && tar -xf /root/repo.tar -C " ++ repo_dir ++
        " && ls " ++ repo_dir;
    const unpacked = try session.run(unpack, vm.limits.command_timeout_kvm_s);
    try H.show(out, "unpack them", unpacked);
    if (unpacked.status != 0) return error.UnpackFailed;
    // The whole group is redirected: a background job that still holds the `$( )` pipe keeps
    // `Session.run` waiting for its end.
    const start = "(cd " ++ repo_dir ++ " && exec setsid python3 -m http.server 8081 " ++
        "--bind 127.0.0.1) >/tmp/repo-server.log 2>&1 </dev/null & sleep 2; " ++
        "curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:8081/zigbox-test-key.asc";
    const served = try session.run(start, vm.limits.command_timeout_kvm_s);
    try H.show(out, "serve them on 127.0.0.1:8081", served);
    if (!std.mem.eql(u8, std.mem.trim(u8, served.output, " \r\n"), "200")) return error.NotServed;
}

const apt_source = "/etc/apt/sources.list.d/zigbox-test.list";
const apt_key = "/usr/share/keyrings/zigbox-test.gpg";
const apt_line = "deb [signed-by=" ++ apt_key ++ "] http://127.0.0.1:8081/apt stable main";
const apt_only_zigbox = "-o Dir::Etc::sourcelist=" ++ apt_source ++
    " -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0";

fn install_apt(session: *Session, out: *Io.Writer, report: *Report) !void {
    const setup = "install -m 644 " ++ repo_dir ++ "/zigbox-test-key.gpg " ++ apt_key ++
        " && echo '" ++ apt_line ++ "' > " ++ apt_source;
    const prepared = try session.run(setup, vm.limits.command_timeout_kvm_s);
    try H.show(out, "add the signed apt source", prepared);
    if (prepared.status != 0) return error.AptSetupFailed;
    const update = "apt-get update " ++ apt_only_zigbox;
    const probe = try session.run(update, install_timeout_s);
    try H.show(out, "apt-get update (the Ed25519 probe)", probe);
    report.metadata = checks.apt_update_verdict(probe.output, probe.status);
    report.package = report.metadata;
    const install = "DEBIAN_FRONTEND=noninteractive apt-get -y -q install zigbox";
    const installed = try session.run(install, install_timeout_s);
    try H.show(out, "apt-get install zigbox", installed);
    report.installed = installed.status == 0;
}

const dnf_repo = "/etc/yum.repos.d/zigbox-test.repo";
const dnf_header = "[zigbox-test]\nname=zigbox test\n" ++
    "baseurl=http://127.0.0.1:8081/rpm/$basearch\nenabled=1\n";
const dnf_signed = dnf_header ++ "gpgcheck=1\nrepo_gpgcheck=1\n" ++
    "gpgkey=file://" ++ repo_dir ++ "/zigbox-test-key.asc\n";

fn write_repo(session: *Session, text: []const u8) !void {
    var buffer: [512]u8 = undefined;
    const command = try std.fmt.bufPrint(&buffer, "printf '%b' '{s}' > {s}", .{ text, dnf_repo });
    const result = try session.run(command, vm.limits.command_timeout_kvm_s);
    if (result.status != 0) return error.RepoNotWritten;
}

/// `text` for `printf %b`: newlines as `\n`. The texts above hold no quote or backslash.
fn escaped(comptime text: []const u8) []const u8 {
    comptime var result: []const u8 = "";
    inline for (text) |byte| {
        result = result ++ if (byte == '\n') "\\n" else &[_]u8{byte};
    }
    return result;
}

fn install_dnf(session: *Session, out: *Io.Writer, report: *Report) !void {
    try write_repo(session, comptime escaped(dnf_signed));
    const makecache = "dnf -y --disablerepo='*' --enablerepo=zigbox-test makecache";
    const cache = try session.run(makecache, install_timeout_s);
    try H.show(out, "dnf makecache (the repodata Ed25519 probe)", cache);
    report.metadata = checks.dnf_makecache_verdict(cache.output, cache.status);
    const rpm_probe = "rpmkeys --import " ++ repo_dir ++ "/zigbox-test-key.asc; " ++
        "rpm -K " ++ repo_dir ++ "/rpm/x86_64/zigbox-*.rpm";
    const rpm = try session.run(rpm_probe, vm.limits.command_timeout_kvm_s);
    try H.show(out, "rpm -K (the package Ed25519 probe)", rpm);
    report.package = checks.rpm_check_verdict(rpm.output, rpm.status);
    const install = "dnf -y -q --disablerepo='*' --enablerepo=zigbox-test install zigbox";
    const installed = try session.run(install, install_timeout_s);
    try H.show(out, "dnf install zigbox", installed);
    report.installed = installed.status == 0;
}

fn check_installed(session: *Session, out: *Io.Writer, version: []const u8, report: *Report) !void {
    const shown = try session.run("/usr/bin/zbx --version", vm.limits.command_timeout_kvm_s);
    try H.show(out, "zbx --version", shown);
    report.version_ok = checks.version_ok(shown.output, version) and shown.status == 0;
    const command = H.as_demo ++ "/usr/bin/zbx doctor";
    const doctor = try session.run(command, vm.limits.command_timeout_kvm_s);
    try H.show(out, "zbx doctor (as demo)", doctor);
    report.doctor_ran = checks.doctor_ran(doctor.output, doctor.status);
}

test {
    _ = @import("checks_m8_packages.zig");
}
