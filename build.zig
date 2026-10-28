const std = @import("std");

/// The release targets. Both are built statically (no libc is ever linked) and in ReleaseSafe so
/// assertions stay on. See docs/STYLE.md.
const release_targets = [_]std.Target.Query{
    .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .musl },
    .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .musl },
};

const release_install_dirs = [_][]const u8{
    "release/x86_64-linux",
    "release/aarch64-linux",
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The version has one source of truth, build.zig.zon, handed to the code as an option.
    const manifest = @import("build.zig.zon");
    const options = b.addOptions();
    options.addOption([]const u8, "version", manifest.version);

    // LLVM in every mode, not Zig's own x86_64 backend in Debug: that backend writes each
    // `undefined` global into .data as 0xaa bytes, which made a Debug zbx 335 MB and a test
    // binary 1.4 GB, filling the build cache a build at a time. LLVM leaves them in .bss.
    const exe = b.addExecutable(.{
        .name = "zbx",
        .root_module = zbx_module(b, options, target, optimize, null),
        .use_llvm = true,
    });
    b.installArtifact(exe);
    add_library_module(b, options, target, optimize);

    add_test_step(b, options, target, optimize);
    add_tidy_step(b);
    const fuzz = add_fuzz_step(b, options, target);
    add_release_step(b, options);
    add_demo_step(b, options);
    add_errors_site_steps(b);
    add_dbus_live_step(b, options);
    add_check_step(b, fuzz);
}

/// The runtime as a module named `zigbox`, for Zigcube's agent to link: another build adds this
/// package as a dependency and imports `zigbox` from it. Its root is in `src/` so that the files
/// it imports (`constants.zig`, `host.zig`, ...) are inside the module's path.
fn add_library_module(
    b: *std.Build,
    options: *std.Build.Step.Options,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    _ = b.addModule("zigbox", .{
        .root_source_file = b.path("src/zigbox.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = false,
        .imports = &.{.{ .name = "build_options", .module = options.createModule() }},
    });
}

fn zbx_module(
    b: *std.Build,
    options: *std.Build.Step.Options,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    strip: ?bool,
) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .strip = strip,
        .link_libc = false,
        .imports = &.{.{ .name = "build_options", .module = options.createModule() }},
    });
}

fn add_test_step(
    b: *std.Build,
    options: *std.Build.Step.Options,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const test_step = b.step("test", "Run unit, snapshot and simulation tests");
    const roots = [_][]const u8{
        "src/testing/vm/main.zig",
        "src/testing/vm/main_m1.zig",
        "src/testing/vm/main_m2.zig",
        "src/testing/vm/main_m3.zig",
        "src/testing/vm/main_m4.zig",
        "src/testing/vm/main_top20.zig",
        "src/main.zig",
        "src/zigbox.zig",
        "src/tidy.zig",
        "src/fuzz.zig",
        "src/size_check.zig",
        "src/errors_site.zig",
    };
    for (roots) |root| {
        const module = b.createModule(.{
            .root_source_file = b.path(root),
            .target = target,
            .optimize = optimize,
            .link_libc = false,
            .imports = &.{.{ .name = "build_options", .module = options.createModule() }},
        });
        // Only the top-20 harness reads it; the policy is a data file, so an import costs nothing.
        module.addAnonymousImport("seccomp_policy", .{
            .root_source_file = b.path("src/runtime/policy/seccomp.zon"),
        });
        // LLVM, as for zbx above: Zig's own backend fills `undefined` globals with 0xaa in the
        // binary, so a test could pass on that fill (gc_tests did) where a release would not.
        const unit_tests = b.addTest(.{ .root_module = module, .use_llvm = true });
        test_step.dependOn(&b.addRunArtifact(unit_tests).step);
    }
}

fn add_tidy_step(b: *std.Build) void {
    // Tidy is a host tool: always built for the machine running the build.
    const tidy = b.addExecutable(.{
        .name = "tidy",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tidy.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    const run = b.addRunArtifact(tidy);
    run.setCwd(b.path("."));
    // Formatting is checked alongside the mechanical rules: both must pass before review.
    const format = b.addFmt(.{ .paths = &.{ b.path("src"), b.path("build.zig") }, .check = true });
    const step = b.step("tidy", "Check formatting, line and function length, banned patterns");
    step.dependOn(&format.step);
    step.dependOn(&run.step);
}

fn add_fuzz_step(
    b: *std.Build,
    options: *std.Build.Step.Options,
    target: std.Build.ResolvedTarget,
) *std.Build.Step.Compile {
    // Fuzzers keep assertions on regardless of the user's optimize flag: they exist to trip them.
    const fuzz = b.addExecutable(.{
        .name = "fuzz",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/fuzz.zig"),
            .target = target,
            .optimize = .ReleaseSafe,
            .link_libc = false,
            .imports = &.{.{ .name = "build_options", .module = options.createModule() }},
        }),
    });
    const run = b.addRunArtifact(fuzz);
    run.addPassthruArgs();
    const description = "Run one seeded fuzzer: zig build fuzz -- <fuzzer> [seed] [iterations]";
    const step = b.step("fuzz", description);
    step.dependOn(&run.step);
    return fuzz;
}

/// The spec's release criterion: a static binary under 4 MiB (2 MiB until M4's TLS client and
/// decoders; live doc rev 54).
const release_size_limit_bytes = 4 * 1024 * 1024;

fn add_release_step(b: *std.Build, options: *std.Build.Step.Options) void {
    const description = "Cross-compile static ReleaseSafe binaries, stripped, under 4 MiB";
    const step = b.step("release", description);
    // Release binaries are stripped by default so that they meet the size limit; ReleaseSafe
    // stays, so assertions still fire, only without symbolised stack traces. -Dstrip=false builds
    // the debug-info variant (about 3.7 MB) for diagnosing a crash, and skips the size gate.
    const strip_help = "Strip debug info from release binaries (default true)";
    const strip = b.option(bool, "strip", strip_help) orelse true;

    const checker = b.addExecutable(.{
        .name = "size_check",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/size_check.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    const check = b.addRunArtifact(checker);
    check.addArg(b.fmt("{d}", .{release_size_limit_bytes}));

    for (release_targets, release_install_dirs) |query, install_dir| {
        const exe = b.addExecutable(.{
            .name = "zbx",
            .root_module = zbx_module(b, options, b.resolveTargetQuery(query), .ReleaseSafe, strip),
        });
        const install = b.addInstallArtifact(exe, .{
            .dest_dir = .{ .override = .{ .custom = install_dir } },
        });
        step.dependOn(&install.step);
        check.addFileArg(exe.getEmittedBin());
        // The binary that can run here is run once. A release binary has its own startup (no
        // libc: `std.os.linux.tls`), and a thread-local variable once made it panic before
        // `main`, which no test binary showed.
        if (query.cpu_arch == b.graph.host.result.cpu.arch) {
            const smoke = b.addRunArtifact(exe);
            smoke.addArg("--version");
            step.dependOn(&smoke.step);
        }
    }
    if (strip) step.dependOn(&check.step);
}

/// The milestone demos: the step, the harness's root file and the help line.
const demos = [_]struct { step: []const u8, root: []const u8, help: []const u8 }{
    .{
        .step = "demo-m0",
        .root = "src/testing/vm/main.zig",
        .help = "Run the M0 demo in a real Ubuntu 24.04 VM (see docs/demos/m0.md)",
    },
    .{
        .step = "demo-m1",
        .root = "src/testing/vm/main_m1.zig",
        .help = "Run the M1 demo: zbx run in an Alpine rootfs, in the VM (docs/demos/m1.md)",
    },
    .{
        .step = "demo-m2",
        .root = "src/testing/vm/main_m2.zig",
        .help = "Run the M2 demo: limits, hardening, lifecycle, in the VM (docs/demos/m2.md)",
    },
    .{
        .step = "demo-m3",
        .root = "src/testing/vm/main_m3.zig",
        .help = "Run the M3 demo, as far as it is built: the store and running by digest",
    },
    .{
        .step = "demo-m4",
        .root = "src/testing/vm/main_m4.zig",
        .help = "Run the M4 demo, as far as it is built: pull, the lock, run by name",
    },
    .{
        .step = "top20",
        .root = "src/testing/vm/main_top20.zig",
        .help = "Pull and run the top 20 Docker Hub images in the VM (docs/demos/m4.md)",
    },
};

/// `zig build demo-m0` and `demo-m1`: the milestone demos in a real Ubuntu VM. They use the
/// stripped ReleaseSafe binaries, the ones that ship. -Daccel=kvm|tcg|auto chooses the accelerator:
/// auto means KVM and fails with a one-line message if /dev/kvm is unusable; tcg (software
/// emulation, much slower) must be asked for explicitly.
fn add_demo_step(b: *std.Build, options: *std.Build.Step.Options) void {
    const Accel = enum { auto, kvm, tcg };
    const accel_help = "VM accelerator for the demos: auto (default), kvm, tcg";
    const accel = b.option(Accel, "accel", accel_help) orelse .auto;
    const dropin_help = "demo-m0 only: provision a Delegate= drop-in for user managers";
    const dropin = b.option(bool, "delegate-dropin", dropin_help) orelse false;
    const keep_help = "demos: keep the VM disk overlay (development)";
    const keep = b.option(bool, "keep-overlay", keep_help) orelse false;
    const reuse_help = "demos: boot the kept, provisioned overlay (development)";
    const reuse = b.option(bool, "reuse-overlay", reuse_help) orelse false;

    const mirror_help = "top20: a docker.io mirror for the guest (the weekly run uses none)";
    const mirror = b.option([]const u8, "mirror", mirror_help);
    const only_help = "top20: run only these images, e.g. redis,nginx (development)";
    const only = b.option([]const u8, "only", only_help);
    const ca_help = "demos: a CA bundle the guest trusts, for a host that inspects TLS";
    const ca_file = b.option(std.Build.LazyPath, "ca-file", ca_help);

    for (demos) |demo| {
        const is_top20 = std.mem.eql(u8, demo.step, "top20");
        const vm = b.addExecutable(.{
            .name = "vm",
            .root_module = b.createModule(.{
                .root_source_file = b.path(demo.root),
                .target = b.graph.host,
                .optimize = .ReleaseSafe,
            }),
        });
        // The top-20 run tells a seccomp refusal from another EPERM by the allowlist itself.
        if (is_top20) {
            vm.root_module.addAnonymousImport("seccomp_policy", .{
                .root_source_file = b.path("src/runtime/policy/seccomp.zon"),
            });
        }
        const run = b.addRunArtifact(vm);
        run.setCwd(b.path("."));
        run.addArgs(&.{ "--accel", @tagName(accel) });
        if (dropin and std.mem.eql(u8, demo.step, "demo-m0")) run.addArg("--delegate-dropin");
        if (std.mem.eql(u8, demo.step, "demo-m3")) {
            add_old_binary(b, run, @import("src/testing/vm/old_release.zon").commit);
        }
        if (std.mem.eql(u8, demo.step, "demo-m4")) {
            add_old_binary(b, run, @import("src/testing/vm/old_release.zon").m4_commit);
            run.addArgs(&.{ "--blob-cache", ".zig-cache/zbx-vm/m4-blobs.img" });
        }
        if (is_top20 and mirror != null) run.addArgs(&.{ "--mirror", mirror.? });
        if (is_top20 and only != null) run.addArgs(&.{ "--only", only.? });
        if (ca_file) |path| {
            run.addArg("--ca-file");
            run.addFileArg(path);
        }
        if (keep) run.addArg("--keep-overlay");
        if (reuse) run.addArg("--reuse-overlay");
        add_release_binaries(b, options, run);
        const step = b.step(demo.step, demo.help);
        step.dependOn(&run.step);
    }
}

/// The shipped zbx for each release target, handed to a demo as `--zbx-<arch>`.
fn add_release_binaries(
    b: *std.Build,
    options: *std.Build.Step.Options,
    run: *std.Build.Step.Run,
) void {
    const flags = [_][]const u8{ "--zbx-x86_64", "--zbx-aarch64" };
    for (release_targets, flags) |query, flag| {
        const exe = b.addExecutable(.{
            .name = "zbx",
            .root_module = zbx_module(b, options, b.resolveTargetQuery(query), .ReleaseSafe, true),
        });
        run.addArg(flag);
        run.addFileArg(exe.getEmittedBin());
    }
}

/// The upgrade test of demo-m3 and demo-m4: the older zbx, built from a worktree of the pinned
/// commit by `src/testing/vm/build_old.zig`, handed to the harness as `--old-zbx`.
fn add_old_binary(b: *std.Build, run: *std.Build.Step.Run, commit: []const u8) void {
    const builder = b.addExecutable(.{
        .name = "build_old",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/testing/vm/build_old.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    const old = b.addRunArtifact(builder);
    old.setCwd(b.path("."));
    old.addArg(b.graph.zig_exe);
    old.addArg(commit);
    run.addArg("--old-zbx");
    run.addFileArg(old.addOutputFileArg("zbx-old"));
}

/// `zig build dbus-live`: the D-Bus client against a real bus (see src/dbus_live.zig). It is not
/// a test: it needs a bus, so run it as `dbus-run-session -- zig build dbus-live`.
fn add_dbus_live_step(b: *std.Build, options: *std.Build.Step.Options) void {
    const live = b.addExecutable(.{
        .name = "dbus_live",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/dbus_live.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
            .link_libc = false,
            .imports = &.{.{ .name = "build_options", .module = options.createModule() }},
        }),
    });
    const run = b.addRunArtifact(live);
    const step = b.step("dbus-live", "Run the D-Bus client against a real bus (dbus-run-session)");
    step.dependOn(&run.step);
}

/// `zig build errors-site` writes site/errors/<code>.html from the diagnostic registry;
/// `zig build errors-site-check` (run by CI) fails if a checked-in page is missing or stale.
fn add_errors_site_steps(b: *std.Build) void {
    const generator = b.addExecutable(.{
        .name = "errors_site",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/errors_site.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    const write = b.addRunArtifact(generator);
    write.setCwd(b.path("."));
    write.addArg("site/errors");
    const write_step = b.step("errors-site", "Write site/errors/<code>.html from the registry");
    write_step.dependOn(&write.step);

    const check = b.addRunArtifact(generator);
    check.setCwd(b.path("."));
    check.addArgs(&.{ "site/errors", "--check" });
    const check_step = b.step("errors-site-check", "Fail if site/errors is stale");
    check_step.dependOn(&check.step);
}

/// `zig build check`: every gate a slice must pass, in one command, ending in the one line a
/// report quotes (`check: PASS <commit>`). Build, test, tidy, release and the error pages run
/// first, as dependencies; then, as root, `zig build test` again as -Dcheck-user (default tester)
/// in a scratch worktree, because CI runs as an ordinary user. -Dcheck-user=- skips that.
/// `fuzz` is the fuzzers' binary: `check` runs every one of them with a fresh seed.
fn add_check_step(b: *std.Build, fuzz: *std.Build.Step.Compile) void {
    const user = b.option([]const u8, "check-user", "User for the non-root test run, or -") orelse
        "tester";
    const tool = b.addExecutable(.{
        .name = "check",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/testing/check.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    const run = b.addRunArtifact(tool);
    run.setCwd(b.path("."));
    run.addArgs(&.{ b.graph.zig_exe, user });
    run.addArtifactArg(fuzz);
    run.has_side_effects = true;
    const gates = [_][]const u8{ "install", "test", "tidy", "release", "errors-site-check" };
    for (gates) |name| {
        const gate = b.top_level_steps.get(name) orelse @panic(name);
        run.step.dependOn(&gate.step);
    }
    const step = b.step("check", "Every gate, then the test suite as a non-root user; one line");
    step.dependOn(&run.step);
}
