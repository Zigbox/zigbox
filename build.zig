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
    // On a Mac the default install is the macOS zbx (a forwarder to a Linux VM; it links
    // libSystem and Virtualization.framework). The Linux zbx, static and libc-free, is what
    // `-Dtarget=<arch>-linux` and `release` build, and what the VM's initramfs carries.
    const for_macos = target.result.os.tag == .macos;
    if (for_macos) {
        add_macos_install(b, options, target, optimize);
    } else {
        const exe = b.addExecutable(.{
            .name = "zbx",
            .root_module = zbx_module(b, options, target, optimize, null),
            .use_llvm = true,
        });
        b.installArtifact(exe);
    }
    add_library_module(b, options, target, optimize);

    add_test_step(b, options, target, optimize);
    add_tidy_step(b);
    const fuzz = add_fuzz_step(b, options, target);
    add_release_step(b, options);
    add_demo_step(b, options);
    add_errors_site_steps(b);
    add_dbus_live_step(b, options);
    add_check_step(b, fuzz);
    add_vm_kernel_steps(b);
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

/// Every test root. `zig build tidy` reads this list to find tests that no root reaches. On a Mac
/// the roots that need a Linux kernel (the simulator and the Linux runtime, `linux_only`) are
/// skipped by name and the macOS root runs; `-Dtarget=aarch64-linux` compiles the first kind
/// without running it. On Linux, the macOS root is not built.
const roots = [_][]const u8{
    "src/testing/vm/main.zig",
    "src/testing/vm/main_m1.zig",
    "src/testing/vm/main_m2.zig",
    "src/testing/vm/main_m3.zig",
    "src/testing/vm/main_m4.zig",
    "src/testing/vm/main_m5.zig",
    "src/testing/vm/main_m6.zig",
    "src/testing/vm/main_top20.zig",
    "src/main.zig",
    "src/zigbox.zig",
    "src/tidy.zig",
    "src/fuzz.zig",
    "src/size_check.zig",
    "src/errors_site.zig",
    "src/mac_release.zig",
    "src/testing/mac_demo.zig",
    "src/vm_image_make.zig",
    "src/vm_image/kernel_build.zig",
    "src/macos_main.zig",
};

const linux_only = [_][]const u8{
    "src/testing/vm/main.zig",
    "src/testing/vm/main_m1.zig",
    "src/testing/vm/main_m2.zig",
    "src/testing/vm/main_m3.zig",
    "src/testing/vm/main_m4.zig",
    "src/testing/vm/main_m5.zig",
    "src/testing/vm/main_m6.zig",
    "src/testing/vm/main_top20.zig",
    "src/main.zig",
    "src/zigbox.zig",
    "src/fuzz.zig",
};

const macos_root = "src/macos_main.zig";
const kernel_build_root = "src/vm_image/kernel_build.zig";

fn is_listed(list: []const []const u8, name: []const u8) bool {
    for (list) |item| {
        if (std.mem.eql(u8, item, name)) return true;
    }
    return false;
}

fn add_test_step(
    b: *std.Build,
    options: *std.Build.Step.Options,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const test_step = b.step("test", "Run unit, snapshot and simulation tests");
    const for_macos = target.result.os.tag == .macos;
    const runs_here = target.result.os.tag == b.graph.host.result.os.tag;
    for (roots) |root| {
        if (for_macos and is_listed(&linux_only, root)) continue; // Skipped on a Mac, by name.
        if (!for_macos and std.mem.eql(u8, root, macos_root)) continue;
        const module = b.createModule(.{
            .root_source_file = b.path(root),
            .target = target,
            .optimize = optimize,
            // macOS needs libSystem; the Linux roots never link a libc.
            .link_libc = if (for_macos) null else false,
            .imports = &.{.{ .name = "build_options", .module = options.createModule() }},
        });
        // Only the top-20 harness reads it; the policy is a data file, so an import costs nothing.
        module.addAnonymousImport("seccomp_policy", .{
            .root_source_file = b.path("src/runtime/policy/seccomp.zon"),
        });
        if (std.mem.eql(u8, root, macos_root)) link_macos(module, add_vm_image(b, options));
        if (std.mem.eql(u8, root, kernel_build_root)) {
            module.addImport("build_options", kernel_pin_options(b).createModule());
        }
        // LLVM, as for zbx above: Zig's own backend fills `undefined` globals with 0xaa in the
        // binary, so a test could pass on that fill (gc_tests did) where a release would not.
        const unit_tests = b.addTest(.{ .root_module = module, .use_llvm = true });
        if (runs_here) {
            test_step.dependOn(&b.addRunArtifact(unit_tests).step);
        } else {
            test_step.dependOn(&unit_tests.step); // Compiled, not run: another OS than this host.
        }
    }
}

/// The kernel pin (`vm/kernel/pin.zon`) as build options, for the kernel build program.
fn kernel_pin_options(b: *std.Build) *std.Build.Step.Options {
    const pinned = @import("vm/kernel/pin.zon");
    const options = b.addOptions();
    options.addOption([]const u8, "url", pinned.url);
    options.addOption([]const u8, "tarball_sha256", pinned.tarball_sha256);
    options.addOption([]const u8, "image_sha256", pinned.image_sha256);
    options.addOption([]const u8, "toolchain", pinned.toolchain);
    return options;
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
        // Only a Linux host can run it; on a Mac the binaries are built and measured, not run.
        const host = b.graph.host.result;
        if (query.cpu_arch == host.cpu.arch and host.os.tag == .linux) {
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
        .step = "demo-m5",
        .root = "src/testing/vm/main_m5.zig",
        .help = "Run the M5 demo, as far as it is built: the upgrade test against M4",
    },
    .{
        .step = "demo-m6",
        .root = "src/testing/vm/main_m6.zig",
        .help = "Run the M6 demo, as far as it is built: the five steps, upgrade from M5",
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
    // `zig build test` only compiles what a test reaches, and a demo's steps are reached through
    // its `parts` list, not a test: compiling every harness is a gate of its own (`check`).
    const harness = b.step("harness", "Compile every VM demo harness, without running it");

    const harness_target = harness_target_of(b);
    for (demos) |demo| {
        const is_top20 = std.mem.eql(u8, demo.step, "top20");
        const vm = b.addExecutable(.{
            .name = "vm",
            .root_module = b.createModule(.{
                .root_source_file = b.path(demo.root),
                .target = harness_target,
                .optimize = .ReleaseSafe,
            }),
        });
        harness.dependOn(&vm.step);
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
        if (std.mem.eql(u8, demo.step, "demo-m5")) {
            add_old_binary(b, run, @import("src/testing/vm/old_release.zon").m5_commit);
        }
        if (std.mem.eql(u8, demo.step, "demo-m6")) {
            add_old_binary(b, run, @import("src/testing/vm/old_release.zon").m6_commit);
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

/// The harness drives QEMU on a Linux host. On a Mac it is compiled for Linux (so a change to
/// it cannot break unseen) and never run: the demos are CI's job.
fn harness_target_of(b: *std.Build) std.Build.ResolvedTarget {
    const host = b.graph.host.result;
    if (host.os.tag == .linux) return b.graph.host;
    return b.resolveTargetQuery(.{ .cpu_arch = host.cpu.arch, .os_tag = .linux, .abi = .musl });
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

/// The upgrade test of demo-m3 to demo-m6: the older zbx, built from a worktree of the
/// pinned commit by `src/testing/vm/build_old.zig`, handed to the harness as `--old-zbx`.
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
    const gates = [_][]const u8{
        "install", "test", "tidy", "release", "errors-site-check", "harness",
    };
    for (gates) |name| {
        const gate = b.top_level_steps.get(name) orelse @panic(name);
        run.step.dependOn(&gate.step);
    }
    const step = b.step("check", "Every gate, then the test suite as a non-root user; one line");
    step.dependOn(&run.step);
}

/// Where the VM's kernel `Image` lives between builds: large, so under the cache, and found by
/// the macOS build from here unless `-Dvm-kernel` names another.
const vm_kernel_default = ".zig-cache/zbx-vm/kernel/Image";

/// `zig build vm-kernel` builds the VM's kernel on an arm64 Ubuntu host; `vm-kernel-docker` does
/// the same inside an `ubuntu:24.04` arm64 container, as a developer convenience on a Mac (the
/// product never uses Docker). The program is `src/vm_image/kernel_build.zig`.
fn add_vm_kernel_steps(b: *std.Build) void {
    const pin = kernel_pin_options(b).createModule();
    const jobs = b.fmt("{d}", .{std.Thread.getCpuCount() catch 4});
    const native = b.addExecutable(.{
        .name = "kernel_build",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/vm_image/kernel_build.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
            .imports = &.{.{ .name = "build_options", .module = pin }},
        }),
    });
    const run = b.addRunArtifact(native);
    run.addArgs(&.{ "--config", "vm/kernel/config-arm64", "--cache", ".zig-cache/zbx-vm/kernel" });
    run.addArgs(&.{ "--work", ".zig-cache/zbx-vm/kernel-build", "--out", vm_kernel_default });
    run.addArgs(&.{ "--jobs", jobs });
    run.setCwd(b.path("."));
    const description = "Build the VM kernel Image (needs an arm64 Ubuntu 24.04 host)";
    b.step("vm-kernel", description).dependOn(&run.step);

    const linux_arm: std.Target.Query = .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .musl };
    const inside = b.addExecutable(.{
        .name = "kernel_build",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/vm_image/kernel_build.zig"),
            .target = b.resolveTargetQuery(linux_arm),
            .optimize = .ReleaseSafe,
            .imports = &.{.{ .name = "build_options", .module = pin }},
        }),
    });
    const install = b.addInstallArtifact(inside, .{
        .dest_dir = .{ .override = .{ .custom = "vm-tools" } },
    });
    const docker = b.addSystemCommand(&.{ "docker", "run", "--rm", "--platform", "linux/arm64" });
    docker.setCwd(b.path("."));
    docker.addArgs(&.{
        "-v", "./zig-out/vm-tools:/tools:ro",
        "-v", "./vm/kernel:/kernel:ro",
        "-v", "./.zig-cache/zbx-vm/kernel:/cache",
    });
    docker.addArgs(&.{ "ubuntu:24.04", "/tools/kernel_build", "--config", "/kernel/config-arm64" });
    docker.addArgs(&.{ "--cache", "/cache", "--work", "/build", "--out", "/cache/Image" });
    docker.addArgs(&.{ "--install-deps", "--jobs", jobs });
    docker.step.dependOn(&install.step);
    const docker_text = "Build the VM kernel in an ubuntu:24.04 arm64 container (developer aid)";
    b.step("vm-kernel-docker", docker_text).dependOn(&docker.step);
}

// ---- The macOS zbx and the VM image it carries -----------------------------------------------

const VmImage = struct {
    kernel: std.Build.LazyPath,
    initramfs: std.Build.LazyPath,
    version: std.Build.LazyPath,
};

/// The VM's initramfs and its version, made from the pinned kernel, the guest's init and the
/// Linux zbx (aarch64, the same ReleaseSafe build as `release`). `-Dvm-kernel` names the kernel
/// Image (default: where `zig build vm-kernel` leaves it); its digest must be the pin's.
fn add_vm_image(b: *std.Build, options: *std.Build.Step.Options) VmImage {
    if (vm_image_made) |made| return made; // One set of options and steps per build.
    const kernel_help = "VM kernel Image (default: " ++ vm_kernel_default ++ ")";
    const kernel = b.option(std.Build.LazyPath, "vm-kernel", kernel_help) orelse
        b.path(vm_kernel_default);
    const label_help = "development: text mixed into the VM image's version, to tell builds apart";
    const label = b.option([]const u8, "vm-label", label_help) orelse "";
    const guest: std.Target.Query = .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .musl };
    const init_exe = b.addExecutable(.{
        .name = "init",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/vm_guest_init.zig"),
            .target = b.resolveTargetQuery(guest),
            .optimize = .ReleaseSafe,
            .strip = true,
            .link_libc = false,
        }),
    });
    const linux_zbx = b.addExecutable(.{
        .name = "zbx",
        .root_module = zbx_module(b, options, b.resolveTargetQuery(guest), .ReleaseSafe, true),
    });
    const tool = b.addExecutable(.{
        .name = "make_image",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/vm_image_make.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    const pinned = @import("vm/kernel/pin.zon");
    const run = b.addRunArtifact(tool);
    // A fresh checkout has no kernel yet. Say so in one line, only to the steps that need it.
    if (kernel_missing(b, kernel)) {
        const missing = b.addFail("the VM kernel is missing: run `zig build vm-kernel-docker` " ++
            "(or pass -Dvm-kernel=<path to the pinned Image>)");
        run.step.dependOn(&missing.step);
    }
    run.addArg("--kernel");
    run.addFileArg(kernel);
    run.addArgs(&.{ "--kernel-sha256", pinned.image_sha256, "--init" });
    run.addFileArg(init_exe.getEmittedBin());
    run.addArg("--zbx");
    run.addFileArg(linux_zbx.getEmittedBin());
    if (label.len > 0) run.addArgs(&.{ "--label", label });
    run.addArgs(&.{ "--apk-cache", ".zig-cache/zbx-vm/apk" });
    run.addArgs(&.{ "--apk-mirror", @import("vm/alpine.zon").mirror });
    inline for (@import("vm/alpine.zon").packages) |package| {
        run.addArgs(&.{ "--apk", package.name, package.url, package.sha256 });
    }
    run.addArg("--out-initramfs");
    const initramfs = run.addOutputFileArg("initramfs.cpio");
    run.addArg("--out-version");
    const version = run.addOutputFileArg("image-version");
    vm_image_made = .{ .kernel = kernel, .initramfs = initramfs, .version = version };
    return vm_image_made.?;
}

var vm_image_made: ?VmImage = null;

/// True if the kernel Image is not a file this build can read. Checked when the build is
/// configured, relative to the directory `zig build` runs in (the repository's root).
fn kernel_missing(b: *std.Build, kernel: std.Build.LazyPath) bool {
    const path = switch (kernel) {
        .src_path => |source| source.sub_path,
        else => return false,
    };
    std.Io.Dir.cwd().access(b.graph.io, path, .{}) catch {
        // The answer is "missing" now and may change without build.zig changing, so a cached
        // configuration must not be reused.
        b.graph.poisonCache();
        return true;
    };
    b.dependOnFileMetadata(kernel); // Replaced or rebuilt: configure again.
    return false;
}

/// The VM image as the three files the macOS zbx embeds, and the frameworks it needs.
fn link_macos(module: *std.Build.Module, image: VmImage) void {
    module.addAnonymousImport("vm_kernel", .{ .root_source_file = image.kernel });
    module.addAnonymousImport("vm_initramfs", .{ .root_source_file = image.initramfs });
    module.addAnonymousImport("vm_image_version", .{ .root_source_file = image.version });
    module.linkSystemLibrary("objc", .{});
    module.linkFramework("Foundation", .{});
    module.linkFramework("Virtualization", .{});
    module.linkFramework("SystemConfiguration", .{});
}

/// Builds the macOS zbx, signs it ad hoc with the virtualization entitlement (good for this Mac;
/// a Developer ID signature and notarization are the release's job) and installs it.
/// `zig build demo-mac`: the M1 to M4 demo steps and M4b's, driven from this Mac through the macOS
/// `zbx` it installs (src/testing/mac_demo.zig). Only where the build runs on macOS.
fn add_demo_mac(b: *std.Build) void {
    const exe = b.addExecutable(.{
        .name = "demo_mac",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/testing/mac_demo.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
        }),
    });
    const run = b.addRunArtifact(exe);
    run.setCwd(b.path("."));
    run.addArgs(&.{ "--zbx", "zig-out/bin/zbx" });
    run.step.dependOn(b.getInstallStep());
    const step = b.step("demo-mac", "Run the M1 to M4 and M4b demo steps from macOS, inside the VM");
    step.dependOn(&run.step);
}

/// `zig build mac-release`: the ReleaseSafe macOS `zbx`, signed with the hardened runtime and the
/// virtualization entitlement, zipped, and (with `-Dnotarize`) notarized; see src/mac_release.zig.
/// `-Dsign-identity=-` signs ad hoc, for trying it; the defaults are the owner's.
fn add_mac_release(
    b: *std.Build,
    options: *std.Build.Step.Options,
    target: std.Build.ResolvedTarget,
) void {
    const release = @import("src/mac_release.zig");
    const identity = b.option([]const u8, "sign-identity", "mac-release: the codesign identity (default: " ++
        release.default_identity ++ "; - is ad hoc)") orelse release.default_identity;
    const profile = b.option([]const u8, "notary-profile", "mac-release: the notarytool keychain profile (default: " ++
        release.default_profile ++ ")") orelse release.default_profile;
    const notarize = b.option(bool, "notarize", "mac-release: submit the archive to Apple's notary service") orelse false;
    const image = add_vm_image(b, options);
    const module = b.createModule(.{
        .root_source_file = b.path("src/macos_main.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
        .imports = &.{.{ .name = "build_options", .module = options.createModule() }},
    });
    link_macos(module, image);
    const exe = b.addExecutable(.{ .name = "zbx", .root_module = module, .use_llvm = true });
    const tool = b.addExecutable(.{
        .name = "mac_release",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/mac_release.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    const run = b.addRunArtifact(tool);
    run.setCwd(b.path("."));
    run.addArg("--binary");
    run.addArtifactArg(exe);
    run.addArgs(&.{ "--entitlements", "vm/zbx.entitlements", "--formula", "packaging/homebrew/zigbox.rb" });
    run.addArgs(&.{ "--out", "zig-out/mac-release", "--version", @import("build.zig.zon").version });
    run.addArgs(&.{ "--identity", identity, "--profile", profile });
    if (notarize) run.addArg("--notarize");
    const step = b.step("mac-release", "Sign (hardened runtime), zip and optionally notarize the macOS zbx");
    step.dependOn(&run.step);
}

fn add_macos_install(
    b: *std.Build,
    options: *std.Build.Step.Options,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const image = add_vm_image(b, options);
    const module = b.createModule(.{
        .root_source_file = b.path("src/macos_main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "build_options", .module = options.createModule() }},
    });
    link_macos(module, image);
    const exe = b.addExecutable(.{ .name = "zbx", .root_module = module, .use_llvm = true });
    add_mac_release(b, options, target);
    add_demo_mac(b);
    const copy = b.addSystemCommand(&.{"cp"});
    copy.addArtifactArg(exe);
    const signed = copy.addOutputFileArg("zbx");
    const sign = b.addSystemCommand(&.{ "codesign", "--force", "--sign", "-", "--entitlements" });
    sign.addFileArg(b.path("vm/zbx.entitlements"));
    sign.addFileArg(signed);
    sign.step.dependOn(&copy.step);
    const install = b.addInstallBinFile(signed, "zbx");
    install.step.dependOn(&sign.step);
    b.getInstallStep().dependOn(&install.step);
}
