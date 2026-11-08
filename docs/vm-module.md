# The VM module (`zigbox_vm`)

Zigbox's VM demos boot a throwaway Ubuntu 24.04 guest under QEMU, provision it with cloud-init and drive it over its serial console. That harness is a public module of the `zigbox` package, `zigbox_vm`, so that another package (Zigcube's real-runtime smoke test) boots the same guest the same way instead of keeping a copy. The Zigbox demos (`zig build demo-mN`) are built on it.

Source: `src/testing/vm/lib/`, root `zigbox_vm.zig`. Standard library only, no libc. The only external programs are QEMU's (`qemu-img`, `qemu-system-x86_64`) on the host and `curl` in the guest (for `copy_in`).

## What it exposes

| Name | What it does |
| --- | --- |
| `cloud_init.Config` | The guest's user (name, uid, shell, subuid/subgid range, linger), packages, sysctls (with their file and comments), cgroup controllers delegated to user managers, hostname and instance id. Every text is checked to be plain, so a value cannot change the seed's structure. |
| `cloud_init.render_user_data`, `render_meta_data` | Render a `Config` into a caller's buffer (`limits.user_data_bytes_max`, `limits.meta_data_bytes_max`). Fixed parts of every seed: the root autologin on the serial console, and `cloud_init.ready_marker` printed when provisioning is done. |
| `image.ubuntu_noble`, `image.Pin` | The pinned Ubuntu 24.04 cloud image (dated release, SHA-256, `lib/image.zon`), and the type for any file pinned by URL and SHA-256. |
| `image.ensure_pin` | Finds a pinned file in a cache directory, checks its SHA-256, downloads it with `std.http` (honouring the proxy variables) if absent or wrong. |
| `image.debian_12`, `image.fedora_45`, `image.rocky_9` | The other guests, pinned in `lib/guests.zon` (URL and SHA-256, with where each checksum came from). Used by the M8 packages check; Zigcube may ignore them. |
| `image.make_overlay_sized` | `make_overlay` with an explicit virtual size (`"12G"`), for a base larger than the default overlay (Rocky's image is 10 GiB). |
| `image.make_overlay`, `image.ensure_raw_disk` | A qcow2 overlay on the base image for one run (the base is never written), and a sparse raw disk kept between runs (a cache). |
| `Config.console_prompt`, `Seed.seed_id` | Both default to the Ubuntu behaviour (seed bytes and QEMU arguments unchanged). `console_prompt = true` writes `/etc/profile.d/zigbox-console.sh` so the root shell prompt is `root@host:~#` on Fedora and Rocky. `seed_id = "nocloud-net"` is for cloud-init older than 23 (Debian 12's 22.4 drops a URL seed given as `ds=nocloud`). |
| `accel.choose`, `accel.kvm_usable` | `auto` means KVM and fails with `error.NoKvm` without it; TCG only when asked for by name. Timeouts scale by `limits.tcg_timeout_factor` under TCG. |
| `Session.start(init, out, overlay, accel, seed)` | Starts the HTTP server on 127.0.0.1 (the guest reaches it at 10.0.2.2) and QEMU. A `Seed` holds the rendered user data and meta data, the files to serve (`Route`: path and body, borrowed), and extra raw disks. |
| `Seed.forwards` | TCP forwards from the host into the guest: a list of `Forward{ .host_address = 127.0.0.1, .host_port, .guest_port }`, at most `limits.forwards_max` (8), rendered as `-netdev user,id=net0,hostfwd=tcp:127.0.0.1:H-:G`. Host port 0 is not supported (QEMU's choice cannot be read back with `-monitor none`): name every host port, and make them unique per guest and per run (several guests on one host need different ports). A bad list is one coded line, `vm: VM-F001` to `VM-F004`, and `error.BadForward` before anything starts. No forwards: the QEMU command line is unchanged. |
| `Session.provision(hostname, reuse)` | Waits for the ready marker and the root prompt, quiets the shell, and waits for cloud-init and systemd to settle. `reuse` boots an overlay that was already provisioned. |
| `Session.run(command, timeout_s)` | The exec channel: runs a command in the root shell and returns its combined output (cleaned of escape sequences) and exit status. `send`, `wait_for` and `pump` drive the console directly (a Ctrl-C, a long-running command). |
| `Session.copy_in(.{ .route, .guest_path, .owner, .mode })` | Fetches a served file into the guest, sets owner and mode, and returns the `ls -l` line. |
| `Session.put_file(path, text)` | Types a small file (up to `limits.put_file_bytes_max`) into the guest through base64. |
| `Session.shutdown`, `Session.deinit` | Powers the guest off and waits for QEMU; `deinit` kills QEMU if it is still running and stops the server (safe after `shutdown`, and on every error path). |
| `limits` | Every bound the module uses, with comptime checks on how they relate. |

The guest channel is the serial console, not SSH: the console needs no host `ssh` client and no per-run key in a throwaway VM, and it is the one external program (QEMU) the style guide allows.

What stays with the caller: which binaries to serve and where they go, which packages and sysctls the guest needs, its user and subuid range, linger and delegation, the overlay's path and whether to keep it, and what to run. Zigbox's own choices are in `src/testing/vm/cloud_init.zig` (the `demo` user, `uidmap`, `passt`, the userns sysctl) and `src/testing/vm/session.zig` (the `/zbx`, `/zbx-old`, `/ca.crt` and `/rootfs.tar.gz` routes).

## Using it from another package

`build.zig.zon`:

```zig
.dependencies = .{
    .zigbox = .{ .url = "git+https://github.com/zigbox/zigbox#<commit>", .hash = "..." },
},
```

`build.zig`:

```zig
const zigbox = b.dependency("zigbox", .{});
const smoke = b.addExecutable(.{
    .name = "smoke",
    .root_module = b.createModule(.{
        .root_source_file = b.path("src/smoke.zig"),
        .target = b.graph.host,
        .optimize = .ReleaseSafe,
        .imports = &.{.{ .name = "zigbox_vm", .module = zigbox.module("zigbox_vm") }},
    }),
});
```

The module takes its target and optimize mode from the module that imports it. It runs on a Linux host only.

A run:

```zig
const std = @import("std");
const vm = @import("zigbox_vm");

const config: vm.Config = .{
    .hostname = "zigcube-smoke",
    .instance_id = "iid-zigcube-smoke",
    .user = .{ .name = "cube", .uid = 1000, .subid_start = 100000, .subid_count = 65536, .linger = true },
    .packages = &.{"uidmap"},
    .sysctls = &.{.{ .key = "kernel.apparmor_restrict_unprivileged_userns", .value = "0" }},
};

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    var buffer: [4096]u8 = undefined;
    var stdout: std.Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &stdout.interface;
    defer out.flush() catch {};
    const accel = try vm.accel.choose("auto", vm.accel.kvm_usable(init.io));
    const base = try vm.image.ensure_pin(init, ".zig-cache/vm", out, vm.image.ubuntu_noble);
    const overlay = ".zig-cache/vm/overlay-smoke.qcow2";
    try vm.image.make_overlay(init, base, overlay);
    defer std.Io.Dir.cwd().deleteFile(init.io, overlay) catch {};

    var user_data: [vm.limits.user_data_bytes_max]u8 = undefined;
    var meta_data: [vm.limits.meta_data_bytes_max]u8 = undefined;
    const agent = try std.Io.Dir.cwd().readFileAlloc(init.io, "zig-out/bin/agent", arena, .unlimited);
    var session: vm.Session = undefined;
    try session.start(init, out, overlay, accel, .{
        .user_data = try vm.cloud_init.render_user_data(&config, &user_data),
        .meta_data = try vm.cloud_init.render_meta_data(&config, &meta_data),
        .files = &.{.{ .path = "/agent", .body = agent }},
    });
    defer session.deinit();
    try session.provision(config.hostname, false);
    _ = try session.copy_in(.{ .route = "/agent", .guest_path = "/home/cube/agent", .owner = "cube:cube", .mode = "755" });
    const result = try session.run("runuser -u cube -- /home/cube/agent --version", vm.limits.command_timeout_kvm_s);
    if (result.status != 0) return 1;
    try session.shutdown();
    return 0;
}
```

A guest listener is reachable from the host like this (`zig build demo-z7` does it in a VM):

```zig
try session.start(init, out, overlay, accel, .{
    .user_data = user_data,
    .meta_data = meta_data,
    .forwards = &.{.{ .host_port = 18729, .guest_port = 9000 }},
});
// ... start a listener on guest port 9000, then connect to 127.0.0.1:18729 on the host.
```

`session` must not move after `start` (its HTTP server borrows from it), and served bodies must outlive it. Everything the console prints is echoed to `out` with a `  vm| ` prefix, so a failure has the whole console above it.

A run as an ordinary user needs read-write access to `/dev/kvm`; CI's `ubuntu-24.04` runners get it from a udev rule (`.github/workflows/vm.yml`). Cache the base image keyed on `lib/image.zon`.
