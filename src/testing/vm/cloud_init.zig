//! The cloud-init seed of Zigbox's demo VM, as a `zigbox_vm.cloud_init.Config`. Provisioning,
//! in the order it happens:
//!   - user `demo` (uid 1000, no sudo, no password) with subuid/subgid 100000:65536;
//!   - `uidmap` installed (newuidmap/newgidmap, setuid root);
//!   - `passt` (pasta, for `--net user`) and `iptables` (demo-m5 reads the rules before and after);
//!   - `postgresql-client` (`psql` and `pg_isready`, for the state volumes of M6);
//!   - kernel.apparmor_restrict_unprivileged_userns=0 persisted: Ubuntu 24.04 ships it as 1,
//!     which refuses user namespaces to unconfined users, and doctor rightly reports that;
//!   - lingering enabled for demo, so the systemd user manager (user@1000.service) exists
//!     whatever way commands reach the guest;
//!   - a passwordless root shell on the serial console (the module's part of every seed).
//! Nothing here sets Delegate=: the demo shows what stock Ubuntu delegates (see docs/demos/m0.md).

const std = @import("std");
const vm = @import("zigbox_vm");

pub const hostname = "zigbox-demo";
pub const instance_id = "iid-zigbox-demo-m0";
pub const ready_marker = vm.cloud_init.ready_marker;

/// The seed every demo boots with.
pub const config: vm.Config = .{
    .hostname = hostname,
    .instance_id = instance_id,
    .user = .{
        .name = "demo",
        .uid = 1000,
        .subid_start = 100000,
        .subid_count = 65536,
        .linger = true,
    },
    .packages = &.{ "uidmap", "passt", "iptables", "postgresql-client" },
    .sysctls = &.{.{
        .key = "kernel.apparmor_restrict_unprivileged_userns",
        .value = "0",
        .comment = &.{
            "Host prerequisite of the Zigbox demo: Ubuntu 24.04 defaults this to 1, which refuses",
            "user namespaces to unconfined users. zbx doctor reports it when it is 1.",
        },
    }},
    .sysctl_path = "/etc/sysctl.d/60-zigbox-userns.conf",
};

/// demo-m0's experiment (`-Ddelegate-dropin`): the systemd drop-in that delegates controllers
/// to user managers. It is a prerequisite of the demo only if stock Ubuntu does not delegate
/// cpu, memory and pids already.
pub const config_with_delegate: vm.Config = config: {
    var with = config;
    with.delegate_controllers = "cpu cpuset io memory pids";
    break :config with;
};

/// The seed as it was written by hand before the VM module rendered it. The demos' guests must
/// be provisioned exactly as before, so the rendering is checked against it byte for byte.
const user_data_before =
    \\#cloud-config
    \\users:
    \\  - name: demo
    \\    uid: 1000
    \\    shell: /bin/bash
    \\    lock_passwd: true
    \\ssh_pwauth: false
    \\package_update: true
    \\packages:
    \\  - uidmap
    \\  - passt
    \\  - iptables
    \\  - postgresql-client
    \\write_files:
    \\  - path: /etc/sysctl.d/60-zigbox-userns.conf
    \\    content: |
    \\      # Host prerequisite of the Zigbox demo: Ubuntu 24.04 defaults this to 1, which refuses
    \\      # user namespaces to unconfined users. zbx doctor reports it when it is 1.
    \\      kernel.apparmor_restrict_unprivileged_userns = 0
    \\  - path: /etc/systemd/system/serial-getty@ttyS0.service.d/zigbox-autologin.conf
    \\    content: |
    \\      [Service]
    \\      ExecStart=
    \\      ExecStart=-/sbin/agetty --autologin root --noclear %I $TERM
    \\
;

const delegate_before =
    \\  - path: /etc/systemd/system/user@.service.d/delegate.conf
    \\    content: |
    \\      [Service]
    \\      Delegate=cpu cpuset io memory pids
    \\
;

const runcmd_before =
    \\runcmd:
    \\  - sysctl --system
    \\  - grep -q '^demo:' /etc/subuid || echo 'demo:100000:65536' >> /etc/subuid
    \\  - grep -q '^demo:' /etc/subgid || echo 'demo:100000:65536' >> /etc/subgid
    \\  - loginctl enable-linger demo
    \\  - for i in $(seq 120); do systemctl is-active -q user@1000 && break; sleep 1; done
    \\  - systemctl daemon-reload
    \\  - echo ZBX-VM-PROVISIONED > /dev/console
    \\  - systemctl restart serial-getty@ttyS0.service
    \\
;

test "the rendered seed is byte for byte the seed the demos booted with before the module" {
    // Goal: moving the seed into the VM module changed nothing a guest sees. Method: render both
    // configs and compare with the hand-written seed of the previous harness, with and without
    // the delegation drop-in; the meta data too.
    var buffer: [vm.limits.user_data_bytes_max]u8 = undefined;
    const plain = try vm.cloud_init.render_user_data(&config, &buffer);
    try std.testing.expectEqualStrings(user_data_before ++ runcmd_before, plain);
    const delegated = try vm.cloud_init.render_user_data(&config_with_delegate, &buffer);
    const expected = user_data_before ++ delegate_before ++ runcmd_before;
    try std.testing.expectEqualStrings(expected, delegated);
    var meta: [vm.limits.meta_data_bytes_max]u8 = undefined;
    const meta_text = try vm.cloud_init.render_meta_data(&config, &meta);
    const meta_before = "instance-id: iid-zigbox-demo-m0\nlocal-hostname: zigbox-demo\n";
    try std.testing.expectEqualStrings(meta_before, meta_text);
}

test "user data is cloud-config, provisions the demo user, and sets no Delegate by default" {
    // Goal: the fixed facts the demo depends on are in the seed, and the stock-delegation
    // experiment is real: no Delegate= unless asked.
    var buffer: [vm.limits.user_data_bytes_max]u8 = undefined;
    const user_data = try vm.cloud_init.render_user_data(&config, &buffer);
    try std.testing.expect(std.mem.indexOf(u8, user_data, "enable-linger demo") != null);
    try std.testing.expect(std.mem.indexOf(u8, user_data, "Delegate=") == null);
    try std.testing.expect(std.mem.indexOf(u8, user_data, ready_marker) != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, user_data, '\t') == null);
}
