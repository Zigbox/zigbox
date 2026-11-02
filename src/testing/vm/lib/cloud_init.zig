//! The cloud-init NoCloud seed for the test VM, served over HTTP by the session itself (no
//! genisoimage, no cloud-localds). `render_user_data` writes it from a `Config` that names
//! everything a package's demo needs; the parts every guest gets are fixed here:
//!   - one user (no sudo, no password), optionally with a subuid/subgid range;
//!   - the packages asked for, after an apt update;
//!   - sysctls persisted to one file under /etc/sysctl.d and applied with `sysctl --system`;
//!   - optionally a Delegate= drop-in for user managers, and lingering for the user, so the
//!     systemd user manager (user@<uid>.service) exists whatever way commands reach the guest;
//!   - a passwordless root shell on the serial console, which the session drives. The VM is
//!     throwaway and has no other way in;
//!   - `ready_marker` on the console when provisioning is complete.
//! Every text in a `Config` is checked to be plain (no newline, quote or other character that
//! YAML or the shell would read specially), so a value cannot change the seed's structure.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const limits = @import("limits.zig");

/// Printed on the console (by the last runcmd) when provisioning is complete.
pub const ready_marker = "ZBX-VM-PROVISIONED";

pub const User = struct {
    name: []const u8,
    uid: u32,
    shell: []const u8 = "/bin/bash",
    /// The subordinate id range for the user's namespaces, written to /etc/subuid and
    /// /etc/subgid. A count of 0 writes none.
    subid_start: u32 = 0,
    subid_count: u32 = 0,
    /// `loginctl enable-linger`, then wait for user@<uid>.service to be active.
    linger: bool = false,
};

pub const Sysctl = struct {
    key: []const u8,
    value: []const u8,
    /// Comment lines written above the setting, each without its `# `.
    comment: []const []const u8 = &.{},
};

pub const Config = struct {
    hostname: []const u8,
    instance_id: []const u8,
    user: User,
    packages: []const []const u8 = &.{},
    sysctls: []const Sysctl = &.{},
    sysctl_path: []const u8 = "/etc/sysctl.d/60-zigbox-vm.conf",
    /// Controllers delegated to user managers through a drop-in for user@.service
    /// (`cpu cpuset io memory pids`). Empty writes no drop-in: the guest's stock delegation.
    delegate_controllers: []const u8 = "",
};

pub const Error = error{ ConfigTextUnsafe, ConfigTooLarge, UserDataTooLong };

/// The prompt of the root shell on the console, which `Session.provision` waits for.
pub fn prompt(buffer: []u8, hostname: []const u8) ![]const u8 {
    assert(hostname.len > 0);
    const text = std.fmt.bufPrint(buffer, "root@{s}:~#", .{hostname}) catch
        return error.ConfigTooLarge;
    assert(std.mem.endsWith(u8, text, ":~#"));
    return text;
}

/// The NoCloud meta data: the instance id and the hostname.
pub fn render_meta_data(config: *const Config, buffer: []u8) Error![]const u8 {
    try validate(config);
    const format = "instance-id: {s}\nlocal-hostname: {s}\n";
    const text = std.fmt.bufPrint(buffer, format, .{ config.instance_id, config.hostname }) catch
        return error.ConfigTooLarge;
    assert(std.mem.startsWith(u8, text, "instance-id: "));
    return text;
}

/// The `#cloud-config` user data. The result is a slice of `buffer`.
pub fn render_user_data(config: *const Config, buffer: []u8) Error![]const u8 {
    try validate(config);
    var writer: Io.Writer = .fixed(buffer);
    write_user_data(&writer, config) catch return error.UserDataTooLong;
    const text = writer.buffered();
    assert(std.mem.startsWith(u8, text, "#cloud-config\n"));
    assert(std.mem.indexOf(u8, text, ready_marker) != null);
    return text;
}

fn write_user_data(writer: *Io.Writer, config: *const Config) Io.Writer.Error!void {
    const user = &config.user;
    try writer.writeAll("#cloud-config\nusers:\n");
    try writer.print("  - name: {s}\n    uid: {d}\n    shell: {s}\n", .{
        user.name, user.uid, user.shell,
    });
    try writer.writeAll("    lock_passwd: true\nssh_pwauth: false\n");
    if (config.packages.len > 0) {
        try writer.writeAll("package_update: true\npackages:\n");
        for (config.packages) |package| try writer.print("  - {s}\n", .{package});
    }
    try writer.writeAll("write_files:\n");
    if (config.sysctls.len > 0) {
        try writer.print("  - path: {s}\n    content: |\n", .{config.sysctl_path});
        for (config.sysctls) |sysctl| {
            for (sysctl.comment) |line| try writer.print("      # {s}\n", .{line});
            try writer.print("      {s} = {s}\n", .{ sysctl.key, sysctl.value });
        }
    }
    try writer.writeAll(autologin_dropin);
    if (config.delegate_controllers.len > 0) {
        try writer.writeAll("  - path: /etc/systemd/system/user@.service.d/delegate.conf\n" ++
            "    content: |\n      [Service]\n");
        try writer.print("      Delegate={s}\n", .{config.delegate_controllers});
    }
    try write_runcmd(writer, config);
}

/// The serial console's root autologin, which is how the session reaches the guest.
const autologin_dropin =
    \\  - path: /etc/systemd/system/serial-getty@ttyS0.service.d/zigbox-autologin.conf
    \\    content: |
    \\      [Service]
    \\      ExecStart=
    \\      ExecStart=-/sbin/agetty --autologin root --noclear %I $TERM
    \\
;

fn write_runcmd(writer: *Io.Writer, config: *const Config) Io.Writer.Error!void {
    const user = &config.user;
    try writer.writeAll("runcmd:\n");
    if (config.sysctls.len > 0) try writer.writeAll("  - sysctl --system\n");
    if (user.subid_count > 0) {
        for ([_][]const u8{ "subuid", "subgid" }) |file| {
            try writer.print("  - grep -q '^{s}:' /etc/{s} || echo '{s}:{d}:{d}' >> /etc/{s}\n", .{
                user.name, file, user.name, user.subid_start, user.subid_count, file,
            });
        }
    }
    if (user.linger) {
        try writer.print("  - loginctl enable-linger {s}\n", .{user.name});
        try writer.print("  - for i in $(seq 120); do systemctl is-active -q user@{d} && " ++
            "break; sleep 1; done\n", .{user.uid});
    }
    try writer.writeAll("  - systemctl daemon-reload\n");
    try writer.writeAll("  - echo " ++ ready_marker ++ " > /dev/console\n");
    try writer.writeAll("  - systemctl restart serial-getty@ttyS0.service\n");
}

/// Refuses a config whose texts could break out of the YAML scalar or the shell word they are
/// written into, or whose lists are over their bounds.
pub fn validate(config: *const Config) Error!void {
    if (config.hostname.len > limits.hostname_bytes_max) return error.ConfigTooLarge;
    if (config.packages.len > limits.packages_max) return error.ConfigTooLarge;
    if (config.sysctls.len > limits.sysctls_max) return error.ConfigTooLarge;
    const words = [_][]const u8{
        config.hostname,   config.instance_id, config.user.name,
        config.user.shell, config.sysctl_path,
    };
    for (words) |word| try check_word(word, false);
    try check_word(config.delegate_controllers, true);
    for (config.packages) |package| try check_word(package, false);
    for (config.sysctls) |sysctl| {
        try check_word(sysctl.key, false);
        try check_word(sysctl.value, false);
        for (sysctl.comment) |line| try check_line(line);
    }
}

/// A word: not empty (unless `may_be_empty`), and only letters, digits and `-_./@:+`, or a
/// space between words when `may_be_empty` (a controller list).
pub fn check_word(word: []const u8, may_be_empty: bool) Error!void {
    if (word.len == 0) {
        if (may_be_empty) return;
        return error.ConfigTextUnsafe;
    }
    if (word.len > limits.command_bytes_max) return error.ConfigTooLarge;
    for (word) |byte| {
        if (std.ascii.isAlphanumeric(byte)) continue;
        if (std.mem.indexOfScalar(u8, "-_./@:+", byte) != null) continue;
        if (byte == ' ') {
            if (may_be_empty) continue;
        }
        return error.ConfigTextUnsafe;
    }
}

/// A comment line: printable ASCII, with no newline or tab (YAML forbids tabs).
fn check_line(line: []const u8) Error!void {
    if (line.len > limits.command_bytes_max) return error.ConfigTooLarge;
    for (line) |byte| {
        if (byte < 0x20) return error.ConfigTextUnsafe;
        if (byte > 0x7e) return error.ConfigTextUnsafe;
    }
}

const test_config: Config = .{
    .hostname = "vm-test",
    .instance_id = "iid-vm-test",
    .user = .{ .name = "tester", .uid = 1001 },
};

test "a minimal config renders a seed with no packages, sysctls, subids or linger" {
    // Goal: every optional part is absent unless asked for, and the fixed parts are present.
    var buffer: [limits.user_data_bytes_max]u8 = undefined;
    const text = try render_user_data(&test_config, &buffer);
    try std.testing.expect(std.mem.indexOf(u8, text, "  - name: tester\n    uid: 1001\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "packages:") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "sysctl") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "/etc/subuid") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "enable-linger") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "Delegate=") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "--autologin root") != null);
    try std.testing.expect(std.mem.endsWith(u8, text, "serial-getty@ttyS0.service\n"));
    try std.testing.expect(std.mem.indexOfScalar(u8, text, '\t') == null);
    var meta: [limits.meta_data_bytes_max]u8 = undefined;
    const meta_text = try render_meta_data(&test_config, &meta);
    const meta_expected = "instance-id: iid-vm-test\nlocal-hostname: vm-test\n";
    try std.testing.expectEqualStrings(meta_expected, meta_text);
}

test "texts that could change the seed's structure are refused" {
    // Goal: a newline, quote, or empty name never reaches the YAML. Method: one bad field at a
    // time, each refused; the boundary (a space) is allowed only in the controller list.
    var buffer: [limits.user_data_bytes_max]u8 = undefined;
    const bad_words = [_][]const u8{ "", "a\nb", "a'b", "a b", "a\"b", "a;b", "a$b" };
    for (bad_words) |word| {
        var config = test_config;
        config.user.name = word;
        try std.testing.expectError(error.ConfigTextUnsafe, render_user_data(&config, &buffer));
        config = test_config;
        config.packages = &.{word};
        try std.testing.expectError(error.ConfigTextUnsafe, render_user_data(&config, &buffer));
    }
    var config = test_config;
    config.delegate_controllers = "cpu memory pids";
    _ = try render_user_data(&config, &buffer);
    config.delegate_controllers = "cpu\nmemory";
    try std.testing.expectError(error.ConfigTextUnsafe, render_user_data(&config, &buffer));
    config = test_config;
    config.sysctls = &.{.{ .key = "a.b", .value = "0", .comment = &.{"tab\there"} }};
    try std.testing.expectError(error.ConfigTextUnsafe, render_user_data(&config, &buffer));
}

test "a seed over its buffer is an error, not a truncated seed" {
    // Goal: the fixed buffer bounds the seed. Method: render into a buffer one byte short.
    var buffer: [limits.user_data_bytes_max]u8 = undefined;
    const text = try render_user_data(&test_config, &buffer);
    var short: [limits.user_data_bytes_max]u8 = undefined;
    const fits = try render_user_data(&test_config, short[0..text.len]);
    try std.testing.expectEqual(text.len, fits.len);
    const refused = render_user_data(&test_config, short[0 .. text.len - 1]);
    try std.testing.expectError(error.UserDataTooLong, refused);
    const many: [limits.packages_max + 1][]const u8 = @splat("p");
    var config = test_config;
    config.packages = &many;
    try std.testing.expectError(error.ConfigTooLarge, render_user_data(&config, &buffer));
}

test "the console prompt names the host" {
    var buffer: [80]u8 = undefined;
    try std.testing.expectEqualStrings("root@vm-test:~#", try prompt(&buffer, "vm-test"));
    var tiny: [4]u8 = undefined;
    try std.testing.expectError(error.ConfigTooLarge, prompt(&tiny, "vm-test"));
}
