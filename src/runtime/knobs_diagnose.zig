//! The diagnostics of the workload knobs (ZBX-E0310 to ZBX-E0318): a `--ulimit`, `--shm-size`
//! or `--sysctl` that is refused before the run starts, and the child's step that set one and
//! failed. Only the parent calls this; nothing here prints.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const codes = @import("../diag/codes.zig");
const errors = @import("../diag/errors.zig");
const Diag = @import("../diag/diag.zig").Diag;
const host_mod = @import("../host.zig");
const knobs = @import("knobs.zig");

const linux = std.os.linux;

/// Why a `/dev/shm` size is refused: E0313, except `above_memory`, which is E0314.
pub const ShmIssue = enum {
    /// Not a size in `--memory`'s syntax.
    not_a_size,
    /// Below one page.
    below_page,
    /// Above the host's `MemTotal`, with no `--memory`.
    above_host,
    /// No `--memory`, and the host's `MemTotal` can't be read to bound it.
    host_unknown,
    /// Above `--memory`.
    above_memory,
};

/// ZBX-E0310: a `--ulimit` that does not parse, or a library caller's soft limit above its hard.
pub fn ulimit_invalid(diag: *Diag, text: []const u8, problem: knobs.UlimitProblem) void {
    assert(diag.code == null);
    assert(text.len <= constants.arg_bytes_max);
    diag.raise(.E0310);
    diag.while_("reading --ulimit", .{});
    diag.context("ulimit", "{s}", .{text});
    switch (problem) {
        .no_value => diag.cause("'{s}' has no value: write name=soft[:hard]", .{text}),
        .unknown_name => diag.cause("zbx sets only nofile, nproc, memlock and stack", .{}),
        .not_a_number => diag.cause("the value is not a count, a size or unlimited", .{}),
        .too_large => diag.cause("the value is past what the kernel can hold", .{}),
        .soft_above_hard => diag.cause("the soft limit is above the hard one", .{}),
        .repeated => diag.cause("the same resource is set twice", .{}),
    }
    diag.fix(.{
        .sentence = "a valid limit looks like this:",
        .command = "zbx run --rootfs ./alpine --ulimit nofile=1024:65536 -- /bin/sh",
        .template = true,
    });
    assert(diag.code.? == .E0310);
    assert(diag.causes.count == 1);
}

/// ZBX-E0311: a hard limit above the invoking user's own. Raising one needs `CAP_SYS_RESOURCE`
/// in the host's user namespace, which a rootless run never has; zbx never sets a lower one.
pub fn ulimit_above_hard(
    diag: *Diag,
    resource: knobs.Resource,
    asked: u64,
    user_hard: u64,
    uid: u32,
) void {
    assert(diag.code == null);
    assert(asked > user_hard);
    var asked_buffer: [24]u8 = undefined;
    var hard_buffer: [24]u8 = undefined;
    const asked_text = value_text(asked, &asked_buffer);
    const hard_text = value_text(user_hard, &hard_buffer);
    diag.raise(.E0311);
    diag.while_("checking --ulimit {s}", .{@tagName(resource)});
    diag.context("asked", "{s}", .{asked_text});
    diag.context("hard", "{s}", .{hard_text});
    diag.cause("--ulimit {s} asks for a hard limit of {s}, above your own, {s}; a rootless " ++
        "run can't raise it", .{ @tagName(resource), asked_text, hard_text });
    diag.context("unit", "{s}={s}", .{ resource.systemd_property(), asked_text });
    diag.fix_with(
        "for login sessions, raise it in limits.conf, then log in again:",
        "echo \"$(id -un) hard {s} {s}\" | sudo tee -a /etc/security/limits.conf",
        .{ @tagName(resource), asked_text },
    );
    diag.fix_with(
        "for the systemd user manager, put the unit line under [Service], then log in again:",
        "sudo systemctl edit user@{d}.service",
        .{uid},
    );
    assert(diag.code.? == .E0311);
    assert(diag.fixes.count > 0);
}

/// A limit as `ulimit` writes it: a number, or `unlimited`.
fn value_text(value: u64, buffer: *[24]u8) []const u8 {
    if (value == knobs.unlimited) return "unlimited";
    // Cannot fail: a u64 has at most 20 digits and the buffer holds 24.
    const result = std.fmt.bufPrint(buffer, "{d}", .{value}) catch unreachable;
    assert(result.len > 0);
    return result;
}

/// ZBX-E0312: the child's `setrlimit` failed, after the parent's check let it through.
pub fn rlimit_failed(
    diag: *Diag,
    operation: []const u8,
    resource: knobs.Resource,
    err: host_mod.Error,
    errno: u16,
) void {
    assert(diag.code == null);
    assert(operation.len > 0);
    diag.raise(.E0312);
    diag.context("ulimit", "{s}", .{@tagName(resource)});
    errors.cause_host_error(diag, operation, err, errno);
    diag.cause("the limit passed zbx's check against your own, so a security policy or a " ++
        "change to your limits since is the usual reason", .{});
    diag.fix_with("check your limits:", "ulimit -a -H", .{});
    diag.fix(.{ .sentence = "check what this host allows:", .command = "zbx doctor" });
    assert(diag.code.? == .E0312);
    assert(diag.fixes.count > 0);
}

/// ZBX-E0313 and ZBX-E0314: a `/dev/shm` size that is refused. `text` is what the user wrote, or
/// the number a library caller gave; `bound` is the page, `MemTotal` or `--memory` it broke.
pub fn shm_invalid(diag: *Diag, text: []const u8, issue: ShmIssue, bound: u64) void {
    assert(diag.code == null);
    assert(text.len <= constants.arg_bytes_max);
    diag.raise(if (issue == .above_memory) .E0314 else .E0313);
    diag.while_("reading --shm-size", .{});
    diag.context("size", "{s}", .{text});
    switch (issue) {
        .not_a_size => diag.cause("'{s}' is not a size: use digits and k, m or g, as in 256m", .{
            text,
        }),
        .below_page => diag.cause("/dev/shm needs at least one page, {d} bytes", .{bound}),
        .above_host => diag.cause("the host has {d} MiB of memory, and /dev/shm's pages are " ++
            "memory", .{bound >> 20}),
        .host_unknown => diag.cause("without --memory, /dev/shm is bounded by the host's " ++
            "memory, and /proc/meminfo can't be read", .{}),
        .above_memory => diag.cause("/dev/shm's pages are charged to the container's memory " ++
            "limit, {d} MiB, so a larger /dev/shm can never fill", .{bound >> 20}),
    }
    if (issue == .above_memory or issue == .host_unknown) {
        diag.fix(.{
            .sentence = "raise --memory, or lower --shm-size to at most it:",
            .command = "zbx run --rootfs ./alpine --memory 512m --shm-size 256m -- /bin/sh",
            .template = true,
        });
    } else {
        diag.fix(.{
            .sentence = "a valid size looks like this:",
            .command = "zbx run --rootfs ./alpine --shm-size 256m -- /bin/sh",
            .template = true,
        });
    }
    assert(diag.code != null);
    assert(diag.causes.count == 1);
}

/// ZBX-E0315, ZBX-E0316 and ZBX-E0317: the first refused `--sysctl` of a run.
pub fn sysctl_invalid(diag: *Diag, list: []const knobs.Sysctl, problem: knobs.ListProblem) void {
    assert(diag.code == null);
    assert(list.len > 0);
    switch (problem) {
        .too_many => {
            diag.raise(.E0315);
            diag.while_("reading --sysctl", .{});
            diag.cause("a run takes at most {d} --sysctl options", .{constants.sysctls_max});
        },
        .malformed => |found| sysctl_malformed(diag, list[found.index], found.problem),
        .repeated => |index| {
            sysctl_raise(diag, .E0315, list[index]);
            diag.cause("{s} is set twice", .{list[index].key});
        },
        .host_setting => |index| sysctl_host_setting(diag, list[index]),
        .shared_network => |index| {
            sysctl_raise(diag, .E0317, list[index]);
            diag.cause("with --net host the container shares the host's network namespace, so " ++
                "{s} would change the host", .{list[index].key});
            diag.fix(.{ .sentence = "drop --net host, so the container has a network of its own" });
        },
    }
    if (diag.fixes.count == 0) diag.fix(.{
        .sentence = "a valid sysctl looks like this:",
        .command = "zbx run --rootfs ./alpine --sysctl net.core.somaxconn=8192 -- /bin/sh",
        .template = true,
    });
    assert(diag.code != null);
    assert(diag.causes.count > 0);
}

fn sysctl_raise(diag: *Diag, code: codes.Code, sysctl: knobs.Sysctl) void {
    assert(diag.code == null);
    assert(sysctl.key.len > 0);
    diag.raise(code);
    diag.while_("reading --sysctl", .{});
    diag.context("sysctl", "{s}", .{sysctl.key});
}

fn sysctl_malformed(diag: *Diag, sysctl: knobs.Sysctl, problem: knobs.SysctlProblem) void {
    assert(diag.code == null);
    diag.raise(.E0315);
    diag.while_("reading --sysctl", .{});
    if (sysctl.key.len > 0) diag.context("sysctl", "{s}", .{sysctl.key});
    switch (problem) {
        .no_value => diag.cause("'{s}' has no value: write key=value", .{sysctl.key}),
        .key_malformed => diag.cause("the key is not in dot form, as in net.core.somaxconn", .{}),
        .value_empty => diag.cause("the value is empty", .{}),
        .value_too_long => diag.cause("the value is {d} bytes; at most {d} are allowed", .{
            sysctl.value.len, constants.sysctl_value_bytes_max,
        }),
        .value_not_printable => diag.cause("the value holds a byte that is not printable " ++
            "ASCII, such as a newline", .{}),
    }
    assert(diag.code.? == .E0315);
}

fn sysctl_host_setting(diag: *Diag, sysctl: knobs.Sysctl) void {
    assert(diag.code == null);
    assert(knobs.lookup(sysctl.key) == null);
    sysctl_raise(diag, .E0316, sysctl);
    diag.cause("{s} is a host setting, not one of the container's own namespaces, so a " ++
        "container can't set it", .{sysctl.key});
    if (knobs.is_host_setting(sysctl.key)) {
        diag.fix_with("set it on the host instead:", "sudo sysctl -w {s}=<value>", .{sysctl.key});
        diag.mark_last_fix_template();
    }
    diag.fix(.{ .sentence = "the keys a container may set:", .command = "zbx explain E0316" });
    assert(diag.code.? == .E0316);
}

/// ZBX-E0318: the kernel refused a sysctl's value, or writing it failed. `path` is the file the
/// child wrote, beneath the container's `/proc/sys`.
pub fn sysctl_failed(
    diag: *Diag,
    operation: []const u8,
    path: []const u8,
    value: []const u8,
    err: host_mod.Error,
    errno: u16,
) void {
    assert(diag.code == null);
    assert(std.mem.startsWith(u8, path, knobs.proc_path_prefix));
    var key_buffer: [knobs.key_bytes_max]u8 = undefined;
    const key = key_of(path, &key_buffer);
    diag.raise(.E0318);
    diag.context("sysctl", "{s}={s}", .{ key, value });
    if (errno == @backingInt(linux.E.INVAL)) {
        diag.cause("the kernel refused {s}={s}: not a value this key takes", .{ key, value });
        if (std.mem.eql(u8, key, "net.ipv4.ping_group_range")) {
            diag.cause("its group ids must be ones the container has: within its id map", .{});
        }
    } else {
        errors.cause_host_error(diag, operation, err, errno);
    }
    diag.fix_with("read the key's current value on the host for its form:", "sysctl {s}", .{key});
    assert(diag.code.? == .E0318);
    assert(diag.causes.count > 0);
}

/// The dot form of a `/proc/sys` path.
fn key_of(path: []const u8, buffer: *[knobs.key_bytes_max]u8) []const u8 {
    const rest = path[knobs.proc_path_prefix.len..];
    assert(rest.len > 0);
    assert(rest.len <= buffer.len);
    for (rest, buffer[0..rest.len]) |byte, *out| out.* = if (byte == '/') '.' else byte;
    return buffer[0..rest.len];
}
