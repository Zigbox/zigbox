//! The diagnostic registry: every code zbx can show, declared once (DIAGNOSTICS.md, "Codes").
//!
//! A code is an enum tag, so naming one that is not declared does not compile. The `comptime`
//! block below fails the build if the registry and the enum disagree, if a tag has the wrong
//! prefix or kind letter for its severity, if a summary or explanation is missing or malformed,
//! or if blame and severity contradict each other. The long explanations are what
//! `zbx explain` prints offline.
//!
//! Numbering: `00xx` CLI and general, `01xx` host and doctor (one code per doctor check),
//! `02xx` runtime and isolation, `03xx` limits, `04xx` store, `05xx` registry and pull,
//! `06xx` network, `07xx` state, `08xx` build, `09xx` trust and policy. A code is never reused
//! or renumbered.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const text_util = @import("../text.zig");

pub const Severity = enum { @"error", warning, note, bug };

/// Whose problem it is. This decides the exit code (see `exit_code`).
pub const Blame = enum { user, environment, external, internal };

/// Every code, in registry order: `registry[i].code` is the i-th tag. The tag is the part of the
/// code after "ZBX-": a kind letter (E error, W warning, B bug) and four digits.
pub const Code = enum(u8) {
    E0001,
    E0002,
    E0003,
    E0004,
    E0005,
    E0006,
    E0007,
    E0008,
    E0009,
    E0101,
    E0102,
    E0103,
    E0104,
    E0105,
    E0106,
    E0201,
    E0202,
    E0203,
    E0204,
    E0205,
    E0206,
    W0201,
    W0202,
    W0203,
    E0701,
    E0702,
    E0703,
    E0704,
    W0701,
    B0001,
};

pub const Entry = struct {
    code: Code,
    severity: Severity,
    blame: Blame,
    /// One line, present tense, no trailing period. Fixed per code: what varies goes in causes.
    summary: []const u8,
    /// Printed by `zbx explain`: what it means, why it happens, what to do. Hard-wrapped.
    explanation: []const u8,
};

pub const registry = [_]Entry{
    .{
        .code = .E0001,
        .severity = .@"error",
        .blame = .user,
        .summary = "unknown command",
        .explanation =
        \\zbx was given a first word that is not one of its commands. Command names
        \\are matched exactly: "Help" and "version" are not "help" and "--version".
        \\
        \\Run "zbx help" for the list of commands. Options such as --verbose may come
        \\before or after the command.
        ,
    },
    .{
        .code = .E0002,
        .severity = .@"error",
        .blame = .user,
        .summary = "no command given",
        .explanation =
        \\zbx needs a command and was given none, only options or nothing at all.
        \\
        \\Run "zbx help" for the list of commands, or "zbx doctor" to check whether
        \\this machine can run zbx.
        ,
    },
    .{
        .code = .E0003,
        .severity = .@"error",
        .blame = .user,
        .summary = "unexpected arguments",
        .explanation =
        \\The command takes fewer arguments than it was given. "doctor", "help" and
        \\"--version" take none; "explain" takes exactly one code; "run" takes its
        \\command only after "--".
        \\
        \\Remove the extra arguments. The message names the first one zbx ignored.
        ,
    },
    .{
        .code = .E0004,
        .severity = .@"error",
        .blame = .user,
        .summary = "unknown option",
        .explanation =
        \\An argument starting with a dash is not an option zbx knows. The options are
        \\-v and --verbose, and --output text or --output json (also written
        \\--output=json); "run" also takes --rootfs and --name. "--help" and
        \\"--version" are commands, not options.
        \\
        \\Run "zbx help" for the full list.
        ,
    },
    .{
        .code = .E0005,
        .severity = .@"error",
        .blame = .user,
        .summary = "option has a missing or invalid value",
        .explanation =
        \\--output needs a value, and the only values are "text" and "json".
        \\--rootfs and --name need one too, a directory and a name. Either the
        \\value is missing (the option was last, or empty) or it is wrong.
        \\
        \\Write --output json or --output=json. With json, every failure is written
        \\to stderr as one JSON object per line, for scripts and CI.
        ,
    },
    .{
        .code = .E0006,
        .severity = .@"error",
        .blame = .user,
        .summary = "missing argument",
        .explanation =
        \\The command needs an argument and was given none. "zbx explain" needs the
        \\code of a diagnostic, for example E0001 or ZBX-E0001; "zbx run" needs
        \\--rootfs <dir> and, after "--", the command to run.
        \\
        \\The code is printed in the first line of every diagnostic, between
        \\"error[" and "]".
        ,
    },
    .{
        .code = .E0007,
        .severity = .@"error",
        .blame = .user,
        .summary = "unknown diagnostic code",
        .explanation =
        \\"zbx explain" was given a code that zbx does not have. Codes are a letter
        \\and four digits, optionally with the "ZBX-" prefix: E0001, ZBX-E0001. Codes
        \\that start with "ZC-" belong to Zigcube, and "zcube explain" shows those.
        \\
        \\Copy the code from the first line of the diagnostic you saw.
        ,
    },
    .{
        .code = .E0008,
        .severity = .@"error",
        .blame = .user,
        .summary = "command line exceeds the supported limits",
        .explanation =
        \\zbx accepts at most 64 arguments of at most 4096 bytes each, and refuses
        \\more instead of cutting them, so that a command is never silently
        \\misread. The command after "run --" has its own limits: 48 words of at
        \\most 4000 bytes, 32 KiB with the environment.
        \\
        \\Pass fewer or shorter arguments. For long lists, use a file when the
        \\command supports one.
        ,
    },
    .{
        .code = .E0009,
        .severity = .@"error",
        .blame = .environment,
        .summary = "can't write output",
        .explanation =
        \\zbx could not write to its standard output or standard error. The usual
        \\causes are a full disk behind a redirect, a closed pipe, or a terminal that
        \\has gone away. The command itself may have worked.
        \\
        \\Free space or fix the redirect, then run the command again. If stderr is
        \\what failed, this message could not be shown, and only the exit code (2)
        \\tells you.
        ,
    },
    .{
        .code = .E0101,
        .severity = .@"error",
        .blame = .environment,
        .summary = "can't create a user namespace",
        .explanation =
        \\zbx runs containers without root, and that needs user namespaces. The kernel
        \\refused to create one for this user, or a setting forbids it.
        \\
        \\Common causes: user.max_user_namespaces is 0;
        \\kernel.unprivileged_userns_clone is 0 (Debian);
        \\kernel.apparmor_restrict_unprivileged_userns is 1 (the Ubuntu 24.04
        \\default), which blocks unconfined programs; or a security policy or a
        \\seccomp filter denies the call although the settings allow it.
        \\
        \\The diagnostic names the cause that applies and prints the command that
        \\fixes it. If the check could not run at all (an unreadable file, a probe
        \\that timed out or was killed), the cause says so; fix that first. Then run
        \\"zbx doctor".
        ,
    },
    .{
        .code = .E0102,
        .severity = .@"error",
        .blame = .environment,
        .summary = "kernel version is unsupported or unknown",
        .explanation =
        \\zbx needs Linux 5.15 or newer. Overlayfs mounts inside user namespaces
        \\arrived in 5.11, and 5.15 is the oldest long-term kernel that has them.
        \\
        \\This is also reported when the kernel release cannot be read or is not a
        \\version number zbx can parse, because zbx does not guess. The cause says
        \\which of the three happened.
        \\
        \\Upgrade the kernel, or run zbx on a host with a supported one. Containers
        \\share the host's kernel, so inside a container the host's version counts.
        ,
    },
    .{
        .code = .E0103,
        .severity = .@"error",
        .blame = .environment,
        .summary = "cgroup v2 is not set up for this user",
        .explanation =
        \\zbx limits a container's cpu, memory and process count through cgroup v2,
        \\and asks systemd to create the container's cgroup under the user's own
        \\manager, user@UID.service. That needs cgroup v2 mounted at /sys/fs/cgroup, a
        \\systemd user manager for the user, and the cpu, memory and pids controllers
        \\delegated to it.
        \\
        \\The diagnostic says which of these is missing. A cgroup v1 or hybrid host
        \\needs systemd.unified_cgroup_hierarchy=1 on the kernel command line. Missing
        \\controllers are fixed with a Delegate= drop-in for user@.service, a daemon-
        \\reload and a fresh login. If the check could not run, the cause says why.
        ,
    },
    .{
        .code = .E0104,
        .severity = .@"error",
        .blame = .environment,
        .summary = "can't mount overlayfs in a user namespace",
        .explanation =
        \\zbx builds a container's root file system with overlayfs, mounted by an
        \\unprivileged user inside a user and mount namespace. The doctor tried
        \\exactly that in a scratch directory and it failed.
        \\
        \\Causes: the overlay module is not loaded or not built in, the kernel is
        \\older than 5.11, a security policy forbids the mount, or the user namespace
        \\itself could not be created (fix ZBX-E0101 first: the same permission is
        \\needed).
        \\
        \\Try "sudo modprobe overlay", then run "zbx doctor" again. If the check could
        \\not run, the cause says why.
        ,
    },
    .{
        .code = .E0105,
        .severity = .@"error",
        .blame = .environment,
        .summary = "uid and gid mapping is not set up",
        .explanation =
        \\A rootless container maps its users onto a range of ids that the host user
        \\owns. That needs a range of at least 65536 subordinate ids for the user in
        \\both /etc/subuid and /etc/subgid, and the setuid helpers newuidmap and
        \\newgidmap (package uidmap, or shadow-utils on Fedora), which write the maps.
        \\
        \\The diagnostic lists what is missing. Ranges are matched by user name or by
        \\numeric uid. The root user normally has no range, so run zbx as an ordinary
        \\user. If a file could not be read, the cause says so.
        ,
    },
    .{
        .code = .E0106,
        .severity = .@"error",
        .blame = .environment,
        .summary = "seccomp is not available",
        .explanation =
        \\zbx confines container processes with a seccomp filter. The kernel must be
        \\built with CONFIG_SECCOMP and CONFIG_SECCOMP_FILTER, and must report it the
        \\same way in the Seccomp: line of /proc/self/status and through
        \\prctl(PR_GET_SECCOMP).
        \\
        \\Use a kernel with seccomp enabled; every mainstream distribution kernel has
        \\it. If the two answers disagree, run "zbx doctor" again, and report it if it
        \\repeats. If a file could not be read, the cause says so.
        ,
    },
    .{
        .code = .E0201,
        .severity = .@"error",
        .blame = .user,
        .summary = "the rootfs is missing or not a directory",
        .explanation =
        \\"zbx run" needs a directory to use as the container's root file system,
        \\and the path given to --rootfs is not one: it does not exist, it is a
        \\file, or it cannot be read.
        \\
        \\In this version the root file system is a directory that you unpack
        \\yourself. An Alpine minirootfs works:
        \\
        \\  mkdir alpine
        \\  tar -xzf alpine-minirootfs-3.20.10-x86_64.tar.gz -C alpine
        \\  zbx run --rootfs ./alpine -- /bin/sh
        \\
        \\The container reads and writes this directory in place, so what it
        \\changes stays there. Unpack it as the user who runs zbx.
        ,
    },
    .{
        .code = .E0202,
        .severity = .@"error",
        .blame = .user,
        .summary = "can't run the command in the rootfs",
        .explanation =
        \\The container was set up, but its command could not be run inside the
        \\root file system. The cause says which: the file is not there, it is not
        \\executable, or it is not a program for this machine's CPU.
        \\
        \\A command without a slash is looked up in the container's PATH, which is
        \\/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin inside the
        \\rootfs, not in the host's. The host's environment is not passed on.
        \\A dynamically linked program also needs its libc and loader inside the
        \\rootfs; a missing loader is reported as a missing file.
        \\
        \\Give the program's full path inside the rootfs after the "--", for
        \\example /bin/sh.
        ,
    },
    .{
        .code = .E0203,
        .severity = .@"error",
        .blame = .environment,
        .summary = "can't create the container's namespaces",
        .explanation =
        \\zbx runs a container in new user, mount, PID, UTS and IPC namespaces and
        \\writes the id maps of the user namespace. The kernel refused one of
        \\these, or a setting forbids it, so the container was not started.
        \\
        \\The cause names what failed. The usual reason is a restriction on
        \\unprivileged user namespaces: user.max_user_namespaces is 0,
        \\kernel.unprivileged_userns_clone is 0 (Debian), AppArmor restricts them
        \\(the Ubuntu 24.04 default), or a seccomp filter around zbx, as inside
        \\another container, blocks clone3. "zbx doctor" runs the same check and
        \\prints the command that fixes the setting (ZBX-E0101).
        \\
        \\A refused id map means the user namespace exists but could not be mapped.
        \\Without the helper newuidmap only the user's own id can be mapped.
        ,
    },
    .{
        .code = .E0204,
        .severity = .@"error",
        .blame = .environment,
        .summary = "writing the id maps failed",
        .explanation =
        \\A container with a full range of ids has its uid and gid maps written by
        \\the setuid helpers newuidmap and newgidmap, because only they may map ids
        \\the user does not own. A helper could not be run, or refused the map.
        \\
        \\The cause names the helper and how it ended, with what it printed. A
        \\refusal usually means the range in /etc/subuid or /etc/subgid does not
        \\cover the ids zbx asked for, or the helper is not setuid root. "zbx doctor"
        \\checks both (ZBX-E0105).
        \\
        \\zbx does not fall back to a single-id map here: it falls back only when
        \\the helpers or ranges are missing before the container starts, and says so
        \\(ZBX-W0201).
        ,
    },
    .{
        .code = .E0205,
        .severity = .@"error",
        .blame = .environment,
        .summary = "a container setup step failed",
        .explanation =
        \\zbx sets a container up in steps: the mounts, the minimal /dev, moving
        \\into the new root with pivot_root, the hostname. The kernel refused one
        \\of them, so the container was not started and nothing it mounted is
        \\left on the host.
        \\
        \\The cause names the step and the kernel's reason. Mounts inside a user
        \\namespace are refused when the host forbids them: a security policy
        \\(AppArmor, SELinux, seccomp), or running zbx inside another container,
        \\which hides parts of /proc. "zbx doctor" checks what this host allows.
        \\
        \\Rerun with --verbose to see the step's place in the plan. If the reason
        \\fits none of these, report it with the output.
        ,
    },
    .{
        .code = .E0206,
        .severity = .@"error",
        .blame = .user,
        .summary = "invalid container name",
        .explanation =
        \\A container's name is also its hostname, so it must be a valid hostname
        \\label: one to 63 characters, lowercase letters, digits and '-', and not
        \\starting or ending with '-'.
        \\
        \\Leave --name out and zbx picks one: zbx- and six hex digits.
        ,
    },
    .{
        .code = .W0201,
        .severity = .warning,
        .blame = .environment,
        .summary = "mapping only your own id into the container",
        .explanation =
        \\A rootless container can map a full range of ids (root, and 65536 more
        \\for its other users), which needs a range in /etc/subuid and /etc/subgid
        \\and the setuid helpers newuidmap and newgidmap. This host lacks one of
        \\them, so zbx mapped only the container's root, to your own id, and went on.
        \\
        \\Everything runs, but a program in the container that switches to another
        \\user, or owns files as one, fails: only id 0 exists inside. The warning
        \\names what is missing and the command that fixes it; "zbx doctor" shows
        \\the same under ZBX-E0105.
        ,
    },
    .{
        .code = .W0202,
        .severity = .warning,
        .blame = .environment,
        .summary = "can't save the run record",
        .explanation =
        \\zbx keeps a small record of each run in its state directory
        \\($XDG_STATE_HOME/zbx/runs, or ~/.local/state/zbx/runs): the name, the
        \\command, the times and how it ended. This one could not be written, for
        \\example because the disk is full, so the run goes on without it.
        \\
        \\"zbx bundle" and tools that look up a run by name will not find this
        \\one. Free space, or point XDG_STATE_HOME at a directory with room.
        ,
    },
    .{
        .code = .W0203,
        .severity = .warning,
        .blame = .environment,
        .summary = "skipped a run record that can't be read",
        .explanation =
        \\Among the records in the state directory one could not be used: it is
        \\damaged, it was written by a newer zbx than this one, or it cannot be
        \\read. zbx skips it and goes on; a record it cannot read never stops a run.
        \\
        \\The oldest records are deleted when there are more than 32, so a record
        \\that stays unreadable goes away on its own. To keep it, move it out of
        \\the runs directory, or run the zbx that wrote it.
        ,
    },
    .{
        .code = .E0701,
        .severity = .@"error",
        .blame = .environment,
        .summary = "no state directory to keep bundles and run records in",
        .explanation =
        \\zbx keeps run records and diagnostic bundles under $XDG_STATE_HOME/zbx,
        \\or ~/.local/state/zbx when that is not set. Neither variable names an
        \\absolute directory here, so there is nowhere to read a run record from or
        \\to write a bundle to.
        \\
        \\Set HOME, or point XDG_STATE_HOME at a directory you can write to.
        ,
    },
    .{
        .code = .E0702,
        .severity = .@"error",
        .blame = .environment,
        .summary = "can't write the bundle",
        .explanation =
        \\The bundle was put together but could not be saved in the bundles
        \\directory under the state directory ($XDG_STATE_HOME/zbx/bundles, or
        \\~/.local/state/zbx/bundles). The cause says why; a full disk is the usual
        \\one. Nothing partial is left behind: the file is written under a
        \\temporary name and renamed only when it is complete.
        \\
        \\Free space, or point XDG_STATE_HOME at a directory with room, and run the
        \\same command again.
        ,
    },
    .{
        .code = .E0703,
        .severity = .@"error",
        .blame = .user,
        .summary = "no run record with that name",
        .explanation =
        \\"zbx bundle <name>" collects the record of one run, found by its name in
        \\the runs directory under the state directory. There is none called that:
        \\the name is misspelled, or the record was deleted. zbx keeps the newest 32.
        \\
        \\"zbx bundle --last" takes the most recent run whatever its name.
        ,
    },
    .{
        .code = .E0704,
        .severity = .@"error",
        .blame = .user,
        .summary = "no runs are recorded yet",
        .explanation =
        \\"zbx bundle --last" collects the most recent run, but the runs directory
        \\holds no record that can be read: nothing has been run with this state
        \\directory yet, or the records were deleted or are from a newer zbx.
        \\
        \\Run something first with "zbx run", then ask for the bundle.
        ,
    },
    .{
        .code = .W0701,
        .severity = .warning,
        .blame = .user,
        .summary = "writing a bundle without redaction",
        .explanation =
        \\--no-redact keeps the environment values, labels, and anything that looks
        \\like a password, token or key in the bundle exactly as they were. Nobody
        \\should send such a bundle anywhere without reading every file in it first.
        \\
        \\Leave --no-redact out and the values are replaced by [redacted:<kind>],
        \\which is what you want for a bug report.
        ,
    },
    .{
        .code = .B0001,
        .severity = .bug,
        .blame = .internal,
        .summary = "zbx hit an internal error",
        .explanation =
        \\zbx broke one of its own rules: a failed assertion, an unexpected error from
        \\its own code, or an arithmetic or bounds check. This is a bug in zbx, not
        \\something you did, and it always exits with code 70.
        \\
        \\Rerun with --verbose to see the internal message, and report it at
        \\https://github.com/Zigbox/zigbox/issues/new with the command you ran. A
        \\stack trace is not printed.
        ,
    },
};

/// The longest tag: a kind letter and four digits.
const tag_bytes: u32 = 5;

comptime {
    const fields = std.meta.fieldNames(Code);
    // One entry per tag, in tag order: this is what makes a duplicate or a missing entry a
    // build error, and lets `entry` index the table directly.
    assert(registry.len == fields.len);
    assert(fields.len <= std.math.maxInt(u8));
    @setEvalBranchQuota(100_000);
    for (registry, fields, 0..) |item, name, index| {
        assert(@backingInt(item.code) == index);
        assert(std.mem.eql(u8, @tagName(item.code), name));
        check_entry(item);
    }
}

/// Compile-time validation of one entry. Split out so each rule reads on its own line.
fn check_entry(item: Entry) void {
    comptime {
        const tag = @tagName(item.code);
        assert(tag.len == tag_bytes);
        for (tag[1..]) |digit| assert(std.ascii.isDigit(digit));
        // The kind letter and the severity say the same thing.
        switch (item.severity) {
            .@"error" => assert(tag[0] == 'E'),
            .warning => assert(tag[0] == 'W'),
            .bug => assert(tag[0] == 'B'),
            .note => unreachable, // Notes carry no code letter; none is registered.
        }
        // A bug is ours; anything ours is a bug.
        assert((item.blame == .internal) == (item.severity == .bug));
        check_summary(item.summary);
        check_explanation(item.explanation);
    }
}

fn check_summary(summary: []const u8) void {
    comptime {
        assert(summary.len > 0);
        assert(summary.len <= constants.diag_summary_bytes_max);
        assert(summary[summary.len - 1] != '.');
        assert(summary[0] != ' ');
        assert(summary[summary.len - 1] != ' ');
        for (summary) |byte| assert(text_util.is_printable(byte));
    }
}

fn check_explanation(explanation: []const u8) void {
    comptime {
        assert(explanation.len > 0);
        assert(explanation.len <= constants.diag_explanation_bytes_max);
        assert(explanation[explanation.len - 1] != '\n');
        var lines = std.mem.splitScalar(u8, explanation, '\n');
        while (lines.next()) |line| {
            assert(line.len <= constants.diag_explanation_line_bytes_max);
            for (line) |byte| assert(text_util.is_printable(byte));
        }
    }
}

pub fn entry(code: Code) *const Entry {
    const index = @backingInt(code);
    assert(index < registry.len);
    const found = &registry[index];
    assert(found.code == code); // Pair assertion with the comptime check above.
    return found;
}

/// The exit code a failure of this blame ends the process with. The only place that decides.
pub fn exit_code(blame: Blame) u8 {
    const code: u8 = switch (blame) {
        .user => constants.exit_user,
        .environment => constants.exit_environment,
        .external => constants.exit_external,
        .internal => constants.exit_internal,
    };
    assert(code != constants.exit_ok);
    assert(code != constants.tool_exit_ok);
    return code;
}

const prefix = "ZBX-";

const full_names = blk: {
    const fields = std.meta.fieldNames(Code);
    var names: [fields.len][]const u8 = undefined;
    for (fields, 0..) |name, index| names[index] = prefix ++ name;
    break :blk names;
};

/// "ZBX-E0001". Comptime-built, so it is a static string.
pub fn full_name(code: Code) []const u8 {
    const name = full_names[@backingInt(code)];
    assert(name.len == constants.diag_code_bytes);
    assert(std.mem.startsWith(u8, name, prefix));
    return name;
}

/// "E0101.html": the file name of a code's generated page, shared by the site generator and the
/// docs URL of a diagnostic, so the two cannot drift apart.
pub fn page_name(buffer: *[16]u8, code: Code) []const u8 {
    // Cannot fail: a tag is five bytes.
    const name = std.fmt.bufPrint(buffer, "{s}.html", .{@tagName(code)}) catch unreachable;
    assert(name.len == 10);
    assert(std.mem.endsWith(u8, name, ".html"));
    return name;
}

/// Finds a code from what a user typed: "E0001", "ZBX-E0001", in any letter case. Anything else
/// (another product's prefix, extra characters, an unregistered number) is null.
pub fn parse(text: []const u8) ?Code {
    assert(text.len <= constants.arg_bytes_max);
    assert(registry.len > 0);
    var rest = text;
    if (rest.len >= prefix.len) {
        if (std.ascii.eqlIgnoreCase(rest[0..prefix.len], prefix)) rest = rest[prefix.len..];
    }
    if (rest.len != tag_bytes) return null;
    for (registry) |item| {
        if (std.ascii.eqlIgnoreCase(rest, @tagName(item.code))) return item.code;
    }
    return null;
}

test "every registered code round-trips through its names" {
    // Goal: full_name and parse are inverse for every code, and the table is indexed by tag.
    // Method: walk the whole registry; the comptime block already proved the table is
    // complete, so a failure here means the lookup helpers disagree with it.
    for (registry) |item| {
        try std.testing.expect(entry(item.code).code == item.code);
        try std.testing.expectEqualStrings(item.summary, entry(item.code).summary);
        try std.testing.expectEqual(item.code, parse(@tagName(item.code)).?);
        try std.testing.expectEqual(item.code, parse(full_name(item.code)).?);
        try std.testing.expectEqual(constants.diag_code_bytes, full_name(item.code).len);
    }
    try std.testing.expectEqualStrings("ZBX-E0001", full_name(.E0001));
    try std.testing.expectEqualStrings("ZBX-B0001", full_name(.B0001));
}

test "parse accepts case-insensitive codes and refuses everything else" {
    // Goal: the boundary where an argument stops being a code. Near misses are null, never a
    // guess, because "zbx explain" must not explain the wrong code.
    try std.testing.expectEqual(Code.E0001, parse("e0001").?);
    try std.testing.expectEqual(Code.E0001, parse("zbx-E0001").?);
    try std.testing.expectEqual(Code.B0001, parse("ZBX-b0001").?);
    try std.testing.expect(parse("") == null);
    try std.testing.expect(parse("ZBX-") == null);
    try std.testing.expect(parse("E001") == null);
    try std.testing.expect(parse("E00011") == null);
    try std.testing.expect(parse("E9999") == null);
    try std.testing.expect(parse("ZC-E0001") == null);
    try std.testing.expect(parse("ZBX-ZBX-E0001") == null);
    try std.testing.expect(parse(" E0001") == null);
    try std.testing.expect(parse("E0001 ") == null);
    try std.testing.expect(parse("E0001\x00") == null);
}

test "blame decides the exit code, and every blame has a distinct one" {
    // Goal: the mapping is total, distinct, and agrees with each registered entry.
    try std.testing.expectEqual(@as(u8, 1), exit_code(.user));
    try std.testing.expectEqual(@as(u8, 2), exit_code(.environment));
    try std.testing.expectEqual(@as(u8, 3), exit_code(.external));
    try std.testing.expectEqual(@as(u8, 70), exit_code(.internal));
    for (registry) |item| {
        try std.testing.expect(exit_code(item.blame) != constants.exit_ok);
    }
}
