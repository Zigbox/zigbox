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
//! `06xx` network, `07xx` state, `08xx` build, `09xx` trust and policy, `10xx` the macOS VM. A
//! code is never reused
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
    E0010,
    E0011,
    E0012,
    E0013,
    E0101,
    E0102,
    E0103,
    E0104,
    E0105,
    E0106,
    W0101,
    W0102,
    E0201,
    E0202,
    E0203,
    E0204,
    E0205,
    E0206,
    E0207,
    E0208,
    E0209,
    E0210,
    E0211,
    W0201,
    W0202,
    W0203,
    E0301,
    E0302,
    E0303,
    E0304,
    E0305,
    E0306,
    E0307,
    E0308,
    W0301,
    W0302,
    E0401,
    E0402,
    E0403,
    E0404,
    E0405,
    E0406,
    E0410,
    E0411,
    E0412,
    E0413,
    E0414,
    E0415,
    E0416,
    E0417,
    E0418,
    E0419,
    E0420,
    E0421,
    E0422,
    E0423,
    E0424,
    E0425,
    E0426,
    E0427,
    E0428,
    E0429,
    E0430,
    E0431,
    E0432,
    E0433,
    E0434,
    E0435,
    E0436,
    W0410,
    W0411,
    W0412,
    W0413,
    E0501,
    E0502,
    E0503,
    E0504,
    E0505,
    E0506,
    E0507,
    E0508,
    E0509,
    E0510,
    E0511,
    E0512,
    E0513,
    E0514,
    E0515,
    E0516,
    E0517,
    E0518,
    E0519,
    E0520,
    E0521,
    E0522,
    E0523,
    E0524,
    E0525,
    E0526,
    W0501,
    W0502,
    W0503,
    E0600,
    E0601,
    E0602,
    E0603,
    E0604,
    E0605,
    E0701,
    E0702,
    E0703,
    E0704,
    E0705,
    E0706,
    E0707,
    E0708,
    E0709,
    E0710,
    E0711,
    E0712,
    E0713,
    E0714,
    E0715,
    E0716,
    W0701,
    W0702,
    W0703,
    E1001,
    E1002,
    E1003,
    E1004,
    E1005,
    E1006,
    E1007,
    E1008,
    W1001,
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
        \\Some options of "run" exclude each other: --rootfs and a tree, and
        \\--publish with --net none or --net host (a forward needs the network of
        \\its own that pasta gives, --net user, which --publish implies).
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
        \\--net takes none, host or user. --rootfs and --name need one too, a
        \\directory and a name; --publish takes HOST:CONTAINER (ZBX-E0600 says
        \\what is wrong with one). Either the value is missing (the option was
        \\last, or empty) or it is wrong.
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
        \\most 4000 bytes, 32 KiB with the environment. A working directory is an
        \\absolute path without "..".
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
        .code = .E0010,
        .severity = .@"error",
        .blame = .user,
        .summary = "can't use this -e option",
        .explanation =
        \\"zbx run -e NAME=VALUE" sets a variable in the container, and "-e NAME"
        \\copies it from zbx's own environment. The option you gave is neither: the
        \\name must be a letter or underscore followed by letters, digits and
        \\underscores (at most 64 of them), a name may be set once, and a run takes
        \\at most 16 of them. The image's own variables and yours together are at
        \\most 64.
        \\
        \\zbx never prints or stores a value, so the message names the variable only.
        \\The run record, "zbx ps" and a bundle list the names that -e set, never
        \\what they were set to. Remember that your shell, and the process list of
        \\this machine while zbx runs, can still show the command line: "-e NAME"
        \\with the value in the environment keeps it off both.
        ,
    },
    .{
        .code = .E0011,
        .severity = .@"error",
        .blame = .user,
        .summary = "-e names a variable that is not set",
        .explanation =
        \\"-e NAME", with no "=", copies the variable NAME from the environment of
        \\the zbx command into the container. NAME is not set there (or its value is
        \\longer than 4096 bytes, more than a container can take), so there is
        \\nothing to copy and zbx did not start the container.
        \\
        \\Give the value on the command line ("-e NAME=VALUE"), or set the variable
        \\for this one command: NAME=VALUE zbx run -e NAME ... A value is never
        \\printed or stored by zbx.
        ,
    },
    .{
        .code = .E0012,
        .severity = .@"error",
        .blame = .user,
        .summary = "not a valid --tmpfs, --bind or --secret value",
        .explanation =
        \\--tmpfs takes PATH or PATH:SIZE, an empty tmpfs gone at exit (64 MiB
        \\without a size; SIZE is bytes, or a number with k, m or g, from 4096
        \\bytes to 1 TiB). --bind takes HOST:PATH, a host directory or file
        \\mounted read-only. --secret takes HOST_FILE:PATH, a host file copied
        \\into the container's memory, mode 0400, read-only, owned by the
        \\container's root.
        \\
        \\Every path is absolute, with parts that are names (no empty, "." or ".."
        \\part), at most 256 bytes, and holds no ':', space or control character.
        \\A path in the container may not be "/", nor /proc, /sys, /dev or below
        \\them, nor /etc/hosts, /etc/hostname or /etc/resolv.conf: zbx mounts
        \\those itself. The cause names the part that is wrong.
        \\
        \\    zbx run --tmpfs /scratch:128m --bind /srv/site:/srv nginx
        ,
    },
    .{
        .code = .E0013,
        .severity = .@"error",
        .blame = .user,
        .summary = "mounts that cannot go together",
        .explanation =
        \\One run's mounts (--state, --tmpfs, --bind and --secret) each have a
        \\path in the container, and no path may be the same as another's, inside
        \\it, or hold it: a mount inside another would be made in the outer one.
        \\At most 8 of --tmpfs, --bind and --secret may be given in one run, and 8
        \\--state.
        \\
        \\Give each mount its own place, or drop one.
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
        \\
        \\The check also asks the user's D-Bus for the manager's version: zbx makes
        \\each container's scope there, so a missing bus socket, a bus that refuses
        \\the user, or a bus with no systemd on it fails the check too (ZBX-E0301
        \\to ZBX-E0304 are what a run reports for the same causes).
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
        .code = .W0101,
        .severity = .warning,
        .blame = .environment,
        .summary = "user namespaces work, but only for unconfined users",
        .explanation =
        \\zbx doctor created a user namespace, so zbx works for this process. The host
        \\also sets kernel.apparmor_restrict_unprivileged_userns = 1, which refuses
        \\the same call to processes that no AppArmor profile confines. The check
        \\passed because this process runs under a profile that allows it.
        \\
        \\Run from a terminal or another service, zbx may meet the refusal as
        \\ZBX-E0101. To allow user namespaces system-wide, set the sysctl to 0 as
        \\root; "zbx doctor" shows the same host as a failure when this process is
        \\not confined by a permissive profile.
        ,
    },
    .{
        .code = .W0102,
        .severity = .warning,
        .blame = .environment,
        .summary = "--net user is not available",
        .explanation =
        \\--net user and --publish connect a container to the network through pasta
        \\(from the passt project), and the net check of zbx doctor found it missing,
        \\unable to report its version, or older than zbx can use. Nothing else
        \\depends on it: --net none (the default) and --net host run without pasta,
        \\so this is a warning and "zbx doctor" still exits 0.
        \\
        \\Install a current passt (Debian and Ubuntu: apt install passt; Fedora:
        \\dnf install passt). A run that asks for --net user without it is refused
        \\as ZBX-E0601 (missing) or ZBX-E0602 (too old) before anything starts.
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
        \\zbx runs a container in new user, mount, PID, UTS, IPC and network
        \\namespaces and writes the id maps of the user namespace. The kernel
        \\refused one of these, or a setting forbids it, so the container was not
        \\started.
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
        .code = .E0207,
        .severity = .@"error",
        .blame = .environment,
        .summary = "can't restrict the container's capabilities",
        .explanation =
        \\Just before the command starts, zbx drops every capability the container
        \\does not keep: from the bounding set, then from the effective, permitted
        \\and inheritable sets, and it empties the ambient set. The list that is
        \\kept is Docker's default without NET_RAW and MKNOD, and has no SYS_ADMIN
        \\(src/runtime/policy/capabilities.zon). The kernel refused one of those
        \\calls, so the container was not started: a container with more rights
        \\than intended is never run.
        \\
        \\The cause names the step and the kernel's reason. This is unusual: the
        \\child is root of its own user namespace and holds these capabilities
        \\there. A security module that restricts capability changes, or a very
        \\old kernel, is the likely reason.
        ,
    },
    .{
        .code = .E0208,
        .severity = .@"error",
        .blame = .environment,
        .summary = "can't install the container's seccomp filter",
        .explanation =
        \\The last thing zbx does before the command starts is set no_new_privs and
        \\install a seccomp filter (src/runtime/policy/seccomp.zon): a list of the
        \\system calls the container may make, which fails every other with EPERM.
        \\The kernel refused one of the two calls, so the container was not
        \\started: a container without its filter is never run.
        \\
        \\The cause names the step and the kernel's reason. The kernel may lack
        \\seccomp filters (CONFIG_SECCOMP_FILTER), or a policy may forbid
        \\installing one. "zbx doctor" checks that this host has seccomp (ZBX-E0106).
        ,
    },
    .{
        .code = .E0209,
        .severity = .@"error",
        .blame = .environment,
        .summary = "can't set up the read-only rootfs",
        .explanation =
        \\--read-only mounts a tmpfs on the rootfs's /tmp and /run, then remounts
        \\the rootfs read-only. One of those steps failed, so the container was not
        \\started.
        \\
        \\When the cause says /tmp or /run could not be made, the rootfs does not
        \\have the directory and is not writable by this user, so zbx cannot make
        \\the mount point: make both directories as the rootfs's owner (mkdir -p
        \\<rootfs>/tmp <rootfs>/run) and run again. Otherwise the kernel refused the
        \\mount or the remount; the cause says why.
        ,
    },
    .{
        .code = .E0210,
        .severity = .@"error",
        .blame = .user,
        .summary = "a --bind or --secret source can't be used",
        .explanation =
        \\A --bind source is a directory or a regular file on the host, and a
        \\--secret source is one regular file. The cause says what is wrong with
        \\the path you gave: it does not exist, cannot be looked at, or is another
        \\kind of file (a socket, a device). zbx never makes a source: a bind is
        \\read-only, and what a container writes belongs in a state volume
        \\(--state).
        \\
        \\Check the path, or make the file first, then run again.
        ,
    },
    .{
        .code = .E0211,
        .severity = .@"error",
        .blame = .environment,
        .summary = "can't set up a --tmpfs, --bind or --secret mount",
        .explanation =
        \\A mount is made before the container's command starts. A bind or a
        \\secret is staged in the container's own /dev, made read-only, and moved
        \\onto its path once the container's root is entered (so the path is read
        \\as the container reads it); a tmpfs is mounted on its path. One of those
        \\steps failed; the cause names it and what the kernel said.
        \\
        \\A secret is copied by the container's root, so the file must be readable
        \\by you and at most 65536 bytes. With --read-only the path must already
        \\exist in the image: nothing can be made in a read-only root. zbx doctor
        \\shows what this host allows.
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
        .code = .E0301,
        .severity = .@"error",
        .blame = .environment,
        .summary = "can't reach the systemd user manager over D-Bus",
        .explanation =
        \\zbx puts each container in its own cgroup, a transient systemd "scope" of
        \\the user's systemd manager, and asks for it over the user's D-Bus socket
        \\($DBUS_SESSION_BUS_ADDRESS, or $XDG_RUNTIME_DIR/bus). It could not get
        \\there: nothing set the address, the socket is missing or refuses
        \\connections, the address is not a unix:path= one, or the bus has no
        \\systemd on it.
        \\
        \\The cause says which. The usual one is a login with no systemd user
        \\session: ssh without PAM's systemd module, su, or sudo -u. Log in through
        \\a systemd session, or keep the manager running with
        \\"loginctl enable-linger $USER". "zbx doctor" runs the same probe.
        ,
    },
    .{
        .code = .E0302,
        .severity = .@"error",
        .blame = .environment,
        .summary = "the user bus refused to authenticate this user",
        .explanation =
        \\zbx proves who it is to the user's D-Bus socket with the SASL mechanism
        \\EXTERNAL, which sends only the user id and relies on the socket's
        \\credentials. The bus rejected that, or answered something else, or
        \\refused the Hello that follows.
        \\
        \\This usually means the socket belongs to another user: an address
        \\inherited through su or sudo points at the previous user's bus. Unset
        \\DBUS_SESSION_BUS_ADDRESS, or run zbx from the user's own login session.
        \\The cause shows what the bus answered.
        ,
    },
    .{
        .code = .E0303,
        .severity = .@"error",
        .blame = .external,
        .summary = "the user bus answered in a way zbx can't use",
        .explanation =
        \\The conversation with the user bus broke: a reply was malformed or too
        \\big, the connection closed in the middle, a call got no answer in time,
        \\or reading or writing the socket failed.
        \\
        \\The cause names the step and what went wrong. A bus that stops answering
        \\is overloaded or stuck; "systemctl --user status" and
        \\"journalctl --user -u dbus" show why. A malformed reply from a real bus is
        \\a bug worth reporting with the output of "zbx bundle --last".
        ,
    },
    .{
        .code = .E0304,
        .severity = .@"error",
        .blame = .external,
        .summary = "systemd refused the container's scope, or its job failed",
        .explanation =
        \\zbx asked the user's systemd manager to start the scope that holds the
        \\container, and systemd either refused the request or started a job that
        \\did not end well. The cause gives systemd's own error name and message,
        \\or the job's result.
        \\
        \\Typical reasons: the user manager is shutting down, a property is not
        \\accepted by this systemd version, or the user has no cgroup to delegate.
        \\"journalctl --user" shows what the manager logged.
        ,
    },
    .{
        .code = .E0305,
        .severity = .@"error",
        .blame = .user,
        .summary = "a scope with this container's name already exists",
        .explanation =
        \\Each container runs in a systemd scope named zbx-<name>.scope, and a
        \\unit of that name is already there: another container with the same name
        \\is running, or one that ended has not been cleaned up yet. zbx never
        \\reuses a scope, so the run was refused.
        \\
        \\Choose another name with --name, or stop the other container. The unit
        \\can be listed with "systemctl --user list-units 'zbx-*'".
        ,
    },
    .{
        .code = .E0306,
        .severity = .@"error",
        .blame = .user,
        .summary = "invalid resource limit",
        .explanation =
        \\A resource limit has to be a sensible number. --memory takes a size with
        \\a binary unit (k, m or g; 128m is 128 MiB) between 4 MiB and 1 TiB.
        \\--pids takes a count from 1 to 4194304. --cpus takes a number of CPUs
        \\with up to three decimals (0.5 is half of one) from 0.01 to 1024.
        \\
        \\A zero, a number out of range, or text that is not a number is refused
        \\before anything starts.
        ,
    },
    .{
        .code = .E0307,
        .severity = .@"error",
        .blame = .environment,
        .summary = "a limit needs a cgroup scope, and none can be made",
        .explanation =
        \\--memory, --pids and --cpus are enforced by the container's cgroup, which
        \\zbx gets from the user's systemd manager. That manager is not reachable,
        \\so the limit cannot be enforced, and zbx refuses to run the container as
        \\though it were: a limit that is silently ignored is worse than none.
        \\
        \\The cause says why the manager is not reachable (see ZBX-E0301 and the
        \\codes after it). Fix that, or run without the limit flags: a run with no
        \\limits still works without a scope, with a warning (ZBX-W0301).
        ,
    },
    .{
        .code = .E0308,
        .severity = .@"error",
        .blame = .environment,
        .summary = "can't write a limit to the container's cgroup",
        .explanation =
        \\This systemd is too old to take one of the limits as a unit property, so
        \\zbx writes it to the scope's own cgroup files (memory.max, pids.max,
        \\cpu.max). Finding the scope's cgroup or writing the file failed.
        \\
        \\The cause names the file and the kernel's reason. The controller may not
        \\be delegated to the user: "zbx doctor" shows which are (ZBX-E0103).
        ,
    },
    .{
        .code = .W0301,
        .severity = .warning,
        .blame = .environment,
        .summary = "running without a cgroup scope",
        .explanation =
        \\The user's systemd manager could not be reached, so this container has
        \\no cgroup scope of its own. It runs, as in M1, but nothing limits or
        \\accounts for what it uses, and tools that look for the scope will not
        \\find it. The warning names why the manager is out of reach.
        \\
        \\"zbx doctor" runs the same probe and prints the fix. A run that asks for
        \\a limit does not get this far: it is refused (ZBX-E0307).
        ,
    },
    .{
        .code = .W0302,
        .severity = .warning,
        .blame = .environment,
        .summary = "the container's cgroup scope was left behind",
        .explanation =
        \\The container has ended, and zbx made sure its systemd scope went away:
        \\the scope goes by itself when its last process exits, and zbx asks the
        \\user's systemd manager to stop it if it does not. That did not work, so
        \\the scope, with its cgroup under /sys/fs/cgroup, may still be there. It
        \\holds no process of the container, but a new run with the same name will
        \\be refused until it is gone (ZBX-E0305).
        \\
        \\The cause says what went wrong. "systemctl --user stop zbx-<name>.scope"
        \\removes the scope by hand.
        ,
    },
    .{
        .code = .E0401,
        .severity = .@"error",
        .blame = .user,
        .summary = "a time is not a number of milliseconds",
        .explanation =
        \\--timeout and --grace take a number of milliseconds: a whole number
        \\from 1 to 86400000 (a day) for --timeout, and from 0 for --grace, which is
        \\how long a container gets between SIGTERM and SIGKILL. Anything else is
        \\refused before anything starts.
        ,
    },
    .{
        .code = .E0402,
        .severity = .@"error",
        .blame = .user,
        .summary = "no container with that name",
        .explanation =
        \\No run record has that name, so there is no container to stop. "zbx ps
        \\--all" lists the containers zbx knows, running or not; the newest 32 are
        \\kept. A container that ended is found, and "zbx stop" on it says it was
        \\already stopped.
        ,
    },
    .{
        .code = .E0403,
        .severity = .@"error",
        .blame = .environment,
        .summary = "can't signal the container",
        .explanation =
        \\zbx found the container's PID 1 but the kernel refused to signal it.
        \\That is unusual: the container belongs to the user who runs zbx. The
        \\record may be another user's, or the pid was reused by a process that is
        \\not ours. The cause names the kernel's reason.
        ,
    },
    .{
        .code = .E0404,
        .severity = .@"error",
        .blame = .environment,
        .summary = "the container did not stop in time",
        .explanation =
        \\zbx sent the container SIGTERM, and SIGKILL after the grace period, and
        \\it was still there when --timeout ran out (or a few seconds after SIGKILL).
        \\A process in uninterruptible sleep (a stuck mount, a hung disk) cannot be
        \\killed until the kernel lets it go.
        \\
        \\Look at what it is doing with "ps -o pid,stat,wchan -p <pid>" and try
        \\again; the pid is in "zbx ps".
        ,
    },
    .{
        .code = .E0405,
        .severity = .@"error",
        .blame = .environment,
        .summary = "can't start the supervisor of a detached run",
        .explanation =
        \\A detached run ("zbx run -d") hands the container to a supervisor
        \\process that stays to wait for it and to finish its record. The kernel
        \\refused to create that process (a process limit, or no memory), so
        \\nothing was started.
        \\
        \\The cause names the kernel's reason. Check the process limits with
        \\"ulimit -u".
        ,
    },
    .{
        .code = .E0406,
        .severity = .@"error",
        .blame = .user,
        .summary = "no schema for that command",
        .explanation =
        \\zbx publishes a JSON schema for the output of run, bundle, ps, stop and
        \\doctor ("zbx schema ps"), of commit, and of the store commands, named
        \\store-import, store-ls, store-du, store-rm, store-diff, store-verify,
        \\store-gc, store-trash (gc --trash) and store-restore, and of explain and
        \\"lock show" (lock-show). Other commands have no machine-readable output
        \\that needs one: help prints text, version prints a line.
        ,
    },
    .{
        .code = .E0410,
        .severity = .@"error",
        .blame = .user,
        .summary = "no tree with that digest",
        .explanation =
        \\The store has no tree whose digest starts with what was given. A tree's
        \\digest is printed by "zbx store import" (and by "zbx commit"), and
        \\"zbx store ls" lists the trees the store keeps as roots. A tree that
        \\was dropped with "zbx store rm" stays until "zbx store gc" collects it.
        \\
        \\A running container started from a digest the store does not have fails
        \\with this code before anything is created.
        ,
    },
    .{
        .code = .E0411,
        .severity = .@"error",
        .blame = .user,
        .summary = "that digest prefix matches more than one tree",
        .explanation =
        \\A digest may be shortened to a prefix of at least 12 hex digits, but
        \\only while the prefix names one tree. zbx never picks one of several:
        \\a wrong guess here could delete or run the wrong tree.
        \\
        \\The message names the first two matches. Give more digits, or the whole
        \\digest from "zbx store ls".
        ,
    },
    .{
        .code = .E0412,
        .severity = .@"error",
        .blame = .user,
        .summary = "not a digest",
        .explanation =
        \\A digest is "b3:" and 64 lowercase hex digits (BLAKE3). It may be
        \\shortened to a prefix of at least 12 hex digits, with or without the
        \\"b3:". Anything else is refused, as are uppercase digits: a digest has
        \\one spelling.
        \\
        \\"zbx store ls" prints the digests the store keeps.
        ,
    },
    .{
        .code = .E0413,
        .severity = .@"error",
        .blame = .environment,
        .summary = "can't use the store: its format is unknown",
        .explanation =
        \\The store's store.zon is missing a readable format version, or names one
        \\this zbx does not know. A newer zbx wrote it, or something else changed
        \\the file. zbx does not touch a store it cannot read: it could damage
        \\what a newer version put there.
        \\
        \\Run the zbx that wrote the store, or move the store directory away to
        \\start a new one. The cause names the file.
        ,
    },
    .{
        .code = .E0414,
        .severity = .@"error",
        .blame = .user,
        .summary = "can't read the directory to import",
        .explanation =
        \\"zbx store import" reads the directory it is given from inside your user
        \\namespace, with the same ids a container would see. The path, or
        \\something below it, is missing, is not what it should be (the source
        \\must be a directory), or cannot be read by you.
        \\
        \\The cause names the path and the kernel's reason. Files that only you
        \\cannot read (mode 0600 and owned by a subordinate id) are readable
        \\inside the namespace; files owned by an id outside it are not.
        ,
    },
    .{
        .code = .E0415,
        .severity = .@"error",
        .blame = .user,
        .summary = "the directory tree is bigger than an import limit",
        .explanation =
        \\zbx holds a bounded amount in memory while it imports: at most 16384
        \\entries in one directory, names up to 255 bytes, 64 levels of nesting,
        \\a symlink target up to 4095 bytes, files up to 4 GiB, and 16 MiB for the
        \\names and entries of all the directories being read at once.
        \\
        \\The cause names the limit and the path where it was passed. Split the
        \\directory, or leave out what is not part of the root filesystem.
        ,
    },
    .{
        .code = .E0416,
        .severity = .@"error",
        .blame = .environment,
        .summary = "the disk is full while writing the store",
        .explanation =
        \\The file system that holds the store has no room left. Everything zbx
        \\wrote before is complete and stays: every write is a temporary file
        \\that is renamed into place only when it is whole, so there is no half
        \\file under any digest. The message says how much was written.
        \\
        \\Free space (or point XDG_DATA_HOME at a bigger disk) and run the same
        \\command again: objects already stored are skipped, so it carries on.
        ,
    },
    .{
        .code = .E0417,
        .severity = .@"error",
        .blame = .environment,
        .summary = "can't write the store",
        .explanation =
        \\The kernel refused a write to the store directory (permissions, a
        \\read-only file system, an I/O error). Nothing partial is left under a
        \\digest: a failed write leaves at most a temporary file in the store's
        \\tmp directory, which "zbx store gc" removes.
        \\
        \\The cause names the path and the kernel's reason. The store is in
        \\$XDG_DATA_HOME/zbx/store, or ~/.local/share/zbx/store.
        ,
    },
    .{
        .code = .E0418,
        .severity = .@"error",
        .blame = .user,
        .summary = "a file changed while it was being imported",
        .explanation =
        \\zbx reads each file twice, once to learn its digest and once to copy
        \\it, and the two reads did not agree: something wrote to the file in
        \\between. Importing a tree that is being written would store a mixture,
        \\so zbx stops.
        \\
        \\Stop whatever writes to the directory (a running container using it as
        \\its root, a build), or import a copy, and run the command again.
        ,
    },
    .{
        .code = .E0419,
        .severity = .@"error",
        .blame = .environment,
        .summary = "can't run the store worker",
        .explanation =
        \\Store work runs in a short-lived child process inside your user
        \\namespace. This one could not be created or set up (the same causes as
        \\a container that will not start: see "zbx doctor"), or it was killed by
        \\a signal before it finished. Nothing partial is left under a digest.
        \\
        \\The cause says which. Run the command again once it is fixed.
        ,
    },
    .{
        .code = .E0420,
        .severity = .@"error",
        .blame = .user,
        .summary = "that tree is not a root",
        .explanation =
        \\"zbx store rm" drops a root: the record that keeps a tree in the store.
        \\The digest names a tree the store has, but no root keeps it (it is only
        \\part of another tree, or was already dropped), so there is nothing to
        \\remove.
        \\
        \\"zbx store ls" lists the roots.
        ,
    },
    .{
        .code = .E0421,
        .severity = .@"error",
        .blame = .environment,
        .summary = "no data directory to keep the store in",
        .explanation =
        \\zbx keeps its store under $XDG_DATA_HOME/zbx/store, or
        \\~/.local/share/zbx/store when that is not set. Neither variable names an
        \\absolute directory here, so there is nowhere to put the store.
        \\
        \\Set HOME, or point XDG_DATA_HOME at a directory you can write to.
        ,
    },
    .{
        .code = .E0422,
        .severity = .@"error",
        .blame = .environment,
        .summary = "a tree in the store is missing or damaged",
        .explanation =
        \\zbx followed a tree down through its subtrees and found one that is not
        \\in the store, does not hash to its name, or cannot be decoded. A tree
        \\object is a file named by the hash of its bytes, so this means the
        \\store was changed or damaged outside zbx (a disk error, a file removed
        \\by hand), or an earlier zbx wrote it wrongly.
        \\
        \\The cause names the tree. Nothing was changed. Importing the directory
        \\again writes the trees it needs; objects that are already stored are
        \\reused.
        ,
    },
    .{
        .code = .E0423,
        .severity = .@"error",
        .blame = .environment,
        .summary = "can't read the store",
        .explanation =
        \\The kernel refused to read something in the store directory, or the
        \\store has more entries in one place than zbx can count at once. The
        \\store is in $XDG_DATA_HOME/zbx/store, or ~/.local/share/zbx/store.
        \\
        \\The cause names the step and the kernel's reason. Check that the
        \\directory belongs to you, and that the disk is healthy.
        ,
    },
    .{
        .code = .E0424,
        .severity = .@"error",
        .blame = .environment,
        .summary = "a file name in the store has too many links",
        .explanation =
        \\Building the directory a container runs on makes a hard link from every
        \\file of the tree to its object. The file system refused one because the
        \\object already has as many names as the file system allows (ext4: about
        \\65,000). A file that appears under many names in one tree, or in many
        \\trees that are all in use, can reach it.
        \\
        \\Nothing was changed: the half-built directory was removed. The usual
        \\ways out are to import a tree in which that file is not repeated so
        \\often, or to move the store to a file system with a higher limit (xfs
        \\and btrfs allow far more).
        ,
    },
    .{
        .code = .E0425,
        .severity = .@"error",
        .blame = .environment,
        .summary = "overlayfs can't be mounted for this container",
        .explanation =
        \\A container started from a tree digest runs on an overlayfs mount: the
        \\tree is the read-only lower layer and the container's own writes go to
        \\an upper layer under the state directory. The kernel refused to mount
        \\it in the container's user and mount namespaces.
        \\
        \\Unprivileged overlayfs needs Linux 5.11 or newer with the overlay
        \\module, and an upper layer on a file system that keeps user.* extended
        \\attributes. A security policy can also deny the mount. "zbx doctor"
        \\runs the same mount in a scratch directory and says which of these it
        \\is. A path that contains a comma, a colon or a backslash can not be
        \\given to the mount and is refused with this code too.
        \\
        \\A container can still run on a plain directory: "zbx run --rootfs".
        ,
    },
    .{
        .code = .E0426,
        .severity = .@"error",
        .blame = .user,
        .summary = "the container has no layer to commit",
        .explanation =
        \\"zbx commit" turns what a container changed into a new tree. That needs
        \\a container that was started from a tree digest ("zbx run <digest>"),
        \\because its writes are in an upper layer of their own. A container run
        \\on a directory ("zbx run --rootfs") wrote into that directory, a
        \\container run with --read-only had no upper layer, and the upper layer
        \\of an old container is removed with its record (the newest 32 are kept).
        \\
        \\The cause says which of these it is. To keep a directory's contents,
        \\import it: "zbx store import <dir>".
        ,
    },
    .{
        .code = .E0427,
        .severity = .@"error",
        .blame = .user,
        .summary = "the container is still running",
        .explanation =
        \\A commit reads the container's upper layer while nothing writes to it, so
        \\that the new tree is one the container really had. The container is
        \\still running, and zbx does not freeze a running container (a
        \\"--pause" option is not part of this version).
        \\
        \\Stop it with "zbx stop <name>", then commit. Nothing was changed.
        ,
    },
    .{
        .code = .E0428,
        .severity = .@"error",
        .blame = .environment,
        .summary = "the upper layer uses an overlayfs feature a commit can't follow",
        .explanation =
        \\A commit reads a container's upper layer file by file. Overlayfs can
        \\also keep a change as a redirect (a renamed directory,
        \\"user.overlay.redirect") or as metadata only ("user.overlay.metacopy"),
        \\and the upper layer alone
        \\does not say what the change was then. zbx mounts without those
        \\features, so this means the layer was made by something else, or by a
        \\kernel whose defaults turn them on.
        \\
        \\The cause names the file. Nothing was changed.
        ,
    },
    .{
        .code = .E0429,
        .severity = .@"error",
        .blame = .environment,
        .summary = "a file in the store is damaged",
        .explanation =
        \\"zbx store verify" read every object, tree and root record in the store
        \\and checked it against its name. This one does not match: its bytes (or,
        \\for a file object, its mode, owner or attributes) are not what its id
        \\says, or its chunk list disagrees with it, or it can not be read, or a
        \\tree names something that is not in the store.
        \\
        \\The message names the id and the file, and the first path in the trees of
        \\the roots that reach it, with how many more there are, so you know which
        \\images are affected. --verbose lists three; --output json lists up to 16
        \\for each damaged thing, with the root of each.
        \\
        \\Nothing was changed. A damaged file can not be repaired in place: delete
        \\it and import the directory it came from again (the import writes what is
        \\missing), or drop the roots that reach it with "zbx store rm". A disk
        \\that damages files needs looking at; "zbx store verify" again afterwards.
        ,
    },
    .{
        .code = .E0430,
        .severity = .@"error",
        .blame = .environment,
        .summary = "the store failed verification",
        .explanation =
        \\"zbx store verify" found damage; this is the summary after one
        \\ZBX-E0429 for each damaged thing (the first 256, then a count). The exit
        \\code is 2, because the store is part of the environment: zbx did not
        \\do wrong, and neither did the command.
        \\
        \\Nothing was changed. See the diagnostics above this one.
        ,
    },
    .{
        .code = .E0431,
        .severity = .@"error",
        .blame = .user,
        .summary = "the store changed since that gc plan was made",
        .explanation =
        \\"zbx store gc --confirm <hash>" acts only on the plan the hash names. A plan
        \\hash covers the ids of everything the plan would move and a counter that
        \\every write to the store raises, so a plan can not be applied after an
        \\import, a commit, a "store rm", a restore or another gc, even one that
        \\changed nothing the plan holds.
        \\
        \\Nothing was moved. The message gives the hash of the plan as the store
        \\is now: run "zbx store gc" to read it, and confirm that one if it is what
        \\you want.
        ,
    },
    .{
        .code = .E0432,
        .severity = .@"error",
        .blame = .user,
        .summary = "a restore would overwrite something that is back in the store",
        .explanation =
        \\"zbx store restore" puts back what a gc moved to the trash. Something in
        \\that trash is in the store again (an import or a commit wrote the same
        \\object, tree or materialized directory in the meantime), and restore
        \\does not decide which copy is right.
        \\
        \\Nothing was moved. The message names the first one and how many there
        \\are. Drop the roots that brought them back with "zbx store rm" and gc
        \\again, or leave the trash to expire.
        ,
    },
    .{
        .code = .E0433,
        .severity = .@"error",
        .blame = .user,
        .summary = "no trash with that id",
        .explanation =
        \\A gc id is the 12 hex digits of the plan hash a gc ran with. "zbx store
        \\gc --trash" lists the trash that is still there. Trash is emptied by the
        \\first gc after its time is up (seven days), and a restore removes the
        \\trash it restored.
        ,
    },
    .{
        .code = .E0434,
        .severity = .@"error",
        .blame = .environment,
        .summary = "the trash is missing things the gc moved into it",
        .explanation =
        \\The trash holds fewer objects, trees or materialized directories than
        \\the gc that made it recorded, so putting it back would give a store
        \\with holes. Something removed files from the trash directory by hand.
        \\
        \\Nothing was moved. The message says how many were recorded and how many
        \\are there. What is missing can be imported again from its source.
        ,
    },
    .{
        .code = .E0435,
        .severity = .@"error",
        .blame = .environment,
        .summary = "a root record can't be used",
        .explanation =
        \\A gc keeps what the roots reach, and a root's record in the store can not
        \\be read or is from a newer zbx, so what it keeps is not known. gc
        \\refuses rather than guess: a wrong guess deletes a tree somebody needs.
        \\
        \\The message names the root. "zbx store verify" says more. Delete the
        \\record if the tree is not wanted, or import the directory again to
        \\write it afresh.
        ,
    },
    .{
        .code = .E0436,
        .severity = .@"error",
        .blame = .user,
        .summary = "the store is in use by another zbx command",
        .explanation =
        \\A store has one lock file. Every command that writes to the store and may
        \\reuse what is in it (an import, a commit, building a directory to run on,
        \\writing an object chunk by chunk) holds it shared while it works. "zbx
        \\store gc --confirm" and "zbx store restore", which move things out of
        \\the store, hold it alone. Without that, a gc could move an object to the
        \\trash in the very moment an import decided to reuse it, and the new tree
        \\would name an object that is not there.
        \\
        \\The command waited ten seconds for the lock and gave up; nothing was
        \\changed. The message names the command that holds the lock when it is a
        \\gc or a restore, and says "writers" when it is shared importers that are
        \\keeping a gc waiting. Run the command again when the other one is done. A
        \\lock never outlives its process: if nothing else is running, it was held
        \\for the last of those ten seconds only.
        ,
    },
    .{
        .code = .W0410,
        .severity = .warning,
        .blame = .user,
        .summary = "a file was left out of the import",
        .explanation =
        \\The store keeps regular files, directories and symlinks. A device
        \\node, a FIFO or a socket in the imported directory was skipped, and the
        \\message names it. A root filesystem normally has none of these on disk:
        \\a container gets its own /dev, so the digest does not miss them.
        \\
        \\Past the first few, the warnings are counted and the last one says how
        \\many were not shown.
        ,
    },
    .{
        .code = .W0411,
        .severity = .warning,
        .blame = .user,
        .summary = "an extended attribute was left out of the import",
        .explanation =
        \\The store keeps the user.* attributes and security.capability (the file
        \\capabilities). Others were skipped, and the message names the file and
        \\the attribute: the trusted.*, system.* and security.* attributes
        \\other than the capability (SELinux labels, ACLs), an attribute with a
        \\name or value over the store's limits, and any attribute past the
        \\sixteenth on a file. user.overlay.* is overlayfs's own and is never
        \\imported, without a warning.
        \\
        \\The digest does not include what was left out.
        ,
    },
    .{
        .code = .W0412,
        .severity = .warning,
        .blame = .user,
        .summary = "some files have an owner or group that could not be mapped",
        .explanation =
        \\The import runs in the user's namespace, where only the user (as 0) and
        \\the subordinate range from /etc/subuid and /etc/subgid (as 1 and up)
        \\exist. A file owned by any other host id shows as 65534, the kernel's
        \\overflow id, and that is what the store records, so the container sees
        \\those files owned by 65534 whatever their owner on the host.
        \\
        \\The message counts the owners and the groups and names the first path.
        \\A file that really is owned by 65534 in the container is counted too,
        \\because the kernel gives no way to tell the two apart. The digest holds
        \\65534 either way. To record a real owner, chown the files to an id the
        \\user can map, or import as a user with a subuid range.
        ,
    },
    .{
        .code = .W0413,
        .severity = .warning,
        .blame = .environment,
        .summary = "a container's upper layer could not be removed",
        .explanation =
        \\Every container started from a tree digest has an upper layer under
        \\$XDG_STATE_HOME/zbx/containers/<name>, which is kept as long as its run
        \\record is. When the record is dropped (zbx keeps the newest 32), or a
        \\new run takes the name, the layer is removed, from inside the user's
        \\namespace because it holds files owned by subordinate ids. This one
        \\could not be removed, and the message names the path and the reason.
        \\
        \\Nothing else is affected. After checking that no container uses it,
        \\remove the directory by hand from inside a user namespace that maps
        \\your subordinate id range, the one zbx itself uses: its files belong to
        \\those ids, and the next zbx run with the same container name tries
        \\again.
        ,
    },
    .{
        .code = .E0501,
        .severity = .@"error",
        .blame = .user,
        .summary = "not an image reference",
        .explanation =
        \\zbx was given text that is not an image reference. A reference is
        \\
        \\    [registry/][namespace/]name[:tag][@sha256:<64 hex digits>]
        \\
        \\and zbx never guesses a repair: an uppercase name, a space, a URL, a
        \\missing name or a digest of another kind is refused with the reason.
        \\
        \\Without a registry the image is on Docker Hub (docker.io), and a name of
        \\one part there lives in the library/ namespace, so "alpine:3.20" is
        \\docker.io/library/alpine:3.20. The first part names a registry when it
        \\has a dot or a port, or is "localhost"; otherwise it is a namespace.
        \\With no tag and no digest the tag is "latest". With both a tag and a
        \\digest, the digest decides.
        \\
        \\The message names what is wrong with the text.
        ,
    },
    .{
        .code = .E0502,
        .severity = .@"error",
        .blame = .environment,
        .summary = "the registry's name does not resolve",
        .explanation =
        \\zbx could not find an address for the registry's host name. Either the
        \\name is misspelled in the reference, or this machine has no working DNS,
        \\or the network is down.
        \\
        \\When the machine reaches the internet through an HTTPS proxy (the
        \\HTTPS_PROXY variable), the proxy looks the name up and this error means
        \\the proxy could not. Check the name in the reference first, then that
        \\other programs on this machine can resolve names.
        ,
    },
    .{
        .code = .E0503,
        .severity = .@"error",
        .blame = .environment,
        .summary = "can't reach the registry",
        .explanation =
        \\zbx found the registry's address but the connection failed: it was
        \\refused, the network is unreachable, the proxy refused to open a tunnel,
        \\or nothing answered within 30 seconds.
        \\
        \\zbx honours HTTPS_PROXY and NO_PROXY (and the lower-case spellings). A
        \\proxy that is set but not running, or a firewall that blocks the
        \\registry, shows up here. The message names the host, the port and the
        \\reason; --verbose adds the system error.
        \\
        \\A registry on localhost is spoken to in plain HTTP on the port in the
        \\reference.
        ,
    },
    .{
        .code = .E0504,
        .severity = .@"error",
        .blame = .environment,
        .summary = "the registry's certificate can't be trusted",
        .explanation =
        \\The TLS handshake with the registry failed its checks: the certificate
        \\does not lead to a root this machine trusts, it has expired, or it is for
        \\another host name. zbx verifies every HTTPS connection and has no option
        \\to turn that off.
        \\
        \\Behind a proxy that inspects traffic, the proxy's own certificate
        \\authority must be trusted: put it in the system store, or point
        \\SSL_CERT_FILE at a file holding the certificates to trust. A wrong clock
        \\makes every certificate look expired or not yet valid.
        ,
    },
    .{
        .code = .E0505,
        .severity = .@"error",
        .blame = .external,
        .summary = "the registry answered with an error",
        .explanation =
        \\The registry answered a request with an HTTP status that zbx does not
        \\handle, or a redirect it could not follow. The message names the URL
        \\without its query (a query can carry a signature) and the status.
        \\
        \\A 5xx status is the registry's own failure and usually passes: run the
        \\command again later. Statuses with their own meaning have their own
        \\codes: 401 is ZBX-E0507, 404 is ZBX-E0508 and 429 is ZBX-E0506.
        ,
    },
    .{
        .code = .E0506,
        .severity = .@"error",
        .blame = .external,
        .summary = "the registry is rate limiting this host",
        .explanation =
        \\The registry answered 429 Too Many Requests. Docker Hub limits anonymous
        \\pulls by the address they come from, so machines behind one NAT, and
        \\CI runners, share one allowance.
        \\
        \\zbx does not retry on its own: a retry inside the limit only uses more
        \\of it. When the registry says how long to wait (Retry-After) the message
        \\gives it. Try again after that, name a mirror of Docker Hub in
        \\ZBX_REGISTRY_MIRRORS (for example mirror.gcr.io), pull from another
        \\registry, or reuse an image already in the store (zbx store ls).
        ,
    },
    .{
        .code = .E0507,
        .severity = .@"error",
        .blame = .external,
        .summary = "the registry refused anonymous access",
        .explanation =
        \\zbx pulls anonymously: when a registry answers 401 it asks for a token
        \\from the realm in the WWW-Authenticate header, with no credentials, and
        \\repeats the request once. This time that did not work: the token
        \\service refused, the registry refused the token, or the challenge asked
        \\for credentials (Basic) that zbx does not have.
        \\
        \\A private image, or one that does not exist (some registries answer
        \\"denied" for both), ends here. Private registries are not supported
        \\yet. Check the name; the message says which step was refused.
        ,
    },
    .{
        .code = .E0508,
        .severity = .@"error",
        .blame = .user,
        .summary = "the registry has no such image",
        .explanation =
        \\The registry answered 404 for the manifest: the repository does not
        \\exist, or the tag or digest is not in it. The message names the
        \\registry, the repository and the tag or digest.
        \\
        \\Check the spelling, and the tag with the registry's own listing. On
        \\Docker Hub an official image lives in library/, which zbx adds for a
        \\name of one part.
        ,
    },
    .{
        .code = .E0509,
        .severity = .@"error",
        .blame = .user,
        .summary = "the image has no build for this platform",
        .explanation =
        \\An image index lists one image per platform. zbx runs linux/amd64 and
        \\linux/arm64 images, the one that matches this machine (arm64 images
        \\with variant v8 or none), and the index has none for it. The message
        \\lists the platforms the image offers, up to eight.
        \\
        \\Choose another tag or image, or run on a machine of a platform the
        \\image has. An image built for another CPU cannot run here.
        ,
    },
    .{
        .code = .E0510,
        .severity = .@"error",
        .blame = .external,
        .summary = "the registry sent a type of document zbx does not read",
        .explanation =
        \\zbx reads the OCI image index and manifest and the Docker v2 manifest
        \\list and manifest, with layers that are tar, gzip tar or zstd tar. The
        \\registry sent something else and the message names its media type:
        \\the old Docker schema 1 manifests, a Helm chart or other artifact, a
        \\layer type that cannot be unpacked here, or a document whose own type
        \\and Content-Type disagree.
        \\
        \\zbx refuses rather than guess from the shape of the JSON. Pull an image
        \\that is published in the supported formats.
        ,
    },
    .{
        .code = .E0511,
        .severity = .@"error",
        .blame = .external,
        .summary = "downloaded bytes do not match their digest",
        .explanation =
        \\Every manifest and every layer is named by the SHA-256 of its bytes, and
        \\zbx hashes what arrives before using it. These bytes hash to something
        \\else than the digest that named them (or than the Docker-Content-Digest
        \\header), or a layer in the blob cache has changed on the disk since it
        \\was downloaded. The message shows both digests.
        \\
        \\The bytes were damaged on the way, or the registry, a mirror or a proxy
        \\in between is serving something it should not. Nothing from this
        \\answer was kept. Try again; if it repeats, the source is not to be
        \\trusted. For a damaged cache the message gives the file to remove.
        ,
    },
    .{
        .code = .E0512,
        .severity = .@"error",
        .blame = .external,
        .summary = "the registry's answer can't be used",
        .explanation =
        \\The registry answered, but the answer is not a document zbx can use:
        \\the JSON is malformed or too complex, a manifest is larger than 1 MiB,
        \\an index has more than 256 entries, an image more than 128 layers, a
        \\digest is not sha256 and 64 hex digits, or a size is zero or too large.
        \\
        \\The message says which. Nothing was kept. This is the registry's or a
        \\proxy's fault, not something to fix on this machine.
        ,
    },
    .{
        .code = .E0513,
        .severity = .@"error",
        .blame = .external,
        .summary = "the registry's answer ended early",
        .explanation =
        \\The connection ended, or went quiet, before the whole answer arrived: the
        \\body was shorter than the Content-Length the registry declared. zbx does
        \\not use part of a document.
        \\
        \\A network drop or a proxy timeout is the usual cause. Run the command
        \\again.
        ,
    },
    .{
        .code = .E0514,
        .severity = .@"error",
        .blame = .user,
        .summary = "not a registry mirror",
        .explanation =
        \\ZBX_REGISTRY_MIRRORS names registries to try before Docker Hub, as a
        \\comma-separated list of host or host:port, for example
        \\
        \\    ZBX_REGISTRY_MIRRORS=mirror.gcr.io
        \\
        \\At most four are read, each a DNS name, with no scheme and no path. An
        \\entry that is anything else is refused at once, also for a pull that
        \\would not use it, so a typo is found before it matters.
        \\
        \\A mirror only changes where bytes come from: every answer is checked by
        \\digest, so a mirror can make a pull fail but never change what is
        \\pulled. The lock file records the reference as written, not the mirror.
        ,
    },
    .{
        .code = .E0515,
        .severity = .@"error",
        .blame = .external,
        .summary = "a layer entry would leave the image's root",
        .explanation =
        \\A layer of the image holds an entry that could write outside the
        \\directory the image is unpacked into, and zbx refused the whole layer:
        \\an absolute path, a path with "..", a path that goes through a symlink
        \\(the layer or an earlier one made it), or a hard link to a path outside
        \\the image. An honest image has none; the message names the entry.
        \\
        \\Nothing from the image was kept in the store as a tree. The blobs that
        \\were downloaded stay, so the layer is not fetched again. Do not run an
        \\image you did not build or trust.
        ,
    },
    .{
        .code = .E0516,
        .severity = .@"error",
        .blame = .external,
        .summary = "a layer can't be unpacked",
        .explanation =
        \\A layer of the image is damaged or uses something zbx does not read:
        \\a compressed stream that is cut or corrupt, a tar header with a wrong
        \\checksum, a sparse file, a name over 4095 bytes, a hard link to a file
        \\that is not there, an owner the user namespace does not map, or more
        \\than 64 GiB in one layer. The message says which, and names the entry.
        \\
        \\The blob was checked against its digest when it arrived, so the image
        \\itself is at fault (or the disk is, if the digest check also fails).
        \\Nothing from the image was kept in the store as a tree.
        ,
    },
    .{
        .code = .E0517,
        .severity = .@"error",
        .blame = .external,
        .summary = "an image's configuration can't be used",
        .explanation =
        \\The configuration of an image (the JSON blob its manifest names) says what
        \\it runs by default: the entrypoint, the command, the environment, the
        \\working directory and the user. This one is not JSON of that shape, or has
        \\more words or more bytes than zbx keeps (48 words in a list, 64 variables,
        \\1024 bytes in a word, 6 KiB in all), or an environment entry without a
        \\name or a "=".
        \\
        \\The blob was checked against its digest, so the image is at fault. Nothing
        \\from the image was recorded. Try another tag of the image.
        ,
    },
    .{
        .code = .E0518,
        .severity = .@"error",
        .blame = .user,
        .summary = "zbx.lock can't be read",
        .explanation =
        \\zbx.lock is ZON, one field a line, and zbx reads it line by line. The
        \\message names the line and what is wrong with it: a line that belongs
        \\nowhere, a digest or platform that is not one, an entry missing a field,
        \\two entries for one image, a version newer than this zbx reads, or more
        \\than 256 entries.
        \\
        \\Fix the line, or remove the file and run zbx pull again to write a new
        \\one: the lock only records what each reference resolved to, and a pull
        \\makes it again. Do not edit a lock to point at digests you have not
        \\checked.
        ,
    },
    .{
        .code = .E0519,
        .severity = .@"error",
        .blame = .user,
        .summary = "zbx.lock and the store disagree about an image",
        .explanation =
        \\zbx.lock says the reference means one tree, and the store's record of the
        \\image with the lock's manifest digest says another. A run starts from
        \\neither: it would be running something nobody chose.
        \\
        \\The message names both tree digests. Either the lock was changed by hand
        \\(or by a merge), or the store's record was made by a different pull. To
        \\take the store's tree as the truth, remove the entry or the file and pull
        \\again; to keep the lock's, restore the store from it with the pull the
        \\message shows.
        ,
    },
    .{
        .code = .E0520,
        .severity = .@"error",
        .blame = .user,
        .summary = "the image zbx.lock names is not in the store",
        .explanation =
        \\zbx.lock names a manifest digest for the reference, and the store has no
        \\image with that digest. The store may be new, the image may have been
        \\removed (zbx store rm), or the lock may name a digest that was never
        \\pulled. A run never fetches by itself, because the lock is what says what
        \\to trust.
        \\
        \\The message names the digest the lock wants and, if the store has some
        \\other image under the same reference, that one. Pull the locked digest to
        \\fill the store from the lock:  zbx pull <repository>@sha256:<digest>
        ,
    },
    .{
        .code = .E0521,
        .severity = .@"error",
        .blame = .external,
        .summary = "the image's user is not in the image",
        .explanation =
        \\The image's configuration says it runs as a user (or group) by name, and the
        \\image's own /etc/passwd or /etc/group has no such name. A number needs no
        \\lookup and is used as it is; a name does. The message names what was looked
        \\for and where.
        \\
        \\The image is at fault. Nothing was started.
        ,
    },
    .{
        .code = .E0522,
        .severity = .@"error",
        .blame = .user,
        .summary = "no image of that name is locked or in the store",
        .explanation =
        \\zbx run was given a name that is not a tree digest, and neither zbx.lock nor
        \\the store knows an image by it. A run starts only what a lock has recorded
        \\(or what is in the store when a library caller names it): it does not pull
        \\by itself once a zbx.lock exists. Run zbx pull with the name to fetch the
        \\image and record it.
        ,
    },
    .{
        .code = .E0523,
        .severity = .@"error",
        .blame = .environment,
        .summary = "the image's user needs more ids than this run maps",
        .explanation =
        \\The image runs as a user other than root. That user's id exists in the
        \\container only when the container maps a whole range of ids, which needs
        \\the setuid helpers newuidmap and newgidmap and a range of subordinate ids
        \\for your account. Without them the container maps only root, to your own
        \\id (the warning ZBX-W0201 says so), and the image's user cannot be set.
        \\
        \\Give your account the ranges (zbx doctor shows how), or use an image that
        \\runs as root.
        ,
    },
    .{
        .code = .E0524,
        .severity = .@"error",
        .blame = .user,
        .summary = "the image has no command to run",
        .explanation =
        \\The image sets neither an entrypoint nor a command, and none was given after
        \\"--". Docker would fail the same way. Give the command to run:
        \\
        \\    zbx run <image> -- <command> [arguments]
        ,
    },
    .{
        .code = .E0525,
        .severity = .@"error",
        .blame = .environment,
        .summary = "zbx.lock can't be written",
        .explanation =
        \\zbx writes zbx.lock to the nearest directory up from the working directory
        \\that has one, or else the working directory, through a temporary file in
        \\the same directory that it renames over the lock. That failed: the disk is
        \\full, the directory is not writable, or it is read-only. The message gives
        \\the path and the reason. The image itself was pulled and is in the store;
        \\run the command again once the directory can be written.
        ,
    },
    .{
        .code = .E0526,
        .severity = .@"error",
        .blame = .user,
        .summary = "there is no zbx.lock for this project",
        .explanation =
        \\zbx lock show prints the project's zbx.lock: the nearest one in the working
        \\directory or any directory above it. There is none. A lock is made by the
        \\first pull (or the first run of a tag) in the project directory, so pull
        \\an image to make one, from the directory the project lives in.
        ,
    },
    .{
        .code = .W0501,
        .severity = .warning,
        .blame = .external,
        .summary = "device nodes in a layer were left out",
        .explanation =
        \\A layer holds device nodes, FIFOs or sockets. The store keeps regular
        \\files, directories and symlinks only, and a rootless container cannot
        \\make device nodes, so they were skipped. The message names the first
        \\and says how many there were.
        \\
        \\A container gets its own /dev, so a root filesystem does not miss them.
        ,
    },
    .{
        .code = .W0502,
        .severity = .warning,
        .blame = .external,
        .summary = "extended attributes in a layer were left out",
        .explanation =
        \\The store keeps the user.* attributes and security.capability. A layer
        \\carried others (trusted.*, system.*, security.selinux), too many on one
        \\file or too large, or this file system would not take them, so they
        \\were skipped. The message names the first file and says how many.
        \\
        \\The tree's digest does not cover them. Nothing to do unless the image
        \\relies on file capabilities that were refused: then the program may
        \\need a different capability setup.
        ,
    },
    .{
        .code = .W0503,
        .severity = .warning,
        .blame = .user,
        .summary = "no zbx.lock was found, so one was written",
        .explanation =
        \\zbx run was given an image name and there is no zbx.lock in the working
        \\directory or any directory above it. It pulled the image and wrote zbx.lock
        \\in the working directory, recording which manifest and tree the name meant
        \\today. Commit the file to keep every machine on the same image. The next run
        \\checks the store against it and refuses if they differ.
        ,
    },
    .{
        .code = .E0600,
        .severity = .@"error",
        .blame = .user,
        .summary = "--publish is not a usable HOST:CONTAINER",
        .explanation =
        \\--publish HOST:CONTAINER forwards TCP port HOST of this machine to port
        \\CONTAINER of the container, through pasta. Both are decimal port numbers
        \\from 1 to 65535, with no protocol after them: every forward is TCP. The
        \\option may be given up to 16 times, each with its own host port.
        \\
        \\--publish gives the container a network of its own through pasta, as
        \\--net user does, so it needs no --net. The cause names what is wrong with
        \\the value; nothing was started.
        ,
    },
    .{
        .code = .E0601,
        .severity = .@"error",
        .blame = .environment,
        .summary = "pasta is not installed",
        .explanation =
        \\--net user and --publish connect the container to the network through
        \\pasta, a program from the passt project that runs as the user, needs no
        \\privilege and changes no firewall rule, route or interface of the host.
        \\zbx looks for it in the directories of PATH and found none.
        \\
        \\Install it (Debian and Ubuntu: apt install passt; Fedora: dnf install
        \\passt), or run without a network (the default) or with the host's
        \\(--net host). zbx doctor shows whether pasta was found.
        ,
    },
    .{
        .code = .E0602,
        .severity = .@"error",
        .blame = .environment,
        .summary = "pasta is too old",
        .explanation =
        \\zbx attaches pasta to the container's network namespace by the
        \\container's process id. pasta releases created before 2024_02_16 do not
        \\notice when such a namespace goes away, so they would keep the published
        \\ports after the container ended. zbx refuses them before it starts
        \\anything.
        \\
        \\The cause names the version found and the one needed. Install a newer
        \\passt package; Ubuntu 24.04 and Debian 13 ship one that is new enough.
        ,
    },
    .{
        .code = .E0603,
        .severity = .@"error",
        .blame = .environment,
        .summary = "pasta failed to start",
        .explanation =
        \\zbx started pasta to connect the container's network namespace, and pasta
        \\ended, or did not report the interface ready within 10 seconds, before
        \\the container's command could run. The container was stopped and never
        \\ran.
        \\
        \\The cause is pasta's own last line. Its whole output is in the run's
        \\pasta log, named in the context (zbx state directory, logs). A host with
        \\no default route, or a security policy that confines pasta, are the
        \\usual reasons.
        ,
    },
    .{
        .code = .E0604,
        .severity = .@"error",
        .blame = .user,
        .summary = "a published host port is already in use",
        .explanation =
        \\--publish HOST:CONTAINER has pasta listen on port HOST of this machine,
        \\on every address. Another program already listens there, so pasta could
        \\not, and the container was not started.
        \\
        \\Choose another host port, or stop the program that holds it. On the host,
        \\ss -tlnp shows which program listens on which port.
        ,
    },
    .{
        .code = .E0605,
        .severity = .@"error",
        .blame = .environment,
        .summary = "the host lets users bind no port this low",
        .explanation =
        \\pasta listens on the host's port as the user, without privilege. Linux
        \\lets an unprivileged process bind only ports from
        \\net.ipv4.ip_unprivileged_port_start up (1024 unless changed), so a lower
        \\host port was refused before anything started. The container's own port
        \\may be low: port 80 inside the container works.
        \\
        \\Publish a host port at or above that bound (--publish 8080:80), or lower
        \\the bound for every user, as root:
        \\    sysctl net.ipv4.ip_unprivileged_port_start=80
        ,
    },
    .{
        .code = .E0701,
        .severity = .@"error",
        .blame = .environment,
        .summary = "no state directory to keep bundles and run records in",
        .explanation =
        \\zbx keeps run records and diagnostic bundles under $XDG_STATE_HOME/zbx,
        \\or ~/.local/state/zbx when that is not set, and the layers of a container
        \\started from a tree digest under its containers directory. Neither
        \\variable names an absolute directory here, so there is nowhere to read a
        \\run record from, to write a bundle to or to put a container.
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
        .code = .E0705,
        .severity = .@"error",
        .blame = .user,
        .summary = "not a valid state volume name",
        .explanation =
        \\A state volume's name is a directory name under the state directory, never
        \\a path: lowercase letters, digits, '.', '-' and '_', starting with a letter
        \\or a digit, at most 63 bytes. "pgdata", "web.cache" and "db_2" are names;
        \\"PgData", ".hidden" and "a/b" are not.
        \\
        \\--state takes NAME:PATH, or NAME:PATH:ro to mount it read-only:
        \\    zbx run --state pgdata:/var/lib/postgresql/data postgres:16
        ,
    },
    .{
        .code = .E0706,
        .severity = .@"error",
        .blame = .user,
        .summary = "the state volume is in use",
        .explanation =
        \\A state volume has one writer at a time. A run that mounts it read-write
        \\holds it for its whole life, from before its command starts until it ends
        \\(a clean exit, zbx stop, --timeout, a killed container or a killed zbx all
        \\let it go). A run that mounts it with :ro shares it with other readers,
        \\never with a writer. zbx state rm needs it free as well.
        \\
        \\The cause names the container that holds it. Stop that container first
        \\(zbx stop <name>), or mount the volume read-only with NAME:PATH:ro if
        \\reading is all this run needs.
        ,
    },
    .{
        .code = .E0707,
        .severity = .@"error",
        .blame = .user,
        .summary = "no state volume with that name",
        .explanation =
        \\There is no state volume of that name in the state directory
        \\($XDG_DATA_HOME/zbx/state, or ~/.local/share/zbx/state). A volume is made
        \\only by the first run that names it with --state, and removed only by zbx
        \\state rm, after which zbx state restore brings it back for a week.
        \\
        \\zbx state ls lists the volumes, and the trash.
        ,
    },
    .{
        .code = .E0708,
        .severity = .@"error",
        .blame = .user,
        .summary = "a state volume with that name exists already",
        .explanation =
        \\zbx state restore puts a removed volume back under its name, and a volume
        \\of that name was made again since it was removed (a run named it with
        \\--state). Restoring would replace the new one, so nothing was changed.
        \\
        \\Remove the new volume first if it is not needed (zbx state rm <name>,
        \\which moves it to the trash too), then restore the old one.
        ,
    },
    .{
        .code = .E0709,
        .severity = .@"error",
        .blame = .user,
        .summary = "no state volume with that name in the trash",
        .explanation =
        \\zbx state restore brings back a volume that zbx state rm moved to the trash.
        \\The trash has no volume of that name: it was never removed, the name is
        \\misspelled, or its trash was emptied by a later zbx state rm after it
        \\expired.
        \\
        \\zbx state ls lists the volumes and what the trash holds.
        ,
    },
    .{
        .code = .E0710,
        .severity = .@"error",
        .blame = .user,
        .summary = "the state volume's trash has expired",
        .explanation =
        \\What zbx state rm moves to the trash is kept for 7 days, as what zbx store
        \\gc moves is; after that the next zbx state rm empties it. This volume was
        \\removed longer ago than that, so it is not restored: an expired trash is
        \\due to go, and bringing it back would make the expiry a matter of luck.
        \\
        \\Its files are still in the trash directory until then
        \\(<state>/.trash/<name>@<seconds>), and can be copied out by hand from the
        \\user's namespace: unshare --map-auto --map-root-user, then cp -a.
        ,
    },
    .{
        .code = .E0711,
        .severity = .@"error",
        .blame = .environment,
        .summary = "can't make or read the state directory",
        .explanation =
        \\State volumes live in $XDG_DATA_HOME/zbx/state, or ~/.local/share/zbx/state
        \\when that is not set, beside the store. Either neither variable names an
        \\absolute directory, or a directory or file there could not be made, read
        \\or written; the cause names the path and what the system said. A full
        \\disk and a directory owned by another user are the usual reasons.
        \\
        \\Set HOME, or point XDG_DATA_HOME at a directory you own with room.
        ,
    },
    .{
        .code = .E0712,
        .severity = .@"error",
        .blame = .environment,
        .summary = "can't read a state volume's record",
        .explanation =
        \\Each volume has a small record, <state>/<name>/state.zon: when it was made,
        \\when it was last used and by which container. This one is damaged, or was
        \\written by a newer zbx, which this one does not misread.
        \\
        \\Use the zbx that wrote it, or move the record aside: the volume's files in
        \\<state>/<name>/data are not touched, and the next run writes a new record.
        ,
    },
    .{
        .code = .E0713,
        .severity = .@"error",
        .blame = .environment,
        .summary = "can't mount a state volume in the container",
        .explanation =
        \\A state volume is bound into the container before its command starts: its
        \\data directory is made by the container's root, bound in the container's
        \\/dev, then moved onto its path once the container's root is entered, so
        \\that the path is read as the container reads it. One of those steps
        \\failed; the cause names it and what the kernel said.
        \\
        \\With --read-only the path must already exist in the image: nothing can be
        \\made in a read-only root. zbx doctor shows what this host allows.
        ,
    },
    .{
        .code = .E0714,
        .severity = .@"error",
        .blame = .user,
        .summary = "won't write the archive to a terminal",
        .explanation =
        \\zbx state export writes a gzip-compressed tar archive: binary data a
        \\terminal would show as noise. Standard output is a terminal, so nothing
        \\was read.
        \\
        \\Name a file with -o, or redirect the output:
        \\    zbx state export pgdata -o pgdata.tar.gz
        \\    zbx state export pgdata > pgdata.tar.gz
        ,
    },
    .{
        .code = .E0715,
        .severity = .@"error",
        .blame = .environment,
        .summary = "can't write the archive",
        .explanation =
        \\The archive could not be written: the file named with -o cannot be made,
        \\the disk is full, or the output was closed. The cause says which. A file
        \\that was started is removed again; nothing partial is left.
        \\
        \\Free space, or write somewhere else with -o.
        ,
    },
    .{
        .code = .E0716,
        .severity = .@"error",
        .blame = .environment,
        .summary = "can't read the state volume to export it",
        .explanation =
        \\Exporting reads every file of the volume in the user's namespace, where
        \\files of the container's users can be read. The read stopped: a file or
        \\directory could not be read, one changed while it was read, the tree is
        \\deeper than 64 directories, a path is longer than 4095 bytes, or it has
        \\more entries or more files with several names than one export keeps
        \\(4194304 and 16384). The cause says which.
        \\
        \\Nothing is written for a stopped export when -o names a file. A volume
        \\that a container is still changing cannot be read consistently: stop it
        \\first.
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
        .code = .W0702,
        .severity = .warning,
        .blame = .environment,
        .summary = "a state volume's size could not be counted",
        .explanation =
        \\zbx state ls counts a volume's size in the user's namespace, where files of
        \\the container's users can be read, each file with several names once. The
        \\count stopped for this volume (a file could not be read, the tree is deeper
        \\than 64 directories, or it has more names or hard links than one listing
        \\keeps), so its size is shown as unknown. The rest of the listing is right.
        \\
        \\du -sh in the user's namespace counts it by hand:
        \\    unshare --map-auto --map-root-user du -sh <state>/<name>/data
        ,
    },
    .{
        .code = .W0703,
        .severity = .warning,
        .blame = .user,
        .summary = "a file was left out of the export",
        .explanation =
        \\A state volume can hold files a tar archive of this kind does not keep:
        \\devices, sockets and fifos. Each one is skipped with this note (the
        \\first 16; the rest are counted). The archive holds everything else, and
        \\is complete without them.
        ,
    },
    .{
        .code = .E1001,
        .severity = .@"error",
        .blame = .environment,
        .summary = "this zbx is not allowed to run virtual machines",
        .explanation =
        \\On a Mac, zbx runs containers in a small Linux virtual machine that it
        \\starts through Apple's Virtualization.framework. The framework refuses a
        \\program that does not carry the com.apple.security.virtualization
        \\entitlement, or a Mac that cannot virtualize at all (an Intel Mac, or a
        \\Mac inside another virtual machine without nested virtualization).
        \\
        \\A zbx installed from a release is signed with the entitlement already.
        \\A zbx built from source is not: sign it with the entitlements file in
        \\the repository (vm/zbx.entitlements). An ad-hoc signature is enough on
        \\the Mac that built it.
        ,
    },
    .{
        .code = .E1002,
        .severity = .@"error",
        .blame = .environment,
        .summary = "the virtual machine did not start",
        .explanation =
        \\Virtualization.framework refused to start the Linux virtual machine, or
        \\the machine failed while it started. The cause gives the framework's own
        \\words, its error domain and its code, and the step that failed
        \\(configuring, validating or starting).
        \\
        \\The usual reasons are a size the framework does not allow (see zbx vm
        \\config), too little free memory on the Mac, and a damaged VM image.
        \\The machine's console is in the log file the diagnostic names: its last
        \\lines say how far the guest got.
        ,
    },
    .{
        .code = .E1003,
        .severity = .@"error",
        .blame = .environment,
        .summary = "the virtual machine did not answer in time",
        .explanation =
        \\The virtual machine started, but its init did not answer on the vsock
        \\port within the time zbx allows for a boot. The kernel may have stopped
        \\(see the console log the diagnostic names), or the Mac is too busy to
        \\run it.
        \\
        \\zbx vm stop stops what is left of it; the next command starts a fresh
        \\one. If it happens every time, send the console log with the report.
        ,
    },
    .{
        .code = .E1004,
        .severity = .@"error",
        .blame = .environment,
        .summary = "another process holds the virtual machine",
        .explanation =
        \\There is one virtual machine per user, owned by one host process that
        \\holds a lock file in the VM directory. That lock is held, but the process
        \\that holds it does not answer on its control socket: it is starting, hung
        \\or stuck. A host that was killed leaves no lock behind, so this is not a
        \\stale file.
        \\
        \\The cause names the process. If it is hung, end it with kill, and run the
        \\command again.
        ,
    },
    .{
        .code = .E1005,
        .severity = .@"error",
        .blame = .environment,
        .summary = "can't make or write the VM directory",
        .explanation =
        \\zbx keeps the virtual machine's files in ~/Library/Application Support/
        \\zbx/vm: the unpacked kernel and initramfs, the console log, the lock
        \\and the control socket. A file or directory there could not be made,
        \\read or written, or the path is too long for a Unix socket (103 bytes).
        \\The cause names the path and what the system said.
        \\
        \\A full disk and a directory owned by another user are the usual
        \\reasons. HOME decides the place.
        ,
    },
    .{
        .code = .E1006,
        .severity = .@"error",
        .blame = .user,
        .summary = "no virtual machine is running",
        .explanation =
        \\zbx vm stop was asked to stop the virtual machine, and there is none. The
        \\machine starts by itself when a command needs it and stops by itself
        \\when it has been idle, so this is often exactly what you wanted.
        \\
        \\zbx vm status says whether one is running.
        ,
    },
    .{
        .code = .E1007,
        .severity = .@"error",
        .blame = .user,
        .summary = "the virtual machine's size is out of range",
        .explanation =
        \\zbx vm config sets how many CPUs and how much memory the virtual machine
        \\boots with. The value is outside what this Mac allows: zbx's own limits,
        \\Virtualization.framework's, and the Mac's CPUs and memory together. The
        \\cause names the allowed range. Memory is in whole MiB: 2G, 4096M.
        \\
        \\Nothing was changed. zbx vm config with no options shows the current
        \\values.
        ,
    },
    .{
        .code = .E1008,
        .severity = .@"error",
        .blame = .environment,
        .summary = "can't read the virtual machine's settings",
        .explanation =
        \\The file ~/Library/Application Support/zbx/vm-settings holds the size
        \\chosen with zbx vm config. This one is damaged, or was written by a newer
        \\zbx, which this one does not misread.
        \\
        \\Set the size again with zbx vm config, which writes a new file, or move
        \\the old one aside.
        ,
    },
    .{
        .code = .W1001,
        .severity = .warning,
        .blame = .environment,
        .summary = "replacing a virtual machine of another version",
        .explanation =
        \\A virtual machine is running from an image (kernel and initramfs) of
        \\another version than this zbx carries, left over from before an upgrade.
        \\zbx does not drive it: it stops it and starts one from its own image.
        \\
        \\Nothing is lost that the containers did not already lose by the stop of
        \\their machine; state volumes are not in the machine's memory.
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
    @setEvalBranchQuota(400_000);
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

/// Which family of exit codes a command uses. A command that runs a container passes the
/// container's own exit code through, so it cannot also use the standard four.
pub const ExitScope = enum { standard, container_run };

/// The exit code for a failure of `code`, in `scope`. `command_missing` is true only for an
/// E0202 whose cause is a command that was not found (as opposed to one that cannot be run).
/// The only place that decides, for both scopes; call sites pass what they know and never pick.
pub fn exit_code_in(scope: ExitScope, code: Code, command_missing: bool) u8 {
    if (command_missing) assert(code == .E0202);
    const result: u8 = switch (scope) {
        .standard => exit_code(entry(code).blame),
        .container_run => if (code == .E0202)
            (if (command_missing) constants.exit_run_not_found else constants.exit_run_not_runnable)
        else
            constants.exit_run_failed,
    };
    assert(result != constants.exit_ok);
    if (scope == .container_run) assert(result >= constants.exit_run_failed);
    if (scope == .standard) assert(result <= constants.exit_internal);
    return result;
}

/// What the process exits with when a diagnostic cannot even be written to stderr. In the
/// standard scope that is the environment's code; a container run uses its own failure code.
pub fn exit_code_unwritable(scope: ExitScope) u8 {
    const result = switch (scope) {
        .standard => constants.exit_environment,
        .container_run => constants.exit_run_failed,
    };
    assert(result != constants.exit_ok);
    assert(result != constants.exit_internal);
    return result;
}

/// Whether a failure of this code can end a `zbx run`. The commands that report the others
/// (the doctor's checks, `explain`, `bundle`, a missing command word) never run a container.
pub fn can_end_run(code: Code) bool {
    assert(@backingInt(code) < registry.len);
    assert(registry[@backingInt(code)].code == code);
    return switch (code) {
        .E0001, .E0002, .E0007 => false,
        .E0101, .E0102, .E0103, .E0104, .E0105, .E0106 => false,
        .E0702, .E0703, .E0704 => false,
        .E0707, .E0708, .E0709, .E0710, .W0702 => false,
        .E0714, .E0715, .E0716, .W0703 => false,
        .E0402, .E0403, .E0404, .E0406 => false,
        .E0414, .E0418, .E0420, .E0426, .E0427, .E0428 => false,
        .E0429, .E0430, .E0431, .E0432, .E0433, .E0434, .E0435, .E0436 => false,
        .W0410, .W0411, .W0412, .W0413 => false,
        .E0501, .E0502, .E0503, .E0504, .E0505, .E0506, .E0507 => false,
        .E0508, .E0509, .E0510, .E0511, .E0512, .E0513, .E0514 => false,
        .E0515, .E0516, .E0517, .W0501, .W0502, .E0526 => false,
        .E1006, .E1007 => false,
        else => true,
    };
}

/// The longest text `exit_text` writes.
pub const exit_text_bytes_max = 40;

/// How a code's exit code reads in `zbx explain` and on the error pages: the standard one and,
/// for a failure that `zbx run` can report, the code `run` uses instead. A warning never ends a
/// command, so it has only the standard one.
pub fn exit_text(code: Code, buffer: *[exit_text_bytes_max]u8) []const u8 {
    const found = entry(code);
    const standard = exit_code_in(.standard, code, false);
    const text = if (found.severity == .warning or !can_end_run(code))
        std.fmt.bufPrint(buffer, "{d}", .{standard})
    else if (code == .E0202)
        std.fmt.bufPrint(buffer, "{d} ({d} or {d} in zbx run)", .{
            standard,
            exit_code_in(.container_run, code, false),
            exit_code_in(.container_run, code, true),
        })
    else
        std.fmt.bufPrint(buffer, "{d} ({d} in zbx run)", .{
            standard,
            exit_code_in(.container_run, code, false),
        });
    const written = text catch unreachable; // The longest form is 24 bytes; the buffer holds 40.
    assert(written.len > 0);
    assert(written.len <= exit_text_bytes_max);
    return written;
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

test "a container run exits 125, 126 or 127 for zbx's own failures, whatever the blame" {
    // Goal: no code of the registry can make a container run exit with a standard code, and E0202
    // alone splits into 126 and 127. Method: every entry, in both scopes.
    for (registry) |item| {
        const standard = exit_code_in(.standard, item.code, false);
        try std.testing.expectEqual(exit_code(item.blame), standard);
        const run = exit_code_in(.container_run, item.code, false);
        if (item.code == .E0202) {
            try std.testing.expectEqual(@as(u8, 126), run);
            try std.testing.expectEqual(@as(u8, 127), exit_code_in(.container_run, .E0202, true));
            try std.testing.expectEqual(standard, exit_code_in(.standard, .E0202, true));
        } else {
            try std.testing.expectEqual(@as(u8, 125), run);
        }
    }
    try std.testing.expectEqual(@as(u8, 125), exit_code_in(.container_run, .E0201, false));
    try std.testing.expectEqual(@as(u8, 125), exit_code_in(.container_run, .B0001, false));
    var text: [exit_text_bytes_max]u8 = undefined;
    try std.testing.expectEqualStrings("1 (125 in zbx run)", exit_text(.E0201, &text));
    try std.testing.expectEqualStrings("1 (126 or 127 in zbx run)", exit_text(.E0202, &text));
    try std.testing.expectEqualStrings("70 (125 in zbx run)", exit_text(.B0001, &text));
    try std.testing.expectEqualStrings("2", exit_text(.E0101, &text)); // The doctor's, not a run's.
    try std.testing.expectEqual(@as(u8, 2), exit_code_unwritable(.standard));
    try std.testing.expectEqual(@as(u8, 125), exit_code_unwritable(.container_run));
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
