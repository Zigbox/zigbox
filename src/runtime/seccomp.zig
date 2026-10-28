//! The container's seccomp filter: the policy file (`policy/seccomp.zon`), compiled at build
//! time to one classic BPF program for x86_64 and aarch64, and the compiler itself, which works
//! on numbers so the fuzzer and the tests can feed it policies of their own.
//!
//! The program starts by reading the architecture: x86_64 and aarch64 jump to their own
//! section, and anything else (the 32-bit entry points of a 64-bit kernel above all) gets
//! EPERM. A section reads the syscall number, runs the argument rules, then the plain allowlist
//! in chunks, and ends in EPERM. A syscall not named anywhere fails with EPERM, not a kill, as
//! in Docker, so programs fail politely.
//!
//! Jump offsets in classic BPF are eight bits, so the allowlist is a chain of `jeq`s with a
//! `ret ALLOW` after every `chunk_max` of them for the matches to jump to; a long jump between
//! sections uses `ja`, whose offset has 32 bits. `run`-time work is none: the program is a
//! constant, and the child hands it to the kernel as it is.

const std = @import("std");
const assert = std.debug.assert;
const bpf = @import("bpf.zig");
const policy_file = @import("policy/seccomp.zon");

const linux = std.os.linux;
const Insn = bpf.Insn;

pub const ret_allow: u32 = linux.SECCOMP.RET.ALLOW;
pub const errno_perm: u32 = 1;
pub const errno_nosys: u32 = 38;

/// What a rule does with a syscall it names (`policy/seccomp.zon` says how each is used).
pub const RuleKind = enum {
    /// Allowed if argument 0 is one of the values.
    equals_any,
    /// Allowed if argument 0 has none of the bits of `values[0]` set.
    mask_zero,
    /// Allowed unless argument 0 is `values[0]`.
    not_equal,
    /// Always fails, with errno `values[0]`.
    errno,
};

pub const rule_values_max: u32 = 8;

pub const Rule = struct {
    nr: u32,
    kind: RuleKind,
    values: [rule_values_max]u32,
    count: u8,
};

/// A policy for one architecture, as syscall numbers.
pub const Policy = struct {
    /// Allowed whatever the arguments.
    plain: []const u32,
    /// Checked before `plain`; the first rule for a number decides.
    rules: []const Rule,
};

pub const ArchPolicy = struct {
    /// The `AUDIT_ARCH_*` value the kernel puts in the data.
    audit_arch: u32,
    policy: Policy,
};

pub const CompileError = error{TooManyInstructions};

/// How many `jeq`s one `ret ALLOW` serves; a `jeq`'s jump must stay within eight bits.
pub const chunk_max: u32 = 100;

fn eperm() u32 {
    const value = linux.SECCOMP.RET.ERRNO | errno_perm;
    assert(value & linux.SECCOMP.RET.ACTION == linux.SECCOMP.RET.ERRNO);
    assert(value & linux.SECCOMP.RET.DATA == errno_perm);
    return value;
}

fn errno_return(errno: u32) u32 {
    assert(errno > 0);
    assert(errno <= linux.SECCOMP.RET.DATA);
    return linux.SECCOMP.RET.ERRNO | errno;
}

const Emitter = struct {
    out: []Insn,
    len: u32,

    fn push(emitter: *Emitter, insn: Insn) CompileError!void {
        assert(emitter.len <= emitter.out.len);
        assert(insn.code != 0);
        const room = @min(emitter.out.len, bpf.insns_max);
        if (emitter.len >= room) return error.TooManyInstructions;
        emitter.out[emitter.len] = insn;
        emitter.len += 1;
    }
};

/// The number of instructions of a rule's block, after its `jeq`.
fn block_len(rule: *const Rule) u32 {
    assert(rule.nr < 1 << 20);
    assert(rule.count <= rule_values_max);
    return switch (rule.kind) {
        .equals_any => 1 + rule.count + 2, // ld, one jeq per value, ret EPERM, ret ALLOW.
        .mask_zero => 5, // ld, and, jeq, ret EPERM, ret ALLOW.
        .not_equal => 4, // ld, jeq, ret EPERM, ret ALLOW.
        .errno => 1,
    };
}

/// The number of instructions of one architecture's section.
pub fn section_len(policy: *const Policy) u32 {
    assert(policy.rules.len <= 1024);
    assert(policy.plain.len <= 1 << 20);
    var length: u32 = 1; // ld nr.
    for (policy.rules) |*rule| length += 1 + block_len(rule);
    const plain: u32 = @intCast(policy.plain.len);
    length += plain + 2 * ((plain + chunk_max - 1) / chunk_max);
    return length + 1; // The final ret EPERM.
}

fn emit_rule(emitter: *Emitter, rule: *const Rule) CompileError!void {
    const length = block_len(rule);
    assert(length <= std.math.maxInt(u8));
    if (rule.kind == .equals_any) assert(rule.count > 0);
    try emitter.push(bpf.jeq(rule.nr, 0, @intCast(length)));
    switch (rule.kind) {
        .equals_any => {
            try emitter.push(bpf.ld(bpf.offset_arg(0)));
            for (rule.values[0..rule.count], 0..) |value, at| {
                // A match jumps over the later values and the EPERM, onto ret ALLOW.
                const to_allow: usize = (rule.count - at - 1) + 1;
                try emitter.push(bpf.jeq(value, @intCast(to_allow), 0));
            }
            try emitter.push(bpf.ret(eperm()));
            try emitter.push(bpf.ret(ret_allow));
        },
        .mask_zero => {
            try emitter.push(bpf.ld(bpf.offset_arg(0)));
            try emitter.push(bpf.and_k(rule.values[0]));
            try emitter.push(bpf.jeq(0, 1, 0));
            try emitter.push(bpf.ret(eperm()));
            try emitter.push(bpf.ret(ret_allow));
        },
        .not_equal => {
            try emitter.push(bpf.ld(bpf.offset_arg(0)));
            try emitter.push(bpf.jeq(rule.values[0], 0, 1));
            try emitter.push(bpf.ret(eperm()));
            try emitter.push(bpf.ret(ret_allow));
        },
        .errno => try emitter.push(bpf.ret(errno_return(rule.values[0]))),
    }
}

fn emit_section(emitter: *Emitter, policy: *const Policy) CompileError!void {
    assert(emitter.len > 0); // The header comes first.
    assert(chunk_max + 1 <= std.math.maxInt(u8)); // A match reaches its ret ALLOW in a byte.
    const start = emitter.len;
    try emitter.push(bpf.ld(bpf.offset_nr));
    for (policy.rules) |*rule| try emit_rule(emitter, rule);
    var from: usize = 0;
    while (from < policy.plain.len) {
        const to = @min(policy.plain.len, from + chunk_max);
        for (policy.plain[from..to], from..) |number, at| {
            // A match jumps over the later `jeq`s and the `ja` onto the chunk's ret ALLOW.
            const to_allow: u32 = @intCast((to - at - 1) + 1);
            try emitter.push(bpf.jeq(number, @intCast(to_allow), 0));
        }
        try emitter.push(bpf.ja(1));
        try emitter.push(bpf.ret(ret_allow));
        from = to;
    }
    try emitter.push(bpf.ret(eperm()));
    assert(emitter.len - start == section_len(policy));
}

/// Compiles the policies of the architectures this build supports into one program in `out`.
/// A syscall made under an architecture not listed gets EPERM.
pub fn compile(out: []Insn, arches: []const ArchPolicy) CompileError![]const Insn {
    assert(arches.len > 0);
    assert(arches.len <= 4);
    var emitter: Emitter = .{ .out = out, .len = 0 };
    const header: u32 = @intCast(1 + 2 * arches.len + 1);
    try emitter.push(bpf.ld(bpf.offset_arch));
    var start = header;
    for (arches, 0..) |arch, index| {
        try emitter.push(bpf.jeq(arch.audit_arch, 0, 1));
        // The `ja` sits right after its `jeq`; its distance counts from the next instruction.
        const here: u32 = @intCast(2 + 2 * index);
        try emitter.push(bpf.ja(start - here - 1));
        start += section_len(&arch.policy);
    }
    try emitter.push(bpf.ret(eperm()));
    assert(emitter.len == header);
    for (arches) |*arch| try emit_section(&emitter, &arch.policy);
    assert(emitter.len == start);
    return out[0..emitter.len];
}

/// Whether the program lets syscall `name` through on the machine this runs on. The simulator
/// asks it of the calls a container's child still makes after the filter is installed.
pub fn allows_native(filter: []const Insn, comptime name: []const u8) bool {
    assert(bpf.verify(filter) == null);
    const native = @import("builtin").cpu.arch;
    var data: bpf.Data = .{ .nr = 0, .arch = 0 };
    switch (native) {
        .x86_64 => {
            data.arch = audit_x86_64;
            data.nr = @backingInt(@field(SysX64, name));
        },
        .aarch64 => {
            data.arch = audit_aarch64;
            data.nr = @backingInt(@field(SysArm64, name));
        },
        else => return true, // No release runs there; nothing to ask.
    }
    return bpf.run(filter, &data) == ret_allow;
}

// ---- The policy file, resolved for each architecture, at build time --------------------------

const SysX64 = linux.syscalls.X64;
const SysArm64 = linux.syscalls.Arm64;

fn exists(comptime name: []const u8) bool {
    comptime assert(name.len > 0);
    return @hasField(SysX64, name) or @hasField(SysArm64, name);
}

fn number_on(comptime Sys: type, comptime name: []const u8) ?u32 {
    comptime assert(name.len > 0);
    if (!@hasField(Sys, name)) return null;
    return @backingInt(@field(Sys, name));
}

/// The numbers of the plain allowlist on one architecture. A name neither architecture has is
/// a build error (a typo would otherwise drop a syscall without a word).
fn plain_numbers(comptime Sys: type) []const u32 {
    comptime {
        @setEvalBranchQuota(2_000_000);
        var storage: [2048]u32 = undefined;
        var count: usize = 0;
        for (policy_file.groups) |group| {
            for (group.syscalls) |name| {
                if (!exists(name)) @compileError("seccomp.zon: no such syscall: " ++ name);
                if (number_on(Sys, name)) |number| {
                    storage[count] = number;
                    count += 1;
                }
            }
        }
        const final: [count]u32 = storage[0..count].*;
        return &final;
    }
}

fn rule_list(comptime Sys: type) []const Rule {
    comptime {
        @setEvalBranchQuota(200_000);
        var storage: [policy_file.rules.len]Rule = undefined;
        var count: usize = 0;
        for (policy_file.rules) |item| {
            if (!exists(item.syscall)) {
                @compileError("seccomp.zon: no such syscall: " ++ item.syscall);
            }
            const number = number_on(Sys, item.syscall) orelse continue;
            const kind = std.meta.stringToEnum(RuleKind, @tagName(item.kind)) orelse
                @compileError("seccomp.zon: unknown rule kind");
            var rule: Rule = .{ .nr = number, .kind = kind, .values = @splat(0), .count = 0 };
            if (item.values.len > rule_values_max) @compileError("seccomp.zon: too many values");
            for (item.values, 0..) |value, at| rule.values[at] = value;
            rule.count = item.values.len;
            storage[count] = rule;
            count += 1;
        }
        const final: [count]Rule = storage[0..count].*;
        return &final;
    }
}

fn policy_for(comptime Sys: type) Policy {
    return .{ .plain = plain_numbers(Sys), .rules = rule_list(Sys) };
}

/// `AUDIT_ARCH_X86_64` and `AUDIT_ARCH_AARCH64` (linux/audit.h): EM_* | 64BIT | LE. The standard
/// library's `AUDIT.ARCH` enum does not compile with this build, so they are written out.
pub const audit_x86_64: u32 = 0xc000003e;
pub const audit_aarch64: u32 = 0xc00000b7;

/// The two architectures a release is built for.
pub const release_arches = [_]ArchPolicy{
    .{ .audit_arch = audit_x86_64, .policy = policy_for(SysX64) },
    .{ .audit_arch = audit_aarch64, .policy = policy_for(SysArm64) },
};

/// The program the child installs: compiled when the binary is built.
pub const program: [program_len]Insn = blk: {
    @setEvalBranchQuota(10_000_000);
    var storage: [bpf.insns_max]Insn = undefined;
    const compiled = compile(&storage, &release_arches) catch
        @compileError("seccomp.zig: the program is longer than the kernel takes");
    var final: [program_len]Insn = undefined;
    @memcpy(&final, compiled);
    break :blk final;
};

const program_len: usize = blk: {
    var length: usize = 1 + 2 * release_arches.len + 1;
    for (release_arches) |arch| length += section_len(&arch.policy);
    break :blk length;
};

comptime {
    assert(bpf.verify(&program) == null);
    assert(program.len <= bpf.insns_max);
}

// ---- Tests ---------------------------------------------------------------------------------

const testing = std.testing;

const arch_x64: u32 = audit_x86_64;
const arch_arm64: u32 = audit_aarch64;

/// The verdict of the shipped program for a syscall by name.
fn verdict(comptime arch: u32, comptime name: []const u8, arg0: u64) u32 {
    const Sys = if (arch == arch_x64) SysX64 else SysArm64;
    var data: bpf.Data = .{ .nr = @backingInt(@field(Sys, name)), .arch = arch };
    data.args[0] = arg0;
    return bpf.run(&program, &data);
}

const denied = linux.SECCOMP.RET.ERRNO | errno_perm;

test "the shipped program is valid and fits the kernel's limit" {
    // Goal: the filter the child installs is a program the kernel accepts. The size is part of
    // the test so growth of the policy is seen.
    try testing.expectEqual(@as(?bpf.Problem, null), bpf.verify(&program));
    try testing.expect(program.len < 1200);
    try testing.expectEqual(@as(u32, 0x7fff0000), ret_allow);
}

test "each group has a syscall it allows, on both architectures" {
    // Goal: an allow case per group of the policy file. Method: one syscall of each group,
    // chosen for being common, answered ALLOW under the architecture's own numbers.
    inline for (.{
        "execve",        "sched_yield", "mmap", "openat", "newfstatat", "getuid", "rt_sigaction",
        "clock_gettime", "futex",       "bind", "semget", "uname",
    }) |name| {
        try testing.expectEqual(ret_allow, verdict(arch_x64, name, 0));
        try testing.expectEqual(ret_allow, verdict(arch_arm64, name, 0));
    }
    // The legacy calls exist on x86_64 only, and are allowed there.
    inline for (.{ "open", "stat", "fork", "arch_prctl", "poll" }) |name| {
        try testing.expectEqual(ret_allow, verdict(arch_x64, name, 0));
    }
}

test "what the top-20 run found is allowed, and its neighbours that change things are not" {
    // Goal: the two calls added from real failures (mongo asked get_mempolicy, a JDK asked
    // fchmodat2) are allowed on both architectures, while the calls that change a NUMA policy
    // and io_uring, which the images that ask for it do without, are still refused. Method:
    // the shipped program's verdict for each name.
    inline for (.{ "get_mempolicy", "fchmodat2", "fchmodat" }) |name| {
        try testing.expectEqual(ret_allow, verdict(arch_x64, name, 0));
        try testing.expectEqual(ret_allow, verdict(arch_arm64, name, 0));
    }
    const refused = .{ "set_mempolicy", "mbind", "migrate_pages", "move_pages", "io_uring_setup" };
    inline for (refused) |name| {
        try testing.expectEqual(denied, verdict(arch_x64, name, 0));
        try testing.expectEqual(denied, verdict(arch_arm64, name, 0));
    }
}

test "what the container has no capability for is refused with EPERM" {
    // Goal: a deny case that matters per family of calls the policy leaves out: mounting,
    // namespaces, the clock, reboot, modules, bpf, keys and tracing another process.
    const names = .{
        "mount",             "umount2",         "pivot_root",  "unshare",      "setns",
        "reboot",            "kexec_load",      "init_module", "finit_module", "delete_module",
        "bpf",               "perf_event_open", "keyctl",      "add_key",      "settimeofday",
        "clock_settime",     "swapon",          "sethostname", "userfaultfd",  "process_vm_readv",
        "open_by_handle_at", "acct",            "quotactl",    "mbind",        "iopl",
    };
    inline for (names) |name| {
        if (@hasField(SysX64, name)) {
            try testing.expectEqual(denied, verdict(arch_x64, name, 0));
        }
        if (@hasField(SysArm64, name)) {
            try testing.expectEqual(denied, verdict(arch_arm64, name, 0));
        }
    }
}

test "a foreign architecture, and the x32 range, are refused" {
    // Goal: the arch check. The 32-bit entry (AUDIT_ARCH_I386) must not reach the x86_64 table
    // by number, and x32 calls (bit 30 set) are not in the list.
    const arch_i386: u32 = 0x40000003; // AUDIT_ARCH_I386.
    var data: bpf.Data = .{ .nr = @backingInt(SysX64.execve), .arch = arch_i386 };
    try testing.expectEqual(denied, bpf.run(&program, &data));
    data.arch = arch_x64;
    data.nr = @backingInt(SysX64.execve) | 0x40000000;
    try testing.expectEqual(denied, bpf.run(&program, &data));
    data.arch = 0;
    try testing.expectEqual(denied, bpf.run(&program, &data));
}

test "clone may fork and make threads, not namespaces; clone3 says ENOSYS" {
    // Goal: Docker's clone rule. Method: the flags of fork, of a thread, and each namespace flag.
    const sigchld: u64 = 17;
    const thread: u64 = 0x3d0f00; // CLONE_VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|SETTLS|...
    try testing.expectEqual(ret_allow, verdict(arch_x64, "clone", sigchld));
    try testing.expectEqual(ret_allow, verdict(arch_x64, "clone", thread));
    try testing.expectEqual(ret_allow, verdict(arch_arm64, "clone", thread));
    const namespaces = [_]u64{
        0x00020000, // CLONE_NEWNS
        0x02000000, // CLONE_NEWCGROUP
        0x04000000, // CLONE_NEWUTS
        0x08000000, // CLONE_NEWIPC
        0x10000000, // CLONE_NEWUSER
        0x20000000, // CLONE_NEWPID
        0x40000000, // CLONE_NEWNET
    };
    for (namespaces) |flag| {
        try testing.expectEqual(denied, verdict(arch_x64, "clone", sigchld | flag));
        try testing.expectEqual(denied, verdict(arch_arm64, "clone", thread | flag));
    }
    const enosys = linux.SECCOMP.RET.ERRNO | errno_nosys;
    try testing.expectEqual(enosys, verdict(arch_x64, "clone3", 0));
    try testing.expectEqual(enosys, verdict(arch_arm64, "clone3", 0));
}

test "personality takes the usual values only, and socket refuses AF_VSOCK" {
    inline for (.{ 0, 8, 131072, 131080, 0xffffffff }) |value| {
        try testing.expectEqual(ret_allow, verdict(arch_x64, "personality", value));
    }
    try testing.expectEqual(denied, verdict(arch_x64, "personality", 0x40000)); // No ASLR.
    try testing.expectEqual(denied, verdict(arch_arm64, "personality", 1));
    try testing.expectEqual(ret_allow, verdict(arch_x64, "socket", 1)); // AF_UNIX.
    try testing.expectEqual(ret_allow, verdict(arch_arm64, "socket", 2)); // AF_INET.
    try testing.expectEqual(denied, verdict(arch_x64, "socket", 40)); // AF_VSOCK.
    try testing.expectEqual(denied, verdict(arch_arm64, "socket", 40));
}

// ---- The compiler on small policies ---------------------------------------------------------

fn plain_verdict(program_slice: []const Insn, arch: u32, nr: u32, arg0: u64) u32 {
    var data: bpf.Data = .{ .nr = nr, .arch = arch };
    data.args[0] = arg0;
    return bpf.run(program_slice, &data);
}

test "a long allowlist jumps correctly across chunk boundaries" {
    // Goal: the eight-bit jump limit is respected for every position in a list of 350 numbers,
    // the first, the last, each chunk's edges, and numbers just outside the list.
    var numbers: [350]u32 = undefined;
    for (&numbers, 0..) |*number, at| number.* = @intCast(3 * at + 1);
    const one: Policy = .{ .plain = &numbers, .rules = &.{} };
    const arch_list = [_]ArchPolicy{.{ .audit_arch = 7, .policy = one }};
    var storage: [bpf.insns_max]Insn = undefined;
    const compiled = try compile(&storage, &arch_list);
    try testing.expectEqual(@as(?bpf.Problem, null), bpf.verify(compiled));
    for (numbers) |number| {
        try testing.expectEqual(ret_allow, plain_verdict(compiled, 7, number, 0));
        try testing.expectEqual(denied, plain_verdict(compiled, 7, number + 1, 0));
    }
    try testing.expectEqual(denied, plain_verdict(compiled, 7, 0, 0));
    try testing.expectEqual(denied, plain_verdict(compiled, 8, numbers[0], 0));
}

test "a program that would not fit is an error, not a truncation" {
    var numbers: [5000]u32 = undefined;
    for (&numbers, 0..) |*number, at| number.* = @intCast(at);
    const one: Policy = .{ .plain = &numbers, .rules = &.{} };
    const arch_list = [_]ArchPolicy{.{ .audit_arch = 7, .policy = one }};
    var storage: [bpf.insns_max]Insn = undefined;
    try testing.expectError(error.TooManyInstructions, compile(&storage, &arch_list));
    var small: [8]Insn = undefined;
    const twenty: Policy = .{ .plain = numbers[0..20], .rules = &.{} };
    const few = [_]ArchPolicy{.{ .audit_arch = 7, .policy = twenty }};
    try testing.expectError(error.TooManyInstructions, compile(&small, &few));
}
