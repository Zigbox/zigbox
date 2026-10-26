//! The seccomp compiler's fuzzer: `zig build fuzz -- seccomp`. One iteration does four things,
//! all from the seed.
//!
//!   1. Builds a random policy (one or two architectures, an allowlist of up to 400 numbers,
//!      up to six argument rules of every kind), compiles it, and checks that the program is
//!      valid and that the interpreter answers what an independent reading of the policy says,
//!      for every number in it, for numbers next to them, and for random numbers, arguments and
//!      architectures. A policy that does not fit the kernel's limit must be refused as such,
//!      and only then.
//!   2. Damages the compiled program (flips instruction fields) and asks the verifier: it must
//!      return, and a program it accepts must run to a verdict on any data.
//!   3. Feeds the verifier and the interpreter programs of random instructions.
//!   4. Checks the shipped program against the shipped policy the same way as in 1.
//!
//! The oracle reads the policy directly: it does not look at the program, so a compiler that
//! gets a jump offset wrong, or loses a chunk's last number, disagrees with it.

const std = @import("std");
const assert = std.debug.assert;
const bpf = @import("runtime/bpf.zig");
const seccomp = @import("runtime/seccomp.zig");

const Insn = bpf.Insn;
const Rule = seccomp.Rule;
const ArchPolicy = seccomp.ArchPolicy;

const eperm: u32 = 0x00050000 | 1;
const allow: u32 = 0x7fff0000;

pub fn fuzz_seccomp(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    check_random_policy(random);
    check_shipped(random);
    check_soup(random);
}

/// What a correct program answers, from the policy alone.
fn oracle(arches: []const ArchPolicy, arch: u32, nr: u32, arg0: u64) u32 {
    const low: u32 = @truncate(arg0);
    for (arches) |*one| {
        if (one.audit_arch != arch) continue;
        for (one.policy.rules) |*rule| {
            if (rule.nr != nr) continue;
            return switch (rule.kind) {
                .equals_any => for (rule.values[0..rule.count]) |value| {
                    if (low == value) break allow;
                } else eperm,
                .mask_zero => if (low & rule.values[0] == 0) allow else eperm,
                .not_equal => if (low == rule.values[0]) eperm else allow,
                .errno => 0x00050000 | rule.values[0],
            };
        }
        for (one.policy.plain) |number| {
            if (number == nr) return allow;
        }
        return eperm;
    }
    return eperm;
}

fn ask(program: []const Insn, arch: u32, nr: u32, arg0: u64) u32 {
    var data: bpf.Data = .{ .nr = nr, .arch = arch };
    data.args[0] = arg0;
    return bpf.run(program, &data);
}

// ---- 1. A random policy -----------------------------------------------------------------------

const Storage = struct {
    plain: [2][400]u32,
    rules: [2][6]Rule,
    arches: [2]ArchPolicy,
};

fn random_rule(random: std.Random) Rule {
    var rule: Rule = .{
        .nr = random.uintLessThan(u32, 700),
        .kind = random.enumValue(seccomp.RuleKind),
        .values = @splat(0),
        .count = 0,
    };
    switch (rule.kind) {
        .equals_any => {
            rule.count = random.intRangeAtMost(u8, 1, seccomp.rule_values_max);
            for (rule.values[0..rule.count]) |*value| value.* = random.int(u32) >> 20;
        },
        .mask_zero => rule.values[0] = random.int(u32),
        .not_equal => rule.values[0] = random.int(u32) >> random.uintLessThan(u5, 31),
        .errno => rule.values[0] = random.intRangeAtMost(u32, 1, 133),
    }
    return rule;
}

fn random_policy(random: std.Random, storage: *Storage) []const ArchPolicy {
    const count = random.intRangeAtMost(usize, 1, 2);
    for (0..count) |at| {
        const plain_count = random.uintAtMost(usize, storage.plain[at].len);
        for (storage.plain[at][0..plain_count]) |*number| number.* = random.uintLessThan(u32, 700);
        const rule_count = random.uintAtMost(usize, storage.rules[at].len);
        for (storage.rules[at][0..rule_count]) |*rule| rule.* = random_rule(random);
        storage.arches[at] = .{
            .audit_arch = 0xc000_0000 + @as(u32, @intCast(at)) * 0x10 + 3,
            .policy = .{
                .plain = storage.plain[at][0..plain_count],
                .rules = storage.rules[at][0..rule_count],
            },
        };
    }
    return storage.arches[0..count];
}

fn check_random_policy(random: std.Random) void {
    var storage: Storage = undefined;
    const arches = random_policy(random, &storage);
    var out: [bpf.insns_max]Insn = undefined;
    const program = seccomp.compile(&out, arches) catch |err| {
        assert(err == error.TooManyInstructions);
        var needed: usize = 2 + 2 * arches.len;
        for (arches) |*one| needed += seccomp.section_len(&one.policy);
        assert(needed > bpf.insns_max); // Refused only when it really does not fit.
        return;
    };
    assert(bpf.verify(program) == null);
    for (arches) |*one| check_arch(random, program, arches, one);
    check_foreign(random, program, arches);
    check_damaged(random, program);
}

fn check_arch(
    random: std.Random,
    program: []const Insn,
    arches: []const ArchPolicy,
    one: *const ArchPolicy,
) void {
    for (one.policy.plain) |number| {
        for ([_]u32{ number, number +% 1, number -% 1 }) |nr| {
            const arg = random.int(u64);
            const got = ask(program, one.audit_arch, nr, arg);
            assert(got == oracle(arches, one.audit_arch, nr, arg));
        }
    }
    for (one.policy.rules) |*rule| {
        for ([_]u64{ 0, rule.values[0], rule.values[0] ^ 1, ~@as(u64, 0), random.int(u64) }) |arg| {
            const got = ask(program, one.audit_arch, rule.nr, arg);
            assert(got == oracle(arches, one.audit_arch, rule.nr, arg));
        }
    }
    for (0..64) |_| {
        const nr = random.uintLessThan(u32, 800);
        const arg = random.int(u64);
        assert(ask(program, one.audit_arch, nr, arg) == oracle(arches, one.audit_arch, nr, arg));
    }
}

fn check_foreign(random: std.Random, program: []const Insn, arches: []const ArchPolicy) void {
    for (0..16) |_| {
        const arch = random.int(u32);
        const nr = random.uintLessThan(u32, 800);
        assert(ask(program, arch, nr, 0) == oracle(arches, arch, nr, 0));
    }
}

// ---- 2. A damaged program ----------------------------------------------------------------------

fn check_damaged(random: std.Random, program: []const Insn) void {
    var copy: [bpf.insns_max]Insn = undefined;
    @memcpy(copy[0..program.len], program);
    for (0..1 + random.uintLessThan(u8, 4)) |_| {
        const at = random.uintLessThan(usize, program.len);
        switch (random.uintLessThan(u8, 4)) {
            0 => copy[at].code = random.int(u16),
            1 => copy[at].jt = random.int(u8),
            2 => copy[at].jf = random.int(u8),
            else => copy[at].k = random.int(u32),
        }
    }
    run_if_valid(random, copy[0..program.len]);
}

/// A program the verifier accepts runs to a verdict on any data; one it refuses is not run.
fn run_if_valid(random: std.Random, program: []const Insn) void {
    if (bpf.verify(program) != null) return;
    for (0..8) |_| {
        var data: bpf.Data = .{ .nr = random.int(u32), .arch = random.int(u32) };
        for (&data.args) |*arg| arg.* = random.int(u64);
        _ = bpf.run(program, &data);
    }
}

// ---- 3. Programs of random instructions --------------------------------------------------------

const codes = [_]u16{
    bpf.ld_w_abs,  bpf.alu_and_k,  bpf.jmp_ja, bpf.jmp_jeq_k, bpf.jmp_jgt_k,
    bpf.jmp_jge_k, bpf.jmp_jset_k, bpf.ret_k,  0x61,          0x00,
};

/// Half the time a plausible load offset, else anything.
fn random_operand(random: std.Random) u32 {
    if (random.boolean()) return random.uintLessThan(u32, 70) & ~@as(u32, 3);
    return random.int(u32);
}

fn check_soup(random: std.Random) void {
    var program: [48]Insn = undefined;
    const length = random.intRangeAtMost(usize, 1, program.len);
    for (program[0..length]) |*insn| {
        insn.* = .{
            .code = codes[random.uintLessThan(usize, codes.len)],
            .jt = random.uintLessThan(u8, 6),
            .jf = random.uintLessThan(u8, 6),
            .k = random_operand(random),
        };
    }
    if (random.boolean()) program[length - 1] = bpf.ret(random.int(u32));
    run_if_valid(random, program[0..length]);
}

// ---- 4. The shipped program --------------------------------------------------------------------

fn check_shipped(random: std.Random) void {
    const program = &seccomp.program;
    const arches = &seccomp.release_arches;
    assert(bpf.verify(program) == null);
    for (arches) |*one| check_arch(random, program, arches, one);
    check_foreign(random, program, arches);
}
