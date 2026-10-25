//! Classic BPF, the subset a seccomp filter needs: the instruction, an interpreter that runs a
//! program against a `seccomp_data` (the tests and the simulator use it to ask what the
//! kernel's filter would answer), and a verifier that refuses what the kernel would.
//!
//! The kernel accepts a larger language; the compiler in `seccomp.zig` emits only these
//! instructions, and the verifier refuses anything else, so a program that passes here is one
//! the interpreter can run exactly. No allocation, no recursion: jumps only go forward, so a
//! run takes at most as many steps as the program has instructions.

const std = @import("std");
const assert = std.debug.assert;

/// `struct sock_filter`: one instruction, as the kernel takes it.
pub const Insn = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

/// The kernel refuses a longer filter (`BPF_MAXINSNS`).
pub const insns_max: u32 = 4096;

// Instruction classes and modes (linux/bpf_common.h), spelled out for the instructions used.
pub const ld_w_abs: u16 = 0x20; // A = the 32-bit word at offset k of the data.
pub const alu_and_k: u16 = 0x54; // A &= k.
pub const jmp_ja: u16 = 0x05; // pc += k.
pub const jmp_jeq_k: u16 = 0x15; // pc += (A == k) ? jt : jf.
pub const jmp_jgt_k: u16 = 0x25; // pc += (A > k) ? jt : jf.
pub const jmp_jge_k: u16 = 0x35; // pc += (A >= k) ? jt : jf.
pub const jmp_jset_k: u16 = 0x45; // pc += (A & k) ? jt : jf.
pub const ret_k: u16 = 0x06; // Return k.

/// `struct seccomp_data` is 64 bytes: nr, arch, instruction pointer, six arguments.
pub const data_bytes: u32 = 64;
pub const offset_nr: u32 = 0;
pub const offset_arch: u32 = 4;

/// The low word of argument `index` (both architectures are little-endian).
pub fn offset_arg(index: u32) u32 {
    assert(index < 6);
    return 16 + 8 * index;
}

pub fn ld(offset: u32) Insn {
    assert(offset % 4 == 0);
    assert(offset + 4 <= data_bytes);
    return .{ .code = ld_w_abs, .jt = 0, .jf = 0, .k = offset };
}

pub fn jeq(value: u32, jt: u8, jf: u8) Insn {
    return .{ .code = jmp_jeq_k, .jt = jt, .jf = jf, .k = value };
}

pub fn ret(value: u32) Insn {
    return .{ .code = ret_k, .jt = 0, .jf = 0, .k = value };
}

pub fn and_k(mask: u32) Insn {
    return .{ .code = alu_and_k, .jt = 0, .jf = 0, .k = mask };
}

pub fn ja(distance: u32) Insn {
    return .{ .code = jmp_ja, .jt = 0, .jf = 0, .k = distance };
}

/// What the kernel gives a filter to look at, in the fields the filters here read.
pub const Data = struct {
    nr: u32,
    arch: u32,
    args: [6]u64 = @splat(0),

    fn word(data: *const Data, offset: u32) u32 {
        assert(offset % 4 == 0);
        assert(offset + 4 <= data_bytes);
        if (offset == offset_nr) return data.nr;
        if (offset == offset_arch) return data.arch;
        if (offset < 16) return 0; // The instruction pointer: filters here never read it.
        const index = (offset - 16) / 8;
        const half: u6 = if ((offset - 16) % 8 == 0) 0 else 32;
        return @truncate(data.args[index] >> half);
    }
};

pub const Problem = enum {
    empty,
    too_long,
    unknown_opcode,
    bad_load,
    jump_out_of_range,
    falls_off_the_end,
};

/// Null if the kernel would accept the program and `run` can run it; else why not.
pub fn verify(program: []const Insn) ?Problem {
    if (program.len == 0) return .empty;
    if (program.len > insns_max) return .too_long;
    if (program[program.len - 1].code != ret_k) return .falls_off_the_end;
    for (program, 0..) |insn, at| {
        const remaining: u64 = program.len - at - 1;
        switch (insn.code) {
            ld_w_abs => {
                if (insn.k % 4 != 0 or insn.k + 4 > data_bytes) return .bad_load;
            },
            alu_and_k, ret_k => {},
            jmp_ja => if (insn.k >= remaining) return .jump_out_of_range,
            jmp_jeq_k, jmp_jgt_k, jmp_jge_k, jmp_jset_k => {
                if (insn.jt > remaining or insn.jf > remaining) return .jump_out_of_range;
            },
            else => return .unknown_opcode,
        }
    }
    return null;
}

/// Runs a verified program and returns its verdict (the `ret` value).
pub fn run(program: []const Insn, data: *const Data) u32 {
    assert(verify(program) == null);
    var accumulator: u32 = 0;
    var pc: usize = 0;
    var steps: usize = 0;
    while (steps <= program.len) : (steps += 1) {
        const insn = program[pc];
        pc += 1;
        switch (insn.code) {
            ld_w_abs => accumulator = data.word(insn.k),
            alu_and_k => accumulator &= insn.k,
            ret_k => return insn.k,
            jmp_ja => pc += insn.k,
            jmp_jeq_k => pc += if (accumulator == insn.k) insn.jt else insn.jf,
            jmp_jgt_k => pc += if (accumulator > insn.k) insn.jt else insn.jf,
            jmp_jge_k => pc += if (accumulator >= insn.k) insn.jt else insn.jf,
            jmp_jset_k => pc += if (accumulator & insn.k != 0) insn.jt else insn.jf,
            else => unreachable, // The verifier refused every other opcode.
        }
        assert(pc < program.len); // The verifier proved every jump lands inside.
    }
    unreachable; // Forward jumps only: the program ended in a ret within `len` steps.
}

const testing = std.testing;

test "the interpreter loads, masks, compares and returns" {
    // Goal: each instruction does what the kernel's does. Method: a small program per case.
    const program = [_]Insn{
        ld(offset_arg(1)),
        and_k(0xf0),
        jeq(0x30, 0, 1),
        ret(1),
        ret(2),
    };
    try testing.expectEqual(@as(?Problem, null), verify(&program));
    var data: Data = .{ .nr = 0, .arch = 0 };
    data.args[1] = 0xabcd_ef37; // 0x37 & 0xf0 = 0x30.
    try testing.expectEqual(@as(u32, 1), run(&program, &data));
    data.args[1] = 0x41;
    try testing.expectEqual(@as(u32, 2), run(&program, &data));
    // The high word of an argument is at offset + 4.
    const high = [_]Insn{ ld(offset_arg(0) + 4), jeq(7, 0, 1), ret(10), ret(20) };
    data.args[0] = 7 << 32;
    try testing.expectEqual(@as(u32, 10), run(&high, &data));
    // ja, jgt, jge and jset.
    const compare = [_]Insn{
        ld(offset_nr),
        .{ .code = jmp_jgt_k, .jt = 0, .jf = 1, .k = 5 },
        ret(1),
        .{ .code = jmp_jge_k, .jt = 0, .jf = 1, .k = 3 },
        ja(1),
        ret(2),
        .{ .code = jmp_jset_k, .jt = 0, .jf = 1, .k = 1 },
        ret(3),
        ret(4),
    };
    try testing.expectEqual(@as(?Problem, null), verify(&compare));
    const cases = [_]struct { nr: u32, want: u32 }{
        .{ .nr = 9, .want = 1 }, // Above 5.
        .{ .nr = 5, .want = 3 }, // Not above 5, at least 3, ja over ret 2, odd.
        .{ .nr = 4, .want = 4 }, // The same, even.
        .{ .nr = 2, .want = 2 }, // Below 3.
    };
    for (cases) |case| {
        data.nr = case.nr;
        try testing.expectEqual(case.want, run(&compare, &data));
    }
}

test "the verifier refuses what the kernel would, and what the interpreter cannot run" {
    // Goal: empty, too long, a jump past the end, an unknown opcode, a bad load, no final ret.
    try testing.expectEqual(@as(?Problem, .empty), verify(&.{}));
    try testing.expectEqual(@as(?Problem, .falls_off_the_end), verify(&.{ld(0)}));
    try testing.expectEqual(@as(?Problem, .jump_out_of_range), verify(&.{ jeq(0, 5, 0), ret(0) }));
    try testing.expectEqual(@as(?Problem, .jump_out_of_range), verify(&.{ ja(2), ret(0) }));
    const odd: Insn = .{ .code = 0x61, .jt = 0, .jf = 0, .k = 0 };
    try testing.expectEqual(@as(?Problem, .unknown_opcode), verify(&.{ odd, ret(0) }));
    const unaligned: Insn = .{ .code = ld_w_abs, .jt = 0, .jf = 0, .k = 2 };
    try testing.expectEqual(@as(?Problem, .bad_load), verify(&.{ unaligned, ret(0) }));
    const past: Insn = .{ .code = ld_w_abs, .jt = 0, .jf = 0, .k = 64 };
    try testing.expectEqual(@as(?Problem, .bad_load), verify(&.{ past, ret(0) }));
    var long: [insns_max + 1]Insn = @splat(ret(0));
    try testing.expectEqual(@as(?Problem, .too_long), verify(&long));
    try testing.expectEqual(@as(?Problem, null), verify(long[0..insns_max]));
}
