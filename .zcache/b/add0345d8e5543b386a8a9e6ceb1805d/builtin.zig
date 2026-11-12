const std = @import("std");
pub const zig_version = std.SemanticVersion.parse(zig_version_string) catch unreachable;
pub const zig_version_string = "0.17.0";
pub const zig_backend = std.lang.CompilerBackend.stage2_llvm;

pub const output_mode: std.lang.OutputMode = .Lib;
pub const link_mode: std.lang.LinkMode = .static;
pub const unwind_tables: std.lang.UnwindTables = .async;
pub const is_test = false;
pub const single_threaded = false;
/// Deprecated; to be removed in 0.18.0. Use `target.abi` instead.
pub const abi: std.Target.Abi = .gnu;
/// Deprecated; to be removed in 0.18.0. Use `target.cpu` instead.
pub const cpu: std.Target.Cpu = .{
    .arch = .x86_64,
    .model = &std.Target.x86.cpu.emeraldrapids,
    .features = std.Target.x86.featureSet(&.{
        .@"64bit",
        .adx,
        .aes,
        .allow_light_256_bit,
        .amx_bf16,
        .amx_int8,
        .amx_tile,
        .avx,
        .avx2,
        .avx512bf16,
        .avx512bitalg,
        .avx512bw,
        .avx512cd,
        .avx512dq,
        .avx512f,
        .avx512fp16,
        .avx512ifma,
        .avx512vbmi,
        .avx512vbmi2,
        .avx512vl,
        .avx512vnni,
        .avx512vpopcntdq,
        .avxvnni,
        .bmi,
        .bmi2,
        .cldemote,
        .clflushopt,
        .clwb,
        .cmov,
        .crc32,
        .cx16,
        .cx8,
        .ermsb,
        .f16c,
        .false_deps_getmant,
        .false_deps_mulc,
        .false_deps_mullq,
        .false_deps_perm,
        .false_deps_range,
        .fast_15bytenop,
        .fast_gather,
        .fast_scalar_fsqrt,
        .fast_shld_rotate,
        .fast_variable_crosslane_shuffle,
        .fast_variable_perlane_shuffle,
        .fast_vector_fsqrt,
        .fma,
        .fsgsbase,
        .fsrm,
        .fxsr,
        .gfni,
        .idivq_to_divl,
        .invpcid,
        .lzcnt,
        .macrofusion,
        .mmx,
        .movbe,
        .movdir64b,
        .movdiri,
        .no_bypass_delay_blend,
        .no_bypass_delay_mov,
        .no_bypass_delay_shuffle,
        .nopl,
        .pclmul,
        .popcnt,
        .prefer_256_bit,
        .prfchw,
        .rdpid,
        .rdrnd,
        .rdseed,
        .rtm,
        .sahf,
        .serialize,
        .sha,
        .slow_pmullq,
        .smap,
        .smep,
        .sse,
        .sse2,
        .sse3,
        .sse4_1,
        .sse4_2,
        .ssse3,
        .tsxldtrk,
        .tuning_fast_imm_vector_shift,
        .vaes,
        .vpclmulqdq,
        .vzeroupper,
        .wbnoinvd,
        .x87,
        .xsave,
        .xsavec,
        .xsaveopt,
        .xsaves,
    }),
};
/// Deprecated; to be removed in 0.18.0. Use `target.os` instead.
pub const os: std.Target.Os = .{
    .tag = .linux,
    .version_range = .{ .linux = .{
        .range = .{
            .min = .{
                .major = 6,
                .minor = 18,
                .patch = 44,
            },
            .max = .{
                .major = 6,
                .minor = 18,
                .patch = 44,
            },
        },
        .glibc = .{
            .major = 2,
            .minor = 39,
            .patch = 0,
        },
        .android = 29,
    }},
};
pub const target: std.Target = .{
    .cpu = cpu,
    .os = os,
    .abi = abi,
    .ofmt = object_format,
    .dynamic_linker = .init("/lib64/ld-linux-x86-64.so.2"),
};
/// Deprecated; to be removed in 0.18.0. Use `target.ofmt` instead.
pub const object_format: std.Target.ObjectFormat = .elf;
/// Deprecated, to be removed after 0.18.0
pub const mode = optimize;
pub const optimize: std.lang.Optimize = .fast;
pub const link_libc = false;
pub const link_libcpp = false;
pub const have_error_return_tracing = false;
pub const valgrind_support = true;
pub const sanitize_thread = false;
pub const fuzz = false;
pub const position_independent_code = false;
pub const position_independent_executable = false;
pub const strip_debug_info = false;
pub const code_model: std.lang.CodeModel = .default;
pub const omit_frame_pointer = false;
