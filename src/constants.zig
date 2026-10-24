//! Every limit in Zigbox lives here, named with its unit last, with comptime assertions on how
//! the limits relate. Exceeding a limit at run time is an operating error with a one-line
//! message, never undefined behaviour (docs/STYLE.md, "Put a limit on everything").

const std = @import("std");
const assert = std.debug.assert;

// Exit codes of `zbx` (DIAGNOSTICS.md). A diagnostic's blame decides which one a failure
// exits with, in `diag/codes.zig`, never at a call site. A container's own exit code is passed
// through unchanged and is never confused with these.
pub const exit_ok: u8 = 0;
/// The user's input was refused: every command line usage error.
pub const exit_user: u8 = 1;
/// The host or environment cannot do what was asked: any doctor FAIL, a failing output stream.
pub const exit_environment: u8 = 2;
/// An external service failed (a registry, the store). Unused until M3 and M4.
pub const exit_external: u8 = 3;
/// A bug in zbx: EX_SOFTWARE from sysexits.h.
pub const exit_internal: u8 = 70;

// Exit codes of the build-host tools (`size_check`, the fuzz runner). They are not `zbx`.
pub const tool_exit_ok: u8 = 0;
pub const tool_exit_failed: u8 = 1;
pub const tool_exit_usage: u8 = 2;

// Command line.
/// Arguments after the program name. Far above anything a milestone needs; a bound, not a goal.
pub const args_count_max: u32 = 64;
/// One argument. Longer arguments are refused rather than truncated, so a command is never
/// silently misread.
pub const arg_bytes_max: u32 = 4096;
/// How much of a refused argument is echoed back in an error line.
pub const arg_echo_bytes_max: u32 = 64;
/// One rendered CLI message (help text, version, doctor report, or one diagnostic). The
/// diagnostic bound below is checked against it at comptime.
pub const output_bytes_max: u32 = 16 * 1024;

// Host interface.
/// Linux PATH_MAX, without the terminating NUL.
pub const path_bytes_max: u32 = 4095;
/// Largest single file read through the host: bounds every /proc, /sys and /etc read.
pub const file_bytes_max: u32 = 64 * 1024;
/// Consecutive EINTR results tolerated for one operation before it is reported as failed.
pub const eintr_retries_max: u32 = 16;
/// Upper bound on read calls for one file. Every call that is not EOF makes progress of at least
/// one byte, so this covers the worst case of one-byte short reads plus the final EOF probe.
pub const read_calls_max: u32 = file_bytes_max + 1;
/// Upper bound on write calls for one message, by the same argument.
pub const write_calls_max: u32 = output_bytes_max + 1;
/// Size of a utsname field in the kernel ABI, including the terminating NUL.
pub const uname_field_bytes: u32 = 65;

/// A security.capability xattr is at most 24 bytes (vfs_cap_data revision 3); the margin lets an
/// oversized value be recognised as malformed instead of being cut off.
pub const capability_bytes_max: u32 = 64;
/// Child polling step while waiting for a probe, in milliseconds.
pub const probe_poll_ms: u32 = 1;
/// Probe scratch directory creation attempts (name collisions with leftovers).
pub const probe_dir_attempts_max: u32 = 8;
/// The scratch directory path (parent plus `/zbx-doctor-<pid>-<n>`) and its parent.
pub const probe_scratch_bytes_max: u32 = 256;
pub const probe_scratch_parent_bytes_max: u32 = 200;
/// Polls spent reaping a child after SIGKILL before giving up on it.
pub const probe_reap_polls_max: u32 = 2000;

// Doctor: one buffer size per file read, sized from what the kernel can actually produce.
pub const sysctl_bytes_max: u32 = 32;
pub const cgroup_list_bytes_max: u32 = 512;
pub const passwd_bytes_max: u32 = 64 * 1024;
pub const subid_bytes_max: u32 = 64 * 1024;
pub const status_bytes_max: u32 = 16 * 1024;
/// Longest accepted line of /etc/passwd, /etc/subuid, /etc/subgid; longer lines are malformed.
pub const account_line_bytes_max: u32 = 1024;
pub const user_name_bytes_max: u32 = 256;
pub const controller_name_bytes_max: u32 = 32;
pub const controllers_count_max: u32 = 32;
pub const kernel_number_digits_max: u32 = 9;
pub const doctor_checks_count: u32 = 6;
pub const detail_bytes_max: u32 = 240;
pub const binary_candidates_count: u32 = 3;

// Diagnostics (docs: DIAGNOSTICS.md). All of these are fixed-size: a `Diag` never allocates, and
// text past a bound is cut with a visible "..." marker, items past a bound are counted and shown
// as an "omitted" note. Nothing here can crash a failure path.
/// Cause entries, innermost first. The newest cause always survives (it is the real cause).
pub const diag_causes_count_max: u32 = 6;
/// `while` entries (what the program was doing), innermost first.
pub const diag_whiles_count_max: u32 = 6;
/// Key-value context pairs. The oldest are kept.
pub const diag_context_count_max: u32 = 6;
/// Fixes. The oldest are kept: the first fix is the most specific one.
pub const diag_fixes_count_max: u32 = 3;
/// One cause, `while`, context value or fix sentence.
pub const diag_field_bytes_max: u32 = 200;
/// One runnable fix command. Never wrapped, so it can be copied whole.
pub const diag_command_bytes_max: u32 = 160;
/// A context key: the label column of the rendering is six wide.
pub const diag_key_bytes_max: u32 = 6;
/// Longest registered summary: "under about 70 characters".
pub const diag_summary_bytes_max: u32 = 70;
/// Longest registered explanation, and its longest line.
pub const diag_explanation_bytes_max: u32 = 2048;
pub const diag_explanation_line_bytes_max: u32 = 76;
/// Width at which prose in a diagnostic is wrapped; the label column takes the first nine.
pub const diag_wrap_columns: u32 = 80;
pub const diag_label_columns: u32 = 9;
/// Width of a code such as "ZBX-E0001".
pub const diag_code_bytes: u32 = 9;

// The generated diagnostics pages (src/errors_site.zig): one page, CSS included, is far below
// this; the bound is what the tool's buffers and file reads use.
pub const errors_page_bytes_max: u32 = 24 * 1024;

// Host simulator.
pub const sim_files_max: u32 = 128;
pub const sim_open_files_max: u32 = 8;
pub const sim_output_bytes_max: u32 = 64 * 1024;

// Doctor policy, used from slice 2 on and kept here so every limit has one home.
/// Overlayfs mounts inside user namespaces need 5.11; 5.15 is the oldest LTS kernel that has it
/// and is still widely deployed. The oldest kernel the project supports.
pub const kernel_major_min: u32 = 5;
pub const kernel_minor_min: u32 = 15;
/// A full container uid/gid map needs 65536 ids.
pub const subid_range_min: u32 = 65536;
pub const probe_timeout_ms: u32 = 5000;

// Fuzz runner.
pub const fuzz_iterations_default: u32 = 10_000;
pub const fuzz_iterations_max: u32 = 100_000_000;

comptime {
    // Four distinct failure classes, none colliding with success, and the internal code is the
    // sysexits one.
    const exits = [_]u8{ exit_ok, exit_user, exit_environment, exit_external, exit_internal };
    for (exits, 0..) |first, index| {
        for (exits[index + 1 ..]) |second| assert(first != second);
    }
    assert(exit_ok == 0);
    assert(exit_internal == 70);
    assert(tool_exit_ok == exit_ok);
    assert(tool_exit_failed != tool_exit_usage);

    assert(args_count_max > 0);
    assert(arg_echo_bytes_max >= 8); // Room for a truncation marker and some text.
    assert(arg_echo_bytes_max < arg_bytes_max);
    assert(arg_bytes_max <= path_bytes_max + 1);
    // An error line echoes an argument, so the message buffer must hold prose plus the echo.
    assert(output_bytes_max >= 2 * arg_echo_bytes_max + 256);

    assert(path_bytes_max > 0);
    assert(path_bytes_max < std.math.maxInt(u16));
    assert(file_bytes_max > 0);
    assert(file_bytes_max <= std.math.maxInt(u32) / 2); // Offsets and lengths fit in u32.
    assert(read_calls_max > file_bytes_max);
    assert(write_calls_max > output_bytes_max);
    assert(eintr_retries_max > 0);
    assert(uname_field_bytes <= std.math.maxInt(u8));

    assert(capability_bytes_max >= 24);
    assert(probe_poll_ms > 0);
    assert(probe_timeout_ms % probe_poll_ms == 0);
    assert(probe_dir_attempts_max > 0);
    assert(probe_scratch_parent_bytes_max + 40 <= probe_scratch_bytes_max);
    assert(probe_reap_polls_max > 0);

    assert(sysctl_bytes_max >= 12); // "4294967295\n" is 11 bytes.
    assert(cgroup_list_bytes_max <= file_bytes_max);
    assert(passwd_bytes_max <= file_bytes_max);
    assert(subid_bytes_max <= file_bytes_max);
    assert(status_bytes_max <= file_bytes_max);
    assert(account_line_bytes_max <= passwd_bytes_max);
    assert(user_name_bytes_max < account_line_bytes_max);
    assert(controller_name_bytes_max * controllers_count_max <= 2 * cgroup_list_bytes_max);
    assert(kernel_number_digits_max < 10); // Nine digits always fit in u32.
    // The whole report is written in one call, so six check lines must fit one message.
    // Per line: status word, name, separators, detail, the "  [ZBX-E0101]" code, and colour
    // escapes.
    const line_bytes_max = 6 + 16 + 8 + detail_bytes_max + 4 + diag_code_bytes + 24;
    assert(doctor_checks_count * line_bytes_max <= output_bytes_max);

    // Worst case for one rendered diagnostic: every list full, every field at its bound, and
    // each of those bytes doubled (a JSON escape, or a wrap indent) plus its label; plus the
    // header, fixed lines and an omitted note per list. It must fit the one output buffer.
    const field_lines = diag_causes_count_max + diag_whiles_count_max + diag_context_count_max;
    const fix_lines = diag_fixes_count_max * (diag_command_bytes_max + diag_field_bytes_max);
    const rendered_bytes_max = 2 * (field_lines * diag_field_bytes_max + fix_lines) +
        (field_lines + diag_fixes_count_max) * (diag_label_columns + 16) + 1024;
    assert(rendered_bytes_max <= output_bytes_max);
    assert(diag_explanation_bytes_max + 256 <= output_bytes_max);
    assert(diag_key_bytes_max == 6); // The label column of the rendering.
    assert(diag_label_columns == 3 + diag_key_bytes_max);
    assert(diag_label_columns < diag_wrap_columns / 4);
    assert(diag_summary_bytes_max < diag_wrap_columns);
    assert(diag_explanation_line_bytes_max < diag_wrap_columns);
    assert(diag_explanation_line_bytes_max <= diag_explanation_bytes_max);
    assert(diag_code_bytes == 4 + 5); // "ZBX-" and a letter with four digits.
    assert(diag_causes_count_max > 0);
    assert(diag_whiles_count_max > 0);
    assert(diag_context_count_max > 0);
    assert(diag_fixes_count_max > 0);
    assert(diag_command_bytes_max <= diag_field_bytes_max);

    // A page holds the stylesheet (under 6 KiB), one explanation with every character escaped
    // to at most six bytes, and room for the index's table row per code.
    assert(6 * 1024 + 6 * diag_explanation_bytes_max + 2048 <= errors_page_bytes_max);
    assert(diag_code_bytes < 16); // A page name ("E0101.html") fits the 16-byte buffers.

    assert(sim_files_max > 0);
    assert(sim_open_files_max > 0);
    assert(sim_output_bytes_max >= 2 * output_bytes_max);

    assert(kernel_major_min >= 5);
    assert(kernel_minor_min < 1000);
    assert(subid_range_min == 65536);
    assert(probe_timeout_ms > 0);

    assert(fuzz_iterations_default > 0);
    assert(fuzz_iterations_default <= fuzz_iterations_max);
}
