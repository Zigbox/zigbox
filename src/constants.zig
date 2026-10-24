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
/// Where the generated page of each code is served (GitHub Pages, deployed from `main`): the
/// base ends in "/", and a code's page is the base plus "<code>.html" (src/errors_site.zig).
pub const docs_url_base = "https://zigbox.github.io/zigbox/errors/";
/// The base plus "E0001.html", with room to spare.
pub const docs_url_bytes_max: u32 = 96;
comptime {
    assert(std.mem.startsWith(u8, docs_url_base, "https://"));
    assert(std.mem.endsWith(u8, docs_url_base, "/"));
    assert(docs_url_base.len + "E0001.html".len <= docs_url_bytes_max);
}
/// Width of a code such as "ZBX-E0001".
pub const diag_code_bytes: u32 = 9;

// The generated diagnostics pages (src/errors_site.zig): one page, CSS included, is far below
// this; the bound is what the tool's buffers and file reads use.
pub const errors_page_bytes_max: u32 = 24 * 1024;

// Host simulator.
pub const sim_files_max: u32 = 128;
pub const sim_open_files_max: u32 = 8;
pub const sim_output_bytes_max: u32 = 64 * 1024;
/// The simulator's container model: paths, nodes (directories, files, links), mounts per
/// namespace, processes, and pipe ends. Simulated paths are short; a longer one is refused.
pub const sim_path_bytes_max: u32 = 256;
pub const sim_nodes_max: u32 = 96;
pub const sim_mounts_max: u32 = 32;
pub const sim_processes_max: u32 = 3;
pub const sim_pipe_ends_max: u32 = 8;
/// Files the simulated programs write (run records), and the most one can hold: a bigger write
/// is "no space left on the device", which is also how a full disk is simulated.
pub const sim_written_files_max: u32 = 40;
pub const sim_written_bytes_max: u32 = 16 * 1024;

// Doctor policy, used from slice 2 on and kept here so every limit has one home.
/// Overlayfs mounts inside user namespaces need 5.11; 5.15 is the oldest LTS kernel that has it
/// and is still widely deployed. The oldest kernel the project supports.
pub const kernel_major_min: u32 = 5;
pub const kernel_minor_min: u32 = 15;
/// A full container uid/gid map needs 65536 ids.
pub const subid_range_min: u32 = 65536;
pub const probe_timeout_ms: u32 = 5000;

// Containers (M1). A run is planned as a fixed list of steps, built from these bounds only.
/// The longest rootfs path accepted. The plan derives a dozen paths from it (`/dev/pts`, ...),
/// and every one must still fit `path_bytes_max`.
pub const rootfs_bytes_max: u32 = 1024;
/// A container name is a hostname label (RFC 1123): at most 63 characters.
pub const container_name_bytes_max: u32 = 63;
pub const container_name_prefix = "zbx-";
/// Random hex digits after the prefix of a generated name.
pub const container_name_hex_digits: u32 = 6;
/// Words of the command after `--`. Fewer than `args_count_max`: `zbx run --rootfs R --` and a
/// name take some.
pub const command_words_count_max: u32 = 48;
/// One command word. It becomes an exec path, which is tried under each directory of the
/// container's PATH, so it leaves room for the longest of those plus a slash.
pub const command_word_bytes_max: u32 = 4000;
/// All bytes of the command's arguments and the container's environment, NUL included. The
/// child execs from a copy of this made before `clone3`, so it never formats text.
pub const exec_strings_bytes_max: u32 = 32 * 1024;
/// The `TERM` value copied from the host. A longer one is not copied.
pub const term_bytes_max: u32 = 64;
/// Environment variables the container gets: PATH, HOME, HOSTNAME and (if set) TERM.
pub const environment_count_max: u32 = 4;
/// The container's PATH, in the order a shell searches it. Counted for the exec candidates.
pub const container_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
pub const container_path_dirs_count: u32 = 6;
/// The devices bind-mounted from the host into the container's `/dev`.
pub const container_devices_count: u32 = 6;
/// The symlinks in the container's `/dev`: fd, stdin, stdout, stderr and ptmx.
pub const container_links_count: u32 = 5;
/// Steps in a plan. The plan's own comptime check proves the count it builds is below this.
pub const plan_steps_max: u32 = 64;
/// Bytes of path text in a plan (rootfs-derived paths, exec candidates, map lines).
pub const plan_paths_bytes_max: u32 = 64 * 1024;
/// One id map line, "0 4294967295 1\n", with room to spare.
pub const id_map_line_bytes_max: u32 = 32;
/// A record the child writes to the failure pipe: kind, step, and a two-byte errno.
pub const sync_record_bytes: u32 = 4;
/// Records a child can write: one note per tolerant step, then at most one failure.
pub const sync_records_max: u32 = 8;
/// `read` calls the parent spends collecting records; each non-EOF call returns at least one
/// byte, so this covers one-byte reads of a full buffer and the EOF read.
pub const sync_read_calls_max: u32 = sync_record_bytes * sync_records_max + 1;
/// Interrupted `wait` calls tolerated before a container's wait is reported as failed.
pub const wait_interrupts_max: u32 = 1024;
/// The exit code of a container child that failed before its command started. The parent never
/// uses it: a failure is the record in the pipe. It only keeps a zombie's status meaningful.
pub const child_exit_setup_failed: u8 = 125;
/// EIO: the errno that stands for a failure with none (an error made inside host.zig).
pub const errno_io: u16 = 5;
/// SIGKILL, the same number on x86_64 and aarch64.
pub const signal_kill: u8 = 9;
/// A signal number is below this on every Linux architecture.
pub const signal_number_max: u8 = 64;
/// Added to a signal number to make the exit code of a container killed by it.
pub const exit_signal_offset: u8 = 128;

// Id mapping through the setuid helpers (M1, slice 2).
/// Output of a helper kept for a diagnostic. The rest is read and dropped.
pub const helper_output_bytes_max: u32 = 120;
/// Words of a helper's command line: its name, the pid, and three triples of numbers.
pub const helper_words_max: u32 = 10;
/// One helper map argument list, "0 4294967295 1 1 4294967295 4294967295".
pub const helper_map_bytes_max: u32 = 64;
/// Reads spent draining a helper's output; each non-EOF read makes progress.
pub const helper_read_calls_max: u32 = 64;

// Signals (slice 2).
/// Signals the parent forwards to the container, and the bound on how many it forwards in one
/// wait. Past the bound the container is killed: a signal flood is not forwarded forever.
pub const forwarded_signals_count: u32 = 4;
pub const forwarded_signals_max: u32 = 1024;

// Run records (slice 2).
/// Records kept; the oldest is deleted when a run would make it more.
pub const runs_max: u32 = 32;
/// The version `zbx` writes. A record with a higher one is skipped, not misread.
pub const record_version: u32 = 1;
/// One record. The command is cut to `record_command_bytes_max` and says so.
pub const record_bytes_max: u32 = 32 * 1024;
pub const record_command_bytes_max: u32 = 2048;
pub const labels_count_max: u32 = 8;
pub const label_key_bytes_max: u32 = 32;
pub const label_value_bytes_max: u32 = 128;
/// A directory listing: entries kept and the bytes of their names. A name is at most
/// `container_name_bytes_max` plus ".zon" for a record.
pub const dir_entries_max: u32 = 96;
pub const dir_name_bytes_max: u32 = 72;
pub const dir_listing_bytes_max: u32 = dir_entries_max * (dir_name_bytes_max + 1);
/// The state directory path: $XDG_STATE_HOME or $HOME/.local/state, then /zbx/runs/<name>.zon.
pub const state_path_bytes_max: u32 = 512;
pub const record_suffix = ".zon";
/// Seconds since the epoch; a record's times are these.
pub const record_time_unknown: u64 = 0;

// Bundles (M1, slice 3).
/// The directory under the state directory that holds bundles, next to "runs".
pub const bundles_dir_name = "bundles";
/// The most one bundle file keeps of any source; the manifest says when it cut something.
pub const bundle_file_bytes_max: u32 = 32 * 1024;
/// All files of a bundle together, before compression (tar headers included).
pub const bundle_stage_bytes_max: u32 = 160 * 1024;
/// The compressed bundle: the staged bytes plus the tar and gzip overhead always fit.
pub const bundle_gz_bytes_max: u32 = 192 * 1024;
/// The most one write_file call is given.
pub const write_bytes_max: u32 = 256 * 1024;
pub const bundle_files_max: u32 = 12;
/// The bundle's static workspace: staged files, the compressor's window and tables, its mask.
pub const facts_bytes_max: u32 = 256 * 1024;
pub const bundle_workspace_bytes_max: u32 = 768 * 1024;
/// The run `Handle` of a foreground run, kept off the stack too.
pub const handle_bytes_max: u32 = 160 * 1024;
/// The environment variables listed in a bundle, and those whose values are scrubbed elsewhere.
pub const environment_entries_max: u32 = 256;
pub const bundle_secrets_max: u32 = 32;
pub const secret_value_bytes_min: u32 = 4;
pub const secret_value_bytes_max: u32 = 256;
/// The diagnostic kept in a run record, as the JSON line zbx printed. Bigger is replaced by a
/// short object that names the code.
pub const diag_json_bytes_max: u32 = 3072;
/// "[redacted:private-key]" and its siblings fit this.
pub const redaction_bytes_max: u32 = 32;
/// The words of a bundle name, "2026-10-23T22-41-07Z".
pub const timestamp_bytes: u32 = 20;
pub const bundle_name_bytes_max: u32 = timestamp_bytes + 1 + container_name_bytes_max + 7;

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

    // Containers: every path the plan derives from the longest rootfs fits a path, and the
    // plan's text arena holds the worst case of all of them at once.
    const derived_suffix_bytes_max = "/dev/pts".len + 1;
    assert(rootfs_bytes_max + derived_suffix_bytes_max <= path_bytes_max);
    assert(container_name_bytes_max == 63);
    assert(container_name_prefix.len + container_name_hex_digits <= container_name_bytes_max);
    assert(command_words_count_max + 8 <= args_count_max);
    assert(command_word_bytes_max < arg_bytes_max);
    // A word tried under the longest PATH directory ("/usr/local/sbin/") still fits a path.
    assert(command_word_bytes_max + "/usr/local/sbin/".len <= path_bytes_max);
    assert(exec_strings_bytes_max >= command_word_bytes_max + container_path.len + 64);
    assert(term_bytes_max < exec_strings_bytes_max);
    assert(environment_count_max == 4);
    assert(std.mem.count(u8, container_path, ":") + 1 == container_path_dirs_count);
    assert(container_devices_count == 6);
    assert(container_links_count == 5);
    const derived_paths_max = 4 + container_devices_count + container_links_count;
    const candidates_bytes_max = (container_path_dirs_count + 1) * (command_word_bytes_max + 20);
    const paths_needed = derived_paths_max * (rootfs_bytes_max + 16) + candidates_bytes_max +
        2 * id_map_line_bytes_max + 512;
    assert(paths_needed <= plan_paths_bytes_max);
    assert(plan_steps_max <= std.math.maxInt(u8)); // The failure record names a step in a byte.
    assert(id_map_line_bytes_max >= "0 4294967295 1\n".len);
    assert(sync_record_bytes == 4);
    assert(sync_records_max >= 2); // At least one note and the failure.
    assert(sync_read_calls_max > sync_record_bytes * sync_records_max);
    assert(wait_interrupts_max > eintr_retries_max);
    assert(child_exit_setup_failed != exit_ok);
    assert(signal_number_max <= 64);
    assert(signal_kill < signal_number_max);
    assert(@as(u32, exit_signal_offset) + signal_number_max <= std.math.maxInt(u8));
    assert(sim_path_bytes_max >= 64);
    assert(sim_nodes_max >= 64);
    assert(sim_mounts_max >= container_devices_count + 8);
    assert(sim_processes_max >= 2);
    assert(sim_pipe_ends_max >= 4);
    assert(sim_written_files_max > runs_max + 4); // Every record, a temporary one, and slack.
    assert(sim_written_bytes_max > 1024);

    assert(helper_words_max >= 2 + 6 + 1); // name, pid, two triples' worth... and the null.
    assert(helper_map_bytes_max >= "0 4294967295 1 1 4294967295 4294967295".len);
    assert(helper_output_bytes_max < diag_field_bytes_max);
    assert(forwarded_signals_count == 4);
    assert(forwarded_signals_max > forwarded_signals_count);
    assert(runs_max > 0);
    assert(runs_max < dir_entries_max); // Room to see every record and the one being added.
    assert(record_command_bytes_max < record_bytes_max / 2);
    const label_bytes = label_key_bytes_max + label_value_bytes_max + 16;
    assert(labels_count_max * label_bytes < record_bytes_max / 2);
    assert(container_name_bytes_max + record_suffix.len <= dir_name_bytes_max);
    assert(state_path_bytes_max > "/zbx/runs/".len + dir_name_bytes_max + 64);
    assert(record_version >= 1);
    assert(bundle_stage_bytes_max + 16 * 1024 <= bundle_gz_bytes_max);
    assert(bundle_gz_bytes_max <= write_bytes_max);
    assert(bundle_file_bytes_max * 2 < bundle_stage_bytes_max);
    assert(bundle_files_max * 1024 < bundle_stage_bytes_max); // The tar headers.
    assert(diag_json_bytes_max * 4 < record_bytes_max / 2); // Fully escaped, in the record.
    assert(secret_value_bytes_min < secret_value_bytes_max);
    assert(bundle_secrets_max * secret_value_bytes_max < bundle_file_bytes_max);
    assert(bundle_name_bytes_max < dir_name_bytes_max + 32);

    assert(fuzz_iterations_default > 0);
    assert(fuzz_iterations_default <= fuzz_iterations_max);
}
