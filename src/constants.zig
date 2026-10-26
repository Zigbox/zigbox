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

// Exit codes of a command that runs a container (`zbx run`): the container's own code is passed
// through, so these four classes must not collide with it, and the shell's reserved codes are used
// instead (DIAGNOSTICS.md, "Exit codes"). `codes.exit_code_in` decides which applies.
/// zbx itself failed before the command started, whatever the blame.
pub const exit_run_failed: u8 = 125;
/// The command was found but could not be run: not executable, or not for this CPU.
pub const exit_run_not_runnable: u8 = 126;
/// The command was not found.
pub const exit_run_not_found: u8 = 127;
/// A command killed by signal n exits 128 + n.
pub const exit_signal_base: u8 = 128;

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

// A second product's diagnostics (src/diag/product.zig): the strings a `Product` supplies, which
// the renderer places in fixed buffers. The proofs below keep the longest of each within them.
/// "ZBX-", "ZC-": capital letters and a dash. The tag after it ("E0501") is always five bytes.
pub const product_prefix_bytes_max: u32 = 4;
/// The command that explains and bundles: "zbx", "zcube".
pub const product_command_bytes_max: u32 = 16;
/// The hint that names the command that collects a bundle: "zbx bundle --last".
pub const product_bundle_hint_bytes_max: u32 = 48;
pub const product_report_url_bytes_max: u32 = 128;
/// Ends in "/"; a code's page is the base plus "<tag>.html".
pub const product_docs_base_bytes_max: u32 = 64;
/// How many products one rendering looks through for the owner of a code.
pub const products_count_max: u32 = 8;
/// "zbx explain E0501": the `more` line's command, and the buffer it is built in.
pub const product_explain_bytes_max: u32 = 32;
/// A diagnostic as JSON on the wire (`Diagnostic.parse_json`). Larger input is refused unread.
pub const diag_wire_bytes_max: u32 = output_bytes_max;
/// `parse_json` skips the members it does not know (a newer writer added them). How deep a
/// skipped value may nest, and how many bytes of unknown members one line may carry in all
/// (each counted from its key's quote to the end of its value).
pub const diag_skip_depth_max: u32 = 8;
pub const diag_skip_bytes_max: u32 = 4096;

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
pub const sim_nodes_max: u32 = 160;
pub const sim_mounts_max: u32 = 32;
pub const sim_processes_max: u32 = 3;
pub const sim_pipe_ends_max: u32 = 8;
/// Files the simulated programs write (run records), and the most one can hold: a bigger write
/// is "no space left on the device", which is also how a full disk is simulated.
pub const sim_written_files_max: u32 = 72;
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
/// Variables a caller may add (`Spec.env`), each with a bounded name and value. They count
/// against `exec_strings_bytes_max` with the command.
pub const env_vars_count_max: u32 = 32;
pub const env_name_bytes_max: u32 = 64;
pub const env_value_bytes_max: u32 = 4096;
/// The container's PATH, in the order a shell searches it. Counted for the exec candidates.
pub const container_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
pub const container_path_dirs_count: u32 = 6;
/// The devices bind-mounted from the host into the container's `/dev`.
pub const container_devices_count: u32 = 6;
/// The symlinks in the container's `/dev`: fd, stdin, stdout, stderr and ptmx.
pub const container_links_count: u32 = 5;
/// Steps in a plan. The plan's own comptime check proves the count it builds is below this.
pub const plan_steps_max: u32 = 80;

/// The size of the tmpfs mounts of a read-only rootfs (`/tmp` and `/run`): memory the container
/// may use for scratch files, in addition to any memory limit it has.
/// The longest a single wait may be given, and a single sleep: a bound on a stuck caller.
pub const wait_timeout_ms_max: u32 = 24 * 60 * 60 * 1000;
pub const sleep_ms_max: u32 = 60 * 1000;

/// How many scopes without a record `list` adds beyond the records, and the longest a caller
/// should let pass between two `poll`s of a watcher.
pub const scopes_listed_max: u32 = 16;
pub const events_poll_ms_max: u32 = 1000;

pub const tmpfs_bytes_max: u32 = 64 * 1024 * 1024;
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
pub const signal_term: u8 = 15;

/// How long a stop waits between SIGTERM and SIGKILL when nobody says.
pub const stop_grace_ms_default: u32 = 10_000;
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

// D-Bus and the scope (M2, slice 1). Every message, name and wait is bounded here.
/// One D-Bus message, as sent or received. The spec allows 128 MiB; zbx's replies are under 1 KiB,
/// and a bigger one from the bus is refused as a protocol error.
pub const dbus_message_bytes_max: u32 = 16 * 1024;
/// Header fields of one message. The spec defines nine; a message with more is malformed.
pub const dbus_header_fields_max: u32 = 16;
/// Elements of any array zbx reads or writes (header fields, scope properties, PIDs).
pub const dbus_array_elements_max: u32 = 64;
/// How deep a signature may nest (arrays and structs together). The spec's limit is 64.
pub const dbus_nesting_depth_max: u32 = 8;
/// A signature is at most 255 bytes in the spec.
pub const dbus_signature_bytes_max: u32 = 255;
/// A string, object path or name read from a message.
pub const dbus_string_bytes_max: u32 = 1024;
/// `DBUS_SESSION_BUS_ADDRESS`, the longest accepted.
pub const dbus_address_bytes_max: u32 = 512;
/// `sun_path` in the kernel ABI is 108 bytes including the NUL.
pub const dbus_socket_path_bytes_max: u32 = 107;
/// One SASL line, without its CRLF.
pub const dbus_auth_line_bytes_max: u32 = 256;
/// The wait for a reply to one method call, and for a unit's job to finish. The read step is
/// one poll; a wait is a bounded number of steps.
pub const dbus_call_timeout_ms: u32 = 10_000;
pub const dbus_job_timeout_ms: u32 = 30_000;
pub const dbus_poll_step_ms: u32 = 500;
/// Messages processed while waiting for one reply or one job: past this the peer is flooding.
pub const dbus_messages_per_wait_max: u32 = 64;
/// `JobRemoved` signals kept while a reply is awaited.
pub const dbus_job_results_max: u32 = 4;
/// The pids, properties and text of the scope request.
pub const scope_properties_max: u32 = 16;
pub const scope_prefix = "zbx-";
pub const scope_suffix = ".scope";
pub const scope_name_bytes_max: u32 = 4 + container_name_bytes_max + 6;
/// The text of a systemd `Version` property ("255.4-1ubuntu8.4"), kept for diagnostics.
pub const systemd_version_text_bytes_max: u32 = 64;
/// The most of a remote error's name and message kept for a diagnostic.
pub const dbus_error_text_bytes_max: u32 = 160;
/// A cgroup directory below /sys/fs/cgroup, and the files written in it by the fallback.
pub const cgroup_path_bytes_max: u32 = 256;
pub const cgroup_file_bytes_max: u32 = 24;

// Limits (`--memory`, `--pids`, `--cpus`): what a user may ask for. Past either end is a
// diagnostic naming the bound.
pub const limit_memory_bytes_min: u64 = 4 * 1024 * 1024;
pub const limit_memory_bytes_max: u64 = 1 << 40;
pub const limit_pids_min: u32 = 1;
pub const limit_pids_max: u32 = 4_194_304;
/// One CPU is 1000 millis.
pub const limit_cpu_millis_min: u32 = 10;
pub const limit_cpu_millis_max: u32 = 1_024_000;
/// The longest value of a limit flag.
pub const limit_text_bytes_max: u32 = 24;

// Run records (slice 2).
/// Records kept; the oldest is deleted when a run would make it more.
pub const runs_max: u32 = 32;
/// The version `zbx` writes. A record with a higher one is skipped, not misread.
pub const record_version: u32 = 3;
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
pub const bundle_workspace_bytes_max: u32 = 1024 * 1024;
/// The run `Handle` of a foreground run, kept off the stack too.
pub const handle_bytes_max: u32 = 480 * 1024;
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

// Store (M3). The layout is documented in the module doc of `src/store/store.zig`.
/// A BLAKE3 digest, and its lowercase hex; the text form is "b3:" and the hex.
pub const store_digest_bytes: u32 = 32;
pub const store_digest_hex_bytes: u32 = 64;
pub const store_digest_text_bytes: u32 = 67;
/// The shortest digest prefix accepted as input, in hex digits. A shorter one is refused, never
/// guessed at.
pub const store_prefix_hex_min: u32 = 12;
/// The version `store.zon` records. A store with a larger one is refused (written by a newer zbx).
pub const store_format_version: u32 = 1;
/// A file object records one BLAKE3 hash per chunk of this many bytes (the last may be shorter).
pub const store_chunk_bytes: u32 = 1024 * 1024;
/// The most chunks one object has, so the longest file is 4 GiB.
pub const store_chunks_max: u32 = 4096;
pub const store_file_bytes_max: u64 = @as(u64, store_chunk_bytes) * store_chunks_max;
/// Every file of the store is stamped with this modification time (2000-01-01T00:00:00Z), so a
/// materialized tree does not depend on when it was imported. Zero is avoided: some tools treat
/// the epoch as "no time".
pub const store_mtime_seconds: u64 = 946_684_800;
/// The tree encoding's version byte.
pub const store_tree_version: u8 = 1;

/// The id the kernel shows for an owner the user namespace has no mapping for.
pub const store_overflow_id: u32 = 65534;
/// The most entries one directory has, the longest name, and the deepest nesting. A source tree
/// past any of them is refused with a message that names the path.
pub const store_dir_entries_max: u32 = 16384;
pub const store_name_bytes_max: u32 = 255;
pub const store_depth_max: u32 = 64;
pub const store_symlink_target_bytes_max: u32 = 4095;
/// Extended attributes of one file: how many, and the longest name and value.
pub const store_xattrs_max: u32 = 16;
pub const store_xattr_name_bytes_max: u32 = 255;
pub const store_xattr_value_bytes_max: u32 = 4096;
/// The attributes' canonical encoding (count, then name and value of each, with lengths).
pub const store_xattr_blob_bytes_max: u32 = 1 + store_xattrs_max * (4 + 255 + 4096);
/// One encoded directory: the longest a tree object can be.
pub const store_tree_bytes_max: u32 = 4 * 1024 * 1024;
/// The working memory of a walk: names, sorting indexes and the encoded entries of every open
/// directory. A tree that needs more is refused.
pub const store_arena_bytes_max: u32 = 16 * 1024 * 1024;
/// File contents move through a buffer of this size.
pub const store_io_buffer_bytes: u32 = 256 * 1024;
/// A root's record, and the most roots `ls` lists.
pub const store_root_record_bytes_max: u32 = 8192;
pub const store_roots_max: u32 = 1024;
pub const store_source_bytes_max: u32 = 1024;
/// The shard directories (the first byte of a digest).
pub const store_shards_count: u32 = 256;
/// Entries a walk of stored trees visits before it gives up (a damaged store, or one built by
/// hand, could make a tree refer to itself through its subtrees).
pub const store_walk_entries_max: u32 = 1 << 24;
/// Warnings shown for one command; the rest are counted.
pub const store_warnings_shown_max: u32 = 8;
/// Temporary files of one process: `tmp/<pid>-<n>`.
pub const store_tmp_attempts_max: u32 = 1 << 20;
/// A store path: the data directory, then "/zbx/store/objects/ab/" and 62 hex digits, with room
/// for a suffix.
pub const store_path_bytes_max: u32 = 600;
pub const store_data_base_bytes_max: u32 = 400;
/// Failed attempts at a rename or write that are retried because the kernel was interrupted.
pub const store_io_retries_max: u32 = 16;

// The simulator's file tree for the store (`src/store/fs_sim.zig`): nodes, the bytes of every
// file written, and open files.
pub const sim_fs_nodes_max: u32 = 640;
pub const sim_fs_path_bytes_max: u32 = 192;
pub const sim_fs_pool_bytes_max: u32 = 2 * 1024 * 1024;
pub const sim_fs_handles_max: u32 = 8;

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
    // The container-run codes are the shell's reserved ones: distinct from each other, from the
    // standard four, and below the signal range.
    const run_exits = [_]u8{ exit_run_failed, exit_run_not_runnable, exit_run_not_found };
    for (run_exits, 0..) |first, index| {
        for (exits) |standard| assert(first != standard);
        for (run_exits[index + 1 ..]) |second| assert(first != second);
        assert(first < exit_signal_base);
    }
    assert(exit_run_failed == 125);
    assert(exit_run_not_runnable == 126);
    assert(exit_run_not_found == 127);
    assert(tool_exit_ok == exit_ok);
    assert(tool_exit_failed != tool_exit_usage);

    // D-Bus: a message holds its own header fields and one scope request, and the waits are whole
    // numbers of poll steps.
    assert(dbus_header_fields_max >= 9); // The spec defines nine.
    assert(dbus_array_elements_max >= scope_properties_max);
    assert(dbus_string_bytes_max <= dbus_message_bytes_max / 8);
    assert(dbus_socket_path_bytes_max + "unix:path=".len < dbus_address_bytes_max);
    assert(dbus_call_timeout_ms % dbus_poll_step_ms == 0);
    assert(dbus_job_timeout_ms % dbus_poll_step_ms == 0);
    assert(dbus_call_timeout_ms < dbus_job_timeout_ms);
    assert(scope_prefix.len + container_name_bytes_max + scope_suffix.len == scope_name_bytes_max);
    assert(limit_memory_bytes_min < limit_memory_bytes_max);
    assert(limit_pids_min < limit_pids_max);
    assert(limit_cpu_millis_min < limit_cpu_millis_max);
    assert(dbus_signature_bytes_max == 255);

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

    assert(diag_code_bytes == product_prefix_bytes_max + 5);
    assert(product_command_bytes_max + " explain ".len + 5 <= product_explain_bytes_max);
    assert(product_docs_base_bytes_max + diag_code_bytes + ".html".len <= docs_url_bytes_max);
    assert(product_bundle_hint_bytes_max <= diag_field_bytes_max);
    // What a product's strings add to one rendering (the `more`, `docs` and `report` lines and
    // the bug sentence, each with its label) is far inside the 1024 bytes that the proof of
    // `rendered_bytes_max` above keeps for everything but the lists.
    const product_lines_bytes_max = 2 * (docs_url_bytes_max + product_report_url_bytes_max +
        2 * product_command_bytes_max + 4 * (diag_label_columns + 16));
    assert(product_lines_bytes_max + 2 * diag_summary_bytes_max + 128 <= 1024);
    // The longest diagnostic as JSON, every byte of free text escaped to two: the lists as in
    // `rendered_bytes_max`, the summary, the saved path, the docs URL and the framing. It must
    // fit what a renderer buffers and what the parser accepts.
    const json_free_text = diag_causes_count_max * diag_field_bytes_max +
        diag_whiles_count_max * diag_field_bytes_max +
        diag_context_count_max * (diag_key_bytes_max + diag_field_bytes_max) +
        diag_fixes_count_max * (diag_field_bytes_max + diag_command_bytes_max) +
        diag_summary_bytes_max + state_path_bytes_max + 128;
    const json_bytes_max = 2 * json_free_text + docs_url_bytes_max + 1024;
    assert(json_bytes_max <= diag_wire_bytes_max);
    assert(diag_wire_bytes_max == output_bytes_max);
    assert(diag_skip_depth_max > 0);
    assert(diag_skip_depth_max <= 16); // The skipper's stack is this many bytes.
    assert(diag_skip_bytes_max > 0);
    // Unknown members cannot be most of a line.
    assert(diag_skip_bytes_max * 2 <= diag_wire_bytes_max);

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

    assert(store_digest_hex_bytes == store_digest_bytes * 2);
    assert(store_digest_text_bytes == store_digest_hex_bytes + "b3:".len);
    assert(store_prefix_hex_min < store_digest_hex_bytes);
    assert(store_chunk_bytes % 4096 == 0);
    assert(store_io_buffer_bytes % 4096 == 0);
    assert(store_file_bytes_max == 4 * 1024 * 1024 * 1024);
    assert(store_name_bytes_max <= std.math.maxInt(u8));
    assert(store_xattr_value_bytes_max <= std.math.maxInt(u16));
    assert(store_xattr_blob_bytes_max < store_arena_bytes_max / 16);
    assert(store_tree_bytes_max < store_arena_bytes_max / 2);
    assert(store_dir_entries_max * 4 < store_arena_bytes_max / 8); // The sorting indexes.
    assert(store_symlink_target_bytes_max < std.math.maxInt(u16));
    assert(store_symlink_target_bytes_max <= path_bytes_max);
    assert(store_depth_max * 2 < path_bytes_max);
    assert(
        store_path_bytes_max > store_data_base_bytes_max + "/zbx/store/objects/ab/".len + 62 + 16,
    );
    assert(store_root_record_bytes_max >= store_source_bytes_max * 4 + 512); // All escaped.
    assert(store_source_bytes_max <= path_bytes_max);
    assert(store_shards_count == 256);
    assert(store_warnings_shown_max > 0);
    assert(sim_fs_path_bytes_max > 100); // A store path: "/s/objects/ab/" and 62 digits.
    assert(sim_fs_handles_max >= 4);

    assert(fuzz_iterations_default > 0);
    assert(fuzz_iterations_default <= fuzz_iterations_max);
}
