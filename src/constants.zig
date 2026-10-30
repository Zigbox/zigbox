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
pub const doctor_checks_count: u32 = 7;
pub const detail_bytes_max: u32 = 240;
pub const binary_candidates_count: u32 = 3;
/// The doctor's look for `pasta` (M5): directories of PATH tried, the longest path kept, and the
/// bytes of `pasta --version` read (its first line is shown).
pub const pasta_path_dirs_max: u32 = 32;
pub const pasta_path_bytes_max: u32 = 256;
pub const pasta_version_bytes_max: u32 = helper_output_bytes_max;

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
pub const errors_page_bytes_max: u32 = 32 * 1024;

// Host simulator.
pub const sim_files_max: u32 = 128;
pub const sim_open_files_max: u32 = 8;
pub const sim_output_bytes_max: u32 = 64 * 1024;
/// The simulator's container model: paths, nodes (directories, files, links), mounts per
/// namespace, processes, and pipe ends. Simulated paths are short; a longer one is refused.
pub const sim_path_bytes_max: u32 = 256;
pub const sim_nodes_max: u32 = 160;
pub const sim_mounts_max: u32 = 32;
pub const sim_processes_max: u32 = 8;
pub const sim_pipe_ends_max: u32 = 24;
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
pub const env_vars_count_max: u32 = 64;
pub const env_name_bytes_max: u32 = 64;
pub const env_value_bytes_max: u32 = 4096;
/// `-e` options of one run (M6). A value is never stored; the record keeps the names. Each takes
/// two of the `args_count_max` arguments when typed `-e NAME=VALUE`, so the limit leaves room for
/// the rest of a command line, and the image's own variables share `env_vars_count_max`.
pub const run_env_count_max: u32 = 16;
/// The container's PATH, in the order a shell searches it. Counted for the exec candidates.
pub const container_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
pub const container_path_dirs_count: u32 = 6;
/// Directories of an image's own PATH that a command is looked for in (the rest are ignored).
pub const candidates_max: u32 = 16;
/// The devices bind-mounted from the host into the container's `/dev`.
pub const container_devices_count: u32 = 6;
/// The symlinks in the container's `/dev`: fd, stdin, stdout, stderr and ptmx.
pub const container_links_count: u32 = 5;
/// The generated `/etc/hosts` and `/etc/resolv.conf` of a container (M5): the most one of them
/// holds. The host's `resolv.conf`, which a `--net host` container gets, is cut to whole lines
/// within this.
pub const etc_file_bytes_max: u32 = 4096;
/// The hidden names, in the container's `/dev` tmpfs, the two files are written to before they
/// are bound over the image's `/etc` files and removed again.
pub const etc_stage_hosts = ".zbx-hosts";
pub const etc_stage_resolv = ".zbx-resolv";
/// Steps in a plan. The plan's own comptime check proves the count it builds is below this.
pub const plan_steps_max: u32 = 224;

// User-mode networking through pasta (M5 slice 3; docs/demos/m5.md settles each fact below
// against the pasta that Ubuntu 24.04 ships, 0.0~git20240220.1e6f92b).

/// `--publish` given at most this many times.
pub const publish_count_max: u32 = 16;
/// The address a `--net user` container's /etc/resolv.conf names. pasta's `--dns-forward` maps
/// DNS sent to it to the host's own first resolver, from the host's side, which is how a
/// container reaches systemd-resolved's stub at 127.0.0.53. Link-local, like Podman's choice,
/// so that it is never a real host the container would mean.
pub const pasta_dns_forward = "169.254.1.1";
/// The oldest pasta zbx runs: the first release (2024_02_16.08344da) whose watch of a namespace
/// named by a PID (`/proc/<pid>/ns/net`, where inotify sees nothing) falls back to a timer, so
/// that it exits when the container does. As a date, and as its release prints it.
pub const pasta_version_min_date: u32 = 20240216;
pub const pasta_version_min = "2024_02_16";
/// How long pasta has, from its start, to report the container's interface configured and the
/// ports bound (its PID on its standard output, `--pid /proc/self/fd/1`). It takes tens of
/// milliseconds; a pasta that has not done it in this long is stuck, and the run is refused.
pub const pasta_ready_timeout_ms: u32 = 10_000;
/// The ready line is a PID and a newline; anything longer is not one.
pub const pasta_ready_line_bytes_max: u32 = 16;
/// Reads of the ready pipe: each returns a byte or more, an end of file, or a timeout.
pub const pasta_ready_reads_max: u32 = pasta_ready_line_bytes_max + eintr_retries_max + 4;
/// pasta's arguments: twenty fixed words, two per forward (`-t` and its value), and the PID.
pub const pasta_argv_words_max: u32 = 20 + 2 * publish_count_max + 1;
/// The bytes of those words: the fixed ones, the forwards and the PID, with their NULs.
pub const pasta_argv_bytes_max: u32 = 512 + publish_count_max * 16;
/// What may stand between "port " and the number in pasta's bind failure: an IPv6 address, a
/// wildcard and a slash.
pub const pasta_port_prefix_bytes_max: u32 = 48;
/// The end of pasta's log read for the diagnostic of a pasta that failed: its last line.
pub const pasta_log_tail_bytes_max: u32 = 4096;
/// The file name of a run's pasta log in the logs directory, after the run's name.
pub const pasta_log_suffix = ".pasta.log";

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
pub const plan_paths_bytes_max: u32 = 96 * 1024;
/// One id map line, "0 4294967295 1\n", with room to spare.
pub const id_map_line_bytes_max: u32 = 32;
/// A record the child writes to the failure pipe: kind, step, and a two-byte errno.
pub const sync_record_bytes: u32 = 4;
/// Records a child can write: one note per tolerant step, then at most one failure.
pub const sync_records_max: u32 = 12;
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
/// SIGWINCH (the terminal's window changed size), 28 on x86_64 and aarch64. `exec` with a
/// pseudo-terminal passes the new size on; nothing forwards it to a container.
pub const signal_winch: u8 = 28;

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
/// Pids the scope's keeper process takes from the scope's `TasksMax`: the container gets the
/// `--pids` it asked for, so the unit's limit is that plus this.
pub const scope_keeper_tasks: u32 = 1;
/// Reads the keeper makes of its pipe before it gives up and ends. Nothing is ever written to
/// the pipe, so one read that waits for the end of file is the whole life of a keeper; the bound
/// is for interrupted reads and for a pipe that someone writes to by mistake.
pub const keeper_reads_max: u32 = 4096;
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
/// The cgroupfs driver removes a container's cgroup, trying again while the kernel says it is busy.
pub const cgroup_remove_tries_max: u32 = 20;
pub const cgroup_remove_wait_ms: u32 = 10;

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
pub const record_version: u32 = 8;
/// One record. The command is cut to `record_command_bytes_max` and says so.
pub const record_bytes_max: u32 = 64 * 1024;
// Every reader of a record reads a file of at most `file_bytes_max`, so a record is never larger.
comptime {
    assert(record_bytes_max <= file_bytes_max);
}
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
/// The recent execs a container's history keeps (`runtime/exec_history.zig`): the oldest goes.
pub const exec_history_entries_max: u32 = 16;
/// How long an exec waits for another to finish writing the history: tries, and the wait
/// between two (one second in all).
pub const exec_history_lock_tries_max: u32 = 100;
pub const exec_history_lock_wait_ms: u32 = 10;
/// A container's directory under the state directory: `<state>/zbx/containers/<name>`, and the
/// longest path inside it (`/upper`, `/merged`).
pub const containers_path_bytes_max: u32 = 640;
/// Seconds since the epoch; a record's times are these.
pub const record_time_unknown: u64 = 0;

// Container logs (M6b, slice 2).
/// The log of a container, `logs/<name>.log` beside the run record: a header, then records. The
/// header is 16 bytes: the version, seven zero bytes, and the payload bytes that came before its
/// first record in the stream of everything the container wrote (u64, little endian). A record
/// is a 12-byte header
/// (stream, time in seconds as 5 bytes, length as 2 bytes, CRC-32 of those 8 bytes and the
/// payload) and its payload.
pub const log_version: u8 = 1;
pub const log_header_bytes: u32 = 16;
pub const log_record_header_bytes: u32 = 12;
/// The most bytes one record holds; a longer write is cut into several records.
pub const log_record_bytes_max: u32 = 4096;
/// The most a container's log keeps, both files together. At the cap the older file is replaced
/// by the current one, so what is dropped is always a whole file of whole records.
pub const log_bytes_max: u64 = 5 * 1024 * 1024;
/// One of the two files a log is kept in: half the cap.
pub const log_segment_bytes_max: u32 = 2_621_440;
/// A record's time is seconds since the epoch, as in every other record zbx keeps.
pub const log_time_max: u64 = 1 << 40;
/// The file names in the logs directory, after the container's name: the current file and the
/// older one. A container name has no dot, so neither collides with `pasta_log_suffix`.
pub const log_suffix = ".log";
pub const log_older_suffix = ".log.1";
/// The reader's window into a file: room for the largest record and for reading ahead.
pub const log_read_bytes: u32 = 16 * 1024;
/// How often `zbx logs --follow` looks for more, and how many looks it spends on the end of a
/// log that is still being written to after the container has ended.
pub const log_follow_poll_ms: u32 = 100;
pub const log_follow_settle_looks: u32 = 3;
/// The most `--tail` may ask for.
pub const log_tail_lines_max: u32 = 1_000_000;
/// The most a pump reads from one stream at a time.
pub const log_pump_bytes: u32 = log_record_bytes_max;
/// The most time the end of a container's output is waited for after it has gone.
pub const log_drain_ms: u32 = 200;
/// Reads in one drain of the output after the container ended: it ends at the end of the output,
/// and a stuck holder of the pipe's write end costs `log_drain_ms` once.
pub const log_drain_reads_max: u32 = 4096;
/// The most output events one `wait` takes before it looks at the signals again.
pub const log_wait_events_max: u32 = 1 << 30;

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
/// An exec's handle (`runtime/exec.zig`): the plan, the container's environment, its passwd and
/// group files, and the room the history is rewritten in.
pub const exec_handle_bytes_max: u32 = 640 * 1024;
/// The environment variables listed in a bundle, and those whose values are scrubbed elsewhere.
pub const environment_entries_max: u32 = 256;
pub const bundle_secrets_max: u32 = 32;
pub const secret_value_bytes_min: u32 = 4;
pub const secret_value_bytes_max: u32 = 256;
/// The diagnostic kept in a run record, as the JSON line zbx printed. Bigger is replaced by a
/// short object that names the code.
pub const diag_json_bytes_max: u32 = 3072;
/// A diagnostic carried through a pipe from the store's worker to its caller (`Diag.encode`).
pub const diag_carry_bytes_max: u32 = 6 * 1024;
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
/// The room gc has for the sets of what it keeps: untouched memory until a plan sizes them to
/// the store, then 16 bytes a slot at three quarters full. About 1.5 million objects fit.
pub const store_gc_tables_bytes: u32 = 64 * 1024 * 1024;
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
/// How long what gc moved stays in `trash/<gc id>/` before the next gc empties it: 7 days.
pub const store_trash_seconds: u64 = 7 * 24 * 60 * 60;

/// A cut download (`blobs/partial/`) that nobody has written to for this long is abandoned: gc
/// plans it. A pull that is resumed later starts again from nothing.
pub const store_partial_seconds: u64 = 24 * 60 * 60;
/// A gc id is this many hex digits of the plan hash it ran with.
pub const store_gc_id_hex_bytes: u32 = 12;
/// The most bytes a store lock's holder record takes: "<pid> <command>", padded with NUL.
pub const store_lock_holder_bytes: u32 = 64;
/// How long a command waits for the store lock before it gives up (`Busy`), and how long it
/// sleeps between two tries. The wait is bounded: a store is never waited on for ever.
pub const store_lock_wait_ms: u32 = 10_000;
pub const store_lock_retry_ms: u32 = 20;
/// `verify` reports this many damaged things in full (and counts the rest), and for each names at
/// most `store_verify_paths_max` of the paths that reach it.
pub const store_verify_damaged_max: u32 = 256;
pub const store_verify_paths_max: u32 = 16;
/// The most gc ids `gc --trash` lists.
pub const store_trash_entries_max: u32 = 256;

// State volumes (M6 slice 2, docs/briefs/M6-state.md). The layout is in the module doc of
// `src/state/state.zig`.
/// A volume's name: lowercase letters, digits, `.`, `-` and `_`, starting with a letter or digit.
/// A directory name, never a path.
pub const state_name_bytes_max: u32 = 63;
/// `--state` given at most this many times in one run.
pub const state_volumes_max: u32 = 8;
/// A mount target in the container: absolute, every part a name, no `.` or `..` part.
pub const state_target_bytes_max: u32 = 256;
/// A `--state` value: the name, a colon, the target and ":ro".
pub const state_value_bytes_max: u32 = state_name_bytes_max + 1 + state_target_bytes_max + 3;
/// The version `state.zon` records. A record with a larger one is refused, never misread.
pub const state_record_version: u32 = 1;
/// One `state.zon`: a name, a container name and a target, every byte escaped, and the rest.
pub const state_record_bytes_max: u32 = 4096;
/// The times a volume's record keeps are seconds since the epoch, below this (year 36812): a
/// bound `render` asserts and `parse` refuses past.
pub const state_time_max: u64 = 1 << 40;
/// The state directory: the data directory, then "/zbx/state", a name, and "/data" or a trash
/// entry's name; a state path holds the longest of these.
pub const state_volume_path_bytes_max: u32 = 640;
/// The trash keeps what `zbx state rm` moved for `store_trash_seconds`, as gc's does; the most
/// entries `state ls` lists, and the most volumes.
pub const state_trash_listed_max: u32 = 64;
pub const state_volumes_listed_max: u32 = 128;
/// A run waits this long for a volume's lock before it refuses (a `zbx state rm` holding it for
/// a moment), trying every `store_lock_retry_ms`.
pub const state_lock_wait_ms: u32 = 500;
/// The size walk of `state ls`: the names of every open directory share one region, nesting is
/// at most `store_depth_max`, entries counted at most this many, and inodes with more than one
/// name are remembered (so that each is counted once) up to this many. Past any of them the
/// size is not known, and a warning says so.
pub const state_walk_arena_bytes: u32 = 4 * 1024 * 1024;
pub const state_walk_entries_max: u32 = 1 << 22;
pub const state_walk_links_max: u32 = 16384;
/// Containers named as holding one volume, in a refusal or in `state ls`.
pub const state_holders_max: u32 = 8;

// Other mounts (M6 slice 3, docs/briefs/M6-state.md): `--tmpfs`, `--bind` and `--secret`.
/// The three flags together, in one run. State volumes are counted apart (`state_volumes_max`).
pub const mounts_max: u32 = 8;
/// A path of a mount: the host's side (a bind or a secret) and the container's (all of them).
/// The same bound as a state volume's target, so one set of rules reads both.
pub const mount_path_bytes_max: u32 = 256;
/// A mount as the run record keeps it: `secret:`, the host path, a colon and the target.
pub const mount_value_bytes_max: u32 = 7 + mount_path_bytes_max + 1 + mount_path_bytes_max;
/// The default size of a `--tmpfs`, and its bounds. The pages of a tmpfs are charged to the
/// memory of the container's cgroup, so with `--memory` the limit holds for them too; the size
/// is a ceiling for the mount, not a reservation.
pub const tmpfs_mount_bytes_default: u64 = 64 * 1024 * 1024;
pub const tmpfs_mount_bytes_min: u64 = 4096;
pub const tmpfs_mount_bytes_max: u64 = 1 << 40;
/// The longest secret file: it is copied into the container's own memory (a tmpfs file), and the
/// copy is made by a child that keeps it on its stack.
pub const secret_bytes_max: u32 = 64 * 1024;
/// The hidden names, in the container's /dev, a mount is staged at before it is moved onto its
/// target (followed by the mount's index, one digit).
pub const mount_stage_prefix = "/dev/.zbx-mount-";
/// The options of a `--tmpfs` mount: `mode=1777,size=` and the size in decimal.
pub const tmpfs_options_bytes_max: u32 = 16 + 20;

// Writable project mounts and `--user` (M6b slice 1, docs/briefs/M6b-dev-loop.md).
/// Symbolic links followed while a `--mount` source or the project directory is resolved, as
/// the kernel's own limit is: past it the path is a loop, and the mount is refused.
pub const symlinks_followed_max: u32 = 40;
/// Steps of the resolver: each name of the path, and of the target of each link followed. It
/// stops there with a refusal, never loops on.
pub const path_resolve_steps_max: u32 = (symlinks_followed_max + 1) * path_bytes_max;
/// The longest `--user` value, `USER[:GROUP]`.
pub const user_value_bytes_max: u32 = 256;

// `zbx state export` (M6 slice 3).
/// Notes about devices, sockets and fifos left out: shown one each up to this many, then counted.
pub const state_export_notes_max: u32 = 16;
/// The room the archive is assembled in before each write, and the paths of hard-linked files
/// remembered so that a second name becomes a link: past either the export stops, never cuts.
pub const state_export_buffer_bytes: u32 = 64 * 1024;
pub const state_export_links_bytes: u32 = 1024 * 1024;
/// The largest owner a ustar header holds (seven octal digits).
pub const state_export_id_max: u32 = 0o7777777;
/// The largest time (eleven octal digits).
pub const state_export_time_max: u64 = 0o77777777777;

// The simulator's file tree for the store (`src/store/fs_sim.zig`): nodes, the bytes of every
// file written, and open files.
pub const sim_fs_nodes_max: u32 = 640;
pub const sim_fs_path_bytes_max: u32 = 192;
pub const sim_fs_pool_bytes_max: u32 = 2 * 1024 * 1024;
pub const sim_fs_handles_max: u32 = 8;

// Registry and pull (M4, docs/briefs/M4-pull.md). Every byte a registry sends is bounded: it is
// an external service, and what it sends is untrusted until its digest is checked.
/// A whole reference as typed, and the parts of it (the registry of the OCI distribution spec is
/// a DNS name of at most 253 bytes and a port; a repository at most 255).
pub const reference_bytes_max: u32 = 1024;
pub const reference_registry_bytes_max: u32 = 261;
pub const reference_repository_bytes_max: u32 = 255;
pub const reference_tag_bytes_max: u32 = 128;
/// SHA-256 in an image: 32 bytes, "sha256:" and 64 hex digits.
pub const oci_digest_bytes: u32 = 32;
pub const oci_digest_hex_bytes: u32 = 64;
pub const oci_digest_text_bytes: u32 = 71;
/// The most a manifest or an index may weigh. The OCI distribution spec asks registries to stop
/// at 4 MiB; real indexes are a few KiB (python's, with its attestations, about 10).
pub const registry_manifest_bytes_max: u32 = 1024 * 1024;
/// Entries of an index, and layers of an image. An overlay mount stops at 128 lower layers.
pub const registry_index_entries_max: u32 = 256;
pub const registry_layers_max: u32 = 128;
/// The memory the JSON of a manifest is parsed in (slices of the body are not copied).
pub const registry_json_arena_bytes: u32 = 512 * 1024;
/// A token (a JWT is about 2 KiB) and the response it came in.
pub const registry_token_bytes_max: u32 = 16 * 1024;
pub const registry_token_response_bytes_max: u32 = 32 * 1024;
/// A challenge, a request path with its query, a redirect target, and one response header.
pub const registry_challenge_bytes_max: u32 = 1024;
pub const registry_url_bytes_max: u32 = 2048;
pub const registry_header_bytes_max: u32 = 128;
/// The head of a response (status line and headers) and of a request.
pub const registry_head_bytes_max: u32 = 16 * 1024;
pub const registry_request_head_bytes_max: u32 = 24 * 1024;
/// Redirects followed for one request; a blob normally has one (to a CDN).
pub const registry_redirects_max: u32 = 4;
/// How long a connect, a handshake, or any wait for the next bytes may take, and how long all of
/// one small request (a token, a manifest) may take. A blob's total is not bounded: it is
/// bounded by progress (each wait is `net_idle_timeout_ms`).
pub const net_idle_timeout_ms: u32 = 30_000;
pub const net_request_timeout_ms: u32 = 120_000;
/// The platforms an image offers that a refusal lists; the rest are counted.
pub const registry_platforms_listed_max: u32 = 8;
/// A proxy URL from the environment, and a NO_PROXY list.
pub const net_proxy_url_bytes_max: u32 = 512;
pub const net_no_proxy_bytes_max: u32 = 2048;
/// The CA certificates of the system, parsed once per process: the room for the bundle.
pub const net_ca_arena_bytes: u32 = 2 * 1024 * 1024;
/// The JSON result of a resolve: 128 layers of about 150 bytes, and the rest.
pub const pull_output_bytes_max: u32 = 32 * 1024;
/// What the pull's child tells its parent through a pipe (`pull_report.zig`): the warnings it
/// raised, then the failure (a diagnostic, at most `diag_carry_bytes_max`) or the result. The
/// parent reads the pipe only when the child has ended, so the whole report must fit a pipe
/// (65536 bytes on Linux) with room to spare; a warning that does not fit is counted, not sent.
pub const pull_report_bytes_max: u32 = 16 * 1024;
/// How long the parent waits for more of a report from a child that has ended: its writes are
/// all in the pipe, so a poll that finds nothing ready is the end.
pub const pull_report_drain_wait_ms: u32 = 1;
/// The most `ensure_pipe_capacity` is asked for (the kernel's default maximum is 1 MiB).
pub const pipe_capacity_bytes_max: u32 = 1024 * 1024;
/// The header of one record of the report: its kind and the length of what follows.
pub const pull_report_header_bytes: u32 = 3;
/// A result record's payload: the tree's digest, six counts and the number of warnings dropped.
pub const pull_report_result_bytes: u32 = store_digest_bytes + 6 * 8 + 4;
/// What the warnings of a report may use: the rest is kept for the record that ends it.
pub const pull_report_warnings_bytes_max: u32 =
    pull_report_bytes_max - pull_report_header_bytes - diag_carry_bytes_max;
/// Calls one read or write loop makes before it gives up (each wait inside is time bounded).
pub const net_io_calls_max: u32 = 1 << 20;
/// Mirrors for docker.io that a setting may name, and the longest setting.
pub const registry_mirrors_max: u32 = 4;
pub const registry_mirrors_bytes_max: u32 = 1024;
/// An image record (`store/images.zig`): its fixed fields, its tags (each a reference escaped
/// four bytes a byte at the worst), 128 layer digests and the image's settings.
pub const image_record_bytes_max: u32 = 80 * 1024;
/// The settings an image carries (entrypoint, cmd, env, working directory, user): the bytes of
/// all their strings together, and the words of each list. An image with more is refused.
pub const image_settings_bytes_max: u32 = 6 * 1024;
pub const image_settings_words_max: u32 = 48;
/// The tags an image record keeps: every reference the image was pulled as. When it is full, the
/// oldest goes.
pub const image_tags_max: u32 = 8;
pub const images_max: u32 = 4096;
/// `zbx.lock` (`lock_file.zig`): the entries it holds, the bytes of their references together,
/// and the largest file read or written.
pub const lock_entries_max: u32 = 256;
pub const lock_pool_bytes: u32 = 64 * 1024;
pub const lock_file_bytes_max: u32 = 160 * 1024;
/// The buffer a blob is hashed and copied through.
pub const blob_io_bytes: u32 = 64 * 1024;
/// How many hosts one name may resolve to that are tried.
pub const net_addresses_max: u32 = 8;

// Fuzz runner.
pub const fuzz_iterations_default: u32 = 10_000;
pub const fuzz_iterations_max: u32 = 100_000_000;
/// Each fuzzer's share of `zig build check`, with a fresh seed: a quick look, not the soak.
pub const fuzz_check_iterations: u32 = 2_000;

// The macOS VM (milestone M4b). One VM per user, started by the first command that needs it.
/// The vsock port the guest's init listens on.
pub const vm_guest_port: u32 = 1024;
/// The VM's size when nothing is set: this many virtual CPUs, or half the Mac's if fewer, and
/// this much memory.
pub const vm_cpus_default: u32 = 4;
pub const vm_memory_bytes_default: u64 = 2 << 30;
/// What `zbx vm config` accepts, before Virtualization.framework's own limits and the Mac's are
/// applied on top. The least memory is what the kernel and the initramfs need to boot and run
/// a container; the most is far past any Mac that has Apple silicon.
pub const vm_cpus_min: u32 = 1;
pub const vm_cpus_max: u32 = 64;
pub const vm_memory_bytes_min: u64 = 512 << 20;
pub const vm_memory_bytes_max: u64 = 256 << 30;
/// The store disk (slice 3): a sparse file on the Mac that the guest formats as ext4. It costs
/// the Mac only what the guest writes. The default is generous because it is only a ceiling; the
/// least holds a few images; the most is far past what a Mac's volume has.
pub const vm_disk_bytes_default: u64 = 64 << 30;
pub const vm_disk_bytes_min: u64 = 1 << 30;
pub const vm_disk_bytes_max: u64 = 8 << 40;
/// The Mac's volume must have this much free room beside the disk file's current size, or the
/// machine is not started: a full volume would show up as I/O errors inside the guest.
pub const vm_disk_host_free_bytes_min: u64 = 2 << 30;
/// The guest reports a full disk when less than this is free after a command failed.
pub const vm_disk_full_bytes: u64 = 32 << 20;
/// Where the guest mounts the disk, and the directories on it that zbx's XDG paths point to.
pub const vm_disk_mount = "/mnt/store";
pub const vm_disk_device = "/dev/vda";
/// The home directory share: the tag the guest mounts it by.
pub const vm_home_tag = "home";
pub const vm_rosetta_tag = "rosetta";
pub const vm_rosetta_mount = "/mnt/rosetta";
/// The size at which the host's log is renamed to `host.log.1` and started afresh.
pub const vm_host_log_bytes_max: u64 = 64 << 10;
/// The VM stops after this long without a command to run (enforced from slice 2).
pub const vm_idle_timeout_ms: u32 = 5 * 60 * 1000;
/// From the start of the host process to the guest's answer on vsock.
pub const vm_boot_timeout_ms: u32 = 30_000;
/// From the request to stop to the VM being off; then it is stopped by force.
pub const vm_stop_timeout_ms: u32 = 10_000;
/// A client waiting for the host's answer on the control socket.
pub const vm_control_timeout_ms: u32 = 5_000;
/// Between two looks at something that has no notification (the socket, the VM's state).
pub const vm_poll_step_ms: u32 = 20;
/// One line of the control socket, of the guest's handshake, and of a settings record.
pub const vm_line_bytes_max: u32 = 512;
/// The image version: hex digits of the digest over the kernel and the initramfs.
pub const vm_image_version_bytes: u32 = 16;
/// A socket path on macOS is at most 103 bytes and a NUL.
pub const vm_socket_path_bytes_max: u32 = 103;
pub const vm_path_bytes_max: u32 = 1024;
/// A file of the image (kernel, initramfs) is at most this big, so a damaged one is refused.
pub const vm_image_file_bytes_max: u64 = 256 << 20;
/// The lines of the host's log shown after a host that died before it answered.
pub const vm_log_tail_bytes_max: u32 = 2048;

// The macOS VM, slice 2: forwarding commands into the VM (docs/briefs/M4b-mac.md).
/// The vsock port of `zbx guest serve`, which runs the forwarded commands.
pub const vm_forward_port: u32 = 1025;
/// The guest's port forwarder (slice 4): the host keeps one connection to learn which ports are
/// published, and opens one per Mac connection to carry its bytes.
pub const vm_ports_port: u32 = 1026;
/// Published ports the Mac listens on at one time, and Mac connections carried at one time.
pub const vm_ports_max: u32 = 64;
pub const vm_relays_max: u32 = 128;
/// A port the client reserved and the guest never reported open is released after this long (the
/// client died between the reservation and the command).
pub const vm_reserve_ttl_ms: u64 = 60_000;
/// While a command runs the host asks the guest for its ports this often, as a fallback to the
/// guest's own news (a port that opens during a foreground `run`).
pub const vm_ports_scan_ms: u32 = 500;
/// A relay's buffer, and how long the guest has to connect to the published port.
pub const vm_relay_buffer_bytes: u32 = 64 * 1024;
pub const vm_relay_connect_ms: u32 = 5_000;
/// The vsock address of the host (VMADDR_CID_HOST). The guest's two listeners take connections
/// from nowhere else: with the Mac's home shared (slice 3), a container that could reach a
/// listener would run zbx as the user outside its sandbox.
pub const vm_host_cid: u32 = 2;
/// A frame of the forwarding protocol: a kind byte, a four-byte length and the payload.
pub const forward_header_bytes: u32 = 5;
pub const forward_frame_bytes_max: u32 = 64 * 1024;
/// The most data one stdin, stdout or stderr frame carries.
pub const forward_data_bytes_max: u32 = 16 * 1024;
/// The command line, working directory and environment of the first frame.
pub const forward_start_bytes_max: u32 = 60 * 1024;
pub const forward_env_count_max: u32 = 32;
/// Commands the guest runs at one time for one Mac user.
pub const forward_sessions_max: u32 = 16;
/// The guest user: the Mac user's name, ids and home, and the range of ids it may map.
pub const vm_user_name_bytes_max: u32 = 32;
pub const vm_home_bytes_max: u32 = 255;
pub const vm_subid_start: u32 = 100_000;
pub const vm_subid_count: u32 = 65_536;
/// From the guest to a closed connection to the command it ran: SIGHUP, then SIGKILL this long
/// after.
pub const vm_hangup_grace_ms: u32 = 2_000;
/// How often the host asks the guest whether anything runs, and the environment variable that
/// replaces `vm_idle_timeout_ms` (tests; milliseconds).
pub const vm_idle_check_ms: u32 = 1_000;
/// What the variable may say: not so small that the machine stops between two commands of a
/// script, not so big that it never does.
pub const vm_idle_timeout_ms_min: u32 = 500;
pub const vm_idle_timeout_ms_max: u32 = 24 * 60 * 60 * 1000;
pub const vm_idle_timeout_variable = "ZBX_VM_IDLE_TIMEOUT_MS";
/// The delegated cgroup subtree the guest's init makes for the guest user.
pub const vm_cgroup_root = "/sys/fs/cgroup/zbx";
pub const cgroup_root_variable = "ZBX_CGROUP_ROOT";
/// DHCP in the guest: tries, and the wait for each answer.
pub const vm_dhcp_tries_max: u32 = 10;
pub const vm_dhcp_wait_ms: u32 = 500;
pub const vm_dhcp_packet_bytes_max: u32 = 1500;
/// The guest's setup line (time, user, home) and the host's wait for the guest to finish it.
pub const vm_setup_timeout_ms: u32 = 20_000;

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
    assert(limit_pids_max + scope_keeper_tasks > limit_pids_max); // Cannot overflow a u32.
    assert(scope_keeper_tasks == 1);
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
    // A diagnostic carried through a pipe: every item at its bound, the longest line framing.
    const carry_items = diag_causes_count_max + diag_whiles_count_max;
    const carry_text = carry_items * (diag_field_bytes_max + 3) +
        diag_context_count_max * (diag_key_bytes_max + diag_field_bytes_max + 4) +
        diag_fixes_count_max * (diag_field_bytes_max + diag_command_bytes_max + 8) + 16;
    assert(carry_text <= diag_carry_bytes_max);
    assert(diag_skip_depth_max > 0);
    assert(diag_skip_depth_max <= 16); // The skipper's stack is this many bytes.
    assert(diag_skip_bytes_max > 0);
    // Unknown members cannot be most of a line.
    assert(diag_skip_bytes_max * 2 <= diag_wire_bytes_max);

    // A page holds the stylesheet (under 6 KiB), one explanation with every character escaped
    // to at most six bytes, and room for the index's table row per code.
    assert(6 * 1024 + 6 * diag_explanation_bytes_max + 2048 <= errors_page_bytes_max);
    assert(diag_code_bytes < 16); // A page name ("E0101.html") fits the 16-byte buffers.

    // Logs: a record and its header fit the window the reader reads in, two files make the cap,
    // and a file holds a header and at least one largest record.
    assert(log_header_bytes + log_record_header_bytes + log_record_bytes_max <= log_read_bytes);
    assert(2 * @as(u64, log_segment_bytes_max) <= log_bytes_max);
    const smallest_file = log_header_bytes + log_record_header_bytes + log_record_bytes_max;
    assert(log_segment_bytes_max >= smallest_file);
    assert(log_record_bytes_max <= std.math.maxInt(u16));
    assert(log_time_max == 1 << 40); // Five bytes hold a time below it.
    assert(log_pump_bytes <= output_bytes_max);
    assert(log_read_bytes <= store_io_buffer_bytes);
    assert(std.mem.indexOfScalar(u8, log_suffix, '.') == 0);
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
    const derived_paths_max = 12 + container_devices_count + container_links_count;
    const candidates_bytes_max = (container_path_dirs_count + 1) * (command_word_bytes_max + 20);
    const paths_needed = derived_paths_max * (rootfs_bytes_max + 16) + candidates_bytes_max +
        2 * id_map_line_bytes_max + 2 * etc_file_bytes_max + 512 +
        pasta_path_bytes_max + state_path_bytes_max + 80 + 2;
    // Each state volume: its name, its target twice, its data directory, and a stage path below
    // the rootfs and one below /dev, each with its NUL.
    const state_paths = state_volumes_max * (state_name_bytes_max + 2 * state_target_bytes_max +
        state_volume_path_bytes_max + rootfs_bytes_max + 2 * 20 + 6);
    assert(paths_needed + state_paths <= plan_paths_bytes_max);
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
    assert(sim_processes_max >= 6); // zbx, a container, its keeper, pasta, exec's two.
    assert(sim_pipe_ends_max >= 4);
    assert(sim_written_files_max > runs_max + 4); // Every record, a temporary one, and slack.
    assert(sim_written_bytes_max > 1024);

    assert(publish_count_max > 0);
    assert(run_env_count_max > 0);
    assert(run_env_count_max <= env_vars_count_max / 2); // Room for the image's own variables.
    assert(2 * run_env_count_max + 16 <= args_count_max);
    assert(env_name_bytes_max < arg_bytes_max);
    assert(publish_count_max < 1024); // A forward per port number would be absurd, not useful.
    assert(pasta_argv_words_max >= 20 + 2 * publish_count_max + 1);
    // Eleven bytes per forward ("65535:65535"), a NUL and "-t" with its NUL.
    assert(pasta_argv_bytes_max >= 400 + publish_count_max * (11 + 1 + 3));
    assert(pasta_ready_line_bytes_max >= "4294967295\n".len);
    assert(pasta_ready_timeout_ms <= wait_timeout_ms_max);
    assert(pasta_log_tail_bytes_max <= file_bytes_max);
    // The logs directory is never listed, so a log's name may be longer than a listed one;
    // its path fits the room a run keeps for it (`Handle.pasta_log`).
    assert(state_path_bytes_max + 1 + container_name_bytes_max + pasta_log_suffix.len <=
        state_path_bytes_max + 80);
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

    assert(state_name_bytes_max <= container_name_bytes_max);
    assert(state_volumes_max > 0);
    assert(state_volumes_max <= 16);
    assert(state_target_bytes_max <= path_bytes_max / 4);
    assert(state_value_bytes_max <= arg_bytes_max);
    assert(state_record_bytes_max >= 4 * (state_name_bytes_max + container_name_bytes_max +
        state_target_bytes_max) + 512); // Every string escaped to four bytes, and the rest.
    assert(state_time_max > 4_000_000_000); // Past 2106: a u32 of seconds would not do.
    assert(state_volume_path_bytes_max + state_target_bytes_max <= path_bytes_max);
    // The data directory, "/zbx/state/.trash/", a name, "@" and 20 digits, "/data/", and a
    // temporary file's name.
    assert(state_volume_path_bytes_max >= store_data_base_bytes_max + 18 +
        state_name_bytes_max + 21 + 6 + 64);
    assert(state_lock_wait_ms % store_lock_retry_ms == 0);
    assert(state_walk_arena_bytes >= (store_depth_max + 1) * (store_name_bytes_max + 1) * 4);
    assert(state_walk_links_max > 0);
    assert(state_holders_max > 0);
    // A plan with every volume: each has seven steps, eight when read-only; and every other
    // mount, at most six (plan.zig).
    assert(80 + state_volumes_max * 8 + mounts_max * 6 <= plan_steps_max);
    assert(plan_steps_max <= std.math.maxInt(u8));
    // The stage names end in one digit; a mount's value and options fit their buffers.
    assert(mounts_max <= 10);
    assert(mount_path_bytes_max == state_target_bytes_max);
    assert(mount_value_bytes_max <= arg_bytes_max);
    assert(tmpfs_mount_bytes_min < tmpfs_mount_bytes_default);
    assert(tmpfs_mount_bytes_default <= tmpfs_mount_bytes_max);
    assert(secret_bytes_max <= file_bytes_max);
    assert(std.fmt.comptimePrint("mode=1777,size={d}", .{tmpfs_mount_bytes_max}).len <=
        tmpfs_options_bytes_max);
    assert(state_export_buffer_bytes >= 8 * 512);
    assert(state_export_links_bytes >= 2 * path_bytes_max);

    assert(oci_digest_hex_bytes == oci_digest_bytes * 2);
    assert(oci_digest_text_bytes == "sha256:".len + oci_digest_hex_bytes);
    assert(reference_registry_bytes_max + 1 + reference_repository_bytes_max +
        1 + reference_tag_bytes_max + 1 + oci_digest_text_bytes <= reference_bytes_max);
    assert(reference_bytes_max <= arg_bytes_max);
    assert(registry_token_bytes_max < registry_token_response_bytes_max);
    assert(registry_challenge_bytes_max + 1024 < registry_head_bytes_max);
    assert(registry_url_bytes_max < registry_head_bytes_max);
    // A request head holds the longest path, a token as a bearer header, and the fixed headers.
    assert(registry_url_bytes_max + registry_token_bytes_max + 1024 <=
        registry_request_head_bytes_max);
    assert(registry_manifest_bytes_max <= 4 * 1024 * 1024);
    assert(registry_json_arena_bytes < registry_manifest_bytes_max);
    assert(registry_redirects_max > 0);
    assert(net_idle_timeout_ms < net_request_timeout_ms);
    assert(net_addresses_max > 0);
    assert(registry_layers_max * 160 + 2048 <= pull_output_bytes_max);
    // The last record of a report (a failure or a result) always fits, after the warnings.
    assert(pull_report_header_bytes + diag_carry_bytes_max < pull_report_bytes_max);
    assert(pull_report_header_bytes + pull_report_result_bytes <=
        pull_report_header_bytes + diag_carry_bytes_max);
    assert(pull_report_warnings_bytes_max + pull_report_header_bytes + diag_carry_bytes_max ==
        pull_report_bytes_max);
    // The parent asks the kernel for a pipe this big and refuses the pull if it gets less.
    assert(pull_report_bytes_max <= pipe_capacity_bytes_max);
    assert(pull_report_warnings_bytes_max >= 4096);
    assert(diag_carry_bytes_max <= std.math.maxInt(u16));
    assert(image_tags_max > 0);
    // A record holds the tags escaped, 128 layer lines of 90 bytes and the settings escaped.
    assert(image_tags_max * (reference_bytes_max * 4 + 16) + registry_layers_max * 90 +
        image_settings_bytes_max * 4 + 2048 <= image_record_bytes_max);

    assert(fuzz_iterations_default > 0);
    assert(fuzz_iterations_default <= fuzz_iterations_max);
    assert(fuzz_check_iterations <= fuzz_iterations_default);

    assert(vm_cpus_min <= vm_cpus_default);
    assert(vm_cpus_default <= vm_cpus_max);
    assert(vm_memory_bytes_min <= vm_memory_bytes_default);
    assert(vm_memory_bytes_default <= vm_memory_bytes_max);
    assert(vm_disk_bytes_min <= vm_disk_bytes_default);
    assert(vm_disk_bytes_default <= vm_disk_bytes_max);
    assert(vm_disk_bytes_min % (1 << 20) == 0);
    assert(vm_disk_bytes_max % (1 << 20) == 0);
    assert(vm_disk_full_bytes < vm_disk_bytes_min);
    assert(vm_memory_bytes_max % (1 << 20) == 0); // Whole MiB: the framework counts in them.
    assert(vm_memory_bytes_min % (1 << 20) == 0);
    assert(vm_poll_step_ms < vm_control_timeout_ms);
    assert(vm_stop_timeout_ms < vm_boot_timeout_ms);
    assert(vm_boot_timeout_ms % vm_poll_step_ms == 0);
    assert(vm_stop_timeout_ms % vm_poll_step_ms == 0);
    assert(vm_control_timeout_ms % vm_poll_step_ms == 0);
    assert(vm_idle_timeout_ms > vm_boot_timeout_ms);
    assert(vm_socket_path_bytes_max < vm_path_bytes_max);
    assert(vm_guest_port > 0);
    assert(forward_header_bytes + forward_data_bytes_max <= forward_frame_bytes_max);
    assert(forward_start_bytes_max < forward_frame_bytes_max);
    assert(forward_env_count_max * (env_name_bytes_max + 1 + env_value_bytes_max) >=
        env_value_bytes_max);
    assert(vm_forward_port != vm_guest_port);
    assert(vm_ports_port != vm_forward_port);
    assert(vm_ports_port != vm_guest_port);
    assert(vm_ports_max >= publish_count_max);
    assert(vm_relay_buffer_bytes >= 4096);
    assert(vm_subid_start + vm_subid_count > vm_subid_start);
    assert(vm_hangup_grace_ms < vm_stop_timeout_ms);
    assert(vm_idle_check_ms % vm_poll_step_ms == 0);
    assert(vm_dhcp_packet_bytes_max >= 576); // The least an IP host must accept.
    assert(vm_setup_timeout_ms < vm_boot_timeout_ms);
    assert(vm_idle_timeout_ms_min < vm_idle_timeout_ms);
    assert(vm_idle_timeout_ms <= vm_idle_timeout_ms_max);
    assert(vm_idle_timeout_ms_min >= vm_idle_check_ms / 2);
    assert(vm_user_name_bytes_max + vm_home_bytes_max + 64 <= vm_line_bytes_max);
}
