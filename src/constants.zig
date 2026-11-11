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
// this; the index lists every code and outgrew 32 KiB with M6c. The bound is what the tool's
// buffers and file reads use.
pub const errors_page_bytes_max: u32 = 64 * 1024;
/// One row of the index (link, summary, blame), and the stylesheet and head every page carries.
/// `errors_site.zig` asserts at compile time that the registry's rows fit in a page, so the next
/// milestone's codes fail the build there, not in the tool's run.
pub const errors_index_row_bytes_max: u32 = 256;
pub const errors_index_head_bytes_max: u32 = 6 * 1024;

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
// The listener handoff (M8b, docs/briefs/M8b-listen.md).

/// A container has at most one listener handed out (`--listen`).
pub const listen_count_max: u32 = 1;
/// The backlog of that listener: connections the kernel queues for an accept the holder has not
/// made yet. The workload is one process on the loopback, so a short queue is enough.
pub const listen_backlog: u32 = 16;
/// The listener's address is IPv4 loopback, in text, as `--listen` takes it ("127.0.0.1:65535").
pub const listen_text_bytes_max: u32 = 15;
/// The simulator's room for listeners made in one world.
pub const sim_listeners_max: u32 = 4;
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
pub const record_version: u32 = 10;
/// What a record without a listener is written as: a run that never asked for `--listen` leaves
/// the same bytes it did before version 10 (which only added `.listen`).
pub const record_version_plain: u32 = 9;
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
/// Every file of the store, and every entry of a materialized tree, is stamped with this
/// modification time, `SOURCE_DATE_EPOCH` (1980-01-01T00:00:00Z, the earliest time `zip`
/// stores), so a farm does not depend on when it was imported and a build step sees no host
/// time. Zero is avoided: some tools treat the epoch as "no time". Releases up to 0.2.0 stamped
/// 2000-01-01; a farm built since repairs the objects it links.
pub const store_mtime_seconds: u64 = build_source_date_epoch;
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
/// Room for the names `listxattr` returns for one file: more than 16 names of 255 bytes.
pub const store_xattr_names_bytes_max: u32 = 8192;
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
pub const sim_fs_pool_bytes_max: u32 = 3 * 1024 * 1024;
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
/// Extra request headers a call may carry (the AWS calls: a signature, a date, a target, a
/// session token, the instance metadata token), and the room one header's value gets (a session
/// token is the longest).
pub const net_extra_headers_max: u32 = 8;
pub const net_header_value_bytes_max: u32 = 8 * 1024;

// ---- AWS (M6c): credentials, SigV4, ECR ----------------------------------------------------
/// An access key id (AWS says 16 to 128 characters), a secret access key, a session token (they
/// run to a few KiB), and the account digits of an ECR registry host.
pub const aws_key_id_bytes_max: u32 = 128;
pub const aws_secret_key_bytes_max: u32 = 128;
pub const aws_session_token_bytes_max: u32 = 8 * 1024;
pub const aws_account_digits: u32 = 12;
/// The longest ECR registry host: 12 digits, `.dkr.ecr.`, a region and `.amazonaws.com`.
pub const aws_ecr_host_bytes_max: u32 = 64;
/// A region name (`ap-southeast-4`), a role ARN, a role session name (STS allows 2 to 64), and
/// the service name a signature is scoped to.
pub const aws_region_bytes_max: u32 = 24;
pub const aws_service_bytes_max: u32 = 16;
pub const aws_role_arn_bytes_max: u32 = 2048;
pub const aws_role_session_name_bytes_max: u32 = 64;
/// The web identity token file (STS takes up to 20000 characters; a JWT from GitHub or EKS is
/// 1 to 2 KiB), and the form body that carries it to STS.
pub const aws_web_identity_token_bytes_max: u32 = 16 * 1024;
pub const aws_request_body_bytes_max: u32 = 32 * 1024;
/// What STS, IMDS or ECR answers: a credentials document is 1 to 4 KiB, an error a few hundred
/// bytes.
pub const aws_response_bytes_max: u32 = 24 * 1024;
/// The ECR `authorizationToken` (base64 of `AWS:` and a password about 1.1 KiB long).
pub const aws_ecr_token_bytes_max: u32 = 4 * 1024;
/// IMDS: how long a wait for the link-local address may take (a host off EC2 must not be
/// slowed), the whole exchange, the session token's lifetime we ask for, the token it returns,
/// and a role name.
pub const aws_imds_timeout_ms: u32 = 1_000;
pub const aws_imds_total_timeout_ms: u32 = 3_000;
pub const aws_imds_token_ttl_s: u32 = 60;
pub const aws_imds_token_bytes_max: u32 = 256;
pub const aws_role_name_bytes_max: u32 = 128;
/// Credentials that expire within this many seconds are refused as already expired.
pub const aws_credentials_margin_s: u32 = 60;
/// SigV4: the canonical request, the headers a signature covers, and the `Authorization` value.
pub const aws_canonical_bytes_max: u32 = 16 * 1024;
/// The most query parameters a signed target may carry.
pub const aws_query_params_max = 16;
pub const aws_signed_headers_max: u32 = 12;
pub const aws_authorization_bytes_max: u32 = 1024;
/// An AWS error's code name (`AccessDeniedException`), the only part of an error response a
/// diagnostic may carry.
pub const aws_error_code_bytes_max: u32 = 64;
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
/// The labels an image record keeps, so that the result a pushed image was made from can be
/// derived again (M8 slice 14): the bytes of all keys and values together, and the labels. An
/// image with more keeps none, and says so (`.labels_unknown`); it is never refused for them.
pub const image_labels_bytes_max: u32 = 2 * 1024;
pub const image_labels_count_max: u32 = 32;
/// The tags an image record keeps: every reference the image was pulled as. When it is full, the
/// oldest goes.
pub const image_tags_max: u32 = 8;
pub const images_max: u32 = 4096;
/// Subtrees waiting on the stack of the walk that checks an image from a peer is complete
/// (`store/image_peer.zig`); a tree with more directories pending than this is refused. It is
/// the stack gc walks with (1 MiB of 32-byte ids), so a tree that a pull or gc accepts is not
/// refused here: one directory holds `store_dir_entries_max` entries, and the walk pushes all
/// the directories of a tree it has popped, so the stack needs more than twice that.
pub const image_import_stack_max: u32 = 32768;
/// `zbx.lock` (`lock_file.zig`): the entries it holds, the bytes of their references together,
/// and the largest file read or written.
pub const lock_entries_max: u32 = 256;
pub const lock_pool_bytes: u32 = 64 * 1024;
pub const lock_file_bytes_max: u32 = 160 * 1024;
/// The buffer a blob is hashed and copied through.
pub const blob_io_bytes: u32 = 64 * 1024;
/// How many hosts one name may resolve to that are tried.
pub const net_addresses_max: u32 = 8;

// Build files (M7 slice 1, docs/briefs/M7-build.md): `zbx.build.zon`, read by
// `src/build/file.zig`. Every list a file can hold has a bound here, and the parser refuses a
// file past one with its line and column.
/// The largest build file read. Its canonical rendering can be longer (indentation), so the
/// parser itself accepts up to `build_render_bytes_max`.
pub const build_file_bytes_max: u32 = 64 * 1024;
/// The decoded bytes of every string in one file together.
pub const build_pool_bytes: u32 = 64 * 1024;
/// One string: an argv entry, an env entry, a path, a reference.
pub const build_string_bytes_max: u32 = 4096;
pub const build_steps_max: u32 = 64;
/// A step's name: `[a-z0-9-]`, as a directory name under `/in` and in the report's column.
pub const build_step_name_bytes_max: u32 = 32;
/// The longest `--verbose` prefix: a step's name and ` | `.
pub const stream_prefix_bytes_max: u32 = build_step_name_bytes_max + 3;
/// The most one streamed write carries: the prefix, a line or a piece of one, and its newline.
/// It is also the size of each stream's line buffer. At most the kernel's `PIPE_BUF`, so that a
/// write to a pipe is never split and two steps' lines never mix inside a line.
pub const stream_write_bytes_max: u32 = 1024;
/// `PIPE_BUF` on Linux: the largest write to a pipe the kernel keeps whole.
pub const pipe_buf_bytes: u32 = 4096;
pub const build_step_inputs_max: u32 = 64;
/// Each needed step is a read-only mount at `/in/<name>`; with `/src` and `/out` that is two
/// fewer than a run's mounts (`mounts_max`).
pub const build_step_needs_max: u32 = 6;
pub const build_step_argv_max: u32 = 64;
pub const build_step_env_max: u32 = 32;
/// Steps that run at once: fixed at 4 (a cut from the brief, which also bounds it by the online
/// CPUs; nothing checks the CPUs yet, see docs/demos/m7.md).
pub const build_parallel_max: u32 = 4;
/// A step's limits (docs/briefs/M7-build.md, "What a step is"): a step that runs past the timeout
/// is ended (SIGTERM, then SIGKILL) and fails with E0805, as do one out of memory or PIDs. CPU is
/// not limited: a build step is meant to use the machine.
pub const build_step_timeout_ms: u32 = 30 * 60 * 1000;
pub const build_step_memory_bytes: u64 = 1 << 30;
pub const build_step_pids: u32 = 1024;
/// `image.add`: step outputs spliced into the result.
pub const build_image_adds_max: u32 = 32;
/// `image.config`: `entrypoint` and `cmd` entries, `env` entries, and `labels`.
pub const build_config_argv_max: u32 = 64;
pub const build_config_env_max: u32 = 64;
pub const build_config_labels_max: u32 = 32;
/// A label's key: `[a-z0-9._/-]`.
pub const build_label_key_bytes_max: u32 = 128;
/// How much of a refused value a build file problem keeps, to name it.
pub const build_problem_word_bytes_max: u32 = 64;
/// The decimal digits of `.version`.
pub const build_version_digits_max: u32 = 4;
/// Bumped when what a step means changes (its mounts, its fixed environment, how its output is
/// imported), so that no cache entry of the old meaning is a hit. A zbx patch release keeps it,
/// and with it the cache.
pub const build_step_format_version: u32 = 1;
/// `SOURCE_DATE_EPOCH` for every step, 1980-01-01T00:00:00Z: the earliest time `zip` stores.
/// Every file a step sees carries it as its mtime (`store_mtime_seconds`).
pub const build_source_date_epoch: u64 = 315_532_800;
/// A key's preimage (`build/key.zig`): one step's strings are at most the file's pool, its
/// base's env at most an image's settings, and the rest (digests, needs, the fixed environment,
/// the length prefixes) fits in the margin.
pub const build_key_preimage_bytes_max: u32 = build_pool_bytes + image_settings_bytes_max +
    16 * 1024;
/// A build result record (`build/result.zig`): the tree digest and the resolved config in their
/// canonical encoding. Its strings come from the build file's pool and the base image's
/// settings; the rest (the magic, counts, digests, length prefixes) fits in the margin.
pub const build_result_bytes_max: u32 = build_pool_bytes + image_settings_bytes_max + 16 * 1024;
/// The bytes of a result's labels (keys and values, together): the pool bound, since they come
/// from the build file.
pub const build_result_label_bytes_max: u32 = build_pool_bytes;
/// The room `zbx inspect` gathers a result's config in: every byte of the settings and labels
/// escaped to six, and the fixed text around them.
pub const inspect_output_bytes_max: u32 =
    (image_settings_bytes_max + build_result_label_bytes_max) * 6 + 4096;
/// The room `zbx inspect --provenance` renders a record in, as text or as `zbx.provenance/1`:
/// each says again what the payload says, once, with names written as the payload writes them,
/// and adds a label to each member, so twice the payload's bound holds either
/// (`provenance_view.zig` checks the worst record against it).
pub const inspect_provenance_bytes_max: u32 = 2 * statement_bytes_max;
/// Directories two trees of an assembly may have in common at one level (`build/assemble.zig`);
/// past this a merge is refused rather than grow without bound.
pub const build_merge_common_max: u32 = 256;
/// A build cache entry (`build/cache.zig`): its fixed fields and a key's preimage.
pub const build_cache_entry_bytes_max: u32 = 64 + build_key_preimage_bytes_max;
/// The entries in `build/cache/` that gc follows. Each names a tree that gc keeps, so past this
/// gc refuses (naming the limit) rather than free a tree an entry might still name.
pub const build_cache_entries_max: u32 = 8192;
/// The strings one file can hold, from the bounds above.
pub const build_strings_max: u32 = 2 + build_steps_max *
    (2 + build_step_inputs_max + build_step_needs_max + build_step_argv_max +
        build_step_env_max) + 2 * build_image_adds_max + 2 * build_config_argv_max +
    build_config_env_max + 2 * build_config_labels_max + 2;
/// The canonical rendering of the largest file the parser accepts: every string escaped four
/// bytes a byte with its quotes and separator, and the fixed text of every field and step.
pub const build_render_bytes_max: u32 = 4 * build_pool_bytes + 8 * build_strings_max +
    build_steps_max * 256 + build_image_adds_max * 64 + build_config_labels_max * 32 + 1024;

comptime {
    assert(build_result_bytes_max < store_tree_bytes_max);
    assert(image_import_stack_max <= store_arena_bytes_max / 2 / 32); // A stack of 32-byte ids.
    assert(image_import_stack_max >= 2 * store_dir_entries_max);
    assert(build_result_label_bytes_max <= build_pool_bytes);
    assert(build_merge_common_max <= store_dir_entries_max);
    assert(build_cache_entry_bytes_max < store_tree_bytes_max);
    assert(build_cache_entry_bytes_max < store_arena_bytes_max);
    assert(build_cache_entries_max > build_steps_max);
    // `/src`, `/out` and every needed step's `/in/<name>` are a run's mounts.
    assert(build_step_needs_max + 2 <= mounts_max);
    assert(build_step_needs_max < build_steps_max);
    assert(build_image_adds_max <= build_steps_max);
    // An input is a path: a string bound at least the path bound.
    assert(build_string_bytes_max >= path_bytes_max);
    assert(build_string_bytes_max <= build_pool_bytes);
    assert(build_step_name_bytes_max < build_string_bytes_max);
    // A streamed line holds the prefix, at least one byte of the line and its newline.
    assert(stream_prefix_bytes_max + 2 <= stream_write_bytes_max);
    assert(stream_write_bytes_max <= pipe_buf_bytes);
    assert(build_label_key_bytes_max < build_string_bytes_max);
    // The parser reads its own rendering back, so the file bound is the smaller.
    assert(build_file_bytes_max < build_render_bytes_max);
    assert(build_pool_bytes <= build_render_bytes_max);
    // A u32 offset holds any position in the rendering.
    assert(build_render_bytes_max < std.math.maxInt(u32));
    assert(build_problem_word_bytes_max <= std.math.maxInt(u8));
    assert(build_problem_word_bytes_max > build_step_name_bytes_max);
}

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
        diag_fixes_count_max * (diag_field_bytes_max + diag_command_bytes_max + 8) +
        diag_summary_bytes_max + 3 + 16;
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
    assert(listen_count_max == 1);
    assert(listen_backlog > 0);
    assert(listen_text_bytes_max == "127.0.0.1:65535".len);
    assert(sim_listeners_max > listen_count_max);
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
    assert(record_version_plain + 1 == record_version);
    assert(bundle_stage_bytes_max + 16 * 1024 <= bundle_gz_bytes_max);
    assert(bundle_gz_bytes_max <= write_bytes_max);
    assert(bundle_file_bytes_max * 2 < bundle_stage_bytes_max);
    assert(bundle_files_max * 1024 < bundle_stage_bytes_max); // The tar headers.
    assert(diag_json_bytes_max * 4 < record_bytes_max / 2); // Fully escaped, in the record.
    assert(secret_value_bytes_min < secret_value_bytes_max);
    assert(bundle_secrets_max * secret_value_bytes_max < bundle_file_bytes_max);
    assert(bundle_name_bytes_max < dir_name_bytes_max + 32);

    assert(store_digest_hex_bytes == store_digest_bytes * 2);
    assert(store_xattr_names_bytes_max >= store_xattrs_max * (store_xattr_name_bytes_max + 1));
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
    assert(net_extra_headers_max > 0);
    // A request head holds a session token, a signature, the longest path and the fixed headers.
    assert(net_header_value_bytes_max + aws_authorization_bytes_max + registry_url_bytes_max +
        2048 <= registry_request_head_bytes_max);
    assert(aws_session_token_bytes_max <= net_header_value_bytes_max);
    assert(aws_authorization_bytes_max <= net_header_value_bytes_max);
    assert(aws_account_digits == 12);
    assert(aws_session_token_bytes_max * 2 <= aws_response_bytes_max);
    assert(aws_ecr_token_bytes_max * 2 <= aws_response_bytes_max);
    assert(aws_response_bytes_max <= registry_token_response_bytes_max);
    // The form that asks STS for credentials: the token file, a role ARN and a session name with
    // every byte escaped, and the fixed words.
    assert(aws_web_identity_token_bytes_max + aws_role_arn_bytes_max * 3 +
        aws_role_session_name_bytes_max * 3 + 256 <= aws_request_body_bytes_max);
    assert(aws_request_body_bytes_max <= push_chunk_bytes);
    assert(aws_imds_timeout_ms < aws_imds_total_timeout_ms);
    assert(aws_imds_total_timeout_ms < net_idle_timeout_ms);
    assert(aws_imds_token_bytes_max <= net_header_value_bytes_max);
    assert(aws_canonical_bytes_max >= aws_signed_headers_max * 128 + registry_url_bytes_max);
    // The `Authorization` value: the scheme, the credential scope, the header list, 64 hex.
    assert(aws_authorization_bytes_max >= 64 + aws_key_id_bytes_max + 80 +
        aws_region_bytes_max + aws_service_bytes_max + aws_signed_headers_max * 24);
    assert(aws_region_bytes_max + 16 <= 253);
    assert(aws_account_digits + 9 + aws_region_bytes_max + 14 <= aws_ecr_host_bytes_max);
    assert(aws_error_code_bytes_max < aws_response_bytes_max);
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
    // And its labels: two lines a label, each key and value escaped four bytes a byte.
    assert(image_tags_max * (reference_bytes_max * 4 + 16) + registry_layers_max * 90 +
        image_settings_bytes_max * 4 + image_labels_bytes_max * 4 +
        image_labels_count_max * 40 + 2048 <= image_record_bytes_max);
    // A label of a result is a label of an image only while both bounds agree on the count.
    assert(image_labels_count_max == build_config_labels_max);
    assert(image_labels_bytes_max <= build_result_label_bytes_max);

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

comptime {
    assert(build_step_memory_bytes >= limit_memory_bytes_min);
    assert(build_step_memory_bytes <= limit_memory_bytes_max);
    assert(build_step_pids >= limit_pids_min);
    assert(build_step_pids <= limit_pids_max);
    assert(build_step_timeout_ms > 0);
}

// ---- Packages (M8, slice 6): the `zigbox_package` module and `zig build packages` ----

/// The most files (directories included) one package holds. `zbx` and its licence need three; the
/// Zigcube omnibus of C3 needs a few more.
pub const package_files_max: u32 = 64;
/// A package path is a tar name without a prefix field: at most 99 bytes and a terminator.
pub const package_path_bytes_max: u32 = 99;
/// The largest file in a package: a static `zbx` is under 4 MiB (`release_size_limit`).
pub const package_file_bytes_max: u32 = 64 * 1024 * 1024;
/// The largest package payload, uncompressed. One rpm header field (ARCHIVESIZE) holds it as a
/// 32-bit integer, so the bound sits well under 2^31.
pub const package_payload_bytes_max: u32 = 256 * 1024 * 1024;
/// The most weak dependencies (`Recommends`) a package names.
pub const package_recommends_max: u32 = 8;
/// A package's name, version and architecture strings, a dependency name, and its one-line text.
pub const package_name_bytes_max: u32 = 64;
pub const package_summary_bytes_max: u32 = 200;
/// The long description and the licence text.
pub const package_description_bytes_max: u32 = 4096;
/// The most packages one repository holds (two architectures of a few packages).
pub const repo_packages_max: u32 = 32;
/// The most files `zig build packages` writes under `zig-out/packages/`.
pub const repo_files_max: u32 = 256;
/// A repository metadata file (`Packages`, `primary.xml`): at most this, uncompressed.
pub const repo_metadata_bytes_max: u32 = 4 * 1024 * 1024;
/// The deflate window and output buffer sizes the gzip writer needs (std: `flate.max_window_len`).
pub const package_gzip_window_bytes: u32 = 64 * 1024;
/// An rpm header: its index entries and data store. A signature header is far smaller.
pub const rpm_header_entries_max: u32 = 128;
pub const rpm_header_bytes_max: u32 = 1024 * 1024;
/// The most OpenPGP signature bytes one detached signature or rpm signature tag holds.
pub const openpgp_signature_bytes_max: u32 = 1024;
/// An ASCII-armored block's line width (RFC 4880: at most 76).
pub const armor_line_bytes: u32 = 64;
/// `SOURCE_DATE_EPOCH` for every package: the same instant as a build step's, so the package of a
/// commit and the store it was built beside agree.
pub const package_source_date_epoch: u64 = build_source_date_epoch;
/// The `Maintainer` of the `zigbox` packages. A supervisor assumption the owner may change
/// (docs/decisions/2026-11-08-package-bounds.md).
pub const package_maintainer = "Zigbox project <packages@zigbox.org>";
/// The release of the fixed test key (the package writer's own signer; vouches for nothing).
pub const package_test_key_user_id =
    "Zigbox package test key (vouches for nothing) <test@zigbox.invalid>";

comptime {
    assert(package_path_bytes_max < 100); // A ustar name field is 100 bytes with its terminator.
    assert(package_payload_bytes_max <= std.math.maxInt(i32));
    assert(package_file_bytes_max <= package_payload_bytes_max);
    assert(package_gzip_window_bytes >= std.compress.flate.max_window_len);
    assert(armor_line_bytes % 4 == 0); // Base64 lines break on whole groups.
    assert(armor_line_bytes <= 76);
    assert(package_files_max <= rpm_header_entries_max);
    assert(package_recommends_max < rpm_header_entries_max);
    assert(repo_packages_max * 2 <= repo_files_max);
}

// ---- Keys (M8 trust) ----

/// A key's name: `[a-z0-9-]`, at most this many bytes.
pub const key_name_bytes_max: u32 = 32;
/// argon2id's defaults for a new key (cost measured in `docs/demos/m8.md`): passes, memory in
/// KiB, and lanes. One lane, so argon2 runs on one thread.
pub const key_kdf_t: u32 = 3;
pub const key_kdf_m_kib: u32 = 65536;
pub const key_kdf_p: u32 = 1;
/// What parse accepts from a key file, so that a hostile file cannot make `sign` allocate or
/// loop without bound: `t` at most 6 and memory at most 128 MiB (see
/// `docs/decisions/2026-11-08-m8-kdf-maxima-tightened.md`). `p` is fixed at one (a second lane
/// would need threads, and zbx's namespace-free parent runs argon2 on its own thread).
pub const key_kdf_t_max: u32 = 6;
pub const key_kdf_m_kib_max: u32 = 131072;
pub const key_kdf_p_max: u32 = 1;
/// Random bytes in the name of a key's temporary file, so that two `key new` of one name never
/// share a temporary (hex in the name: twice this many characters).
pub const key_temp_random_bytes: u32 = 8;
/// How long a key file or temporary must have sat before `key new` calls it a leftover of a
/// killed run (and removes it, or says it can be removed) instead of a live run's work.
pub const key_leftover_age_seconds: u32 = 600;
/// Most leftover temporaries one `key new` removes.
pub const key_sweep_max: u32 = 32;
pub const key_seed_bytes: u32 = 32;
pub const key_public_bytes: u32 = 32;
pub const key_salt_bytes: u32 = 16;
pub const key_nonce_bytes: u32 = 24;
pub const key_tag_bytes: u32 = 16;
pub const key_sealed_bytes: u32 = key_seed_bytes + key_tag_bytes;
/// `zbx-ed25519:` and 64 hex digits.
pub const key_public_text_bytes: u32 = 12 + 2 * key_public_bytes;
/// A key's id: BLAKE3, 32 bytes, 64 hex digits.
pub const key_id_text_bytes: u32 = 64;
/// The key file and the `.pub` file are small records; this bounds what is read of either.
pub const key_file_bytes_max: u32 = 1024;
/// The first line of a passphrase file, or what a terminal read gives, without the newline.
pub const passphrase_bytes_max: u32 = 1024;
/// A passphrase file is read to this many bytes: the line, its newline, and some room for a
/// file that goes on (which is read no further).
pub const passphrase_file_bytes_max: u32 = passphrase_bytes_max + 1;
/// The most keys `key list` shows.
pub const keys_listed_max: u32 = 64;
/// Most containers open at once in the canonical JSON writer and reader (`src/trust/json.zig`).
/// A supervisor assumption (docs/decisions/2026-11-08-m8-trust-bounds.md).
pub const json_depth_max: u32 = 16;

// ---- Statements, envelopes and signature records (M8 trust, slice 2) ----
// The four numbers below are supervisor assumptions (docs/decisions/2026-11-08-m8-trust-bounds.md).

/// Most subjects in a statement: the tree, and optionally the binding (a result or a manifest).
pub const statement_subjects_max: u32 = 2;
/// Most bytes of a statement's payload: the longest provenance record (`provenance_bytes_max`,
/// from `provenance_steps_max` steps) rounded up to 64 KiB. Slice 2 had 128 KiB, a number made
/// before provenance existed (docs/decisions/2026-11-09-m8-statement-bytes-from-provenance.md).
pub const statement_bytes_max: u32 =
    (provenance_bytes_max + 64 * 1024 - 1) / (64 * 1024) * (64 * 1024);
/// Most envelopes (lines) in one tree's signature record. A ninth distinct one is `E0910`.
pub const signatures_per_tree_max: u32 = 8;
/// Most signature records (and, from slice 4, provenance records) in the store.
pub const trust_records_max: u32 = 4096;
/// Most records one `trust prune` scan keeps in its report: each of the two directories
/// (signatures, provenance) is read up to `trust_records_max` entries.
pub const trust_prune_entries_max: u32 = 2 * trust_records_max;
/// Most file objects one tree's `trust/verified` record holds (slice 3's tamper check): 56 bytes
/// each, so a record is under 4 MiB. A tree with more objects is checked whole on every run and
/// writes no record.
pub const trust_verified_entries_max: u32 = 65536;
/// The bytes of a `trust/verified` record: a 16-byte header and its entries.
pub const trust_verified_entry_bytes: u32 = 56;
pub const trust_verified_file_bytes_max: u32 =
    16 + trust_verified_entries_max * trust_verified_entry_bytes;
/// The one place our type URIs start (the owner's `2026-11-04-project-domain-zigbox-org.md`).
/// Once a signature has been made with a URI it is part of the format.
pub const type_uri_base = "https://zigbox.org";
pub const sign_predicate_path = "/attestation/sign/v1";
pub const sign_predicate_type = type_uri_base ++ sign_predicate_path;
/// The provenance predicate is SLSA's, so its type is not ours; its `buildType` is.
pub const provenance_predicate_type = "https://slsa.dev/provenance/v1";
pub const provenance_build_type = type_uri_base ++ "/build/v1";
pub const provenance_builder_id = type_uri_base ++ "/zbx";
/// Most steps a provenance record lists: every step of a build file.
pub const provenance_steps_max: u32 = build_steps_max;
/// Most distinct bases a record lists: one per step and the image's.
pub const provenance_bases_max: u32 = provenance_steps_max + 1;
/// The release a record names as its builder (`build_options.version`), at most this long.
pub const provenance_version_bytes_max: u32 = 64;
/// One step's JSON at its longest: fixed text and a key, a base index and four digests (about
/// 160 bytes), plus its name and its needs' names at six bytes a byte (`\u00xx`), and each
/// need's digest and separators.
pub const provenance_step_bytes_max: u32 = 160 + 3 * 64 +
    6 * build_step_name_bytes_max * (1 + build_step_needs_max) + build_step_needs_max * 72;
/// One base's JSON: its reference (a lock reference has nothing to escape) and two digests.
pub const provenance_base_bytes_max: u32 = 300 + reference_bytes_max;
/// The longest provenance record: its steps, its bases, the build file's path at six bytes a
/// byte, and the fixed text and image record around them.
pub const provenance_bytes_max: u32 = 2048 + provenance_steps_max * provenance_step_bytes_max +
    provenance_bases_max * provenance_base_bytes_max + 6 * path_bytes_max;
/// A sign statement's `signedAt` is RFC 3339 UTC to the second: `2026-11-08T10:00:00Z`.
pub const signed_at_text_bytes: u32 = 20;
/// The latest `signedAt` the form can write: 9999-12-31T23:59:59Z.
pub const signed_at_seconds_max: u64 = 253402300799;
/// The base64 of `statement_bytes_max` bytes, with padding.
pub const payload_base64_bytes_max: u32 = ((statement_bytes_max + 2) / 3) * 4;
/// Everything in an envelope that is not the payload's base64: the member names, the payload
/// type, one key id and one signature (checked against the longest rendering in `dsse.zig`).
pub const envelope_overhead_bytes: u32 = 512;
pub const envelope_bytes_max: u32 = payload_base64_bytes_max + envelope_overhead_bytes;
/// A signature record: at most `signatures_per_tree_max` envelopes, each with its newline.
pub const signature_record_bytes_max: u32 = signatures_per_tree_max * (envelope_bytes_max + 1);

comptime {
    assert(key_kdf_t >= 1);
    assert(key_kdf_t <= key_kdf_t_max);
    assert(key_kdf_m_kib >= 8 * key_kdf_p);
    assert(key_kdf_m_kib <= key_kdf_m_kib_max);
    assert(key_kdf_p >= 1);
    assert(key_kdf_p <= key_kdf_p_max);
    assert(key_kdf_p_max == 1);
    assert(json_depth_max >= 1);
    assert(json_depth_max <= 64); // The reader's frame stack lives on the stack.
    assert(statement_subjects_max == 2); // The tree, then at most one binding.
    assert(statement_bytes_max <= 1024 * 1024);
    assert(statement_bytes_max >= provenance_bytes_max); // Rounded up, never down.
    assert(statement_bytes_max < provenance_bytes_max + 64 * 1024);
    assert(provenance_steps_max == build_steps_max);
    assert(provenance_bases_max >= provenance_steps_max + 1);
    assert(provenance_bases_max <= lock_entries_max);
    assert(signatures_per_tree_max >= 1);
    assert(trust_records_max >= signatures_per_tree_max);
    assert(payload_base64_bytes_max >= statement_bytes_max);
    assert(payload_base64_bytes_max % 4 == 0);
    assert(envelope_bytes_max > payload_base64_bytes_max + envelope_overhead_bytes - 1);
    assert(signature_record_bytes_max >= envelope_bytes_max);
    assert(signature_record_bytes_max <= 4 * 1024 * 1024);
    assert(signed_at_text_bytes == "2026-11-08T10:00:00Z".len);
    assert(key_sealed_bytes == 48);
    assert(key_public_text_bytes == 76);
    assert(key_file_bytes_max >= 512); // Room for the longest rendering, checked in key.zig.
    assert(passphrase_bytes_max >= 64);
    assert(key_name_bytes_max <= 32);
}

// ---- Policy (M8 slice 3) ----

/// Keys one policy file may trust (docs/briefs/M8-trust.md, "The policy file").
pub const policy_keys_max: u32 = 16;
/// A policy file's size. Sixteen keys take about 2 KiB, so the rest is room for comments.
pub const policy_bytes_max: u32 = 16 * 1024;
/// The policy files: the system one, and the user one under the user's config directory.
pub const policy_system_path = "/etc/zbx/policy.zon";
pub const policy_user_suffix = "/zbx/policy.zon";
/// The policy files a run is checked against: the system file and the user file.
pub const policy_files_max: u32 = 2;

comptime {
    assert(policy_keys_max >= 1);
    assert(policy_keys_max * (key_name_bytes_max + key_public_text_bytes + 64) <
        policy_bytes_max);
    assert(policy_bytes_max <= build_render_bytes_max); // M7's lexer takes the text whole.
    assert(policy_files_max == 2);
    assert(policy_system_path.len < store_path_bytes_max);
}

// ---- Pack and export (lane U, docs/decisions/2026-11-08-push-in-m8.md) --------------------

/// The version of the layer writer: the tar form and the gzip stream a pack produces. The same
/// tree and config give the same bytes for one version. A change to either is a new version.
pub const layer_writer_version: u32 = 1;

/// Annotation keys of a packed manifest.
pub const pack_annotation_tree = "org.zigbox.tree";
pub const pack_annotation_writer = "org.zigbox.layer-writer";

/// The OCI media types a pack writes.
pub const oci_manifest_media_type = "application/vnd.oci.image.manifest.v1+json";
pub const oci_index_media_type = "application/vnd.oci.image.index.v1+json";
pub const oci_config_media_type = "application/vnd.oci.image.config.v1+json";
pub const oci_layer_media_type = "application/vnd.oci.image.layer.v1.tar+gzip";

/// The objects a pack tracks (every file's, once: the first name of each), to write later names
/// of the same object as hard links, and the room for those first paths. Past either, later names
/// of an object not tracked are written as ordinary files (the bytes are repeated, the result is
/// the same tree). So a tree of more than `pack_links_max` files, or with more than
/// `pack_link_paths_bytes` of paths, gets a different layer from the one a larger table would
/// give: these numbers are part of the layer writer version. The numbers are those of
/// `zbx state export`.
pub const pack_links_max: u32 = 16384;
pub const pack_link_paths_bytes: u32 = 1024 * 1024;

/// The most bytes of the config and of the manifest of a packed image.
pub const pack_config_bytes_max: u32 = 64 * 1024;
pub const pack_manifest_bytes_max: u32 = 4096;

/// The bytes the pack's file reads and compressed writes move at a time.
pub const pack_io_bytes: u32 = 256 * 1024;

/// The mode of the files an export writes (its directories take the process's umask).
pub const export_file_mode: u16 = 0o644;

// ---- Upload (lane U, slice 11) -------------------------------------------------------------

/// The bytes of one PATCH of a blob upload (owner, 2026-11-08). Also the most a request body
/// holds: the manifest (`pack_manifest_bytes_max`) is far below it.
pub const push_chunk_bytes: u32 = 8 * 1024 * 1024;

/// The most chunks of one blob: the loop's bound, 8 TiB at the chunk size above.
pub const push_chunks_max: u32 = 1 << 20;

/// The most bytes of a registry's error answer that are read (the JSON `errors` array).
pub const push_error_body_bytes: u32 = 4096;

/// The blobs of one packed image: its config and its layer, in the order they are pushed.
pub const push_blobs: u32 = 2;

/// The bytes of a push's username and password together (owner, 2026-11-10, slice 12). A registry
/// token is far longer and is not a credential the user types; 4 KiB holds any password.
pub const push_credential_bytes_max: u32 = 4096;

/// The bytes read from a password file or from standard input: the credential bound and a newline,
/// so a line at the bound is read whole and one past it is seen to be too long.
pub const push_password_read_bytes: u32 = push_credential_bytes_max + 2;

/// The memory a token response's JSON is read in: the response bound with room for the copies the
/// parser makes of its two token fields.
pub const push_token_arena_bytes: u32 = 2 * registry_token_response_bytes_max;

/// The `user:password` text and its base64 form, which is what `Authorization: Basic` carries.
pub const push_basic_bytes_max: u32 = (push_credential_bytes_max + 1 + 2) / 3 * 4;

comptime {
    assert(push_chunk_bytes >= pack_manifest_bytes_max);
    assert(push_chunk_bytes >= pack_io_bytes);
    assert(push_chunks_max > 0);
    assert(push_error_body_bytes < registry_manifest_bytes_max);
    assert(push_blobs == 2);
    assert(push_credential_bytes_max >= 256);
    assert(push_password_read_bytes > push_credential_bytes_max);
    assert(push_basic_bytes_max > push_credential_bytes_max);
    assert(aws_ecr_token_bytes_max <= push_basic_bytes_max);
    assert(push_credential_bytes_max < registry_token_bytes_max);
    assert(push_token_arena_bytes > registry_token_response_bytes_max);
    assert(pack_links_max > 0);
    assert(std.math.isPowerOfTwo(pack_links_max));
    assert(pack_link_paths_bytes >= path_bytes_max + 1);
    assert(pack_config_bytes_max >= image_settings_bytes_max);
    assert(layer_writer_version >= 1);
}
