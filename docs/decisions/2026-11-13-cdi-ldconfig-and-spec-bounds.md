# CDI: ldconfig deadline and spec bounds

Date: 2026-11-13. Context: re-review of PR 130 (M10 slice 2). Approved by the supervisor.

- **Approved bounds.** The `ldconfig` deadline `cdi_ldconfig_seconds_max` is 10 seconds. A run
  reads at most 64 CDI spec files in all (`cdi_dir_entries_max`), each at most 64 KiB minus one
  byte (`cdi_spec_bytes_max`). Both are set as they are in the code.
- **Where the deadline lives.** In the waiter, not in the program. `run_helper` puts the helper in
  its own process group, polls the output pipe with the deadline, and at expiry sends SIGKILL to
  the group and to the helper, closes the pipe and reaps it. The alarm inside the helper stays as
  a second bound, but nothing relies on it: a program that ignores SIGALRM, or leaves a process
  holding the pipe, ends at the deadline all the same. A killed `ldconfig` is a failed one: W0208
  and the `LD_LIBRARY_PATH` fallback.
- **Not covered.** A background process that moved to its own session or group survives the kill;
  it no longer holds the waiter, which has closed the pipe, and ends with the container.
- **Join.** An empty `LD_LIBRARY_PATH` value is replaced by the CDI directories, with no trailing
  `:` (it would search the working directory); the too-long branch is an assert, as each
  environment value is bounded by `env_value_bytes_max`.
