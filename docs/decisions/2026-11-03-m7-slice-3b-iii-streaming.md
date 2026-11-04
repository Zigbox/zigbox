# M7 slice 3b-iii: `--verbose` streams to stderr, a line at a time

*Decided 2026-11-03, by the slice; revised the same day after review.*

With `--verbose`, `zbx build` copies each step's output to **stderr** as it is produced, every line behind the prefix `<step> | `. Stdout stays the report (or the JSON), so `zbx build --verbose --output json | jq` keeps working.

- **Whole lines only.** Steps run in parallel. Each of a step's two streams (stdout, stderr) has its own line buffer in the run's handle (`stream_write_bytes_max`, 1024 bytes, in `constants.zig`; comptime-asserted to be at most `PIPE_BUF`). Bytes wait there until the line ends; the log sink then writes the prefix, the line and its newline in one `write`, so two steps' lines never mix, and neither do the two streams of one step. A line too long for the buffer is written in pieces, each with the prefix and a newline of its own. A line still open when the step ends is written then, with a newline added.
- **Always pipe, not `mirror`.** The runtime's `mirror` mode leaves the terminal uncaptured; the build needs the bytes in the log file as well, for the last-lines-on-failure cause. The log sink therefore sees every byte and streams from there (`runtime/run.zig`, `StartOptions.stream_prefix`).
- **A closed stderr ends the streaming, not the build.** While the run waits, SIGPIPE is ignored whenever streaming (or `mirror`) is on. A write to stderr that fails, with EPIPE or anything else, stops the streaming for the rest of that step; the log keeps every byte and the build goes on.
- **A reader that stops reading stalls the build.** The writes are blocking. If whoever reads stderr stops reading (a paused pager, a full pipe), the step's output is not drained, and the step, then its timeout clock's checks, wait for it, as `make` does. Non-blocking writes with a bounded backlog were considered and not built.
- **Known limit: `ignore_broken_pipe` is process-wide.** It changes the process's SIGPIPE action, so two `run_step` callers on two threads of one process race on it (one's restore can undo the other's ignore). The CLI runs steps in forked workers, so it is not affected; a library caller with threads should ignore SIGPIPE itself once. Left for C8, not fixed here.
- **W0801** is raised once per build, before the first step, when any step has `network = true`; it names the steps. It goes to stderr in the output mode asked for, and never ends the run.
- The text row ends with `net` for a network step. The JSON record already had `"network"`.

Without `--verbose` nothing changes: the log file and the last 20 lines on failure.
