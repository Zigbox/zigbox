# M7 slice 3b-iii: `--verbose` streams to stderr, a line at a time

*Decided 2026-11-03, by the slice.*

With `--verbose`, `zbx build` copies each step's output to **stderr** as it is produced, every line behind the prefix `<step> | `. Stdout stays the report (or the JSON), so `zbx build --verbose --output json | jq` keeps working.

- **Line-atomic writes.** Steps run in parallel. The log sink cuts what a step wrote into lines and writes each line, with its prefix, in one `write`, so two steps' output never mixes inside a line. A line longer than one write (1024 bytes) is continued with the prefix on each piece.
- **Always pipe, not `mirror`.** The runtime's `mirror` mode leaves the terminal uncaptured; the build needs the bytes in the log file as well, for the last-lines-on-failure cause. The log sink therefore sees every byte and streams from there (`runtime/run.zig`, `StartOptions.stream_prefix`).
- **W0801** is raised once per build, before the first step, when any step has `network = true`; it names the steps. It goes to stderr in the output mode asked for, and never ends the run.
- The text row ends with `net` for a network step. The JSON record already had `"network"`.

Without `--verbose` nothing changes: the log file and the last 20 lines on failure.
