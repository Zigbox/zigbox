# M5 · Network: the no-network hint, --publish, and M4's carried-over notes

*Decided 2026-10-28, after M4 merged.*

- **The no-network hint is shown on failure.** When a run with the default network (no `--net` given) exits non-zero, zbx adds `zbx: network: none (grant with --net)` to stderr. It does not try to detect whether the container used the network; the line is a note, and the exit code stays the container's.
- **`--publish` implies `--net user`.** `zbx run --publish 8080:80 nginx` works as the spec types it; `--publish` with an explicit `--net none` or `--net host` is a usage error.
- **M4's demo step 3 is reworded** (live doc and `docs/SPEC.md`): the second python image costs the store less than its compressed size because most of its stored bytes are shared with the first. It costs about 65%; "far less" overstated it.
- **An image record keeps its tags.** A pull by digest after a pull by tag no longer replaces the tag; a record lists every tag it was pulled as.
- **The agent-interface gaps go into M5**: `zbx explain --output json`, `zbx lock show`, and `run --output json` naming what ran.
- **M4b (Mac) waits** for an Apple Developer ID and an Apple Silicon runner; M5 goes first.
