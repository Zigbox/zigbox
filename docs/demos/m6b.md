# M6b demo: the dev loop

This document grows slice by slice. Until the `demo-m6b` job is green in CI, M6b is built, not
demonstrated. Slice 4 adds the by-hand steps for the whole milestone.

## Slice 1: writable mounts and `--user`

`--mount HOST:CTR` (repeatable), `--user USER[:GROUP]`, the id-mapped mount line of `zbx doctor`,
run record version 8, and codes `E0014`, `E0015`, `E0212` to `E0216`.

### The rules

- **Project directory**: the directory holding the nearest `zbx.lock` up from the working
  directory, else the working directory (`src/runtime/project.zig`). `Spec.project` overrides it
  for a library caller. When it is `/` no `--mount` is allowed.
- **A source is resolved first**, part by part with every symbolic link followed
  (`project.resolve`, over the `Fs` interface, at most 40 links), and the result must be the
  project or below it (`E0212`, one line naming the project directory). `../other`, a link that
  points out, a link to `/etc` and `/` are refused. The source must exist and be a directory or a
  regular file (`E0214`); it is never made. A resolved path with `:`, a space or a control byte,
  or over 256 bytes, is `E0214` too (the record keeps paths in one space-separated string, as for
  `--bind`).
- **The run's user must be root, user and group both 0** (`E0213`, naming the user and the
  fixes `--user 0` and `--bind`). The brief says "uid 0"; a group other than 0 would give the
  project's files a subordinate group, which the acceptance criterion forbids, so the group is
  held to 0 as well. The check is in the library's `start`, before the container is made.
  A process of the container that is root can still `chown` a file in a mount to another id;
  that is the program's own act, not the run's user.
- **The CLI looks at `--mount` before it looks for the image**, so a refused mount pulls
  nothing. The library repeats the same resolution (`mounts.resolve`), so a caller that does
  not go through the CLI meets the same rules.
- The shared target rules, the count of 8 (with `--tmpfs`, `--bind`, `--secret`) and the
  exclusion of mount points from `zbx commit` hold: the record's `mounts` names the target.
- **Plan**: a writable mount is staged and bound like a `--bind` without the read-only remount
  (five steps, `mount_steps_writable`); a failing step is `E0215`.

### `--user`

Resolved against the image's own `/etc/passwd` and `/etc/group` as the image's `User` is, and it
replaces that `User`. A name the image lacks is `E0216`, naming the image (the image's own
unknown name stays `E0521`, blamed on the image).

Cut: `--user` needs an image. A `--rootfs` directory or a bare tree digest is `E0015`
("a directory or a tree has no image to look the user up in"); there is no image configuration
to replace and the store's tree is only read for an image run.

### The record and the JSON

Run record version 8 adds `.user = "UID:GID"` and the `mount:` kind in `.mounts` (host path as
resolved). Versions 1 to 7 are still read; `record_written_by_m6_merged` in `records.zig` is the
text the merged M6 renderer wrote. `run --output json` (`container_exit`, and the detached
document's `container`) and `ps --output json` add `writable_mounts` (`host`, `target`) and
`user` (`uid`, `gid`; `null` in `ps` for an older record). Additive; the `run` and `ps` schemas
list them.

### `zbx doctor`

A detail of the **overlay** check, never a warning and never a failure: after the overlay's own
words, `; id-mapped mounts of <project directory>: allowed|not allowed|could not be tested
(zbx does not use them)`. The probe is `Host.probe_idmap`: in a forked child that drops root, in
a scratch user and mount namespace, `open_tree` with `OPEN_TREE_CLONE`, then `mount_setattr` with
`MOUNT_ATTR_IDMAP` and that namespace; the clone is detached and goes with the namespace. An
ordinary user is normally refused. It is not asked when the overlay check fails.

### Failure modes

| What | How it shows | Recovery |
| --- | --- | --- |
| `../other`, a link that points out, `/` | `E0212`, exit 125, names the project and where it landed | run from the project, or `--bind` |
| a source that is not there, a socket, a loop, a path with a space | `E0214` | make it; move the project |
| an image whose user is not root | `E0213`, names the user, both fixes | `--user 0`, or `--bind` |
| a mount step refused in the container | `E0215` | `zbx doctor`; a path the image has with `--read-only` |
| `--user` of a name the image lacks | `E0216` names the image | a name it has, or a number |
| `--user` with `--rootfs` or a tree | `E0015` | run an image |

### Mac

The home directory is one owner over virtiofs, so writes land as the Mac user whatever the
container user; the same rule is kept anyway (one behaviour on both platforms).

### What was checked

- Unit and simulation tests: `project.zig` (resolution, loops, bounds), `writable_tests.zig`
  (success, file and project sources, every refusal, the lock-based project, the library's
  project and user, the plan's steps, `E0215` at each step, JSON), `pull_tests.zig` (`--user`
  and `--mount` on an image run as app:staff), the record's old and new text, the doctor line,
  goldens and pages for the new codes.
- Fuzzers at 10,000 iterations: `cli`, `run` (writable mounts, escaping and missing sources,
  `E0215` by step) and `record` (user, `mount:` kind).
- The VM: the `WRITABLE` part of `demo-m6` (`writable_m6.zig`, `checks_writable_m6.zig`),
  temporary until slice 4 moves it to `demo-m6b`.

## Slice 2: `zbx logs`

`zbx logs NAME [--follow] [--tail N] [--stream stdout|stderr] [--output json]`, the framed log
every run keeps, the cap, and codes `E0217` to `E0219`, `W0204` and `W0205`. Schema `zbx.logs/1`.

### What is kept, and where

`<state>/zbx/logs/<name>.log` (and `<name>.log.1`), beside the run record's directory
(`runs/`). A run's output was inherited from `zbx` (or `/dev/null` for a supervisor); now the
container's standard output and error are two pipes that the process that waits for the container
reads: a foreground `zbx run` copies each chunk to the terminal first and then writes it to the
log; a detached run's supervisor only writes the log. The code is in the library
(`runtime/session.zig`, `Session.wait` pumps; `runtime/run.zig`, `log_sink`), so Zigcube's agent
gets it from `start`/`wait` (`StartOptions.keep_log`, default true; `mirror` is the CLI's copy to
the terminal). Reading: `zigbox.open_log` and a `zigbox.LogReader` of the caller's own.

### The frame (`runtime/logfile.zig`, constants in `constants.zig`)

```
file   = header record*
header = version (1) | seven zero bytes | base (u64 LE)          16 bytes
record = stream (1 stdout, 2 stderr) | time (5 bytes, seconds) | length (2 bytes, 1..4096)
         | crc32 (of the first 8 bytes and the payload) | payload     12 bytes + payload
```

`base` is the offset of the file's first record in the stream of everything the container wrote.
A reader stops at the first record that is short, out of range or fails its CRC (a torn tail);
a newer version is `E0218`.

### The cap: two rotated files

5 MiB (`log_bytes_max`) per container as two files of at most half that. When the current file
would pass 2.5 MiB, the writer syncs and closes it, `rename`s it over `<name>.log.1` (the older
file, and its records, are dropped as a whole file) and makes a new `<name>.log` whose `base`
continues the stream. `dropped_bytes` is the older file's `base`. Why not one file compacted: a
compaction copies up to the cap on every drop and needs a temporary file and a rename too; the
rotation is one `rename`, so a crash at any step leaves either the old pair or the new pair,
each of whole records. The price: the log holds between 2.5 and 5 MiB, not always 5.
`logfile.zig`'s test crashes the simulated disk at every write point (with torn short writes and
four seeds for the bytes a crash keeps) and checks the log reads as a contiguous run of whole
records, each equal to what was written; the `logs` fuzzer does the same with random sizes, and
damages a file (bursts of up to four bytes, cuts, zeroed and garbage tails).

### Readers

- Text: the bytes as written, both streams in the order the pump read them. `--stream` filters,
  `--tail N` is the last N lines (a first pass counts newlines; no memory is held).
- `--output json`: one `zbx.logs/1` object per record (`stream`, `time`, `text`, `lossy` when
  bytes were not UTF-8, `dropped_bytes` on the first record when the cap cut). A record is one
  read of the container's pipe (up to 4096 bytes), not a line.
- `--follow` keeps its descriptor on the current file, so it follows a rotation (the file it
  holds became the older one; it reads that to its end, then takes the new current file), and
  ends, exit 0, when the container's record says it is no longer running, after one last read.
  It works on a foreground run that is still going, the same way.
- Text mode with dropped output prints `W0205` on stderr (not with `--tail` that skips them).

### Removal

The only code that removes a run record is the prune in `run.start` (`records.prune`); it now
removes the log of every record it removes (`remove_logs`, next to the pasta log). `ps` does not
remove records. A run that takes a name again starts its log empty (`Writer.open` removes both
files first). Tested in `runtime/logs_tests.zig`.

### Failure and deviations

- A log that cannot be made: `W0204` once, and the container writes where it always did (no
  pipes). A log that fails while the container runs: `W0204` once (a detached run's supervisor
  cannot say it any more after the start was reported, so it does not), the terminal still gets
  everything, a detached container's output is read and dropped so it never blocks.
- A foreground run's standard output and error are now pipes: a program that checks `isatty`
  (colour, line buffering) sees a pipe, as in `docker run` without `-t`. The order of the two
  streams is the order the pump read them (a write to each within microseconds can swap). If the
  terminal cannot be written to, that stream's pipe is closed, so the container's next write
  fails as it did before.
- A record's time is seconds (the host interface has no wall clock in milliseconds).
- `E0402` (no such container) is reused for an unknown name.
- Cut: the Mac forwards `logs` in slice 6.

### What was checked

- Unit and simulation tests: `logfile.zig` (frame, header, bounds, cap, crash at every write
  point, torn tails, damage, a follow through a rotation), `logs_commands.zig`,
  `runtime/logs_tests.zig` (foreground, detached, `--stream`, `--tail`, JSON, `--follow`, errors,
  an unwritable log, a failing log, the cap through the command, prune, name reuse, the library
  caller), goldens and pages for the five codes, the help text.
- Fuzzer `logs` at 10,000 iterations.
- The VM: the `LOGS` part of `demo-m6` (`logs_m6.zig`, `checks_logs_m6.zig`), temporary until
  slice 4 moves it to `demo-m6b`.
