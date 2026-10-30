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

`base` is the number of payload bytes (what the container wrote, headers not counted) that came before the file's first record, over everything the container wrote.
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

### Bundles

`zbx bundle` collects the run record, system files, the names of the environment, and the
doctor's report; it reads nothing under `logs/`, so a bundle never carries a log, redacted or not
(`bundle_tests.zig` plants a secret-shaped marker in a container's output, shows it is in the
log, and finds it in no byte of the bundle with redaction on or off).

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
- A foreground run's standard output and error are pipes, except a stream that is a terminal
  (`is_terminal`): that stream is left to the container, so editors, pagers, colours and job
  control work, and it is not in the log. The log's header records which streams were left
  (`not_kept`), and `zbx logs` gives `W0206` for it. A run with stdout redirected to a file or
  a pipe sees a pipe, as in `docker run` without `-t`. Logging an interactive run through a
  pseudo-terminal can come with slice 3's `exec`. The order of the two
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

## Slice 3: `zbx exec`

`zbx exec NAME [-e NAME[=VALUE]] [--user USER[:GROUP]] [--workdir DIR] -- COMMAND...`, the
library's `exec_start`/`exec_wait` (`runtime/exec.zig`, exported by `zigbox.zig`), codes `E0220`
to `E0224` and `W0207`, schema `zbx.exec` (`zbx schema exec`), and the exec history beside the
log. The run record is unchanged (still version 8).

### How a command gets into a container (`runtime/exec_plan.zig`)

Three processes, all single-threaded, nothing allocated or formatted after the first fork:

1. **zbx** finds the container by name from its run record and checks it runs (its PID 1 alive,
   its innermost pid 1, in its scope: `lifecycle.alive`). It reads the container's environment
   from `/proc/<pid>/environ`, and for `--user` the container's `/etc/passwd` and `/etc/group`
   through `/proc/<pid>/root`. It opens `/proc/<pid>/ns/{user,ipc,uts,net,pid,mnt}` (a namespace
   that is zbx's own, the network of a `--net host` container, is not joined: joining it would
   need a privilege the user lacks) and, with a terminal, a pseudo-terminal of the container's
   own devpts (`/proc/<pid>/root/dev/pts/ptmx`, so `tty` names it inside; the host's `/dev/ptmx`
   if the container has none). Then it forks the joiner.
2. **The joiner** joins, in this order: **user** first (zbx made it, so joining needs no
   privilege; it gives the joiner every capability inside it, which the others need, since the
   container's user namespace owns them all: EPERM otherwise, which the simulator enforces),
   then **IPC, UTS, network, PID**, and **mount last** (`setns` of a mount namespace sets the
   root and the working directory to the namespace's, so every path after it is the
   container's; the namespace files were opened before for that reason). Joining a PID
   namespace changes only where children are born, so the joiner forks the command with
   `CLONE_PARENT`: the command is zbx's child, born in the container's PID namespace, and zbx
   waits for it directly. The joiner writes the command's host pid on the report pipe and ends.
3. **The command** asks to die with zbx, then waits for the go-ahead. Meanwhile zbx reaps the
   joiner and **puts the command in the container's cgroup**: with systemd, the user manager
   moves it into the scope (`AttachProcessesToUnit`, systemd 238; moving a process needs write
   access to the cgroup above both where it is and where it goes, and a login session and the
   manager's `app.slice` meet only in a cgroup root owns, so the manager does it, asking the
   system manager when it must); with the cgroupfs driver (the macOS VM), zbx writes its pid to
   the container's `cgroup.procs`. Only then the go-ahead: nothing the command does happens
   outside the container's limits. The command then takes the terminal (its own session, the
   peer as its controlling terminal and three streams), enters the working directory, closes
   every descriptor above 2 at exec, **drops to the container's capability set** (the bounding,
   effective, permitted and inheritable sets, `policy/capabilities.zon`, and the ambient set
   emptied), becomes the user (and asks again to die with zbx, which a change of user clears),
   **sets `no_new_privs`**, **loads the container's seccomp filter** (the same program), and
   `execve`s. This is the order the brief gives; the kernel needs the capabilities dropped while
   CAP_SETPCAP is held and the user taken while CAP_SETUID is, and the filter last.

A failed step of any of the three is one record on the report pipe naming the step, and zbx
builds the diagnostic, kills and reaps what it started, closes every descriptor and puts its
terminal back (the simulator test fails each step of the longest plan in turn and checks all of
that, and the `exec` fuzzer does the same at random).

### What the command has

- **Environment**: the container's (its PID 1's, as it was started: the defaults, the image's,
  the run's `-e`), with each `-e` of the exec replacing the variable of its name, and TERM (the
  caller's) added only for a terminal when the container has none. A value is never kept or
  printed.
- **Working directory**: the container's PID 1's (`/proc/1/cwd`, followed inside the
  container), which is the image's or the run's unless PID 1 moved; `--workdir DIR` replaces it.
  It must exist: exec makes nothing in a running container (`E0223`).
- **User**: the run's (the record's `.user`; root for a record older than version 8); `--user`
  looks the name up in the container's own files (`E0216` names the container). A container
  with only root mapped refuses another user (`E0523`, naming `--user`).
- **Streams**: with a terminal on zbx's standard input *and* output, a pseudo-terminal sized as
  zbx's (`TIOCGWINSZ`, `TIOCSWINSZ`), resized on SIGWINCH, zbx's terminal raw while it runs and
  put back on every path; zbx copies the keys to it and its output to zbx's. Otherwise the
  command's streams are zbx's own. The command's output is not in the container's log.
- **Signals**: INT, TERM, HUP and QUIT that zbx receives are passed to the command as they are
  (it is not a PID 1, so a signal it has no handler for acts on it); a flood past 1024 kills it.
  A run's wait now has SIGWINCH blocked too, and drops it.
- **Exit code**: the command's own, or 128 plus its signal; zbx's own failures are 125, and 126
  or 127 for a command that cannot run or is not there (`E0202`), as for `run`. `--output json`
  ends with `{"exec_exit":{"container":...,"reason":"exited"|"signal","code":N,
  "container_ended":bool}}` (and `"signal"`) on stderr.
- **Lifetime**: the command is in the container's PID namespace, so when PID 1 ends the kernel
  kills it; zbx reaps it (137) and, when the container's PID 1 is gone, says
  `zbx: exec: the container NAME ended, and the command with it` (`container_ended` in JSON).
  A SIGKILL of zbx kills the command (`PR_SET_PDEATHSIG`).

### Not a container: the history

`ps` lists records and scopes, and an exec has neither. Each exec appends one line to
`<state>/zbx/logs/<name>.exec` when it ends (`runtime/exec_history.zig`): start, end, exit and
the command, quoted; never the environment. At most 16 are kept, oldest dropped; an append
takes `<name>.exec.lock` (`flock`) and rewrites the file atomically, so two execs ending together
keep both. It is removed with the record (prune) and when a run takes the name again. `zbx
bundle` of the container adds `execs.txt` (redacted like every file). A history that cannot be
written is `W0207`; the command ran.

### Codes

`E0220` the container is not running (names its state: stopped and how, or lost), `E0221` can't
join (environment, a namespace, the fork into the PID namespace), `E0222` can't put the command
in the cgroup (the manager's or the kernel's answer), `E0223` the working directory is not there,
`E0224` can't give the command a terminal, `W0207` the history not written. Reused with the same
meaning: `E0402` (no such container), `E0202`, `E0207`, `E0208`, `E0216`, `E0523`, `E0005` (a
`--workdir` that is not absolute or has `..`), `E0008`, `E0010`, `E0011`, `E0015`. The error
pages of the exec-only codes give their exit code as "125 in zbx exec"; the shared codes' pages
still say "in zbx run" (an exec ends with the same code).

### The library

`zigbox.exec_start(host, &spec, options, &handle, &diag)` and `exec_wait(&handle)`, an
`ExecHandle` of the caller's (under 640 KiB: the plan, the container's environment and passwd
and group files, the history's room), no module-level state. The thread that starts it must be
the process's only thread then (namespaces are joined in a forked child), and must be the one
that waits. `ExecSpec.terminal` is the caller's choice; Zigcube's agent leaves it off.

### Deviations and cuts

- **The working directory is PID 1's, not a stored one.** Keeping the run's working directory in
  the record (a version 9) was built and taken out: its worst case (1024 bytes, each escaped to
  four) does not fit the record's 64 KiB bound with the rest. PID 1's own directory is the run's
  unless PID 1 changed it; `--workdir` covers the rest.
- **The environment is PID 1's environ**: what it was started with, not what it set later.
- No `-i`/`-t` flags: the terminal follows zbx's own streams, as `zbx run`'s does.
- A SIGKILL of zbx leaves no history entry (the command dies with it).
- The death signal is asked for again after the change of user; zbx dying in the instant between
  the two leaves the command to finish by itself in the container.
- Cut: the Mac forwards `exec` in slice 6.

### What was checked

- Unit and simulation tests: `exec_plan.zig` (order, counts, environment, bounds),
  `exec_history.zig` (round trip, damage, bounds), `exec_tests.zig` (every namespace joined, the
  cgroup joined before the command ran with the bus and the cgroupfs driver, the hardening,
  environment, user, directory, a stopped and a missing container, death with the container,
  the terminal with keys, output and a resize, every failed step, the history and `-e`),
  `sync.zig`, the CLI (parsing and refusals, exit codes, `exec_exit`), `bundle_tests.zig` (the
  execs noted, a `-e` value in no byte), goldens and pages for the six codes, the schema.
- Fuzzers at 10,000 iterations: `exec` (new) and `cli`.
- By hand in the cloud container (root, no user bus, so no scope, kernel 6.18), against an
  Alpine minirootfs, `run -d` then `exec`: the namespaces and hardening (`CapEff
  00000000a00405fb`, `NoNewPrivs 1`, `Seccomp 2`, the container's hostname, `ps` showing its PID
  1), exit 42 passed through, `unshare -U` and `mount` refused as in the container, `-e`,
  `--workdir`, 127 for a missing command, `E0223`, a terminal under `script` with its size and
  `tty` naming `/dev/pts/0`, SIGTERM forwarded (143), the command killed with its container (137
  and the line), `E0220` after the stop, and the history file. The VM is the real check.
- The VM: the `EXEC` part of `demo-m6` (`exec_m6.zig`, `checks_exec_m6.zig`), temporary until
  slice 4 moves it to `demo-m6b`.

## Slice 4: pull in the library

Zigcube's agent links the `zigbox` module and could not fetch an image: pull lived in the command
line's code and its child printed the result itself. Pull is now a library call, and `zbx pull` is
a thin caller of it. Zigcube's orders call the operation `ensure_image`; here it is `pull.pull`
(`zigbox.pull.pull`), and `ensure_image` is that call plus a look at the store first (the agent's
to write: `images.load` by manifest digest, or a pull).

### What the library offers (`src/pull.zig`)

```zig
pub fn pull(
    host: Host,
    facts: *doctor.Facts,
    request: *const Request,       // reference (tag or digest), platform, mirrors
    progress: ?Progress,           // may be null
    workspace: *Workspace,         // the caller's memory, about 15 MiB: static or heap
    import_workspace: *import.Workspace,
    result: *Result,
    diag: *Diag,
) Error!void
```

It resolves the reference for the platform, downloads what the cache lacks (a cut download
resumes), verifies every blob by its digest, unpacks the layers into one tree in the store's
single-threaded child, imports it and writes the image record exactly as `zbx pull` does. The
`Result` has the manifest digest, the config digest, the tree digest, the platform
(`linux/amd64`), the layer count, the unpack's counts (files, directories, symlinks, bytes, special
entries and attributes skipped), the number of warnings that did not fit the child's report, and
the image's settings (entrypoint, cmd, env, working directory, user; a pointer into the
workspace, valid until its next pull). `pull.resolve` asks the registry only. `Platform` is the
architecture to ask for (null: this machine's, from `uname`) and a fallback.

- **Per caller, no process-wide state.** The store is the one `host` locates, as for every call of
  the library. Memory is the caller's. The real network's buffers, parsed CA certificates and
  resolver `Io`, which were module-level statics (and a "not reentrant" assertion), are now a
  `host_real_net.Memory` that `HostReal.network_memory` points to; `zbx` has one static in
  `main.zig`. A host that makes a request without one asserts.
- **Bounded.** Memory is fixed by constants; the child's report is at most 16 KiB
  (`pull_report_bytes_max`), the same timeouts apply, and the store's shared lock is held from the
  first byte downloaded to the record.
- **Prints nothing, reads no pull variable.** Warnings (W0201 from the id map, the unpack's, the
  import's) go to the progress callback, with `resolved` and `blob` events. A failure is the same
  coded `Diag`, carried from the child through the report (`pull_report.zig`; the same carrier
  as `Diag.encode`), so the CLI's stderr is byte for byte what the child used to write.
- **Never touches `zbx.lock`.** The library has no lock code. `pull_commands.zig` reads the lock
  before the pull (a lock that does not read ends the command before the network is asked, which
  is earlier than before: the child used to check it after resolving) and writes it after.

### What moved out of the library, and what stayed

Moved to the caller: `ZBX_REGISTRY_MIRRORS` (the `mirrors` of the request), `ZBX_PLATFORM` and
`ZBX_PLATFORM_FALLBACK` (the `platform`), `zbx.lock`, and the rendering of the result, of the JSON
`zbx.pull/1` and of warnings. `pull_commands.zig` reads them with `host.environment` and builds
the request.

Stayed: `HTTPS_PROXY`/`https_proxy`, `NO_PROXY`/`no_proxy` and `SSL_CERT_FILE`, read by the real
network from `host`'s environment at each request (the CA bundle once per `Memory`). They are
properties of the host's network, not of the pull; the library does what the rest of it does and
asks `host`. They are per caller, because the host and the `Memory` are.

### Differences a caller can see

- Warnings of the store's child reach the callback (and so stderr) when the child has ended, not
  as it goes: the child is another process and the parent reads its pipe after it. The text and
  the order among stderr lines are the same.
- `zbx run` of a tag whose implicit pull fails now exits through the run scope of the diagnostic
  (125 for every code a pull raises) instead of a fixed 125; the line is the same.
- A client's `machine` text now lives in the workspace; it used to point into a stack frame that
  had returned.

### What was checked

- `pull_report.zig`: both ends against each other, the bound and one past it, damage.
- `pull_library_tests.zig`: a caller that is not the CLI (result, record, store whole, no
  `zbx.lock`, a second pull from the cache), the environment ignored, E0515, E0516, bad reference
  and E0503 as diagnostics, and two callers on two threads, three rounds, each with its own host,
  disk, wire and memory.
- Unchanged and passing: every test and golden of `pull_tests.zig`, `run_image`, `cli`.
