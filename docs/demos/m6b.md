# M6b demo: the dev loop

This document grows slice by slice. Until the `demo-m6b` job is green in CI, M6b is built, not
demonstrated. Slice 5 adds the demo, the by-hand steps and the failure modes for the whole milestone.

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
container user; the same rule is kept anyway (one behaviour on both platforms). Slice 6 runs it
from macOS (see "The Mac" at the end).

### What was checked

- Unit and simulation tests: `project.zig` (resolution, loops, bounds), `writable_tests.zig`
  (success, file and project sources, every refusal, the lock-based project, the library's
  project and user, the plan's steps, `E0215` at each step, JSON), `pull_tests.zig` (`--user`
  and `--mount` on an image run as app:staff), the record's old and new text, the doctor line,
  goldens and pages for the new codes.
- Fuzzers at 10,000 iterations: `cli`, `run` (writable mounts, escaping and missing sources,
  `E0215` by step) and `record` (user, `mount:` kind).
- The VM: the `WRITABLE` part, first in `demo-m6` and moved to `demo-m6b` in slice 5
  (`writable_m6b.zig`, `checks_writable_m6b.zig`). The note that said slice 4 would move it was a
  slip: slice 4 was pull in the library.

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
- On the Mac `logs` is forwarded like `run` (slice 6; see "The Mac" at the end).

### What was checked

- Unit and simulation tests: `logfile.zig` (frame, header, bounds, cap, crash at every write
  point, torn tails, damage, a follow through a rotation), `logs_commands.zig`,
  `runtime/logs_tests.zig` (foreground, detached, `--stream`, `--tail`, JSON, `--follow`, errors,
  an unwritable log, a failing log, the cap through the command, prune, name reuse, the library
  caller), goldens and pages for the five codes, the help text.
- Fuzzer `logs` at 10,000 iterations.
- The VM: the `LOGS` part, first in `demo-m6` and moved to `demo-m6b` in slice 5
  (`logs_m6b.zig`, `checks_logs_m6b.zig`).

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
- On the Mac `exec` is forwarded like `run` (slice 6; see "The Mac" at the end).

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
- The VM: the `EXEC` part, first in `demo-m6` and moved to `demo-m6b` in slice 5
  (`exec_m6b.zig`, `checks_exec_m6b.zig`).

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

## Slice 5: `demo-m6b`, the acceptance checks, the agent test and the upgrade test

`zig build demo-m6b` (`src/testing/vm/main_m6b.zig`), run in CI by the `demo-m6b` job and on
demand by a push to `vm/m6b-<x>` (`vm/all-<x>` runs every demo). Until that job is green, M6b is
built, not demonstrated.

### The parts, in order

| Part | File | What it shows |
| --- | --- | --- |
| UPGRADE | `upgrade_m6b.zig`, `checks_upgrade_m6b.zig` | the merged M6 `zbx` (`bf57ec8`, PR #12) pulls alpine and starts a detached container with a new `--state` volume; this `zbx` reads the store, the image record (version 2), the lock and the run record (version 7, its own are 8), lists the container running, shows the volume in use by it, `exec`s into it (a container it did not start: `cat` reads what M6 wrote, `id -u` is 0), finds `logs` of it ZBX-E0217 (exit 1; M6 kept no log), stops it, finds the lock free and `exec` ZBX-E0220, and runs the image with M6's volume |
| SPEC | `spec_m6b.zig`, `checks_spec_m6b.zig` | the spec's five steps (below) |
| WRITABLE | `writable_m6b.zig` | slice 1's checks, moved from `demo-m6`: the edit seen, the file the host user's, the refusals, `--user 0` |
| LOGS | `logs_m6b.zig` | slice 2's checks, moved from `demo-m6`: requests in the log, the log after the starting `zbx` was killed, a foreground run, `--follow`, the cap |
| EXEC | `exec_m6b.zig` | slice 3's checks, moved from `demo-m6`: a file through the mount, a refused syscall, a missing capability, the scope and `--pids`, the exit code, the terminal, death with the container, a stopped container |
| AGENT | `agent_m6b.zig`, `agent_json_m6b.zig` | the dev loop by JSON only (below) |
| ACCEPT | `accept_m6b.zig`, `checks_accept_m6b.zig` | a log, rotated once, is removed with its run record |

`demo-m6` lost WRITABLE, LOGS and EXEC (they stay green there as part of `demo-m6b`, which a CI
job and a `vm/m6b-*` push run). Every assertion of every part is a pure function with a unit test
(`zig build test`); the parts only run commands and pass what the guest printed to them.

The acceptance criteria and where they are shown:

| Criterion | Part |
| --- | --- |
| files written through a writable mount are owned by the host user | SPEC 3 (`ls -l`, and no file of another owner under the mount), WRITABLE 3 and 5, EXEC 1, AGENT 3 |
| a writable mount for a non-root user is refused, naming the user and the fix | WRITABLE 4 (E0213: the user, `--user 0`, `--bind`), AGENT 4 |
| logs are bounded | LOGS 5 (more than 5 MiB written; the end is kept from a whole record, `dropped_bytes` and the bytes shown add up) |
| logs survive the exit of the `zbx` that started the container | LOGS 2 (the `zbx` is killed with SIGKILL) |
| logs are removed with the run record | ACCEPT (`lrm00` writes 3,000,000 bytes, so both log files exist; the record is pruned by newer runs; neither file is left, `logs` is E0402 with its summary) |
| `exec` gains nothing the container lacks | EXEC 2 (`unshare -U` refused, `mount` without the capability), EXEC 3 (the scope, `--pids`), EXEC 8 (the death signal after a change of user) |
| upgrade test against M6 (`bf57ec8`) | UPGRADE |
| stable diagnostics | SPEC 5, WRITABLE 4, EXEC 7, ACCEPT, AGENT 4 and 5 read the codes (`E0212`, `E0213`, `E0214`, `E0217`, `E0220`, `E0402`) |
| the agent test | AGENT |

### The spec's five steps, as the demo runs them

In the net project (`zn`), with `python:3.12-slim`:

1. `zbx run -d --name web --publish 8000:8000 --mount ./site:/srv python:3.12-slim -- python -m http.server -d /srv 8000` (the spec's line, with `-d` so that the demo keeps its shell).
2. `curl localhost:8000/index.html` returns `first-SIGMA`; the page is edited on the host; the next `curl` returns `second-SIGMA`.
3. `zbx exec web -- sh -c 'echo made-inside > /srv/new.txt'`; `ls -l site/new.txt` shows `demo` as the owner, the file holds `made-inside`, and `find site ! -user demo -print`, run from the project, exits 0 and prints nothing (a `find` that fails says so on stderr and exits non-zero, so it never passes as an empty search).
4. `zbx logs web` shows the two requests (`GET /index.html` answered 200), and no others.
5. `zbx run --mount ../outside-spec:/x alpine -- true` is ZBX-E0212: the project directory, "outside the project", and the real path.

The one difference from the spec's text is how the demo waits for the port: a connection that
sends no request (so the log has the two requests of step 2 and nothing else). The part ends by
stopping `web` and checking that port 8000 is free.

### By hand on Ubuntu 24.04

```
mkdir ~/dev && cd ~/dev && mkdir site && echo hello > site/index.html
zbx pull python:3.12-slim
zbx run -d --name web --publish 8000:8000 --mount ./site:/srv python:3.12-slim -- python -m http.server -d /srv 8000
curl localhost:8000/index.html            # hello
echo edited > site/index.html
curl localhost:8000/index.html            # edited
zbx exec web -- sh -c 'echo made-inside > /srv/new.txt'
ls -l site/new.txt                        # owned by you
zbx logs web                              # the two GET lines
zbx run --mount ../elsewhere:/x alpine -- true    # ZBX-E0212, naming the project
zbx stop web
```

Also by hand: `zbx logs web --follow` (ends with the container), `zbx exec web -- sh` at a terminal,
`zbx run --mount site:/srv memcached:alpine` (E0213, then `--user 0`), `zbx exec web -- true` after
the stop (E0220), and `ls ~/.local/state/zbx/logs` before and after enough runs to prune a record
(`runs_max`, 32).

### The agent test (demo-m6b's AGENT part)

`agent_m6b.zig` and `agent_json_m6b.zig`: a scripted agent in its own project (`za`), on port 18090,
with `--output json`, `zbx schema <command>` and `zbx explain --output json` only. The schemas of
`run`, `ps`, `logs`, `exec` and `pull` have no `$ref` to follow, and every document is checked
against the schema the agent read. The `exec` schema describes a stderr line (`exec_exit`) and has
no `schema` member, so that one is found by the member name instead.

| Step | What the agent does | What it reads |
| --- | --- | --- |
| 1 | `run -d --mount agentsite:/srv --publish` | `container.writable_mounts` (the resolved host path and the target) and `container.user` (0:0); it checks the path is inside its own project; `ps` says the same |
| 2 | `curl` twice with an edit between; `logs --output json` | `zbx.logs/1` lines: it counts the records of stream `stderr` whose text has `GET /index.html`: two |
| 3 | `exec --output json -e TOKEN=... -- sh -c '...; exit 3'` | the status 3 and the `exec_exit` line agree (`exited`, 3, `container_ended` false); the value of `-e` is in no document; the file is the host user's |
| 4 | a mount outside the project; a mount with a non-root image | E0212 (`context.within` is its project, `real` the path) and E0213 (`context.uid` is not 0), each checked against the `run` schema; the fix of each is a template, so the agent takes the flag and its value from E0213's fix command (`--user 0`, by `flag_from_fix`) and adds it to its own command, which works; `explain` agrees with each |
| 5 | `stop`, then `exec`; `logs`; a missing name | E0220 against the `exec` schema (`context.state` `stopped`; its first fix is a command, which the agent runs, and `ps --all` gives `agentweb`'s own entry as `stopped`); the stopped container's log still gives the two requests; E0402 for the missing name (exit 1, checked against the `logs` schema, which describes the refusal as well as the records, and by its members) |

Findings (things the agent could not read from JSON; a `FINDING` line each, not worked around):

- No document says when a container is ready; the agent polls the published port (as in M6).
- The fixes of E0212 and E0213 are templates (`<image>`, `./site`). The agent adapts them by the
  flag they name and never runs them as written.
- Resolved: the `logs` schema used to describe only its stdout records, so a refusal of `logs`
  on stderr followed no schema. The owner decided (2026-10-30, `docs/DECISIONS.md`) that
  `zbx.logs/1` grows to describe the diagnostic too, as `exec`'s does; the agent now checks E0402
  against it, and the finding is gone.

### A bug the first VM runs found

An exec'd command that the kernel kills with its container's PID namespace is reaped while PID 1
is still on its way out, so `lifecycle.alive` still answered yes and `exec` did not say "the
container ended, and the command with it" (exit 137 was right; the line was missing). It showed
as a failure of EXEC 6 in one of three runs. Slice 3's tests used a simulator in which PID 1 is
gone at once.

The kernel kills the rest of a PID namespace from PID 1's `do_exit` (`exit_notify` →
`forget_original_parent` → `find_child_reaper` → `zap_pid_ns_processes`), and PID 1 stays out of
the zombie state until every other process of the namespace has been reaped, by parents that may
be slow (other execs' `zbx`), so no fixed wait is long enough. But `do_exit` sets PF_EXITING
(`0x4`) in PID 1's flags first (`exit_signals`), and never clears it. So when the command was
killed by SIGKILL and PID 1 still looks alive, the exec reads field 9 of `/proc/<pid1>/stat`
(`lifecycle.is_exiting`): PF_EXITING means the container is ending and the command died with it.
That is decided at once, with no retry (a first fix asked again 20 times, 10 ms apart; it is
gone). No retry backs it up: `zbx` signals only PID 1, so every path on which the kernel kills the
command for the namespace passes PF_EXITING first; a command SIGKILLed before that (a kill of the
whole cgroup from outside `zbx`) was killed by someone else, which is what the exec says.

Tested first, then fixed: the simulator can keep a killed PID 1 exiting (`pid1_exit_ms`: PF_EXITING
in its stat, no zombie, still in its scope, the namespace's other processes already killed), and
`exec_tests.zig` asserts that the exec says the container ended without the clock moving; a
command killed alone says it did not, also without the clock moving. The `exec` fuzzer ends the
command by itself, by its own SIGKILL, or with its container (a PID 1 that takes up to two
minutes to exit), and asserts the same. `lifecycle_tests.zig` reads the flags from real stat
lines (a sleeping process, and a zombie with PF_EXITING).

### Cuts and deviations

- **The disk full while logging is not in the VM.** It cannot be made reliably in the guest in
  minutes; the simulator tests it (`logs_tests.zig`: a disk that takes the header and the first
  write, then is full, gives one `W0204`, the terminal is unharmed, and the run continues). See
  the failure modes.
- **`logs` ends a refusal with status 1**, as DIAGNOSTICS.md, "Exit codes", says: the four
  blame codes (`1` user) for every command, and 125 only for a command that runs a container or
  waits on a workload (`run`, `exec`). The UPGRADE and ACCEPT checks assert 1.
- The upgrade test uses an `exec` into a container M6 started because the record is the only
  thing `exec` and `stop` share with it; a record without a field it needs would show there.
- ACCEPT runs last because pruning removes the oldest records of the demo's state directory.
- **The Mac** runs these steps from macOS (slice 6; see "The Mac" at the end).

### Failure modes

| What | How it shows | Recovery |
| --- | --- | --- |
| a mount outside the project (`../other`, `/`) | `E0212`, exit 125, one line naming the project and the real path | run from the project; `--bind` for a read-only mount |
| a symlink inside the project that points out | `E0212` (the link is followed, the real path is named) | point it inside, or `--bind` |
| an image whose user is not root | `E0213`, exit 125, the user and both fixes; nothing is made | `--user 0`, or `--bind` |
| a log at its cap (5 MiB) | the oldest records are dropped as whole records; `zbx logs` says how many bytes (`W0205`, `dropped_bytes` in JSON); the container is not slowed | keep what matters elsewhere (the application's own files) |
| `exec` into a stopped container | `E0220` naming its state (stopped how, or lost), exit 125 | `zbx ps --all`; run it again |
| `logs` of a container from before logs were kept | `E0217`, exit 1 | run it again |
| the disk full while logging | one `W0204`; the container goes on and the terminal still gets everything; a detached container's output is read and dropped so that it never blocks | make room; the log up to the last whole record is readable |
| a log that cannot be made | one `W0204` at the start; the container writes where it always did | check the state directory's permissions and space |
| `logs` or `exec` of a name with no record | `E0402` (exit 1 for `logs`, 125 for `exec`) | `zbx ps --all` (only the newest 32 records are kept) |
| a connection to a published port before the server listens | the forward accepts it on the host and then resets it, so the client sees a reset rather than a refusal; this predates M6b | wait for the server from inside the container (the demo does), or retry |

### What was checked

- `zig build test`: the unit tests of every new check (each with right and wrong input), run from
  `main_m6b.zig`'s test block. The right input of each is text captured from the green runs of
  `503a591`: https://github.com/Zigbox/zigbox/actions/runs/41079428757 (`vm/m6b-slice5d`: the
  `ls -l` line, python's request lines, `find`'s stderr, the old container's `ps` entry, E0217's
  text, the agent's documents, the exec schema, E0213 and `ps --all`),
  https://github.com/Zigbox/zigbox/actions/runs/41076069695 (the agent's first captures) and
  https://github.com/Zigbox/zigbox/actions/runs/41089445044 (`vm/m6b-review5a`: the ACCEPT
  summary with the rotated file and E0402's line); the wrong inputs are those texts changed.
- `zig build harness` compiles the demo.
- Run in the VM: see the report of the slice (the `vm/m6b-*` and `vm/all-*` runs).

## Slice 6: the Mac

`logs` and `exec` are forwarded into the machine like `run`: `src/macos_main.zig` lists them in
`linux_commands`, and `src/mac/forward.zig` already relayed everything a forwarded command needs,
so no new protocol was needed. What is true on the Mac:

- **The same options, output, JSON and exit codes** as on Linux, because the Linux `zbx` in the
  machine does the work. `logs --follow` and `exec` pass the terminal (raw mode with its size, and
  its changes) when standard input and output are both terminals, and INT, TERM, HUP and QUIT go
  to the guest as signals. A SIGINT to `zbx exec` ends the command and exits 130; a SIGINT to
  `zbx logs --follow` ends it and leaves the container running.
- **`exec` ends as `run` does**: 125 when zbx or the machine failed (a container that is not
  there or not running is `E0402` or `E0220`, 125), the command's own code otherwise. `logs`
  refuses with 1. The macOS `zbx` used to decide this by looking at the first word that did not
  start with `-`, which read the `json` of `--output json` as the command; `runs_container`
  skips the value of `--output` (a unit test).
- **The write rule is the Linux one.** `--mount` is held to the project directory and to a root
  user by the guest's `zbx`, unchanged. The home directory is one owner over virtiofs, so a file
  written inside lands as the Mac user whatever the container's user; the rule is kept anyway so
  that a project behaves the same on both platforms. A project outside the home is refused by
  the macOS `zbx` before the machine is asked (`ZBX-E1013`), for `logs` and `exec` as for `run`.
- **The project directory** is the one holding the nearest `zbx.lock` up from the working
  directory, as on Linux. A `zbx.lock` in the home directory (left by a `pull` run in the home itself)
  makes the whole home the project of every directory below it that has no closer lock, and then
  `--mount ../other` inside the home is allowed. The Mac demo gives its project a lock of its own.

### The steps, from macOS (`zig build demo-mac`, `m6b.*` in `src/testing/mac_demo.zig`)

The demo's five steps exactly as the spec types them (`m6b.1` to `m6b.5`; the wait for the
server listening uses `exec`, so nothing but the steps' requests is in the log), run from
`$HOME/zbx-demo-mac/m6b-project`, on port 8000 of the Mac:

| Step | What it runs |
| --- | --- |
| `m6b.1` | `zbx run -d --name web --publish 8000:8000 --mount ./site:/srv python:3.12-slim -- python -m http.server -d /srv 8000`; `exec` waits until the server takes a connection |
| `m6b.2` | `curl localhost:8000/index.html` returns the page; after an edit on the Mac, the edit |
| `m6b.3` | `zbx exec web -- sh -c 'echo made-inside > /srv/new.txt'`; `ls -l site/new.txt`; the owner is the Mac user's uid, and `find site ! -user` finds nothing |
| `m6b.4` | `zbx logs web` has exactly two requests, both `GET /index.html` answered 200 |
| `m6b.5` | `zbx run --mount ../outside-spec:/x` is `ZBX-E0212`, "outside the project", exit 125 |
| `m6b.5h` | the same command line from a directory outside the home is `ZBX-E1013`, exit 1 |

and what only the Mac has (`m6b.6` to `m6b.11`): `exec`'s exit code (7) and 125 for a container
that does not exist; SIGINT to `zbx exec sleep 1000` within 2 s, exit 130; `exec ... tty` under
`script` prints `/dev/pts/`; `logs --follow` of a detached container shows its output and exits
0 when it ends; SIGINT to `zbx logs --follow` ends it, exit 130, with the container still
running; `zbx stop web` closes port 8000 and `exec` into it is `E0220`, 125.

### Cuts and deviations

- The Mac demo is a table of shell lines, not the Linux demo's pure-function checks over a
  console; its checks are `mac_demo.zig`'s `check` (exit code and pieces of each stream). The
  assertions on the log (`m6b.4`) and the owner (`m6b.3`) are shell tests.
- The Mac steps do not run the agent test, the upgrade test, the cap or the removal of a log
  with its record: they do not depend on the platform (the Linux `zbx` in the machine is the same
  program, and `demo-m6b` proves them in CI).
- **A `zbx.lock` in the home directory** (above) is a trap for a developer who runs `pull` at
  the top of the home; it is the lock's rule on Linux too, and is not changed in this slice.

