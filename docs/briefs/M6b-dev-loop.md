# Brief: M6b · Dev loop

Read these first:
- `AGENTS.md`, `REVIEW.md`, `docs/STYLE.md` and `DIAGNOSTICS.md`.
- The M6b section of `docs/SPEC.md` (live doc rev 68), and "Non-goals" (no Compose equivalent: more than one service is Zigcube's).
- `docs/DECISIONS.md`: the "Local dev" entry (the guardrails and the ownership rule are decided there), the M6 entry, and the M4b entries on forwarding and files (slices 2 and 3).
- `docs/demos/m6.md` (mounts, the run record, the detached supervisor) and `docs/demos/m4b.md` (how the macOS zbx forwards commands, and the virtiofs share of the home directory).

Do not start M7. Nothing here runs more than one container, schedules anything or restarts anything: that is Zigcube's. `demo-m0` to `demo-m6`, the top-20 check, and the Mac demos must keep passing.

## Goal and demo (from the spec, live doc rev 68)

A developer edits code on the host and sees it run in a container, with no Docker.

1. `zbx run -d --name web --publish 8000:8000 --mount ./site:/srv python:3.12-slim -- python -m http.server -d /srv 8000`.
2. `curl localhost:8000/index.html` returns the page. Edit `./site/index.html` on the host; the next `curl` returns the edit.
3. `zbx exec web -- sh -c 'echo made-inside > /srv/new.txt'`; on the host, `ls -l site/new.txt` shows the presenter's user as its owner.
4. `zbx logs web` shows the two requests.
5. A writable mount outside the guardrails is refused, naming the rule.

Acceptance criteria:
- Files the container writes through a writable mount are owned by the host user. A writable mount for a container whose user is not root is refused, naming the user and the fix, so no file owned by a subordinate id ever lands in the project.
- Logs are bounded, survive the exit of the zbx that started the container, and are removed with its run record.
- `exec` joins the container's namespaces, cgroup, capabilities and seccomp; it gains nothing the container lacks.
- The production-readiness checklist: an upgrade test against M6 (`bf57ec8`, the merge of PR #12), stable diagnostics, documented failure modes, and the agent test.
- On the Mac, the same demo passes driven from macOS (slice 6).

## Fixed decisions

### Writable mounts: `--mount HOST:CTR`

- **Only under the project directory**: the directory that holds the nearest `zbx.lock` up from the working directory (found as `zbx run` finds it), else the working directory. `HOST` may be relative to the working directory. It is resolved with every symlink followed, and the resolved path must be the project directory or inside it: `--mount ../other:/x`, a symlink inside the project that points out of it, and `/` are refused with one line naming the project directory and the rule. It must exist and be a directory or a regular file; it is never created.
- **Ownership: written as the container's root.** The container's root is the host user, so what it writes is the host user's. The run's user is the image's `user`, or `--user` (below). If that user is not root (uid 0), a writable mount is refused before the container is made, naming the user and two fixes: `--user 0`, or `--bind` for a read-only mount. zbx never creates files owned by a subordinate id in the project. The rejected alternatives and why are in `docs/DECISIONS.md`; don't build them.
- **`zbx doctor` reports, but does not use, id-mapped mounts**: a `W`-level line or a detail of an existing check saying whether the kernel lets this user make an id-mapped mount of the project's file system (`mount_setattr` with `MOUNT_ATTR_IDMAP` on a detached `open_tree` clone, in a scratch namespace). It changes nothing; it keeps the door open with a fact.
- **The rest of the mount rules hold**: the shared target rules (absolute, no `..`, no duplicates, nothing over `/proc`, `/sys`, `/dev` or a generated `/etc` file), the count of mounts in `constants.zig`, and a mount point never in `zbx commit` (as `--bind` and `--secret`). The run record and `run --output json` list each writable mount's host path and target, additive.
- **On the Mac** the home directory is shared over virtiofs with one owner, so writes land as the Mac user whatever the container user. Keep the same rule there anyway (one behaviour on both platforms), and note it in `docs/demos/m6b.md`. A project outside the home is already refused on the Mac (`ZBX-E1013`).

### `--user USER[:GROUP]`

- A name or a number, resolved against the image's `/etc/passwd` and `/etc/group` as the image's own `user` is today (`src/image_user.zig`); overrides the image's `user`. A name the image does not have is a coded error naming the image. `--user 0` is how a developer runs a non-root image with a writable mount.

### `zbx logs NAME [--follow] [--tail N]`

- **What is kept.** Every container's standard output and error, detached or foreground, written into `logs/<name>.log` beside the run record as framed records (stream, time, bytes), so that the order of the two streams and the time of each line survive. A detached container's supervisor writes it; a foreground `zbx run` writes it as it copies the output to the terminal, which it still does unchanged. A run whose log cannot be written still runs, and says so once.
- **Bounded.** 5 MiB per container, a constant in `constants.zig`. At the cap the oldest records are dropped as whole records, never a torn one, and the reader says how many bytes were dropped. Removed with the run record, on every path that removes it.
- **Survives zbx.** The supervisor of a detached run owns the file, so the `zbx` that started it may exit; a crash of the writer (the supervisor, or a foreground `zbx`) leaves a readable log up to its last whole record.
- **Reading.** Text by default: the bytes as written, both streams in order (`--stream stdout|stderr` filters). `--tail N` the last N lines. `--follow` waits for more until the container ends, then exits 0. `--output json`: one `zbx.logs/1` record per line (`stream`, `time`, `text`, and `dropped_bytes` where the cap cut), with a schema. A container that does not exist is a coded error with a fix. `--follow` on a foreground run that is still going works as on a detached one.

### `zbx exec NAME [-e ...] [--user ...] [--workdir DIR] -- COMMAND...`

- **Joins, gains nothing.** A child of `zbx` joins the running container's user, mount, PID, UTS, IPC and network namespaces (`setns`, in the order the kernel requires; the user namespace is the caller's own, so no privilege is needed), moves into the container's cgroup (its scope, or the cgroupfs child of M4b's driver), drops to the container's capability set, sets `no_new_privs`, and loads the container's seccomp filter, all in a single-threaded child before `execve`, like `run`. It never runs with more than the container has; a test proves each (a capability the container lacks, a syscall its filter refuses, a limit it is under).
- **Environment and user.** The container's environment (the image's plus `-e`), its working directory and user by default; `-e`, `--user` and `--workdir` override for that process only.
- **Streams and exit.** Standard streams pass through; with a terminal on stdin, a pseudo-terminal, with its size kept and resized; signals forwarded as `run` does; the exit code is the command's, with `zbx`'s own codes for its refusals (the same ranges as `run`). `--output json` ends with an `exec_exit` line (`schema`, additive).
- **Its lifetime.** An exec'd process is inside the container's PID namespace, so it dies with the container. `exec` into a container that is not running is a coded error naming its state.
- **Not recorded as a container.** `ps` does not list exec'd processes; `bundle` of the container notes recent execs (command and exit, never the environment's values).

### In the library, and on the Mac

- Writable mounts, `--user`, logs, exec and pull go into the `zigbox` module the same way `run` does, with per-caller storage and no process-wide state, so Zigcube's agent can use them (its `Runtime` interface will follow).
- **The Mac** forwards `logs` and `exec` like the other Linux commands (`src/mac/forward.zig`), including the terminal and signals for `exec` and `--follow`. That is slice 6, for the session on the owner's Mac.

### Pull in the library

- **Decided (2026-10-30):** pull moves into the `zigbox` module, so Zigcube's agent can fetch an image without shelling out to `zbx` (its restart orders, `docs/restart.md` in the zigcube repository, call it `ensure_image`).
- What it takes and gives: a reference (tag or digest), a platform, and the caller's store; it pulls, verifies, flattens into the store and writes the image record exactly as `zbx pull` does, and returns the manifest and tree digests. It does not touch a `zbx.lock`: the lock is a project's file, which the CLI keeps writing around the library call.
- Per-caller storage, no process-wide state, bounded memory, the same timeouts, mirrors (`ZBX_REGISTRY_MIRRORS` read by the caller and passed in, not read inside), and every failure the same coded diagnostic as today. A progress callback the CLI uses for its output and Zigcube may ignore.
- `zbx pull` becomes a thin caller of it; its output and JSON do not change (the goldens prove it).
- A test that drives the library from a caller other than the CLI, and the demo's agent test unchanged.

### Diagnostics

Usage and mount refusals are `00xx` or `02xx`, whichever group fits the existing ones; logs and exec failures are `02xx` (runtime). Each with a cause, a fix, goldens and an error page; don't reuse taken codes (`src/diag/codes.zig`).

## Slices (commit and stop for review after each; do not push to the working branch)

1. **Writable mounts and `--user`.** `--mount` with the project-directory rule (symlink escape tested), the root-only rule with its refusal, `--user`, the doctor id-mapped-mount line, the record and JSON fields, and the `cli`, `run` and `record` fuzzers extended. VM check (demo-m6 can hold a temporary part): python's `http.server` serving a mounted directory, an edit on the host seen by the next request, a file written inside owned by the host user, and the refusals.
2. **`zbx logs`.** The framed log, written by the supervisor and by a foreground run, the cap, removal with the record, `--tail`, `--follow`, `--stream`, `--output json` and its schema; a `logs` fuzzer over the framed format (damage and re-read). VM check: a detached server's requests in the log, the log after the starting `zbx` was killed, the cap.
3. **`zbx exec`.** Joining, the pseudo-terminal, signals, exit codes, and the tests that it gains nothing; `exec` in the library. VM check: `exec` writes a file, `exec` of a refused syscall and of a missing capability fail as in the container, `exec` into a stopped container is refused, an exec'd process dies with the container.
4. **Pull in the library.** The section above; `zbx pull` on top of it with unchanged output; a test from a second caller; the `registry` and `layer` fuzzers still at 10,000 iterations. VM check: demo-m4 unchanged and green.
5. **VM, CI and the agent test.** `zig build demo-m6b` with the spec's five steps exactly, every assertion a unit-tested pure function; the acceptance checks; the agent test by JSON only; the upgrade test against M6 (`bf57ec8`); the `demo-m6b` CI job and `m6b` in `vm.yml`'s picker; `docs/demos/m6b.md` with the by-hand steps, cuts and failure modes (a mount outside the project, a symlink escape, a non-root image, a log at its cap, exec into a stopped container, the disk full while logging).
6. **The Mac** (for the session on the owner's Mac, after slice 5 merges): `logs` and `exec` forwarded, `demo-m6b`'s steps on `mac.yml`, and the Mac notes in `docs/demos/m6b.md`.

The slices run one after another, in order.

## Done means

- All gates pass (`zig build check`), and every fuzzer you touched or added runs at 10,000 iterations.
- `demo-m6b` is green in CI, with `demo-m0` to `demo-m6` still green, and slice 6's Mac run green on `mac.yml`. Until then M6b is "built, not demonstrated".
- Your report lists what you ran and its output, what you did not run and why, which REVIEW.md items you touched, every deviation from this brief, and anything in the spec, this brief or `DIAGNOSTICS.md` that seemed wrong.
