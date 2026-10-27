# Decisions

These are decisions the owner has made ahead of the milestone that needs them. Each one goes into that milestone's brief when the brief is written. Newest first.



## M4 · Pull: the lockfile, the top-20 check, and /sys

*Decided 2026-10-27.*

- **`zbx.lock` lives in the project directory**: the nearest one up from the working directory, as with `Cargo.lock`. `zbx pull` adds or updates the entry for the tag. `zbx run <tag>` runs the locked digest and refuses, naming both digests, when the lock and the store disagree; it never re-pulls silently. Without a lockfile, `run <tag>` resolves the tag and writes one. Live doc rev 53.
- **The top-20 acceptance check runs weekly and on demand**, in its own workflow. `demo-m4` on every PR uses only alpine and the two python images, from a cached blob store. M4 is demonstrated once both the `demo-m4` job and one top-20 run are green, with the run linked.
- **`/sys` is the host's, bound read-only**, until M5 gives each container its own network namespace and a real sysfs can be mounted. Podman does the same when running rootless without its own netns. It shows the host's network devices; that leak is recorded in `docs/demos/m4.md` and closes in M5.

## M3 · The store: whole-file objects, per-user, gc by plan hash with a trash

*Decided 2026-10-26.*

The spec's two M3 open questions are settled (live doc rev 52), and so is how much of "Agent operability" lands with the first deletion.

- **Whole files, with chunk lists.** One object per file, hashed with BLAKE3 and stored whole, so a container's lower directory can be a hardlink farm with no copy. Each object also records fixed-size chunk hashes, so Zigcube's C2 can fetch and verify pieces by hash. Content-defined chunking is a later change behind the same interface.
- **Per-user.** The store lives in the user's data directory, written from inside the user's own namespace so ownership round-trips. No shared or system store until Zigcube's node agent needs one.
- **gc is plan, confirm, trash.** `zbx store gc` prints a plan and its hash; only `--confirm <hash>` acts, and it refuses if the store changed since. What it removes goes to a time-limited trash, and `zbx store restore` brings it back.
- **The upgrade test pins a commit.** No release is tagged yet, so M3's upgrade test builds the merged M2 commit `95ba1da` as "the previous release". It switches to the tag once one exists.

## M2 · Zigcube's agent runs each container under a `zbx` supervisor process

*Decided 2026-10-26.*

`zcube-agent` never calls `start` and `wait` in its own process. For each container it starts a detached run, and a `zbx` process supervises that container: it is single-threaded, calls `start` and `wait`, stays the container's parent, and writes the exit reason to the run record. The agent links the `zigbox` module for everything else: starting a detached run, `list`, `inspect`, `stop` and the event stream. This is the "detached run is `start` without `wait` in a supervisor process that is not the caller" already sketched at the top of `src/runtime/run.zig`.

**Why:**

- Only a process's parent can collect its exit status. If the agent were the parent, an agent restart would lose the exit code of every container that was re-adopted, and of every container that exited while the agent was down. Zigcube's HANDOFF requires re-adoption after an agent restart, and `zcube why` needs real exit reasons.
- The agent is multi-threaded (HTTP, watches, reconciliation). `start` asserts a single-threaded caller, and `wait` forwards the caller's HUP, INT, QUIT and TERM to the container, so a restart of the agent would signal every container. A supervisor keeps both rules exactly as M1 built them.
- The cost is one small `zbx` process per container. Zigcube's "no shims" principle gets a recorded exception: the supervisor is `zbx` itself, not a separate shim binary or daemon.

**What M2 slice 4 delivers for it:**

- A library call that starts a detached run and returns once the command has started (as `zbx run -d` does), reporting a refused start as a `Diag` in the caller.
- The supervisor survives the agent: its own session, outside the agent's process group, and inside the container's transient scope rather than the agent's systemd unit, so stopping or restarting the agent's unit does not kill it.
- The run record is the source of truth for the exit reason, and it names the supervisor's PID. If the supervisor itself dies, the container ends as `lost` with a diagnostic that says so, and the scope is cleaned up.
- `list`, `inspect`, `stop`, re-adoption by name and the event stream work from a multi-threaded caller that is not the container's parent: per-caller storage, and no process-wide state (such as `host_real.zig`'s `errno_last`) on those paths.

**Points the slice must settle:**

- Whether the library starts the supervisor by executing a `zbx` binary (its path given by the caller) or by forking and calling `start` in the child. Executing `zbx` keeps the supervisor a known, single-threaded, versioned program; forking avoids depending on a binary path.
- How `stop` reaches the container: signal the supervisor, which forwards with M1's rule, or signal the container's PID 1 through its pidfd.

## M2 · Zigcube's diagnostic codes plug into Zigbox's diagnostics

*Decided 2026-10-26.*

Zigcube uses Zigbox's diagnostics machinery instead of keeping its own, and adds its own `ZC-` codes to it. A runtime failure on a node must reach `zcube why` intact, and both products must render diagnostics identically (DIAGNOSTICS.md, "Same model everywhere"). Today `Diag` is typed to the `ZBX-` code registry and the renderer hard-codes `ZBX-`, so a second registry cannot plug in.

**What changes:** a second product's registry plugs into the `Diag` data and the renderer without forking them. Zigcube's proposal (its `docs/diagnostics-plan.md`, option D) is a plain `Diagnostic` data type with JSON write and parse, and a `render` that takes a `Diagnostic` plus a product record (code prefix, command name, report URL, docs base) instead of a `*const Diag`. Each product keeps its own collector and registry. Settle the exact shape in the brief.

**When:** with the library slice (4), or a small slice just before it, so that the agent can carry `ZBX-` and `ZC-` diagnostics side by side from its first link.

## M2 · How a container gets its cgroup: the systemd user manager over D-Bus, wire protocol in Zig

*Decided 2026-10-24.*

The spec puts each container in "a transient systemd user scope". `zbx` asks the user's systemd manager for that scope by speaking the D-Bus wire protocol itself, written in Zig with the standard library only. It does not link libsystemd or libdbus, and it does not run `systemd-run` or `busctl`.

**Reference design:** runc's systemd cgroup driver, [docs/systemd.md](https://github.com/opencontainers/runc/blob/main/docs/systemd.md). Follow it unless a specific point does not suit Zigbox. Each departure goes in the M2 brief with its reason. What we take from it:

- One transient `.scope` unit per container, created with `StartTransientUnit` on the user manager (`org.freedesktop.systemd1`). It sets `Slice=`, `Delegate=true`, and accounting for CPU, IO, memory and tasks.
- Limits are set as unit properties where systemd supports them on cgroup v2: `MemoryMax` for `--memory`, `TasksMax` for `--pids`, and `CPUQuota`/`CPUWeight` for CPU. Anything systemd cannot express is written to cgroupfs inside the delegated scope.
- Properties are only set when the running systemd version supports them.

**Points the M2 brief must settle:**

- **OCI-only parts.** runc's `cgroupsPath` syntax (`slice:prefix:name`) and its `org.systemd.property.*` annotations exist because runc takes an OCI `config.json`. `zbx` has no such input, so it probably drops both and picks its own unit naming (for example `zbx-<container id>.scope`).
- **Wire-protocol scope.** The user bus address comes from `DBUS_SESSION_BUS_ADDRESS`, falling back to `$XDG_RUNTIME_DIR/bus`. Authentication is SASL `EXTERNAL`. Marshalling covers only the types the calls need. The client waits for the `JobRemoved` signal before it moves the child into the scope.
- **Limits.** Message size, property count and the reply timeout are bounded, with the limits in `constants.zig`. The protocol parser gets a seeded fuzzer like the other parsers.
- **Failures.** Each failure (no user bus, auth refused, job failed, unit already exists) becomes an `E02xx`/`E03xx` diagnostic that names its cause.
- **Doctor.** Should `zbx doctor` probe the user bus as part of the cgroup check?
