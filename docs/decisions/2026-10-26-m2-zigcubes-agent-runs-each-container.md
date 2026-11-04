# M2 · Zigcube's agent runs each container under a `zbx` supervisor process

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
