# Decisions

These are decisions the owner has made ahead of the milestone that needs them. Each one goes into that milestone's brief when the brief is written. Newest first.

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
