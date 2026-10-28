# Zigbox: A First-Principles Container Runtime in Zig

Snapshot of https://claude.ai/artifact/6D9js8mxSLYmfuZe3rQ26w taken 2026-10-28 (doc rev 60), Parts I to III. The live doc is authoritative; update this file when it changes. The three diagrams in the live doc are listed as figure notes, not reproduced.

## Purpose and design principles

Zigbox is a Linux container runtime, image store and builder written in Zig, designed as if Docker were being invented today. It is a learning-and-showcase build: every milestone must end in something a person can watch work in under five minutes.

The opinions it encodes, in priority order:

1. **Rootless and daemonless.** No privileged daemon, no root socket. Every command is an ordinary process run by the user. Privilege comes only from user namespaces and the standard setuid helpers (`newuidmap`, `newgidmap`).
2. **Content-addressed files, not stacked layers.** Images are Merkle trees of file chunks hashed with BLAKE3. Identical files dedupe across all images; deleting a file shrinks the image; identity is a digest, never a mutable tag.
3. **Hermetic, reproducible builds.** Build steps form a DAG with declared inputs, no network unless a step asks for it, and a cache keyed on input content rather than on the text of the instruction.
4. **Secure by default.** Capabilities default-deny, seccomp on, `no_new_privs` on, network off unless granted. Isolation strength is a stated choice, not an accident.
5. **Separable tools.** Run, store and build are distinct subsystems with narrow interfaces, even if they ship as one binary.
6. **The thirty-second experience survives.** `zbx pull alpine && zbx run alpine sh` must be as easy as Docker. Principles that make the first run painful are wrong.

Why Zig: namespace setup (`clone3`, `unshare`, `setns`, `pivot_root`) must happen in a single-threaded process. Go's runtime forces runc to carry a C shim for this; Zig has no hidden runtime, calls syscalls directly through `std.os.linux`, needs no libc, and produces small static binaries.

## How to read the milestones

A milestone is done when its demo script runs live, start to finish, on a clean test VM, in front of someone who did not write the code. Passing unit tests is necessary but not sufficient.

Each milestone below has four parts:

- **Goal**: the one capability it adds, in a sentence.
- **Scope**: what to build, and what is deliberately deferred.
- **Demo script**: the exact commands a presenter types and what the audience should see. The implementer turns each script into an automated integration test (`zig build demo-mN`) that asserts the same outputs.
- **Acceptance criteria**: checkable conditions, including failure behaviour.

Ground rules for the implementer:

- Each milestone ships as a tagged release with a `DEMO.md` that a stranger can follow.
- Error messages are part of the demo. Every failure follows the diagnostics standard below, from M0 onward.
- Never break an earlier demo. All prior `demo-mN` tests run in CI on every change.
- When a milestone's scope is in doubt, cut scope and keep the demo.
- Production-ready from the start. From M1 on, every milestone's acceptance criteria include the production-readiness checklist below: an upgrade test, stable diagnostics, documented failure modes.

## Milestone map

*Figure: milestone map · 9 milestones, 3 tracks (diagram in the live doc, node 24eb2c38-a0d5; not reproduced here).*

M0 to M2 make a hardened runtime; M3 and M4 add the store and real images, which unlocks networking and state (M5, M6) and hermetic builds and signing (M7, M8). M7 steps also reuse the M2 sandbox.

## Milestones

### M0 · Doctor: the host is ready

**Goal:** a binary that tells you, truthfully, whether this machine can run Zigbox.

**Scope:** `zig build` project layout, CLI skeleton, CI, a QEMU test VM with a pinned kernel and distro. `zbx doctor` probes for unprivileged user namespaces, cgroup v2 with user delegation, overlayfs in user namespaces, subuid/subgid ranges, and seccomp support.

**Demo script:**

1. On the test VM, run `zbx doctor`. Every check prints `ok` with the detected value (kernel version, cgroup controllers delegated to the user).
2. Disable unprivileged user namespaces with `sysctl`, run `zbx doctor` again. That check fails with a one-line fix.
3. Run `file zbx` to show a single static binary with no libc dependency.

**Acceptance criteria:**

- [ ] Static binary under 4 MB for x86_64 and aarch64, cross-compiled from one machine. (Under 2 MB until M4, whose TLS client, gzip, zstd and tar pushed one `ReleaseSafe` binary past it; assertions stay on rather than shipping a smaller build mode.)
- [ ] Each failing check names the fix (sysctl key, package, or kernel version).
- [ ] CI boots the VM and runs `demo-m0`.

### M1 · Shell: a rootless, isolated process

**Goal:** run a shell inside an unpacked root filesystem, with no root privileges, isolated from the host.

**Scope:** `clone3` with user, mount, PID, UTS and IPC namespaces; UID/GID maps (single-UID mapping first, then a full subuid range via `newuidmap`); bind-mounted rootfs, `pivot_root`, fresh `/proc`, minimal `/dev`; exit-code propagation and signal forwarding. Input is a plain directory (an Alpine minirootfs tarball unpacked by hand). Deferred: images, limits, networking.

**Demo script:**

1. As an ordinary user, run `zbx run --rootfs ./alpine -- /bin/sh`.
2. Inside: `id` shows `uid=0(root)`; `ps` shows only PID 1 and `ps`; `hostname` shows the container name; `cat /etc/os-release` shows Alpine.
3. In a second host terminal: `ps -o user,pid,cmd` shows the shell running as the presenter's own UID.
4. Inside: `touch /etc/hacked`. On the host, `ls ./alpine/etc/hacked` shows it landed only in the rootfs, nowhere else.
5. Inside: `exit 42`. On the host, `echo $?` prints `42`.
6. Run `zbx run --rootfs ./alpine -- sleep 1000`, press Ctrl-C: it stops immediately.

**Acceptance criteria:**

- [ ] No setuid bit on `zbx`; works with the setuid `newuidmap` only.
- [ ] Host mounts and processes are invisible from inside.
- [ ] Namespace setup happens before any thread is spawned (assert in debug builds).
- [ ] Diagnostic bundles: `zbx bundle [--last | <container>]` and an automatic bundle on every bug diagnostic, redacted by default, with the CI redaction check from the diagnostics standard.

### M2 · Limits: contained and hardened

**Goal:** a misbehaving container cannot take down the host or regain privilege.

**Scope:** cgroup v2 limits for memory, CPU and PIDs inside the user's delegated cgroup (a transient systemd user scope); capabilities dropped to a minimal allowlist; a default seccomp filter; `no_new_privs`; read-only rootfs option. Exit reasons reported in plain words.

**Demo script:**

1. `zbx run --rootfs ./alpine --pids 64 -- sh -c 'b(){ b|b& }; b; wait; sleep 3'`. The fork bomb stalls; the host stays responsive; `zbx` exits reporting the PID limit. (The classic `:(){ :|:& };:` cannot be used: Alpine's `sh` rejects `:` as a function name. `wait` alone is not enough either: it waits only for PID 1's own jobs, which fork and exit at once, so PID 1 would end before the tree reaches 64; the `sleep 3` keeps it alive while the bomb grows.)
2. `zbx run --rootfs ./alpine --memory 128m -- stress-ng --vm 1 --vm-bytes 512m --oomable`. Output ends with `killed: out of memory (limit 128 MiB)`. (Without `--oomable`, stress-ng restarts its worker after every out-of-memory kill and runs for its default day.)
3. `zbx run --rootfs ./alpine -- mount -t tmpfs none /mnt` fails with `operation not permitted`.
4. `zbx run --rootfs ./alpine --read-only -- touch /x` fails; `touch /tmp/x` succeeds (tmpfs).

**Acceptance criteria:**

- [ ] Limits are visible in `/sys/fs/cgroup` under the user's slice while running and gone after exit.
- [ ] Seccomp profile is a checked-in, reviewed file, not an inline list.
- [ ] OOM, PID-limit and signal exits are distinguished in the exit report.

### M3 · Store: content-addressed file trees

**Goal:** root filesystems live in a deduplicated, verifiable store and are run by digest.

**Scope:** `zbx store import <dir>` walks a tree, chunks files, hashes with BLAKE3, and writes a Merkle tree of directories; the root hash is the tree's identity. Materialize for running as a read-only lower directory (hardlink farm from the store) plus a per-container writable upper via overlayfs. `zbx commit` turns a container's changes into a new tree digest. `zbx store verify` and `zbx store gc`.

**Demo script:**

1. Import `./alpine`; note its digest and `zbx store du` total.
2. Copy the rootfs, add one 10 MB file, import the copy. `zbx store du` grows by about 10 MB, not by a second full rootfs.
3. `zbx run <digest> -- sh`, install a package with `apk add`, exit, then `zbx commit`. A new digest prints; `zbx store diff <old> <new>` lists only the added files. From M5 on, the run adds --net host so that apk can reach its mirror, since a container has no network unless granted.
4. Corrupt a chunk on disk by hand. `zbx store verify` names the damaged file and every tree that references it.
5. Delete a file in a committed tree: the new tree's stored size drops (no whiteout baggage).

**Acceptance criteria:**

- [ ] Importing the same directory twice yields the same digest, independent of mtime and import order.
- [ ] File modes, ownership, xattrs and symlinks round-trip.
- [ ] Running a container never writes into the shared store.

### M4 · Pull: real images run

**Goal:** pull a public OCI image and run it, with the store doing the deduplication across images.

**Scope:** registry client for anonymous pulls (Docker Hub token dance, GHCR); manifest index platform selection; gzip and zstd layer decode; tar extraction with whiteout handling, applied into the M3 store as one flattened tree; image config (entrypoint, env, working dir, user) honoured at run. Tags resolve to digests, recorded in a lockfile `zbx.lock` in the project directory (the nearest one up from the working directory, as with `Cargo.lock`); `zbx pull` writes it, and `zbx run <tag>` runs the locked digest. Until containers get their own network namespace (M5), `/sys` is the host's, bound read-only. Deferred: push, private registries.

**Demo script:**

1. `zbx pull alpine:3.20` prints the resolved digest.
2. `zbx run alpine:3.20 -- cat /etc/os-release`.
3. `zbx pull python:3.12-slim` then `zbx pull python:3.13-slim`. `zbx store du --by-image` shows the second costs the store less than its compressed size, because most of its stored bytes are files it shares with the first, and those are stored once.
4. `zbx run python:3.12-slim -- python -c 'print(2**100)'`.
5. Change the tag in `zbx.lock` to a wrong digest: `zbx run` refuses, naming the expected and actual digests.

**Acceptance criteria:**

- [ ] Top 20 official Docker Hub images run their default command (or a documented reason they cannot rootless).
- [ ] Every image is identified internally by tree digest; tags are aliases only.
- [ ] Interrupted pulls resume without re-downloading completed blobs.

### M4b · Mac: the thirty seconds on macOS

**Goal:** a Mac user goes from `brew install zigbox` to a running container with no setup step.

**Scope:** a macOS `zbx` for Apple Silicon that drives a pinned, minimal Linux VM through Apple's Virtualization.framework. The VM is a small kernel plus an initramfs carrying the Linux `zbx`, booted lazily on the first command and stopped when idle; one VM per user, not per container (per-container microVMs stay stretch S1). Commands are forwarded over vsock; the user's home directory is shared with virtiofs, so `--rootfs` paths, state volumes and build contexts work unchanged; Rosetta runs `amd64` images. Inside the VM, Zigbox is unchanged and fully rootless. `zbx doctor` on macOS checks the VM, its version, file sharing and disk space. Distributed as a signed, notarized Homebrew formula; an Apple Developer ID and the virtualization entitlement are prerequisites. The macOS binary links libSystem, as macOS requires; the no-libc rule applies to the Linux binaries. Published ports arrive with M5, whose acceptance criteria then cover the Mac too. Deferred: Intel Macs, Windows, a GUI.

**Demo script:**

1. On a clean Mac: `brew install zigbox`.
2. `zbx run alpine -- cat /etc/os-release` prints Alpine. The first run, VM boot included, takes under five seconds on Apple Silicon.
3. `zbx run --rootfs ~/demo/alpine -- touch /hello`; on the Mac, `ls ~/demo/alpine/hello` shows the file.
4. Leave it idle past the idle timeout: Activity Monitor shows no VM. The next `zbx run` brings it back.

**Acceptance criteria:**

- [ ] Nothing to set up between `brew install` and the first `zbx run`, and no administrator password prompt.
- [ ] The macOS binary is signed and notarized; Gatekeeper shows no warning.
- [ ] The M1 to M4 demos pass unchanged inside the VM, driven from macOS. If hosted macOS CI runners cannot nest virtualization, this runs on a self-hosted Apple Silicon runner.
- [ ] Every failure in the VM layer is a coded diagnostic with a fix, in a new code group added to DIAGNOSTICS.md (both repos) when M4b starts.

### M5 · Network: access as an explicit grant

**Goal:** a container has no network unless granted, and a granted service is reachable from the host.

**Scope:** `--net none` as the default (loopback only); `--net host`; rootless user-mode networking via `pasta` (from the passt project) for `--publish HOST:CONTAINER`; a generated `/etc/resolv.conf` and `/etc/hosts`. Publishing a port implies user-mode networking. A run on the default network that fails gets a one-line hint naming the grant. M5 also closes M4's agent-interface gaps: a JSON form of explain, a read-only view of the lockfile, and a run result that names what ran. Deferred: container-to-container networks and egress allowlists (see stretch goals).

**Demo script:**

1. `zbx run alpine -- wget -qO- https://example.com` fails: `network: none (grant with --net)`.
2. `zbx run --net user alpine -- wget -qO- https://example.com` prints the page.
3. `zbx run --publish 8080:80 nginx` in one terminal; `curl localhost:8080` on the host returns the nginx welcome page.
4. `ss -tlnp` on the host shows the listener owned by the presenter's user, and `sudo iptables -S` shows no rules added.

**Acceptance criteria:**

- [ ] No host firewall or routing changes, ever.
- [ ] `pasta` absence is caught by `zbx doctor` and by a clear error at run.
- [ ] Published ports are released when the container exits, including on crash.

### M6 · State: durable data is declared

**Goal:** data that must outlive a container is named, typed and listed, never an anonymous directory.

**Scope:** named state volumes (`--state pgdata:/var/lib/postgresql/data`), ephemeral tmpfs mounts, read-only bind mounts from the host, and read-only secret files mounted from a host path at run. `zbx state ls`, `zbx state rm`, `zbx state export` to a tarball. UID mapping handled so the container's user owns its state.

**Demo script:**

1. `zbx run --state pgdata:/var/lib/postgresql/data --publish 5432:5432 -e POSTGRES_PASSWORD=demo postgres:16`.
2. From the host, `psql` in, create a table, insert a row.
3. Kill the container. Start it again with the same command; the row is still there.
4. `zbx state ls` shows `pgdata`, its size and the last container that used it.
5. Run without `--state`: data is gone after exit, as advertised.

**Acceptance criteria:**

- [ ] State volumes live outside the content store and are never garbage-collected implicitly.
- [ ] Ownership inside the container is correct without `chmod 777` workarounds.
- [ ] Secret mounts are read-only and excluded from `zbx commit`.

### M7 · Build: hermetic and reproducible

**Goal:** build images from a declared DAG of steps, so the same inputs always produce the same digest.

**Scope:** a build file (format is an open question below) declaring steps, each with a base tree, input files or prior step outputs, a command, and an optional `network: true`. Each step runs as an M2-hardened container with network off by default; its output tree goes into the store; its cache key is the hash of its inputs plus command. Timestamps normalized; independent steps run in parallel. Deferred: Dockerfile import (stretch).

**Demo script:**

1. Build a small Zig or Go hello-world image: `zbx build`. Note the final digest and the step timings.
2. Run `zbx build` again: every step is a cache hit, completes in under a second.
3. Edit a README that no step declares as input: no rebuild, same digest.
4. Edit the source file: only the compile step and its dependents rebuild; the cache report shows hits and misses per step.
5. On a second clean VM, build from the same commit: identical digest.
6. Add a step that runs `curl` without `network: true`: it fails, naming the step and the grant needed.

**Acceptance criteria:**

- [ ] Bit-for-bit reproducible digest across two machines for the demo project.
- [ ] Cache keys depend on content, never on file mtimes or step text order alone.
- [ ] `zbx build --graph` prints the step DAG.

### M8 · Trust: signed, with provenance

**Goal:** a host can refuse to run anything it cannot trace back to a trusted key and a recorded build.

**Scope:** ed25519 keys (`zbx key new`); `zbx sign <digest>`; a provenance record emitted by M7 builds (input digests, build file hash, builder version) stored beside the tree; a run policy file (`trusted keys`, `require signature`, `require provenance`). Deferred: Sigstore integration, transparency logs.

**Demo script:**

1. Build and sign an image. `zbx inspect --provenance <digest>` shows its inputs and builder.
2. Enable policy `require signature`. Running the signed image works; running an unsigned `alpine` is refused, naming the policy rule.
3. Tamper with one file in the stored tree. `zbx run` refuses: the tree digest no longer matches the signature.
4. `zbx verify <digest>` walks from the signature to every input, offline.

**Acceptance criteria:**

- [ ] Signatures are over tree digests, so they survive re-pulls and re-materialization.
- [ ] Policy refusals happen before any process starts.

### Stretch milestones

Each keeps the same demo-first contract; none blocks M0 to M8.

- **S1 · MicroVM isolation:** the same image runs under a Firecracker or Cloud Hypervisor backend with `--isolation vm`; demo shows a kernel exploit test passing in namespace mode and contained in VM mode.
- **S2 · Lazy start:** start a large image before its files are local, fetching chunks on first read; demo starts a multi-GB image in seconds.
- **S3 · Container networks and egress grants:** `--allow db:5432`, `--egress api.example.com:443`; demo shows an allowed call succeed and a disallowed one refused.
- **S4 · Dockerfile import:** translate a common Dockerfile into the M7 build format, flagging non-hermetic steps.
- **S5 · WASM workloads:** run a WASI component through the same CLI, store and policy.

## Diagnostics: designed from the first commit

Failures are a product surface, not an afterthought. The full standard is `DIAGNOSTICS.md` in both repos; the essentials:

- **Coded, short, causal.** Every user-facing failure has a stable code (`ZBX-E0101`, `ZC-E0203`), a one-line summary, the real cause (not the last symptom), and a runnable fix. Never a raw stack trace or a bare Zig error name.
- **Layered.** Default output is a few lines; `--verbose` adds the cause chain and context; `--output json` gives scripts the same structure; a redacted **bundle** (the kitchen sink) is written automatically only for internal bugs, or on request with `zbx bundle` / `zcube bundle`.
- **Correct blame.** Each diagnostic says whether the cause is the user, the host, an external service, or our bug. Only bugs ask for a report.
- **One model everywhere.** The CLI, the Zigcube API and `zcube why` render the same structure, so a failure on a remote node reads exactly like a local one.
- **In Zig:** functions take a `*Diag` collector alongside their plain error return; text is formatted only at the CLI or API boundary; codes live in one registry checked at build time and generate the docs pages at `site/errors/`.
- **Tested.** Golden tests for every code, demo assertions on codes, and a CI check that no user-facing output contains a stack trace or an unredacted secret.

The M0 acceptance criteria therefore include the diagnostics machinery itself: the registry, `zbx explain` and the output modes. The bundle arrives with M1, the first milestone with containers and state worth bundling.

## Production readiness

Every milestone should leave Zigbox, and later Zigcube, something an operator would choose to run. From M1 and C0 on, each milestone's acceptance criteria therefore include this checklist:

- [ ] **Upgrade test.** CI runs the new binary against state written by the previous tagged release (run records, store, state volumes, the control-plane database), and the previous milestone's demo still passes.
- [ ] **Stable diagnostics.** Every new failure path has a registered code with a fix and golden tests; no existing code changes its meaning.
- [ ] **Documented failure modes.** The milestone's demo document lists what can go wrong in production, how it shows up (code, exit reason or log line) and how to recover.
- [ ] **Agent test (from M4).** CI runs a scripted agent through the milestone's demo using only `--output json`, the MCP tools and `zbx explain`. Anything the agent has to scrape from text or guess is a bug.

Zigbox in production:

- **Upgrades are a file swap.** One static binary and no daemon. From v1, the CLI and the runtime library API (the `zigbox` module Zigcube links) follow semantic versioning, with a published deprecation policy.
- **systemd supervises.** `zbx systemd generate <name>` writes a user unit, so restarts, logs (journald), boot ordering and resource scopes come from systemd, not from Zigbox.
- **Deploy by digest.** Production runs digests from a lockfile, never tags; switching versions and rolling back is one command (from M3 and M4).
- **Observability without a daemon.** Each container has an event log and an exit reason in its run record; `zbx top` shows live cgroup usage; an optional OpenMetrics and OpenTelemetry exporter publishes the same data for a collector.
- **Support.** Coded diagnostics whose pages read as runbook entries, and redacted bundles for bug reports.
- **Trust in zbx itself.** Reproducible release builds, signed releases, an SBOM and a published security response policy: M8's machinery applied to Zigbox.

Zigcube in production:

- **Small to start, able to grow.** One binary on SQLite for a single node; Postgres for high availability. Backup and restore are tested in CI.
- **Upgrades without downtime.** A version-skew policy (agents at most one minor version behind the server), tested on every release.
- **Explainable by design.** `zcube why`, a request ID on every call, and one diagnostic model from node to CLI.
- **Simulation-tested control plane.** Deterministic, seeded simulation of controllers, store and agents, with partitions, lost leases and a crashing store, each failure replayable from its seed.
- **Configuration in git.** Service files are reviewed in pull requests; `zcube apply` shows a diff before it changes anything; every change lands in an audit log.

### Agent operability

Agents (AI or scripts) will drive Zigbox and Zigcube more often than people will. Agents fail in three predictable ways: they guess output formats, they act without previewing, and they retry destructive things. Both projects are built so that none of these is necessary.

Easy for agents to run:

- **Stable, versioned machine output.** Every command's result, not only its failures, is available as `--output json`, with a versioned schema; `zbx schema <command>` prints it. A diagnostic's fix keeps its command separate from its sentence, so an agent can run `fixes[0].command` without parsing prose.
- **Built-in MCP servers.** `zbx mcp` and `zcube mcp` expose typed tools (run, ps, logs, explain, why, apply), generated from the same schemas and the code registry, so agents call tools instead of composing shell lines. Arrives after M4, with the Mac work.
- **Preview before acting.** Commands that change things can show what they would do first: `zbx run --plan` prints the container setup plan, `zcube apply` shows a diff, `zbx store gc` lists what it would delete.
- **Never prompt, never hang.** Without a terminal nothing waits for input: anything that would prompt fails with a coded diagnostic naming the flag that proceeds, and every command takes `--timeout`.
- **Machine-readable docs.** The registry also generates `errors.json` and an `llms.txt`, so an agent learns every code and its fix in one fetch.

Hard to break by accident:

- **Plan, then apply by plan hash.** Destructive commands (`store gc`, `state rm`, deleting applies, rollbacks) print a plan and its hash; only `--confirm <hash>` acts, and it refuses if anything changed since. This stops hallucinated targets, stale assumptions and blind retries. From M3 and M4, when deletion first exists.
- **Undo.** `zbx state rm` and `zbx store gc` move data to a time-limited trash with `zbx restore`; content addressing makes rollback cheap; `zcube rollback` is the documented answer to a failed apply.
- **Idempotent by default.** Repeating a command converges rather than duplicates: `zbx run --name x` when `x` exists is a coded refusal unless `--replace`; `zcube apply` is declarative; ids and digests are never matched by an ambiguous prefix.
- **Limits an agent cannot flag its way past.** A policy file (a minimal form of M8's run policy, brought forward) can deny `--net host`, mounting `$HOME` or unsigned images regardless of flags. Zigcube API tokens are scoped (read-only, or apply to a set of services) and carry quotas, from C0.
- **Attribution.** Every change records who made it (`--actor`, or an environment variable) and a request ID in an audit log, so `zcube why` can say which agent did it. From C0.
- **A place to rehearse.** `zcube apply --simulate` runs the change against the deterministic simulator and reports what would restart, move or fail. From C1.

From M2 on, every new command meets the two cheap rules now: its results have a JSON form with a schema, and it never prompts without a terminal.

## Non-goals

These are out of scope for M0 to M8. Raise a change to this doc before building any of them.

- **Native non-Linux runtimes.** Containers run only on a Linux kernel. On macOS, zbx runs a small Linux VM for the user, invisibly (milestone M4b); there is no native macOS runtime, and no Windows support.
- **Rootful mode.** There is no `sudo zbx`. If something only works as root, it is not supported.
- **Docker API or CLI compatibility.** Commands may resemble Docker's, but no socket API and no drop-in flag parity.
- **Orchestration.** No Compose equivalent, no clustering, no scheduler, no restart policies beyond what a systemd user unit gives.
- **Image push and private registries.** Pull-only from public registries until after M8.
- **Dockerfile execution.** Dockerfiles are not run directly (import is stretch S4).
- **Live migration, checkpoint/restore, GPU passthrough.**

## Technical notes, risks and open questions

### Notes for the implementer

- **Pin the Zig version** in `build.zig.zon` and CI. Zig is pre-1.0 and its standard library changes between releases; upgrade deliberately, between milestones, never during one.
- **Lean on the standard library first.** Zig's std covers raw Linux syscalls, BLAKE3, ed25519, JSON, tar, gzip/deflate, zstd decompression and a TLS client. Verify each is adequate when its milestone starts; add a dependency only with a written reason.
- **Single-threaded until exec.** All namespace work happens in the child before `execve`. Thread pools (pull, build) live only in the parent `zbx` process.
- **Kernel baseline.** Target a recent LTS kernel with unprivileged user namespaces, cgroup v2 delegation and overlayfs mountable inside user namespaces. Ubuntu 24.04 and Fedora 40 or later are reasonable test VMs; some distros restrict unprivileged user namespaces through AppArmor, so `zbx doctor` must detect that.
- **Test in VMs, not containers.** Integration tests boot a QEMU guest so namespace and cgroup behaviour is real.

### Risks

| Risk | Where it bites | Mitigation |
| --- | --- | --- |
| Rootless networking is a deep rabbit hole | M5 | Depend on `pasta` rather than writing a userspace network stack |
| Registry quirks (auth, rate limits, odd manifests) | M4 | Test against a fixed list of images; cache blobs in CI |
| File-level store is slower to materialize than layer unpacking | M3, M4 | Benchmark against the top 20 images at M4; fall back to cached materialized trees |
| Reproducibility leaks (timestamps, file order, locale) | M7 | Two-VM digest comparison in CI from M7 on |
| Zig std churn breaks the build | All | Pinned version; upgrades are their own tagged change |

### Open questions

- [ ] Build file format for M7: ZON (Zig's native object notation), a small Starlark subset, or a typed config language? Decide before M7 starts.
- [x] Chunking for M3, decided: whole files. Each file is one object, hashed with BLAKE3 and stored whole so it can be hardlinked into a container's lower directory. Each object also carries a list of fixed-size chunk hashes, which gives Zigcube's C2 verified fetch-by-hash from the start. Content-defined chunking can come later behind the same interface, for large files that change slightly.
- [x] Store scope, decided: strictly per-user, under the user's data directory, written from inside the user's own namespace so ownership round-trips. A store shared across users would need privileged setup and cross-user trust rules; revisit with Zigcube's node agent.
- [ ] Final project name and CLI name (`zigbox` / `zbx` are placeholders).

## Part II · Zigcube: orchestrating Zigbox

Zigcube runs Zigbox workloads across a fleet of machines. It keeps the one idea Kubernetes got right, declared desired state reconciled by controllers against a watchable store, and rebuilds everything around it to exploit Zigbox's content-addressed images, signatures and explicit grants. Its control plane starts in parallel with Zigbox, against a fake runtime (see When Zigcube starts, below), and keeps the same demo-first contract: every C-milestone ends in a live demo on a small VM cluster.

Principles it adds on top of Part I:

1. **One thin node agent.** `zcube-agent` links Zigbox as a library and runs rootless. No CRI, no containerd, no shims.
2. **Store-aware scheduling and distribution.** The scheduler knows which file chunks each node holds and prefers nodes where most of an image is already local. Nodes fetch missing chunks from peers before the registry.
3. **Trust checked twice.** The control plane admits only digests that satisfy policy; every node re-verifies signature and policy before exec, so a compromised control plane cannot make a node run unsigned code.
4. **Identity-based networking, default deny.** Workloads talk only along declared grants (`web → db:5432`), authenticated by workload identity, not by IP address.
5. **Two layers.** An application primitive (`service`: image, replicas, ports, state, secrets) for most users, compiled down to lower-level placement objects that operators can still touch.
6. **Explainable reconciliation.** Every controller decision is recorded with its cause, so `zcube why <thing>` answers "why is this not running" in one command.
7. **Proven storage for the control plane.** Desired and observed state live behind a narrow, pluggable versioned key-value interface (get, list, compare-and-swap, gap-free watch, leases), backed by an existing database rather than a hand-written one: Postgres first (OrioleDB for the hot observed-state tables), SQLite for development, others such as etcd or FoundationDB if Postgres HA disappoints; the novelty budget goes to the agent, scheduler and distribution.

### Architecture

*Figure: ZigCube architecture · control plane, 3 nodes, registry (diagram in the live doc, node 6ca653d0-61c0; not reproduced here).*

The control plane writes desired state and reads back what agents observe; each node runs one rootless agent over Zigbox and its own chunk store, fetching from peers before falling back to the registry.

### When Zigcube starts

The control plane needs no containers, so it starts on day one behind a `Runtime` interface, developed against a fake runtime that runs plain host processes. The real coupling point is Zigbox M1: from then on Zigbox must expose a stable runtime library API, which the agent links. Each C-milestone waits only on specific Zigbox milestones:

| Zigcube | Needs from Zigbox | Why |
| --- | --- | --- |
| C0 Loop | M2 (for the real runtime) | Exit reasons and cgroup scopes, to tell OOM from crash and re-adopt cleanly |
| C1 Fleet | M2 | Resource fit needs real CPU and memory limits |
| C2 Swarm | M3, and M4 for the demo | Peer fetch and locality are built on the chunk store |
| C3 Rollout | M4 | Health checks and rollouts against real images |
| C4 Mesh | M5 | Builds on Zigbox's network namespaces and grants |
| C5 Edge | C4 | Nothing new from Zigbox |
| C6 Trust | M8 | Node-side signature checks |
| C7 State | M6 | Named state volumes |
| C8 Jobs | M7 | Cluster builds are M7 steps |

The Zigbox M3 store is shared design work: it must expose chunk listings and verified fetch-by-hash from the start, or C2 forces a rework. The coding handoff for C0 and C1 lives in the zigcube repo as `HANDOFF.md`.

### Zigcube milestones

The demo environment is a set of three to five QEMU VMs on one host, created by a script checked into the repo, so any presenter can rebuild it from nothing.

#### C0 · Loop: one node keeps a promise

**Goal:** declare a service, and a controller keeps reality matching it on a single node.

**Scope:** `zcube-server` (API plus controllers) backed by Postgres; `zcube-agent` on the same VM, linking Zigbox; a `service` object (image digest, replicas, command, env); `zcube apply`, `zcube get`, `zcube why`. Agent reports observed state; controller reconciles. Deferred: multiple nodes, networking.

**Demo script:**

1. `zcube apply hello.zon` with `replicas = 3`. `zcube get service hello` shows 3 running within seconds.
2. On the VM, `kill -9` one of the processes. A replacement starts; `zcube get` shows 3 again.
3. Edit the file to `replicas = 5`, apply: two more start. Back to 2: three stop.
4. Apply a service whose digest does not exist. `zcube why service broken` prints the causal chain: `pending ← agent: image not found ← digest sha…`.

**Acceptance criteria:**

- [ ] Restarting `zcube-server` mid-demo changes nothing; restarting the agent re-adopts running containers instead of duplicating them.
- [ ] Every controller action is recorded with its cause and visible to `zcube why`.

#### C1 · Fleet: placement and failover

**Goal:** workloads spread across nodes and survive the loss of one.

**Scope:** node registration with leases; a scheduler with resource fit (CPU, memory) and spread; node failure detection; rescheduling. `zcube get nodes`.

**Demo script:**

1. Three VMs join. `zcube get nodes` shows them with capacity.
2. Apply `hello` with `replicas = 6`. `zcube get ``replica``s -o wide` shows two per node.
3. Power off one VM from the host. Within the lease timeout, its two replicas are marked lost and restarted on the survivors.
4. Power it back on. It rejoins empty; `zcube why node vm3` explains why nothing moved back (no rebalancing by default).

**Acceptance criteria:**

- [ ] Lease timeout is configurable and printed at failover.
- [ ] A partitioned node stops its workloads when its lease expires, so a replica never runs twice for long.

#### C2 · Swarm: store-aware distribution

**Goal:** images reach nodes fast because nodes share chunks and the scheduler prefers nodes that already have them.

**Scope:** agent advertises a compact summary of its local store (for example a Bloom filter of chunk hashes per image tree); scheduler adds a locality score; agents fetch chunks from peers before the registry, verifying every chunk by hash. `zcube stats pull` reports bytes by source.

**Demo script:**

1. Deploy `python-app v1` to three nodes; `zcube stats pull` shows registry bytes once, then peer bytes for the other two nodes.
2. Deploy `v2`, which changes one source file. Each node transfers only that file's chunks; the stats show kilobytes, not hundreds of megabytes.
3. Block registry access from VM3 with a host firewall rule, add a replica there: it starts anyway, entirely from peers.
4. Add a fourth empty node and a new replica: the scheduler picks a warm node and `zcube why` names locality as the reason.

**Acceptance criteria:**

- [ ] A peer serving a corrupted chunk is detected by hash, skipped and reported.
- [ ] Locality never overrides resource fit or spread constraints.

#### C3 · Rollout: safe updates and automatic rollback

**Goal:** changing a service's image rolls out gradually, gated by health, and undoes itself on failure.

**Scope:** readiness and liveness checks (HTTP, TCP, command); rolling update with surge and unavailable limits; automatic rollback when new replicas fail health; `zcube history service <name>` and `zcube rollback`.

**Demo script:**

1. A load generator hits `hello` continuously and prints error counts.
2. Roll out `v2`: replicas replace one by one; zero errors on the load generator.
3. Roll out `v3-broken`, whose health check fails. The rollout stops after the first replica, rolls back, and `zcube why` names the failing check.
4. `zcube history service hello` lists v1, v2, v3 (rolled back), with digests and who applied each.

**Acceptance criteria:**

- [ ] No request errors during a healthy rollout at the demo load.
- [ ] Rollback restores the previous digest exactly, never "latest".

#### C4 · Mesh: grants between services

**Goal:** services find each other by name, talk over authenticated encrypted links, and only along declared grants.

**Scope:** WireGuard tunnels between nodes; cluster DNS for service names; per-workload identity issued by the control plane and bound to service name, image digest and placement epoch (the epoch is carried in every identity from C4 and enforced for stateful services from C7, so C7 needs no change to the identity format); mutual TLS between workloads (or WireGuard-level identity, decided at C4 start); grants such as `web → db:5432` compiled into per-node rules. Default deny.

**Demo script:**

1. Deploy `web` and `db` on different nodes, with the grant `web → db:5432`. `web`'s page shows data from `db`.
2. Exec into a third service `batch` and try `db:5432`: refused, and `zcube why` names the missing grant.
3. Add the grant `batch → db:5432` live; the same call now succeeds without restarting anything. Remove it: cut off again.
4. Capture traffic between nodes with `tcpdump` on the host: only encrypted packets.

**Acceptance criteria:**

- [ ] Grants change within seconds, cluster-wide, without restarts.
- [ ] A workload's identity changes when its digest changes, so a grant can be scoped to signed versions.
- [ ] Every identity carries the placement epoch of the replica it was issued to; grants ignore it until C7 enforces it for stateful services.

#### C5 · Edge: public HTTPS

**Goal:** a service gets a public HTTPS address with one line of config.

**Scope:** an edge proxy role on chosen nodes; `public = "app.example.dev"` on a service; automatic ACME certificates; routing to healthy replicas only; edge traffic enters the mesh through a grant like any other caller.

**Demo script:**

1. Add `public = "hello.<demo-domain>"` to the service, apply.
2. From a laptop outside the cluster, open the URL: valid certificate, the hello page.
3. Roll out a new version during a browser refresh loop: no errors, the new version appears.
4. Remove the `public` line: the URL stops answering, certificate retained for reuse.

**Acceptance criteria:**

- [ ] Certificates renew automatically and are stored encrypted in the control plane.
- [ ] The edge can only reach services that declare `public`.

#### C6 · Trust: policy at admission and on every node

**Goal:** the cluster runs only signed, policy-compliant images, even if the control plane is compromised.

**Scope:** cluster policy (trusted keys, required provenance, allowed source repositories); admission check in `zcube-server`; independent re-check in `zcube-agent` before exec using a node-local copy of trusted keys; refusals reported back with cause.

**Demo script:**

1. `zcube apply` a service with an unsigned image: refused at admission, naming the policy rule.
2. Simulate a compromised control plane: edit the database row directly to point the service at an unsigned digest.
3. The agents refuse to run it; `zcube why` shows `refused by node policy` on every node; the old version keeps serving.
4. Sign the image with a trusted key and apply: it rolls out.

**Acceptance criteria:**

- [ ] Node trust configuration cannot be changed through the control plane API.
- [ ] Refusal never takes down the currently running, valid version.

#### C7 · State: stateful services that survive a node

**Goal:** a service with declared state recovers on another node after its node dies, with a known, bounded data loss.

**Scope:** Zigbox named state volumes placed by the scheduler (a stateful replica is pinned to the node holding its state); periodic snapshots of state shipped to object storage; on node loss, restore the latest snapshot onto a new node and restart there. Recovery point equals the snapshot interval, stated in the spec. Deferred: synchronous replication.

**Demo script:**

1. Deploy Postgres with `state = pgdata`, `snapshot_every = "1m"`. Insert a row with a timestamp each second from a client.
2. Power off its node.
3. Within the lease timeout plus restore time, Postgres runs on another node. The client reconnects; the last row before failure is at most about one minute old.
4. `zcube why service pg` shows the failover chain and the snapshot it restored.

**Acceptance criteria:**

- [ ] A stateful replica never runs on two nodes at once (an expired lease alone never moves it: a move needs a fencing proof, which is the node confirming, an external fence succeeding, or an operator asserting the node is dead; snapshot writes and peer identities check the placement epoch; verified by test).
- [ ] Snapshot restore is tested in CI from a cold cluster.

#### C8 · Jobs: batch work and cluster builds

**Goal:** the cluster runs finite jobs, including Zigbox M7 builds, sharing one build cache.

**Scope:** a `job` object (run to completion, retries, deadlines); gang scheduling (all tasks start together or none do); M7 build steps dispatched as jobs across nodes, with outputs in the shared chunk store as a cluster-wide cache.

**Demo script:**

1. `zcube build` a project with independent steps: `zcube get jobs` shows steps running in parallel on different nodes.
2. A second developer builds the same commit: every step is a cache hit; the result digest is identical.
3. Submit a 4-task gang job on a cluster with room for only 3: it waits rather than starting 3; free a node and all 4 start together.

**Acceptance criteria:**

- [ ] Cluster-built digests match local `zbx build` digests for the same inputs.
- [ ] A failed task retries within its budget, then fails the job with the cause recorded.

#### Zigcube stretch milestones

- **CS1 · Kubernetes API facade:** enough of the Kubernetes API that `kubectl get pods` and simple Deployments work, translated to Zigcube objects.
- **CS2 · Cells:** many small clusters managed as one fleet, with services placed across cells.
- **CS3 · Tenant isolation:** tenants pinned to microVM isolation (Zigbox S1), with separate keys and grants.
- **CS4 · Accelerators:** GPU allocation and topology-aware gang scheduling for training jobs.

### Zigcube non-goals, risks and open questions

**Non-goals for C0 to C8:**

- Kubernetes API compatibility (stretch CS1 only).
- Clusters beyond a few hundred nodes; scale comes later through cells (CS2).
- A custom consensus store. The control plane uses an existing database.
- Multi-region active-active control planes.
- Synchronous replication for stateful services; C7 is snapshot-based with a stated recovery point.

**Risks:**

| Risk | Where it bites | Mitigation |
| --- | --- | --- |
| Control-plane store choice limits scale or watch performance | C0 onward | Hide it behind a narrow storage interface; benchmark watch fan-out at C1 |
| Split-brain runs a replica twice | C1, C7 | Lease-based fencing; agents stop work before their lease can expire; stateful moves need a fencing proof and epoch-checked writes; partition tests in CI |
| Peer chunk fetch adds latency or load on busy nodes | C2 | Bandwidth caps per node; registry fallback after a timeout |
| Identity and mTLS design is easy to get subtly wrong | C4, C6 | Reuse proven libraries and an existing identity format such as SPIFFE IDs; external review before C6 |
| Demo cluster on one host hides real network behaviour | C1 to C5 | Add a netem-based latency and packet-loss profile to the demo VMs |

**Open questions:**

- [ ] Control-plane store, decided: Postgres, with OrioleDB (`USING orioledb`) for the hot, update-heavy observed-state tables and plain heap for the rest. FoundationDB rejected as too hard to operate. Open: fall back to all-heap if OrioleDB is still alpha or lacks a needed feature when C0 starts.
- [ ] Is the control plane also written in Zig, or in a language with a richer server ecosystem, keeping Zig for the agent and runtime?
- [ ] Service config format: same as the M7 build file, so one language describes build and run?
- [ ] Workload identity at C4: mTLS per connection, or identity carried at the WireGuard layer?

## Part III · The ecosystem: how Zigbox wins people, not just benchmarks

The goal is not to replace Docker. It is to become the secure, reproducible runtime that security-minded teams choose, while staying compatible enough that switching costs nothing. Ecosystems tip when a niche grows large enough that the default starts to look risky.

Three precedents set the rules:

| Project | Why it won or lost | Rule we take from it |
| --- | --- | --- |
| Docker | A five-minute demo (`docker run`) and Docker Hub's catalogue of ready-made images | Win the first five minutes; treat the catalogue as the product |
| Kubernetes | Given to a neutral foundation, so rival vendors could invest; plugin interfaces (CNI, CSI, CRI) let others build businesses on it | Neutral ownership early; stable seams for others to profit from |
| Nomad | Cleaner design, but single-vendor, and the owner's later licence change confirmed users' fears | Never be a project people fear depending on |

Our wedge is **provenance by construction**: every image reproducibly built, signed and traceable, in one tool. Supply-chain regulation (the EU Cyber Resilience Act, US federal SBOM and attestation requirements) gives organizations a reason to care; the developer experience gives individuals a reason to try it. We ride existing gravity at the edges (OCI images from M4, a Kubernetes API facade at CS1) and differ inside.

### Ecosystem roadmap

*Figure: ecosystem roadmap · 4 phases, 4 gates (diagram in the live doc, node f290429c-f927; not reproduced here).*

Each phase rides on a block of engineering milestones, and the next phase starts only when its gate, set out below, is met.

### The four phases

Gate numbers are first-guess targets to calibrate after Phase 1, not commitments. A phase ends when its gate is met, not on a date.

#### Phase 1 · Prove (Zigbox M0 to M4)

**Goal:** make people who see it want to try it.

**Who we win:** the Zig community first; then engineers who already believe in hermetic builds (Nix users); then curious container people.

**Actions:**

- Build in public: every milestone demo becomes a short video and a written post ("A rootless container in 400 lines of Zig", "Pulling Python with most of it already on disk").
- Apache 2.0 from the first commit, with a public no-relicensing pledge in the README.
- Show up where the beachhead gathers: Zig meetups and online communities, FOSDEM's container devroom, Hacker News launch at M4.
- Ask two or three respected container, Podman or Nix engineers for a public design critique of Part I.

**Gate to Phase 2:** the M4 demo is published; a stranger can go from zero to `zbx run python` in under five minutes using only the README; roughly 1,000 GitHub stars and 20 people outside the project who have run it and reported back.

#### Phase 2 · Recruit (Zigbox M5 to M8)

**Goal:** turn watchers into contributors and first users.

**Who we win:** contributors; platform and security teams willing to try it in staging.

**Actions:**

- Open an RFC process: design changes are proposed and decided in public.
- Keep the codebase readable in a weekend; curate good-first-issues; review pull requests within one working day.
- A contributor guide that explains the architecture with the same diagrams as this doc.
- First conference talks built around the M7 and M8 demos ("the build that cannot lie", "the runtime that refuses unsigned code").
- Publish a security-team brief mapping Zigbox features to supply-chain requirements.

**Gate to Phase 3:** at least 10 outside contributors with merged changes; 3 teams running it in staging or CI and willing to say so publicly; one outside maintainer with commit rights.

#### Phase 3 · Ecosystem (Zigcube C0 to C4, plus the catalogue)

**Goal:** give other people and companies a reason to build on it.

**Who we win:** tool builders and vendors; teams that want orchestration.

**Actions:**

- Freeze and document the extension seams (below) with a compatibility policy.
- Launch the verified catalogue: common base images reproducibly built and signed, verifiable by anyone; explore a partnership with an existing signed-image provider rather than building it alone.
- Run Zigcube's C2 demo (images that are mostly already on the cluster) as the flagship talk.
- Pair with one or two early adopters to publish case studies.

**Gate to Phase 4:** the first third-party plugin in real use; engineers from at least one other company contributing regularly; the catalogue covers the 20 most-used base images.

#### Phase 4 · Neutralize (Zigcube C5 to C8 and CS1)

**Goal:** make the project safe for anyone to bet a company on.

**Who we win:** larger organizations and their procurement and security reviewers.

**Actions:**

- Apply to a neutral foundation (a CNCF Sandbox application is the obvious path) and move the trademark there.
- Publish conformance tests so third parties can certify compatible implementations and distributions.
- Ship the Kubernetes API facade (CS1) so existing tooling works on day one.
- Founders' commercial offering (hosted fleets or support) launched, with the open-source boundary stated plainly.

**Gate (steady state):** foundation acceptance; maintainers from at least two companies besides the founders'; one vendor shipping a commercial product built on Zigbox or Zigcube.

### Standing commitments

These hold in every phase and are stated publicly from day one, because trust is cheaper to keep than to rebuild.

- **Licence:** Apache 2.0 for everything in Parts I and II, with a written pledge never to relicense. No contributor licence agreement that would make relicensing possible; use a Developer Certificate of Origin sign-off instead.
- **Governance:** public RFCs for design changes; a maintainers file naming who decides what; the path to a neutral foundation published in Phase 1, even though the application waits for Phase 4.
- **Extension seams:** stable, versioned interfaces where others can build products:

| Seam | What plugs in | First needed at |
| --- | --- | --- |
| Isolation backend | Namespaces, microVMs, WASM | Zigbox S1, S5 |
| Network | Rootless user-mode networking, mesh dataplanes | Zigbox M5, Zigcube C4 |
| State | Volume drivers, snapshot targets | Zigbox M6, Zigcube C7 |
| Policy | Admission and run-time policy engines | Zigbox M8, Zigcube C6 |
| Registry and store | Registries, chunk caches, mirrors | Zigbox M4, Zigcube C2 |

- **Catalogue:** verified base images are built from public build files on public infrastructure, so anyone can reproduce the digest. The catalogue is a commons, never a paywall.
- **Business model:** the founders may sell hosted Zigcube fleets and support. The open-source runtime, orchestrator and catalogue stay complete and free; no feature that security or correctness depends on is ever paid-only.

### Ecosystem risks and open questions

| Risk | Mitigation |
| --- | --- |
| Seen as a hobby rewrite of Docker | Lead every message with the wedge (provenance by construction), never with "Docker in Zig" |
| Zig's pre-1.0 status scares organizations | Ship static binaries so users never touch Zig; publish the version-pinning policy |
| Founder bottleneck on reviews and decisions | Second maintainer by the Phase 2 gate; RFCs decided by maintainers, not one person |
| Incumbents add the same features | Compete on coherence and defaults, not on any single feature; stay compatible so adopters lose nothing |
| Commercial offering erodes community trust | Standing commitments published in Phase 1; boundary of the paid offering stated before it launches |

**Open questions:**

- [ ] Final names: is "Zigbox" too tied to Zig for organizations that do not care about the language? (Zigcube likewise.)
- [ ] Which signed-image provider to approach for the catalogue partnership, and when?
- [ ] Which foundation: CNCF, or a smaller neutral home first?
- [ ] Should the security-team brief in Phase 2 map to specific frameworks (SLSA levels, CRA obligations) and get an outside review?
