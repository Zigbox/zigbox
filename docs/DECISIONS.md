# Decisions

These are decisions the owner has made ahead of the milestone that needs them. Each one goes into that milestone's brief when the brief is written. Newest first.




## M6c · Authenticated pull from Amazon ECR, brought forward; push stays after M8

*Decided 2026-10-30, by the owner.*

- **M6b ships as it is. ECR is a milestone of its own, M6c**, after M6b. It is not folded into M6b (which is down to its Mac slice), and it does not wait for push.
- **Pull only.** Push stays after M8, where signatures and provenance give it something to push beside an image. M6c's credential layer is written with push's scopes in mind, so push adds to it rather than replacing it.
- **Why now:** a self-hosted Zigcube on EC2 runs images its owners keep in ECR. Without authenticated pull, gate B (self-hosted) waits on M7 and M8, which are otherwise off its path.
- **Native, no helper programs:** zbx signs AWS requests itself (SigV4) and finds credentials in the environment, a web identity token, or EC2 instance metadata (IMDSv2). `docker-credential-*` helpers and the `aws` CLI are external programs STYLE.md does not allow. Credentials are never cached to disk.
- Other private registries (GHCR, Docker Hub private repositories, Basic or token credentials) are not in M6c. They reuse its auth path later.
- The live doc needs an M6c section and a narrower non-goal ("push, and private registries other than ECR pull, until after M8"). The brief is `docs/briefs/M6c-ecr.md`.



## `zbx.logs/1` describes its refusals: every document is checked against its command's schema

*Decided 2026-10-30, by the owner.*

- **`zbx schema logs` describes the error document a refused `logs --output json` prints** (E0402, E0217, and the rest), as `run`'s and `exec`'s schemas describe theirs: one object schema with no `$ref`, the diagnostic's members beside the record's, and `oneOf` to tell them apart. An agent can validate every document a command prints against that command's own schema. (The diagnostic is on stderr, the records on stdout, as before.)
- **Schemas only grow.** The record's members and its required ones (`schema`, `stream`, `time`, `text`) are unchanged, so the schema stays `zbx.logs/1`.
- The M6b agent test validates E0402 against the logs schema; its finding about this is gone.

## Zigcube's restart: C1 includes local mode; Zigcube drives

*Decided 2026-10-30.*

- **C1 includes local mode** (live doc rev 76): zcube-server on SQLite with one agent on the same machine, started by one command, on Linux and macOS (the agent in the zbx machine), with services reaching each other by name where the service file grants it, a single-node form of C4 without WireGuard. C1's demo gains a step: an app and postgres on a laptop, from one file.
- **Zigcube's own session drives the restart**, from orders written into the zigcube repository (`docs/restart.md`).
- **The owner reviews the revised `Runtime` contract** before Zigcube builds on it; the orders carry it as a draft.
- **Pull goes into the `zigbox` library in M6b** (its slice 4), because Zigcube's agent cannot fetch an image without it: it lives in the CLI's code today. `zbx pull` becomes a thin caller with unchanged output.

## M6b · Dev loop: logs for every run, 5 MiB, one implementer

*Decided 2026-10-30, on the M6b brief.*

- **Every run keeps its log**, foreground as well as detached: a foreground `zbx run` writes the framed log as it copies the output to the terminal.
- **The cap is 5 MiB per container**, the oldest whole records dropped first.
- **The upgrade baseline is the M6 merge (`bf57ec8`)**, not the 0.1.1 macOS release.
- **The cap is two files, rotated** (slice 2): each at most half of 5 MiB; at the cap the current file is renamed over the older one. One `rename` drops the oldest whole records, a crash leaves whole records, the log holds 2.5 to 5 MiB. A compaction copies the log on every drop.
- **One implementer, slices in order**, Sonnet for slices 1 and 2.

## M4b · Mac: the network (slice 4)

*Decided 2026-10-29, on the slice 4 design.*

- **pasta comes from Alpine 3.20 `passt` 2024.11.21** (pinned in `vm/alpine.zon`, one package, no libraries beyond musl; newer than the `2024_02_16` zbx needs). The Linux zbx in the machine publishes exactly as on Linux. Two things in the guest's init made it work: `/dev/net/tun` is made again with mode 0666 (the kernel's node is root-only, and pasta runs as the user), and `net.ipv4.ip_unprivileged_port_start` is 0, so the Mac, not the guest, decides which ports a user may publish.
- **The listener is in the host process (`zbx vm serve`), the data path is vsock, and the client is not in it.** A Mac connection to a published port makes the host open a vsock connection to port 1026 of the guest, say `connect <port>`, and copy bytes both ways in a thread of its own (at most 128 at a time). The guest's port agent (a process of `zbx guest serve`, running as the Mac user, named `zbx-ports`) accepts only CID 2, connects to `127.0.0.1:<port>` in the guest and copies the bytes.
- **How the Mac knows which ports are open.** The client reserves each port before it runs the command (`publish <address> <port>` on the control socket): the host binds the Mac port at once, so a taken port is refused before anything runs and a free one cannot be taken in between. The agent reports the ports `pasta` forwards (read from its command line, `--tcp-ports HOST:CONTAINER`): to the host's `scan` request, which the client sends when its command has ended and the host sends every 500 ms only while a command runs (a foreground `run --publish` opens its port in the middle of the command), and, with no request, when a `pasta` ends: the agent holds a pidfd of each, so the end of a container, by `zbx stop`, a crash, a kill or the end of the machine, is an event, and the host closes the Mac listener at once. A reserved port the guest never reported is closed when the client says `sync` (its command ended without publishing) or after 60 seconds (the client is gone). Nothing is polled while no command runs.
- **Which address.** `--publish HOST:CONTAINER` listens on `127.0.0.1` and `::1` only. An address in front (`ADDRESS:HOST:CONTAINER`) is read by the macOS zbx and removed before the Linux zbx sees the option: `127.0.0.1` and `localhost` the same as none; `0.0.0.0` every interface (a dual-stack listener), which exposes the port on the Mac's network and happens only when the user wrote it; another IPv4 address that one only. Anything the Mac cannot read as an address is left for the Linux zbx to refuse (`ZBX-E0600`).
- **A Mac port that cannot be listened on is `ZBX-E1017`**, before the container exists. A port is in use if a connection to it on the loopback is accepted, or neither refused nor answered within 200 ms, whatever address its holder listens on: a program that listens on every address with SO_REUSEADDR (a Java server was found on 8080 on the owner's Mac) would let a bind to 127.0.0.1 succeed beside it and take the connections. What holds it is not looked up; the fix is `lsof -nP -iTCP:<port> -sTCP:LISTEN`. macOS lets a program that is not root listen on a port under 1024 only on every interface: `--publish 81:80` is refused with a cause and the fix `0.0.0.0:81`, which works without root.
- **An open published port keeps nothing awake.** The agent and the connections it carries are left out of the processes init counts as busy; the running container is what keeps the machine up, as before.

## M4b · Mac: files, storage and Rosetta (slice 3)

*Decided 2026-10-29, on the slice 3 design; the disk image was approved by the owner.*

- **The store lives on a disk image.** `~/Library/Application Support/zbx/store.img` is a sparse file, 64 GiB by default (1 GiB to 8 TiB), attached as a virtio block device. `zbx vm config --disk <size>` sets it, persisted with the CPUs and memory (`zbx-vm-settings/2`; version 1 is still read and means the default disk) and shown in `zbx.vm.config/1` and `zbx.vm.status/1` as additive `disk_bytes` members. The disk only grows: a smaller `--disk` than the file now is `ZBX-E1012`, whose second fix tells the person to move the file aside themselves. zbx never deletes the image.
- **The guest formats only an empty disk.** The first 64 KiB are zeros: `mke2fs -t ext4` (owner of the root directory the Mac user). An ext superblock: `e2fsck -p` before every mount (0 and 1 are accepted, anything else refuses the disk), and a disk that grew gets `e2fsck -f` and `resize2fs` before the mount. Anything else is refused and left alone, as `ZBX-E1011` naming the disk. The tools come from the Alpine 3.20 packages `e2fsprogs`, `e2fsprogs-extra` (resize2fs), `e2fsprogs-libs`, `libcom_err`, `libblkid`, `libuuid` and `libeconf`, pinned in `vm/alpine.zon`. Before power off the guest remounts the disk read-only so that the next boot needs no journal recovery.
- **The store and the state never land on the shared home.** The guest mounts the disk at `/mnt/store` and `zbx guest serve` sets `XDG_DATA_HOME` and `XDG_STATE_HOME` to directories on it, ignoring any XDG variable the Mac forwards.
- **The Mac user's home is shared read-write over virtiofs** (tag `home`), mounted in the guest at the same path before the command service starts. The guest keeps its own `/etc/passwd`; the share only covers the path. Files a container writes appear on the Mac owned by the Mac user (the container's root is the guest user, whose ids are the Mac's); a `chown` to another id inside the container succeeds and changes nothing, because the share has one owner.
- **A working directory outside the home is refused**, before the machine starts: `ZBX-E1013`, one line naming the directory and the home, fix `cd ~`. The guest no longer falls back to the user's home anywhere.
- **Rosetta.** When Rosetta is installed the machine shares it (tag `rosetta`), and the guest registers it with `binfmt_misc` (flag `F`, so it works in any container root). `--platform linux/amd64|arm64` is read by the macOS zbx and becomes `ZBX_PLATFORM` for the Linux zbx; the guest sets `ZBX_PLATFORM_FALLBACK=linux/amd64` when Rosetta is registered, which the pull uses only when an image's index has no entry for the native platform. These are the only changes in the Linux zbx, and without the variables nothing differs. A linux/amd64 request on a Mac without Rosetta is `ZBX-E1016` with the fix `softwareupdate --install-rosetta --agree-to-license`; zbx never runs that command.
- **A full disk is told in both places.** The host refuses to start the machine when the Mac's volume has less than 2 GiB free beside the disk file (`ZBX-E1015`); a sparse file that cannot grow would otherwise show as I/O errors in the guest. When a command fails and the guest's disk has less than 32 MiB free, the guest sends a `disk_full` frame before the exit frame and the Mac prints `ZBX-E1014` after the command's own output.
- **`host.log` is capped** at 64 KiB: a log at that size is renamed to `host.log.1` (replacing the one there) when the next host starts.

## M4b · Mac: forwarding (slice 2)

*Decided 2026-10-29, on the slice 2 design.*

- **A cgroupfs scope driver in the Linux zbx.** The VM has no systemd. When there is no user bus and `ZBX_CGROUP_ROOT` names a delegated cgroup v2 directory, zbx makes one child cgroup per container there, moves the container (and the scope's keeper) in before the container can run, writes `memory.max`, `pids.max` and `cpu.max` directly, and removes the cgroup on every exit path, as runc's and Podman's cgroupfs drivers do. On a host with a user bus nothing changes. It goes through `host.zig`, so the simulator covers it with fault injection, and each failure is a coded diagnostic (E0309, or W0302 for a cgroup that stays). Only the VM's guest service sets the variable; the guest's init makes the delegated subtree the way `Delegate=` does.
- **`newuidmap` and `newgidmap` come from Alpine's aarch64 packages**, pinned by URL and SHA-256 in `vm/alpine.zon` with the C library and the libraries they need, and Mozilla's CA bundle the same way. The Zig image tool unpacks them into the initramfs (setuid root for the two helpers). In Alpine 3.20 the package is called `shadow-subids` (`shadow-uidmap` in later releases). `pasta` comes the same way in slice 4.
- **Where the pinned Alpine packages come from.** Each `.apk` in `vm/alpine.zon` is fetched first from a mirror on a GitHub release of this repository (`https://github.com/Zigbox/zigbox/releases/download/vm-deps-alpine-3.20/<file name>`, the base is in the `.zon` beside the pins), then from its dl-cdn URL, because dl-cdn drops a file when its package is updated. Both are checked against the same SHA-256; a file that fails is refused and the next source is tried; if both fail the build stops with one line naming the package and both URLs.
- **Forwarding.** The macOS `zbx` forwards the Linux commands (run, ps, stop, commit, store, state, lock, pull, bundle, doctor) whole to `zbx guest serve`, a hidden forwarding mode of the Linux zbx that runs as the Mac user's twin inside the VM. `vm`, `help`, `explain`, `schema` and `--version` stay local. The machine starts lazily under the host lock and stops after the idle timeout (5 minutes, `ZBX_VM_IDLE_TIMEOUT_MS` replaces it for tests) once no process of the user runs in it; `run -d` containers keep it alive.

## M4b · Mac: the VM's kernel, image, lifecycle and size (slice 1)

*Decided 2026-10-29, on the slice 1 proposals.*

- **The kernel is Linux 6.18.59 (longterm), built from the upstream source** with a checked-in config fragment (`vm/kernel/config-arm64`, applied over `allnoconfig`), everything built in. The tarball is pinned by its SHA-256 and the resulting `Image` by its own (`vm/kernel/pin.zon`); the build fails if either differs.
- **The kernel and the initramfs are embedded in the macOS `zbx`** and unpacked on first use into `~/Library/Application Support/zbx/vm/<image version>/`. The image version is a digest over both, so an upgrade is a file swap and a version mismatch cannot ship.
- **The idle timeout is 5 minutes** (a named constant).
- **The VM boots with 4 vCPUs (or half the Mac's if fewer) and 2 GiB**, as named constants.
- **Sizing is a persisted setting, and the VM is never started explicitly by the user.** `zbx vm config --cpus N --memory SIZE` writes a small versioned record; every boot, explicit (`zbx vm start`, an optional pre-warm) or lazy from any command, reads it. A running machine keeps its size until it stops. The range is the named constants, Virtualization.framework's limits and the Mac's own CPUs and memory together.
- **The Homebrew tap is `Zigbox/homebrew-tap`.**

## Local dev: zbx runs one thing; more than one is Zigcube's

*Decided 2026-10-29.*

- **No Compose equivalent in zbx, ever.** zbx runs one container at a time. To run more than one service, even on one laptop, install the Zigcube server (SQLite store, one agent on the same machine): "if you want to run more than one thing, do it right". Live doc rev 64 says so in Non-goals and in Part II's opening.
- **Zigbox adds only the local primitives both need**, as a new milestone **M6b · Dev loop** before M7: writable mounts, `zbx logs`, `zbx exec`, all three in the library for Zigcube's agent.
- **Writable mounts only under the project directory** (the one holding `zbx.lock`, else the working directory).
- **Ownership: written as the container's root, refused otherwise.** Most dev images run as root, so a file the container writes is the host user's. For an image whose user is not root, a writable mount is refused, naming the user and the fix (`--user 0`, new in M6b, or a read-only `--bind`); no subordinate-owned file ever lands in a project. Rejected: id-mapped mounts (they need privilege over the host file system that rootless zbx lacks; `zbx doctor` only reports whether the kernel allows them), a keep-id map of the image's user to the host user (it changes how the store's trees are owned; a milestone of its own if real use asks), and chown at exit (too late for a dev loop, and wrong after a crash). Live doc rev 68.
- **Zigcube's single-node path is an early target**: services reaching each other by name on one machine, a single-node form of C4's DNS and grants without WireGuard. Zigcube's session scopes it when Zigcube restarts.

## M4b · Mac: handed off to a session on the owner's Mac

*Decided 2026-10-29, after M6 merged.*

- **M4b is built by a Claude Code session on the owner's Apple Silicon Mac**, from `docs/briefs/M4b-mac.md`, because the cloud container cannot run macOS, Virtualization.framework, code signing or notarization. The brief stands alone; its open choices are marked **(propose)** for that session to settle with the owner.
- **The cloud session waits** meanwhile.

## M6 · State: one writer, a trash, and tar.gz

*Decided 2026-10-28, after M5 merged.*

- **One writer at a time.** A run holds its read-write state volumes for its whole life; a second run naming one read-write is refused, naming the holder. `--state NAME:PATH:ro` shares, read-only.
- **`zbx state rm` goes to a trash**, as `store gc` does since M3, and `zbx state restore` brings a volume back until the trash expires. State is the one thing zbx cannot rebuild from a registry.
- **`zbx state export` writes tar.gz**, with std's own tar writer and deflate compressor (both are in the pinned std), owners as the container sees them.
- **M5's agent-test findings go into M6**: a hint in the failure JSON, the network in `run -d` and `ps` JSON, fixes that say they need root or are templates, `doctor --output json`, and a schema an agent can follow.
- **M4b (Mac) follows M6.**

## M5 · Network: the no-network hint, --publish, and M4's carried-over notes

*Decided 2026-10-28, after M4 merged.*

- **The no-network hint is shown on failure.** When a run with the default network (no `--net` given) exits non-zero, zbx adds `zbx: network: none (grant with --net)` to stderr. It does not try to detect whether the container used the network; the line is a note, and the exit code stays the container's.
- **`--publish` implies `--net user`.** `zbx run --publish 8080:80 nginx` works as the spec types it; `--publish` with an explicit `--net none` or `--net host` is a usage error.
- **M4's demo step 3 is reworded** (live doc and `docs/SPEC.md`): the second python image costs the store less than its compressed size because most of its stored bytes are shared with the first. It costs about 65%; "far less" overstated it.
- **An image record keeps its tags.** A pull by digest after a pull by tag no longer replaces the tag; a record lists every tag it was pulled as.
- **The agent-interface gaps go into M5**: `zbx explain --output json`, `zbx lock show`, and `run --output json` naming what ran.
- **M4b (Mac) waits** for an Apple Developer ID and an Apple Silicon runner; M5 goes first.

## M4 · A 4 MB binary, and a docker.io mirror for PR CI

*Decided 2026-10-27, after M4 slice 1.*

- **The release size limit is 4 MB**, up from 2 MB (live doc rev 54). std's TLS client and its crypto are about 550 KB, and gzip, zstd and tar follow in slice 2. Splitting the pull code into a second binary or shipping `ReleaseSmall` (assertions off) were rejected. The size is still checked on every CI run, so growth stays visible.
- **PR CI reaches docker.io through a mirror.** Docker Hub's anonymous limit ran out after about 20 resolves from one address, and GitHub runners share egress addresses. zbx gets a registry-mirror setting, as Docker's `registry-mirrors` does: a pull of a docker.io image tries the mirror first, then falls back to Docker Hub. PR CI's `demo-m4` points docker.io at `mirror.gcr.io`, with blobs cached. The weekly top-20 run and the by-hand demo use real Docker Hub, so its token flow stays tested.

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
