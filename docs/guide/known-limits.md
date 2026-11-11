# Known limits

Zigbox is a public beta. This page says what it does not do, what is not built yet, and the
problems we know about. If you hit something not listed here, please
[report it](#reporting-a-problem).

## Not supported, by design

- **Windows**, natively or otherwise.
- **Intel Macs.** On a Mac, `zbx` needs Apple Silicon.
- **Root.** There is no `sudo zbx`. If something works only as root, it is not supported.
- **Docker's API and CLI.** There is no Docker socket, so tools that talk to the Docker daemon
  will not find one. The commands look like Docker's, but the flags are not a drop-in match.
- **More than one service at a time.** No Compose, no networks between containers, no restart
  policies. Several cooperating services are the job of Zigcube, a separate project.
- **Running a Dockerfile.** `zbx build` reads `zbx.build.zon`, never a Dockerfile.
- Live migration, and checkpoint and restore.

## Not built yet

- **Dockerfile import:** translating a Dockerfile into a `zbx.build.zon` you can read and commit.
  Planned.
- **GPU access** in containers. Planned.
- **Pull from other registries.** `zbx pull` works with Docker Hub, GitHub's registry
  (`ghcr.io`) and Amazon ECR (with your AWS credentials). Other registries, and logging in to pull
  from them, are not supported. `zbx push` can log in to a registry.
- **Networks between containers.** A container gets no network (the default), the host's
  (`--net host`), or user-mode networking (`--net user`, `--publish`).

## Platform notes

- **cgroup v2.** Resource limits (`--memory`, `--pids`, `--cpus`) and `zbx build` need a host with
  cgroup v2 and a systemd user session. On a cgroup v1 or hybrid host, containers still run, without
  limits ([W0301](https://zigbox.org/errors/box/W0301)), and `zbx build` is refused
  ([E0307](https://zigbox.org/errors/box/E0307)).
- **Ubuntu 24.04** blocks unprivileged user namespaces by default; `zbx doctor` names the one
  setting to change ([E0101](https://zigbox.org/errors/box/E0101)).
- **Mac:** `zbx push` runs on Linux only; to get an image off a Mac, use `zbx store export --oci`.
  `zbx build` and the signing commands have not been tested on a real Mac yet.
- **Claude Code cloud sessions:** containers run, but ports, user-mode networking and builds do
  not. See [Try in Claude Code](try-claude-code.md#zbx-inside-a-claude-code-cloud-session).
- **Linux packages** are built for the Debian and Fedora families (apt and dnf). Other
  distributions are not packaged yet.

## Known problems

Found while writing this guide, with `zbx 0.4.0`:

- **`zbx stop` on a container that failed to start** reports a bug,
  `bug[ZBX-B0001]` "reached unreachable code", and exits 70. Such a container (state
  `start_failed` in `zbx ps --all`) never ran, so there is nothing to stop; the message is wrong,
  not harmful.
  <!-- owner: seen in a cloud session with a --publish run refused by E0603. Check 0.5.1. -->
- **`zbx push --dry-run <name>@sha256:<digest>`** is refused with
  [E0550](https://zigbox.org/errors/box/E0550), although `zbx sign` accepts the same name. Push by
  tag (`alpine:3.20`) or by store tree (`b3:...`) instead.
- **`zbx store ls`** can show an image as much larger than it is (busybox as 394.6 MiB over 420
  files): files linked under several names seem to be counted once per name.
- **`zbx exec <name> -- cat /etc/hostname`** prints `localhost`, while the container's hostname
  is its name.
- **Pushing through a published port** to a registry in another container can stall and fail with
  [E0503](https://zigbox.org/errors/box/E0503) after 30 seconds; trying again works. Seen in CI,
  where the registry runs behind `pasta`; a direct connection does not stall.

## Reporting a problem

Open an issue at <https://github.com/Zigbox/zigbox/issues/new> with:

1. what you ran, and the full error, including its code (`ZBX-E....`, `ZBX-W....` or
   `ZBX-B....`);
2. the output of
   ```sh
   zbx --version
   zbx doctor --output json
   ```
   which describes your host (kernel, user namespaces, cgroups, ids and network helpers);
3. for a `ZBX-B` code, the same command again with `--verbose`.

`zbx explain <code>` and <https://zigbox.org/errors/box/> explain every code; a `ZBX-B` code
always means a bug in `zbx`, never something you did.
