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
- **Running a Dockerfile.** `zbx build` reads `zbx.build.zon`, never a Dockerfile. `zbx import`
  translates one into a build file (see [Experimental](#experimental)); it never runs it.
- Live migration, and checkpoint and restore.

## Not built yet

- **Pull from other registries.** `zbx pull` works with Docker Hub, GitHub's registry
  (`ghcr.io`) and Amazon ECR (with your AWS credentials). Other registries, and logging in to pull
  from them, are not supported. `zbx push` can log in to a registry.
- **Networks between containers.** A container gets no network (the default), the host's
  (`--net host`), or user-mode networking (`--net user`, `--publish`).

## Experimental

Built, demonstrated in CI and released, but new: the flags and the output may still change, and
fewer hosts have run them. Devices and GPUs are in the release since 0.5.1, Dockerfile import since
0.5.2.

- **Dockerfile import** (`zbx import`): translates a Dockerfile into a `zbx.build.zon` you can read
  and commit, with a report of what it did not carry over. It never runs the Dockerfile.
  - Covered: stages, `FROM` an image (pinned by digest in the lock), `COPY`, `ADD` of a file of
    the context and `ADD` of an https URL with `--checksum=sha256:`, `RUN` with a cache mount or
    a read-only bind from another stage, `ENV`, `ARG`, `WORKDIR`, `USER`, `SHELL`, `LABEL`,
    `ENTRYPOINT` and `CMD`; `--chown` and `--chmod` on a copy.
  - Not covered: `EXPOSE`, `VOLUME`, `HEALTHCHECK`, `STOPSIGNAL` and `MAINTAINER` are kept only
    as labels and reported (W0811). Refused (E0811): `ONBUILD`; `FROM scratch` with steps;
    `FROM --platform` other than the host's; `ADD` of a git repository, of a URL without
    `--checksum`, and of a local archive it would unpack; and other `RUN --mount` kinds (secret,
    ssh, tmpfs, a bind from the context or from an image). A copy from an image, and `--exclude`
    on a copy from a stage, are translated but `zbx build` refuses them for now (E0802).
    `WORKDIR` sets the directory but, unlike Docker, does not create it.
- **Devices and GPUs** (`--device`, `--gpu`): pass a host device node, or devices from a CDI spec,
  into one container.
  - Covered: `--device /dev/<path>`, with your supplementary groups kept so the node opens;
    `--device vendor/class=name` from a JSON CDI spec; `--gpu dri` and `--gpu all`, with
    `zbx doctor` naming what it finds.
  - Not covered: `--gpu` has not been run on a real GPU, and `--gpu dri` has not run in CI
    (the test VM has no render node). Paths with `:` (by-path and by-id names), paths over 48
    bytes, YAML CDI specs, specs over 64 KiB and most CDI hooks are refused, each with a code.
    `--device /dev/net/tun` is passed in but cannot be used, because a container has no
    `CAP_NET_ADMIN`.

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
  not. See [Try in Claude Code](try-claude-code.md#what-works-in-a-cloud-session).
- **Linux packages** are built for the Debian and Fedora families (apt and dnf). Other
  distributions are not packaged yet.

## What `zbx store ls` counts

`zbx store ls` shows two sizes for a tree. In text, the SIZE column is the **unique** size: each
distinct file counted once, however many names it has (hard links, or the same bytes and
attributes twice), the space the tree needs. In JSON (`zbx.store.ls/1`), `bytes` is the sum of
the files' lengths with a file counted once per name, as it always was, and `size_unique` is the
unique size (`null` if the tree cannot be read; the text shows `?`). `size_unique` is new in
0.5.1; `bytes` did not change.

## Known problems

- **`zbx ps` of 0.5.x hides containers started by a newer `zbx`.** A container whose record was
  written by a newer release (for example a lazy-started one, from 0.6.0) is skipped without a
  word: it is not listed, and nothing says that a container was left out. Use the newer `zbx`
  to see it. Found while building lazy start (S2, slice 6).
- **Pushing through a published port** to a registry in another container can stall and fail with
  [E0503](https://zigbox.org/errors/box/E0503) after 30 seconds; trying again works. Seen with
  `zbx 0.4.0` in CI, where the registry runs behind `pasta`; a direct connection does not stall.

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
