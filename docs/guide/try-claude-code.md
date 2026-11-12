# Try Zigbox in Claude Code

> **Not yet verified for this release.** The `uidmap`, `passt`, `useradd` and `usermod` lines were
> run in a cloud session with zbx 0.4.0 built from source. The apt lines were not run (the
> repository is not live yet), nor the block as an environment setup script. The CLAUDE.md
> suggestion was written for this guide and not tested with an agent.

A Claude Code cloud session is a container itself, and Docker's daemon does not run in it: the
`docker` command is there, but finds no daemon to talk to. `zbx` needs no daemon and no root, so
Claude Code can pull and run containers in the session with it: start a database for its tests,
try a command in a clean Alpine or Debian, sign and check an image. And `zbx` was built to be
driven by an agent: every output has a JSON form and every error a code and a fix.

## Set up a cloud session

Install the signed package from our apt repository and the two helpers it uses, then give an
ordinary user a range of ids, so containers get the full id mapping:

```sh
curl -fsSL https://zigbox.org/zigbox-archive-keyring.gpg > /usr/share/keyrings/zigbox.gpg
echo "deb [signed-by=/usr/share/keyrings/zigbox.gpg] https://zigbox.org/apt stable main" > /etc/apt/sources.list.d/zigbox.list
apt-get update && apt-get install -y zigbox uidmap passt
useradd -m tester
usermod --add-subuids 165536-231071 --add-subgids 165536-231071 tester
```

The session runs as root, so there is no `sudo`. Put these lines in your cloud environment's
setup script and every new session starts with `zbx` ready. Then run `zbx` as that user
(`su - tester -c 'zbx ...'`). As root, `zbx` also runs containers, but maps only root inside them
([W0201](https://zigbox.org/errors/box/W0201)), which breaks images that switch to another user.

Docker Hub limits anonymous pulls, and a session shares its address with many others, so pulls
soon get [E0506](https://zigbox.org/errors/box/E0506). Ask a mirror first:

```sh
export ZBX_REGISTRY_MIRRORS=mirror.gcr.io
```

If your cloud environment limits network access, it must allow `zigbox.org` and the registries
you pull from.

<!-- owner: the uidmap, passt, useradd and usermod lines and the mirror were run in a cloud
session on 2026-11-11 with zbx 0.4.0 built from source, because the apt repository was not live
yet (404). Run the apt lines, and the whole block as an environment setup script, once 0.5.x
is published. -->

## What works in a cloud session

Tried on 2026-11-11, as the user above:

- `zbx pull` and `zbx run`, with the default: no network, only `lo`;
- `--state` volumes, `run -d`, `ps`, `logs`, `exec`, `stop`;
- `key`, `sign`, `policy check`, a run under a policy, `verify`, `push --dry-run`;
- every `--output json`, `schema` and `explain` call below.

What does not work:

- **`--publish` and `--net user`** fail with [E0603](https://zigbox.org/errors/box/E0603): the
  session's `/dev/net/tun` can be opened by root only, and as root `pasta` cannot join the
  container's user namespace. Containers in a session have no network, so a container cannot
  serve a port to the session, nor download anything at run time.
- **`zbx build`** is refused with [E0307](https://zigbox.org/errors/box/E0307): a build needs
  cgroup v2, and the session's host has v1. Build on your own machine or in CI, push, and pull
  the result in the session.
- **Resource limits** (`--memory`, `--pids`, `--cpus`) are refused for the same reason. Every
  run warns [W0301](https://zigbox.org/errors/box/W0301) that it has no limits; that is
  expected in a session.
- `zbx doctor` fails its cgroup check ([E0103](https://zigbox.org/errors/box/E0103)) and exits
  2, although containers run.

## Claude Code driving zbx

In a cloud session or on your own machine ([Mac](try-mac.md), [Linux](try-linux.md)), Claude Code
uses `zbx` like any other command. Four things make that work without scraping text:

- **`--output json`** turns a command's output into JSON documents, and its diagnostics into JSON
  objects on stderr. Put it before the command name (`zbx --output json run ...`) or after it.
- **`zbx schema <command>`** prints the JSON Schema of that command's output, so an agent can
  check a document before it relies on a field.
- **Every error has a code** (`ZBX-E0522`), a `blame` (`user`, `environment` or `internal`) and
  fixes with a command to run. **`zbx explain <code> --output json`** gives the long
  explanation and the exit code.
- **Exit codes are fixed:** 0, 1 (refused input), 2 (the host is not ready), 70 (a bug), and for
  `zbx run`, 125 when it fails before the container starts, otherwise the container's own code.

A refusal, as an agent sees it:

```
$ zbx --output json run nosuch:1 -- true
{"code":"ZBX-E0522","severity":"error","blame":"user","summary":"no image of that name is locked or in the store","causes":["'/home/tester/hello/zbx.lock' has no entry for 'nosuch:1'"],"while":["finding the image 'nosuch:1'"],"context":{"path":"/home/tester/hello/zbx.lock","ref":"nosuch:1"},"fixes":[{"sentence":"pull it (this also records it in zbx.lock):","command":"zbx pull 'nosuch:1'"}],"docs":"https://zigbox.github.io/zigbox/errors/E0522.html","omitted":{"causes":0,"while":0,"context":0,"fixes":0}}
$ echo $?
125
```

The agent reads `fixes[0].command`, runs it, and tries again. `zbx doctor --output json` prints a
`zbx.doctor/1` document with one entry per check and, for a failed one, the same diagnostic.

The demos are checked this way: a scripted agent drives the pull, network, state,
dev-loop and build demos using only `--output json`, `zbx schema` and `zbx explain`, and records
what it still had to guess. Two that remain:

- A failed `zbx run` on the default network does not say in JSON that the network may be the
  cause; the hint that names `--net user` is printed as text only.
- `zbx run -d --output json` does not echo the network or the published ports; the agent has to
  remember what it asked for.

A few lines in your project's `CLAUDE.md` help Claude Code start well:

```markdown
Containers: use `zbx` (Zigbox), not Docker. Run `zbx doctor` first.
Pass `--output json` and act on a diagnostic's `fixes[].command`; `zbx explain <code>` explains a code.
Images must be pulled before `zbx run`. Containers have no network unless you pass `--net user`
(not available in a cloud session). In a cloud session, run zbx as `tester`: `su - tester -c 'zbx ...'`.
```

<!-- owner: the CLAUDE.md lines are a suggestion written for this guide, not tested with an
agent. -->
