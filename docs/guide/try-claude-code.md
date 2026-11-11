# Try Zigbox in Claude Code

There are two questions here: can an agent such as Claude Code drive `zbx` well, and does `zbx`
run inside a Claude Code cloud session. The short answers: yes, `zbx` was designed to be driven
by an agent; and in a cloud session it runs containers today with some setup, but cannot publish
ports or build.

## Claude Code driving zbx

On your own machine, install `zbx` ([Mac](try-mac.md), [Linux](try-linux.md)) and Claude Code can
use it like any other command. Four things make that work without scraping text:

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

Every change to `zbx` is tested this way: a scripted agent drives the pull, network, state,
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
Images must be pulled before `zbx run`. Containers have no network unless you pass `--net user`.
```

<!-- owner: the CLAUDE.md lines are a suggestion written for this guide, not tested with an
agent. -->

## zbx inside a Claude Code cloud session

**Partly.** We tried `zbx 0.4.0` in a Claude Code cloud session on 2026-11-11. That container runs
as root, on a cgroup v1 host, without `newuidmap` or `pasta`, and its outbound traffic goes
through a proxy.

What works, after the setup below:

- `zbx pull` from Docker Hub (through a mirror, see below) and `zbx run`, as root or as an
  ordinary user;
- the default no-network container, `--state` volumes, `run -d`, `ps`, `logs`, `exec`, `stop`;
- `key`, `sign`, `policy check`, a run under a policy, `verify`, `push --dry-run`;
- every `--output json`, `schema` and `explain` call above.

What does not work, and why:

- **`--publish` and `--net user`** fail with [E0603](https://zigbox.org/errors/box/E0603): the
  session's `/dev/net/tun` can be opened by root only, and as root `pasta` cannot join the
  container's user namespace. Containers there have no network.
- **`zbx build`** is refused with [E0307](https://zigbox.org/errors/box/E0307): a build needs
  cgroup v2, and the host has v1.
- **`--memory`, `--pids`, `--cpus`** are refused for the same reason, and every run warns
  [W0301](https://zigbox.org/errors/box/W0301) that it has no limits.
- `zbx doctor` fails its cgroup check ([E0103](https://zigbox.org/errors/box/E0103)) and exits
  2 even when everything else is ready.

### Setup we used

No Linux binary is published yet, so we built `zbx` from source; Zig downloads work through the
session's proxy. Then, as root in the session:

```sh
apt-get install -y uidmap passt
useradd -m tester
usermod --add-subuids 165536-231071 --add-subgids 165536-231071 tester
```

and ran `zbx` as that user (`su - tester`). As root, `zbx` also runs containers, but maps only
root inside them ([W0201](https://zigbox.org/errors/box/W0201)) and `doctor` fails its
`subid` check too.

Docker Hub limits anonymous pulls, and a session shares its address with many others, so pulls
soon get [E0506](https://zigbox.org/errors/box/E0506). Ask a mirror first:

```sh
export ZBX_REGISTRY_MIRRORS=mirror.gcr.io
```

If your cloud environment limits network access, it must allow the registries you pull from.

<!-- owner: findings from one session; worth re-checking with 0.5.1 and a published binary. -->

## Not yet

- Ports and builds in a cloud session, as above. Both need a host change, not a `zbx` change.
- A published `zbx` binary to download into a session in one line.
