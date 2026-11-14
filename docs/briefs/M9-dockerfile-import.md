# Brief: M9 · Dockerfile import

Read these first:
- `AGENTS.md`, `REVIEW.md`, `docs/STYLE.md` and `DIAGNOSTICS.md`.
- `docs/decisions/2026-11-11-docker-parity-scope.md` (why this is a goal, and what stays out).
- `docs/briefs/M7-build.md` and the code it produced (`src/build/`, `src/build_commands.zig`):
  M9 extends M7's build file and builder. A Dockerfile is translated, never executed.
- `docs/research/2026-11-11-dockerfile-survey.md`: 61 real Dockerfiles counted instruction by
  instruction. Every number below comes from it. Its "hard cases" are this brief's acceptance set.
- `zbx commit` (M3) and the store's tree format (`src/store/tree.zig`): a root step's output is a
  commit of its upper layer.

M9 starts after Zigbox 0.5.0 is tagged and targets 0.6.0. Every earlier demo keeps passing, and
`demo-m7`'s golden digest must not change: a build file without the new fields builds exactly as
before, key for key.

## Goal and demo

`zbx import` reads a Dockerfile and writes a `zbx.build.zon` that a person reads, commits and
builds with `zbx build`. The translation is deterministic (the same Dockerfile, build arguments,
`.dockerignore` and `zbx.lock` give the same bytes), it says which Dockerfile line each step came
from, and it flags every step that is not hermetic: network, cache mounts. Whatever cannot be
translated faithfully is refused by name, with the line and a fix, never approximated in silence.

The demo imports a two-stage Go project (ARG in `FROM`, `COPY --from`, a glob, a `.dockerignore`,
a user created in a `RUN` and named in `USER` and `--chown`, `EXPOSE`, `HEALTHCHECK`), builds it,
runs it, rebuilds it with every step a hit, gets the same import bytes and the same result digest
on a second clean VM (checked against a golden), and shows a network target flagged on import and
refused under `--hermetic`.

## How a Dockerfile maps (fixed)

### Builder additions (in the build file, usable by hand too)

M7's step runs a command against a base and keeps only `/out`. A Dockerfile stage is a chain of
changes to a whole root file system. M9 adds what that needs, and nothing else:

- **`.base = "step:<name>"`**: the step starts from the root output of an earlier step instead of
  a locked image. It counts as a need for the graph (ordering, cycles, `E0802`), not for the
  mount count. The chain's image config (its `env` and the rest) is the config of the image at
  the chain's start (`scratch`: none).
- **`.output = .root`** (default `.out`, which is M7's behaviour): the step's output is its whole
  root after the run: the base tree with the step's upper layer committed onto it, exactly as
  `zbx commit` does (deletions applied, no whiteouts kept, owners kept in container ids). `/out`
  is not mounted for such a step. Device files, FIFOs and sockets are refused as for `/out`
  (`E0806`). `/src` is not mounted either: a root step reads the project only through a `copy`
  step or a bind (below).
- **`.user`** and **`.workdir`** on a step: who the step runs as and where. `user` is
  `uid:gid`, `uid`, `name` or `name:group`; a name is resolved at build time from the step's base
  tree (`/etc/passwd`, `/etc/group`), so `RUN adduser app` followed by `USER app` works. A name
  that is not there is `E0817`. `HOME` in the fixed environment is the user's home from
  `/etc/passwd` (`/` if none) instead of `/root`; the rest of M7's fixed environment is unchanged.
  The step runs with that uid and gid inside the user namespace, with no capabilities when it is
  not 0.
- **`.copy` steps.** A step with `copy` and no `run` puts files into its base's tree, with
  Docker's rules: later files replace earlier ones, a source directory's contents are copied (not
  the directory), a destination ending in `/` is a directory, missing parents are created
  `0755`, owned by the entry's `.chown` owner (0:0 with none) as Docker gives them; a parent the
  base already has keeps its own mode and owner
  (`docs/decisions/2026-11-14-m9-copy-chown-rulings.md`). Each entry is `.{ .from = "<input path>" | "step:<name>" | "<locked ref>",
  .src = .{ ... }, .to = "/abs/path", .chown = "...", .chmod = "0644" }`. Sources from a step or
  an image may use globs (`*`, `?`, `[...]`), matched at build time against that tree. `chown`
  names are resolved as `.user` is, against the destination tree. An entry may give `.exclude`, as
  inputs do (`COPY --exclude`). It is pure store work, like M7's image assembly: no container,
  cached the same way, reported as a step.
- **Input globs and excludes.** `inputs` may use the same globs, and a step or the file may give
  `.exclude`, a list in `.dockerignore` syntax (`**`, `!` re-includes, later lines win). Both are
  evaluated at build time against the project, so a new file that a `COPY *.go` would take is
  taken, and an excluded file is never read. The matched set is what enters the input tree, so
  the key does not change unless the matched files do.
- **`.caches`** on a step: `.{ .{ .id = "go-build", .path = "/root/.cache/go-build" } }`. Each is a
  writable directory kept per project under the store's `build/caches/<project hash>/<id>`,
  bound at `path`. A cache is not in the step's key and not in its output. Steps that share an
  id run one at a time (Docker's `sharing=locked`). The build report marks the step `cache`, and
  `W0802` names such steps once per build: their output can depend on what a cache held.
  `zbx store gc` does not touch caches; `zbx build --clear-caches` empties the project's.
- **`.binds`** on a step: read-only mounts of a project path or of a needed step's tree at an
  absolute path (`RUN --mount=type=bind`). They count against the run's mount limit with
  `needs`.
- **`image.base = "step:<name>"`**: the result's tree is that step's root output; `add` may still
  follow. Config is inherited from the chain's start image, field by field, as M7 inherits from
  a locked base.
- **`config.user`** accepts a name, resolved against the result's tree when the result is
  assembled. The build record holds the numeric `uid:gid`, so a result's identity stays numeric.
- **Keys.** Each new field enters a step's key preimage only when it is set, as a tagged
  extension after M7's fields. A file without them has M7's keys (the `demo-m7` golden is the
  proof). `step_format_version` is not bumped.
- **Bounds** (supervisor decision; the survey's largest translated stage set needs 131 steps):
  `build_steps_max` 64 → 256, `build_file_bytes_max` and `build_pool_bytes` 64 KiB → 256 KiB.
  New constants: `build_step_caches_max` 4, `build_step_binds_max` 4 (with `needs`, still
  within the run's 8 mounts), `build_copy_entries_max` 64, `build_exclude_lines_max` 256.
  Each with a comptime assert against what it feeds.

### `zbx import`

```
zbx import [<Dockerfile>] [--context <dir>] [--target <stage>] [--build-arg K=V]...
           [--network detect|all|none] [--hermetic] [-o <file>] [--force]
```

- Defaults: `./Dockerfile`, context `.`, the last stage, `--network detect`, output
  `zbx.build.zon` in the context. The output is refused if it exists (`E0816`) unless `--force`.
- **Base images.** Every `FROM` and `COPY --from` image is resolved as `zbx pull` resolves it,
  and pinned in `zbx.lock`. A reference the lock already pins is never re-resolved, so a
  committed lock makes import reproducible and offline. `FROM scratch` is an empty base. Only
  stages the target reaches are translated (and only their images pulled).
- **The output** is a build file with a header naming the Dockerfile and the arguments used,
  and a `// Dockerfile:<line>  <instruction>` comment before each step. Step names are
  `<stage>-<n>`, the stage name lowered and cut to `[a-z0-9-]`, unnamed stages `stage<i>`,
  numbered within the stage; a collision is refused (`E0813`), never renamed silently.
- **The report** (stderr, text; `--output json`, schema `zbx.import/1` in `zbx schema import`):
  one line per step with its Dockerfile line and its flags (`net (matched "apk add")`, `cache`,
  `bind`), then what did not carry over (labels made, instructions ignored), then the counts.
  A report with flags ends with `W0810`; one with dropped instructions, `W0811`.
- **`--hermetic`** refuses the import (`E0814`, naming the first flagged line and why) when any
  step would have the network or a cache. The build file is not written.
- **The library.** `zigbox.dockerfile.translate` is a pure function: the Dockerfile bytes, the
  `.dockerignore` bytes, the arguments, the target and the platform, and a resolver for image
  references, in; the build file bytes, lock additions and the report, out. No I/O, no
  process-wide state. The CLI does the reading, the pulls and the writing. A test calls it from a
  caller other than the CLI.

### The mapping

| Dockerfile | Survey (files) | Build file |
|---|---|---|
| `FROM ref [AS name]` | 100% | a chain starting at the locked ref; `--platform` must name the host platform or `$BUILDPLATFORM`/`$TARGETPLATFORM`, otherwise `E0811` |
| `FROM <stage>` | 70% multi-stage | `base = "step:<last step of stage>"` |
| `RUN` (shell form) | 97% | a root step, argv = current `SHELL` (default `/bin/sh -c`) + the text |
| `RUN` (exec form) | | a root step with that argv |
| `RUN <<EOF` heredoc | 5% | the body is the shell's script; `<<-` strips tabs; an interpreter after the delimiter, a shebang body or two heredocs in one `RUN` is `E0811` |
| `RUN --mount=type=cache` | 28% | `.caches` (`id` defaults to the target path; `ro`, `mode`, `uid`, `gid` kept; `sharing` is always `locked`; `from` is `E0811`); flagged |
| `RUN --mount=type=bind` | 10% | `.binds` (`from` a stage, a locked image or the context, `source` within it); `rw` is `E0811` |
| `RUN --mount=type=secret\|ssh\|tmpfs` | 2% / 0% / 0% | `E0811` |
| `RUN --network=none\|default` | | no network / per `--network`; `host` is `E0811` |
| `RUN --security`, `RUN --device` | | `sandbox` noted (`W0811`); `insecure` and `--device` are `E0811` (devices: M10) |
| `COPY src... dest` | 92% | a `copy` step from project inputs |
| `COPY --from=<stage\|image>` | 69% | a `copy` step from `step:` or the locked image; globs at build time |
| `COPY --chown`, `--chmod` | 13%, 7% | `.chown`, `.chmod` |
| `COPY --link` | 10% | ignored: our copy has its meaning already (`W0811`) |
| `COPY --exclude` | | the copy entry's `.exclude` |
| `COPY <<EOF` heredoc, `--parents` | | `E0811` |
| `ADD` local file or directory | 11% | as `COPY` (a local archive only with `--unpack=false`) |
| `ADD` URL, git URL, or a local tar | 3%, 2%, 0% | `E0811`, the fix showing a `RUN` with a checksum |
| `ENV` | 79% | resolved and carried into each later step's `env` and the config |
| `ARG` | 79% | resolved at import from `--build-arg` or the default; a needed `ARG` with neither is `E0812`. `TARGETOS`, `TARGETARCH`, `TARGETPLATFORM`, `BUILDPLATFORM` and friends are the host's. A `RUN` sees in-scope args in its env, as Docker's does |
| `WORKDIR` | 79% | `.workdir` on later steps (created by the next step, `0755`); the config's `workdir` |
| `USER` | 34% (name 26%) | `.user` on later steps; the config's `user`; names resolved at build time |
| `SHELL` | 10% | changes the argv prefix of later shell-form instructions |
| `ENTRYPOINT`, `CMD` | 75%, 48% | config, Docker's shell-form and inheritance rules |
| `LABEL` | 38% | config labels; a key outside `[a-z0-9._/-]` is `E0811` naming it |
| `EXPOSE`, `VOLUME`, `HEALTHCHECK`, `STOPSIGNAL` | 62%, 28%, 23%, 2% | labels `org.zigbox.import.expose`, `.volume`, `.healthcheck`, `.stopsignal`, the value as written (a `HEALTHCHECK`'s flags included); listed in the report (`W0811`) |
| `ONBUILD`, `MAINTAINER` | 0% | `E0811`; `MAINTAINER` becomes a label |
| `# syntax=`, `# escape=`, `# check=` | | `syntax` and `check` ignored (`W0811`); `escape` honoured |
| `BUILDKIT_*` and `SOURCE_DATE_EPOCH` args | | ignored (`W0811`); the fixed environment keeps its `SOURCE_DATE_EPOCH` |
| `HTTP_PROXY` and the other proxy args | | from `--build-arg` only, in `network = true` steps' env, never in the config |

Variable substitution follows Docker's (`$X`, `${X}`, `${X:-w}`, `${X:+w}`, `${X-w}`, `${X+w}`,
`${X?m}` and `${X:?m}` as `E0812`, escapes) in the instructions Docker substitutes in, and nowhere
else. A `RUN`'s own text is left to its shell. The pattern forms (`${X#p}`, `${X%p}`, `${X/p/r}`
and their doubles) are pre-release Docker syntax and `E0811`.

Every option of every instruction, with its disposition, is in `M9-dockerfile-flags.md`. Where
that table and this section disagree, this section wins.

**Network detection** (`--network detect`): a `RUN` gets `network = true` when its text holds a
word from a checked-in table (`apk add`, `apt-get`, `apt`, `dnf`, `yum`, `pip install`,
`uv`, `poetry`, `npm`, `yarn`, `pnpm`, `go mod download`, `go get`, `go install`, `cargo build`,
`cargo fetch`, `cargo install`, `bundle`, `gem install`, `composer`, `mvn`, `gradle`, `curl`,
`wget`, `git clone`, and the rest the survey found). The report names the word that matched. A
miss is caught by M7: the build fails with `E0805`'s "the step has no network" and the fix
naming the step. `all` gives every `RUN` the network, as Docker does; `none` gives none.

**Where we differ from Docker** (written in `docs/demos/m9.md` and `zbx explain E0810`): steps
run rootless under M2's hardening and M7's fixed environment and timestamps; there is no daemon
cache, only the store's; `RUN` without a detected fetch has no network; image references are
pinned once and never re-resolved by a build.

## Diagnostics (`08xx`, each with cause, fix, goldens and an error page)

Import takes `E0810`–`E0819` and `W0810`–`W0811` from the build range; `W0802` and `E0817` are
the builder's. Registered by the supervisor with this brief.

- `E0810` the Dockerfile cannot be read or parsed (line, column, what was expected).
- `E0811` an instruction, flag or form is not supported (names it and its line; the fix says what
  to write instead, from the table above).
- `E0812` a variable has no value (names it, its line, and `--build-arg NAME=...`).
- `E0813` a stage problem: an unknown `--target`, `FROM` or `--from` stage, a stage cycle, two
  stages whose step names collide.
- `E0814` `--hermetic` refused a step (its line and the flag it carries).
- `E0815` the translation exceeds a builder bound (which bound, the count, the stage).
- `E0816` the output file exists (fix: `--force` or `-o`).
- `E0817` a user or group name is not in the tree's `/etc/passwd` or `/etc/group` (the step or
  `image.config`, and the name).
- `W0802` the build has steps with cache mounts (named).
- `W0810` the import has steps that are not hermetic (named, with why).
- `W0811` parts of the Dockerfile did not carry over as instructions (named, with what became of
  each: a label, or ignored).

An import that is refused exits 1 and writes nothing.

## Slices (commit and stop for review after each; do not push to the working branch)

1. **The build file grows.** Parser, validation and canonical printer for every builder addition
   above; `step:` bases in the graph (ordering, cycles, `--graph` text and JSON); globs and
   `.dockerignore` matching as a pure function; key encoding of the new fields (unit tests: an
   M7 file's keys are unchanged, byte for byte against `demo-m7`'s recorded keys; each new field
   changes the key; an excluded file never changes it). The bounds change. The `build_file` fuzzer
   learns the new fields; a new `dockerignore` fuzzer (random patterns and paths: never crashes,
   agrees with a slow reference matcher) at 10,000 iterations. *Mechanical, for Haiku:* the
   constants and their asserts, `E0817`/`W0802` registration boilerplate, error pages,
   `zbx explain` entries and goldens once their text is written.
2. **Root steps run.** `.output = .root` through commit, `.user`/`.workdir`/`HOME`, name
   resolution and `E0817`, `copy` steps (with Docker's replacement rules, globs on trees,
   `chown`/`chmod`), `.caches` with per-id locking and `--clear-caches`, `.binds`,
   `image.base = "step:"` and `config.user` names. The simulator: random chains of root and copy
   steps with crashes at every write; a copy is a pure function of its sources; a cache never
   changes a key. VM check (`vm/m9-slice2`): a hand-written build file with a chain that runs
   `adduser`, copies with `--chown` by name, and runs as that user, built twice (misses, then
   hits).
3. **The translator.** The Dockerfile parser (directives, continuations, `escape`, comments,
   exec and shell forms, flags, heredocs), substitution, stages and `--target` pruning, the
   mapping table, network detection, emission, the report, `zbx import` with lock resolution
   through the library pull, `zigbox.dockerfile.translate` with its second-caller test, `E0810`
   to `E0816`, `W0810`, `W0811`. A `dockerfile` fuzzer (random and mutated files from the
   fixture set: never crashes, every refusal is a registered code, every accepted translation
   parses with slice 1's parser and prints back to the same bytes) at 10,000 iterations. The
   fixtures (below), each with a golden output. **Slice 3 may start as soon as slice 1 merges, in
   parallel with slice 2**: it needs only the file format. *Mechanical:* registration, error
   pages, explain entries, golden copying.
4. **VM, CI and the corpus.** `zig build demo-m9` exactly as below, every assertion a
   unit-tested pure function in `checks_m9.zig`; the second VM; the golden import bytes and
   golden digest; ACCEPT; the agent test by JSON only (`import`, `build`, `explain`); the
   `demo-m9` CI job and its path rule in `.github/ci-changes.sh` (with a table-test row);
   `docs/demos/m9.md` with the by-hand steps, cuts and the differences from Docker. **The corpus
   run:** import every file the survey lists (its URLs, fetched by hand in the session, not
   checked in: their licences vary) and record in `docs/demos/m9.md` how many translate, and the
   refusals by code. A crash or an unregistered refusal there is a bug to fix in this slice.
   *Mechanical:* `m9` in `vm.yml`'s picker and `all` list, the demo-table entry in `build.zig`,
   the CI job copied from `demo-m7`'s, the goldens copied from the first green run.
5. **The Mac** (after slice 4; cuttable): `import` forwarded like `build`, and `demo-mac`
   importing and building the demo project.

### The fixtures (the acceptance set)

Hand-written under `src/build/dockerfile_fixtures/`, one per pattern the survey found hard, each
naming the survey file and line that motivated it. Each has a golden translation or a golden
refusal.

- `ARG` in `FROM` (prometheus:3, docker/cli `Dockerfile.dev`:14), with and without
  `--build-arg`, and with no default (`E0812`).
- `ARG` in `COPY` paths and in `USER` (vault:85, vault:132, grafana:290).
- `ADD` of a URL built from an `ARG` (mastodon:219), and of a git URL (moby:113): `E0811`.
- Heredoc `RUN` (docker/cli `Dockerfile.dev`:59, moby:158).
- Shell logic in `RUN` (grafana:51, 70, 189): passed through to the shell untouched.
- `SHELL` (mastodon:75).
- `COPY --from` a stage with a glob (docker/cli `Dockerfile.dev`:86).
- `COPY --from` an image reference; `FROM --platform=$BUILDPLATFORM`; `TARGETARCH` in a path.
- Cache and bind mounts (ollama, rclone); a secret mount (vllm): `E0811`.
- `USER` by name after `adduser` in a `RUN`; `USER` numeric; `USER` from a variable.
- `.dockerignore` with `**` and `!`; `Dockerfile.dockerignore` beside a named Dockerfile.
- `--target` skipping a stage that would be refused.
- `# escape=` with a backtick; line continuations inside exec form.
- Labels from `EXPOSE`, `VOLUME`, `HEALTHCHECK`, `STOPSIGNAL`; a label key we cannot keep.
- `ONBUILD`: `E0811`. A Dockerfile over the step bound: `E0815`. Two stages whose names
  collide after lowering: `E0813`.

## The demo: `zig build demo-m9`

The project is checked in at `src/testing/vm/m9_project/`: `Dockerfile`, `.dockerignore`
(`README.md`, `*.tmp`), `zbx.lock` pinning `golang:1.23-alpine` and `alpine:3.20` for
`linux/amd64` (M7's pins), `go.mod`, `main.go` (prints `hello from zigbox`, and with `--whoami` its
uid), `VERSION`, `LICENSE`, `README.md`. The Dockerfile:

```dockerfile
# syntax=docker/dockerfile:1
ARG GO_VERSION=1.23
FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
ENV CGO_ENABLED=0 GOFLAGS="-trimpath -buildvcs=false" GOPROXY=off
RUN go build -ldflags="-s -w -buildid=" -o /usr/local/bin/hello .

FROM alpine:3.20 AS tools
RUN --mount=type=cache,target=/var/cache/apk apk add curl

FROM alpine:3.20
RUN adduser -D -u 10001 app
COPY --from=build /usr/local/bin/hello /usr/local/bin/hello
COPY --chown=app:app --chmod=0644 VERSION LICENSE /etc/hello/
USER app
WORKDIR /home/app
EXPOSE 8080
HEALTHCHECK CMD ["/usr/local/bin/hello", "--whoami"]
ENTRYPOINT ["/usr/local/bin/hello"]
```

The harness copies it into the guest as the ordinary user's `~/hello`. Images come through
`mirror.gcr.io` with the blob cache, as `demo-m7`'s do. Parts in order: SPEC, ACCEPT, AGENT.

1. **Import.** `cd ~/hello && zbx import` exits 0. `zbx.build.zon` equals the golden
   `m9_expected.build.zon` byte for byte; `zbx.lock` is unchanged. The report lists every step
   with its Dockerfile line, no `net` and no `cache` flag (the `tools` stage is not reached),
   and `W0811` naming `EXPOSE` and `HEALTHCHECK` as labels.
2. **Build and run.** `zbx build` exits 0 and ends `built b3:<64 hex>`. `zbx run <digest>` prints
   `hello from zigbox`; `zbx run <digest> -- /usr/local/bin/hello --whoami` prints `10001`;
   `zbx inspect <digest> --output json` shows `user` `10001:10001`, workdir `/home/app` and the
   two labels; `/etc/hello/VERSION` in the tree is owned `10001:10001`, mode `0644`.
3. **Again.** `zbx build --output json`: every step `hit`, the same digest.
4. **Globs and excludes.** `echo more >> README.md && zbx build`: all hits, the same digest.
   `cp main.go extra.go` with a second `func` renamed so it compiles, `zbx build`: the
   `build` stage's copy and compile steps miss, the final stage's `adduser` step hits, a new
   digest. Remove `extra.go`; `zbx build` gives the first digest with every step a hit.
5. **A second clean VM.** As `demo-m7`'s step 5: the same project, `zbx import` gives the same
   bytes, `zbx build` gives step 2's digest, which equals the golden in
   `src/testing/vm/m9_expected.zon`.
6. **Not hermetic.** `zbx import --target tools -o tools.build.zon` exits 0; its report flags
   `tools-1` with `net (matched "apk add")` and `cache`, and ends with `W0810`.
   `zbx import --target tools --hermetic -o t2.build.zon` exits 1, stderr starts
   `error[ZBX-E0814]:` and names `Dockerfile:11`, and `t2.build.zon` does not exist.
   `zbx build -f tools.build.zon` exits 0 with `W0801` and `W0802`; `zbx run <it> -- curl
   --version` exits 0.

ACCEPT also checks: every fixture's golden, through the binary; `zbx build --graph` on the
imported file against its golden; reordering nothing in the Dockerfile but its comments gives the
same bytes; an unlocked `FROM` with the network down is the pull's own `05xx` refusal;
`zbx import` over an existing file is `E0816`; the steps' run records and `build/work/` are gone
after the build. AGENT: `zbx import --output json` against `zbx schema import`, `zbx explain
E0811`.

## Non-goals

- Executing a Dockerfile, or `docker build` flags and output. `zbx import` and `zbx build` are the
  interface (the Docker parity decision).
- BuildKit frontends (`# syntax=` is ignored), `RUN --security`, multi-platform builds, and
  cross-building.
- Secret and ssh mounts, tmpfs mounts, `ADD` of URLs, git repositories or tar archives,
  `COPY <<EOF`, `ONBUILD`, named build contexts. Each is refused by name.
- Keeping a Dockerfile and its build file in sync, or importing on every build. The build file is
  the source once written.
- Compose files, `docker-compose build`, and anything that needs several containers (Zigcube).
- Pulling from registries other than Docker Hub, GHCR and ECR (parked, the parity decision).
- GPU access, which has its own brief.

## Scope that can be cut while keeping the demo

Record any cut in `docs/demos/m9.md`.
- **`.binds`** and `RUN --mount=type=bind` (10%): refuse it with `E0811` instead.
- **Heredoc `RUN`** (5%): refuse it.
- **`COPY --from` an image reference**: refuse it; stages only.
- **`--network all|none`**: keep `detect`.
- **`--clear-caches`**: document `rm -rf` of the directory instead.
- **Slice 5 (the Mac).**

Not cuttable: root output and `step:` chains, build-time user names, globs and excludes at build
time, network detection with the report, `--hermetic`, and the second-VM golden.

## Choices the supervisor made (the owner may overrule)

The owner asked for sane assumptions, documented. These are the brief's:
1. **One step per instruction**, chained, rather than one step per stage: the cache then behaves
   as Docker users expect (a change late in a stage reuses everything before it).
2. **`detect` is the default network rule**, not Docker's "every `RUN` has the network": 46% of
   `RUN` lines fetch, and a miss fails loudly with the fix.
3. **Names resolve at build time**, not import time: 26% of files name a user, often one a `RUN`
   just created, which the base's `/etc/passwd` does not have.
4. **Globs and excludes are evaluated at build time.** M7 cut globs; import-time expansion would
   freeze the file list and miss the next `.go` file.
5. **Cache mounts are kept** (28% of files), out of the key and flagged, rather than dropped.
6. **The bounds above** grow to fit the survey's largest translated target.

## Spec notes (flagged, not changed)

- **SPEC.md's non-goals** still say Dockerfile import is a stretch (S4) and GPU passthrough a
  non-goal. The parity decision overrides them until the next spec sync, which also adds M9.
- **M7's non-goals** (build arguments, host cache mounts, globs) are partly reversed for build
  files: arguments only through import, caches flagged, globs at build time.
- **M7's "user is numeric; names are not resolved at build time"** is reversed. The build record
  stays numeric.
- **DIAGNOSTICS.md** gives `08xx` to build; this brief takes `E0810`–`E0817` and `W0802`,
  `W0810`, `W0811` from it, and leaves the rest of `08xx` free.
