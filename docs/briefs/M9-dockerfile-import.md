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
- `docs/decisions/2026-11-14-m9-pinned-fetches-and-output-pins.md`: the owner's rulings on fetches
  pinned by hash and on output pins for network steps. They amend this brief (sections marked
  *owner, 2026-11-14*).

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
refused under `--hermetic`. It then imports and builds an `ADD --checksum` from a local test
server (downloaded once, never again, refused when the bytes differ), and pins a network step
with `zbx build --pin`, then shows `--locked` refusing it when its output drifts.

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

### Pinned fetches and output pins (*owner, 2026-11-14*)

Two additions let a build use the network and still get the same result twice. A file fetched by
hash is content-addressed from the start. A network step's output can be pinned, so a change in
what it fetched is caught and reported rather than passed on silently. Neither changes a build
file that does not use it: the `demo-m7` golden and the M9 import golden stay as they are.

**Fetches.** A copy entry may name a download instead of `.from`/`.src`:

```zig
.{ .name = "fetch-tool", .base = "step:final-1", .copy = .{
    .{ .fetch = .{ .url = "https://example.org/tool-1.2.tar.gz", .sha256 = "<64 hex>" },
       .to = "/opt/tool.tar.gz", .chmod = "0644" },
} },
```

- A fetch is a copy source, so a `RUN` reaches the file the way it reaches any copied file: the
  copy step goes in its chain, or a copy step on `scratch` is one of its `needs`. That adds no new
  mount kind, and the step that uses the file runs with no network. Reason: the Dockerfile form
  is `ADD` then `RUN`, so this is the shape import already emits for `ADD`, and the builder needs
  only one new source kind.
- The download happens in the parent, before any step runs, outside every sandbox, through the
  pull's HTTP client (proxies from the environment, `SSL_CERT_FILE` honoured). Only `https://`
  is fetched. Plain `http://` is allowed only for a loopback host, the rule the registry client
  has followed since M8. A redirect may not go from `https` to `http`, and may not go from a
  non-loopback host to a loopback one. Every hop counts against the redirect bound.
- The bytes stream to `blobs/partial/` and are hashed as they arrive. When the SHA-256 matches,
  the file is renamed to `blobs/sha256/<hex>`, where downloaded registry blobs already live. When
  it does not, the partial file is deleted and the build fails with `E0821` before any step runs.
  If the store already has `blobs/sha256/<hex>`, from an earlier build or a pull of a layer with
  that digest, nothing is downloaded.
- **The key** of a copy entry with a fetch is tagged `fetch` and covers the SHA-256, `.to`,
  `.chown` and `.chmod`. It never covers the URL. A mirror URL serving the same bytes is a hit,
  and the same URL serving different bytes is refused, not rebuilt. A copy step that hits its
  cache needs no bytes, so a warm store builds with no network at all.
- Defaults follow Docker's remote `ADD`: mode `0600` unless `.chmod` is given, owner `0:0` unless
  `.chown` is given, and the file name taken from the URL's last path segment when `.to` ends in
  `/`. The file is never unpacked.
- `zbx store gc` treats a fetched blob as it treats a build cache entry: it is kept while a step
  record names it.
- At load time, a URL that is not `https://` (or loopback `http://`), a URL longer than the URL
  bound, or a `sha256` that is not 64 lowercase hex characters is `E0801`.

**Output pins.** A pin is the output digest a network step is expected to produce.

- **`.expect = "b3:<hex>"`** on a step with `network = true` is a pin written by hand. On any
  other step it is `E0801`: a step without the network is already keyed by what it reads. On a
  step with `.caches` it is also `E0801`, because the step's output depends on a cache that is
  outside its key (*supervisor, 2026-11-14*); `zbx build --pin` leaves such a step unpinned.
- **`zbx build --pin`** records, in `zbx.lock`, the output of every network step that has no
  `.expect` and no current pin. A pin is current when its recorded key equals the step's key, so
  a step whose key has changed gets a new pin. The lock is written once, atomically, and only
  when the build succeeds. Pins sit next to the image pins:

  ```zig
  .pins = .{
      .{ .file = "zbx.build.zon", .step = "fetch-deps", .key = "b3:<hex>", .output = "b3:<hex>" },
  },
  ```

  Pins are sorted by file, then step. A lock with no pins keeps `.version = 1` and is
  byte-identical to the lock M7 writes. A lock with pins is `.version = 2`, so an older `zbx`
  refuses it rather than ignoring the pins.
- A **pinned step** is one with `.expect`, one with a current lock pin, or one this build is
  pinning. When a pinned step's output equals its pin, the steps after it are keyed by the pin.
  In M9 the pin and the output are then the same bytes; keying by the pin is what lets a later
  shared cache skip the network step on a host whose dependents already hit (not built here).
- **Drift** is a pinned step whose output differs from its pin. Under `--locked` or `--hermetic`
  it is `E0822`, naming the step, the pinned digest and the new one. No step that depends on it
  runs, and the lock is not changed. Without those flags it is `W0803`, naming the same three:
  the new output is used, every step after it misses and rebuilds, and the pin stays as it was,
  so the warning repeats on every build until the pin is updated. A person accepts drift by
  deleting the pin and running `zbx build --pin`, or by editing `.expect`. There is no `--repin`
  flag (*supervisor, 2026-11-14*).
- **`.output_exclude`** on a step is a list of absolute paths whose changes are dropped from the
  output before it is hashed. In a root output, an excluded path is left as the base had it. In
  an `/out` output, it is absent. A pinned step without `.output_exclude` gets
  `.{ "/var/log", "/var/cache", "/var/lib/apt/lists", "/tmp" }`. The list, whether written or defaulted, enters the
  step's key, so the first `--pin` of an existing network step re-runs it once. A lock pin is found
by file and step name, and is current when its key equals the step's key computed with the
defaults applied, so the defaults never make a pin look stale. Package databases
  (`/var/lib/dpkg`, `/lib/apk/db`, `/var/lib/rpm`) are content and must not be excluded. What M7
  already normalises, and what it does not, is under *Spec notes*.

**`zbx build --locked`** (no such flag exists on `build` under any name; `cli.zig` has `-f`,
`--graph`, `--clear-caches`, `--output` and `--verbose`). The build adds nothing to the lock and
enforces every pin. A stale pin, one whose key no longer matches, is `E0822` rather than a
re-pin. A network step with no pin runs as it does today, with `W0801`. `--pin --locked` is a
usage refusal, `E0005`, and the message names both flags.

**`zbx build --hermetic`** (new on `build`; `zbx import` already has it): `--locked`, plus a
refusal of any network step without a pin and of any step with `.caches`. It reuses `E0814`,
naming the step instead of a Dockerfile line. *Supervisor choice, 2026-11-14*: the ruling
names the flag but does not define it. It is cuttable to an alias of `--locked`.

**Mirror snapshots are out of scope** (owner). An apt or apk mirror that publishes a new package
version changes what a step installs. That is drift, and it is reported loudly by `W0803` or
`E0822`. It is not prevented.

**Bounds (approved by the owner, 2026-11-14; added to `constants.zig` in slices 3b and 3c):**

| Constant | Value | Reason |
|---|---|---|
| `build_fetch_bytes_max` | 1 GiB | The largest common `ADD` payloads are toolchains and JDKs, 50 to 200 MB. The bytes go to disk, not memory, so the bound only stops a runaway server. The alternative is 4 GiB, the store's largest object. |
| `build_fetch_redirects_max` | 4 | Equals `registry_redirects_max`. GitHub release assets take one redirect and most CDNs take one or two. |
| URL length | 2048 bytes | Reuses `registry_url_bytes_max`. |
| Timeouts | 30 s idle | Reuse `net_idle_timeout_ms` (30 s). There is no total-time bound, because a 1 GiB file on a slow link must be able to finish. |
| `build_output_excludes_max` | 32 | Four defaults, room for one per package manager's log and cache directories. |
| `lock_pins_max` | 256 | Equals `build_steps_max`: a build file cannot pin more steps than it has. |

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
| `ADD --checksum=sha256:<hex> <url> <dest>` | | a `copy` step with `.fetch = .{ .url, .sha256 }` (*owner, 2026-11-14*); `--chmod`, `--chown` kept; not flagged, and accepted under `--hermetic` |
| `ADD <url>` without `--checksum`, a git URL, or a local tar | 3%, 2%, 0% | `E0811`; for a URL the fix shows `ADD --checksum=sha256:<hex>`, or a `RUN curl` that import flags `net` |
| `ADD --checksum=sha256:` on a git URL or a local file; `sha384`/`sha512` | | `E0811` naming the form |
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

**For fetches and pins (approved by the owner, 2026-11-14; registered in slices 3b and 3c).**
They come after the import range (`E0810`–`E0819`). `W0803` is the next free
builder warning.

- `E0820` a fetch could not be downloaded: the url, and why (the HTTP status, the network error,
  over `build_fetch_bytes_max`, too many redirects, a redirect to `http` or to loopback, a URL
  that is not `https`). Blame: external, exit 3. Fix: check the URL, or put the bytes in the
  store with an earlier build on a host that can reach it.
- `E0821` the fetched bytes do not match: the url, the expected `sha256:<hex>` and the received
  one. Blame: external, exit 3. Two fixes, because either side can be wrong: correct `.sha256`
  (or `--checksum`) if the hash was copied wrongly, or find out why the server's file changed
  before trusting it.
- `E0822` a pinned step's output differs from its pin under `--locked` or `--hermetic`, or its pin
  is stale: the step, the pinned digest and the new one (or, for a stale pin, the two keys).
  Blame: external, exit 3, since what the network served changed. Fix: run without `--locked`
  to see the new output, then delete the pin and `zbx build --pin` (or edit `.expect`) to accept
  it.
- `W0803` a pinned step drifted and the new output was used: the step, the pinned digest and the
  new one, and that the steps after it rebuild.

Under `--pin --locked` the usage refusal is `E0005`. Build `--hermetic` reuses `E0814`. Neither
needs a new code.

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
3b. **Pinned fetches** (*owner, 2026-11-14*; after slice 2 merges, and after slice 3 for the
   import half). The `.fetch` source in the parser, printer and validation; the download in the
   parent through the pull's client (https only, loopback http, the redirect rules and bound,
   the size bound); `blobs/partial` → `blobs/sha256` with the hash checked while streaming; the
   tagged key (URL not in it); Docker's remote-`ADD` defaults; gc keeping fetched blobs that a
   record names; `E0820`, `E0821`; the `ADD --checksum` mapping rows and fixtures. Tests: a fetch
   key ignores the URL and changes with each other field; a present blob is never downloaded (a
   test client that fails on any request); a mismatch leaves nothing in `blobs/sha256`; the
   simulator crashes at every write of a fetch and finds no half blob. The `build_file` and
   `dockerfile` fuzzers learn the new forms. The test HTTP server (below) and VM check
   `vm/m9-fetch`: demo step 7. *Mechanical, for Haiku:* the constants and asserts, `E0820`/`E0821`
   registration, error pages, explain entries, goldens, the
   flags-table rows.
3c. **Output pins** (after 3b). `.expect` and `.output_exclude` in the parser and key, the
   defaults for pinned steps; lock version 2 with `.pins` (read, write, sort, the version rule:
   no pins means byte-identical version 1); `zbx build --pin`, `--locked`, `--hermetic`; keying
   dependents by the pin; drift as `E0822` or `W0803`. Tests: an M7 lock and an M9 golden lock
   read and write back byte for byte; a lock with a version this build does not know is refused (`E0804`'s lock reader); drift under each
   flag; the lock is written only on success; an excluded path never changes the output digest.
   The simulator learns pins: a crash during the lock write leaves the old lock or the new one,
   never a mix; a drifted step never lets a dependent hit on the old key under `--locked`. A
   `lock_file` fuzzer case for `.pins`. VM check `vm/m9-pins`: demo step 8. *Mechanical:*
   constants, `E0822`/`W0803` registration, error pages, explain entries, goldens,
   the lock-format test fixtures copied from the recorded run.
4. **VM, CI and the corpus.** `zig build demo-m9` exactly as below (steps 7 and 8 included), every assertion a
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
- `ADD --checksum=sha256:<hex>` of a URL with `--chmod`, and with a `/`-ending destination: a
  fetch entry. The same with `sha512:`, and `ADD --checksum` of a local file: `E0811`.
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
RUN echo 'app:x:10001:10001::/home/app:/bin/sh' >> /etc/passwd && \
    echo 'app:x:10001:' >> /etc/group && \
    echo 'app:!:3652:0:99999:7:::' >> /etc/shadow && \
    mkdir -p /home/app && chown 10001:10001 /home/app
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
   `build` stage's copy and compile steps miss, the final stage's user step hits, a new
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

Steps 7 and 8 (*owner, 2026-11-14*) use a second project, `src/testing/vm/m9_fetch/`, so that the
first project's import golden and digest are not touched. It holds a `Dockerfile`, a `zbx.lock`
pinning `alpine:3.20` (M7's pin), `hello.txt` (the payload), and `drift.build.zon`. The files are
served by `src/testing/vm/fixture_http.zig`, a small plain-HTTP static server written in Zig and
built with the harness. It runs in the guest on `127.0.0.1:<port>` and logs one line per
request. It has a `/r/<name>` route that redirects to `/<name>`, and a `/loop` route that
redirects to itself. Nothing in steps 7 and 8 reaches the internet. The Dockerfile:

```dockerfile
FROM alpine:3.20
ADD --checksum=sha256:<sha256 of hello.txt> http://127.0.0.1:<port>/hello.txt /opt/hello.txt
RUN cat /opt/hello.txt > /opt/copy.txt
```

7. **A pinned `ADD`.** `cd ~/fetch && zbx import` exits 0, flags nothing, and the fetch step's
   entry has `.fetch` with the URL and hash. `zbx import --hermetic -o h.build.zon` also exits 0.
   `zbx build` exits 0, and the server logged exactly one request. In the result, `/opt/hello.txt`
   has mode `0600`, owner `0:0` and `hello.txt`'s bytes. `zbx build` again: every step a hit, the
   same digest, and no new request. The URL is then changed to `/r/hello.txt`, so the file is
   served through a redirect: the fetch step hits and there is no request, because the URL is not
   in the key. Adding `.chmod = "0644"` misses the copy and the `RUN`, and there is still no
   request, because the blob is in the store. With a wrong `.sha256` in a fresh store (a second
   `XDG_DATA_HOME`), `zbx build` exits 3, stderr starts `error[ZBX-E0821]:`, it names the URL, the
   expected hash and the received one, and no step ran.
8. **Pin, then drift.** `drift.build.zon` has a network step `fetch` that runs
   `cat /proc/sys/kernel/random/uuid > /out/id`, and a step `use` that needs it. That output
   differs on every run, which is what a mirror publishing a new package looks like. *Deviation,
   recorded in `docs/demos/m9.md`:* a network step cannot reach the guest's loopback, because pasta
   runs with `--no-map-gw`, and CI must not fetch from the internet, so the uuid stands in for a
   changed download. `zbx build -f drift.build.zon --pin` exits 0, and `zbx.lock` gains one pin for
   `fetch` with `.version = 2`. `zbx build -f drift.build.zon --locked`: every step a hit, the lock
   unchanged. In a fresh store, the second host, `zbx build -f drift.build.zon --locked` exits 3,
   stderr starts `error[ZBX-E0822]:` and names `fetch`, the pinned digest and the new one, `use`
   did not run, and the lock is byte for byte unchanged. Without `--locked` in that store, the
   build exits 0 with `W0803` naming the same digests, and `use` misses.

ACCEPT also checks: every fixture's golden, through the binary; `zbx build --graph` on the
imported file against its golden; reordering nothing in the Dockerfile but its comments gives the
same bytes; an unlocked `FROM` with the network down is the pull's own `05xx` refusal;
`zbx import` over an existing file is `E0816`; the steps' run records and `build/work/` are gone
after the build. For steps 7 and 8, ACCEPT also checks: a step `steady` with `.expect`, which
writes a constant file and the date into `/out/var/log/when`, gives the same output digest in two
stores a minute apart, and a step that needs it has the same key in both (the default excludes
at work); `--pin --locked` is refused with `E0005`; `zbx build --locked` in `~/hello` is all hits and
leaves that lock byte for byte unchanged (a lock without pins stays version 1); `/r/hello.txt`
is followed and `/loop` is `E0820`, naming the redirect bound; an `https` URL redirected to `http`
is not tested in the VM (the server has no TLS) and is covered by a unit test of the redirect
rule. AGENT: `zbx import --output json` against `zbx schema import`, `zbx explain E0811`, and
`zbx build --output json --locked` on the drift case (the code and both digests are fields).

## Non-goals

- Executing a Dockerfile, or `docker build` flags and output. `zbx import` and `zbx build` are the
  interface (the Docker parity decision).
- BuildKit frontends (`# syntax=` is ignored), `RUN --security`, multi-platform builds, and
  cross-building.
- Secret and ssh mounts, tmpfs mounts, `ADD` of a URL without `--checksum=sha256:`, `ADD` of git
  repositories or tar archives, `COPY <<EOF`, `ONBUILD`, named build contexts. Each is refused by
  name. (`ADD --checksum` of a URL is in scope, *owner, 2026-11-14*.)
- Snapshots of apt or apk mirrors, and any other way of making a network step's output stable
  (*owner, 2026-11-14*). Drift is reported, loudly, and never prevented.
- Fetching by hash in a `RUN` (a fetch is a copy source only), checksums other than SHA-256,
  authenticated or cookie-carrying downloads, and a shared cache that would let a host skip a
  pinned step.
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
- **`zbx build --hermetic`**: make it an alias of `--locked`.
- **`.output_exclude` written by hand**: keep only the defaults for pinned steps.
- **The `/r/` redirect and `/loop` cases in the VM**: keep them as unit tests of the redirect
  rule.

Not cuttable: root output and `step:` chains, build-time user names, globs and excludes at build
time, network detection with the report, `--hermetic` on import, the second-VM golden, the
pinned `ADD` with its hash refusal, and `--pin` then `--locked` refusing drift (*owner,
2026-11-14*).

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

For the owner's 2026-11-14 rulings, these details are the supervisor's:

7. **A fetch is a copy source, not a mount.** "Step input" in the ruling is read as an input to
   the step that places the file. A `RUN` gets the file through its chain or a `needs`, so no new
   mount kind is added, and `ADD` maps one to one.
8. **Docker's remote-`ADD` defaults** (mode `0600`, `0:0`, the basename for a `/` destination),
   so an imported file behaves as it did under Docker.
9. **Pins live in `zbx.lock`**, next to the image pins, with a version bump only when there are
   pins. A separate file would be a second thing to commit and keep in step. Bumping the version
   for every lock would change `demo-m7`'s and `m9_project`'s locks.
10. **A pin records its step's key**, so a changed step is re-pinned by `--pin` and refused by
    `--locked` as stale, rather than compared with an output from a different command.
11. **`--hermetic` on build** is `--locked`, plus a refusal of unpinned network steps and of
    caches. That matches what `--hermetic` refuses on import.
12. **Drift without `--locked` keeps the old pin.** The warning repeats until a person accepts
    the new output. A pin that moved by itself would not be a pin.
13. **Bounds:** 1 GiB per fetch and 4 redirects (see the table under *Pinned fetches*), approved
    by the owner on 2026-11-14.
14. **Picks on the open questions** (*supervisor, 2026-11-14*): a fetch stays a copy source;
    `--hermetic` on build stays as defined; `/var/lib/apt/lists` joins the default excludes; a pin
    changes only by deleting it and running `zbx build --pin` (no `--repin`); `.expect` on a step
    with `.caches` is refused; the demo writes its user's `/etc/passwd`, `/etc/group` and
    `/etc/shadow` lines directly, and `zbx` normalises nothing in them; `E0820`–`E0822` are blame
    external, exit 3.

## Spec notes (flagged, not changed)

- **SPEC.md's non-goals** still say Dockerfile import is a stretch (S4) and GPU passthrough a
  non-goal. The parity decision overrides them until the next spec sync, which also adds M9.
- **M7's non-goals** (build arguments, host cache mounts, globs) are partly reversed for build
  files: arguments only through import, caches flagged, globs at build time.
- **M7's "user is numeric; names are not resolved at build time"** is reversed. The build record
  stays numeric.
- **DIAGNOSTICS.md** gives `08xx` to build; this brief takes `E0810`–`E0817` and `W0802`,
  `W0810`, `W0811` from it, and `E0820`–`E0822` and `W0803` (approved by the owner,
  2026-11-14). It leaves the rest of `08xx` free.
- **What M7's timestamp rules cover, and what they miss** (checked 2026-11-14). M7 fixes
  timestamps in metadata: the store keeps no times, farm mtimes are `SOURCE_DATE_EPOCH`
  (315532800), and every step's environment has `SOURCE_DATE_EPOCH`, `TZ=UTC` and `LC_ALL=C`. It
  does nothing about times, or random values, that a program writes into the contents of a file.
  - *Verified,* by installing Alpine 3.20.3's minirootfs twice, about two seconds apart, and
    running `apk add curl` in each with `SOURCE_DATE_EPOCH` set: the two trees are identical
    (`diff -r` empty). `/lib/apk/db/installed` records no install time (its `t:` field is the
    package's build time), and the mtimes of `scripts.tar` members come from the packages. The
    index files sit under `/var/cache/apk`, which the defaults exclude. So for apk, drift means a
    new package version on the mirror, which is exactly what a pin should report.
  - *Verified,* on Ubuntu 24.04's `passwd` 4.13: `useradd` honours `SOURCE_DATE_EPOCH` (the
    shadow `lastchg` field was 3652 with it set and today's day number without it). On the same
    host, `/var/log/dpkg.log` and apt's history carry timestamps, which `/var/log` covers;
    `/var/cache/debconf` and `/var/cache/ldconfig/aux-cache` are under `/var/cache`;
    `/var/lib/dpkg/status` and `/var/lib/apt/extended_states` hold no dates; but
    `/var/lib/apt/lists/*InRelease` hold the mirror's `Date:`. *Decided (supervisor,
    2026-11-14):* `/var/lib/apt/lists` is in the defaults, since it is an index, not installed
    content, so a pinned `apt-get update` does not drift merely because the mirror published.
  - *Verified, and a risk to this brief's own golden:* BusyBox `adduser -D -u 10001 app`, the
    final stage's first step in the brief's first draft of the demo, writes `app:!:<days since 1970>:0:99999:7:::` to
    `/etc/shadow` and ignores `SOURCE_DATE_EPOCH`. That step is not a network step, so pins do not
    apply. Its output, and so the demo's result digest, changes from one day to the next, and
    step 5's golden would fail on any day but the one it was recorded. Neither the slice-2 check
    nor the earlier steps notice, because they build twice on the same day. *Decided
    (supervisor, 2026-11-14):* the demo's Dockerfile writes the `/etc/passwd`, `/etc/group` and
    `/etc/shadow` lines directly instead of running `adduser`, with `lastchg` fixed at 3652, and
    `zbx` normalises nothing in those files. The slice-2 check and the fixtures may still run
    `adduser`, since they never compare across days.
  - *Not verified:* a full Debian install diffed against a second one (no `debootstrap` here);
    Python's `.pyc` files (documented: under `SOURCE_DATE_EPOCH`, `py_compile` writes
    hash-checked `.pyc` files with no time in them); programs that read the clock or a random
    source directly (machine ids, generated keys, uuids, build ids). The drift codes are how those
    show up.
