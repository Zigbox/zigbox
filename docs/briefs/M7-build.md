# Brief: M7 · Build

Read these first:
- `AGENTS.md`, `REVIEW.md`, `docs/STYLE.md` and `DIAGNOSTICS.md` (codes `08xx` are reserved for build).
- The M7 section of `docs/SPEC.md` (snapshot of live doc rev 86; the M7 section reads the same in rev 91), its open question on the build file format, the Risks row "Reproducibility leaks", and "Production readiness".
- `docs/demos/m3.md` (what a tree digest holds: names, kinds, modes, owners, xattrs, content; no times), `docs/demos/m4.md` (`zbx.lock`, pull by digest, the mirror), `docs/demos/m6b.md` (the project directory, writable mounts, pull in the library).
- `src/zigbox.zig` (`start`, `wait`, `Spec`), `src/store/import.zig` (`import`, `commit`), `src/store/materialize.zig`, `src/store/roots.zig`, `src/store/namespace.zig`, `src/runtime/project.zig`, `src/lock_file.zig`.

Do not start M8: no provenance record, no signing, no policy. `demo-m0` to `demo-m6b`, the top-20 check and the Mac demos must keep passing.

**Owner decisions (2026-11-02):** the build file is ZON, with comments allowed (open question 1); the result is a tree plus a declared config (open question 3, revised); open questions 2 and 4 to 8 are taken as recommended.

## Goal and demo (from the spec, live doc rev 91)

Build images from a declared DAG of steps, so the same inputs always produce the same digest.

1. Build a small Zig or Go hello-world image: `zbx build`. Note the final digest and the step timings.
2. Run `zbx build` again: every step is a cache hit, completes in under a second.
3. Edit a README that no step declares as input: no rebuild, same digest.
4. Edit the source file: only the compile step and its dependents rebuild; the cache report shows hits and misses per step.
5. On a second clean VM, build from the same commit: identical digest.
6. Add a step that runs `curl` without `network: true`: it fails, naming the step and the grant needed.

Acceptance criteria:
- Bit-for-bit reproducible digest across two machines for the demo project.
- Cache keys depend on content, never on file mtimes or step text order alone.
- `zbx build --graph` prints the step DAG.
- The production-readiness checklist: an upgrade test against 0.2.0 (store and run records written by it), stable diagnostics, documented failure modes, and the agent test.

## Fixed decisions

### The build file: `zbx.build.zon` in the project directory

- **Where.** `zbx build` reads `zbx.build.zon` from the project directory (`project.directory`: the nearest `zbx.lock` up, else the working directory); `-f PATH` names another file inside the project. Every path in the file is relative to the project directory and is resolved with `project.resolve`; a path that resolves outside it is refused, as `--mount` is.
- **What it says.** A restricted ZON subset: structs, strings, string lists, booleans, integers. `//` comments are allowed and ignored (never data), no nesting beyond what the schema below has. Parsed by a hand-written, bounded, non-recursive parser in the repo's style (as `zbx.lock` and the image records are), not `std.zon` (it allocates, recurses through `std.zig.Ast` and gives its own error text). Every bound (file size, steps, inputs per step, needs per step, argv entries, env entries, string length) is in `constants.zig`. A parse error names the line and column and what was expected.

```zig
.{
    .version = 1,
    .steps = .{
        .{
            .name = "compile",
            .base = "golang:1.23-alpine",
            .inputs = .{ "go.mod", "main.go" },
            .env = .{ "CGO_ENABLED=0", "GOFLAGS=-trimpath -buildvcs=false", "GOPROXY=off" },
            .run = .{ "go", "build", "-ldflags=-s -w -buildid=", "-o", "/out/hello", "." },
        },
        .{
            .name = "notice",
            .base = "alpine:3.20",
            .inputs = .{ "VERSION", "LICENSE" },
            .run = .{ "sh", "-c", "mkdir -p /out/etc/hello && cp VERSION LICENSE /out/etc/hello/" },
        },
    },
    .image = .{
        .base = "alpine:3.20",
        .add = .{
            .{ .from = "compile", .to = "/usr/local/bin" },
            .{ .from = "notice", .to = "/" },
        },
        // Optional; every field optional. Part of the result's identity.
        .config = .{
            .entrypoint = .{ "/usr/local/bin/hello" },
            .env = .{ "GREETING_STYLE=plain" },
            .workdir = "/",
            .user = "0:0",
            .labels = .{ .{ "org.opencontainers.image.source", "https://github.com/Zigbox/zigbox" } },
        },
    },
}
```

- **A step** has `name` (unique, `[a-z0-9-]`, at most 32 bytes), `base`, `run` (an argv, never a shell string unless the argv says `sh -c`), and optionally `inputs`, `needs`, `env` and `network` (default `false`). Fixed conventions instead of options: declared inputs appear read-only at `/src`, each at its project-relative path, and `/src` is the working directory; each step named in `needs` appears read-only at `/in/<name>`; the step writes its result into `/out`, and `/out` is its output tree. A step that leaves `/out` empty has an empty output; that is allowed.
- **`base`** is a reference that `zbx.lock` pins (a tag or a digest reference). A build never resolves a tag: a base that is not in the lock is refused with the fix `zbx pull <ref>`. A locked base missing from the store is pulled by its locked manifest digest through the library pull (M6b slice 4), with one line saying so. This is the only network a build does outside a `network = true` step.
- **`image`** names the result: a base (optional; absent means an empty tree), an ordered list of step outputs spliced in at absolute paths, and an optional `config` (below). Assembly is pure store work (new directory nodes along each path, no container). Directories merge; a non-directory path present in two sources, or a file where the base has a directory, is refused naming both sources. `image` is required; a file without it is refused. One result per file.
- **Inputs** are files or directories, listed explicitly. No globs (cut, see below). A missing input, or one that resolves outside the project, is refused before anything runs.

### The result: a tree and its config

- **`image.config`** declares how the result runs: `entrypoint` and `cmd` (argv lists), `env` (`KEY=VALUE` list), `workdir` (absolute path), `user` (`uid:gid`, numeric; names are not resolved at build time) and `labels` (key/value pairs, keys `[a-z0-9._/-]`). Every field is optional; bounds in `constants.zig`. It is static text in the build file: nothing is taken from the clock, the host, git or the environment, so it never breaks reproducibility. Without a `config`, the base image's config is inherited field by field (a base's `env` is merged first, then the file's; other fields are replaced when given).
- **The build record.** The result is a small record in the store, `build/results/<digest hex>`, holding the tree digest and the resolved config in a canonical encoding. **The result digest** (`b3:...`, what `zbx build` prints and the golden checks) is BLAKE3 over that encoding, so the same tree with a different entrypoint is a different result. The record is written by atomic rename; a `build` root, labelled with the build file's path and replaced by the next build of the same file, keeps it and its tree alive.
- **Running it.** `zbx run <result digest>` reads the record and runs the tree with its config, as `zbx run <image>` does for a pulled image (entrypoint + cmd, env, workdir, user); `zbx run <result digest> -- <cmd>` overrides the command as it does for images. A bare tree digest still runs as any tree since M3. `zbx inspect <result digest>` prints the tree digest and the config (text and `--output json`, schema `zbx.build_result/1`).
- **Not in M7:** a tag or name for the result, an entry in `zbx.lock`, OCI export or push (after M8), build time, host, duration or git commit in the record (the log and the report carry timings; the commit is M8 provenance, recorded outside the digest).

### What a step is

- **An M2-hardened container** started with the library's `start` and `wait`: the base image's tree as the lower layer and a writable upper that is discarded after the step, the default seccomp filter, capabilities, `no_new_privs`, and the default limits (memory, PIDs, CPU) from `constants.zig`, plus a step timeout (a constant, 30 minutes). It runs as the container's root, whatever the image's `user` says: that is what lets `/out` be written as the host user (the M6b ownership rule).
- **Network `none`** unless the step says `network = true`, which runs it with `--net user` (pasta).
- **Mounts.** `/src` is the materialized input tree (a hardlink farm, `materialize.ensure`) bound read-only; each `/in/<name>` is the needed step's materialized output tree, read-only; `/out` is a fresh scratch directory under the store's `build/work/`, bound writable. The run's mount count limit (8) bounds `needs` to 6: refused above that, as a constant with a comptime assert.
- **A fixed environment.** Nothing from the host's environment. The step sees the image config's `env`, then the build file's `env`, then these, which a build file cannot override: `HOME=/root`, `TZ=UTC`, `LC_ALL=C`, `SOURCE_DATE_EPOCH=315532800`, `ZBX_BUILD_STEP=<name>`. Hostname `build` (a new `Spec.hostname`, additive), umask 022.
- **Its output** is `/out` imported after a zero exit, with ownership squashed to 0:0, xattrs dropped, file modes kept as written (umask fixed), and device files, FIFOs and sockets refused rather than skipped. The step's run record is removed after the step on every path; its standard output and error go to the build's log (below).

### Timestamps

The store keeps no times, so an output's digest never depends on them. What a step *sees* can: a tool that copies times into its output (`tar`, `zip`, `gzip` without `-n`) would leak the host's file times. So every file and directory in a materialized farm has its modification time set to `SOURCE_DATE_EPOCH` (1980-01-01, the earliest time `zip` stores): objects are written with that time, and `materialize.ensure` sets it on every entry it links (one `utimensat` per entry, only when a farm is first built, which also repairs objects written by 0.2.0). The base image's farm is covered by the same rule. `zbx run` containers see those times too (open question 4).

### The cache

- **The key** of a step is BLAKE3 over a canonical, length-prefixed encoding of: a step-format version (a constant, bumped when step semantics change, so a zbx patch release keeps the cache); the platform; the base's tree digest and its config's `env`; the input tree's digest; each needed step's *output* tree digest, sorted by name with its mount path; the argv; the build file's `env`; `network`; and the fixed environment above. Not: the step's position in the file, the build file's other text, file times, the host, the time. Using needed steps' output digests, not their keys, means a rebuild that produces the same bytes stops there.
- **The input tree** is an import of exactly the declared paths (an include list on `import`, not a copy), with owners squashed to 0:0, xattrs dropped, and modes normalized to `0644`/`0755` by the owner's execute bit (directories `0755`), so a different umask or file system (virtiofs on the Mac) gives the same digest. An undeclared file such as `README.md` is never read.
- **A cache entry** is `build/cache/<key hex>` in the store, holding the output tree digest and the key's preimage (the canonical encoding above, so M8 can write provenance without rebuilding), written by atomic rename, and a `build` root keeping the output tree alive. Two builds racing on one key both succeed; the first rename wins.
- **A hit** runs nothing. The image assembly is cached the same way (its key: base tree digest, the base's config, each `add`'s source output digest and path, and the canonical `config`) and is reported as the step `image`; its cached value is the result digest.
- `network = true` steps are cached like any other and marked `net` in the report; a build with one prints `warning[ZBX-W0801]` once, naming them: their output is not reproducible from the inputs.

### Running the graph

- Steps run as soon as their `needs` are done, at most `build_parallel_max` at a time (a constant, 4, and never more than the online CPU count). **No threads:** the parent `zbx` starts each step's child (each child is single-threaded until `execve`, as every run is) and waits on them with pidfds. The graph is checked before anything runs: unknown `needs`, duplicate names and cycles are refused, a cycle named in order (`compile -> notice -> compile`), found with an iterative topological sort.
- **On a failure** no new step starts; running steps finish (their outputs are cached if they succeed); the build exits with the failing step's diagnostic and the last 20 lines of its output.
- **The log.** Each step's output is kept, bounded (M6b's 5 MiB rule, per step), in `build/logs/<step>.log` beside the build's root, replaced by the next build of that file. `--verbose` streams it live, each line prefixed `<step> | `.

### Output

Text (timings are not part of any golden; the rest is):

```
$ zbx build
build: zbx.build.zon, 3 steps
  compile   miss   9.81 s
  notice    miss   0.32 s
  image     miss   0.05 s
built b3:5d1c...e7  (0 hits, 3 misses, 10.2 s)
```

`--output json` prints one `zbx.build/1` record per step as it ends (`schema`, `step`, `cache` (`hit`|`miss`), `key`, `output`, `start_ms` and `end_ms` from the build's start, `network`) and a last `build_result` record (`digest`, `hits`, `misses`, `elapsed_ms`), with a schema in `zbx schema build`, including the error document of a refused build (the `zbx.logs/1` decision). `zbx build --graph` prints the DAG without running anything, in topological order with ties broken by name:

```
$ zbx build --graph
compile   base golang:1.23-alpine   inputs go.mod main.go
notice    base alpine:3.20          inputs VERSION LICENSE
image     base alpine:3.20          adds compile -> /usr/local/bin, notice -> /
```

and `--graph --output json` the same as nodes and edges.

### Diagnostics (`08xx`, each with cause, fix, goldens and an error page)

- `E0801` the build file can't be read or parsed (line, column, what was expected).
- `E0802` the graph is invalid: duplicate step, unknown `needs` or `add.from`, a cycle (named), too many needs.
- `E0803` an input is refused: missing, outside the project directory (naming it), or a kind that can't be imported.
- `E0804` a base is not in `zbx.lock` (fix: `zbx pull <ref>`).
- `E0805` a step failed: its exit or exit reason in plain words (M2's wording for out of memory, PID limit, signal, timeout). When the step had no network, the cause adds a line and the fix names the grant:

```
error[ZBX-E0805]: build step "fetch" failed: exit 4
  cause  wget: bad address 'example.com'
         the step has no network: build steps run with network none unless they ask
  fix    if the step needs the network, add  .network = true  to step "fetch" in zbx.build.zon
  more   zbx explain E0805 · rerun with --verbose for the full cause chain
  docs   https://zigbox.github.io/zigbox/errors/E0805.html
```

- `E0806` a step's output is refused (a device file, FIFO or socket in `/out`, or a limit on files or depth exceeded).
- `E0807` the image assembly conflicts (the path and both sources), or `image.config` is invalid (the field and why: a relative `workdir`, a non-numeric `user`, an env entry without `=`).
- `W0801` the build has network steps (named).

A refused or failed build exits 1, as DIAGNOSTICS "Exit codes" says for commands that do not pass a workload's code through (a step's exit code is in the diagnostic, not the exit status). Store and pull failures inside a build keep their own `04xx`/`05xx` codes.

### In the library

`zigbox.build` exports the parser, the plan (graph, order, keys: pure functions), `run_step` (one step from its resolved spec to an output digest) and the scheduler, with per-caller storage and no process-wide state, so Zigcube's C8 can dispatch single steps and compute the same keys. The CLI is a thin caller. A test drives `run_step` and the key function from a caller other than the CLI.

## Slices (commit and stop for review after each; do not push to the working branch)

1. **The build file and the graph.** Parser, validation, path resolution, topological order and cycle naming, `zbx build --graph` (text and JSON), `E0801` to `E0803`, goldens. A `build_file` fuzzer (random and mutated files: never crashes, every refusal is a registered code, a valid file round-trips through a canonical printer) at 10,000 iterations. No containers yet; the simulator covers resolution (symlink escapes, missing inputs). *Mechanical, for Haiku:* registering the codes' boilerplate and error pages once their text is written, the golden files' copying, `zbx explain` entries.
2. **Keys and one step.** The input-tree import (include list, normalization), the key's canonical encoding (unit tests: invariant under step order, file times, an undeclared file, a umask change; changed by each field it covers), materialized farm times, base from the lock and pull by locked digest, `run_step` (mounts, fixed environment, hostname, `/out` import), cache entries and `build` roots, the step log, `E0804` to `E0806`. The simulator crashes at every write of a cache entry and asserts the store is unchanged or validly updated. VM check: start `src/testing/vm/main_m7.zig` with one part that builds and runs the demo project's `compile` step, twice (miss, then hit). *Mechanical:* `m7` in `vm.yml`'s picker and `all` list, the `demo-m7` entry in `build.zig`'s demo table (both as the M6b entries are).
3. **The graph runs.** The scheduler (bounded parallel children, pidfds, failure handling), image assembly and its cache, `image.config`, the build record and result digest, `zbx run <result digest>` and `zbx inspect <result digest>`, `network = true` and `W0801`, the report (text, JSON, `zbx schema build`), `--verbose` streaming, `E0807`, `zigbox.build` in the library with the second-caller test. A simulation test over random graphs with injected step failures and crashes: no step starts before its needs, never more than the bound at once, a hit never runs a container, a failure starts nothing new, the result digest is a function of the inputs only. VM check: the full demo project builds; `compile` and `notice` overlap in time; a `network = true` step reaches the network through pasta.
4. **VM, CI and the agent test.** `zig build demo-m7` with the six steps below exactly, every assertion a unit-tested pure function in `checks_m7.zig`; the second VM; the golden digest; the acceptance checks; the agent test by JSON only (`build`, `--graph`, `explain`); the upgrade test against 0.2.0; the `demo-m7` CI job; `docs/demos/m7.md` with the by-hand steps, cuts and failure modes (a base not locked, a cycle, a step out of memory, a step that times out, the disk full during an output import, a network step's output changing, a crash mid-build leaving `build/work/` behind and how the next build clears it). *Mechanical:* the upgrade part, copied from `upgrade_m6b.zig` with 0.2.0's commit in `old_release.zon`; the CI job, copied from `demo-m6b`'s; the demo project's `zbx.lock` and the golden digest, copied from the first green run's output.
5. **The Mac** (for the session on the owner's Mac, after slice 4 merges; cuttable, open question 6): `build` forwarded like the other commands (`src/mac/forward.zig`), the project over virtiofs, and `demo-mac` building the demo project and getting the golden digest for `arm64`'s own golden.

The slices run one after another, in order. Slices 1 and 2 are the riskiest by design (the parser is the attack surface; the key is the contract) and are reviewed hardest.

**The harness.** A parallel PR moves the VM harness into a module (0.2.1). M7 adds only new files (`main_m7.zig`, `spec_m7.zig`, `checks_m7.zig`, `agent_m7.zig`, `upgrade_m7.zig`, the project under `src/testing/vm/m7_project/`) and the demo-table and picker lines, and uses only `Session`'s public calls (`start`, `run`, `shutdown`) and `harness.zig`'s public helpers. If that PR has merged when slice 2 starts, build on it; if not, rebase onto it when it does. Change nothing inside `harness.zig` or `session.zig`; anything M7 needs there goes to the supervisor first.

## The demo: `zig build demo-m7`

The project is checked in at `src/testing/vm/m7_project/`: `zbx.build.zon` (above), `zbx.lock` pinning `golang:1.23-alpine` and `alpine:3.20` for `linux/amd64` by manifest digest, `go.mod` (`go 1.23`, no dependencies), `main.go` (prints `hello from zigbox`), `VERSION`, `LICENSE`, `README.md`. The harness copies it into the guest as the ordinary user's `~/hello`. Images come through `mirror.gcr.io` with the blob cache, as `demo-m4` does; the golang blobs (about 70 MB) join the cache key. Parts in order: UPGRADE, SPEC, ACCEPT, AGENT. Assertions on digests, hit/miss columns and refusals are exact; timings are asserted only where the spec gives a bound.

1. **First build.** `cd ~/hello && zbx build` exits 0. The report lists `compile`, `notice` and `image`, all `miss`, and ends `built b3:<64 hex>  (0 hits, 3 misses, ...)`. In the JSON form of the same build (run as part of the step, `--output json`), `compile`'s and `notice`'s `[start_ms, end_ms]` intervals overlap. `zbx run <digest>` (no command: the config's entrypoint) prints `hello from zigbox`, and `zbx inspect <digest> --output json` shows the tree digest and the declared config.
2. **Again.** `zbx build --output json`: every step `hit`, the same digest, `elapsed_ms < 1000`. The text form shows `(3 hits, 0 misses, ...)`.
3. **README.** `echo more >> README.md && zbx build`: 3 hits, the same digest.
4. **Source.** Change the greeting in `main.go` to `hello again from zigbox`, `zbx build`: `compile miss`, `notice hit`, `image miss`, `(1 hit, 2 misses, ...)`, a new digest, and `zbx run <new>` prints the new greeting. Restore `main.go`; `zbx build` gives the first digest again with 3 hits.
5. **A second clean VM.** The demo shuts the first guest down and starts a second from the same base image with a fresh overlay, provisions it and installs the same `zbx`, copies the same project, and runs `zbx build` (which pulls both bases by their locked digests). The digest equals step 1's. Then that digest is compared with the golden digest checked in at `src/testing/vm/m7_expected.zon`: every CI run on any runner must produce it, which is the cross-machine criterion. (The golden changes only with a deliberate commit: a new step-format version, a store tree-format change or a re-pinned base.)
6. **No network.** Append to `zbx.build.zon` a step `fetch` (base `alpine:3.20`, `run = .{ "wget", "-q", "-O", "/out/page", "https://example.com" }`, no `network`). `zbx build` exits 1; stderr starts `error[ZBX-E0805]: build step "fetch" failed: exit` and contains `the step has no network` and `add  .network = true  to step "fetch" in zbx.build.zon`; the other steps report `hit`.

ACCEPT also checks: `zbx build --graph` text against its golden and JSON against the schema; a cycle (`E0802`, naming it), an unlocked base (`E0804`, with the pull fix), an input outside the project (`E0803`); reordering the steps in the file gives the same keys and digest; `touch`ing every input gives 3 hits; `/out` files land owned by the user in the store and as `0:0` in the tree; no `build/work/` directory is left after the build; the steps' run records are gone. UPGRADE: the store and run records written by 0.2.0, then `demo-m6b`'s SPEC part and a build with the new binary.

## Non-goals

- **M8:** the provenance record, `zbx inspect --provenance`, keys, signing, run policy. M7 keeps each step's key preimage in its cache entry so M8 can emit provenance from it; it writes no provenance itself.
- **Push, OCI export, tags and lock entries for built results.** Pull-only until after M8 (spec Non-goals). A built result is a local build record: a tree and its config, named by its digest.
- Dockerfile import (stretch S4) and executing Dockerfiles.
- Cluster builds, a shared or remote cache (C8).
- Multi-platform builds, cross-building for another architecture, build arguments or templating, secrets for steps, host cache mounts (a Go module cache), file watching.
- Cache pruning commands beyond what `store gc` already does with roots (the latest build of each file is kept; older outputs are collectible once replaced).

## Scope that can be cut while keeping the demo

Record any cut in `docs/demos/m7.md`.
- **Directory inputs** (files only): the demo lists files.
- **`--verbose` streaming**: the log file and the last 20 lines on failure stay.
- **The second VM in step 5**: replace it with a fresh user with an empty store in the same guest. The golden digest still proves the cross-machine criterion on every run; say so in the demo document.
- **The positive `network = true` VM check** (slice 3): the unit and simulation tests stay; `demo-m5` already proves pasta.
- **The Mac slice** (slice 5), to a later session.
- **`build_parallel_max` from CPU count**: a fixed 4.

## Open questions for the owner (all decided 2026-11-02)

1. **Build file format** (the spec's open question, "decide before M7 starts"). *Decided (owner, 2026-11-02): ZON, comments allowed.* The reasoning: **ZON**, a restricted subset with a hand-written bounded parser: Zig's own notation, no dependency, already the shape of `zbx.lock`, and Zigcube can reuse it for its service file (Part II's open question). Starlark means writing an interpreter; a typed config language means designing one.
2. **Demo language.** *Decided (owner, 2026-11-02): as recommended.* The spec allows Zig or Go. Recommend **Go**: an official pinned image, and `-trimpath -buildvcs=false -buildid=` builds are reproducible as documented. Zig has no official image; Alpine's `zig` package needs a `network = true` step to install, which the demo would then have to warn about.
3. **What a build produces.** *Decided (owner, 2026-11-02): a tree plus a declared `image.config`* (entrypoint, cmd, env, workdir, user, labels), stored as a build record and named by its digest; see "The result: a tree and its config". No tag, no lock entry, no OCI export in M7. Metadata that is not declared in the file (time, host, git commit, builder) stays out of the result; the commit belongs to M8's provenance.
4. **Times in the store.** *Decided (owner, 2026-11-02): as recommended.* Recommend that store objects and farm entries carry the fixed time `SOURCE_DATE_EPOCH` (1980-01-01). It closes the leak for build steps and is visible to `zbx run` containers as well (files there have unspecified times today, whatever import wrote). The alternative, copying inputs per step with fixed times, costs a copy of every input and leaves the base image's times leaking.
5. **Step 6's `curl`.** *Decided (owner, 2026-11-02): as recommended.* Neither `alpine` nor `golang:*-alpine` has `curl`; both have busybox `wget`. Recommend the live doc say "runs `wget`" (or "fetches a URL"), rather than pulling a third image for `curl`.
6. **Does M7 need the Mac to be "demonstrated"?** *Decided (owner, 2026-11-02): as recommended.* M6b did. Recommend **no**: `demo-m7` green on Linux demonstrates M7; slice 5 follows when the Mac session has time.
7. **Zigcube's simulation-fleet worker image for GHCR.** *Decided (owner, 2026-11-02): as recommended.* `zbx build` can build it, but getting it to GHCR needs push or OCI export, which the spec's Non-goals put after M8. Recommend: not in M7; dogfood by building it (a good second test project) and keep the GHCR image on Docker until push exists. If the owner wants it sooner, an `zbx store export --oci <digest> DIR` (an OCI layout another tool pushes) is the smallest change, and is a spec change.
8. **Network steps and the cache.** *Decided (owner, 2026-11-02): as recommended.* Recommend caching them like any step, marked `net` and warned about (`W0801`), so a rebuild does not refetch. The alternative, never caching them, makes every dependent a miss on every build.

## Spec notes (flagged, not changed)

- **The snapshot is behind.** `docs/SPEC.md` is rev 86; the live doc is rev 91 (and `HANDOFF.md` says 78). The M7 and M8 sections, the build-file open question and the Risks row read the same in both; the other changes were not checked for this brief. The supervisor should refresh the snapshot.
- **"Its cache key is the hash of its inputs plus command" is incomplete.** A key that leaves out the base tree, the environment, the network grant and the needed steps' outputs gives false hits. The brief's key covers them; the spec line could say "the hash of everything the step can see".
- **"Timestamps normalized"** does not say which. The store already keeps no times, so outputs are unaffected; the brief reads it as the times steps see (above, and open question 4).
- **"Never on file mtimes or step text order alone"**: "alone" is ambiguous. The brief reads it as "never on mtimes, and never on the order of steps in the file".
- **"Bit-for-bit reproducible across two machines"** is per platform: an `amd64` and an `arm64` build of the same project give different digests (different base images, different binaries). The brief proves it for `amd64` (the golden) and, with slice 5, `arm64` separately.
- **Production readiness** applies to M7 as to every milestone since M1, though the M7 section does not repeat it; the brief includes it (upgrade test against 0.2.0).
- **Step 6 says `curl`** (open question 5).
