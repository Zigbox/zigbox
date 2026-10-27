# Brief: M4 · Pull

Read these first:
- `AGENTS.md`, `docs/STYLE.md` and `DIAGNOSTICS.md`.
- The M4 section of `docs/SPEC.md`, along with "Production readiness" (this is the first milestone with the **agent test**) and "Agent operability".
- `docs/DECISIONS.md`, the M4 entry.
- `docs/demos/m3.md`: the store you build on.
- The "Notes for later milestones" in `docs/briefs/M2-limits.md` and `docs/briefs/M3-store.md`. Two of them are M4's to close.

This brief settles what those leave open. Do not touch anything from M5 onward: no network namespace, no `--net`, no push, no private registries. `demo-m0` to `demo-m3` must keep passing in every slice.

## Goal and demo (from the spec, live doc rev 53)

Pull a public OCI image and run it, with the store doing the deduplication across images.

1. `zbx pull alpine:3.20` prints the resolved digest.
2. `zbx run alpine:3.20 -- cat /etc/os-release`.
3. `zbx pull python:3.12-slim`, then `zbx pull python:3.13-slim`. `zbx store du --by-image` shows the second costs far less than its compressed size, because shared files are stored once.
4. `zbx run python:3.12-slim -- python -c 'print(2**100)'`.
5. Change the tag in `zbx.lock` to a wrong digest. `zbx run` refuses, naming the expected and the actual digests.

Acceptance criteria:
- The top 20 official Docker Hub images run their default command, or there is a documented reason a given image cannot run rootless.
- Every image is identified internally by its tree digest. Tags are only aliases.
- An interrupted pull resumes without re-downloading the blobs it already completed.
- The production-readiness checklist:
  - an upgrade test against the merged M3 commit;
  - stable diagnostics;
  - documented failure modes;
  - the **agent test**: a scripted agent drives the demo using only `--output json` and `zbx explain`. Anything it has to scrape from text or guess is a bug. MCP is later.

## Fixed decisions

### References and the registry client

- **Reference grammar.** `[registry/][namespace/]name[:tag][@sha256:<hex>]`.
  - The registry is `docker.io` by default, reached at `registry-1.docker.io`. A one-part Docker Hub name gets `library/`.
  - `ghcr.io` and any host with a dot or a port name a registry.
  - The parser is pure. It gets a fuzzer (`reference`) and refuses anything ambiguous with a coded diagnostic; it never guesses.
- **HTTP and TLS.** Use `std.http.Client`, with `std.crypto.tls` and the system CA bundle (`Certificate.Bundle.rescan`). Read the pinned std first; the spec asks that each std piece be checked as adequate when its milestone starts, so report anything that is not.
  - `HTTPS_PROXY` and `NO_PROXY` are honoured, because the build container needs them. The VM has a direct network.
  - Every request has a timeout and a byte bound.
  - Network work runs in the parent, never in the namespace child (AGENTS.md).
- **Anonymous auth.** On a 401, parse the `WWW-Authenticate: Bearer realm=...,service=...,scope=...` header, fetch a token from the realm and retry once. Do not hard-code Docker Hub; GHCR uses the same flow. A 429 is a coded diagnostic that names the rate limit and when to retry. It is never retried in a loop.
- **Manifests.** Accept the OCI image index and manifest, and the Docker v2 manifest list and manifest.
  - Pick the platform `linux/amd64` or `linux/arm64` (variant `v8`) for the host. If there is no match, refuse and list the platforms the image offers.
  - Verify every fetched manifest and blob by its digest before use.
  - Refuse unknown media types, naming them.

### Blobs, layers and the flattened tree

- **The blob cache.** Downloaded blobs live under the store as `blobs/sha256/<hex>`, verified on arrival.
  - A partial download is kept as `blobs/partial/<hex>` and resumed with an HTTP `Range` request. This is the "interrupted pulls resume" criterion.
  - gc treats a blob as live while an image record needs it. Lift the M3 limit of about 49,000 objects in gc's tables now (from the M3 brief): real images will pass it. Make the tables grow in bounded, caller-provided storage, or page through the work. Choose, and say which.
- **Decoding.** Layers are tar, compressed with gzip (`std.compress.flate`) or zstd (`std.compress.zstd`). Use `std.tar` or your own reader, but read the pinned source first.
- **Flattening.**
  - Apply the layers in order inside the store's user-namespace child, so that tar ownership lands as container ids under the M1 mapping.
  - A `.wh.<name>` entry deletes `<name>`, and `.wh..wh..opq` makes its directory opaque.
  - Hardlinks become separate entries, as in M3.
  - Device nodes are skipped with a warning.
  - PAX `SCHILY.xattr.*` records become xattrs, following M3's rules for which ones are allowed.
  - The flattened result is imported as one tree.
  - Start with the simplest correct method: extract into a staging directory under the store, then run the existing import. Measure the time and disk it costs for `python:3.12-slim`, and record that in `docs/demos/m4.md`. Building the tree straight from the tar stream is an optimisation for later.
  - A tar entry that escapes its root (an absolute path, `..`, or a symlink followed while extracting) is refused. Fuzz the layer applier (`layer`) with hostile tars.

### Images, the lockfile and running by tag

- **The image record.** A pulled image is an image record in the store. It holds the reference, the manifest digest, the platform, the config digest, the tree digest and the image config (entrypoint, cmd, env, working dir, user). It is a root, so gc keeps it and its tree. `zbx store ls` shows images. The image's identity is the tree digest; tags are aliases only.
- **`zbx.lock`.** It lives in the project directory: the nearest one up from the working directory. Format: ZON. Each entry has the reference as written, the manifest digest, the platform and the tree digest. It is versioned, sorted by reference, and its writes are atomic.
  - `zbx pull <ref>` adds or updates the entry, then prints the digest. With `--output json` it prints `zbx.pull/1`.
  - `zbx run <tag>` with a lock entry runs the locked tree, after checking that the store's record for that manifest gives the same tree. If the lock names a digest the store does not have, or the two disagree, it refuses (`E05xx`). The refusal names the expected and actual digests and the command that fixes it. It never pulls silently.
  - Without a lockfile, `zbx run <tag>` pulls, writes a lockfile in the working directory, and says so in one line.
  - A digest reference (`@sha256:`) needs no lock.
- **The config at run.**
  - The entrypoint and cmd are combined as Docker does: arguments after `--` replace cmd.
  - The image env comes first and `Spec.env` overrides it.
  - The working directory is created if it is missing.
  - `User` is resolved against the image's `/etc/passwd` and `/etc/group`. A numeric `uid:gid` is used as is. An unknown name is refused.
  - The library's `Spec.image` accepts a tag or a digest; the CLI resolves a tag through the lock.
- **`zbx store du --by-image`.** For each image it shows the logical size, the compressed size of its layers, its stored size, and how much of that it shares with other images. It has `--output json`.
- **`/sys`.** Bind the host's `/sys` read-only into every container, recursively. It is the M4 decision, and it closes in M5 with a real sysfs. Record the leak in `docs/demos/m4.md`: host network devices are visible.

### Closing the carried-over notes

- **Seccomp under glibc.** The allowlist was only exercised with busybox. The top-20 run is the glibc test. Grow the allowlist from what fails, with a reason per syscall, and keep the BPF tests in step. A failure that is seccomp's (EPERM from a syscall that should be allowed) must be distinguishable in the top-20 results.

### Diagnostics

- `05xx` is registry and pull.
- **At least these codes:**
  - a malformed reference;
  - an unknown registry host, or a DNS failure;
  - TLS verification failed;
  - an HTTP error, naming the URL without any token;
  - rate limited (429);
  - auth refused;
  - manifest not found, or the tag missing;
  - no matching platform, listing what the image offers;
  - an unknown media type;
  - a digest mismatch on a blob or manifest;
  - an unsafe layer entry;
  - a lockfile parse error;
  - lock against store mismatch (demo step 5);
  - a locked digest absent from the store;
  - an unknown user in the image.
- Tokens never appear in any output, record or bundle. Extend the redaction test.

### The top-20 check

- A separate workflow, `.github/workflows/top20.yml`, runs weekly and on `workflow_dispatch`. It is not part of the PR CI.
- It boots the same VM and runs each image's default command with a timeout. It records one line per image: pulled, ran, exit code, and the reason for any failure. The list of images is checked in (`src/testing/vm/top20.zon`), taken from Docker Hub's most-pulled official images, with its date.
- An image that cannot run rootless, for example because it needs to bind port 80 as real root or mount something, gets a documented reason. Silence is not allowed.
- M4 counts as demonstrated once `demo-m4` is green on the PR and one top-20 run has passed with that bar, linked from the README.

### The upgrade test

- Pin the merged M3 commit: the merge commit of PR #9, which the supervisor gives you once it exists.
- The old binary imports a tree, runs it by digest and commits it.
- The new binary must then read that store (`ls`, `verify` clean, `run <digest>`) and its run records.

## Slices (commit and stop for review after each; do not push)

1. **References, registry, auth and manifests.**
   - The reference parser and its fuzzer.
   - The HTTP client wiring, including proxy, timeouts and bounds.
   - The Bearer flow; manifest and index parsing; platform selection.
   - A small **test registry in Zig** inside the harness (`src/testing/vm/http_server.zig` exists). It serves fixtures and faults: 401 then a token, 429, a wrong digest, a truncated body, an unknown media type. All slice tests run against it and need no internet.
   - A smoke test against real Docker Hub and GHCR from this container, through the proxy, run by hand only, never in `zig build test`.
2. **Blobs and layers to a tree.**
   - The blob cache, verify and resume; gzip and zstd.
   - The layer applier with whiteouts and opaque directories, the `layer` fuzzer and hostile-tar tests.
   - Flattening into one imported tree.
   - The gc limit lifted, with blobs in its live set.
   - `zbx pull` ends to end against the test registry. A by-hand pull of `alpine:3.20` from Docker Hub here.
3. **Images and running.**
   - Image records and the lockfile.
   - `zbx run <tag>` with the config honoured, and the lock checks.
   - `store du --by-image`; `/sys` read-only; the `05xx` codes, with goldens and pages; the schemas.
   - Real checks in the VM: `alpine:3.20` and `python:3.12-slim` run.
4. **The top-20 workflow and seccomp.** `top20.zon`, the workflow and the result table. Grow the seccomp allowlist from real failures. Run it once under TCG locally for as many images as is practical, and report the results.
5. **VM, CI and the agent test.**
   - `zig build demo-m4`: the spec's five steps exactly, every assertion a unit-tested function, with blobs cached between CI runs (`actions/cache` keyed by `zbx.lock`).
   - The acceptance checks, including a pull killed halfway that then resumes.
   - The agent test: a Zig program in the harness that drives the demo using only `--output json` and `zbx explain`.
   - The upgrade test against M3.
   - The `demo-m4` CI job.
   - `docs/demos/m4.md` with the by-hand steps, cuts and failure modes: rate limited, a registry down, a proxy that breaks TLS, the disk full during a pull, a lockfile conflict, an image that needs real root.

## Done means

- All gates pass, and every fuzzer runs at 10,000 iterations, `reference` and `layer` included.
- `demo-m4` is green in CI, with `demo-m0` to `demo-m3` still green, and one top-20 run has passed. Until then M4 is "built, not demonstrated".
- Your report lists:
  - what you ran and its output;
  - what you did not run, and why;
  - every deviation from this brief;
  - anything in the spec, this brief or `DIAGNOSTICS.md` that seemed wrong.
