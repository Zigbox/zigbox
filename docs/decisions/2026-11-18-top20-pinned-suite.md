# The top-20 check also runs every image pinned by digest, and compares the two

*Decided 2026-11-18, by the slice (owner's item for 0.6.0). Details:
[docs/demos/m4.md](../demos/m4.md), "Floating and pinned".*

## Why

The weekly top-20 run pulls twenty Docker Hub images by floating tag (`nginx:latest`). When one
fails, the run cannot say whether the image changed upstream or zbx regressed. A second list of
the same images pinned by digest can: a digest names content that never changes.

## What

- **One file.** Each entry of `src/testing/vm/top20.zon` keeps its tag (`ref`) and gains
  `pinned`: `<name>@sha256:<index digest>`, the multi-arch index (OCI index or Docker manifest
  list) the tag named on `pinned_date` (2026-11-18 for the first set). The known reason, probe
  and environment are shared, so the two lists cannot drift apart. The digests were read once,
  read-only and anonymous, from Docker Hub's registry API (`HEAD /v2/library/<name>/manifests/<tag>`
  with the index and manifest-list `Accept` types, the `Docker-Content-Digest` header); the
  refresh procedure is in the file's header. The harness refuses at compile time a pin that is
  not the entry's own name by a well-formed digest (a digest is never a tag), or two equal pins.
- **The same job and the same VM boot.** `main_top20.zig` runs, per image: `zbx pull
  --resolve-only --output json <tag>` (where the tag points now, `index_digest`), the tag, then
  the pin. No second job, no second boot, no second cache. The store is kept between the two runs
  when the tag still names the pin, so the pinned pull reuses every blob.
- **The pin runs by the manifest its pull printed.** `zbx run` finds an image by the platform
  manifest it was pulled as and refuses the index digest (`E0522`, seen live), so the harness
  runs `<name>@<manifest digest from the pull's stdout>`. That is the pinned content. The gap in
  `zbx run` is reported, not fixed here: changing what `run` accepts is a product change.
- **The comparison.** One `top20-compare:` line per image: both verdicts, `tag=same|moved|unknown`
  and a class: `ok`, `known`, `upstream image moved` (the tag fails, the pin does not),
  `runtime regression` (both fail), `runtime regression (pinned only)`, and `flaky (same content,
  different results)` when the tag still names the pin and the two runs disagree. A moved tag's
  line ends with its current digest, the start of a refresh. The workflow puts these lines first
  in the job summary.
- **What fails the job.** A `fail` in either list. The canary keeps failing as it did; a pinned
  failure is a regression and is never excused by an upstream move.

## Costs

- About twice the VM time of the run (each image runs twice, plus a resolve), well inside the
  job's 120-minute limit.
- Three manifest requests per image (resolve, two pulls): 60 for the list, under Docker Hub's
  anonymous limit of 100 pulls per six hours per address. A 429 shows as that run's reason.
- No user-visible bound, default or diagnostic code changed.
