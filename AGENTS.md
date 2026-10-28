# Zigbox: operating instructions

Zigbox is a rootless, daemonless Linux container runtime, image store and builder in Zig. The spec is [docs/SPEC.md](docs/SPEC.md), a snapshot of the live design doc (https://claude.ai/artifact/6D9js8mxSLYmfuZe3rQ26w). If they disagree, the live doc wins: stop and report the conflict rather than picking one.

## Rules

- **Style and testing follow [docs/STYLE.md](docs/STYLE.md)** (TigerStyle, adapted). Read it before writing code. Review rejects code that breaks it.
- Work one milestone at a time, from its brief in `docs/briefs/`. Do not start a later milestone or build anything listed under Non-goals.
- A milestone is done only when its demo script runs live in the test VM. Unit tests passing, or code that compiles, is never reported as a passed demo. Say exactly what was and was not run.
- Each demo script becomes an automated test, `zig build demo-mN`. Never break an earlier demo: all prior `demo-mN` tests run in CI.
- Error messages are part of the demo: one line saying what was refused and why, never an `errno` dump.
- When scope is in doubt, cut scope and keep the demo. Record the cut in the milestone's demo document, `docs/demos/mN.md`.
- Zig version is pinned in `build.zig.zon` (`minimum_zig_version`) and CI. Do not upgrade during a milestone.
- No third-party dependencies; standard library only (see STYLE.md for the allowed external programs).
- No libc: never set `link_libc`. Release targets are `x86_64-linux` and `aarch64-linux`, static, built `ReleaseSafe` so assertions stay on.
- The pinned Zig is newer than most model training data, and std APIs (I/O, `std.Io`, readers/writers, build system) changed in 0.15–0.17. Read the pinned std source (`zig env` prints ZON; its `.lib_dir` field names the directory, and `std` is under it) before using an API; do not write from memory.
- All namespace work happens in a single-threaded child before `execve`. Thread pools only in the parent.
- Never run anything with `sudo` in tests on a developer's host. Privileged setup (sysctl toggles) happens only inside the test VM.

## Disk

- The session's disk allowance is fixed and cannot be raised. Give each parallel worktree its own `ZIG_GLOBAL_CACHE_DIR`, and when `zig build check` says `.zig-cache/o` is large, empty it outside a build (`rm -rf .zig-cache`). Never delete another worktree's cache.
- A build that was killed can leave `.zig-cache` half written, which then fails with `FileNotFound`; `rm -rf .zig-cache` fixes it.

## Environment facts (checked 2026-10-23 in the Claude Code cloud container)

- The cloud container runs as root, has cgroup v1/hybrid (no `cgroup.controllers`), no `/dev/kvm` and no `pasta`. A fresh container has no `newuidmap` either; a session may install `uidmap` and give a test user a subuid range to exercise the full id mapping, so check rather than assume. It is not a valid test host: use it to build, unit-test, cross-compile and smoke-test only; the VM demo is the real test.
- Real validation happens in a QEMU guest (Ubuntu 24.04 cloud image) on GitHub Actions `ubuntu-24.04` runners, which expose KVM.
- Zig downloads from https://ziglang.org/download/ work through the proxy.

## Commands

- `zig build` builds `zig-out/bin/zbx`.
- `zig build test` runs unit, snapshot and simulation tests.
- `zig build tidy` checks line length, function length and banned patterns.
- `zig build fuzz -- <fuzzer> [seed] [iterations]` runs one seeded fuzzer; `zig build fuzz -- all [iterations]` runs every fuzzer once, each with a fresh seed.
- `zig build demo-mN` runs milestone N's demo inside the test VM (harness in `src/testing/vm/`, written in Zig).
- `zig build check` runs every gate (build, test, tidy, release, errors-site-check, and `harness`, which compiles every VM demo without running it), then every fuzzer with a fresh seed (`zig build fuzz -- all`), then, when run as root, `zig build test` again as the user `tester` in a scratch worktree, because CI runs as an ordinary user. It ends in one line, `check: PASS <commit>` or `check: FAIL ...`; `-Dcheck-user=-` skips the non-root run. A failed fuzzer's seed is the last `fuzz:` line before the FAIL.

## Working as the implementer subagent

- Work in slices as the brief defines them. At the end of each slice, commit locally and stop with a report. **Do not push to the working branch.** The supervisor reviews each slice adversarially, and you fix what the review finds before the next slice.
- **Before you report, run [REVIEW.md](REVIEW.md) on your own diff**, and say which of its items your slice touched and what you checked.
- **Gates are `zig build check`, on the commit you report.** Paste its last line (`check: PASS <commit>`, without `+dirty`) into the report. A report without that line, or with another commit's, is not a report. Run the fuzzers you touched as well, and say which.
- **VM checks run on CI's KVM runners, not under TCG here.** Push the commit to a scratch branch named `vm/<demo>-<slug>` (`<demo>` is `m0` to `m6`, or `all`; for example `git push origin HEAD:vm/m4-slice4`). `.github/workflows/vm.yml` runs that demo in minutes. Read the result with the GitHub tools (`actions_list` with the branch, then `get_job_logs`), quote the run link in your report. The run deletes its branch when it ends, so push a new commit to the same name to run again. Scratch branches are the only branches you may push to. Use local TCG only to debug something CI cannot show.
- Report what you ran and its output, what you did not run and why, every deviation from the brief, and anything in the spec or brief that seemed wrong.

## README status

- [README.md](README.md) holds the status of every milestone and slice: what is built and reviewed, what is in review, and what is not started. The supervisor updates it in the same push that changes the status. Never mark anything "demonstrated" until its `demo-mN` job is green in CI.
- The project site (`site/index.html`, the `SITE` and `MILESTONES` data at the top of its script) shows the same status. Update it in the same push as the README: the milestone's `status`, its `slices` count, and, once a demo is green in CI, its `demo` lines taken from that run's recorded output with `recorded` linking to the run. Never show output that was not recorded as recorded. Pages deploys only from `main`.

## Git

- Develop on the branch you were given and commit in small, meaningful steps. The supervisor pushes, with `git push -u origin <branch>`, after review.
- Never report an unpushed commit as pushed.
- CI (`ci.yml`) runs only on pull requests and on `main`, never on a plain branch push. When a change needs CI, open a PR (or push to an open one); do not push to trigger CI, and batch small follow-ups into one push. Actions time is limited. The exception is `vm.yml`: a push to a `vm/*` scratch branch runs one demo, for checking work in progress (see the implementer section).
- A commit that only records status (README.md and `site/index.html` updated after a CI result) carries `[skip ci]` in its message, so it does not start a run of its own. Never use `[skip ci]` on a commit that changes code, tests, the harness, CI or generated files.
