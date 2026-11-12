# Zigbox: operating instructions

Zigbox is a rootless, daemonless Linux container runtime, image store and builder in Zig. The spec is [docs/SPEC.md](docs/SPEC.md), a snapshot of the live design doc (https://claude.ai/artifact/6D9js8mxSLYmfuZe3rQ26w). If they disagree, the live doc wins: stop and report the conflict rather than picking one.

## Rules

- **Style and testing follow [docs/STYLE.md](docs/STYLE.md)** (TigerStyle, adapted). Read it before writing code. Review rejects code that breaks it.
- Work one milestone at a time, from its brief in `docs/briefs/`. Do not start a later milestone or build anything listed under Non-goals.
- A milestone is done only when its demo script runs live in the test VM. Unit tests passing, or code that compiles, is never reported as a passed demo. Say exactly what was and was not run.
- Each demo script becomes an automated test, `zig build demo-mN`. Never break an earlier demo. CI runs only the demos a pull request can affect (path rules in `.github/ci-changes.sh`); a push to `main`, a pull request from a `claude/release-*` branch and a pull request labelled `full-ci` run all of them, so a break the affected set missed shows on `main`. If you are unsure, add the `full-ci` label.
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
- `zig build packages` writes the deb, rpm, apt and dnf trees under `zig-out/packages/` (`-Dtest-key` signs with the fixed test key, `-Dsignatures=DIR` places the owner's signatures); `zig build packages-check` reads the tree back and checks every file against its metadata (runbook: `docs/releases/packaging.md`).
- `zig build demo-mN` runs milestone N's demo inside the test VM (harness in `src/testing/vm/`, written in Zig).
- `zig build check` runs every gate (build, test, tidy, release, errors-site-check, and `harness`, which compiles every VM demo without running it), then every fuzzer with a fresh seed (`zig build fuzz -- all`), then, when run as root, `zig build test` again as the user `tester` in a scratch worktree, because CI runs as an ordinary user. It ends in one line, `check: PASS <commit>` or `check: FAIL ...`; `-Dcheck-user=-` skips the non-root run. A failed fuzzer's seed is the last `fuzz:` line before the FAIL.

## Working as the implementer subagent

- Work in slices as the brief defines them. At the end of each slice, commit and stop with a report. The supervisor reviews each slice adversarially; what the review finds is fixed before the next slice, by a fresh agent (see below).
- **Before you report, run [REVIEW.md](REVIEW.md) on your own diff**, and say which of its items your slice touched and what you checked.
- **Gates are `zig build check`, on the commit you report.** Paste its last line (`check: PASS <commit>`, without `+dirty`) into the report. A report without that line, or with another commit's, is not a report. Run the fuzzers you touched as well, and say which.
- Stop and ask the supervisor before a change alters a user-visible bound, limit or default, or registers a new code; give the evidence and the choice. Do not pick one and leave it to review.
- Run long commands (`zig build check`, long fuzz runs) in the background and wait for them to finish; do not poll with sleep loops. Kill what earlier runs left before running again.
- Run every gate once, on the final commit, then report once. Never report, or open a pull request, before the gates finish.
- **VM checks run on CI's KVM runners, not under TCG here.** Push the commit to a scratch branch named `vm/<demo>-<slug>` (`<demo>` is `m0` to `m6`, or `all`; for example `git push origin HEAD:vm/m4-slice4`). `.github/workflows/vm.yml` runs that demo in minutes. Read the result with the GitHub tools (`actions_list` with the branch, then `get_job_logs`), quote the run link in your report. The run deletes its branch when it ends, so push a new commit to the same name to run again. Push only to your own session branch and to scratch branches. Use local TCG only to debug something CI cannot show.
- Report what you ran and its output, what you did not run and why, every deviation from the brief, and anything in the spec or brief that seemed wrong. End the report with the handoff note described below.

## Agent context discipline

An agent re-reads its whole context on every turn, so cost grows with context size, not with the work done. Keep implementer context small.

- **One agent per slice.** The supervisor spawns a fresh implementer for each slice of a milestone. Do not resume a finished implementer for the next slice or for follow-up fixes.
- **Hand off through the repo.** Before stopping, the implementer commits its work and ends its report with a handoff note: decisions made, traps found, what's next. Lasting decisions go in `docs/decisions/`, one file per decision (`YYYY-MM-DD-<slug>.md`, see its README), never in a shared file, so parallel branches do not conflict. The next implementer starts from the brief, the branch and that note.
- **Context ceiling.** Stop at about 250K tokens of context or 60 turns, whichever comes first. At that point, reach the next safe stopping place, commit, write the handoff note and report. The supervisor enforces this and starts a new implementer rather than extending the current one.
- **Small fixes get new agents.** For a bug or review finding, spawn a fresh agent with the symptom and the relevant commit. Do not send it back to the agent that wrote the code.
- **Keep noisy output out of context.** Redirect `zig build` and test output to a file and read only the failing lines. Do not paste full logs.
- **Delegate lookups.** Send broad reads, such as searching the Zig std source, to a read-only Haiku agent and keep only the answer.
- **Purely mechanical work goes to Haiku** (owner, 2026-10-30). A change fully specified by a pattern (threading an argument through call sites, a rename, copying generated output into a doc, a status update, a CI tweak) is done by a Haiku subagent or session, given the exact pattern; whoever delegated checks its diff. Anything that needs judgment (design, tests, invariants, review) stays with Sonnet or the supervisor. Briefs name a slice's mechanical parts.

## Reviews on GitHub (owner, 2026-11-05)

Every adversarial review of a pull request (a slice review, a re-review, either release reviewer) is posted on that pull request as a GitHub pull request review, so the record stays with the PR.

- One review per pass, with the event `COMMENT`. A review never approves or requests changes: the sessions post from the PR author's account, and merging stays with the supervisor and the owner.
- The review body opens with the verdict (merge, merge after MUSTs, or rework), then what the reviewer ran and did not run, then any finding that has no line to attach to.
- Each finding that belongs to a line is an inline comment on that line of the diff, starting with its tag: **MUST**, **SHOULD** or **NIT**, and stating a concrete failure scenario.
- The reviewer posts the review and nothing else on GitHub. The two release reviewers stay independent: neither reads the other's review before posting its own.
- The fix session works from the posted review. The supervisor still relays the verdict to the owner.

## README status

- [README.md](README.md) holds the status of every milestone and slice: what is built and reviewed, what is in review, and what is not started. The supervisor updates it in the same push that changes the status. Never mark anything "demonstrated" until its `demo-mN` job is green in CI.
- The project site (`site/index.html`, the `SITE` and `MILESTONES` data at the top of its script) shows the same status. Update it in the same push as the README: the milestone's `status`, its `slices` count, and, once a demo is green in CI, its `demo` lines taken from that run's recorded output with `recorded` linking to the run. Never show output that was not recorded as recorded. Pages deploys only from `main`.

## Releases (owner, 2026-11-04)

The tag is made by `.github/workflows/tag.yml` once `ci` and `mac` are green on the merged release
commit, never by hand unless the owner has written a go-ahead for that release in
`docs/decisions/` (docs/releases/automation.md).

A release tag is cut only from a commit that is all of:

- **Sim-clean.** `zig build check` passes on it, and an extended seeded run of every fuzzer and
  simulation test (`zig build fuzz -- all <iterations>`, at least 100 times the per-commit
  default) finds nothing. When Zigcube moves its pin to the release, Zigcube's simulation fleet
  must be clean on the commit that moves it.
- **Jepsen-clean,** once the Jepsen battery exists (Zigcube's C5 prerequisite): it passes on a
  Zigcube commit pinned to this release.
- **Reviewed adversarially by two independent Opus reviewers.** Each is a fresh session given the
  diff since the last release and the briefs, not the other's findings nor the implementers'
  conclusions. Every MUST from either is fixed, or the owner accepts it in writing in
  `docs/decisions/`, before the tag.

The release PR quotes the fuzz run's last line, the Jepsen result when it applies, and both
review verdicts.

Every release also gets a quick retro, written by the supervisor within a day of the release and
kept short: what assumptions turned out to be off base, what each cost, and what changes because
of it. It goes in `docs/retros/<version>.md` (one file per release), and any rule it changes lands
in this file or `docs/decisions/` in the same PR.

## Git

- Develop on the branch you were given and commit in small, meaningful steps.
- **Push your work about every 10 minutes** (owner, 2026-11-10), with `git push -u origin <branch>`, to your own session branch, even when it is unfinished: the container is ephemeral, and unpushed commits are lost when it is reclaimed or reset. Never push to `main` or to another session's branch.
- **Do not open a pull request until the work is ready:** gates pass on the final commit and the report is written. Pushing to a branch with an open pull request runs CI, so the pull request comes last.
- Never report an unpushed commit as pushed.
- CI (`ci.yml`) runs only on pull requests and on `main`, never on a plain branch push. A pull request runs the VM demos its changed paths can affect, and nothing but the `changes` job when it changes only docs; `main`, `claude/release-*` pull requests and `full-ci` pull requests run all demos (docs/decisions/2026-11-04-ci-affected-demos.md). Zig jobs restore a build cache keyed on `build.zig`, `build.zig.zon` and `src/**`. When a change needs CI, open a PR (or push to an open one); do not push to trigger CI, and batch small follow-ups into one push. Actions time is limited. The exception is `vm.yml`: a push to a `vm/*` scratch branch runs one demo, for checking work in progress (see the implementer section).
- A commit that only records status (README.md and `site/index.html` updated after a CI result) carries `[skip ci]` in its message, so it does not start a run of its own. Never use `[skip ci]` on a commit that changes code, tests, the harness, CI or generated files.
