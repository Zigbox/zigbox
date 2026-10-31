# Supervisor handoff

This is the handoff for the Zigbox **supervisor** session: the agent that writes briefs, settles decisions with the owner, spawns implementers, reviews their slices and keeps the docs and status in step. A new supervisor starts from this file, `AGENTS.md`, the README's status table and the current brief, and from nothing else. Update this file whenever the state below changes, and before the session hands over.

*State as of 2026-10-30, after M6b (demonstrated), with release 0.2.0 being cut.*

## The role

- **The owner decides; the supervisor proposes.** Anything a brief marks "(propose)", any change to the spec, and anything that changes Zigcube's design goes to the owner as a short question with a recommendation. Record each answer in `docs/DECISIONS.md` in the same push.
- **The supervisor implements nothing of size.** Implementers write the code. The supervisor writes briefs, docs, status, and small mechanical edits.
- **Run each slice the same way.** Spawn a fresh implementer from the brief, the branch and the previous handoff note. Then review the slice adversarially: delegating the read to a fresh reviewer agent keeps your own context small. Fixes go to another fresh agent, given the findings and the commit. Then run `zig build check` yourself on the result and push it to the working branch. Follow `AGENTS.md`, "Agent context discipline", throughout.
- **Models.** Sonnet implements by default ("one Sonnet coding is plenty"). Use Opus where a slice is risky, at the supervisor's judgment. Run one implementer at a time unless slices are independent by file, and give each worktree its own `ZIG_GLOBAL_CACHE_DIR`.
- **The owner merges PRs; the supervisor never merges.** Never push to `main`. CI runs only on PRs and `main`, so batch follow-ups into one push to the open PR. `vm/<demo>-<slug>` scratch branches run one VM demo (`.github/workflows/vm.yml`) and delete themselves.
- **Status follows CI.** The README and `site/index.html` (its `SITE` and `MILESTONES` data) change in the same push as the status. "Demonstrated" only after the `demo-mN` job is green in CI, and recorded output only from that run. Status-only commits carry `[skip ci]`; nothing else does.
- **Commit trailers** come from the session's attribution reminder. Never put a model name in commits, PRs or code. Every GitHub comment ends with the Claude Code footer.

## Where things live

- **The live design doc** is a Claude Docs project, https://claude.ai/artifact/6D9js8mxSLYmfuZe3rQ26w (project `2a300110-fac9-4994-82ce-6791e08952a4`, node `9749ba10-3b2c`), now at **rev 78**. `docs/SPEC.md` is its snapshot; refresh the snapshot in the same push as any doc edit. If the two disagree, the live doc wins: stop and report.
- **The whitepaper**, "Zigbox", is at https://claude.ai/artifact/8izzqJ7L2fUPKa36sGzVfY. The owner will publish it nearly verbatim.
- **The process documents:**
  - Briefs are in `docs/briefs/`.
  - Demo documents, with their cuts and failure modes, are in `docs/demos/`.
  - Decisions are in `docs/DECISIONS.md`.
  - Review is `REVIEW.md` and style is `docs/STYLE.md`.
  - Diagnostics are `DIAGNOSTICS.md`. Zigbox's copy is canonical; Zigcube carries a copy.
- **Zigcube** is the orchestrator, repo `Zigbox/zigcube`, run by its own session. Its restart orders are `docs/restart.md`, in its PR #21. They:
  - re-pin Zigbox at M6b's merge;
  - send the revised `Runtime` contract to the owner for review;
  - set R2, C0 on real Zigbox, as the next step;
  - include local mode in C1.

  Leave Zigcube's PRs to its session unless the owner asks otherwise.

## Milestones

- **M0–M6 and M6b:** demonstrated and merged.
- **M4b (Mac):** built by the session on the owner's Mac (PRs #18–#20), with releases 0.1.0 and 0.1.1. Not demonstrated. The owner's laptop is the self-hosted runner (`Laptopische`, user `ghrunner`, `MAC_RUNNER_LABEL` set); `mac.yml` is green on `main` ([run 24](https://github.com/Zigbox/zigbox/actions/runs/41143740466)). What remains is `brew install` on a clean Mac, recorded; 0.2.0 is the release to do it with. The runner runs only while the laptop is awake: a queued `mac` job is the laptop asleep, not a failure.
- **M6b (dev loop):** demonstrated. Brief `docs/briefs/M6b-dev-loop.md`, six slices run in order. `demo-m6b` green on `main` after the last merge ([run 104](https://github.com/Zigbox/zigbox/actions/runs/41143740654)) and `demo-mac`'s M6b steps green on the Mac runner ([run 24](https://github.com/Zigbox/zigbox/actions/runs/41143740466)).
  - Slices 1–3 (`--mount` and `--user`, `zbx logs`, `zbx exec`) are merged (PR #21).
  - Slice 4 (pull in the library) is merged (PR #22). Its decisions: an over-long reference or mirrors setting is refused (`E0501`, `E0514`); the report pipe is sized with `F_SETPIPE_SZ` and a pipe under 16 KiB refuses the pull with `E0419` (if a real host hits that, drain the pipe instead); a damaged report fails the pull; `W0504` / `Result.warnings_dropped` for warnings past the cap.
  - **Slice 5 (`demo-m6b`)** is merged (PR #24) and green in CI on `main` with every earlier demo ([run 95](https://github.com/Zigbox/zigbox/actions/runs/41104767772)). The red `demo-m6` on `main` after #22 (run 92, EXEC 6) was the `exec` race slice 5 fixed. What it settled:
    - Parts in order: UPGRADE (against M6 `bf57ec8`), SPEC (the five steps), WRITABLE, LOGS, EXEC (moved from `demo-m6`), AGENT, ACCEPT. ACCEPT must stay last: it prunes the oldest records.
    - `exec` decides that a command died with its container by reading PF_EXITING in `/proc/<pid1>/stat`, not by timing. The simulator models a slow PID 1 exit (`pid1_exit_ms`). Unhandled: PID 1's main thread exiting while other threads live.
    - A `zbx logs` refusal exits 1, as DIAGNOSTICS "Exit codes" says (125 is only for commands that run or wait on a workload).
    - The published-port forward accepts a host connection before the server listens and then resets it (predates M6b); the demo waits from inside the container. Recorded as a failure mode.
    - `find … | wc -l` hid a failing `find`; owner checks now use `checks_writable.owners_command`.
    - Trap: the simulator's written-files table (`sim_written_files_max`) drops files silently when full.
  - **Follow-up, PR #26 (merged):** `zbx.logs/1` describes the diagnostic a refused `logs` prints (owner decision, in `docs/DECISIONS.md`).
  - **Trap:** a status commit with `[skip ci]` at the head of a PR stops the PR's CI from running at all (GitHub reads the head commit), and the git proxy here refuses force pushes. Push a status commit to a PR only after its CI has run, or put it in the PR's last code push.
  - **Slice 6 (the Mac)** was done by the Mac session and merged (PR #27): `logs` and `exec` forwarded with the terminal and signals, and `demo-mac` (31 steps) runs M6b's five steps plus the terminal, signal and follow cases. PR #28 (merged) names a missing cgroup v2 first when a run finds no scope.
- **Release 0.2.0** (writable mounts, `--user`, logs, exec): the version bump and this status are on the working branch's PR. Then the owner runs `zig build mac-release -Dnotarize=true`, publishes `v0.2.0` with the zip and its `.sha256`, and puts the new formula in `Zigbox/homebrew-tap`. Optionally tags `v0.0.0-m6b`.
- **Afterwards:** M7 (build) and M8 (trust) are not started. Write M7's brief only when the owner says.

## Owner decisions to remember

Each is in `docs/DECISIONS.md` with its reasons:
- No Compose in zbx: more than one service, even on a laptop, is the Zigcube server's job.
- Writable mounts are allowed only under the project directory, with symlinks resolved.
- Writable mounts are written as the container's root; a non-root user is refused, with `--user 0` as the fix.
- Every run keeps logs, capped at 5 MiB.
- Pull moves into the library in M6b.
- M6: one writer per volume, `state rm` goes to a trash, `state export` writes tar.gz.
- M5: `--publish` implies `--net user`; the no-network hint is printed only on failure.
- Zighub: a catalogue yes, a hub no (spec Part III).

## The cloud environment

- **The setup script did not run in the 2026-10-30 session:** Zig, `uidmap` and `tester` were missing and were installed by hand (Zig from ziglang.org, checksum as in Zigcube's `.claude/hooks/session-start.sh`; `useradd -m tester`, `tester:200000:65536` in `/etc/subuid` and `/etc/subgid`). Check before assuming.
- **Set per command, not in the environment:** `ZIG_GLOBAL_CACHE_DIR`, one directory per worktree. Also `PATH` with the Zig directory prepended, unless the setup script puts `zig` on `PATH`.
- **The setup script provides:**
  - Zig 0.17.0, checksum-verified;
  - `uidmap`, and a user `tester` with a subuid range, for `zig build check`'s non-root pass;
  - Node 22, for Zigcube's wasm checks;
  - for Zigcube, Postgres 16, `libpq-dev` and SQLite's development files.
- **Network access:** `ziglang.org`, GitHub, and the registries the tests pull from. GitHub is reached through the MCP tools, with no token in the environment.
- **No database credentials:** nothing here uses a hosted database. Zigcube's tests start a throwaway Postgres (`zig build pg-up`).

## Traps already paid for

- **Zig's own backend writes `undefined` globals into Debug binaries,** which made 1.4 GB test binaries and filled the disk. Keep `use_llvm = true` on the zbx executable and on the tests.
- **The git proxy refuses branch deletion,** so the workflows delete their own `vm/*` branches.
- **A resumed agent sometimes reports "finished" with no commits.** The rule now is a fresh agent, never a resume.
- **Live doc edits:** an ambiguous find needs `nth`. Inserting into an ordered list can merge an item into the one before it, so delete it and insert it again.
- **Fuzzers have found real bugs in CI with fresh seeds.** Quote the seed in the PR comment, fix the bug, and never re-run the job to make it go green.
- **A container that has done heavy builds can have a stale or half-written `.zig-cache`.** `rm -rf .zig-cache` outside a build fixes it.
