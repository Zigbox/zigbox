# Supervisor handoff

This is the handoff for the Zigbox **supervisor** session: the agent that writes briefs, settles decisions with the owner, spawns implementers, reviews their slices and keeps the docs and status in step. A new supervisor starts from this file, `AGENTS.md`, the README's status table and the current brief, and from nothing else. Update this file whenever the state below changes, and before the session hands over.

*State as of 2026-10-30.*

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

- **M0–M6:** demonstrated and merged.
- **M4b (Mac):** built by the session on the owner's Mac (PRs #18–#20), with releases 0.1.0 and 0.1.1. Not demonstrated. `mac.yml`'s job is skipped until the owner sets the repo variable `MAC_RUNNER_LABEL`.
- **M6b (dev loop):** in progress, brief `docs/briefs/M6b-dev-loop.md`, with six slices run in order.
  - Slices 1–3 (`--mount` and `--user`, `zbx logs`, `zbx exec`) are merged (PR #21).
  - **Slice 4 (pull in the library)** is reviewed, its twelve review findings fixed by a fresh agent (commits 0c40991, 7b1551e), plus one bug the new fuzzer then found (75dc033: a failure record must be an error and must end the report), and merged into the working branch `claude/blissful-cannon-7pcv0x` with the `AGENTS.md` context-discipline section and this file; its PR, [Zigbox/zigbox#22](https://github.com/Zigbox/zigbox/pull/22), is green in CI ([run](https://github.com/Zigbox/zigbox/actions/runs/41065703920), every demo m0–m6) and waits for the owner to merge. What the fixes decided:
    - A caller's over-long reference or mirrors setting is refused (`E0501`, `E0514`), never asserted.
    - The report pipe is sized with `F_SETPIPE_SZ` and verified; a pipe that stays under 16 KiB refuses the pull with `E0419`. This was chosen over draining the pipe while waiting, which would mean reworking `namespace.run`. If a real host hits that refusal, drain instead.
    - The parent reads the report without waiting for end of file, so a write end inherited by another thread's child cannot hang it.
    - A damaged report fails the pull; every exit path of `read_report` is tested; a new `pull_report` fuzzer covers the format.
    - Warnings past the cap print one `W0504` line in the CLI; the library reports them as `Result.warnings_dropped`.
  - **Next:** once #22 is merged, restart the working branch from `main` and start slice 5.
- **Slice 5** is `demo-m6b`:
  - the spec's five steps exactly;
  - the acceptance checks;
  - the agent test, by JSON only;
  - the upgrade test against M6 (`bf57ec8`);
  - the `demo-m6b` CI job and `m6b` in `vm.yml`'s picker;
  - `docs/demos/m6b.md`.

  Start a fresh Sonnet implementer from the brief, the branch and slice 4's handoff above.
- **Slice 6** is the Mac (`logs` and `exec` forwarded). It belongs to the Mac session after slice 5 merges; hand the owner a short note for it then.
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
