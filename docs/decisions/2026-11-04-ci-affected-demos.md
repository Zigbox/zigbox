# CI: build cache, fewer jobs, affected demos only on pull requests
*Decided 2026-11-04, by the owner.*

Pull-request CI took about 23 minutes of wall time: 51 jobs with no `needs`, about 30 of them one fuzzer each, spread over 17 minutes of runner queueing, and nothing cached but the VM images. Three changes:

1. **Zig build cache** (`.github/actions/zig-cache`): `~/.cache/zig` and `.zig-cache` (not the VM images, which have their own entries, and not the old-release worktrees) are cached per job kind, keyed on OS, the pinned Zig (the hash of `setup-zig`'s action file, which names the version and checksum) and the hash of `build.zig`, `build.zig.zon` and `src/**`. A restore without an exact hit starts from the newest entry of the same job kind. Zig's cache is content-addressed, so a restored entry only skips work that identical inputs already did. A Run step with side effects (tidy, fuzz, the size gate, the release smoke run, `dbus-live`, the errors-site check, every VM demo) runs every time; a unit-test binary is skipped only when it is byte-identical to one that passed. An entry over 1500 MB is dropped on restore, because Zig never prunes its cache and a chain of restores would otherwise only grow.
2. **One fuzz job** (`zig build fuzz -- all 10000`) in place of one job per fuzzer. The seeds stay visible: the runner prints `fuzz: <name> seed=<n>` before each fuzzer.
3. **A `changes` job** (`.github/ci-changes.sh`) that every other job needs.
   - A pull request that changes only docs (a `.md` outside `src/`, anything under `site/` outside `site/errors/`) runs nothing else.
   - A pull request runs the VM demos its changed paths can affect: a harness file named for a demo (`checks_m3.zig`) runs that demo and every later one, since a demo repeats the parts of the demos before it; `src/build/` runs m7; the registry, pull and lock code runs m4 and later; state code runs m6 and later; exec and logs code runs m6b and later; the doctor runs m0. Tests of the code, fuzzers, the Mac build, packaging, docs and the site run no demo. `build.zig`, `build.zig.zon`, `.github/`, `vm/`, `src/testing/vm/lib/`, the shared harness files, and any path no rule names (the runtime, the host, the store, the CLI) run every demo.
   - A push to `main`, a pull request from a `claude/release-*` branch and a pull request labelled `full-ci` run everything, docs-only or not.

The owner accepted that a break the affected set did not select can first show on `main`, after the merge. `full-ci` is the way to ask for the full set on a risky pull request. The rules err toward running; when a demo is found to have missed a break, widen its rule in `ci-changes.sh`.

Adding the `full-ci` label starts a run (`pull_request` has `labeled` among its types), and so does any other label; the newer run cancels the older one.

## Cache follow-ups (same PR)

- Negated cache paths need `/**` to exclude a directory's contents (`!.zig-cache/zbx-vm/**`,
  `!.zig-cache/zbx-old-tree-*/**`); without it a restored `zbx-old-tree-<commit>` pointed its
  `.git` at a worktree that no longer existed. The key prefix is `zig-v2-` so no entry saved
  before that fix is restored.
- The size guard runs after every restore and checks the directories, not `cache-matched-key`,
  which is empty on a restore-key hit.
- Each demo job has its own cache name (`demo-m0` ... `demo-m7`), so each saves its own entry
  instead of nine jobs racing for one key. The save step prints the entry size (`Sent N of N`).
