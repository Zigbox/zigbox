# The release evidence table is rendered by a Zig tool from the Actions API

*Decided 2026-11-18, by the slice (release evidence, owner's item 5 for 0.6.0).*

The release notes the workflow drafts end with a table of what CI did for the release commit:
product sha, dependency sha, and for each gating job its run link and one of three labels,
passed, expected failure observed or skipped (docs/releases/automation.md, "The evidence table").

- **The renderer is `src/release_evidence.zig`, a build-host tool in Zig, std only** (STYLE.md:
  tools are Zig, not shell). It reads files and writes Markdown; it never touches the network, so
  its unit test renders 0.5.3's recorded API answers byte for byte, and the release `test` job
  does the same through the command line. Its bounds are named constants in `constants.zig`.
- **Fetching is `gh api` in the `draft` job**, which already uses `gh` with `GH_TOKEN` in the
  environment for every other GitHub call; the token is never printed nor on argv. The renderer
  loads from the workflow's commit (`.release-tools`), as the local actions do, so a fix reaches an
  older release commit.
- **The gates are `ci` and the release run's own `plan`, `mac-check` and `preflight` jobs.** The
  release's Mac gate is `mac-check`, which replaced waiting for `mac.yml`; reading `mac.yml` would
  make the draft wait for, or race, a run nothing else waits for. The release run's head commit is
  the workflow's (main for a dispatch), so that run's commit is not compared with the product's;
  `ci`'s run and every job of it are.
- **Labels.** A skipped job or a skipped step (other than housekeeping: `Set up job`,
  `Complete job`, and `Post X` after a step `X`) is "skipped", and it outranks a failed step; a
  step the API reports as failed in a successful job is "expected failure observed"; anything
  else that is not success refuses the table and fails the draft, as does a successful job with
  no step of its own. 0.5.3's `demo-m6d` (green, demo step skipped) is the recorded case for
  "skipped".
- **`continue-on-error` refuses (review of PR #186).** A probe on a scratch branch (run
  44380683397, recorded in `src/release_evidence/continue-on-error*`) showed the API reports a
  step that failed under `continue-on-error` as `success`, job and step, so the table could not
  tell it from a pass. The renderer therefore reads each gate's workflow file and refuses one
  that sets `continue-on-error` to anything but `false`. "Expected failure observed" stays for a
  failed step in a successful job, which no recorded run has; it is tested on synthetic jobs.
- **Every job `ci.yml` defines must be in the run once (review of PR #186).** The renderer lists
  the jobs from `ci.yml` at the release commit, by the name the API gives each, and refuses a
  missing or repeated one, and a job whose name it cannot predict from the file (a matrix, a
  reusable workflow, an expression). The release run's named jobs must each be there once.
- **A run is attempted once more by a re-run;** the table names the newest run's attempt and the
  API's jobs for it, which are the latest attempt's.
