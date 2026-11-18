# A skipped job in the release evidence refuses unless it is on an allow-list

*Decided 2026-11-18, by the supervisor (review of PR #186).*

The release evidence table ([the table's decision](2026-11-18-release-evidence-table.md)) labels
a job "skipped" when the job, or a step of it other than housekeeping, did not run. A skip is
not a pass, and a gate that was skipped without anyone deciding so must not reach a release.

- **A skipped job or step refuses the table,** and with it the draft, unless the job is on the
  allow-list. The list is the `--allow-skip <job> <reason>` arguments `release.yml` passes to
  `src/release_evidence.zig`, by the job's full name as the API gives it, at most
  `release_evidence_skips_allowed_max` entries.
- **An allowed skip still reads as one:** its row says `skipped (allowed: <reason>)`, never
  `passed`, and the footer counts it as skipped.
- **Each entry gives its reason and what removes it.** This file is the record; a change to the
  list is a new decision file that supersedes this one.

| Job | Reason | Removed when |
| --- | --- | --- |
| `demo-m6d (Ubuntu 24.04 VM, KVM, Artifact Registry and gcr.io through WIF)` | Google WIF is not set up yet: the job runs, but its demo steps are skipped until the owner wires Workload Identity Federation for the repository | the owner's WIF setup lands and `demo-m6d` runs its demo steps in `ci`; the entry is then dropped from `release.yml` |

The `test` job of `release.yml` renders 0.5.3's recorded runs with the same list, and the unit
tests check that an unlisted skip refuses and a listed one is labelled with its reason.
