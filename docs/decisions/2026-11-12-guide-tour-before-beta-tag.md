# The guide's tour runs before the 0.5.1 beta tag

*Decided 2026-11-12 by the supervisor, from the 0.4.0 retro (`docs/retros/0.4.0.md`); the owner can overrule.*

Writing the user guide on 0.4.0 found six user-visible problems that the demos, fuzzers and diff
reviews all missed. So, for the 0.5.1 public beta and every release after it:

- Before the tag, the guide's tour (`docs/guide/tour.md`) and the Try pages run end to end on
  Linux and, for the Mac steps, on a Mac. The release PR says what ran and what did not.
- A `ZBX-B` code that a user can reach from the CLI blocks the tag. It is fixed, or the owner
  accepts it in writing in `docs/decisions/`.
- Every problem the run finds is filed as an issue and listed in `docs/guide/known-limits.md`
  until it is fixed.

0.5.0 is not affected: its gates were set before this decision and have been run.
