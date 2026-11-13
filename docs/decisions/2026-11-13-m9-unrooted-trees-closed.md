# M9 slice 2: the two unrooted trees are rooted

Date: 2026-11-13. Supersedes the "Known gaps" of `2026-11-13-m9-root-output-tests-and-gaps.md`
and the "Known gap" line of `docs/demos/m9.md` (the latter edited, it is not a decision file).

- A command step's input tree is rooted by `input_job` (`root_tree`, shared with the parent),
  as a copy entry's source already was. `compose.begin` drops it on a hit and on an error;
  `settle` drops it after the record is written or the step failed; `abort_step` drops it.
- A copy's selection tree is rooted by `compose.copy_select`, dropped when `begin_copy` ends.
  A project source that is also a selection made earlier in the same step keeps its root until
  the end (`is_selection`).
- The test pinning 0 roots is turned round (1 root at the cache entry's write, and a gc plan
  with it keeps a tree that one without it removes). New tests: a command step's input root
  while its worker runs, after abort and after settle; a copy that selects nothing leaves none.
- Not covered: a `zbx` killed with SIGKILL leaves the roots of the step in flight (the same as
  any root step's output root); `store gc` shows them.
