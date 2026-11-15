# M9: rulings on the copy-chown reviews

*Decided 2026-11-14, by the supervisor; recorded by the fix session (branch `claude/m9-copy-chown`).*

Two adversarial reviews of the copy-chown slice (`2026-11-14-m9-copy-chown.md`) raised findings
the supervisor ruled on before the fix. Each ruling and what carries it out:

1. **The restamp walk is bounded by entries, as `store verify` is.** `copy_owner.restamp` counts
   every entry it decodes against `store_walk_entries_max`; one past it is `too_large`, which
   the step reports as `copy_refused`, never `unreachable`. The budget is a `Context` field that
   defaults to the constant, so a test reaches it with a small shared-subtree DAG; the bound
   itself is unchanged. `compose` checks for a signal right after the restamp, which can take
   seconds.
2. **The child's failure path is tested.** Sim compose tests corrupt the selection's file object,
   make the child's change of owner fail, and cut the child's report while it exits 0; each
   asserts the exact code and cause in the parent and that nothing was recorded.
3. **A number-only `.chown` follows BuildKit.** A uid alone as a number gets the group of the
   same number (`1000` is 1000:1000); a name alone keeps the primary group its passwd line
   gives. `.user` is unchanged: a uid alone there takes its passwd group, as Docker's `USER`
   does. The unmerged `2026-11-14-m9-copy-chown.md`, which said numbers were taken as written,
   was corrected on the branch.
4. **An owner the user namespace cannot map is E0817.** Under the full map ids 0 to 65536 are
   mapped; a larger id is refused in the namespace child before any write, one line naming the
   `.chown` text, the id and the range, never an `EINVAL` dump under E0417. No new code: E0817's
   summary is broadened to "a user, group or owner id cannot be used". Under the one-id map
   (W0201) every owner is 0:0, so nothing is refused there.
5. **Parent directories keep the slice's behaviour.** Directories `.copy` creates on the way to
   `.to` get the `.chown` owner (0:0 with none) and mode 0755; directories the base already has
   keep their own mode and owner. The brief's "missing parents are created `0755 0:0`" is
   amended to say so.
6. **Smaller items.** The depth and entry bounds are tested at and one past the bound; the
   `build_chain` fuzzer draws a random stamp on some copy steps and checks that it is idempotent,
   changes nothing outside `.to`, and leaves the base's directories on the way with their own
   attributes; a chmod-only change is tested to miss; `docs/demos/m9.md` notes that a W0201
   build's 0:0 output stays cached under its `.chown` text after `newuidmap` appears;
   `Frame.on_path` is gone (a selection holds only the way above `.to`, now an assertion), and
   a directory right under `.to` and the `depth >= path_len` boundary are tested; a passwd over
   128 KiB (group over 256 KiB) says the file is too large, not that the name is missing.

Carried out in `src/build/copy_owner.zig`, `copy_job.zig`, `compose.zig`, `diagnose.zig`,
`src/image_user.zig`, `src/diag/codes.zig`, `src/fuzz_build_chain.zig`, and the tests in
`copy_owner_tests.zig` and `compose_tests.zig`.
