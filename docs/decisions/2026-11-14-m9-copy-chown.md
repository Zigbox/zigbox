# M9: a copy step's `.chown` and `.chmod` run

*Decided 2026-11-14, by the slice (branch `claude/m9-copy-chown`).*

Closes the cut slice 2 left (`copy_unrunnable` gave E0802 for both fields). Follows
`2026-11-12-m9-glob-pool-and-copy-chown.md`: the owner is set in the child, never the parent.

- **Where.** The parent selects (`copy.select`) as before. If any entry has a stamp,
  `copy_job.restamp` runs one `namespace.run` child, single-threaded, before any exec. It rewrites
  each stamped selection tree (`copy_owner.restamp`, iterative, bounded by `depth_max`). It
  writes each new file object from the source object's path with the new attributes, and sends
  the new digests back on a pipe, or an encoded diagnostic. The step's shared store lock is held
  from the cache lookup to `cache.record`, so the new trees need no roots.
- **Names.** `.chown` resolves through `image_user.resolve` against the step's base tree, the
  same lookup as `.user`. A user alone takes its primary group, and numbers are taken as
  written. An unknown name is E0817, with the cause naming the step and the text. 4294967295 (in
  either part) is refused under E0817 too. It passes `is_user_part` but means "no owner" to the
  kernel, and the tree writer asserts against it. No new code was registered.
- **What gets stamped.** Every entry the patterns took gets the owner. Files and directories get
  the mode; symlinks keep 0777. The directories `copy.select` makes on the way to `.to` (and
  `.to` itself when it is one of them) take the owner but keep 0755, as Docker gives new parent
  directories the `--chown` owner. A directory the base already has keeps the base's attributes,
  because the merge keeps the base's metadata where two directories meet. The selection's root
  keeps its own attributes.
- **One-id hosts.** Under W0201 the child gets `squash_owner`, the owner becomes 0:0 (as every
  owner the store writes there), and the mode still applies.
- **Key.** `.chown` and `.chmod` text are in the copy entry's key (`ws.copy_keys`), so a changed
  one misses.
- **Damage.** A source object whose bytes no longer match its id is reported the way a copy's
  assembly reports an unreadable tree (`store_diagnose.write_failed`, via `copy_job.failed`).
  It is not written as a new object.

No parser changed, so no fuzzer was added. Tests: `copy_owner_tests.zig` (pure stamping, every
depth, idempotence, damage, a missing tree) and four compose tests, run with the sim's
owner gate, which refuses a change of owner outside a new user namespace.
