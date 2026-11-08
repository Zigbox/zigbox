# M8: trust bounds the supervisor assumed
*Decided 2026-11-08, by the supervisor. These are supervisor assumptions: the owner may change
any of them, and a change is a new decision file that supersedes this one.*

- **Slice 1 leftovers, accepted.** `key_leftover_age_seconds = 600` (a `.key` or temporary
  younger than this is a live run's work, so `key new` says "wait"; older is a leftover) and
  `key_sweep_max = 32` (most leftover temporaries one `key new` removes).
- **Slice 2, accepted.** `json_depth_max = 16`, `statement_subjects_max = 2`,
  `statement_bytes_max = 128 KiB`, `signatures_per_tree_max = 8`, `trust_records_max = 4096`.
  Only `json_depth_max` is in `constants.zig` so far (the canonical JSON writer and reader use
  it); each other constant lands with the code that needs it.
- **Type URI base.** `type_uri_base` is `"https://zigbox.org"` (the owner's
  `2026-11-04-project-domain-zigbox-org.md`).
- **Canonical JSON.** Integers only (a sign only when negative), no `null`, no floats; the
  reader refuses every spelling the writer does not write. The form is in the header of
  `src/trust/json.zig`.
