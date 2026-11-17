# M2b: the run and ps JSON gain the knobs without a schema bump

*Decided 2026-11-17, by the supervisor, on the review of M2b slice 1 (PR #178).*

`zbx.run/1` and `zbx.ps/1` stay at version 1. Slice 1 adds members to both documents (the
container's `ulimits`, `sysctls` and `shm_bytes`) and changes or removes none, so a reader of
version 1 that ignores unknown members, as the schemas ask, reads the new output unchanged. A
bump is for a change that would break such a reader: a member removed, renamed, or given a new
meaning or type.

The members are listed in `src/schemas.zig`, and the snapshots
`src/testdata/run_knobs.json.txt` and `src/testdata/ps_knobs.json.txt` hold the output with all
three knobs set. The run record's own version did move (to 12, `record_version_knobs`): a record
is parsed strictly, and only a version-12 record may carry the knobs.
