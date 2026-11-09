# `statement_bytes_max` follows the provenance record: 256 KiB

*Decided 2026-11-09, by the M8 slice 4 implementer; the supervisor signs off the bound.*

Slice 2 set `statement_bytes_max` (the largest signed payload) to 128 KiB, a number made before provenance existed. A provenance record lists every step of the build file and every base, so its worst case is far larger than a `sign/v1` statement.

**Evidence.** `provenance_bytes_max` (`constants.zig`) is the longest record: `provenance_steps_max` (= `build_steps_max`) steps at `provenance_step_bytes_max` each, one more base than steps, and the build file's path at six bytes a byte (JSON escape). A test (`provenance_tests.zig`) renders that worst case, parses it back and shows it in text and JSON within the buffers. It exceeds 128 KiB.

**Choice.** `statement_bytes_max` is `provenance_bytes_max` rounded up to a multiple of 64 KiB, which is 256 KiB. Comptime asserts keep it at least the record's bound and under one more 64 KiB. `inspect_provenance_bytes_max` is twice it. A signature record of eight envelopes of that size is about 2.8 MB, so `sim_fs_pool_bytes_max` is 3 MiB (4 MiB breaks the test binary's link: static data past 2 GiB).

**Consequences.** Memory of the sign, gate and inspect workspaces grows by about the difference; signature records may grow on disk, and `signature_record_bytes_max` follows. Slice 3's policy and record formats do not change.
