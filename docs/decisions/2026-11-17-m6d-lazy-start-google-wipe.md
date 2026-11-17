# M6d slice 2 edits S2's lazy start to wipe the Google token

*Decided 2026-11-17, by the slice (M6d slice 2's fix session, at the supervisor's direction after the review of #179).*

`src/lazy_start.zig` belongs to S2 and ships dormant behind `build_options.lazy_start` (see [2026-11-16-0.5.2-s2-dormant.md](2026-11-16-0.5.2-s2-dormant.md)). The M6d brief says to touch nothing S2 owns without asking. Slice 2 changed it anyway, in two places, because the change is needed and small:

- **`defer pull.google.wipe()` next to `defer pull.aws.wipe()` in `start`.** `pull_commands.request_of` now fills `pull.google` with a workload identity or metadata access token for an Artifact Registry or gcr.io reference. Without the wipe, `zbx run --lazy` of such a reference would keep that token in memory after its resolve ended.
- **`ws.client.realm_fallback = null` after the resolve, and in `wipe`, with `credential = .none`.** The fallback's context is `pull.google`, which the `defer` above has just wiped. The client must never keep a pointer to wiped storage. Later range requests re-ask the realm with the Basic credential the client already holds.

## What S2 must keep when it changes `start`

Both lines stay, or their equivalent: the Google storage is wiped when the resolve ends, and the lazy client holds no fallback after that.

## Test

`src/google/pull_tests.zig`, "a lazy start keeps no Google token, and no fallback, once its resolve has ended", calls `lazy_start.start` directly, as `src/pull_tests.zig` already does for S2's own tests. It does not need the `lazy_start` build option, which gates only the `--lazy` flag in `cli.zig`. The test runs with workload identity and with the metadata fallback. It fails if either line is removed: removing the `defer` leaves the token in `pull.google`, and removing the `null` leaves the fallback set.
