# M8 slice 4 handoff

*Written 2026-11-09 by the slice 4 implementer.*

**Decisions.** The provenance record is unsigned and stored by result (`trust/provenance/<result hex>`); `sign` wraps its exact bytes and falls back to `sign/v1` when there is none. `require_provenance` is met only by a trusted-key provenance line bound to a result that fits the run, not by a stored record. E0906 mirrors E0905. A full store skips the record with a stderr line and the build still succeeds. The git source read is cut. See docs/demos/m8.md, "Slice 4".

**Traps.** `Verdict.Examined.provenance` is known for every line whose signature verifies, even one judged `untrusted_key`; the E0906 cause depends on it. The compose test's sim store has no `zbx.lock` on disk, so the record's `lock` is null there; the real build reads the file. Test binary static data must stay under 2 GiB (the biggest objects are `cli.shared_storage` and `cli.test_storage`, 234 MB each).

**Next.** Slice 14's push gate asks the same `verdict` question; `require_provenance` there needs a result binding, which a push has only for a result image.
