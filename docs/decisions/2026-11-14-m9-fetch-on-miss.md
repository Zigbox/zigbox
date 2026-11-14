# M9: a fetch is downloaded when its step misses, and its provenance input is the pin

*Decided 2026-11-14, by slice 3b (the review fix of the pinned fetches).*

A `.fetch` copy source is downloaded in the step's copy, under the store's shared lock, and only
when the step misses its cache and the blob is not in `blobs/sha256/` whole. The first version
downloaded every missing blob before the plan, outside the lock, which cost a download even when
every step then hit, and let two builds fetching one pin share a partial file.

- **Unique partial per download.** Each download writes `<store>/tmp/<pid>-<n>`, checks the
  SHA-256 before the rename, and removes the partial on any failure. Two builds racing on one pin
  each write their own bytes; the rename of equal bytes is idempotent.
- **A blob is trusted only whole.** Before a hit on the blob is used, its SHA-256 is checked
  again; a short or damaged blob is downloaded again. A blob damaged between that check and the
  copy is `E0511`, which names "a fetched file" and says to build again.
- **The provenance input of a step whose first source is a fetch is the pin** (the SHA-256, as
  the step's input digest), so the record is the same whether this build downloaded the blob or
  found it, cold or warm.
- **Ctrl-C** is checked in the download's sink as well as before the request.

Details: `docs/demos/m9.md` (slice 3b cuts), `src/build/fetch.zig`, `src/build/compose.zig`.
