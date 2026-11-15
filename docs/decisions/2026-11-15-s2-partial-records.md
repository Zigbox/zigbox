# S2 lazy start: partial image records, run record v11, and `StartOptions.lazy_sources`

*Decided 2026-11-15, by the slice (S2 slice 5b), for the supervisor's review.*

- **Image record version 4** adds `partial=true`, written only by a lazy start
  (`src/lazy_start.zig`): the record roots the tree and the config blob for gc while the files
  are fetched. A whole image is still written as version 3, so a record older zbx can read stays
  readable by it. `store ls` shows `partial N%`; `store verify` counts partial images
  (`partial_images` in JSON) and does not call their missing files corrupt. The field joins
  `zbx.store.verify/1` without a version bump: a schema only grows (a field added, none
  removed or changed in meaning), and `zbx schema` shows it. A lazy start of an image the store
  already holds whole runs it from there and leaves its version 3 record as it is.
- **Run record version 11** adds `.lazy` (local share, fetched bytes, errors, the count of
  sources, not their names), written only for lazy runs; listen and device runs stay version 10,
  plain runs version 9. `ps --output json` shows it as `lazy`. There is no run inspect (cut,
  docs/demos/s2.md).
- **What older releases do with these records.** An older zbx's gc refuses to run on a store
  with a version 4 image record (`images.load` answers `Newer`, which gc treats as a record it
  cannot read), so it never sweeps a partial image's tree; `store ls` of an older zbx shows the
  image as damaged; and an older zbx skips a version 11 run record as `.newer` (`ps` does not
  list that container). `zbx pull` of the image by a current zbx writes it whole (version 3),
  which every release reads.
- **gc roots a partial tree as any tree:** the partial record roots it, gc walks it without
  needing its file objects, and a running container's tree is live through its run record. The
  chunks of an object fetched in part (`partial/<id>/`) are kept while the object is live, and
  swept by gc once no root holds it (counted with the cut downloads; removed, not trashed,
  being refetchable; the same age guard as a cut download, so a run fetching now keeps them).
- **An image of more than one layer is not started lazily:** the index covers the layer it is
  in, the first. `--lazy` of such an image warns W1201 with that cause and pulls it whole.
- **`StartOptions.lazy_sources`** (`src/runtime/run.zig`) hands a library caller's peers to the
  run's resolver, asked after the store and before the registry, through the `run.Lazy.peers`
  hook. Only with `lazy`, at most `lazy_sources_max - 1`. Its types are pinned by the surface
  test in `src/zigbox.zig` ("the lazy surface Zigcube's agent plugs its swarm into").
