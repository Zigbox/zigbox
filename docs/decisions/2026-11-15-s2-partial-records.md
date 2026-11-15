# S2 lazy start: partial image records, run record v11, and `StartOptions.lazy_sources`

*Decided 2026-11-15, by the slice (S2 slice 5b), for the supervisor's review.*

- **Image record version 4** adds `partial=true`, written only by a lazy start
  (`src/lazy_start.zig`): the record roots the tree and the config blob for gc while the files
  are fetched. A whole image is still written as version 3, so a record older zbx can read stays
  readable by it. `store ls` shows `partial N%`; `store verify` counts partial images
  (`partial_images` in JSON) and does not call their missing files corrupt.
- **Run record version 11** adds `.lazy` (local share, fetched bytes, errors, the count of
  sources, not their names), written only for lazy runs; listen and device runs stay version 10,
  plain runs version 9. `ps --output json` shows it as `lazy`. There is no run inspect (cut,
  docs/demos/s2.md).
- **gc and holders need no change:** the partial record roots the tree, gc walks the tree
  without needing its file objects, and a running container's tree is live through its run
  record.
- **`StartOptions.lazy_sources`** (`src/runtime/run.zig`) hands a library caller's peers to the
  run's resolver, asked after the store and before the registry, through the `run.Lazy.peers`
  hook. Only with `lazy`, at most `lazy_sources_max - 1`. Its types are pinned by the surface
  test in `src/zigbox.zig` ("the lazy surface Zigcube's agent plugs its swarm into").
