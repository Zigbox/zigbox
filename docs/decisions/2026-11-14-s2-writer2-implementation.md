# S2: how layer writer 2 records its index, and where the anchor is read

*Decided 2026-11-14, by S2 slice 2. The format is
[2026-11-14-s2-index-format.md](2026-11-14-s2-index-format.md); this file records how the
writer and the manifest reader carry it out. Code: `src/push/pack.zig`,
`src/push/pack_index.zig`, `src/registry/manifest.zig`.*

- **Spill files.** The index can reach `lazy_index_bytes_max` (64 MiB), far more than a pack
  workspace holds, so the recorder writes its three sections (trees, objects, chunks) to three
  temporary files under the store's `tmp/` (mode 0600) as the walk finds them, and copies the
  header and the three files into the stream after end-of-archive. They are unlinked on every
  path out of `write_layer`; one that cannot be unlinked is left to gc's sweep of `tmp/`.
- **The seen set.** First appearance of a tree or an object is decided by `lazy/seen.zig`'s set
  (about 20 MiB, in the pack workspace), sized for `lazy_nodes_max` entries, the same set the
  verifier uses, so writer and reader agree on what "first" means.
- **No index past a bound.** Past `lazy_nodes_max` names, or past `lazy_index_bytes_max` index
  bytes, the recorder stops and the layer is written without index or annotation (the owner's
  answer; the read side says `W1201`). The tar and its compressed segments are the same either
  way, so the bound changes only the bytes after end-of-archive.
- **The pack record.** A version 2 record (`pack/<tree>-2`) gains an `index` line: the anchor
  as the annotation spells it, or `none`. A cached pack gives back the same anchor without
  reading the blob.
- **A test knob.** `pack.Workspace.names_max` is `lazy_nodes_max` in `pack` and lowered only by
  tests and fuzzers calling `pack_pieces`, so the no-index branch is reached without a tree of
  262,144 names. It is not a user-visible bound.
- **The read side.** `registry/manifest.zig` reads `org.zigbox.lazy-index` from `layers[0]`'s
  descriptor only, into `Resolved.lazy_index`, through the same allocation-free annotation
  reader as the manifest's `org.zigbox.tree`. Any other spelling, a repeat, a non-string or an
  anchor on another layer is no index, never a refusal of the manifest.
