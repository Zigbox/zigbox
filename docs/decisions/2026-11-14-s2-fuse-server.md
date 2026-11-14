# S2: the FUSE server's memory and how it addresses objects

*Decided 2026-11-14, by S2 slice 4, approved by the supervisor. The code is `src/fuse/` (`abi.zig`,
`nodes.zig`, `ops.zig`, `resolver.zig`); the brief is `docs/briefs/S2-lazy-start.md`.*

## Memory

The node table has a fixed part and an arena.

- **The fixed part** is per node: an 80-byte `Node`, a 12-byte `Child` and 8 bytes of
  id-to-node map. At `lazy_nodes_max` (262 144 nodes) that is 25 MiB, the brief's estimate of
  about 24 MiB. A comptime assert in `nodes.zig` holds it to that size.
- **The arena** holds the image's directory objects, so that replies can point into their names,
  attribute sections and symlink targets. It is sized from the index's trees section, whose length
  is known before the build, plus one tree's room (`store_tree_bytes_max`). The table checks at
  run time that its arena is exactly that size. Each distinct tree is copied once: a subtree named
  twice is found by digest in the id map and read again from the arena, so the trees section is
  always enough. Its ceiling is `lazy_index_bytes_max`: the trees
  are part of the index, and the index is bounded already.

The lazy run's memory budget is therefore restated: **about 140 MiB plus the image's trees
section**, which is at most `lazy_index_bytes_max`. Most images have a few MiB of trees; only a
maximal index reaches the ceiling. No bound or default changes.

Two alternatives were rejected:

- *Pointing into the index bytes instead of copying them.* The caller would have to keep the
  whole index in memory for the run, which costs more in the usual case.
- *Keeping only names, attribute sections and targets.* This trims about a third of the arena and
  makes the build more complex.

## Object ordinals

Slice 3's `Resolver.read` addresses an object by its position in `Catalog.objects`, which is the
index's object order. That order is first appearance in a preorder walk of the tree: names in the
tree's order, each directory before what it holds. The pack writes a repeated subtree again, so its
objects keep the ordinals of their first appearance.

After the build, the table walks itself the same way and records each file node's ordinal. The
ordinal goes in a field that files do not otherwise use (a directory's first child), so `Node`
stays 80 bytes, which a comptime assert checks. The walk's stack is a fixed array of
`store_depth_max + 1` frames (about half a KiB); a deeper tree, which the store never holds, is
refused as malformed.

When the run starts, the adapter (`fuse/resolver.zig`) checks every file node's id against
`catalog.objects[ordinal].wanted.id`. A mismatch refuses the run as a malformed index, with the
existing malformed-index code; no code is added. This check is what lets the server trust the
ordinal: an index whose object order disagrees with its own tree is refused before any read.

`ops.Chunks.read` returns a `u32`. The adapter asserts that `Resolver.read`'s `usize` result is at
most `out.len` before it casts.
