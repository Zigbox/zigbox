# S2: layer writer 2 and the lazy index, byte for byte

*Decided 2026-11-14, by S2 slice 2 (the brief, `docs/briefs/S2-lazy-start.md`, leaves these
details open; slices 3 to 5 read them). The code is `src/lazy/index.zig` (format, parser, checks,
range inflate) and `src/push/pack.zig` (the writer).*

## The layer (writer version 2)

- One gzip member. The 10-byte header is std's (`flate.Container.gzip.header()`, as version 1),
  the 8-byte footer is CRC-32 and ISIZE of the whole uncompressed stream.
- Between them, raw deflate written in **segments**. A segment ends with a sync flush (every
  block written, byte-aligned, no final bit), and the next segment starts with a **fresh
  compressor**, so no back-reference crosses a segment boundary (zlib's `Z_FULL_FLUSH`; std's own
  `flush` keeps its history, so a new compressor is the full flush). Boundaries sit: before the
  first data byte of each file body that the tar carries, after each 1 MiB chunk of it
  (`store_chunk_bytes`, the store's chunking) and after its last chunk, and before the index. The
  stored bytes between boundaries (tar headers, padding, end-of-archive) are segments too.
- The uncompressed stream is the tar (version 1's walk and entries, unchanged), its two zero
  blocks, then the index bytes. The config's `diff_id` is the SHA-256 of all of it. Tar readers
  stop at the first zero block (M4's `layer/tar.zig` does; `layer/reader.zig` then reads the rest
  of the blob raw for its digest), so every release since M4 reads a version 2 layer.
- The index's segment is the last; the final deflate block closes it.

## Inflating one chunk

The compressed range `[offset, offset + length)` of a chunk (offsets are bytes of the **layer
blob**, gzip header included, so they go into `Range` unchanged) is a run of whole, non-final
deflate blocks that starts with an empty history. It inflates as raw deflate to exactly the
chunk's bytes. `index.inflate_range` does this (it appends an empty final fixed block, `03 00`,
so std's decompressor sees an end); the index's own range ends in the final block and inflates the
same way.

## The annotation

On the **layer descriptor** in the manifest (`layers[0].annotations`), so the manifest digest
commits to it; the manifest's own annotations keep `org.zigbox.tree` and
`org.zigbox.layer-writer` (`"2"`). Name `org.zigbox.lazy-index`, value exactly:

    offset=<decimal> length=<decimal> size=<decimal> digest=b3:<64 lowercase hex>

`offset` and `length` are the index's compressed range in the blob, `size` its uncompressed
length, `digest` the BLAKE3 of the uncompressed index. Decimal without leading zeros (except `0`),
single spaces, nothing else. A value in any other form is not an index (`W1201`), not an error.

## The index, version 1

Little-endian, no padding, no trailing bytes. Every count and length below is checked by the
parser; anything the writer cannot write is refused.

Header, 72 bytes:

| at | bytes | field |
| --- | --- | --- |
| 0 | 8 | magic `zbx-lazy` |
| 8 | 4 | version, 1 |
| 12 | 4 | complete: 1 for an index, 0 for a stub (below) |
| 16 | 32 | the root tree digest (BLAKE3), equal to `org.zigbox.tree` |
| 48 | 4 | chunk bytes, 1 048 576 |
| 52 | 4 | names: entries of the tree counted by path (every tar entry but the root `./`) |
| 56 | 4 | trees count |
| 60 | 4 | objects count |
| 64 | 4 | chunks count |
| 68 | 4 | order count (the reserved prefetch section; must be 0 in version 1) |

Then four sections, in this order:

1. **Trees**: per distinct directory, `digest[32] length:u32 bytes[length]`, the store's tree
   encoding, `1 <= length <= store_tree_bytes_max`, hashing to `digest`. The first is the root.
2. **Objects**: per distinct file object whose bytes the tar carries,
   `id[32] size:u64 first_chunk:u32 chunk_count:u32` (48 bytes). `chunk_count` is
   `ceil(size / chunk bytes)` (0 for an empty file); `first_chunk` is the sum of the counts before
   it. Every file object of the tree is here, empty ones included.
3. **Chunks**: per chunk, object by object,
   `hash[32] chaining[32] offset:u64 length:u32 zero:u32` (80 bytes): the chunk's BLAKE3, its
   BLAKE3 chaining value in its file (all zero for a file of one chunk;
   `2026-11-14-s2-chunk-anchor.md`), its compressed range in the blob, and four zero bytes.
   `1 <= length <= lazy_range_bytes_max`; ranges are in increasing order and never overlap, the
   first starts at or after byte 10, and the last ends at or before the index's own offset.
4. **Order**: `order count` chunk ordinals (`u32`, each below the chunks count). Reserved for a
   start profile (brief, decision 7). Version 1 has none: the parser refuses a non-zero order
   count, so a later version that fills it changes the version number.

**Order of trees and objects.** Both are in the order of the pack's walk (names in the tree's
order, each directory before what it holds), first appearance only. So a checker that walks the
index's own trees from the root, skipping a subtree it has seen, meets every new tree and every
new object in exactly the order they are listed; `index.verify` checks the index that way, and
refuses an index whose trees or objects are not that walk.

**Bounds.** An index longer than `lazy_index_bytes_max`, or with more than `lazy_nodes_max` names,
is too large (`E1207`), not malformed (`E1202`). The writer's memory is bounded by the same
`lazy_nodes_max`: for a tree with more names, or whose index would pass `lazy_index_bytes_max`, it
writes **no index and no annotation**, so the image runs eagerly with "no index" (`W1201`)
(supervisor, 2026-11-14: an image that cannot be lazy must still run). `E1207` stays for an index
read over the bound, such as one another tool wrote. The parser also refuses a **stub** (the
header alone, complete 0, every count but names 0) as too large; zigbox writes none.

## What `index.verify` checks (the `E1202` checks)

The bytes' BLAKE3 and length against the annotation; the header tree against `org.zigbox.tree`;
the structure above; the walk order; that every file entry's object is listed with the entry's
size; that a one-chunk file's chunk hash is its content hash and an empty file's content is the
hash of nothing (`chunks.Wanted`'s rules); that a one-chunk file's chaining field is zero and a
longer file's chaining values join into its content hash (`2026-11-14-s2-chunk-anchor.md`); the
names count; that no tree or object record is left after the walk; and that no chunk range
reaches the index. It writes nothing; a caller stores the trees with `trees.put_checked`.
