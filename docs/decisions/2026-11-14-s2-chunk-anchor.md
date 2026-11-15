# S2: every chunk of a longer file is anchored to the file's content hash

*Decided 2026-11-14, by the S2 slice 2 fix session, from the slice review's MUST on
`src/lazy/verify.zig`. The format details are in `2026-11-14-s2-index-format.md` (this branch's
decision, updated with it). The code is `src/lazy/chaining.zig`, `src/lazy/verify.zig` and
`src/push/pack.zig`.*

## The problem

A chunk record's `hash` is a plain BLAKE3 of the chunk's bytes. For a one-chunk file it equals
the file's content hash, which the tree commits to, so `verify` checks it. For a file of two
chunks or more nothing tied the listed hashes to the tree: an index could list any hashes, and a
fetch that checked bytes against them would accept forged bytes.

## The choice: a chaining value beside the hash, not in its place

Each chunk record now carries, **beside** the plain hash, the chunk's BLAKE3 **chaining value**
(CV) in its file:

- BLAKE3 hashes 1 KiB pieces and joins them in a binary tree whose left subtree always holds the
  largest power of two of pieces that leaves the right one non-empty. A 1 MiB chunk at chunk
  ordinal *i* is therefore one complete subtree of the file's tree, and the last chunk (which may
  be partial) is the rightmost subtree.
- The CV of chunk *i* is that subtree's non-root output: its pieces hashed with the piece counter
  starting at *i* × 1024, joined by parent nodes, no root flag. A one-chunk file has no subtrees,
  so its record's chaining field is all zero.
- `verify` joins a longer file's CVs, first to last, through BLAKE3 parent nodes, the final
  parent with the root flag, and refuses the index (`E1202`, `Malformed`) unless the result is
  the entry's content hash. A one-chunk file's chaining field must be zero.

Why beside and not instead: the store keeps plain chunk hashes (`put_chunk` checks a chunk's
bytes against its plain BLAKE3, `chunks.Wanted` and `<id>.chunks` list them), and slice 3 needs
them before any byte arrives. Replacing them would change the store's chunk identity. Keeping both
costs 32 bytes a chunk (a record is 80 bytes, not 48).

**What slice 3 must check.** A plain hash cannot be checked without the bytes, so a fetch checks
a chunk's bytes against its CV at its ordinal first (`chaining.run_value`), which ties them to
the tree, and only then against the plain hash (`put_chunk` does). A chunk that matches its CV
but not its hash means the index lied: refuse it (`E1202`) and use none of it.

std's `Blake3` keeps its compression function and tree private, so `chaining.zig` has its own
portable copy. Its tests check it against std's root hash for inputs of 1, 2, 3, 5 and 8 runs,
with a partial last run, and the `chaining` fuzzer checks random lengths and run sizes (and that
a flipped or swapped CV joins to another hash).

## The size cost of the cut rule (recorded, not changed)

Writer 2 starts a fresh compressor at every cut (before each body, after each 1 MiB of it,
before the index). On trees of many small files that costs a lot. Measured on
`/usr/share/perl5` (Ubuntu 24.04 container, 212 files, 1,506,304 tar bytes):

| layer | bytes | vs. `tar \| gzip -6` |
| --- | --- | --- |
| `tar \| gzip -6` | 327,464 (review), 327,495 (here) | — |
| writer 2, real (`zbx`, from the review) | 474,319 | +45% |

The option the review asked for, no cut before bodies under a size, was measured with a model of
writer 2 (`zlib` level 6 raw deflate, a fresh compressor at each cut, Python's tar headers;
its writer 2 figure, 447,831, is below the real one because std's deflate is a little weaker and
the model has no index, so compare rows with each other, not with the real figure):

| model | bytes | vs. model writer 2 |
| --- | --- | --- |
| whole stream, one compressor (gzip -6) | 323,850 | −27.7% |
| writer 2: cut before every body and after it | 447,831 | — |
| no cut before bodies < 4 KiB (cut after kept) | 445,714 | −0.5% |
| no cut before bodies < 64 KiB (cut after kept) | 444,923 | −0.6% |
| no cut before or after bodies < 4 KiB | 411,169 | −8.2% |
| no cut before or after bodies < 16 KiB | 351,685 | −21.5% |
| no cut before or after bodies < 64 KiB | 324,849 | −27.5% |
| bodies < 16 KiB share a segment up to 64 KiB of tar | 360,666 | −19.5% |
| bodies < 64 KiB share a segment up to 256 KiB of tar | 328,503 | −26.6% |

So the cut **before** a small body saves almost nothing on its own: the history is lost at the
cut **after** the previous body. What recovers the size is letting small bodies share a segment,
which means a small file's range starts at its segment's start and a reader inflates up to the
segment's cap to get it. A cap bounds that cost. The format's cut rule is **not** changed here
(supervisor, 2026-11-14); a change would be a new writer version and belongs to its own
decision.
