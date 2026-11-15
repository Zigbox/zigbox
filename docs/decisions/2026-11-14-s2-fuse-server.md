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

- **The chunk cache** (`fuse/cache.zig`) holds `2 × lazy_fuse_threads` chunks that the serving
  threads share: 8 MiB at the defaults. See "Reads" below.
- **Per serving thread**, a reply buffer of `fuse_reply_bytes` (1 MiB and 16 bytes) and a request
  buffer of `fuse_request_bytes` (8 KiB): about 4 MiB for four threads. A thread no longer keeps a
  chunk of its own; the cache replaces those 4 MiB with its 8.

The lazy run's memory budget is therefore restated: **about 140 MiB plus the image's trees
section**, which is at most `lazy_index_bytes_max`. Most images have a few MiB of trees; only a
maximal index reaches the ceiling. No bound or default changes. The server's part is the node
table (25 MiB), the cache (8 MiB) and the threads' buffers (about 4 MiB); the resolver's is
93.125 MiB (docs/decisions/2026-11-14-s2-resolver-choices.md).

## Reads

A `READ`'s size and offset are the reader's, up to `max_pages` × 4 KiB, and the server assumes
neither. Measured live through an overlay on kernel 6.18 (this slice; the probe,
docs/decisions/2026-11-14-s2-probe-findings.md, saw only the first case):

- a buffered read reaches the server as 128 KiB `READ`s;
- after `posix_fadvise(SEQUENTIAL)`, as 256 KiB ones;
- a small `pread` as one 4 KiB `READ` at the reader's offset, aligned to nothing;
- an `O_DIRECT` read as one `READ` of the reader's size, up to 1 MiB, at the reader's offset, so
  1 MiB at 512 KiB spans two chunks.

So the server serves any size and offset: a `READ` is cut at the chunk boundaries it crosses (at
most two, since it is at most one chunk long) and each part is copied from that chunk. Brief line
100 ("`FUSE_MAX_PAGES` for 1 MiB reads") still holds for direct reads; the server asks for
`max_pages` of a whole chunk, and its reply buffer holds one.

So that the several `READ`s of a chunk cost one chunk read, the serving threads share a cache of
whole, verified chunks. The first thread to want a chunk reads it into a free slot (unlocked: the
other threads go on serving); a thread that wants the same chunk meanwhile waits on that slot and
copies from it. A slot in use is never given up; otherwise the least recently used one is. A
`READ` holds at most one slot at a time (it copies one chunk's part before it asks for the next),
and there are twice as many slots as threads, so a free slot always exists (asserted). A failed
read is not kept: the threads waiting on it answer `EIO` and the next request asks again.

Unit tests (`fuse/ops.zig`) check: eight 128 KiB `READ`s of a chunk make one chunk read, from one
thread and spread over four; one 1 MiB `READ` at 512 KiB returns two chunks' bytes from one read
of each; a 4 KiB `READ` at an unaligned offset, and one across a chunk boundary; a run of 256 KiB
`READ`s reads each chunk once. The real-kernel test (`fuse/kernel_tests.zig`) reads through the
mount with a 4 KiB `pread` at an unaligned offset, an `O_DIRECT` 1 MiB `pread` at 512 KiB, and
whole files in 256 KiB reads after `posix_fadvise(SEQUENTIAL)`.

Readahead (`lazy_readahead_chunks`) is the resolver's (`Schedule.note_read`). It goes by offsets,
never by `READ` size: it counts chunk reads, and with the cache a file read front to back reaches
it as one read per chunk, in order, whatever size the kernel's `READ`s were.

Internal buffer constants (no user-visible bound): `cache.slots` = `2 × lazy_fuse_threads`,
`fuse_request_bytes` 8 KiB, `fuse_max_write` 4 KiB, `fuse_reply_bytes` 1 MiB + 16.

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

## Run integration (slice 4)

The order of a lazy plan is: the setup child mounts `/dev/fuse` on the overlay's lower layer
(`mount_fuse`) and sends the descriptor to `zbx` (`send_fuse`). Then it makes the overlay mount,
which the kernel holds until `INIT` is answered. The parent's `serve_fuse` comes after the
go-ahead and before `await_report`. It receives the descriptor, answers `INIT` on the calling
thread, and starts the serving threads.

- **No second go-ahead.** An earlier draft had the child wait for the parent's word after
  sending (`await_fuse`). The kernel already gives that ordering, since the overlay's lookups
  wait for `INIT`. The simulator also cannot interleave a two-way handshake in the middle of a
  run, because it runs a pending child to completion inside the parent's blocking call. So the
  step was dropped.
- **One channel, two descriptors.** A lazy run with `--listen` sends the FUSE descriptor and
  then the listener over the same channel. The model's channel queues two, in order.
- **A child that ended early.** When the child has already ended, `serve_fuse` sees end of file
  (`EPIPE`) and does nothing, so `await_report` diagnoses the child's own record.
- **The server reads the store from outside its namespace** (`outside_owners`). Each serving
  thread has its own `HostReal` and `Store`, so the open count and the scratch space are never
  shared. The node table, the cache and the thread buffers are static in `main`, about
  100 MiB of bss that costs nothing until a lazy run.
- **The net layer's `etc`.** A lazy run's lower directory is an empty mount point when the
  container's directory is made, so the net layer's `etc` gets the default mode 0755, owned by
  root, rather than the tree's `etc` attributes. Slice 5 can read them from the node table.
- **Codes (supervisor's ruling, 2026-11-14).** Slice 4 registers E1207 (an image too large
  for the node table: the cause names the bound it passed, entries or MiB of directory
  listings) and E1208 (`--lazy` with `-d` or `--rootfs`; the cause names the option), with the
  brief's wording. A tree whose directories cannot be read, are missing, do not hash or do not
  decode is E0422 `tree_damaged`, with a cause saying which. A refused mount or serve stays the
  generic setup failure, with the plan step's phrase, until slice 5 adds E1201 and E1204.
- **Only `main` serves.** `cli.lazy_server` is null for tests, fuzzers and library callers. A
  lazy run there gets a server that builds nothing and refuses the descriptor, so it fails at
  the serving step and never claims a run it did not serve.
