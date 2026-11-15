# S2 resolver: sources, the registry range, pacing and memory

*Decided 2026-11-14, by the supervisor (rulings asked for by slice 3).*

Slice 3 (the chunk resolver, `src/lazy/schedule.zig`, `src/lazy/resolver.zig`) asked four
questions before choosing. The rulings:

1. **`lazy_sources_max = 8`.** A caller passes at most 8 sources (peers, then the registry). It is a
   named constant in `src/constants.zig`, asserted at comptime to fit the one-byte source set each
   object keeps (the sources that lied about it). Refusing more is a new code; it belongs to slice 5,
   which wires `StartOptions`, so slice 3 only asserts the bound.
2. **The registry is a `lazy.Range`, not a `lazy.Source`.** Peers serve a chunk by object id and
   index; the registry serves bytes of the layer blob by offset (an HTTP `Range`), so neighbouring
   chunks coalesce into one request of at most `lazy_range_bytes_max` and the resolver inflates
   each chunk from its `Location` itself. `lazy.Event` carries each source's outcome for the chunk
   (`not_tried`, `down`, `not_found`, `timed_out`, `failed`, `lied`, ...), so an `unavailable`
   event says why without a log.
3. **Retry pacing reuses `lazy_down_fail_ms`.** When every source has been tried for an entry, the
   next round starts `lazy_down_fail_ms` (2 s) after the last one began, and an entry with no source
   left that is not down fails at `requested + lazy_down_fail_ms`. No new constant.
4. **Memory: option (a), no bound changes.** The resolver allocates everything at start:

   | per slot | bytes |
   |---|---|
   | compressed range, `lazy_range_bytes_max` + 2-byte trailer | 8 MiB + 2 |
   | one inflated chunk, `store_chunk_bytes` | 1 MiB |
   | store write buffer, `store_io_buffer_bytes` | 256 KiB |
   | inflate window, `std.compress.flate.max_window_len` | 64 KiB |
   | **slot total** | **9.3125 MiB + 2** |

   `lazy_slots = lazy_fetches_max + lazy_fill_fetches_max = 10` slots: **93.125 MiB** (and 20
   bytes). `resolver.memory_bytes` is computed from these constants and asserted at comptime to be
   at most 96 MiB. The schedule's tables (`lazy_pending_max` entries, the jobs, the events) are
   a few tens of KiB on top. The earlier estimate of about 140 MiB counted a second network buffer
   per slot for the registry's HTTP client. `Range.fetch` writes into the `out` it is given, which
   is the slot's range buffer, so the client that implements it must not need a second one; that
   client is not in slice 3 (the simulation stands in for it), and its own buffers are counted
   when it lands. The S2 budget for a lazy run is restated (supervisor, 2026-11-14) as about
   140 MiB plus the index's trees section (at most `lazy_index_bytes_max`), which slice 4's node
   table holds; the resolver's share above is unchanged.

## Also decided in slice 3

- **One inflater.** Each chunk's range is inflated by slice 2's `index.inflate_range`
  (`docs/decisions/2026-11-14-s2-index-format.md`): raw deflate closed by an appended empty final
  block. `resolver.zig` held a verbatim copy until slice 2 merged; the merge replaced it with
  slice 2's function.
- **Wake times are in the future.** `Schedule.tick` returns only deadlines, rounds and probes still
  to come. A due probe or round is taken by the next free slot; returning `now` for it once hid a
  2 s deadline behind it (found by the simulation, `src/lazy/sim.zig`).
- **A lie after the reader gave up still counts.** A source that answers a chunk with the wrong
  bytes after its entry failed on the deadline is named (`lied`) and not asked for that object
  again, like any other lie.


## How reads reach the resolver (supervisor's correction, 2026-11-14)

A FUSE READ has the reader's size and offset, up to `max_pages` × 4 KiB: 128 KiB for a buffered
`cat`, 256 KiB with `POSIX_FADV_SEQUENTIAL`, 4 KiB for a small `pread` at any offset, 1 MiB for
`O_DIRECT`; one READ may cross a chunk boundary. The resolver never sees READs. It serves
whole chunks (`Resolver.read(object, chunk, out)`); slice 4 turns a READ into one call per chunk
it touches, in order, and caches what it resolved. So:

- Sequential access is seen from where reads land, chunk by chunk (`Schedule.note_read`): the next
  chunk after the last one is a step forward, the same chunk again leaves the streak as it was,
  any other chunk starts over. Request size plays no part.
- A chunk already resolved is read from the store, with no fetch and no pending entry, and still
  counts as a read for readahead.
- Tests in `src/lazy/sim.zig`: a small unaligned read, a read across two chunks, a sequential run
  of quarter-chunk reads (256 KiB of 1 MiB), and repeat reads of every resolved chunk.

Detail: `docs/briefs/S2-lazy-start.md`, sections 4 and 5.
