# S2 lazy start: the brief's design, approved by the owner

*Decided 2026-11-14, by the S2 brief session. A later decision file supersedes the matching item here.*

The owner approved S2 (lazy start) as a goal on 2026-11-14. The owner approved all thirteen owner's
calls as recommended on 2026-11-14. The brief is
[docs/briefs/S2-lazy-start.md](../briefs/S2-lazy-start.md); it holds the detail and the reasons.
The decided design:

**Sequencing.** The owner ruled on 2026-11-14 that S2 (lazy start) is built in parallel with Zigbox
0.5.2; slices 1 to 4 start at once, each coding against the interfaces this brief fixes, and slice 5
waits for all four, and that S1 (microVM isolation) is deferred until S2 ships. Call 2's split of
S1's EROFS writer is done when S1 starts, not now. Call 13 stands: Zigcube's supervisor checks the
`zigbox.lazy.Source` interface against Zigcube's swarm before slice 3.

1. **Namespace containers use rootless FUSE**, a read-only server written in Zig against
   `/dev/fuse` (no libc, no libfuse, no `fusermount3`), mounted with `mount(2)` by the setup child
   inside the run's user and mount namespaces and served by the supervising `zbx` with a fixed
   thread pool; the FUSE mount is the overlay's lower layer in place of the hardlink farm. The other
   mechanisms either do not trap a first read (overlay over a partial tree, `userfaultfd`) or need
   root (EROFS fscache on demand, fanotify pre-content, `ublk`, FUSE passthrough). A probe in the
   cloud container (kernel 6.18, ordinary user, a stand-in C server) mounted FUSE in a user
   namespace, stacked a `userxattr` overlay on it and read through it as uid 1000 with a full id map;
   Ubuntu 24.04 is checked by slice 1.
2. **MicroVMs are not in S2**: `--lazy` with `--isolation vm` is refused (`E1208`). The later path
   serves an EROFS image file from the same FUSE mount; S1's EROFS writer is asked to split into a
   pure layout function and a filler.
3. **Integrity**: every chunk is BLAKE3-verified in the supervising `zbx` before it reaches the
   store or a FUSE reply; the index is anchored by a new manifest annotation
   (`org.zigbox.lazy-index`) under the pinned manifest digest; a lying source yields `EIO` and a
   coded line, never wrong bytes.
4. **Failure**: a bounded wait (`lazy_read_deadline_ms` 30 000), then `EIO`; a source down for a
   whole deadline fails fast afterwards. Bounds as in the brief's table.
5. **Sources**: local store, then peers (a `zigbox.lazy.Source` interface Zigcube's agent supplies
   in-process; Zigbox never imports Zigcube), then the registry by `Range` on **layer writer
   version 2** (fully flushed deflate at chunk boundaries, the index after the tar's end-of-archive,
   one gzip member), the default for every push. Images without an index are pulled
   whole with `W1201`.
6. **UI and state**: `--lazy` opt-in and experimental; a background fill; image records version 4
   (`partial`); a lazy run's record takes the next free run record version; gc roots partial images.
7. **Codes**: a new group `12xx` (S1 proposes `11xx`). **External programs**: none new.
8. **Prefetch** (start profiles) is later, with Zigcube's C2.

Not checked for this brief: Zigcube's `docs/swarm.md` and `docs/peer.md` (the repository could not
be attached), Ubuntu 24.04's kernel and AppArmor behaviour, and the pinned std's deflate full flush.
