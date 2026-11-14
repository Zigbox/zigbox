# Brief: S2 · Lazy start (`zbx run --lazy`)

*Decided (2026-11-14). The owner approved S2 as a goal, and all thirteen owner's calls at the end as
recommended, on 2026-11-14. Codes and bounds below are approved as those calls. Sequencing: S2 is
built in parallel with Zigbox 0.5.2; slices 1 to 4 start at once, each coding against the interfaces
this brief fixes, and slice 5 waits for all four. S1 is deferred until S2 ships. The owner ruled on
2026-11-14 that S2 ships as Zigbox 0.6.0, released on its own: Jepsen gates Zigcube's 0.6.0 (C3 to
C5), not Zigbox's.*

Release gate for Zigbox 0.6.0 (owner, 2026-11-14): two independent adversarial release reviews run
in parallel, one by an Opus session and one by a Fable session, in place of the usual two Opus
reviews. The Fable review is thorough: it identifies weaknesses, suggests improvements, and above
all suggests improvements to testing. Every MUST from either is fixed, or accepted by the owner in
writing in docs/decisions/, before the tag. This gate does not apply to 0.5.2, which keeps two Opus
reviews.

Read these first:
- `AGENTS.md`, `REVIEW.md`, `docs/STYLE.md` and `DIAGNOSTICS.md`.
- The S2 line in `docs/SPEC.md` ("Stretch milestones"): "start a large image before its files are
  local, fetching chunks on first read; demo starts a multi-GB image in seconds".
- The store this builds on: `src/store/chunks.zig` (`put_chunk`: a verified write of one chunk, in
  any order, from any source, kept in `partial/<id>/<index>` until the object assembles),
  `src/store/chunk_read.zig` (`read_chunk`, and `docs/decisions/2026-11-03-read-chunk-verification.md`),
  `src/store/trees.zig` (`put_checked`), `src/store/walk.zig`, `src/store/image_peer.zig` (a
  tree's image record from a peer), `src/store/materialize.zig` (the hardlink farm a run's overlay
  uses as its lower layer), `src/runtime/image.zig` (how a tree becomes a run's root), and
  `docs/decisions/2026-10-26-m3-store-whole-file-objects-per.md` (whole-file objects with 1 MiB
  chunk hashes: `constants.store_chunk_bytes`, `store_chunks_max`).
- The registry and push side: `src/registry/blobs.zig` (`Range` already used to resume blobs),
  `src/push/pack.zig` (one gzip layer per tree, `layer_writer_version` 1, the manifest's
  `org.zigbox.tree` and `org.zigbox.layer-writer` annotations) and `ZBX-W0551` in
  `src/image_diagnose.zig` (a pull checks the annotated tree against the tree its layers made).
- The S1 brief (`docs/briefs/S1-microvm.md` on `claude/s1-microvm-brief`, 4abcd81, not merged):
  Firecracker, an EROFS root file system image written from the store, vsock control.
- Zigcube's C2 (`docs/SPEC.md`, "C2 Swarm") and the store calls it makes
  (`src/store/zigcube_api_tests.zig`). Zigcube's own `docs/swarm.md` and `docs/peer.md` were **not**
  read for this draft (the session could not attach the repository); see open question 13.

Every earlier demo keeps passing, and a run without `--lazy` changes by no byte (output, JSON,
records): the goldens prove it.

## Goal and demo (summary; the full script is under "The demo")

`zbx run --lazy <image>` starts a container whose image is in a registry (or partly in the local
store, or on Zigcube peers) before the image's files are local. The tree's directories are fetched
first (a small index); file bytes arrive in verified 1 MiB chunks when the container first reads
them, and the rest fills in behind. In the test VM, a 3 GiB image served at 40 MiB/s prints its
first line in under 10 s while a full pull takes over 75 s, having fetched under 64 MiB.

## The shape, in one paragraph

Three layers, each testable alone. (1) **The lazy index**: what a registry must hold so a client
can fetch one chunk of one file without the whole layer; it is written by `zbx push` (a new layer
writer version) and anchored by the pinned manifest. (2) **The chunk resolver** (store side): given
`(object, chunk index)`, return verified bytes from the local store, else from a source (local
store, Zigcube peers through an interface, the registry), writing them into the store with
`put_chunk`; it owns the deadlines, the concurrency limit, and the source health. It knows nothing
of FUSE. (3) **The front end**: for namespace containers, a read-only FUSE file system served by
the `zbx` process that supervises the run, mounted as the overlay's lower layer in place of the
hardlink farm. A later VM front end reuses (2) unchanged (decision 2).

## Decisions (proposed; the supervisor and the owner confirm)

### 1. Mechanism for namespace containers: rootless FUSE, server in Zig against `/dev/fuse`

| Mechanism | Traps a first read? | Privilege and kernel | Ubuntu 24.04 (CI VM, 6.8) | Cloud container (6.18) |
| --- | --- | --- | --- | --- |
| **FUSE mounted in the run's user namespace**, `zbx` serving `/dev/fuse` | Yes, every `read` of uncached pages | None beyond a user namespace: FUSE is `FS_USERNS_MOUNT` since 4.18; `mount(2)` directly, no `fusermount3`; overlayfs with `userxattr` over a FUSE lower since 5.11 | Yes; `/dev/fuse` is 0666 (systemd's udev rule) †; the AppArmor userns rule Zigbox already handles | **Checked today:** works as an ordinary user once `/dev/fuse` is readable (it is 0600 here, no udev) |
| Overlay over a partial tree, fetch-ahead | No: a file not yet fetched reads as zeros (sparse) or is missing | None | Yes | Yes |
| `userfaultfd` | Only page faults on memory the server registered, never another process's `read` of a file | `vm.unprivileged_userfaultfd` or `UFFD_USER_MODE_ONLY` (5.11) | Partly | Partly |
| EROFS over fscache on demand (`cachefiles` ondemand) | Yes | `CAP_SYS_ADMIN` in the initial namespace for `/dev/cachefiles`; EROFS is not mountable in a user namespace; 5.19 and `CONFIG_CACHEFILES_ONDEMAND` | Config unchecked †; needs root regardless | Needs root |
| fanotify pre-content events (`FAN_PRE_ACCESS`) | Yes | 6.14+, `CAP_SYS_ADMIN` in the initial namespace | No (6.8) | Needs root |
| `ublk` (unprivileged mode) + a block file system | Yes | `ublk_drv` and an administrator's udev rule; a block file system cannot be mounted in a user namespace | No | No |
| FUSE passthrough (6.9) | Optimization only | `CAP_SYS_ADMIN` in the initial namespace for backing files | No (6.8) | Needs root |

Recommendation: **FUSE**. It is the only mechanism that traps a first read without privileges, which
Zigbox's thirty-second, rootless rule demands. Fetch-ahead without a trap is rejected outright: it
can hand a process zeros in place of a file's bytes, which breaks the integrity rule below. The
others need root or an administrator.

**The probe run today** (in the Claude cloud container, kernel 6.18, as the ordinary user `tester`,
with the C `fuse-overlayfs` 1.13 from apt as a stand-in server; nothing of it is in the repository):
`unshare -Urm` then a FUSE mount with `mount(2)` (no `fusermount3` installed) succeeded, with
`user_id=0,group_id=0,allow_other` in `mountinfo`; a file read back through it; a kernel overlay
(`userxattr`) with the FUSE mount as its lower mounted, read, copied up on write and created files
in the upper. With a full subordinate map (`newuidmap`, 65536 ids), a process at uid 1000 inside read
the FUSE mount with `allow_other`. Not checked: Ubuntu 24.04's stock 6.8 kernel and its AppArmor
policy (slice 1), and a server written in Zig.

**How it is built.**
- The single-threaded setup child (AGENTS.md) opens `/dev/fuse` inside the run's user and mount
  namespaces, mounts `fuse` read-only (`fd=N,rootmode=40000,user_id=0,group_id=0,allow_other,
  default_permissions`, `nosuid,nodev`), passes the descriptor to the parent over the existing
  socket pair (`SCM_RIGHTS`), **waits for the parent to say `FUSE_INIT` is answered**, and only
  then mounts the overlay whose lower is the FUSE mount (the overlay mount looks up the lower's root,
  which would deadlock against a parent that is not serving yet).
- The parent, the `zbx` that supervises the run (the foreground `zbx run`, or the detached run's
  supervisor), serves the descriptor with a fixed pool of threads (`lazy_fuse_threads`); the
  thread-pool rule allows threads in the parent. The server is outside the container's pid
  namespace and cgroup, so the container can neither signal it nor freeze it, and its memory is not
  the container's. It never touches the mount it serves.
- Read-only operations only: `INIT`, `LOOKUP`, `FORGET`/`BATCH_FORGET`, `GETATTR`, `READLINK`,
  `OPEN`/`OPENDIR` (with `FOPEN_KEEP_CACHE` and `FOPEN_CACHE_DIR`: the tree is immutable, so the
  kernel's page cache serves every read after the first at native speed), `READ`, `READDIRPLUS`,
  `GETXATTR`/`LISTXATTR` (the tree's own attributes; `user.overlay.*` answered as absent),
  `STATFS`, `RELEASE`, `INTERRUPT`. Anything else is `EROFS` or `ENOSYS`. Long timeouts on entries
  and attributes (the tree never changes).
- Node identity: one FUSE node per **object**, so a file's hard links share an inode and `st_nlink`
  is right, as in the farm. Owners, modes and attributes are the tree's, in the run namespace's ids.
- The kernel ABI structs (`linux/fuse.h`, protocol 7.31 or later: `FUSE_MAX_PAGES` for 1 MiB reads)
  are written in Zig in one file, with comptime size asserts; requests are parsed with bounds checks
  and fuzzed.
- End of the run: the container's mount namespace goes away, the kernel ends the connection, the
  server's read returns `ENODEV` and the threads stop. If the server dies first, readers get
  `ENOTCONN`; the run already ends when its supervisor dies (as today), and the record says why.

### 2. Mechanism for S1 microVMs: not in S2; one resolver ready for a later VM front end

Options weighed:
- **vhost-user-blk.** Recent Firecracker releases have a vhost-user block device (a developer
  preview when last known †; S1 has not pinned its version yet, so it is unchecked). It needs guest
  memory shared through a memfd, and a vhost-user server in Zig (vrings, the vhost-user protocol): a
  second security-relevant protocol.
- **A virtio-fs share.** Firecracker has no virtio-fs (S1 brief). Rejected.
- **An EROFS image file served lazily on the same FUSE mount** (the preferred later path). S1 writes
  an EROFS image of the tree and gives it to Firecracker as a plain backing file. Laid out
  uncompressed, every block of that image is either metadata (computed from the tree, which the
  index gives) or a byte range of one object. So the FUSE server can show, beside the tree, one
  file `rootfs.erofs` whose blocks it computes or resolves through the same chunk resolver.
  Firecracker reads its drive with plain `pread`, inside the run's mount namespace where the FUSE
  mount is; it needs no Firecracker feature at all, and a fetch failure is an `EIO` on the guest's
  block device, which EROFS passes to the reading process.
- **Fetch the whole image first.** What S1 does anyway.

Recommendation: **S2 covers namespace containers only; `--lazy` with `--isolation vm` is refused
(`E1208`) and a VM run fetches the whole image first, as S1 specifies.** The later VM front end is
the EROFS-image-on-FUSE design, not vhost-user. To keep that open at no cost now, S1's EROFS writer
(its slice 2) should be split into a pure layout function (tree → a list of extents, each metadata
bytes or `(object, offset, length)`) and a writer that fills the extents; S2 asks this of S1's
implementer and records it in `docs/decisions/` when S1 slice 2 starts. Reasons: S1 is not merged,
its nested-KVM probe has not run, and the demo of S2 needs only one front end.

### 3. Integrity: verified before any byte reaches the container

- **What anchors what.** `zbx.lock` pins the manifest digest (M4); the manifest carries
  `org.zigbox.tree` (the tree digest) and, new, `org.zigbox.lazy-index` (the index's offset and
  length in the layer blob and its BLAKE3). The index carries the tree's directory objects, which
  are checked top-down from the tree digest with `trees.put_checked`, and each file's chunk hash list,
  which `chunks.Wanted` checks against the object id. Offsets in the index are hints, never trusted:
  a wrong offset yields bytes that fail their hash.
- **Who verifies.** The chunk resolver, in the supervising `zbx` process (outside the container),
  hashes every chunk with BLAKE3 against its listed hash before it is written to the store
  (`put_chunk` already refuses a mismatch) and before any byte of it is copied into a FUSE reply.
  Bytes read back from the store are checked again (`read_chunk`'s rule) the first time a run serves
  them: the pair assertion. A FUSE reply is built only from a buffer whose hash matched in this
  process; on any error the reply is `EIO` and carries no data.
- **The trust gate** (M8) runs on the tree digest before the container starts, as today: the tree
  is known from the index before any file byte.
- **A lying registry** (wrong index bytes): `E1202` before start, nothing written. Wrong chunk bytes:
  that source is marked bad for that object for the rest of the run, the next source is tried, and
  if none is left the read is `EIO` and `zbx` prints `W1202` once per source (naming it and the
  file). Never wrong bytes; at worst, denial within the read deadline.
- **A lying peer**: the same, and the resolver reports it through the source interface (C2's "a peer
  serving a corrupted chunk is detected by hash, skipped and reported").
- **What a lazy run does not check**: that the layer's tar would unpack to the annotated tree. A full
  `zbx pull` of the same manifest still does (`W0551`). The pusher is the authority for both; the
  manifest digest commits to both. Recorded in `docs/demos/s2.md`.

### 4. Failure semantics: a bounded wait, then `EIO`

A read of a chunk that is not local waits while the resolver tries sources in order, each attempt
bounded by `lazy_attempt_timeout_ms`, the whole read bounded by `lazy_read_deadline_ms`; then the
reader gets `EIO`. Immediate `EIO` was rejected: a registry's normal latency tail would break
start-up. An unbounded wait was rejected: a cut network would hang the container forever in
uninterruptible-looking reads (FUSE waits are killable, but nothing would end them). After a source
has failed a whole deadline it is marked down; reads that need only it fail after
`lazy_down_fail_ms` instead of the full deadline, and one probe request per `lazy_down_probe_ms`
brings it back. Nothing is poisoned: a later read of the same chunk tries again.

The reading process sees only `EIO`. `zbx` explains it: one coded line per file on stderr (or in
the detached run's log), at most `lazy_errors_shown_max` per run, then one summary line.

**Bounds (approved by the owner 2026-11-14).** In `constants.zig`, each with comptime asserts:

| Constant | Value | Why |
| --- | --- | --- |
| `lazy_attempt_timeout_ms` | 10 000 | One request to one source for at most 8 MiB |
| `lazy_read_deadline_ms` | 30 000 | Matches common client timeouts; the demo asserts `EIO` within it plus 5 s |
| `lazy_down_fail_ms` / `lazy_down_probe_ms` | 2 000 / 5 000 | A cut network fails fast after the first deadline |
| `lazy_fetches_max` | 8 | Concurrent on-demand requests across sources |
| `lazy_fill_fetches_max` | 2 | Background fill; on-demand reads always go first |
| `lazy_readahead_chunks` | 4 | After two sequential chunk reads of one file, fetch up to 4 more |
| `lazy_range_bytes_max` | 8 MiB | Neighbouring chunks coalesced into one `Range` request |
| `lazy_index_bytes_max` | 64 MiB | A 4 GiB file's list is about 200 KiB; 64 MiB is far beyond any real image |
| `lazy_nodes_max` | 262 144 | The FUSE node table, fixed at start (about 24 MiB); a tree with more entries is refused for lazy (`E1207`) and pulled whole |
| `lazy_fuse_threads` | 4 | Server threads reading `/dev/fuse` |
| `lazy_store_free_bytes_min` | 1 GiB | Below it the fill stops; below a quarter of it on-demand fetches fail (`E1206`) |
| `lazy_errors_shown_max` | 16 | Lines per run before the summary |

Memory is fixed at start: `lazy_fetches_max + lazy_fill_fetches_max` buffers of
`lazy_range_bytes_max` plus a chunk each, and the node table: under 128 MiB per lazy run.

### 5. Fetch sources and how Zigcube plugs in

Order for each chunk: **the local store** (the object is whole, or the chunk is in
`partial/<id>/<index>`, from this image or any other: a new version of an image needs only what
changed), **then peers** (only when a library caller supplied a peer source), **then the registry**.
The registry source reads the chunk's compressed range from the layer blob (below).

The interface, exported from the `zigbox` module as `zigbox.lazy`:

```zig
pub const Source = struct {
    context: *anyopaque,
    name: []const u8, // for messages: "registry", "peer 10.0.0.3"
    /// Fills `out` with chunk `index` of object `id` (unverified), or fails. Must return
    /// within `deadline_ms`; may be called from several resolver threads at once.
    fetch: *const fn (context: *anyopaque, id: Digest, index: u32, out: []u8,
        deadline_ms: u32) FetchError!usize,
    /// Told when bytes from this source failed their hash (C2 reports the peer).
    lied: *const fn (context: *anyopaque, id: Digest, index: u32) void,
};
```

Zigcube's agent already runs each container through the `zigbox` library
(`docs/decisions/2026-10-26-m2-zigcubes-agent-runs-each-container.md`), so it passes its swarm's
peer fetch as one `Source` in `StartOptions.lazy_sources`; Zigbox never imports Zigcube and never
talks a peer protocol. The standalone `zbx` CLI has the store and the registry only (no
`ZBX_PEERS` in S2). Verification is never the source's job: the resolver checks whatever it gets.

**The registry format.** A registry holds gzip tar layers, which cannot be read from the middle. So
`zbx push` gains **layer writer version 2**: the same tar, but the deflate stream is fully flushed
(`Z_FULL_FLUSH`, a byte-aligned point with no back-references across it) before each file chunk, so
one chunk's bytes can be inflated from a known compressed offset. It stays one gzip member, so every
gzip reader (Docker, containerd, Podman, older `zbx`) reads it unchanged. After the tar's
end-of-archive blocks, inside the same stream, comes the **lazy index**: the tree's directory
objects, each file's chunk hashes, and for each chunk its compressed offset and length. Tar readers
stop at end-of-archive; the config's `diff_id` is the hash of the whole uncompressed stream, as the
OCI spec defines it. The layer descriptor gets `org.zigbox.lazy-index`. The size cost is a few
bytes per flush point (under 0.1 % at 1 MiB chunks). Two things slice 2 checks first (†): that the
pinned std's deflate compressor can flush fully (if not, separate gzip members, and M4's reader
must then accept multi-member gzip, which older `zbx` releases may not); and that M4's own tar
reader accepts bytes after end-of-archive (if not, it is fixed, and older releases cannot pull
version 2 layers: open question 3).

Images without the annotation (everything not pushed by `zbx` ≥ S2, for example Docker Hub's)
cannot start lazily: `zbx run --lazy` prints `W1201` and pulls the whole image as today. Reading
eStargz or SOCI indexes, or converting images on the fly, is a non-goal.

### 6. What `zbx run` shows, and how records, gc and `ps` treat a partial image

- **Opt-in in S2**: `zbx run --lazy` (and `StartOptions.lazy` for library callers), shipped
  experimental as M9 and M10 were. Making it the default is a later owner decision, once the demo
  has been green for a release.
- **On a terminal**, while starting: one line that rewrites in place, `lazy: index 2.1 MiB, starting
  (3.0 GiB not yet local)`; without a terminal, the same line once. At exit (foreground) one summary:
  `lazy: 41 MiB fetched on first read, 1.2 GiB in the background; image 38% local`. No change
  without `--lazy`.
- **Background fill.** While the container runs, the resolver fetches the rest of the image in
  tree order at `lazy_fill_fetches_max`, always behind on-demand reads, so the image becomes whole
  and the next run uses the farm as any other. The fill stops when the run ends; chunks kept in
  `partial/` are not fetched again (put_chunk's existing contract), and `zbx pull <image>` completes
  it.
- **Image records**: a lazy start writes the image record (as a pull does) with a new field
  `partial: true` until every object is whole (image record version 4). `zbx images` shows
  `partial 38%`; `zbx run` without `--lazy` on a partial image completes it first, as a pull.
- **Run records**: a lazy run's record gains `lazy` (sources used, bytes fetched on demand and in the
  background, errors), written as the next free record version only for lazy runs (11 if S1 has not
  claimed it, else 12), the M10 precedent; others write exactly what they do now.
- **`zbx ps`**: the text table is unchanged (its goldens stay); JSON and `zbx inspect` gain
  `lazy: {local_percent, fetched_bytes, errors}`.
- **gc**: a partial image's record roots its tree like any other. The walk of a rooted partial tree
  keeps the objects and the `partial/<id>/` chunks it finds and does not count missing objects as
  damage; a running lazy container holds its image (the existing holders). `partial/` chunks of
  objects no rooted tree names are swept as today. `zbx store verify` reports a partial image as
  partial, not damaged.

### 7. Prefetch (a start profile): later, not S2

Record-and-replay of the start-up read set helps a **first** start on a host that has never run the
image; on the host that ran it, the background fill has already made it local. So its value is for
fleets, where node B starts what node A profiled, and that belongs with Zigcube's C2 (the profile
travels with the peer's summary). Recommendation: out of S2. The index format reserves an optional
section for a chunk order so a profile can be added without a new layer writer version; readahead
and range coalescing are S2's only prefetch.

## Diagnostics (approved by the owner 2026-11-14)

`src/diag/codes.zig` ends at `10xx` (`E1017`, `W1003`), and S1 proposes `11xx`. Proposal: a new
group **`12xx`, lazy start**, added to `DIAGNOSTICS.md` in both repos when S2 starts. If S1's group
moves, S2 takes the next free one.

- `E1201` lazy start is not possible on this host: `/dev/fuse` missing or not openable, or the kernel
  refused the FUSE mount in the user namespace (names which; fix: the `fuse` udev rule, or run without
  `--lazy`). `zbx doctor` gains the same check as a line in its runtime section.
- `W1201` the image has no lazy index (not pushed by a `zbx` with layer writer 2): pulling it whole.
- `E1202` the lazy index was refused: its hash is not the manifest's, it exceeds a bound, or its
  tree does not check against `org.zigbox.tree` (blame: the registry or the pusher).
- `W1202` a source sent bytes that do not match a chunk's hash; another source was used (names the
  source, the file and the chunk).
- `E1203` a chunk could not be fetched within `lazy_read_deadline_ms`: the reading process got `EIO`
  (names the file, the chunk, each source tried and why).
- `E1204` the lazy server ended before the container did (blame: `zbx` was killed, or our bug).
- `E1205` reserved for the VM front end (not used in S2).
- `E1206` the store's disk is too full to keep fetched chunks.
- `E1207` the image is too large for lazy start (`lazy_nodes_max`, `lazy_index_bytes_max`).
- `E1208` `--lazy` with a flag it does not support (`--isolation vm`, `--rootfs`), or on macOS.

Each with `explain` text, goldens, and the errors site regenerated (`zig build errors-site`).

## Tests

- **Simulation.** The resolver runs against the host model with seeded sources that are slow, cut,
  lying (wrong bytes, wrong lengths, wrong offsets), and a store that fills up or is gc'd mid-run.
  `sim_run`-style checks: no byte leaves the resolver unverified (asserted at the copy into a reply),
  every failed read ends within its deadline with a coded line, a lying source never changes a
  chunk in the store, and a crash at every write point leaves the store unchanged or validly updated
  (M3's rule).
- **Fuzzers.** `lazy_index` (random trees through the writer and an independent reader; random bytes
  into the reader), `fuse_request` (random requests into the parser and the node table; the node
  table's invariants after every request), and the pack fuzzer extended to layer writer 2 (the tar
  read back by M4's reader is the same tree; inflating from each recorded offset gives the chunk).
- **Goldens**: every new error line, `zbx run --help`, the doctor line, a lazy run's record and JSON,
  the progress and summary lines, the pack goldens of layer writer 2 (version 1's stay).
- **A real-kernel test** of the FUSE server that skips cleanly when `/dev/fuse` cannot be opened.

## The demo: `zig build demo-s2`

In the test VM, as the ordinary user. The registry runs **on the runner** (the harness, in Zig: the
push registry fixture made disk-backed, with `Range`, a bandwidth limit and fault switches), reached
from the guest over QEMU's user network; a 3 GiB image does not fit the guest's 2 GiB of memory, and
the guest's disk holds the store. The harness grows the guest overlay if it needs more space (†).

**The fixture image** `lazy:3g`, generated deterministically from a fixed seed on the runner and
pushed with the guest's `zbx push` (layer writer 2), about 3.0 GiB: `/models/weights.bin` (2 GiB of
incompressible bytes), 20 000 small files of `/lib/site` (about 400 MiB), `/data/a.bin` …
`/data/f.bin` (100 MiB each), and `/app/start`, a shell script that reads `/app/config`, hashes the
16 MiB `/app/boot.bin` and the first 4 MiB of `weights.bin`, and prints `ready <sha256>`. Its
expected hashes are computed when the fixture is made. A second image `lazy:3g-v2` differs only in
`/app/boot.bin`.

**Steps and what is asserted** (registry throttled to 40 MiB/s throughout):

1. `zbx doctor` shows FUSE usable.
2. **Lazy start.** `zbx run --lazy <registry>/lazy:3g -- /app/start` prints `ready <expected sha>`.
   Assert: under **10 s** from the command to that line (target and recorded: about 3 s); bytes the
   registry served before the line under **64 MiB** (the registry's counter and `zbx`'s summary line
   agree to the byte). The summary line is printed.
3. **Full pull, for comparison**, into a second store (`XDG_DATA_HOME` of another directory):
   `zbx pull` of the same image takes over **75 s** at the throttle. Assert the lazy start took under
   a quarter of it; record both.
4. **Background fill and gc.** `zbx run -d --lazy --name fill <image> -- sleep 600`; `zbx ps
   --output json` shows `local_percent` below 100; `zbx store gc` plans no removal of the image's
   chunks; the harness waits (Monitor-style, bounded at 300 s) until `local_percent` is 100; `zbx
   stop fill`; `zbx store verify` is clean, and a run without `--lazy` uses the farm (no FUSE mount in
   its `mountinfo`).
5. **The local store as a source.** In a fresh store holding `lazy:3g` whole, `zbx run --lazy
   lazy:3g-v2 -- /app/start` fetches under **20 MiB** from the registry (the index and `boot.bin`).
6. **A corrupt chunk.** The registry flips one byte inside the compressed range of chunk 3 of
   `/data/c.bin`. `zbx run --lazy ... -- sha256sum /data/c.bin` exits non-zero and `sha256sum` says
   `Input/output error`; `zbx` prints `W1202` naming the registry and the file, then `E1203`; the
   store holds no `partial/` chunk 3 of that object. With the registry honest again, the same command
   prints the expected hash: nothing was poisoned.
7. **The network cut mid-run.** `zbx run -d --lazy --name cut ... -- sleep 600`, then `zbx exec cut
   -- cat /app/config` works; the harness stops the registry; `zbx exec cut -- cat /data/e.bin`
   fails with `EIO` within **35 s** (`lazy_read_deadline_ms` plus 5 s) and `zbx logs cut` shows
   `E1203`; a second read of another missing file fails within **7 s** (the source is down);
   `cat /app/config` still works (local); the container is still running. The registry comes back;
   `cat /data/e.bin` then prints the expected hash within 10 s.
8. **Refusals and fallbacks**, one coded line each: `--lazy` on `alpine:3.20` from the mirror (no
   index: `W1201`, then it runs, pulled whole); `--lazy --rootfs ...` (`E1208`); `--lazy` with
   `/dev/fuse` unreadable (the harness runs it as a second user whose `/dev/fuse` access is denied by
   a mode change inside the VM: `E1201`).
9. **Upgrade.** Records written by the release before S2 are read unchanged, and a lazy run's record
   is the existing "newer version" refusal for the old release's `zbx ps`.

`docs/demos/s2.md` records a run: both times, bytes by source, and the cuts.

## Slices (commit and push about every 10 minutes; open the PR only when ready)

1. **Probe.** A throwaway FUSE server in Zig (no libc: the ABI structs, `INIT`, `LOOKUP`, `GETATTR`,
   `OPEN`, `READ`, `READDIRPLUS`, an `EIO` reply), and a `vm/s2-probe` run of a harness step
   `demo-s2-probe` that, in the test VM as the ordinary user with a full subordinate map: mounts it in
   a user and mount namespace with `allow_other`, stacks the overlay (`userxattr`) on it, reads
   through the overlay as uid 0 and as uid 1000 inside, copies up a write, sees `EIO` reach `cat`,
   kills the server and sees `ENOTCONN`, and reports the kernel, `/dev/fuse`'s mode, AppArmor's
   userns setting and the 1 MiB read latency. Ends with the run link. `vm.yml` cannot run it today
   (its `case` lists the demos), so the slice adds `s2` there. *Haiku:* the `vm.yml` case.
2. **Layer writer 2 and the lazy index.** The flushed deflate stream, the index after end-of-archive,
   the annotation, the index reader and its checks, M4's reader taking version 2 layers, the fuzzers.
   Checkable anywhere: a version 2 layer pulls to the same tree as version 1; every chunk inflates
   from its offset. *Haiku:* the pack goldens.
3. **The chunk resolver.** Sources (store, registry range, the `Source` interface), verification,
   `put_chunk`, deadlines, the down state, concurrency, readahead and coalescing, the fill; the
   simulation and its faults. No FUSE yet.
4. **The FUSE server.** ABI, node table, the operations, the mount in the setup child and the
   descriptor handed to the parent, serving threads, teardown; the request fuzzer; the real-kernel
   test. Ends with a `vm/s2-*` run where `zbx run --lazy` reads an image from the store's own objects
   (no registry).
5. **Run integration.** `--lazy`, the fallbacks, the progress and summary lines, image and run
   records, `ps` and `inspect` JSON, gc, verify, holders, the codes, the doctor line, the Zigcube
   interface in `zigbox.lazy` with its surface test. *Haiku:* errors-site regeneration, `--help`
   goldens.
6. **`demo-s2`.** The disk-backed throttled registry with faults in the harness, the fixture image
   generator, the whole script, `docs/demos/s2.md`, the path rule in `.github/ci-changes.sh`.
   *Haiku:* the path rule, the README and site rows.

## Done means

`zig build check` PASS on the final commit, `demo-s2` green on a `vm/s2-*` run (link it), every
earlier demo green (`vm/all-*`), the release binary still under its size limit, the PR open.

## Non-goals and interactions

- **Non-goals:** lazy start for `--isolation vm` (decision 2), for `zbx build` steps, or on macOS;
  start profiles and their replay (decision 7); reading eStargz, SOCI or Nydus images, or converting
  an image on the fly; a peer protocol or peer discovery in Zigbox (Zigcube's job); lazy `--rootfs`;
  writable lazy layers (the upper stays a normal directory); FUSE passthrough or io_uring for FUSE;
  a separate chunk cache outside the store; content-defined chunking.
- **M9 builds.** A build step's base (`FROM`) must be whole: the builder's inputs are hashed and
  hardlinked. `zbx build` and `zbx import` complete a partial base image first, as a pull. Lazy
  builds are a non-goal.
- **The Mac.** The macOS `zbx` forwards `run` to the Linux `zbx` in its VM, whose pinned kernel
  (`vm/kernel/config-arm64`) would need `CONFIG_FUSE_FS`, a change to the pinned kernel and its
  digest. Recommendation: `--lazy` on macOS is refused (`E1208`) in S2; enabling it is a later,
  small follow-up (open question 11).
- **gc.** As in decision 6: partial images are rooted, their present objects and chunks kept, the
  missing ones not damage.

## Owner's calls (approved 2026-11-14, as recommended)

1. **Mechanism for namespace containers.** *Recommendation:* rootless FUSE with a server in Zig on
   `/dev/fuse`, mounted by `mount(2)` in the run's namespaces; no `fusermount3`.
2. **MicroVMs.** *Recommendation:* not in S2 (`E1208`); later through an EROFS image file served by
   the same FUSE server, which asks S1's EROFS writer to be split into layout and fill now.
3. **Registry format.** Layer writer 2 (fully flushed deflate, index after end-of-archive, one gzip
   member). *Recommendation:* the default for every `zbx push`, so lazy-capable images are the norm;
   a re-push of an unchanged tree gets a new manifest digest once. If slice 2 finds that older
   `zbx` releases cannot read version 2 layers, it comes back to the owner before shipping.
4. **Images without an index.** *Recommendation:* fall back to a whole pull with `W1201`; no
   eStargz/SOCI support and no conversion.
5. **Opt-in or default.** *Recommendation:* `--lazy` opt-in, experimental, in S2; the default later.
6. **Failure semantics.** *Recommendation:* a bounded wait, then `EIO`, with a fast fail once a source
   is down, as in decision 4.
7. **Codes.** *Recommendation:* a new group `12xx`, lazy start (S1 has `11xx`), `E1201`–`E1208`,
   `W1201`–`W1202`, in both repos.
8. **Bounds.** *Recommendation:* the table in decision 4.
9. **External programs.** *Recommendation:* none new. FUSE is in the kernel and `zbx` mounts it
   itself; no `fusermount3`, no libfuse. The test VM needs nothing beyond what Ubuntu 24.04 ships.
10. **Prefetch.** *Recommendation:* start profiles later, with Zigcube's C2; S2 keeps readahead and
    coalescing only, and reserves room in the index.
11. **The Mac.** *Recommendation:* refused in S2; a follow-up enables `CONFIG_FUSE_FS` in the guest
    kernel.
12. **Record versions.** *Recommendation:* image records go to version 4 (`partial`); run records take
    the next free version for lazy runs only.
13. **Zigcube's side.** The `Source` interface was designed from Zigbox's C2 calls without reading
    Zigcube's `docs/swarm.md` and `docs/peer.md`. *Recommendation:* Zigcube's supervisor checks it
    against them before slice 3, and the result is recorded in `docs/decisions/`.

† Checked in the slice named, and corrected here if wrong.
