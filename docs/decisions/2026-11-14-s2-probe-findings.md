# S2 probe: rootless FUSE under a userxattr overlay works on Ubuntu 24.04; READ sizes vary

*Decided 2026-11-14, by S2 slice 1 (the probe), at the supervisor's request. Corrected the same
day, before the slice merged, after its two reviews: the first version said every read reaches the
server as 128 KiB READs, which is false.*

The slice 1 probe (`zig build demo-s2-probe`; the guest script is in
`src/testing/vm/main_s2_probe.zig`, the throwaway server in `src/testing/vm/s2_probe/`) passed on
CI's KVM runner on 2026-11-14:
[run 43626834366](https://github.com/Zigbox/zigbox/actions/runs/43626834366), and again after the review fixes,
[run 43636460487](https://github.com/Zigbox/zigbox/actions/runs/43636460487). It confirms item 1 of
[2026-11-14-s2-lazy-start-brief.md](2026-11-14-s2-lazy-start-brief.md) on Ubuntu 24.04 (kernel
6.8.0, FUSE 7.39, `/dev/fuse` 0666). As user `demo` in a user and mount namespace with the full
subordinate id map, a no-libc server mounted FUSE with `mount(2)`, a `userxattr` overlay stacked
on it, and reads worked as uid 0 and uid 1000. Copy-up worked. An `EIO` reply reached `cat`. After
the server was killed, reads got `ENOTCONN`. Run detail is in [docs/demos/s2.md](../demos/s2.md).

Four points are recorded:

1. **A READ's size and offset are the reader's, bounded by `max_pages`.** The server negotiates
   `max_pages` 256 (1 MiB), and any READ from one page up to that is normal. What decides the size
   is how the file is read, not the server:

   - buffered `read(2)`, e.g. `cat` (VM, 6.8; also 6.18): 128 KiB, the default readahead window
     (the kernel's INIT offers `max_readahead` 131072);
   - after `posix_fadvise(SEQUENTIAL)` (6.18): 256 KiB, because the overlay passes the advice to
     the FUSE file, which doubles its readahead window;
   - with the bdi's `read_ahead_kb` raised to 1024 (6.18, set as kuid 0, so not rootless): 1 MiB;
   - a small `pread` (6.18): 4 KiB, at the reader's unaligned offset;
   - `O_DIRECT` (VM, 6.8: `dd iflag=direct bs=1M` on the FUSE mount; 6.18: through the overlay):
     1 MiB, and on 6.18 at offset 512 KiB.

   The VM figures are from the probe runs above. The 6.18 figures were measured by the slice's
   review in the Claude Code cloud container (kernel 6.18.44, FUSE 7.45), not in the VM; the first
   version of this file stated "the same on 6.18" without saying so.

   So a READ may start anywhere and may span two 1 MiB chunks. This changes nothing in the design
   (chunks stay 1 MiB, `FUSE_MAX_PAGES` stays), but the server (slice 2) must:
   - accept any READ size up to `max_pages` and any offset, and answer a READ that spans two chunks
     from both, fetching and verifying each chunk once whatever number of READs it serves;
   - detect sequential access from offsets (a READ starting where the previous one on that file
     ended), never from READ sizes, when it decides on readahead (`lazy_readahead_chunks`).

2. **`FUSE_MAX_PAGES` came in protocol 7.28, not 7.31.** The brief's line 100 says "7.31 or later:
   `FUSE_MAX_PAGES`". 7.28 brought `FUSE_MAX_PAGES`; 7.31 brought `map_alignment` (DAX). The probe
   still speaks 7.31, the brief's floor, which Ubuntu 24.04 (7.39) meets; slice 4 may lower the
   floor to 7.28 if it needs nothing newer.

3. **The page cache does not outlive the server.** After `kill -9` of the server, a new open of
   `big.bin`, every page of it cached and opened with `FOPEN_KEEP_CACHE`, fails with `ENOTCONN`
   ("Transport endpoint is not connected"): the open itself goes to the dead connection. This was
   measured by the review on 6.18 and recorded in the VM by run 43636460487. A descriptor opened
   before the kill still read all 16 MiB from the cache in that run, but closing it failed with
   `ENOTCONN` (the FLUSH goes to the dead connection). Slice 4's "if the server dies first"
   handling must not assume that cached files stay readable: only already-open descriptors read,
   and only what is cached.

4. **AppArmor's userns restriction was off.** The probe ran with
   `kernel.apparmor_restrict_unprivileged_userns=0`, which the harness's provisioning sets for
   every Zigbox demo; Ubuntu ships 1. The shipped value was not tested. S2 needs nothing beyond
   the user namespace `zbx` already needs, so it adds no new requirement here.
