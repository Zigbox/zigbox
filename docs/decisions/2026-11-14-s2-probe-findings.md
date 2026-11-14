# S2 probe: FUSE under a userxattr overlay works rootless on Ubuntu 24.04; buffered READs are 128 KiB

*Decided 2026-11-14, by S2 slice 1 (the probe), at the supervisor's request.*

The slice 1 probe (`zig build demo-s2-probe`; the guest script is in
`src/testing/vm/main_s2_probe.zig`, the throwaway server in `src/testing/vm/s2_probe/`) passed on
CI's KVM runner on 2026-11-14: [run 43626834366](https://github.com/Zigbox/zigbox/actions/runs/43626834366).
It confirms item 1 of [2026-11-14-s2-lazy-start-brief.md](2026-11-14-s2-lazy-start-brief.md) on
Ubuntu 24.04 (kernel 6.8.0, FUSE 7.39, `/dev/fuse` 0666). As user `demo` in a user and mount
namespace with the full subordinate id map, a no-libc server mounted FUSE with `mount(2)`, a
`userxattr` overlay stacked on it, and reads worked as uid 0 and uid 1000. Copy-up worked. An `EIO`
reply reached `cat`. After the server was killed, reads got `ENOTCONN`. Run detail is in
[docs/demos/s2.md](../demos/s2.md).

Two points are recorded:

1. **Brief line 100 is overtaken: buffered reads do not arrive as 1 MiB READs.** The line reads
   "`FUSE_MAX_PAGES` for 1 MiB reads". Every read through the overlay is a buffered read, and each
   one reaches the server as 128 KiB READ requests: 16 MiB arrived as 128 requests. The kernel's
   INIT offers `max_readahead` 131072, and the server may only lower that value. The bdi's
   `read_ahead_kb` could raise it, but changing it needs root in the initial namespace, so that is
   not rootless. A 1 MiB READ arrives only for `O_DIRECT` (`dd iflag=direct bs=1M` gave two of
   them). The behaviour is the same on kernel 6.18 (FUSE 7.45).

   This changes nothing in the design: chunks stay 1 MiB and `FUSE_MAX_PAGES` stays. It does mean
   the server (slice 2) must:
   - fetch and verify a chunk once, and answer its eight 128 KiB READs from that one chunk;
   - count consecutive 128 KiB READs as sequential when it decides on readahead
     (`lazy_readahead_chunks`).

2. **AppArmor's userns restriction was off.** The probe ran with
   `kernel.apparmor_restrict_unprivileged_userns=0`, which the harness's provisioning sets for
   every Zigbox demo; Ubuntu ships 1. The shipped value was not tested. S2 needs nothing beyond
   the user namespace `zbx` already needs, so it adds no new requirement here.
