# CI speed-ups: shared Zig cache for VM demos, per-job timeouts

Date: 2026-11-11. Owner-approved.

## Decision

1. Every VM demo job (demo-m0 to demo-m8, demo-m6b, demo-m8-packages) now runs
   `.github/actions/zig-cache` (name `demo-<id>`) after `setup-zig`, before the VM image caches.
   Same key as the other Zig jobs: build.zig, build.zig.zon, src/**, with the same restore-keys
   prefix, the same 1500 MB cap and the same cleanup of `zbx-vm` and `zbx-old-tree-*`.
2. Every job has `timeout-minutes`, about 2 to 3 times its duration on main run 43014021558.

## Old-release binaries: premise corrected

The old binaries the upgrade demos use are not downloaded and have no checksum. `build_old.zig`
builds each from a pinned commit or tag in a git worktree (`.zig-cache/zbx-old-tree-<rev>`,
`zig build release`); `build.zig` passes the result as `--old-zbx`. The pins live in
`src/testing/vm/old_release.zon`. So there is nothing to checksum, and no verification was
weakened or added. The restored `.zig-cache/o` makes the build step a content-addressed cache
hit if its inputs hash the same; the worktree directory is deleted after restore, so whether
it hits is checked in the PR run (see the PR report). If it does not, the follow-up is an
explicit cache of the built binary keyed on the pinned rev.

## Timeouts (main run 43014021558, seconds -> minutes)

changes 5s -> 5; build 150 -> 10; tidy 108 -> 10; test 468 -> 20; errors-site 17 -> 5;
fuzz 532 -> 25; dbus-live 134 -> 10; m0 356 -> 15; m1 270 -> 15; m2 369 -> 20; m3 375 -> 20;
m4 331 -> 20; m5 431 -> 25; m6 469 -> 25; m6b 377 -> 20; m7 664 -> 30; m8 433 -> 25;
m8-packages 552 -> 30. Cold-cache runs are slower than these durations by under a minute for
the Zig part, inside the margin. Previous demo limits were 30 to 60.

## Cache budget (10 GB per repository, LRU eviction)

A zig-cache entry is about 80 to 150 MB compressed (the build job saves about 100 MB for 293 MB
on disk) and at most 1500 MB uncompressed by the cap. 17 Zig jobs give about 2 to 2.5 GB per
source revision. Fixed entries: the Ubuntu image about 0.6 GB, Alpine rootfs, m4 blobs, the
m8-packages guests (about 1 to 2 GB) and the Zig toolchain 83 MB, so about 3 GB. Expected total
with three live revisions: about 9 GB at worst; older revisions are evicted first, and a miss only
costs a cold build. Cold fallback is unchanged, so the worst case is today's behaviour.

## Not changed

What any job tests; `.github/ci-changes.sh` (so no table-test row); nothing under src/ or
build.zig (so `zig build check` was not run).
