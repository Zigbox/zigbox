# CI speed-ups: per-job timeouts (VM cache sharing dropped)

Date: 2026-11-11, amended 2026-11-12. Supervisor decision: PR #95 is cut down to the timeouts.

## Decision

1. Every job has `timeout-minutes`, about 2 to 3 times its duration on a green main run.
2. Dropped: sharing the Zig cache with the VM demo jobs (a `.github/actions/zig-cache` step in each
   demo job). The first version of this PR added it. The supervisor cut it to keep the PR small
   and to leave the cache budget and the old-release build (`build_old.zig` worktrees under
   `.zig-cache`, whose restore was unverified) as they are on main. Every other job's caching is
   unchanged. If VM job build time matters later, propose it again on its own, with a measured
   hit rate.

## Timeouts (main run 43014021558, seconds -> minutes; demo-m8b from run 43272305959)

changes 5s -> 5; build 150 -> 10; tidy 108 -> 10; test 468 -> 20; errors-site 17 -> 5;
fuzz 532 -> 25; dbus-live 134 -> 10; m0 356 -> 15; m1 270 -> 15; m2 369 -> 20; m3 375 -> 20;
m4 331 -> 20; m5 431 -> 25; m6 469 -> 25; m6b 377 -> 20; m7 664 -> 30; m8 433 -> 25;
m8-packages 552 -> 30; m8b (new since the first version) 273 -> 15. Previous demo limits were 30 to 60.

## Not changed

What any job tests; `.github/ci-changes.sh` (so no table-test row); nothing under src/ or
build.zig (so `zig build check` was not run).
