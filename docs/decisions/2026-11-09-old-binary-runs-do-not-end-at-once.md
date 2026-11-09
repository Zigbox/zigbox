# Runs of the old binary in demo-m3 never end at once

Date: 2026-11-09. Context: issue #80, demo-m3 timing out at "ZBXBEGIN18:" about one run in seven.

## Problem

The UPGRADE step runs the M2 binary (built from `95ba1da`) for `old1 -- true` and
`old3 -- sh -c 'exit 3'`. Its foreground `run` blocks SIGCHLD and then waits for it with
`rt_sigtimedwait` and no timeout. A child that ends before the block has had its SIGCHLD dropped
(the default action ignores it), so the parent waits for ever on a zombie. The command never
returns and the harness times out waiting for the next step's `ZBXBEGIN`.

Evidence (KVM run 42695879126, a watchdog dump 25 s after the `old3` command): `zbx-old run ...
old3` in `rt_sigtimedwait` (timeout NULL), its child `[sh] <defunct>`, `old3.zon` written, the
detached `old2` supervisor on `/dev/null` for all three descriptors (it was never involved). The
guess in #80, a detached child holding the console, was wrong: the old supervisor redirects 0, 1
and 2 to `/dev/null`.

The current `zbx` already has the fix (`host_real.zig`, `wait_event`, with a test for it). The old
binary is a released artifact and is not changed.

## Decision

In demo-m3 every run of the old binary holds on first: `sh -c 'sleep 1'` and
`sh -c 'sleep 1; exit 3'` replace `true` and `sh -c 'exit 3'`. The parent blocks SIGCHLD within
milliseconds of the fork, so the signal always waits in the queue. The harness's treatment of
detached children is unchanged. Cost: two seconds in the demo.
