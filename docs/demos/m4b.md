# M4b demo: the thirty seconds on macOS

This file is written up to the end of slice 2. Slice 5 completes it with the steps a stranger
can follow on a clean Mac, the cuts and the failure modes.

## What runs today (slice 2): demo steps 2 and 4

On an Apple silicon Mac with a `zbx` built by `zig build` (signed ad hoc with the virtualization
entitlement; the build needs the pinned kernel first: `zig build vm-kernel-docker`, once).

1. `zbx run alpine -- cat /etc/os-release` prints Alpine. The machine is not running: the
   command boots it (about 0.25 s), the guest sets itself up for the Mac user (clock, NAT
   network by DHCP, the user's name and ids, the cgroup subtree), the image is pulled, the
   container runs. All of it takes under five seconds.
2. A second `zbx run` takes tens of milliseconds: the machine and the store are warm.
3. Leave it idle: after five minutes with nothing running no `zbx vm serve` process is left
   (`pgrep -f "zbx vm serve"`); the next `zbx run` starts the machine again. To see it in
   seconds: `ZBX_VM_IDLE_TIMEOUT_MS=4000 zbx run alpine -- true`, then `pgrep` after five.
   A `zbx run -d` container keeps the machine alive until it ends.

## Known gap of slice 2

- **A working directory the guest cannot see is quietly replaced with the guest user's home.**
  A command run from a directory of the Mac starts in `/Users/<name>` of the machine, which is
  in the machine's memory. `zbx run` then reads and writes `zbx.lock` there (W0503 says it wrote
  `/Users/<name>/zbx.lock`, a path that does not exist on the Mac) instead of in the project.
  From slice 3 on this must never be silent: a working directory outside what is shared with
  the machine is refused with a one-line coded diagnostic (a new 10xx code) that says it is
  outside what is shared and names what is shared.

## Cuts of this slice

- **The store and the state live in the machine's memory** (the guest's home directory is on
  its root tmpfs), so an image is pulled again after the machine stops, and nothing survives
  `zbx vm stop` or the idle stop. The disk image (slice 3) fixes it.
- **No files of the Mac are visible** to a container: `--rootfs ~/demo/alpine` and `--bind` need
  the home directory shared with virtiofs (slice 3). The working directory is forwarded; where
  the guest has no such directory the command starts in the guest user's home.
- **No `--publish`** (slice 4), no Rosetta (slice 3), no `zbx doctor` of the Mac (slice 5).
- **`zbx run -it` does not exist**: a terminal on the Mac's standard input gives the command a
  terminal, a pipe or a file gives it pipes. `zbx run alpine -- sh` is the interactive shell.
- The helpers and the CA bundle come from Alpine 3.20 packages pinned in `vm/alpine.zon`.
