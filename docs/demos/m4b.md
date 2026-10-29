# M4b demo: the thirty seconds on macOS

This file is written up to the end of slice 3. Slice 5 completes it with the steps a stranger
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

## What runs today (slice 3): demo step 3, state, Rosetta

Run from a directory in your home (anything else is refused with `ZBX-E1013`).

1. `zbx run --rootfs ~/demo/alpine -- touch /hello`, then `ls -l ~/demo/alpine/hello` on the Mac:
   the file is there, owned by you. A container's root writes as you; a `chown` to another id
   inside the container succeeds and changes nothing (the share has one owner).
2. `zbx run --state vol:/data --rootfs ~/demo/alpine -- sh -c 'echo persisted > /data/x'`, then
   `zbx vm stop`, then the same with `cat /data/x`: it prints `persisted`. The store and the
   state are on `~/Library/Application Support/zbx/store.img`, a sparse file (64 GiB by default,
   `du -h` shows what it really holds); nothing of them is under `~/.local`.
3. A second cold boot needs no pull: `zbx vm stop`, then `zbx run alpine -- true` takes about
   one second (boot 0.25 s, setup 0.7 s, the container).
4. `zbx run --platform linux/amd64 alpine:3.19 -- uname -m` prints `x86_64` through Rosetta
   (`zbx pull --platform linux/amd64 alpine:3.19` first when `zbx.lock` has no entry for the
   tag). An image whose index has no arm64 entry runs the same way without the option.
5. `zbx vm config --disk 128G` grows the disk at the next boot; a smaller size is `ZBX-E1012`.
   A small disk fills with `ZBX-E1014` after the command's own error.

## Cuts and limits of slice 3

- **Rosetta's missing diagnostic (`ZBX-E1016`) was not seen live**: this Mac has Rosetta, which
  zbx never uninstalls. The decision is a function with a test on every platform and every state
  of Rosetta, and the diagnostic has its golden.
- **An image with no arm64 entry on a Mac without Rosetta** is the ordinary `ZBX-E0509` ("the
  image offers linux/amd64"); it does not mention Rosetta. Only `--platform linux/amd64` does.
- **`zbx.lock` decides the platform of a tag it already holds.** `zbx run --platform linux/amd64
  alpine` with `alpine` locked as arm64 runs the locked image; pull the other platform under a
  tag the lock does not hold, or in another project.
- The Linux zbx's own disk diagnostics (`W0202`, `E0416`) name guest paths (`/mnt/store/...`)
  in their fixes. `ZBX-E1014` follows them with the fix that works on a Mac.
- `host.log` is capped when the host starts, not while it runs.

## Cuts of the earlier slices that still stand

- **No `--publish`** (slice 4), no `zbx doctor` of the Mac (slice 5).
- **`zbx run -it` does not exist**: a terminal on the Mac's standard input gives the command a
  terminal, a pipe or a file gives it pipes. `zbx run alpine -- sh` is the interactive shell.
- The helpers and the CA bundle come from Alpine 3.20 packages pinned in `vm/alpine.zon`.
