# M4b demo: the thirty seconds on macOS

This file is complete up to slice 5 part 1: the release script, the formula, the doctor, the macOS
workflow and the failure modes are built and tried here; the first signed release, the tap and the
runner are the owner's and are marked below. M4b stays "built, not demonstrated" until the four
demo steps pass on a clean Mac and the macOS job is green.

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

## For a stranger on a clean Mac (Apple silicon, macOS 13 or later)

Nothing here needs `sudo`: Homebrew writes under its own prefix, and `zbx` writes only to
`~/Library/Application Support/zbx` the first time it runs.

1. `brew install Zigbox/tap/zigbox` (the tap and the first release are the owner's, see below).
   `zbx --version` prints `zbx <version> (macOS)`; `zbx doctor` should print `ok` for all six
   checks (`rosetta` may say `warn`: only linux/amd64 images need it).
2. Demo step 2, the machine starts by itself: `zbx run alpine -- cat /etc/os-release` prints
   Alpine (the first run boots the machine and pulls the image, a few seconds). Run it again:
   about one second.
3. Demo step 3, files: `mkdir -p ~/demo/alpine`, fill it with a root file system (`zbx run` does
   not make one; any extracted Alpine minirootfs will do), then
   `zbx run --rootfs ~/demo/alpine -- touch /hello` and `ls -l ~/demo/alpine/hello`: the file is
   yours. `zbx run --state vol:/data alpine -- sh -c 'echo hi > /data/x'`, then `zbx vm stop`, then
   `zbx run --state vol:/data alpine -- cat /data/x` prints `hi`.
4. Demo step 4, the network: `zbx run -d --name web --publish 18080:80 nginx:alpine`, wait a
   second, `curl http://localhost:18080/` prints nginx's page. `zbx stop web`: the port is closed.
5. The machine stops by itself after five idle minutes (`pgrep -f "zbx vm serve"` finds nothing).

The same steps, with checks, run as `zig build demo-mac` (see "The macOS job").

## The macOS job and the harness

`zig build demo-mac` (src/testing/mac_demo.zig) runs 19 steps through the macOS `zbx`: M1 steps
1, 3, 4, 5 (SIGINT instead of the console's Ctrl-C) and 7; M2 steps 3 and 4; M3 steps 1, 3 and 5;
M4's pull, run by tag and its two refusals; M4b steps 2, 3 (files, state) and 4 (a published
port). It pulls `alpine:3.20` and `nginx:alpine` from the registry and the pinned Alpine
minirootfs from dl-cdn. **Deviation from the brief:** the Linux demos drive a QEMU serial
console (`src/testing/vm/session.zig`), which a Mac has no counterpart of, so their code is not
shared; the table in `mac_demo.zig` takes the steps by their numbers in docs/demos/m1.md to
m4.md. Not driven from macOS: M1 steps 2 (host `ps`), M2 steps 1 and 2 (fork bomb and OOM need
`timeout` and a stress image), M3 steps 2 and 4 (store snapshots, a rootfs with a mode-711 root),
and everything after step 5 of each table. `.github/workflows/mac.yml` runs `zig build check` and
`zig build demo-mac` on a self-hosted runner whose label is the repository variable
`MAC_RUNNER_LABEL`; with the variable unset a job on the hosted runner says so and the
workflow is green.

**The runner.** The repository is public, so `mac.yml` does not run for a pull request from a fork
(its `if` requires the head repository to be this one); a push to main, a manual run and a branch
of this repository do. Run the self-hosted runner under **its own macOS user account**, not the
owner's: the machine it starts, its `store.img`, `~/Library/Application Support/zbx` and its
keychain are then separate from the owner's. It needs **no keychain access**: nothing in the
workflow signs with Developer ID (the macOS `zbx` is signed ad hoc by `zig build`), and the
release is the owner's, from their own session.

Recorded: `zig build demo-mac` on the owner's Mac (macOS 26, Apple silicon), run by the
implementer on 2026-10-29: `demo-mac: PASSED, 19 steps`.

## `zbx doctor` on macOS

Run on the Mac, not forwarded. Six checks: `entitlement` (read from the binary's own signature
with `codesign -d --entitlements -`), `vm` (stopped or running, with pid and size), `version` (the
running machine's image against this binary's: a warning, `ZBX-W1001`), `share` (the home), `disk`
(free space on the volume against the 2 GiB the machine needs, and the image's size) and
`rosetta` (a warning, `ZBX-E1016`). A failing check is `FAIL` with its code and a diagnostic on
stderr; the exit code is 0, or 2 when a check fails. `--output json` is `zbx.doctor/1` with these
ids and, when the machine runs, a `guest` member holding the Linux doctor's own document. Both
renderings have goldens (src/testdata/doctor/mac_*.txt). The guest's section is information and
does not change the exit code; **its `cgroup` check always fails** (the machine has no systemd, and
zbx runs there with its own delegated cgroup subtree), which the heading says.

Recorded (healthy, machine stopped), 2026-10-29:

```
ok   entitlement  signed with com.apple.security.virtualization
ok   vm  stopped; it starts when a command needs it
ok   version  this zbx carries image d29201af1f6001a6
ok   share  /Users/zvozin is shared with the machine at the same path
ok   disk  41 GiB free on the Mac's volume; the disk image is 71680 MiB of 70 GiB
ok   rosetta  installed: linux/amd64 images can run
```

## Old images

When the host starts it removes the `vm/<version>` directories of older versions, keeping the
current one and the newest older one (a binary rolled back finds its image there). Only
directories named like a version are looked at, and only the files directly in them; `store.img`,
`vm-settings` and everything else are never touched. Recorded: after the version test below,
`vm/` held `d29201af1f6001a6` (older) and `6c6b103a21ab66c5` (current).

## Releasing

`zig build mac-release` builds the ReleaseSafe macOS `zbx` (the VM image inside), signs it with
the hardened runtime, a secure timestamp and `vm/zbx.entitlements`, runs `codesign --verify
--strict` and `codesign -d --entitlements -`, zips the binary alone (`ditto`) into
`zbx-<version>-macos-arm64.zip`, checks that the zip holds the same code (CDHash) as the binary,
writes `<zip>.sha256` and the Homebrew formula (`packaging/homebrew/zigbox.rb` with the version,
the URL and the hash filled in) into `zig-out/mac-release/`, which it empties first. Options:
`-Dsign-identity=<name>` (default the owner's Developer ID Application identity; `-` signs ad
hoc), `-Dnotary-profile=<name>` (default `zbx-notary`) and `-Dnotarize=true`, which submits
the zip with `xcrun notarytool submit --keychain-profile <name> --wait`. It refuses, before
signing anything, when the profile is not in the keychain or the identity is `-`. No secret is
read, printed or logged: the keychain holds the certificate and the notary credentials.

**Where it runs:** from a logged-in graphical session with an unlocked login keychain (the
owner's Terminal, or a runner with that keychain unlocked), never from an ssh or sandboxed
session: there `codesign` fails with `errSecInternalComponent`, and the script says so in one
line. The workflow does not release.

**The version** has one source, `version` in `build.zig.zon`, which the build hands to the code
(`zbx --version`, the archive name and the formula). Proposal for the first real tag: **0.1.0**
(`v0.1.0`), with the version in `build.zig.zon` changed to match in the same commit.

**What a notarized bare binary does.** A Mach-O cannot be stapled, so the ticket stays with Apple
and Gatekeeper asks for it. Homebrew downloads with curl, which does not mark the file as
quarantined, so Gatekeeper does not assess it at install or first run; the signature and the
notarization matter for a copy downloaded with a browser (quarantined), which a notarized
Developer ID binary may run after Gatekeeper's online check. The second case is reasoned from
Apple's documentation and was **not run**. `spctl -a -t exec -vv` on the signed binary says
`rejected (the code is valid but does not seem to be an app)`, which is its answer for any bare
command-line tool; the coordinator's `spctl -a -vvv -t open --context context:primary-signature`
on it says `accepted, source=Notarized Developer ID`.

Recorded, 2026-10-29. A first run of `zig build mac-release -Dnotarize=true` from the
implementer's shell (not meant to submit anything; the keychain had become usable) signed with
Developer ID and was submitted: `codesign` printed `Authority=Developer ID Application: Alex Zuzin
(56A872L679)`, `TeamIdentifier=56A872L679`, `flags=0x10000(runtime)`, a timestamp, `valid on disk`,
`satisfies its Designated Requirement`, and the entitlement `com.apple.security.virtualization`
`true`; `xcrun notarytool history --keychain-profile zbx-notary` listed submission
`a8ccebff-136d-4b82-bd1e-468cef2765ab` (`zbx-0.0.0-macos-arm64.zip`) with `status: Accepted`. That
archive was later overwritten by ad-hoc test runs and had an extra directory level in it; the layout
is now final, and the first real release is the owner's, from their Terminal. Ad-hoc run of the
final script, same day: the archive holds `zbx` alone, `codesign -d --entitlements -` prints
`com.apple.security.virtualization = true`, and the CDHash of the binary and of the unzipped copy
agree.

**What the owner provides, still:** run `zig build mac-release -Dnotarize=true` from their Terminal
(the Developer ID and `zbx-notary` profile are in their keychain); create the GitHub release
`v<version>` and attach the zip; create the repository `Zigbox/homebrew-tap` and put
`zig-out/mac-release/zigbox.rb` in it as `Formula/zigbox.rb`; set the repository variable
`MAC_RUNNER_LABEL` and register the self-hosted runner. The formula installs the prebuilt
arm64 binary pinned by sha256 (`depends_on arch: :arm64`, `:macos`), builds nothing and needs no
`sudo`; its `test do` runs `zbx --version` and `zbx explain E1001`, which do not start the machine.
Not tried: `brew install` itself (there is no tap yet); `brew audit` was not run.

## Failure modes

Each was tried on the owner's Mac on 2026-10-29 unless it says otherwise.

| What | What the user sees | Recovery |
| --- | --- | --- |
| No virtualization entitlement (a copy signed without it) | `zbx doctor`: `FAIL entitlement  signed without com.apple.security.virtualization  [ZBX-E1001]` and the diagnostic. `zbx run alpine -- true`: `error[ZBX-E1001] ... Virtualization.framework refused: The process doesn't have the "com.apple.security.virtualization" entitlement.` | from a checkout: `codesign -f -s - --entitlements vm/zbx.entitlements $(which zbx)`; from brew: `brew reinstall zigbox` |
| Rosetta missing | `warn rosetta ... [ZBX-E1016]` in the doctor; `--platform linux/amd64` is `ZBX-E1016` with `softwareupdate --install-rosetta --agree-to-license`, then `zbx vm stop`. **Diagnostic only**: this Mac has Rosetta and zbx never removes it; the decision is unit-tested and the diagnostic has a golden. | install Rosetta, `zbx vm stop` |
| The disk image full | `ZBX-E1014` after the command's own error (tried in slice 3 with `--disk 1G` and 2 GB written); `zbx doctor` fails `disk` with `ZBX-E1015` when the Mac's volume has under 2 GiB free (unit-tested, not provoked) | free space, or `zbx vm config --disk <bigger>` and `zbx vm stop` |
| A machine of another version | `zbx doctor` from the new build: `warn version  the machine runs image d29201af1f6001a6, this zbx carries 6c6b103a21ab66c5  [ZBX-W1001]`. Any command from the new build: `warning[ZBX-W1001]: replacing a virtual machine of another version`, then the command runs on a new machine. Built with `-Dvm-label=other`. | nothing; `zbx vm stop` by hand |
| The machine killed from Activity Monitor (`kill -9` of `zbx vm serve`), with a published container | The host and the machine are gone at once; the published port's Mac listener is gone with the process (0 listeners); `zbx vm status` says `stopped`; the next command starts a fresh machine and runs (`recovered`). The container died with the machine, and the image and state are on the disk. | run the command again |
| The Mac sleeps with a container running | **Not run**: `pmset sleepnow` would suspend this session. Expected: the machine's clock stops with the Mac; when it wakes, the container continues, but connections that were open (a client of a published port) have timed out, and the guest's clock is wrong until the machine restarts (zbx sets it at boot only). A machine that does not come back answers nothing: `ZBX-E1009` or `ZBX-E1010` for the next command, and `zbx vm stop` starts it over. | `zbx vm stop` if a command reports E1009 or E1010 |

## Cuts and limits of slice 5

- The first signed release, the tap, the GitHub release and the runner are the owner's (above).
- Demo steps were not run on a *clean* Mac or a fresh user account: this is the developer's Mac.
- `brew install` and `brew audit` were not run.
- The macOS `zbx schema doctor` is not defined (only `vm-status` and `vm-config` are); the
  document follows the Linux `zbx.doctor/1` and adds `guest`.

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

## What runs today (slice 4): M5 demo steps 2 and 3 from macOS

1. `zbx run --net user alpine -- wget -qO- http://example.com` fetches the page through pasta in
   the machine.
2. `zbx run -d --name web --publish 18080:80 nginx:alpine`, then `curl http://localhost:18080/` on
   the Mac prints nginx's page (also on `127.0.0.1` and `[::1]`). `lsof -nP -iTCP:18080
   -sTCP:LISTEN` shows `zbx` listening on `127.0.0.1` and `[::1]` only. The first request may
   be reset when it comes before nginx listens in the container, as on Linux.
3. `zbx stop web`: the port is closed at once. `zbx vm stop` closes every published port.
4. `--publish 0.0.0.0:18085:80` listens on every interface (`*:18085`), and only then.
5. A Mac port that is in use, or `--publish 81:80` (a port under 1024 on 127.0.0.1 needs root on
   macOS), is `ZBX-E1017` before the container starts; `--publish 0.0.0.0:81:80` works.

## Cuts and limits of slice 4

- Only TCP, as on Linux. A Mac connection to a published port whose container has not started
  listening yet is accepted and then closed, not refused.
- What holds a taken Mac port is not looked up; the diagnostic gives the `lsof` command.
- The guest's own diagnostics name guest paths (see slice 3).

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
