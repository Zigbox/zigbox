# Try Zigbox on a Mac

> **Not yet verified for this release.** No command on this page was run for this guide, and none
> on a Mac with 0.5.0: the commands and output come from earlier recorded Mac runs. **Homebrew
> still installs 0.3.1** until the tap is bumped to the 0.5.0 Mac build; that version has no `key`,
> `sign`, `verify`, `trust` or `policy` commands, so those steps fail with it. Whether `zbx run`
> pulls an image by itself on a Mac is unchecked (on Linux it does not: E0522).

You need a Mac with Apple Silicon (M1 or later). Intel Macs are not supported. Nothing here
needs `sudo`.

`zbx` on a Mac runs your containers in a small Linux virtual machine, using Apple's
Virtualization framework. You never manage that machine: the first command that needs it starts
it in a few seconds, and it stops by itself after five idle minutes. Your home folder is shared
with it at the same path, so files a container writes into your projects are yours on the Mac.

<!-- verify on a Mac before 0.5.1: every command and output on this page comes from the recorded
Mac runs cited below, made with an earlier version. None was run for this guide. -->

## 1. Install

```sh
brew install zigbox/tap/zigbox
zbx --version
```

Homebrew installs a signed and notarized binary from the GitHub release. `zbx` keeps its files in
`~/Library/Application Support/zbx`.

<!-- verify on a Mac before 0.5.1: on 2026-11-11 the tap's formula is still at 0.3.1, which has
no key, sign, verify, trust or policy commands. The formula must point at the 0.5.1 zip before
this page goes live. Check the exact `zbx --version` text (`zbx <version> (macOS)`). -->

## 2. Check the Mac

```sh
zbx doctor
```

On a ready Mac every line says `ok`. This is a recorded run, with the machine stopped:

```
ok   entitlement  signed with com.apple.security.virtualization
ok   vm  stopped; it starts when a command needs it
ok   version  this zbx carries image d29201af1f6001a6
ok   share  /Users/you is shared with the machine at the same path
ok   disk  41 GiB free on the Mac's volume; the disk image is 71680 MiB of 70 GiB
ok   rosetta  installed: linux/amd64 images can run
```

If a line says `FAIL` or `warn`, it ends with a code; the diagnostic under it says what to do.
The ones you may meet:

| Code | What it means | What to do |
| --- | --- | --- |
| [E1001](https://zigbox.org/errors/box/E1001) | this copy of `zbx` lacks the virtualization entitlement | `brew reinstall zigbox` |
| [E1015](https://zigbox.org/errors/box/E1015) | under 2 GiB free on the Mac's disk | free some space |
| [E1016](https://zigbox.org/errors/box/E1016) (warning) | Rosetta is not installed; only `linux/amd64` images need it | `softwareupdate --install-rosetta --agree-to-license`, then `zbx vm stop` |
| [W1001](https://zigbox.org/errors/box/W1001) (warning) | the machine running is from another version of `zbx` | nothing: the next command replaces it |

## 3. Run a container

```sh
zbx pull alpine:3.20
zbx run alpine:3.20 -- cat /etc/os-release
```

The first command starts the machine, which takes a few seconds. `zbx run` prints Alpine's
release file. `zbx run` never pulls by itself: an image you have not pulled is refused with
[E0522](https://zigbox.org/errors/box/E0522), whose fix is the `zbx pull` to run.

<!-- verify on a Mac before 0.5.1: docs/demos/m4b.md says "the first run boots the machine and
pulls the image"; on Linux 0.4.0, run without a pull is E0522. Check which the Mac does. -->

Run it again: it takes about a second, because the machine and the image
are warm.

## 4. Keep data, publish a port

```sh
zbx run --state vol:/data alpine:3.20 -- sh -c 'echo hi > /data/x'
zbx vm stop
zbx run --state vol:/data alpine:3.20 -- cat /data/x
```

The last command prints `hi`: a state volume outlives the container and the machine.

```sh
zbx pull nginx:alpine
zbx run -d --name web --publish 18080:80 nginx:alpine
curl http://localhost:18080/
zbx stop web
```

`curl` prints nginx's welcome page. The port listens on the Mac's `localhost` only, and closes
when the container stops.

## 5. Edit a project live

Containers can write into a project under your home folder, and `zbx logs` and `zbx exec` work as
on Linux, with a terminal and Ctrl-C:

```sh
mkdir -p ~/demo/site && cd ~/demo
echo hello > site/index.html
zbx pull python:3.12-slim
zbx run -d --name web --publish 8000:8000 --mount ./site:/srv python:3.12-slim -- python -m http.server -d /srv 8000
curl http://localhost:8000/
zbx logs web
zbx exec web -- sh
zbx stop web
```

Edit `site/index.html` on the Mac and `curl` again: the container serves the new file.

<!-- verify on a Mac before 0.5.1: the run line is the one demo-mac step m6b.1 runs
(src/testing/mac_demo.zig); the mkdir, echo, curl, logs and exec lines are the guide's. -->

A project must be inside your home folder: the machine sees only your home, and a mount outside
the project is refused with [E0212](https://zigbox.org/errors/box/E0212).

## What was recorded

The steps above are the ones `zig build demo-mac` runs on a real Mac in CI. Its recorded run
([run 24](https://github.com/Zigbox/zigbox/actions/runs/41143740466), 2026-10-30) passed all 31
steps, among them:

```
ok   m4.1  pull alpine:3.20 prints the manifest digest
ok   m4b.2  a second run is quick: the machine and the store are warm
ok   m4b.3  files written in the container are on the Mac, owned by the user
ok   m4b.3s  state survives zbx vm stop
ok   m4b.4  a published port answers on the Mac's localhost and is closed by zbx stop
ok   m6b.1  run -d serves ./site on 8000 (python's http.server), and exec sees it listen
ok   m6b.4  logs web shows the two requests of step 2, and no others

demo-mac: PASSED, 31 steps
```

## Mac-only commands

- `zbx vm status` shows whether the machine runs, and its size.
- `zbx vm stop` stops it now (it also stops after five idle minutes).
- `zbx vm config --disk 128G` grows its disk at the next start. It cannot shrink.

## Not on the Mac yet

- `zbx push` is Linux-only. To get an image out of a Mac, use `zbx store export --oci`.
- `zbx build` was not tested on a Mac.
- Signing commands (`key`, `sign`, `verify`, `trust`, `policy`) are passed to the machine, but
  have not run on a real Mac yet.
  <!-- verify on a Mac before 0.5.1: the checks of docs/demos/m8.md, slice 9, must pass first. -->

See [Known limits](known-limits.md) for the rest, and [the tour](tour.md) for every command.
