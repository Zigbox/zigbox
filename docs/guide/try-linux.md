# Try Zigbox on Linux

You need Linux on x86_64 or arm64 (aarch64), kernel 5.15 or newer. `zbx` runs as your own user;
you need `sudo` only to install packages and change a few host settings, once.

Zigbox is tested on Ubuntu 24.04. The packages are also installed and run on Debian, Fedora and
Rocky Linux in CI. Other distributions with cgroup v2 and systemd should work; tell us if one does
not. The output on this page is from `zbx 0.4.0`.

## 1. Install

Pick one.

### From the apt repository (Debian, Ubuntu)

```sh
curl -fsSL https://zigbox.org/zigbox-archive-keyring.gpg | sudo tee /usr/share/keyrings/zigbox.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/zigbox.gpg] https://zigbox.org/apt stable main" | sudo tee /etc/apt/sources.list.d/zigbox.list
sudo apt update && sudo apt install zigbox
```

### From the dnf repository (Fedora, Rocky, RHEL)

Create `/etc/yum.repos.d/zigbox.repo`:

```ini
[zigbox]
name=Zigbox
baseurl=https://zigbox.org/rpm/$basearch
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://zigbox.org/zigbox-archive-keyring.asc
```

then:

```sh
sudo dnf install zigbox
```

The package holds the one `zbx` binary. It recommends `uidmap` (on Fedora, `shadow-utils`) and
`passt`, which step 2 needs. It does not change `/etc/subuid` or `/etc/subgid`.

<!-- owner: on 2026-11-11 https://zigbox.org/apt, /rpm and the keyring return 404, and no release
carries zigbox-repos.tar.gz yet. These commands are the README's and the ones demo-m8-packages
runs against a local copy of the tree; they have not been run against zigbox.org. Run them on a
clean Ubuntu and Fedora before 0.5.1 is announced. -->

### The static binary

`zbx` is one static file with no dependencies. Download it from the
[latest release](https://github.com/Zigbox/zigbox/releases/latest) and put it on your `PATH`:

```sh
curl -fsSLo zbx https://github.com/Zigbox/zigbox/releases/download/v0.5.1/zbx-0.5.1-linux-x86_64
chmod +x zbx && sudo mv zbx /usr/local/bin/
zbx --version
```

On arm64, take `zbx-0.5.1-linux-aarch64`. Install `uidmap` and `passt` from your distribution
too (step 2).

<!-- owner: no release up to 0.4.0 carries a Linux binary (0.4.0 has no assets; 0.3.x only the
Mac zip), and nothing in the repository names one. The file name above is a placeholder: fix it
to the 0.5.1 asset's name, or drop this section. -->

### From source

With [Zig 0.17.0](https://ziglang.org/download/) (exactly that version) and nothing else:

```sh
git clone --branch v0.4.0 https://github.com/Zigbox/zigbox && cd zigbox
zig build release
sudo cp zig-out/release/x86_64-linux/zbx /usr/local/bin/zbx
```

`zig build release` builds both static binaries, `zig-out/release/x86_64-linux/zbx` and
`zig-out/release/aarch64-linux/zbx` (3.6 MB and 3.2 MB for 0.4.0), in a few minutes.

## 2. Check the host

```sh
zbx doctor
```

`zbx doctor` checks seven things and prints one line for each. On a ready host every line says
`ok`. When one says `FAIL`, it ends with a code, and a diagnostic below says why and prints the
command that fixes it. Here is a real run on a host with two problems:

```
$ zbx doctor
ok   kernel  6.18.44-fc-v378 x86_64 (minimum 5.15)
ok   userns  user.max_user_namespaces=64250, unshare(CLONE_NEWUSER) works
FAIL cgroup  cgroup v2 is not mounted at /sys/fs/cgroup (cgroup v1 or hybrid host); a container started here runs without limits, and --memory, --pids and --cpus are refused (ZBX-E0307)  [ZBX-E0103]
ok   overlay  overlayfs mounts inside a user and mount namespace; id-mapped mounts of /home/user: not allowed (zbx does not use them)
FAIL subid  root (uid 0); no subuid range of 65536 ids (largest: 0); no subgid range of 65536 ids (largest: 0); newuidmap not found; newgidmap not found  [ZBX-E0105]
ok   seccomp  seccomp is supported (current mode: disabled for this process)
warn net  pasta not found: --net user and --publish need it (apt install passt)
error[ZBX-E0105]: uid and gid mapping is not set up
  cause  root (uid 0); no subuid range of 65536 ids (largest: 0); no subgid
         range of 65536 ids (largest: 0); newuidmap not found; newgidmap not
         found
  fix    give this user id ranges:    sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $(id -un)
         install on Debian, Ubuntu:   sudo apt install uidmap
         install on Fedora:           sudo dnf install shadow-utils
  more   zbx explain E0105 · rerun with --verbose for the full cause chain
  docs   https://zigbox.github.io/zigbox/errors/E0105.html
```

(The E0103 block is left out here.) The exit code is 0 when every check passes and 2 when one
fails. `zbx explain <code>` prints the long explanation offline.

### What to do about each failure

| Check | Code | Usual cause | Fix |
| --- | --- | --- | --- |
| kernel | [E0102](https://zigbox.org/errors/box/E0102) | kernel older than 5.15 | a newer kernel |
| userns | [E0101](https://zigbox.org/errors/box/E0101) | Ubuntu 24.04 restricts unprivileged user namespaces through AppArmor | `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`, and the diagnostic's line to keep it after a reboot |
| cgroup | [E0103](https://zigbox.org/errors/box/E0103) | cgroup v1 or hybrid host, no systemd user session, or controllers not delegated | the diagnostic names which; a v1 host needs `systemd.unified_cgroup_hierarchy=1` on the kernel command line |
| overlay | [E0104](https://zigbox.org/errors/box/E0104) | overlay module missing, or the user namespace check failed | fix E0101 first; else `sudo modprobe overlay` |
| subid | [E0105](https://zigbox.org/errors/box/E0105) | no subordinate id range, or `newuidmap` missing | `sudo apt install uidmap` (Fedora: `shadow-utils`), and `sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $(id -un)` |
| seccomp | [E0106](https://zigbox.org/errors/box/E0106) | a kernel without seccomp | a distribution kernel |
| net | warning | `pasta` not installed: only `--net user` and `--publish` need it | `sudo apt install passt` (Fedora: `dnf install passt`) |

Some failures still let containers run, with a warning on every run: without cgroup v2 a container
runs without limits ([W0301](https://zigbox.org/errors/box/W0301)), and without a subordinate id
range only your own id is mapped inside ([W0201](https://zigbox.org/errors/box/W0201)). Fix them
anyway: a build needs cgroup v2 ([E0307](https://zigbox.org/errors/box/E0307)).

## 3. Run a container

```
$ zbx pull alpine:3.20
sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e
$ zbx run alpine:3.20 -- cat /etc/os-release
NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.20.10
PRETTY_NAME="Alpine Linux v3.20"
HOME_URL="https://alpinelinux.org/"
BUG_REPORT_URL="https://gitlab.alpinelinux.org/alpine/aports/-/issues"
```

`zbx pull` prints the image's digest. The first `zbx run` in a directory writes a `zbx.lock`
there, which pins the tag to that digest (warning [W0503](https://zigbox.org/errors/box/W0503));
commit it with your project.

If Docker Hub answers [E0506](https://zigbox.org/errors/box/E0506) (its pull rate limit), ask a
mirror first, as the diagnostic says:

```sh
ZBX_REGISTRY_MIRRORS=mirror.gcr.io zbx pull alpine:3.20
```

Next: [the tour](tour.md) walks through ports, state, logs, exec, build, signing and push.
