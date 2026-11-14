# Brief: S1 · MicroVM isolation (`--isolation vm`)

*Draft for review (2026-11-14). The supervisor reviews it; the owner rules on the open questions at
the end. Codes and bounds below are proposals until the owner approves them. Nothing here starts
before 0.5.2 ships (C4 requests and M9: "main milestones complete").*

Read these first:
- `AGENTS.md`, `REVIEW.md`, `docs/STYLE.md` and `DIAGNOSTICS.md`.
- The S1 line in `docs/SPEC.md` ("Stretch milestones"), the "Isolation backend" row of its
  extension seams table, and Zigcube's CS3 (tenant isolation), which depends on S1.
- The macOS VM, which already solves half of this problem for one VM per user:
  `docs/briefs/M4b-mac.md`, `docs/decisions/2026-10-29-m4b-mac-vms-kernel-image-lifecycle.md`,
  `vm/kernel/pin.zon` and `vm/kernel/config-arm64` (the pinned Linux 6.18.59 kernel),
  `src/vm_image/kernel_build.zig` (its reproducible build), `src/vm_image_make.zig` (the
  initramfs), `src/vm_guest_init.zig`, `src/guest_serve.zig` and `src/forward_protocol.zig` (the
  vsock framing for start, streams, signals, window size and exit).
- The runtime this wraps: `src/runtime/plan.zig`, `src/runtime/child.zig`, `src/runtime/pasta.zig`,
  `src/runtime/exec.zig`, `src/runtime/records.zig`, `src/runtime/lifecycle.zig`,
  `src/runtime/devices.zig` (M10's kept supplementary groups, which `/dev/kvm` needs).
- The test VM: `src/testing/vm/lib/session.zig` (`qemu_argv`: `-accel kvm -cpu host`, 2 vCPUs,
  2048 MiB), `src/testing/vm/lib/accel.zig`, `src/testing/vm/lib/cloud_init.zig`,
  `.github/workflows/vm.yml` (KVM on the runner by a udev rule, mode 0666).
- M8b (`docs/briefs/M8b-listen.md`) and M6b (`docs/briefs/M6b-dev-loop.md`) for what VM mode cannot
  carry over in S1.

Every earlier demo keeps passing, and a run without `--isolation vm` changes by no byte (output,
JSON, records): the goldens prove it.

## Goal and demo

The same image from the store runs either in Zigbox's namespace sandbox (today) or inside its own
microVM with its own kernel, chosen per run with `--isolation namespace|vm`. A bug in the host
kernel that a container can reach in namespace mode is out of reach in VM mode.

`zig build demo-s1`, in the test VM, as the ordinary user (harness in `src/testing/vm/`, in Zig):

1. **Setup (privileged, inside the test VM only).** The harness adds the user to the `kvm` group,
   then builds and loads `zbx_vuln.ko`, a deliberately vulnerable test module (fixture source in
   `src/testing/vm/s1/`): a world-writable `/proc/zbx_vuln` whose write handler stands in for an
   unknown host kernel bug. It records each hit, with the writer's uid as the host kernel sees it,
   in `/sys/module/zbx_vuln/parameters/hits`. The module touches nothing else.
2. `zbx doctor` shows the new VM section: `/dev/kvm` openable, the VMM found at its pinned version,
   the guest kernel and initramfs present with their pinned digests.
3. `zbx run alpine:3.20 -- cat /etc/os-release` and
   `zbx run --isolation vm alpine:3.20 -- cat /etc/os-release` print the same bytes.
   `uname -r` differs: the host's Ubuntu kernel, then the pinned 6.18.59.
4. **Exploit, namespace mode:** `zbx run alpine:3.20 -- /exploit` (the fixture image, built with
   `zbx build`) writes to `/proc/zbx_vuln` and succeeds; the host's `hits` goes from 0 to 1. This
   is the expected, documented failure of namespace isolation against a host kernel bug.
5. **Exploit, VM mode:** the same image with `--isolation vm`: the write fails (`/proc/zbx_vuln`
   does not exist in the guest kernel), the workload prints why, and the host's `hits` is still 1.
6. **Lifecycle:** `zbx run --detach --isolation vm --name web alpine:3.20 -- sleep 600`; `zbx ps`
   lists it; `zbx exec web -- cat /proc/version` prints the guest kernel; `zbx logs web` shows what
   it wrote; `zbx stop web` ends it within the grace period and no VMM process is left (`pgrep`).
7. **Limits:** `--memory 256m` gives a guest whose `/proc/meminfo` total is within the VMM's
   overhead of 256 MiB; `--cpus 2` gives 2 vCPUs (`nproc`).
8. **Refusals, one coded line each:** `--isolation vm` with `--rootfs`, `--listen`, `--net host`,
   `--device` and a writable `--mount`; `--isolation vm` when `/dev/kvm` cannot be opened (the
   harness runs it as a second user outside the `kvm` group); `--isolation bogus`.
9. An upgrade check: records written by the release before S1 are read unchanged, and `zbx ps` from
   that release does not trip over a VM run's record (it is a newer version: the existing refusal).

`docs/demos/s1.md` records a run, the boot time seen under nested KVM (not asserted: three levels
of virtualization make it noise), and the cuts.

**Why a test module and not a real CVE.** A real exploit needs a vulnerable host kernel, so the
test VM would boot an old kernel that Zigbox's other demos do not run on, and the repository would
carry a working exploit. The module is a stand-in with the property that matters: host kernel code
reachable through a syscall the default seccomp profile allows. Option B in open question 6 is the
real-CVE variant, for the record in `docs/demos/s1.md` only.

## Nested virtualization (the first thing slice 1 checks)

The runner is already a guest (an Azure VM exposing `/dev/kvm`); the test VM is a guest of that,
started with `-accel kvm -cpu host` (`session.zig`); the microVM would be a third level. Two things
must hold and neither has been checked:
- The runner's `kvm_intel` or `kvm_amd` has `nested=1` (the kernel default on Intel and AMD since
  4.20, but the module parameter decides), so `-cpu host` passes `vmx` or `svm` to the test VM and
  the test VM gets `/dev/kvm`.
- KVM inside the test VM can run a guest under Hyper-V plus KVM nesting. This is not a documented
  configuration for GitHub's runners.

Slice 1 proves it before anything else is built: a `vm/s1-probe` run whose guest checks
`/proc/cpuinfo` for `vmx`/`svm`, opens `/dev/kvm`, and boots the pinned VMM with the pinned kernel
to an init that prints one line and powers off. If it fails, see open question 1: the fallback is
`demo-s1` running on the runner itself (one level down), which departs from "demos run in the test
VM" and needs the owner's word. No VMM supports TCG, so there is no slow-but-working path.

## Fixed decisions (proposed; the supervisor and owner confirm)

### Backend: Firecracker, run as an external program

Evidence (from the projects' documentation and source layout as known; slice 1 pins and records
exact versions and re-checks every claim marked †):

| | Firecracker | Cloud Hypervisor | A VMM in Zig on `/dev/kvm` |
| --- | --- | --- | --- |
| Spec | Named in S1 | Named in S1 | Not named; would be new code |
| STYLE.md's external-program rule | Allowed once named in STYLE.md, as `pasta` is: the spec names it | Same | No program, but tens of thousands of lines of device emulation |
| Distribution | Static musl binaries for x86_64 and aarch64 on GitHub releases, with checksums † | Static binaries for both arches on GitHub releases † | Ships in `zbx`; the 4 MB size limit is at risk |
| Devices | virtio-mmio: net (tap), block, vsock (exposed on the host as a Unix socket), serial | virtio-pci: net (tap or vhost-user), block, vsock (same Unix-socket model), virtio-fs (needs `virtiofsd`), more | What we write |
| Configuration | One JSON file, `--config-file` with `--no-api`: no HTTP client in `zbx` † | Command-line flags; API socket optional | Ours |
| Rootless | Needs only `/dev/kvm` and the tap fd; the jailer needs root, so `zbx` does the jailer's job with its own namespaces | Same, no jailer | Same |
| Attack surface | Smallest device model of the three, built-in seccomp filters, years of production and fuzzing † | Larger (PCI, hotplug, vhost-user) | Unfuzzed guest-facing parsers: the security boundary itself |
| Guest kernel | x86_64 `vmlinux` ELF, arm64 `Image`; virtio-mmio devices on the command line or device tree | x86_64 `vmlinux` (PVH), arm64 `Image`; PCI | Ours |

Recommendation: **Firecracker** for S1, behind an `isolation` backend interface (the spec's seam)
narrow enough that Cloud Hypervisor can be added later without touching the runtime. Writing a VMM
is rejected for S1 not for size but because its device emulation would be the security boundary
the milestone exists to provide, and the only one of the three nobody has attacked. STYLE.md gains
`firecracker` in its list of allowed external programs (the owner approves that edit; open
question 2).

How `zbx` finds it (open question 3): on `PATH` or at `$ZBX_FIRECRACKER`, checked against a
pinned version and SHA-256 per architecture in `vm/firecracker.zon` (as `vm/kernel/pin.zon` pins the
kernel). A mismatch is refused, never run.

### The VMM runs inside Zigbox's sandbox

The VMM process is the container's process as far as the host is concerned: started by the same
single-threaded setup child (AGENTS.md) in a fresh user, mount, pid, ipc, uts and network
namespace, in the run's cgroup (M2), with `no_new_privs`, with `/dev/kvm` and `/dev/net/tun` the
only devices, with the rootfs image, kernel and initramfs bound read-only, and with a seccomp
profile for the VMM (Firecracker's own filters stay on inside it). This is the jailer's job, done
rootless. Its supplementary groups are kept (M10, `src/runtime/devices.zig`), so membership in
`kvm` reaches `/dev/kvm` through the user namespace.

### Inside the guest, Zigbox is unchanged

As on the Mac: the guest kernel boots an initramfs holding an init and the Linux `zbx`. The guest
`zbx` receives the run's plan over vsock and runs the workload with the same code as on a host:
user namespace, capabilities, seccomp, `no_new_privs`, its cgroup. The workload is therefore
sandboxed twice, and the guest agent that holds the vsock channel is outside the workload's reach.

### Guest kernel

The same pinned source as the Mac (Linux 6.18.59, `vm/kernel/pin.zon`), with new fragments
`vm/kernel/config-x86_64-microvm` and `vm/kernel/config-arm64-microvm` for Firecracker's machine
(virtio-mmio, 8250 serial on x86_64, EROFS, overlayfs, tmpfs, vsock, user namespaces, seccomp,
cgroup v2; no modules, so nothing can be loaded into it). The Mac's `config-arm64` and its pinned
digest do not change. `kernel_build.zig` gains `--arch`; the x86_64 kernel builds on an x86_64
Ubuntu 24.04 host, reproducibly, and is pinned by digest the same way. Distribution: open
question 4.

### Root file system: an EROFS image made from the store

Firecracker has no virtio-fs, and the tree is immutable anyway. `zbx` writes an uncompressed EROFS
image of the image's tree (a new writer in `src/store/`, bounded, non-recursive, deterministic:
the same tree digest gives the same bytes), cached in the store under that digest and removed by
`zbx store gc` with its tree. The guest mounts it read-only as the lower layer of an overlay whose
upper is a tmpfs sized from `--memory` (so a VM container's writes, like namespace mode's, are
gone when it ends; open question 5 asks whether a disk-backed scratch device is needed). A second
virtio-blk device carries nothing in S1.

### Networking

- `--net none` (default): no network device; the guest has loopback only.
- `--net user` and `--publish`: `zbx` makes the network namespace and starts `pasta` on it exactly
  as today (`src/runtime/pasta.zig`). The setup child makes a tap device in that namespace for
  Firecracker and bridges it to pasta's interface; the guest is configured on its kernel command
  line with the address, gateway and DNS pasta gives, so `--publish` and `/etc/resolv.conf`
  behave as in namespace mode. Whether pasta's interface can be bridged without losing its address
  handling is unchecked: slice 4 proves it first and, if it cannot, `--net user` in VM mode is cut
  to a later slice and recorded in `docs/demos/s1.md` (the demo does not need the network).
- `--net host`: refused. There is no host network inside a VM.
- `--listen` (M8b): refused. A listening descriptor cannot cross into the guest's kernel, and the
  only alternative is a relay, which M8b's non-goals exclude.

### Control channel: vsock with the Mac's framing

Firecracker exposes the guest's vsock as a host Unix socket (`CONNECT <port>` handshake). `zbx`
speaks `src/forward_protocol.zig` over it, extended by new frame kinds for "here is the plan" and
"log line" (a version bump of that protocol, with its fuzzer extended). The guest's init starts the
guest `zbx` as an agent on one vsock port; the host never listens on anything the guest can dial
beyond that socket.

### What the lifecycle commands mean

- `zbx run --isolation vm`: the run's host process (foreground, or the detached monitor) owns the
  VMM and the vsock connection, relays stdin/stdout/stderr and signals, and writes the log file in
  M6b's format from the agent's log frames. Exit status is the workload's, from the `exit` frame.
- `zbx ps`: the same row; the text table does not change (its goldens stay); JSON and
  `zbx inspect` gain `isolation`, the backend's name and version, the kernel digest, vCPUs and
  memory.
- `zbx exec`: a new vsock connection to the agent, which runs the command in the guest container's
  namespaces with the guest's exec code (M6b). Exit status and streams as for `run`.
- `zbx stop`: `SIGTERM` to the workload through the agent; after the grace period the VMM is
  killed. A VM is the container: killing the VMM is the hard stop, and nothing can survive it.
- `zbx logs`: unchanged, reading the host-side file.
- A VMM crash or guest panic ends the container with a coded line, and the serial console's last
  lines go into the run's diagnostic bundle.

### Records

A run record is version 11 only for a VM run (`isolation`, backend name, version and digest,
kernel and initramfs digests, vCPUs, memory, the vsock socket path relative to the run directory);
every other run writes version 9 or 10 exactly as now (the M10 precedent in `constants.zig`:
`record_version`, `record_version_plain`). If another milestone has claimed 11 by then, take the
next free number and say so.

### Command line and resources

`--isolation namespace|vm` on `zbx run` (default `namespace`). VM size comes from the flags that
already exist: `--memory` is the guest's RAM (default and bounds below), `--cpus` rounded up is
its vCPUs, `--pids` applies inside the guest. The VMM's own overhead is accounted in the host
cgroup on top. `zbx build` steps do not take `--isolation` (non-goal).

### The Mac

`--isolation vm` is **refused on macOS** with one coded line. The Mac already puts a VM between
containers and macOS; per-container VMs there would mean either nested virtualization inside the
Virtualization.framework VM (Apple supports it only on M3 and later with macOS 15 †, and our CI
has neither) or per-container Virtualization.framework VMs driven from the macOS `zbx`, which is a
different design. Open question 7.

### gVisor

Not a second backend in S1. It is a different isolation model (a user-space kernel, not a
hardware boundary), and the research session's findings (source reading only, runsc 2.4, no
experiments) show it would break things Zigbox already ships: no inotify of host edits (#8089)
hurts M6b's dev loop; TCP descriptor donation is unsupported, which rules out M8b's `--listen`;
cgroups only through `--ignore-cgroups`; a 127.0.0.1 forwarding gap behind pasta; directfs bugs
(#16342); and it needs an AppArmor profile, an administrator step the thirty-second rule forbids.
Its one strong case is hosts without `/dev/kvm` (many cloud VMs). Recommendation: a separate, later
stretch goal, opened only if Zigcube's CS3 needs tenants on such hosts; S1's backend interface is
the seam it would plug into. Open question 8.

## Diagnostics (proposals; the owner approves codes)

`DIAGNOSTICS.md` has no group for this: `02xx` (runtime and isolation, `E0201` to `E0230` and
`W0201` to `W0209` registered) or `10xx` (the macOS VM, `E1001` to `E1017` and `W1001` to `W1003`
registered). Proposal: a new group **`11xx`, microVM isolation**, added to `DIAGNOSTICS.md` in both
repos when S1 starts (as M4b added `10xx`). If the owner prefers `02xx`, the same list starts at
`E0231` and `W0210`.

- `E1101` `--isolation vm` is not available here: `/dev/kvm` missing, or not openable (its mode and
  group, and whether the user is in it; fix: `usermod -aG kvm`, log in again).
- `E1102` the VMM program is missing, or its version or digest is not the pinned one.
- `E1103` the guest kernel or initramfs is missing or does not match its pinned digest.
- `E1104` a flag that VM mode does not support (names it: `--rootfs`, `--listen`, `--net host`,
  `--device`, `--gpu`, a writable `--mount`, a state volume).
- `E1105` the VM did not come up: the VMM exited or the agent did not answer within
  `vm_boot_timeout_ms` (the console tail goes in the bundle).
- `E1106` the VM ended unexpectedly: the VMM crashed or the guest kernel panicked.
- `E1107` the root file system image could not be made (a bound, or a file kind EROFS cannot hold).
- `E1108` `--isolation` has a value other than `namespace` or `vm`, or VM sizing is out of range.
- `E1109` `--isolation vm` on macOS.
- `W1101` nested virtualization detected: expect slow boots (once per run, from `/proc/cpuinfo`'s
  `hypervisor` flag and the VMM's boot time).

Each with `explain` text and the errors site regenerated (`zig build errors-site`).

## Bounds (proposals; the owner approves)

In `constants.zig`, each with comptime asserts against what it feeds:
- `vm_memory_mib_default` 512, `vm_memory_mib_min` 128, `vm_memory_mib_max` 16384.
- `vm_vcpus_default` 1, `vm_vcpus_max` 16.
- `vm_boot_timeout_ms` 10000 (nested KVM in CI is slow; the Mac's five-second first run is the
  target outside CI, recorded, not asserted).
- `vm_kernel_cmdline_bytes_max` 2048 (the x86 boot protocol's usual limit †).
- `erofs_image_bytes_max` equal to the store's largest tree, and `erofs_inodes_max` from the
  tree's own entry bound.
- `vm_frame_bytes_max` reuses `forward_protocol.zig`'s bound; `vm_console_tail_bytes` 16 KiB for
  the bundle.

## Tests

- Simulation: the host model gains the VMM process (start, exit, crash at any step), the vsock
  socket (short reads, resets) and `/dev/kvm` (missing, `EACCES`). `sim_run` checks that every
  failure ends with no VMM left and a coded line, and that a VM run never falls back to namespace
  mode silently.
- Fuzzers: `forward_protocol`'s fuzzer gains the new frames; a new `erofs` fuzzer writes random
  trees and reads them back with an independent reader (the pair assertion), and checks
  determinism; the `cli` fuzzer gains `--isolation`; the Firecracker config writer is a pure
  function with goldens.
- Goldens for every new error line, `zbx run --help`, the doctor section, and a VM run's record.
- A real-kernel test that skips cleanly without `/dev/kvm` (the cloud container has none).

## Slices (commit and push about every 10 minutes; open the PR only when ready)

1. **Probe and pins.** `vm/firecracker.zon` (version, URL, SHA-256 per arch), the two microVM
   kernel fragments and their pinned digests, `kernel_build.zig --arch`, and a `vm/s1-probe` run
   proving nested KVM in the test VM (or showing that it fails, which goes to the owner before
   slice 2). Ends with: the probe's run link and the pinned digests. *Haiku:* the `vm.yml` case
   for `s1`, the README and site rows.
2. **The root file system.** The EROFS writer from a store tree, its cache entry and gc, its fuzzer
   and independent reader. Checkable on any host: the guest kernel (under the probe's VMM in CI)
   mounts an image and `find` lists the tree the store holds.
3. **Boot and run.** The backend interface, the Firecracker config, the VMM in the namespace
   sandbox, the guest init and agent, the plan over vsock, streams, signals, exit status, sizing,
   `--isolation`, the refusals and codes, the doctor section. Ends with steps 2, 3, 7 and 8 of the
   demo green on a `vm/s1-*` run. *Haiku:* errors-site regeneration and `--help` goldens.
4. **Lifecycle.** Detached runs, `ps`, `exec`, `stop`, `logs`, records version 11, the upgrade
   check, the bundle's console tail. Ends with step 6 and 9 green.
5. **Network.** `--net user` and `--publish` through pasta and the bridge, or the recorded cut.
6. **The exploit demo and `demo-s1`.** The vulnerable module fixture, the exploit image, the whole
   script as `zig build demo-s1`, `docs/demos/s1.md`, the CI path rule in `.github/ci-changes.sh`.
   *Haiku:* the `ci-changes.sh` path rule, README and site status.

## Done means

`zig build check` PASS on the final commit, `demo-s1` green on a `vm/s1-*` run (link it), every
earlier demo green (`vm/all-*`), the release binary still under its size limit, the PR open.

## Non-goals

A VMM written in Zig; Cloud Hypervisor or gVisor as backends; `--isolation vm` on macOS; VM mode for
`zbx build` steps; `--rootfs`, writable mounts, state volumes (M6), `--device`, `--gpu` and
`--listen` in VM mode; `--net host` in VM mode; virtio-fs; snapshots, live migration, memory
ballooning, hot-plug; sharing one VM between containers; a guest kernel other than the pinned one;
Zigcube's CS3 itself.

## Open questions for the owner (each with a recommendation)

1. **Nested KVM fails in the test VM.** *Recommendation:* run `demo-s1` on the KVM runner directly,
   as an unprivileged user created by the workflow, with the module loaded on the runner; record
   the departure in `docs/decisions/`. The alternative, a self-hosted bare-metal runner, costs
   money and upkeep.
2. **Backend.** *Recommendation:* Firecracker, added to STYLE.md's allowed external programs, with
   the backend interface kept narrow for Cloud Hypervisor later. Not a Zig VMM.
3. **How `zbx` gets Firecracker.** (a) the user installs it, `zbx` checks the pinned version and
   digest; (b) the Linux packages (M8) gain a `zigbox-vm` package carrying it; (c) `zbx` downloads
   it on first use. *Recommendation:* (b) for packaged installs, with (a) as the rule underneath;
   no download at run time.
4. **How the guest kernel and initramfs reach a Linux host** (the binary cannot embed them under the
   4 MB limit). *Recommendation:* the same `zigbox-vm` package, pinned by digest in `zbx`; for
   tarball installs, `zbx vm fetch` from the release (as `zig build vm-kernel-fetch` does).
5. **Writable scratch.** *Recommendation:* tmpfs upper sized from `--memory` in S1 (matches "gone
   when it ends"), a disk-backed scratch device later if CS3 needs it.
6. **The exploit demo.** (A) the test module, as above; (B) additionally a real, patched CVE
   (Dirty Pipe, CVE-2022-0847) against an old kernel in a separate guest, recorded in
   `docs/demos/s1.md` and not in CI. *Recommendation:* (A) only; (B) adds a working exploit to the
   repository for no extra assurance.
7. **The Mac.** *Recommendation:* refuse (`E1109`) in S1; per-container Virtualization.framework
   VMs as a separate later goal if the Mac needs it.
8. **gVisor.** *Recommendation:* a separate later stretch goal, opened only if CS3 needs hosts
   without `/dev/kvm`; not a non-goal forever, not part of S1.
9. **Codes.** *Recommendation:* a new `11xx` group, microVM isolation, in both repos.
10. **Is S1's cut enough for CS3?** Images from the store only, no state volumes or writable mounts
    in VM mode. *Recommendation:* yes for S1; Zigcube confirms against CS3's brief before S1
    starts, and a follow-up (block-backed state volumes) is planned if not.

† Checked in slice 1 against the pinned release, and corrected here if wrong.
