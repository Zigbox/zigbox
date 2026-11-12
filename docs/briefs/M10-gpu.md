# Brief: M10 · GPU access

*2026-11-11. The owner accepted the four recommendations below
(`docs/decisions/2026-11-11-m10-gpu-decisions.md`). It starts after 0.5.0.*

Read these first:
- `AGENTS.md`, `REVIEW.md`, `docs/STYLE.md` and `DIAGNOSTICS.md`.
- `docs/decisions/2026-11-11-docker-parity-scope.md`: GPU access is a goal for Zigbox containers.
  Zigcube's CS4 (GPU allocation, sharing and gang scheduling) is a separate piece of work and is
  unchanged.
- M1's and M2's runtime: `src/runtime/plan.zig` (the setup steps, `deny_setgroups` and the id
  maps), `src/runtime/child.zig`, `src/runtime/spec.zig`, the container's `/dev`
  (`container_devices_count` in `src/constants.zig`), and the seccomp filter.
- The Container Device Interface (CDI) specification, v0.6 and later
  (https://github.com/cncf-tags/container-device-interface, `SPEC.md`). Podman, containerd and
  Docker read it, and NVIDIA's `nvidia-ctk cdi generate` writes it.

M10 does not depend on M9. It can run in parallel with M9 once 0.5.0 is tagged, if there is
capacity.

## Goal and demo

`zbx run --gpu all <image> -- nvidia-smi` works rootless on a Linux host with an NVIDIA GPU and
its driver, given one admin step that the host needs anyway (generating the CDI spec). AMD and
Intel GPUs work through their render nodes, with no vendor tooling. `zbx doctor` says what the
host offers and what is missing, in plain words. Nothing about a run without `--gpu` or
`--device` changes by a byte: the goldens prove it.

## How it works (fixed)

### Devices, from three sources

- **CDI devices** (`--device nvidia.com/gpu=0`, `--device nvidia.com/gpu=all`). Zigbox reads CDI
  spec files from `/etc/cdi` and `/var/run/cdi`, then from `$XDG_CONFIG_HOME/cdi`, so a user
  without root can add one. **JSON only**, because there is no third-party YAML parser. A YAML
  spec is refused (`E0226`), and the fix gives the `nvidia-ctk cdi generate --format=json`
  command. Each spec is bounded (size, devices, edits) and parsed with `std.json` into a
  fixed-capacity structure. Of a device's container edits, Zigbox applies `deviceNodes`,
  `mounts` (read-only binds), `env` and the one hook NVIDIA's specs carry,
  `nvidia-cdi-hook update-ldcache` (below). Any other hook, and `intelRdt`, `additionalGIDs` it
  cannot honour and `cgroupsPath`-style edits, are refused by name (`E0227`). Zigbox never runs a
  host program from a spec.
- **Render nodes** (`--gpu dri`). Every `/dev/dri/renderD*` the user can open, and `/dev/kfd`
  when present (AMD ROCm). No libraries are mounted: Mesa and ROCm userspace come from the image,
  as they do under Docker.
- **A host device** (`--device /dev/<path>`, Docker's flag). A character device the user can
  open, bound at the same path. Block devices, and paths outside `/dev`, are refused (`E0225`).

**`--gpu all`** means every `nvidia.com/gpu` CDI device if a spec offers them, else `--gpu dri`.
It is refused (`E0228`) when there is neither, and `zbx doctor`'s GPU section is the fix.

### Inside the container

- Device nodes are bind-mounted into the container's `/dev` tmpfs at their CDI `path` (or the
  host path), next to M1's six. Nothing is made with `mknod`, which a user namespace cannot do.
  The mount limit grows by a bounded `run_devices_max` (16, with a comptime assert against the
  mount table).
- **Access is the host's file permissions.** A rootless container gets no device cgroup (it
  cannot attach the BPF program), so a node is reachable exactly when the user could open it on
  the host. NVIDIA's nodes are `0666`; render nodes are usually `0660 root:render`.
- **Supplementary groups survive.** A user in `render` or `video` keeps that access inside the
  container, in both id-mapping modes. With the single-id map, `deny_setgroups` already keeps the
  caller's groups. Slice 1 must prove the full-range map (`newgidmap`) keeps them too, and that
  no step calls `setgroups`. A test opens a `0660 root:<group>` node as a member. This is
  crun's `keep-groups` and podman's `--group-add keep-groups`, here by default for a run with
  devices. Inside, the groups show as `nogroup`; the report says so once.
- **Driver libraries (NVIDIA).** The CDI mounts bind the host's driver libraries (they must match
  the kernel driver, so they cannot come from the image). The `update-ldcache` hook becomes a
  built-in step: before the workload, the image's own `ldconfig` (`/sbin/ldconfig` or
  `/usr/sbin/ldconfig`) runs in the container against the mounted library directories, writing
  `/etc/ld.so.cache` in the upper layer. An image without `ldconfig` (musl images such as
  Alpine, which cannot load NVIDIA's glibc libraries anyway) gets `W0208` and the libraries'
  directories on `LD_LIBRARY_PATH` instead.
- **Seccomp.** The default filter already allows `ioctl` and `mmap`. Slice 1 runs a CUDA sample
  and records any syscall that the filter refuses. If one is needed, it is added only when
  devices are requested, and named in `docs/demos/m10.md`.
- `--read-only` rootfs: the `ldconfig` step writes to the run's `/run` tmpfs, with
  `LD_LIBRARY_PATH` as above, rather than refusing.

### Records, exec, doctor

- The run record keeps what was asked (`--gpu all`, the CDI names, the host paths), not what was
  resolved, so `zbx start` after a reboot resolves again. `zbx inspect` shows both.
  `zbx exec` into a running container sees its devices.
- **`zbx doctor` gains a GPU section:**
  - the CDI specs found, and any refused;
  - the devices each spec names, and whether this user can open each node;
  - the NVIDIA driver version (`/proc/driver/nvidia/version`);
  - the render nodes and `/dev/kfd`, with their modes and groups, and whether the user is in each;
  - the one-line fix for each gap (generate the spec, add the user to `render`).

  It is text and `--output json`, like the doctor's other sections.
- **The library.** `Spec` gains a bounded `devices` list of resolved edits (nodes, binds, env,
  ldconfig directories). Resolution (CDI parsing, `--gpu` expansion) is a separate pure function
  over file contents and a host listing, so Zigcube's CS4 can resolve on the agent and pass the
  result in. A test calls it from a caller other than the CLI.

### Not touched

- Builds. `zbx build` steps get no devices: a build stays hermetic (M7). Out of scope, not refused
  by design; a later brief can add it.
- Limits. There is no GPU memory or compute limit. MIG, MPS and time slicing belong to CS4.
- The Mac. Apple's virtualization framework gives a Linux guest no GPU compute. `--gpu` and
  `--device` on the Mac are refused with `E0229`, which names this.

## Diagnostics (`02xx`, runtime; each with cause, fix, goldens and an error page)

E0226, E0227, E0230 and W0208 are registered (slice 2).

- `E0225` a host device is refused: missing, not a character device, outside `/dev`, or the user
  cannot open it (with the node's mode and group, and whether the user is in that group).
- `E0226` a CDI spec cannot be used: YAML, unreadable, over a bound, or invalid (file, field,
  why).
- `E0227` a CDI device needs an edit Zigbox does not apply (the device, the edit).
- `E0228` `--gpu` found nothing to give (what was looked for; fix: `zbx doctor`).
- `E0229` devices are not available on this platform (the Mac).
- `E0230` an unknown CDI device name (lists the names that exist, up to a bound).
- `W0208` the image has no `ldconfig`; the libraries were put on `LD_LIBRARY_PATH`.
- `W0209` a run with devices keeps the user's supplementary groups (said once per run).

## Slices (commit and stop for review after each; do not push to the working branch)

1. **Host devices and groups.** `--device /dev/<path>`, `Spec.devices`, binds in `/dev`,
   `run_devices_max`, supplementary groups kept in both mapping modes (with a test for each),
   `E0225`, `W0209`, records and `inspect`, the goldens proving a run without devices is
   unchanged. The simulator models device binds and refuses a missing node. VM check
   (`vm/m10-slice1`): a `0660 root:render` node made by root in the guest, opened by a member
   and refused to a non-member. *Mechanical, for Haiku:* code registration, error pages,
   `zbx explain`, golden copying.
2. **CDI.** The JSON spec parser (bounded, fuzzed: a `cdi` fuzzer at 10,000 iterations that
   never crashes and whose every refusal is a registered code), spec discovery in the three
   directories, device names and `=all`, edits, the `ldconfig` step and `W0208`,
   `E0226`/`E0227`/`E0230`, and the resolution function with its second-caller test.
   VM check: a fake vendor spec (below).
   *Status: built; the spec size bound is 65535 bytes (the host read limit), not 256 KiB, and the
   codes are registered. Notes: `docs/decisions/2026-11-12-m10-slice2-cdi.md`, `docs/demos/m10.md`.*
3. **`--gpu`, doctor and the real GPU.** `--gpu all|dri`, `E0228`, `E0229` on the Mac, doctor's
   GPU section (text, JSON, goldens over fixture hosts), and the real-hardware run (below).
4. **VM, CI, docs.** `zig build demo-m10` as below, `checks_m10.zig`, the CI job and its path
   rule (with a table-test row), `docs/demos/m10.md` (by-hand steps for NVIDIA, AMD and Intel,
   cuts, failure modes: a driver upgraded under a stopped container, a user not in `render`, a
   YAML spec, an Alpine image with NVIDIA). *Mechanical:* `m10` in `vm.yml`'s picker and `all`
   list, the demo-table entry, the CI job copied from an existing demo's.

## The demo: `zig build demo-m10`

CI's runners have no GPU, so the VM demo proves the plumbing with a **fake vendor**. Inside the
guest, root makes `/dev/zbxgpu0` (a character device with `/dev/zero`'s numbers, `0660
root:render`), a "driver" directory `/opt/zbxgpu/lib` holding `libzbxgpu.so.1` (any small
glibc-built shared object), and `/etc/cdi/zigbox.test.json`, a CDI spec for `zigbox.test/gpu=0`
with that node, a bind of the directory, `ZBXGPU=1`, and an `update-ldcache` hook. The ordinary
user is in `render`.

1. `zbx doctor` lists the spec, `zigbox.test/gpu=0`, and the node as openable.
2. `zbx run --device zigbox.test/gpu=0 debian:12 -- sh -c 'head -c 4 /dev/zbxgpu0 | od -An -tx1;
   echo $ZBXGPU; ldconfig -p | grep libzbxgpu'` prints `00 00 00 00`, `1`, and the library.
3. The same with `--gpu all` and no spec for `nvidia.com`: `E0228`. With `--gpu dri` and the
   guest's virtio-gpu render node (QEMU's `virtio-gpu-gl` if the runner allows it, else cut and
   recorded): `ls /dev/dri` in the container shows it.
4. A user removed from `render`: `E0225`, naming the group.
5. A YAML spec beside the JSON one: `E0226` for it, with the `--format=json` fix; the JSON
   device still works.
6. An Alpine image with the fake device: `W0208`, and `LD_LIBRARY_PATH` holds the directory.
7. `zbx run` without devices: the run record and the JSON output equal `demo-m2`'s goldens.

**The real GPU** (slice 3, recorded in `docs/demos/m10.md`, not part of `demo-m10`): on a cloud
AWS `g4dn.xlarge` (see the owner decisions), with the driver and `nvidia-ctk` installed
and the spec generated as JSON, as an ordinary user:
`zbx run --gpu all docker.io/nvidia/cuda:12.6.3-base-ubuntu24.04 -- nvidia-smi` prints the GPU,
and a CUDA sample (vector add, from the `devel` image's samples or a checked-in `.cu` built in a
`zbx build` step) computes the right answer. AMD by hand if a machine is at hand; cuttable.

## Non-goals

- Zigcube's GPU scheduling, sharing, MIG, MPS and gang scheduling (CS4).
- GPU memory or compute limits, and per-GPU accounting in `zbx stats`.
- GPUs in `zbx build` steps.
- The Mac, Windows and WSL.
- Running hooks from CDI specs (other than the built-in `ldconfig` step), YAML specs, and
  NVIDIA's legacy `nvidia-container-runtime` and `NVIDIA_VISIBLE_DEVICES` environment protocol.
- Docker's `--gpus` flag syntax beyond `all` (`--gpus '"device=0,1"'`): CDI names do this.
- Block devices, `--device-cgroup-rule`, and `--privileged`.

## Scope that can be cut while keeping the demo

Record any cut in `docs/demos/m10.md`.
- **`--gpu dri`'s VM check**, if no runner offers a render node to the guest. Keep the unit tests
  and the by-hand AMD/Intel steps.
- **`$XDG_CONFIG_HOME/cdi`**: the system directories only.
- **`--read-only` with devices**: refuse the combination instead.
- **The AMD real-hardware run.**

Not cuttable: rootless access by file permissions with no device cgroup, supplementary groups
kept, JSON CDI, the built-in `ldconfig` step, and the real NVIDIA run.

## Owner decisions (settled 2026-11-11)

1. **A real GPU to test on:** an AWS `g4dn.xlarge` (one T4, about $0.53/hour on demand in
   us-east-1) under the account set up for M6c, started by hand for slice 3 and stopped after.
   G instances may need a vCPU quota increase; the supervisor asks the owner before slice 3.
2. **NVIDIA first; AMD and Intel by render nodes only.** ROCm-specific work (e.g.
   `HSA_OVERRIDE_*`) is left out.
3. **Supplementary groups are kept by default** for a run with devices, with no flag.
4. **The milestone is M10**, after M9, with no dependency between them.

## Spec notes (flagged, not changed)

- SPEC.md lists GPU passthrough as a non-goal. The parity decision overrides that for Zigbox
  containers; the next spec sync adds M10.
- M1's "minimal `/dev`" gains the requested devices; the spec could say "minimal `/dev`, plus
  devices the user asks for".
- Spec "no libc" is unaffected: Zigbox mounts libraries and runs the image's `ldconfig`; it loads
  nothing itself.
