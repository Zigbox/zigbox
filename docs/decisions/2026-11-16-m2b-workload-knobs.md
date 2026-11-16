# M2b · Workload knobs: what is built, parked and ruled out

*Decided 2026-11-16, by the owner (scope) and the supervisor (defaults).*

## The owner's choice

M2b extends M2 so that the common server workloads people run on Kubernetes start under zbx without hacks. Of the ten items considered, the owner chose:

**Build (M2b):**

1. **rlimits:** `--ulimit nofile|nproc|memlock|stack=SOFT[:HARD]`, set in the child before `execve`, bounded by the invoking user's hard limits. A request above them is refused with one coded line naming the host fix, never clamped. The default stays "inherit".
2. **`/dev/shm` size:** `--shm-size`, counted against the memory cgroup, refused above `--memory`. Today `/dev/shm` is a fixed 64 MiB tmpfs.
3. **NUMA memory policy in the default seccomp allowlist:** `mbind`, `set_mempolicy` and `set_mempolicy_home_node` (`get_mempolicy` is already allowed). The cases are MySQL/MariaDB (`mbind: Operation not permitted`), `numactl --interleave` for MongoDB, and ClickHouse.
4. **Namespaced sysctls:** `--sysctl key=value` from an allowlist of per-namespace keys (per-netns `net.*`, refused with `--net host`; `kernel.shm*`, `kernel.msg*`, `kernel.sem`, `fs.mqueue.*`). Any other key is refused as a host setting.
5. **Host-setting preflight:** a run declares a minimum for a non-namespaced host setting (`vm.max_map_count`, `fs.aio-max-nr`, `vm.overcommit_memory`, transparent huge pages) and is refused before start with the fix; `zbx doctor` reports the same settings.
7. **cgroup namespace:** the container gets its own cgroup namespace rooted at its scope and a read-only cgroup2 view at `/sys/fs/cgroup`, so the JVM, Go, .NET and Node size heaps and threads from `--memory` and `--cpus`.

**Park (an open question in the spec, not M2b):**

6. Adding capabilities from a short list (`IPC_LOCK`, `NET_ADMIN` and `NET_RAW` in the container's own netns, `SYS_NICE`). Motivation: Vault (`mlock`), ClickHouse, VPNs and service-mesh init containers. Related gap: `--device /dev/net/tun` is accepted today but unusable without `NET_ADMIN`; it should be documented or refused.

**Non-goals (added to the spec's Non-goals):**

8. **io_uring.** An opt-in was considered and declined because of the kernel attack surface it exposes; Docker's and containerd's default profiles and Google's production systems all block it.
9. **CPU pinning (cpuset), `io.max`/`io.weight` limits and hugepages/hugetlb.** Seastar-style databases (ScyllaDB, Redpanda) are not a target.
10. **Nested containers.** `unshare` and `clone` with namespace flags, `mount`, `/dev/fuse` inside a container, Docker-in-Docker and rootless BuildKit inside zbx.

## Supervisor defaults

- **Codes:** `E0575`–`E0589`, the next free block of at most 15 after `E0574` (the end of M6d's reservation). The registry's numbering puts limits in `03xx`. This block is in `05xx` (registry and pull) because the supervisor said "after E0574". The brief raises this for the owner to confirm.
- **Defaults:** nothing changes by default except the seccomp NUMA addition. The cgroup view (item 7) has no flag. Every scoped run gets it, because that is the point of the item. The brief lists it for the owner to confirm as a change in what a container sees.
- **Release:** M2b targets 0.6.x. It does not block 0.5.2, M6d or S2.
- **Library:** the `zigbox` module exposes the same knobs on `Spec` (field names in the brief), so Zigcube can pass them later and use the host settings for placement.
- **Ask first:** an implementer stops and asks before anything that alters a user-visible bound, limit or default beyond the above.

## Evidence recorded while writing the brief

- **Docker's default seccomp profile (moby/profiles, `main`, 2026-11-16):**
  - `mbind`, `get_mempolicy`, `set_mempolicy` and `set_mempolicy_home_node` are allowed only in a block gated on `CAP_SYS_NICE`. A default `docker run` does not have that capability, so these calls fail with `EPERM` there too. The usual fix is `--cap-add SYS_NICE`.
  - `move_pages` and `migrate_pages` are not in the profile at all.
  - zbx already allows `get_mempolicy` without the capability. M2b allows the other three the same way. The kernel still checks `CAP_SYS_NICE` itself for the one privileged part (`MPOL_MF_MOVE_ALL`), so allowing the calls grants no capability.
- **`move_pages` and `migrate_pages` stay out.** Neither Docker nor containerd allows them. None of the motivating workloads needs them to start: they set a policy with `set_mempolicy` or `mbind`, and do not move existing pages. Both calls can also act on another process's pages. The brief's slice 1 confirms this with `strace` on the VM host, and the decision is reopened only if that finds a call.
- **What zbx gives a runtime today:**
  - There is no cgroup namespace.
  - With the default isolated network, `/sys` is a fresh read-only sysfs, so `/sys/fs/cgroup` is an empty directory and `/proc/self/mountinfo` has no cgroup2 entry.
  - With `--net host`, the host's `/sys` is bind-mounted read-only and recursively, so the host's whole cgroup tree is visible, and `/proc/self/cgroup` shows the full host path of the scope.
  - The brief's slice 1 measures what each runtime then does, and records it in a decision file.

Detail: `docs/briefs/M2b-workload-knobs.md`; spec: `docs/SPEC.md`, "M2b · Workload knobs", "Non-goals" and "Open questions".
