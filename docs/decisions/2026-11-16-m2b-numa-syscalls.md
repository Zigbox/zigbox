# M2b: the NUMA syscalls the seccomp profile allows

*Decided 2026-11-16, by the slice (M2b slice 1), from a measurement.*

The M2b brief ([item 3](../briefs/M2b-workload-knobs.md)) adds `mbind`, `set_mempolicy` and
`set_mempolicy_home_node` to the seccomp profile and keeps `move_pages` and `migrate_pages`
out, on the condition that real NUMA-aware servers never call the last two at start-up. This
file records that check.

## The measurement

Run on the VM host, outside zbx, by `demo-m2b-probe` ([run 43931483466](https://github.com/Zigbox/zigbox/actions/runs/43931483466)): Ubuntu 24.04,
kernel 6.8.0-147-generic, one NUMA node (`numactl --hardware`: node 0, CPUs 0 and 1). Each
server ran under `strace -f -e trace=mbind,set_mempolicy,set_mempolicy_home_node,get_mempolicy,move_pages,migrate_pages`
for the stated time.

| Server | Calls seen |
| --- | --- |
| `mariadbd --innodb-numa-interleave=1` (MariaDB 10.11.14, Ubuntu) | 2 `get_mempolicy`, 2 `set_mempolicy` (`MPOL_INTERLEAVE`, then `MPOL_DEFAULT`), 1 `mbind` (128 MiB, `MPOL_INTERLEAVE`) |
| `numactl --interleave=all mongod --version` (MongoDB 8.0.12) | 1 `set_mempolicy` (`MPOL_INTERLEAVE`, from numactl), 1 `get_mempolicy` |
| `numactl --interleave=all mongod`, 30 s | 1 `set_mempolicy`, 1 `get_mempolicy` |
| `clickhouse server`, 40 s | 8 `get_mempolicy` |

No server called `move_pages`, `migrate_pages` or `set_mempolicy_home_node`.

## The decision

- Allow `mbind`, `set_mempolicy` and `set_mempolicy_home_node`, as the brief says.
  `get_mempolicy` is already allowed.
- Keep `move_pages` and `migrate_pages` denied. Nothing measured needs them, so the brief's
  stop-and-ask condition did not arise.
- Zig's `std.os.linux.SYS` names all three new calls on both release targets: x86_64 `mbind`
  237, `set_mempolicy` 238, `set_mempolicy_home_node` 450; aarch64 235, 237 and 450. No number
  is hard-coded.

## Limits of the measurement

- The guest has one NUMA node. The calls a server makes do not depend on the node count here
  (MariaDB and numactl call `set_mempolicy` and `mbind` regardless), but a multi-node host was
  not tried.
- MongoDB's own start-up does not set a policy; `numactl` does it before `execve`. Under zbx,
  that `set_mempolicy` happens inside the container, so it needs the new allow entry.
