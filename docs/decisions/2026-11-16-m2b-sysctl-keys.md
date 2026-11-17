# M2b: the sysctl allowlist, checked key by key

*Decided 2026-11-16, by the slice (M2b slice 1), from a measurement.*

The M2b brief ([item 4](../briefs/M2b-workload-knobs.md)) lists 28 candidate keys for
`src/runtime/policy/sysctls.zon` and asks for each to be verified in the VM: per-namespace on its
kernel, and writable from the container's user namespace. A key that fails drops out.

## How it was checked

`demo-m2b-probe` ([run 43931483466](https://github.com/Zigbox/zigbox/actions/runs/43931483466)), Ubuntu 24.04, kernel 6.8.0-147-generic. As the ordinary
user `demo`, the probe entered `unshare --user --map-root-user --net --ipc` and, for each key,
read `/proc/sys/<key>`, wrote a value different from the host's, and read it back (these sysctls
resolve to the writer's own namespaces). It then checked that every host value was unchanged. For
the `net` keys it also wrote the values in a fresh user and network namespace, attached `pasta`
to it about 2 s later, and read them again after 6 s.

## Result

- All 28 keys passed: the write succeeded inside the namespace, the value read back, and the
  host's value did not change. No key drops out.
  - **ipc (13):** `kernel.shmmax`, `kernel.shmall`, `kernel.shmmni`, `kernel.shm_rmid_forced`,
    `kernel.msgmax`, `kernel.msgmnb`, `kernel.msgmni`, `kernel.sem`, `fs.mqueue.msg_max`,
    `fs.mqueue.msgsize_max`, `fs.mqueue.queues_max`, `fs.mqueue.msg_default`,
    `fs.mqueue.msgsize_default`.
  - **net (15):** `net.ipv4.ip_local_port_range`, `net.ipv4.ip_local_reserved_ports`,
    `net.ipv4.ip_unprivileged_port_start`, `net.ipv4.ping_group_range`,
    `net.ipv4.tcp_syncookies`, `net.ipv4.tcp_keepalive_time`, `net.ipv4.tcp_keepalive_intvl`,
    `net.ipv4.tcp_keepalive_probes`, `net.ipv4.tcp_fin_timeout`, `net.ipv4.tcp_rmem`,
    `net.ipv4.tcp_wmem`, `net.core.somaxconn`, `net.ipv4.tcp_max_syn_backlog`,
    `net.ipv4.tcp_tw_reuse`, `net.ipv6.conf.all.disable_ipv6`.
- **pasta** (Ubuntu's passt 0.0~git20240220) kept all 15 `net` values. It sets addresses and
  routes, not sysctls, so writing them before pasta attaches is safe.

## Notes for the implementation

- `net.ipv4.ping_group_range` reads back through the user namespace's id map. On the host it is
  `1 0`; inside, the unmapped ids show as `65534 65534`. A written value names ids as the
  container sees them, so a range outside the map is refused by the kernel (`EINVAL`, E0318).
- `net.core.somaxconn` already defaults to 4096 on this kernel (4096 since Linux 5.4). The
  brief's demo step 3, which sets it to 4096, would pass with the knob doing nothing; the demo
  should use 8192.
