# Z9: `read_chunk` outside the store's namespace
*Decided 2026-11-04, by the Z9 slice.*

**The bug.** Zigcube's peer server has threads, so it cannot run in the store's namespace child and calls `read_chunk` outside it. For an object of one chunk, `id_holds` rebuilds the object id from `lstat`'s uid and gid, and outside the namespace those are host ids (the user's own, or one of its subordinate range, such as 100041), while the id commits to the container's ids (0, 42). So every one-chunk object owned by a container id other than the user's own mapped to 0 was refused as `Damaged`; `etc/shadow` (0:42, mode 0640) is one in every real image. Objects of several chunks were fine: their chunks are checked against the stored list, which does not hold the owner.

**Decision: option (a), map the owner back through the store's id map.** The store gets a field, `Store.owners` (`src/store/owners.zig`):

- `.inside` (what `Store.at` and `Store.locate` set): the reader is in the namespace and `lstat` gives the container's ids, so nothing changes for any `zbx` command, which all run in the child.
- `.outside = Map{ uid, gid, range }`: the store's map seen from the host, the one `namespace.run` writes (`0 own 1` and, with the full map, `1 start 65536`). A reader outside computes it once with `store.namespace.outside_owners(host, &facts)` (returns `.map` and `.fallback`), which calls the same `ids.choose` that `run` does, so the two cannot disagree. `owners.container_id` maps each host id back: the user's own id is 0, `start + n` is `n + 1` for `n < subid_range_min`; any other host id has no container id.

An owner the map does not reach makes `id_holds` false, so the read is `Damaged` and `out` is zeroed, never a guess. We kept `Damaged` rather than a new error: a reader inside the namespace sees such a file as the overflow id (65534), which the id of a store object almost never commits to, and so refuses it as `Damaged` too, and Zigcube's switch over `chunk_read.Error` needs no change.

`read_chunk`'s signature is unchanged. `doctor.Facts` is exported as `zigbox.Facts` (large: static storage or the heap). Zigcube's adapter, after it opens the store, has this line:

```zig
const outside = zigbox.store.namespace.outside_owners(host, &facts);
store.owners = .{ .outside = outside.map }; // and log W0201 if `outside.fallback`
```

(`facts` is a `zigbox.Facts` it owns, as for `run`.) Without it the reader behaves as before the fix.

**Why not (b), the caller passes the tree entry's attributes.** It would also work, but it changes the signature Zigcube calls, makes every caller find and carry the entry, and the store already knows its map from outside: it is a function of the user's ids and the subordinate range, which is all `run` needs to write it.

**Limits.** `outside_owners` returns the one-id map whenever `ids.choose` falls back (W0201): the range moved, or `newuidmap`/`newgidmap` is missing or not setuid (`doctor.subid_answer`). Then only one-chunk objects owned by container root (0:0) verify; others read `Damaged` (it fails closed). `Outside.fallback` is true in that case so the caller can log it. The map is today's: if the user's subordinate range moved since the store was written, objects owned through the old range no longer map and read as `Damaged`, as they would read inside a namespace with the new map. The owner of an object of several chunks is still not checked by `read_chunk` (it never was; the list does not hold it).

**Out of scope: the second gap.** A peer server that is not root cannot open any object whose mode does not let the reader's host user read it, including mode 0000 files owned by container root (Fedora and RHEL ship `/etc/shadow` and `/etc/gshadow` so): inside the namespace root has `CAP_DAC_OVERRIDE`, outside the plain user gets `EACCES`, so `read_chunk` fails with `Unreadable`. The same holds for mode 0640 or 0600 objects owned by an id of the range (on the host, say 100041). Root agents are unaffected. Zigcube's demo runs its agents as root, where this does not arise, so it is left unfixed. A fix needs a reader inside the namespace: per Z6, a single-threaded store reader started by re-exec that calls `namespace.run` and serves chunk reads to the threaded server over a pipe or socket pair (one request, one verified chunk or an error code back), with `Store.owners` left `.inside` there. Opening the file inside and passing the descriptor back (`SCM_RIGHTS`) would avoid the copy but needs the same child.

See `src/store/owners.zig`, `src/store/chunk_read.zig` and the tests in `src/store/zigcube_api_tests.zig`.
