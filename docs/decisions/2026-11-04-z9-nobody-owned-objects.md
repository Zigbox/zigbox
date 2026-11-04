# Z9 correction: objects owned by nobody (65534)
*Decided 2026-11-04, by the 0.3.1 review fixes.*

This corrects one sentence of [2026-11-04-z9-chunk-read-outside.md](2026-11-04-z9-chunk-read-outside.md), which stays as merged. That decision says that a reader inside the namespace sees a file the id map does not reach as the overflow id (65534), "which the id of a store object almost never commits to", and so refuses it as `Damaged` too. That is wrong: some images ship files owned by nobody (65534), and the ids of their objects commit to 65534.

**What holds instead.** With the full map, container id 65534 is inside the subordinate range (`subid_range_min` is 65536), so a file owned by nobody maps both ways and reads the same inside the namespace and outside it. The two readers differ only when the object's host owner is outside today's map (the subordinate range moved, or `ids.choose` fell back to the one-id map, W0201): inside, `lstat` shows the overflow id 65534, which is what the id commits to, so the read succeeds; outside, the owner has no container id and the read is `Damaged`. The outside reader still fails closed: it never accepts an object the inside reader would refuse.

Nothing else in the Z9 decision changes: `read_chunk` keeps `Damaged` for an owner the map does not reach, and Zigcube's switch over `chunk_read.Error` needs no change.
