# Z4: the image record of a tree, to and from a peer
*Decided 2026-11-04, by the Z4/Z6 slice.*

`store.export_image(store, memory, tree, out, failure)` gives the text of the newest image record whose tree is `tree`; `store.import_image(store, memory, text, tree, options, failure)` takes such a text from a peer for a tree that is whole here. Both are in `src/store/image_peer.zig`; its file comment lists the checks and their order.

- **Checks, in order:** size (`image_record_bytes_max`), parse (malformed, newer format), the record names `tree`, then, under the shared store lock, every tree and object below `tree` is present and sound (`walk.objects`, bounded by `entries_max` and `image_import_stack_max`). A refusal writes nothing. It carries a `Refusal` and raises one coded diagnostic, `ZBX-E0437`, through `diagnose.image_refused` (a busy store and a failing write keep their existing codes).
- **What is kept:** the settings, platform, config, layers and manifest of the record; the time is the local one (a peer's clock is not trusted); **tags are dropped by default** (`TagPolicy.drop`), because a tag a peer names would otherwise move a local reference. A caller that trusts the peer passes `.keep`.
- **Roots:** the image record keeps its tree for gc (`reach_images`); a root record (kind `import`, source `peer`) is written too if none exists, so `zbx store` lists the tree with a reason.
- **Idempotent:** the same record again changes nothing. The same manifest with another tree is `conflict` (the record is left as it was); a damaged or newer local record is `local_unusable`, never overwritten.
- **Found while doing it:** `images.parse` accepted a record with an empty platform (which `render` asserts against) and a repeated key standing in for a missing `.tree`. Both are `malformed` now; a text from a peer reaches no assertion.
- **`zbx run`:** `name@sha256:<manifest>` finds the record directly; `name:tag` goes through `zbx.lock`, so a caller that wants `run <tag>` passes `.keep` or writes the lock. Run in the VM, not here.

Fuzzed by `zig build fuzz -- peer` (property 5). Tests: `src/store/image_peer_tests.zig`.
