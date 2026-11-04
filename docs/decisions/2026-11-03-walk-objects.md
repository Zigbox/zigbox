# `walk.objects`: a bounded walk of a tree's objects
*Decided 2026-11-03, by the Z1/Z5 slice.*

Z2 allowed a walk or a public `has` plus `chunks`; both exist. `walk.objects(store, buffer, stack, visited, root, visitor, entries_max, failure)` visits each distinct object once (no recursion, explicit stack, `visited` bounds it) and calls `visitor.object(*const ObjectRef)` with `{id, size, content, chunk_count}`; the walk stops at `entries_max`. Exported as `store.walk_objects`, with `has_object` and `has_tree`.

See `src/store/walk.zig`.
