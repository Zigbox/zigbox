# `read_chunk`: what a verified read checks
*Decided 2026-11-03, by the Z1/Z5 slice.*

`read_chunk(store, io, id, index, out) Error!usize` returns bytes only if they hash right; on any error `out` is zeroed, so unverified bytes never leave (a partial read followed by an error once did, see the regression test). A multi-chunk object is checked against the BLAKE3 hash in its `<id>.chunks` list. A single-chunk object has no list, so its chunk hash is its content hash, which the object id does not contain (the id hashes a header of content hash, mode, uid, gid, xattrs). The id is the only anchor, so `id_holds` recomputes the id from the bytes plus the object metadata and refuses a mismatch. That needs a large stack frame; accepted, it is bounded by `chunk_bytes`. Callers pass `io` of at least `store_chunks_max * 32` bytes and `out` of at least `chunk_bytes`; both are asserted.

See `src/store/chunk_read.zig`.
