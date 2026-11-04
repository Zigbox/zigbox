# Review fixes for Z1–Z5 (2026-11-04)

- `read_chunk` opens the object before it reads the chunk list; a list that is missing is then
  `NotFound` if the object is gone (a gc took it) and `Damaged` if the object is still there.
- Attribute gathering lives in `xattrs.Scratch` (about 150 KB, bounded by the xattr constants).
  The caller passes it in, so a server keeps one per thread; `verify` shares the same code.
- `pull.Result` copies each blob's digest, bytes and outcome (`Result.blobs`) instead of
  pointing into the caller's data, so it outlives the callbacks.
- `walk.objects` stops with `damaged` on a file entry longer than `chunk_bytes * chunks_max`.
  The tree decoder does not know the store's chunk size, and the peer fuzzer found that such an
  accepted tree made the walk assert in the chunk count.
- `SimFs` has a `shrink_on_open` fault (the file is cut after `lstat`, before the read) to test
  the `got != length` refusal.
