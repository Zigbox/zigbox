# S2 slice 5a: the resolver behind the lazy FUSE server (first part)

*Decided 2026-11-15, by the slice (S2 slice 5a, first implementer; the 5a/5b split and the codes by the supervisor).* In progress: a handoff for the next 5a implementer.

## Done (branch `claude/s2-slice5`)

- `fuse/resolver.zig`: `ResolverChunks` serves `ops.Chunks` reads through `lazy.Resolver.read`
  (ordinal and object id asserted against the catalog). `catalog_of(table, index, memory)` builds
  a `lazy.Catalog` from the node table and a verified index: for each file node, the `Wanted`
  attributes come from the node (mode `& 0o7777`, uid, gid, xattrs), the content from the index
  (0 chunks: the empty digest; 1: the chunk hash; 2 or more: the chaining values joined), and the
  object id computed from them must equal the index's (else `error.Malformed`, raised as E1202).
- `fuse/lazy_server.zig`: `Remote{index, registry, log, free}` and `Server.attach(remote)` before
  `prepare_from`. With a remote, `prepare_from` builds the catalog (E1202 when it disagrees,
  E1201 when memory runs out) and inits the resolver with `fill = false` and no peers; `serve`
  points each serving thread's chunk source at a `ResolverChunks` and starts the resolver before
  the threads. `finish` stops the resolver between `serving.stop()` and `serving.wait()`, so a
  reader blocked in `Resolver.read` wakes with `Stopped`. `report()` gives the summary's numbers.
- Codes E1201 and E1202 registered with the brief's wording (supervisor approval 2026-11-15),
  with explanations and goldens built from `fuse/diagnose.zig` directly. `codes.Code` is now
  `enum(u16)`: the registry had reached 256 entries.

## Memory

The catalog's arrays (`objects`, and per chunk a hash and a location) are allocated from the page
allocator in proportion to the verified index: at most `lazy_nodes_max` objects and the index's
chunk count. No bound or default changed.

## Not done; what is next in 5a

1. Nothing calls `Server.attach` yet: the CLI still serves only images whole in the store.
2. The registry Range client: `net.Request` has only `range_from` (`Range: bytes=N-` in
   `host_real_net.zig`); it needs a closed range (`bytes=a-b`) and a 206 check, then a
   `lazy.Range` implementation over `registry/client.zig` that is safe from several resolver
   threads (one connection and token per thread, or a lock), honouring `timeout_ms`.
3. `zbx run --lazy <registry ref>` when the image is not local: manifest, the layer's
   `org.zigbox.lazy-index` anchor (`manifest.zig`), fetch the index range, inflate, `verify.verify`
   (E1202 on refusal, nothing written), `trees.put_checked`, then serve the tree digest
   (`runtime/image.zig` `resolve_image` takes a digest prefix naming a tree) with the `Remote`
   attached. No anchor: W1201 and a whole pull.
4. A `lazy.Log` that renders W1202, E1203 and E1206 as one coded line each, at most
   `lazy_errors_shown_max`, then a count; a `lazy.FreeBytes` over `statfs` of the store; the
   progress and summary lines from `report()`. Register W1201, W1202, E1203, E1206 (and E1204
   where it applies) only as each is raised, with the brief's wording.
5. Tests: `catalog_of` (agrees, disagrees by mode and by content) and `ResolverChunks` through
   `ops` over the simulated store; then the VM run (`vm/s2-slice5`, `demo-s2-lazy`).

## 5b (next implementer after 5a)

Image record v4 `partial`, run record `lazy`, `ps`/`inspect` JSON, `gc`/`verify` of partial
images, holders, the `zbx doctor` line, `StartOptions.lazy_sources` and its surface test.

## Traps

- `lazy` is both an imported module and a `Server` method name in `lazy_server.zig`; the import
  is `lazy_mod` there.
- `catalog_of` is not reached by the compiler until something calls `attach`: build errors in it
  appear only when the CLI path or a test uses it.
