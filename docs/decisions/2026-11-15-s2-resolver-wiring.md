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

## Done since (second 5a implementer)

- Tests: `fuse/resolver_tests.zig` covers `catalog_of` (agrees; an index object made with
  another mode; another content) and `ResolverChunks` through `ops` over the simulated store.
  A lie in the *tree* cannot be tested: `nodes.Table.new_node` already refuses a node whose
  attributes do not give its object id, so the mode test lies in the index's ids.
- Registry `Range`: `net.Request.range_last` (`Range: bytes=a-b` in `host_real_net.zig`),
  `client.fetch_range` (a 206 whose `Content-Range` starts at the offset asked, or no bytes), and
  `lazy/registry_range.zig`: a `lazy.Range` over one client. **Fetches are serialized** (one
  client: one token and one wire state); a thread waits its turn at most its `timeout_ms`, and the
  wait comes off its fetch's time. Tests in `lazy/registry_range_test.zig` (threads included).
- `lazy_start.zig`: `start(host, pull, ws, store, text, warn, image, diag)` parses and resolves
  the reference (`pull.resolve_with`, now `pub`), and with no anchor wipes the client, gives
  W1201 to `warn` and returns `.whole`. Else: no `org.zigbox.tree` is E1202; fetches the config
  (`pull.fetch_settings`, new), fetches the index range by `fetch_range`, inflates, checks the
  hash, `verify.verify` (E1202 for each, nothing written; `TooLarge` is E1207), stores the trees
  with `trees.put_checked`, and fills an `images.Image` in memory. The client stays resolved for
  the run; `finish(pull)` wipes it.
- `run_image.prepare`: `Services.lazy: ?*lazy_start.Workspace` (null by default; **nothing sets
  it yet**), `Prepared.remote`. `lazy_remote` runs `start` only when the image is not local (a
  digest reference with no record; a lock pin with no record; or no lock, then the operand as
  given: no `zbx.lock` is written for a remote lazy run, a cut).
- Codes W1201, W1202, E1203, E1206 registered with the brief's wording, goldens
  (`fuse/diagnose.zig`: `no_index`, `index_refused`, `chunk_lied`, `chunk_unavailable`,
  `store_full`) and errors-site pages. `can_end_run` was left at its default for them.

## Not done; what is next in 5a

1. **Wire the CLI** (`cli.zig`, `main.zig`): a static `lazy_start.Workspace` in `main.zig`
   (about 160 MiB, mostly untouched), set `Services.lazy` in `prepare_image` only for
   `run --lazy` in the foreground with a `lazy_server`. When `prepared.remote`: init `ws.range`
   (`RegistryRange.init(&ws.client, &pull.library.reference, ws.layer, server.threaded.io())`),
   then `server.attach(.{ .index = &ws.index, .registry = ws.range.source(), .log, .free })`
   before `prepare_from`, and `lazy_start.finish(&storage.pull)` after the run. On `.whole`, pull
   as without `--lazy` (the usual path: `remote` false falls through to `via_lock`/digest).
   Check that the composed run resolves the tree from the in-memory `image` (compose reads the
   image record today; the record is 5b, so compose may need the `Image` passed in), and that
   `choose_user` (reads `/etc/passwd` from the store) works for a remote image or is cut.
2. The `lazy.Log` (new module, e.g. `lazy_lines.zig`): an atomic shown counter, at most
   `lazy_errors_shown_max` lines rendered with `render.render` to stderr, then one count line;
   W1202 through `chunk_lied`, E1203 through `chunk_unavailable` (each `Outcome.text()` joined),
   E1206 through `store_full`. The lines name the object id and chunk, not the path (the catalog
   has no path): record that cut in `docs/demos/s2.md`. `lazy.FreeBytes` over `statfs` of the
   store's directory: `host_real.zig` has a private `StatFs` and `syscall2(.statfs)`; add a
   `free_bytes(path)` there and pass it through a `cli` `pub var` set by `main.zig`.
3. Progress line before the run and summary line after it, from `server.report()`.
4. VM: `src/testing/vm/registry_server.zig` parses only `bytes=N-` (`range_start`) and the
   fixture answers only `range_from`: it needs closed ranges before `demo-s2-lazy` can pass. Push
   `HEAD:vm/s2lazy-slice5-a` (vm.yml maps `vm/s2lazy-*` to `demo-s2-lazy`).

## 5b (next implementer after 5a)

Image record v4 `partial`, run record `lazy`, `ps`/`inspect` JSON, `gc`/`verify` of partial
images, holders, the `zbx doctor` line, `StartOptions.lazy_sources` and its surface test.

## Traps

- `lazy` is both an imported module and a `Server` method name in `lazy_server.zig`; the import
  is `lazy_mod` there.
- `catalog_of` is not reached by the compiler until something calls `attach`: build errors in it
  appear only when the CLI path or a test uses it.
- Goldens of direct cases have no generator: write the files empty, print `direct_block` from a
  throwaway test, and copy the blocks in (as done for the four new codes).
- `zig build test` has no filter and takes several minutes: run it in the background.
