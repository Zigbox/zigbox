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

## Done since (third 5a implementer)

- CLI: `main.zig` holds a static `lazy_start.Workspace` and sets `cli.lazy_workspace` and
  `cli.free_bytes` (`host_real.free_bytes`, statfs `f_bavail * f_bsize`). `prepare_image` sets
  `Services.lazy` only for `run --lazy` in the foreground with a `lazy_server`
  (`lazy_workspace_of`). `check_lazy` runs before `prepare_operand`. `run_foreground` takes a
  `Lazy` (`none`, `local`, `remote`); on `remote`, `attach_remote` inits `ws.range` and calls
  `server.attach` with the index, the registry source, the log, the free bytes and `started`;
  `lazy_finish` prints the summary, finishes the server and wipes the client.
- `compose` reads the in-memory `Image`, so nothing was needed there. **A named `User` of a
  remote image is cut** (`choose_user` reads `/etc/passwd` from the store: E0521); numeric works.
- `lazy_lines.zig`: `Lines` (the `lazy.Log`), at most `constants.lazy_errors_shown_max` (16, the
  brief's value) lines, then "lazy: N more lines not shown" in the summary; progress line
  (printed once, from `Remote.started`) and summary line. `Event` gained `id` and `names`;
  `Report` gained `bytes_local` and `bytes_total` (`schedule.zig`).
- VM fixture: `registry_server.zig` parses `bytes=a-b`; the fixture answers closed ranges (206,
  even from 0; 416 past the end).
- Cuts recorded in `docs/demos/s2.md` under "5a: what a remote lazy run does, and the cuts".

## Not done; what is next

1. `can_end_run` for E1203/E1206: asked the supervisor (recommended false: a run that got EIO
   still ends); left at the default until answered.
2. A remote lazy run in a VM demo: no fixture serves a layer-writer-2 image; first live run is
   `demo-s2` (slice 6).
3. Lines naming the path, not the object id (map an object to a node path).
4. Fetch `/etc/passwd` and `/etc/group` through the resolver before the start, for a named `User`.

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
