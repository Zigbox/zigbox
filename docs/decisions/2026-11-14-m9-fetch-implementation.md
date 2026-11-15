# M9 slice 3b: how a pinned fetch is built

*Implementer, 2026-11-14. Open for the supervisor's review.*

- **The download** (`src/build/fetch.zig`) uses the host's `net.Net` directly with
  `client.follow` for redirects, not `client.Client`: a fetch has no registry auth or mirrors.
  `client.is_redirect` became `pub` for it. The bytes stream into `blobs/partial/<hex>`, hashed
  as they arrive, then fsync, rename to `blobs/sha256/<hex>` and fsync the directory. A present
  `blobs/sha256/<hex>` is never asked for.
- **E0821's wording**: the default view shows only the last cause, and a field holds 200 bytes,
  so the last cause names the URL and the received hash, and the first fix names the pinned hash.
  The full cause chain and `expect`/`actual` contexts are in `--verbose`.
- **A blob that no longer hashes to its name** when it is imported (`src/build/fetch_tree.zig`)
  is `E0511`, the code a pull uses for the same damage, rather than a new code.
- **The key** of a fetch entry: `key.Copy.fetch` holds the SHA-256, and `.to` is the resolved
  destination (the URL's last segment appended when `.to` ends in `/`), so a basename change is
  not lost although the URL is not in the key. `key.fetched` reads the hashes back from a
  preimage; gc keeps every blob a cache entry's preimage names ("while a step record names it").
- **Not yet wired** (handoff): the download runs in `compose.run_steps` before `schedule.run`, for
  every fetch entry whose blob is absent; `begin_copy` builds the one-file tree (mode 0600,
  0:0, through `fetch_tree.import` in the store namespace, via `input_job`) only on a miss.
