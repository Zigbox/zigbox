# M7 · Slice 3b-ii: the result

*Decided in slice 3b-ii and its review.*

- **The image is cached as a tree, under an image key.** The brief's cache value for the image is the result digest; here `build/cache/<image key>` holds the assembled tree like a step's entry (so `cache.record` and gc rooting are reused) and the result record under `build/results/<digest>` is written after, from the tree and the resolved config. The image key covers the base tree, each add (source tree, destination, in order) and the config's digest. The record is not a gc root: its tree is rooted by the cache entry, and `zbx run <digest>` of a record whose entry was pruned fails with the missing-tree diagnostic.
- **The result digest** is BLAKE3 of the record's bytes (`zbx-build-result\0`, version 1, tree, the settings lists, labels). It is a function of the tree and the declared config only: no times, no paths.
- **N8.** A step's worker roots its output as `build:<step>` (`step.output_root_prefix`) before it exits; the parent writes the cache entry under the shared lock and then removes that root, only if its source still starts with `build:`. A crash between the two leaves a `build:<step>` root, which stays until it is removed by hand with `zbx store rm`; the tree is never unrooted before the entry exists.
- **`zbx run <digest>`** tries `build/results/<digest>` for a full digest operand before running it as a plain tree. A missing record is a plain tree; a damaged or newer one is E0423. `--user` stays refused for tree operands.
- **`zbx inspect <digest>`** needs the full digest (E0005 otherwise, and for an unknown record). Schema `zbx.build_result/1`, `zbx schema inspect`; the report is `zbx.build/1`, `zbx schema build`.
- **`--output json` for `zbx build`** is one `zbx.build/1` line per ended step and for the image, in the order they ended, then the `build_result` line. A refused build is the usual diagnostic on stderr.
- **A locked base that the store lacks is pulled by digest** (`registry/repository@sha256:...`, the lock entry's platform, `ZBX_REGISTRY_MIRRORS`), under the shared lock released for the pull; E0804 stays for a base not in the lock.
- **Review fixes (N8 and the `build` root).** The step import never rewrites an existing root (`keep_existing_root`), and the parent removes only a `build:` root written at or after the build began (`Context.started_s`), so a user's root and an older build's root survive. No separate `build` root is kept for a result: its tree stays rooted by the image cache entry. If that entry is removed by hand, `store gc` can collect the tree and `zbx run <digest>` fails with the missing-tree diagnostic until a rebuild (cut recorded in `docs/demos/m7.md`).

Where: `docs/demos/m7.md`, `docs/briefs/` (M7 slice 3b).
