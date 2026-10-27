# Brief: M3 · Store

Read these first:

- `AGENTS.md`, `docs/STYLE.md` and `DIAGNOSTICS.md`;
- the M3 section, "Production readiness", "Agent operability" and the open questions (now decided) of `docs/SPEC.md`;
- `docs/DECISIONS.md`, especially the M3 store decision and the two M2 entries for Zigcube;
- the "Notes for later milestones" in `docs/briefs/M2-limits.md`;
- Zigcube's `HANDOFF.md`, section 2 (in `Zigbox/zigcube`; the supervisor has a copy at `/home/user/zigcube/HANDOFF.md`).

This brief settles what they leave open. Do not touch anything from M4 onward: no registry, no OCI, no tags, no `zbx.lock`. `demo-m0`, `demo-m1` and `demo-m2` must keep passing in every slice.

## Goal and demo (from the spec, live doc rev 52)

Root filesystems live in a deduplicated, verifiable store and are run by digest.

1. Import `./alpine`; note its digest and the `zbx store du` total.
2. Copy the rootfs, add one 10 MB file, and import the copy. `zbx store du` grows by about 10 MB, not by a second full rootfs.
3. `zbx run <digest> -- sh`, install a package with `apk add`, exit, then `zbx commit`. A new digest prints, and `zbx store diff <old> <new>` lists only the added files.
4. Corrupt a chunk on disk by hand. `zbx store verify` names the damaged file and every tree that references it.
5. Delete a file in a committed tree: the new tree's stored size drops (no whiteout baggage).

Acceptance criteria:

- Importing the same directory twice yields the same digest, independent of mtime and import order.
- File modes, ownership, xattrs and symlinks round-trip.
- Running a container never writes into the shared store.
- The production-readiness checklist:
  - an upgrade test against the merged M2 commit `95ba1da` (see below);
  - stable diagnostics;
  - documented failure modes.
- Every new command has a JSON result with a versioned schema in `zbx schema`, and nothing prompts.
- `zbx store gc` follows "plan, then apply by plan hash" and "undo" (spec, Agent operability).

## Fixed decisions

### Layout and identity

- **Where the store lives.** It is per-user, in `$XDG_DATA_HOME/zbx/store`, falling back to `~/.local/share/zbx/store`. It holds:
  - objects, sharded by the first two hex digits;
  - tree (directory) objects;
  - roots;
  - the materialized cache;
  - the trash;
  - a `store.zon` with a format version.

  Everything under it is written by zbx only. The layout is documented in the module doc of `src/store/`.
- **Digests.**
  - Shown as `b3:` plus 64 lowercase hex digits.
  - BLAKE3 from std (`std.crypto.hash.Blake3`), unkeyed.
  - Input accepts the full form, or a unique prefix of at least 12 hex digits. An ambiguous or unknown prefix is a diagnostic; zbx never guesses (spec: "ids and digests are never matched by an ambiguous prefix").
- **File objects.** One object per (content, metadata) pair, stored whole: a regular file whose bytes are the file's content.
  - Its content hash is the BLAKE3 of the bytes.
  - Its object id is the BLAKE3 of a canonical header (content hash, mode, uid, gid, sorted xattrs) and identifies the physical file on disk. That file carries those attributes for real (see Ownership).
  - Two files with the same bytes and metadata are one object. The same bytes with different metadata are two objects. The demo's dedupe claim rests on the first case, which is nearly every file.
  - Content-defined chunking is not in M3 (decided).
- **Chunk lists.** Every object records BLAKE3 hashes of its content in fixed chunks of `store_chunk_bytes` (1 MiB, in `constants.zig`), stored beside the object.
  - The library exposes two things for Zigcube's C2:
    - `chunks(object_id)`, which lists the chunk hashes;
    - a verified write, `put_chunk(object_id, index, bytes)`, which accepts bytes from any source only if they hash right and assembles the object when all chunks are present.
  - No networking. Unit-test it with corrupted, short, reordered and duplicate chunks.
- **Tree objects.** A directory is encoded canonically:
  - a version byte;
  - entries sorted by name bytes, each with name, kind (file, dir, symlink), mode, uid, gid, sorted xattrs, and then: for a file, its size, content hash and object id; for a symlink, its target; for a directory, the subtree digest.

  The tree's digest is the BLAKE3 of that encoding, so the root digest is the whole tree's identity.
  - mtime, atime and ctime are not recorded.
  - Materialized files get a fixed mtime (`store_mtime`, document the value).
  - Hardlinks inside an imported tree become separate entries.
  - Device nodes, FIFOs and sockets are skipped with a warning (`W04xx`) naming them.
  - Write the encoder and decoder as a pair with a round-trip test, and fuzz the decoder (`tree` fuzzer).
- **Roots.** A tree stays in the store while it is a root.
  - Roots are created by:
    - `store import`, recording the source path and time;
    - `commit`, recording the container and the parent digest;
    - the trees of live containers.
  - `zbx store rm <digest>` drops a root. It does not delete data; gc does that.
  - `zbx store ls` lists roots, with `--output json`.

### Ownership, xattrs and the user namespace

- **Ownership.** It is recorded as seen inside the container, under the same mapping M1 uses for `--rootfs`:
  - with the full subuid map, the importing user is uid 0 and subuids map to 1 and up;
  - with the single-UID fallback (W0201), everything is 0.
- **Where store work runs.** All of it (import, materialize, commit, verify, gc, restore) runs in a single-threaded child inside the user's namespace with the same mapping, so `chown` and reading `0600` files work and objects carry their real attributes. Outside that namespace the parent only sees paths and digests.
- **Which xattrs round-trip.**
  - `user.*` and `security.capability` round-trip; the latter as a namespaced v3 capability.
  - `user.overlay.*` is overlayfs's own and is never imported.
  - Any other namespace is skipped with a warning naming the file and the attribute. This is a cut; record it.
- **Symlinks.** They are stored, never followed during import. A symlink pointing outside the tree is stored as is; it is the container's view.

### Materialize and run

- **Running by digest.** `zbx run <digest> -- <cmd>` (and `Spec.image` in the library, which closes the "image is rootfs" gap in `docs/demos/m2.md`) runs on an overlayfs mount:
  - **lower:** the tree's materialized directory, a hardlink farm of the tree's objects. It is built once per tree, under the store's materialized cache, on the same filesystem, read-only by mode;
  - **upper and work:** per container, under `$XDG_STATE_HOME/zbx/containers/<name>/`;
  - **mount options:** the overlay is mounted inside the container's user and mount namespaces with `userxattr`.
- **The store is never written by a running container.** Overlay's copy-up gives the container its own copy before any write.
  - The demo asserts this with BLAKE3 sums of the store before and after a container that writes, chmods, chowns and deletes everywhere.
  - A unit test asserts that the plan never mounts a store path writable.
- **Old modes keep working.** `--rootfs` keeps M1/M2 behaviour, and `--read-only` with a digest mounts the overlay read-only, with no upper.
- **Kernels without unprivileged overlayfs** (the doctor's overlay check fails) are a coded refusal for `run <digest>`, naming `zbx doctor`. Copying the tree instead is a cut; record it.
- **Run records.** They go to version 4, adding the tree digest and the upper path. The upper of an ended container is kept until its record is dropped (records keep the newest 32), so `commit` works after exit.

### Commit and diff

- **`zbx commit <container>`** turns the container's upper into a new tree:
  - the parent tree;
  - plus the upper's files, as objects;
  - minus whiteouts (a char device 0/0, or a `user.overlay.whiteout` xattr);
  - with opaque directories (`user.overlay.opaque`) replacing their parent's entries.

  It prints the new digest, makes it a root recording the parent, and works on a running container only with `--pause`. Without it, refuse with a diagnostic saying the container must have exited; freezing a live container is a cut.
- **Deleting a file removes its entry outright,** so the stored size of the new tree drops (demo step 5). No whiteout ever reaches the store.
- **`zbx store diff <a> <b>`** walks both trees, skipping identical subtree digests, and lists:
  - added, removed and changed paths;
  - per changed path, which of content, mode, owner, xattrs or link target changed.

  It has `--output json`.

### du, verify, gc, restore

- **`zbx store du [<digest>]`.**
  - Without a digest: the store's total physical bytes, and the number of objects and trees.
  - With a digest: the tree's logical size, its stored size (the bytes of objects it references), and how much of that it shares with other roots.
  - Step 5's "stored size drops" is the digest form. `--output json`.
- **`zbx store verify`** rehashes every object and tree against its id, and every chunk list. A damaged object is reported with:
  - its id;
  - every path in every root tree that references it.

  Exit 2 if anything is damaged, under DIAGNOSTICS' blame rules: the store is environment. One diagnostic per damaged object, plus a summary.
- **`zbx store gc`.**
  - Without flags it prints a plan and changes nothing. The plan is what is unreachable from the roots, the live containers and the materialized cache of live containers, with counts, bytes and a plan hash: the BLAKE3 of the sorted object ids plus the store's generation counter.
  - `--confirm <hash>` acts only if a fresh plan hashes the same. Otherwise it is a diagnostic saying the store changed, with the new hash.
  - Acting moves objects, trees and dead materialized dirs into `trash/<gc id>/` with an expiry, `store_trash_seconds` (7 days by default), and empties expired trash.
  - Never a prompt.
- **`zbx store restore <gc id>`** moves a trashed gc back, refusing for any object already present again or missing from the trash. `zbx store gc --trash` lists trash entries.

### The library, for Zigcube

- **`src/store/`** joins the `zigbox` module, behind a narrow interface: `import`, `get_tree`, `materialize`, `commit`, `diff`, `verify`, `chunks` / `put_chunk`, and `gc_plan` / `gc_apply` / `restore`.
- **Storage belongs to the caller,** as in M2: no module-level state.
- **`Spec.image`** is a tree digest now. `start_failed` for a digest the store does not have is `ZBX-E04xx` "no tree with that digest". Tell the supervisor which code, so Zigcube's placeholder `ZBX-E0501` in `HANDOFF.md` can be corrected. Do not edit Zigcube.

### Diagnostics

- **The code range.** `04xx` is the store. `E0401`–`E0406` already exist (the M2 lifecycle commands); they keep their meaning, and the store's codes start at `E0410`.
- **At least these codes:**
  - unknown digest;
  - ambiguous prefix;
  - store format too new or unreadable;
  - an import source missing or unreadable (naming the path);
  - a file skipped (`W`);
  - an xattr skipped (`W`);
  - overlay unavailable;
  - a commit of a running container;
  - a damaged object (from `verify`);
  - a gc plan hash that no longer matches;
  - a restore conflict;
  - disk full while writing (with what was written so far and what to do).
- **Interrupted writes are safe.** Every write is atomic (temp file, `fsync`, `rename`), so a killed import or gc never leaves a half object under its id. Test this with the simulator's fault injection at each step.

### The upgrade test

- **What it pins.** No release is tagged, so "the previous release" is the merged M2 commit `95ba1da` (decided).
- **In CI:**
  - build that commit's `zbx` in the `demo-m3` job (`git worktree` at the pinned commit, `fetch-depth: 0`);
  - in the VM, let it write run records (`run`, `run -d`, `stop`);
  - then run M3's binary over the same state: `ps --all` must read every version 3 record, and a new run must write version 4 beside them.
- **Later.** The commit lives in one constant in the harness, to be replaced by a tag later.

## Slices (commit and stop for review after each; do not push)

1. **Trees and import.**
   - `src/store/`: layout, `store.zon`, digests and prefixes.
   - The tree encoder and decoder with the `tree` fuzzer; objects and chunk lists.
   - `zbx store import`, `ls`, `du` and `rm`, with their schemas.
   - The userns child for store work.
   - Simulator support for the walk and the writes, with fault injection.
   - Determinism tests: shuffled readdir order, changed mtimes, two imports giving one digest.
   - Round-trip tests for modes, ownership, xattrs and symlinks.
   - In the build container: import a real Alpine rootfs. The container runs as root and has `uidmap`, so say which mapping you used.
2. **Materialize and run.**
   - The hardlink farm and its cache; the overlay in the setup plan.
   - `zbx run <digest>`, and `Spec.image` in the library.
   - Run record version 4.
   - The "store is never written" plan test.
   - Real check: the build container cannot mount overlay unprivileged as a normal user, so this is the first slice that needs the VM. Use a scratch harness or `-Dkeep-overlay`, as in M2's experiments.
3. **Commit and diff.**
   - `zbx commit`: whiteouts, opaque directories, the parent link.
   - `zbx store diff`.
   - Tests built from real overlay upper directories captured in the VM and checked in as fixtures.
4. **Verify, gc, restore, chunks.**
   - `zbx store verify` with reverse paths.
   - gc plan, confirm and trash; `zbx store restore`.
   - The chunk API with its verified write.
   - Each failure path coded, with goldens and error pages.
5. **VM and CI.**
   - `zig build demo-m3`, every assertion a unit-tested function: the five demo steps, the acceptance criteria (including the store-unchanged check) and gc's plan, confirm and restore.
   - The upgrade test against `95ba1da`.
   - The `demo-m3` CI job.
   - `docs/demos/m3.md`: by-hand steps, cuts, and failure modes, including:
     - a disk filling during import;
     - a hardlink count limit hit on a big farm (ext4 allows 65,000 links per inode);
     - overlay unavailable;
     - a damaged object;
     - a gc plan gone stale;
     - the trash expiring.
   - Run `demo-m3` under TCG from a fresh overlay; `demo-m0`, `demo-m1` and `demo-m2` must still pass.

## Done means

- **All gates pass,** and every fuzzer runs at 10,000 iterations (`tree` is new).
- **CI is green:** the `demo-m3` job, with `demo-m0`, `demo-m1` and `demo-m2` still green. Until then M3 is "built, not demonstrated".
- **Your report lists:**
  - what you ran and its output;
  - what you did not run and why;
  - every deviation from this brief;
  - anything in the spec, this brief, `DIAGNOSTICS.md` or the Zigcube contract that seemed wrong.

## Notes for later milestones (found during M3)

- **The container's umask is the caller's.** `zbx run` inherits the umask of whoever started it (`0002` under some login shells), so files a container creates get different modes on different hosts, and a `zbx commit` of the same steps can give different digests. Docker starts containers with `022`. Decide before M7, whose builds must be reproducible: set a fixed umask in the child, or record the caller's in the plan.
- **The scope keeper ties `start` and `wait` to one thread** (`docs/demos/m2.md`). Zigcube's agent must start and wait for a container on the same thread, or the keeper ends early and the out-of-memory and process-limit reasons are read racily again.
