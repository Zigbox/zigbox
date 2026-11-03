# M3 · The store: whole-file objects, per-user, gc by plan hash with a trash

*Decided 2026-10-26.*

The spec's two M3 open questions are settled (live doc rev 52), and so is how much of "Agent operability" lands with the first deletion.

- **Whole files, with chunk lists.** One object per file, hashed with BLAKE3 and stored whole, so a container's lower directory can be a hardlink farm with no copy. Each object also records fixed-size chunk hashes, so Zigcube's C2 can fetch and verify pieces by hash. Content-defined chunking is a later change behind the same interface.
- **Per-user.** The store lives in the user's data directory, written from inside the user's own namespace so ownership round-trips. No shared or system store until Zigcube's node agent needs one.
- **gc is plan, confirm, trash.** `zbx store gc` prints a plan and its hash; only `--confirm <hash>` acts, and it refuses if the store changed since. What it removes goes to a time-limited trash, and `zbx store restore` brings it back.
- **The upgrade test pins a commit.** No release is tagged yet, so M3's upgrade test builds the merged M2 commit `95ba1da` as "the previous release". It switches to the tag once one exists.
