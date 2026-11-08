# M8 slice 10: review fixes (2026-11-08)

Changes to `2026-11-08-m8-slice10-handoff.md` after the review of PR 72. No bound, limit or default
changed, and no code was registered: E0417 and E0550 are reused.

- A bare tree digest packs with no image settings (it used to scan for an image that held it and
  borrow that image's settings, which made the layer depend on what else the store held).
- `store export --oci` is all or nothing: the layout is written to `<dir>.zbx-tmp-<manifest hex>`,
  synced, and renamed onto the target, which must be absent or empty (checked first, before any
  work). A failure removes the work directory.
- Each blob is hashed while it is copied and compared with its digest. A mismatch drops the blob
  and the pack record and stops with E0550, so the next pack rebuilds it.
- A failed export write is E0417 with the kernel's reason and errno.
- The pack fuzzer drops the pack record between its two packs, so the second really packs, and
  generates long names, long symlink targets, large ids and non-UTF-8 names.
- Hard-link caveat, kept: same-content files are hard links in the layer, including empty ones.
  Changing that changes layer digests, so it is documented in `docs/demos/m8.md` instead.
