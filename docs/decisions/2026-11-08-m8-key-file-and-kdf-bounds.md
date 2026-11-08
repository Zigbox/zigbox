# M8 slice 1: the key file, the KDF's bounds and the small choices
*Decided 2026-11-08, by the slice (supervisor to review).*

The brief fixes the key file's fields and argon2id's defaults (t=3, m=64 MiB, p=1). Slice 1 made
these choices where the brief left room.

1. **Bounds `parse` enforces.** t from 1 to 12, m_kib from 8 to 262144 (256 MiB), p exactly 1
   (`constants.zig`, `key_kdf_*_max`). A file above them is refused as malformed before argon2id
   runs, so a planted key file cannot make zbx take unbounded memory or time. p is 1 so no
   thread is ever started (the `Io` given to argon2 is `failing`). A key made with other
   parameters than the defaults (only possible in a test) opens as long as it is inside these.
2. **An empty passphrase is refused** (E0911). `--no-passphrase` is the only way to an
   unencrypted key.
3. **E0901 also covers** failures to write the key and a missing home or config directory, not
   only an unusable existing file; its cause line says which. E0902 and E0911 are as the brief
   describes. A passphrase typed twice that differs, a Ctrl-C at the prompt, and a file or line
   that is too long are E0911 causes, not new codes.
4. **Exclusive create** is a temporary file, then `link` to the final name: `link` never
   replaces, so two `key new` of one name cannot both win, and a crash leaves no half key under
   the final name. The secret `.key` is linked first, the `.pub` second.
5. **The `.pub` file is two lines:** the public text, then the encryption word (`passphrase` or
   `none`), so `list` and `show` need no passphrase and never open `.key`. The word is advisory
   (see the demo document).
6. **`page_allocator`** is used once, for argon2id's memory, against the "no allocator" comment
   in `main.zig`. The memory is taken for the call and given back; bounds above keep it at most
   256 MiB. The alternative, a static 256 MiB in bss, was rejected: it costs address space in
   every command.
7. **A forgotten passphrase is a lost key**, stated in help, in E0911's page and in the demo
   document.

Detail: `docs/briefs/M8-trust.md`, `docs/demos/m8.md`.
