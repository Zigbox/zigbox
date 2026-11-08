# M8 slice 1: the KDF maxima are tightened
*Decided 2026-11-08, by the supervisor, after the slice 1 adversarial review of PR #65.*

This supersedes point 1 of `2026-11-08-m8-key-file-and-kdf-bounds.md` for the maxima only; that
file is unchanged. The minima, `p` exactly 1, the refusal before argon2id runs, and everything
else in it stand.

- **`parse` accepts t (iterations) from 1 to 6** (was 12) **and m from 8 KiB to 131072 KiB,
  128 MiB** (was 256 MiB). `constants.key_kdf_t_max` and `key_kdf_m_kib_max` carry them.
- **Why.** The review measured std argon2id in ReleaseSafe: the default (t=3, m=64 MiB) takes
  143 ms, the old maximum (t=12, m=256 MiB) 2.6 s. A planted key file could cost that per open,
  and on a memory-limited cgroup a 256 MiB request may be killed by the OOM killer instead of
  refused, so the "memory" cause would never be seen. The new maxima are twice the defaults:
  room for one future doubling of the cost, no more.
- **Effect.** A key file written with t above 6 or m above 128 MiB is refused as malformed. No
  zbx writes one: the defaults are t=3, m=64 MiB, and only a test makes others.
- **Known wording gap.** A key written by a future zbx with defaults above these maxima reads
  as malformed here, not as "made by a newer zbx". Slice 2's error wording may want to say so.
- **Not fixed, for the record.** std's argon2 leaves its first blocks and `h0` on the stack,
  and its memory is unmapped without being zeroed. That is a std limitation, not ours.
