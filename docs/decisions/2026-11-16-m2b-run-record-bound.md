# M2b: run records get their own read bound, 80 KiB

*Decided 2026-11-16, by the supervisor, on the M2b slice 1 implementer's evidence.*

A run record with every M2b knob at its bound is 74,691 bytes: 16 sysctls of the longest
allowlisted keys, each with a 256-byte value of bytes the writer escapes to four, all four
`--ulimit`s, and `--shm-size`, on top of everything a record already held at its bound. That is
more than the 64 KiB a record had, and more than `file_bytes_max`, the largest file the host
reads.

**Decision.**

- `record_bytes_max` goes from 64 KiB to 80 KiB, the same as `image_record_bytes_max`. The
  comptime worst-case sum in `records.zig` still has to fit inside it.
- A new `record_file_bytes_max` is also 80 KiB. Run records are read through their own host
  call, `Host.read_record`, with a buffer of that size. `records.load` and the pruning scan both
  use it.
- `file_bytes_max` stays at 64 KiB. It sizes stack and static buffers in more than 200 places,
  for files that have nothing to do with run records. Raising it would grow those stacks, and
  would move a bound that other files depend on, only to fit one kind of record.
- `read_calls_max` and the real host's per-call read assert now cover `record_file_bytes_max`,
  because that is the largest single read.

**Where the buffer lives.** Records are rendered in `records.save` and read in `records.load`,
and both run in the parent: the supervisor after the run, and the `ps`, `logs`, `stop`, `rm`
and prune commands. The namespace child never reads or writes a record before `execve`, so the
extra 16 KiB of stack is never in the child.

**Older zbx.** zbx 0.6.x and earlier read a record into 64 KiB. A version 12 record over that
size reaches them as "unreadable", not as "written by a newer zbx". `ps` and pruning skip it and
note it as unreadable, as they would any other unreadable record. Only a run with many long
sysctl values writes a record that large. A record that fits in 64 KiB reads as "newer", as
before. This is accepted.

**Tests.** In `records.zig`, on a real kernel in /tmp:

- the worst record is saved, then loaded back, and it is larger than `file_bytes_max`;
- a file of exactly `record_bytes_max` bytes is read and refused as damaged;
- a file one byte longer is unreadable.
