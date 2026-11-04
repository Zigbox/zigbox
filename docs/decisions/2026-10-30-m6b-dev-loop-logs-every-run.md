# M6b · Dev loop: logs for every run, 5 MiB, one implementer

*Decided 2026-10-30, on the M6b brief.*

- **Every run keeps its log**, foreground as well as detached: a foreground `zbx run` writes the framed log as it copies the output to the terminal.
- **The cap is 5 MiB per container**, the oldest whole records dropped first.
- **The upgrade baseline is the M6 merge (`bf57ec8`)**, not the 0.1.1 macOS release.
- **The cap is two files, rotated** (slice 2): each at most half of 5 MiB; at the cap the current file is renamed over the older one. One `rename` drops the oldest whole records, a crash leaves whole records, the log holds 2.5 to 5 MiB. A compaction copies the log on every drop.
- **One implementer, slices in order**, Sonnet for slices 1 and 2.
