# M6 · State: one writer, a trash, and tar.gz

*Decided 2026-10-28, after M5 merged.*

- **One writer at a time.** A run holds its read-write state volumes for its whole life; a second run naming one read-write is refused, naming the holder. `--state NAME:PATH:ro` shares, read-only.
- **`zbx state rm` goes to a trash**, as `store gc` does since M3, and `zbx state restore` brings a volume back until the trash expires. State is the one thing zbx cannot rebuild from a registry.
- **`zbx state export` writes tar.gz**, with std's own tar writer and deflate compressor (both are in the pinned std), owners as the container sees them.
- **M5's agent-test findings go into M6**: a hint in the failure JSON, the network in `run -d` and `ps` JSON, fixes that say they need root or are templates, `doctor --output json`, and a schema an agent can follow.
- **M4b (Mac) follows M6.**
