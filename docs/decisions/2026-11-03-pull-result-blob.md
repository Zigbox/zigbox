# `Result.blob`: bytes and outcome per blob
*Decided 2026-11-03, by the Z1/Z5 slice.*

Z5: `Result.blob(index)` gives `{digest, bytes, outcome}` for the config (0) and layers (1..`layer_count`); `Event.blob` gains `bytes`. `bytes` is the blob whole length in the cache whatever the outcome (a `resumed` blob moved less over the wire). The result keeps pointers to the workspace's resolved and fetched records, valid until the next pull. The `zbx.pull/1` JSON is unchanged.

See `src/pull.zig`.
