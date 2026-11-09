# A policy file is at most 16 KiB

*Decided 2026-11-09, by the M8 slice 3 implementer; the supervisor signs off the bound.*

The brief gives no size for a policy file. The gate reads each file whole into one fixed buffer, so it needs one.

**Evidence.** A policy trusts at most `policy_keys_max` = 16 keys. Each key is a name, a public key text and about 64 bytes of syntax, so sixteen keys take about 2 KiB. M7's lexer takes the text whole and its input bound (`build_render_bytes_max`) is the ceiling.

**Choice.** `policy_bytes_max` = 16 KiB (`constants.zig`). The rest, about 14 KiB, is room for comments. Comptime asserts tie it above the room sixteen keys need and below the lexer's bound. A larger file is E0904 ("too large"), never read as far as it fits, because a half-read policy must not be taken for the whole one. The gate's memory is about 20 KiB.

**Changing it.** Raising it only needs the two asserts to hold; lowering it below the 16-key room fails the build.
