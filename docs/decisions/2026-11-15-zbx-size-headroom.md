# Release size headroom: shared formatting code at call sites

*Decided 2026-11-15, by the slice (claude/zbx-size), for the supervisor's review.*

## Problem

The x86_64 ReleaseSafe `zbx` on `main` (b7225ab) was 4,188,936 bytes, 5,368 under the spec's
4 MiB release limit (`release_size_limit_bytes`, checked by `zig build release`'s size gate and
the VM harness). S2 slice 4 adds about 36 KiB on its own. The limit, the gate, ReleaseSafe and
assertions stay as they are.

## Where the bytes were (x86_64, b7225ab)

The release binary is already stripped (`-Dstrip`, default true), so there is no debug info to
cut. Sections of the stripped binary:

| Section | Bytes | What it is |
|---|---:|---|
| `.text` | 3,359,721 | code |
| `.rodata` | 683,192 | about 370 KB of message, help and diagnostic text; crypto and seccomp tables |
| `.eh_frame` + `.eh_frame_hdr` | 126,376 | unwind tables, used by the panic handler's stack trace |
| `.data` | 18,160 | |

Per-symbol sizes (from a `-Dstrip=false` build, `nm --size-sort -S`): by top-level namespace,
`std.crypto` 572 KB (TLS client, certificate checks), `runtime` 413 KB, `build` 293 KB, `store`
217 KB, `trust` 207 KB, `cli` 202 KB, `std.Io` 142 KB. Duplicated generic instantiations that stay
out of line are small (the largest families: `Diag.while_` 41 copies 27 KB, `Diag.context` 51
copies 18 KB, `Diag.cause` 21 copies 14 KB, `std.crypto.modes.ctr` 2 copies 28 KB).

The real cost was hidden by inlining: the largest functions (`cli.dispatch` 73 KB,
`runtime.run.start` 58 KB, `store_commands.execute` 56 KB) are large because every one of about
1,500 `diag.cause` / `while_` / `context` / `fix_with` calls, and every `text.Bounded.print`,
instantiated its own copy of the formatter (`std.Io.Writer.print` unrolls each format into
`writeAll` calls and `printValue` per placeholder), plus the slot handling, the sanitising loop
and the assertions around it.

## Cuts

1. **A shared path for plain formats** (`src/text.zig`). A format made only of literal text (no
   `{{`/`}}`), `{s}` of a byte slice or byte-array pointer, and `{d}` of an integer of at most 64
   bits is decided plain at compile time. Its call site only fills an array of parts; one
   `noinline` function, `write_parts`, writes them: `writeAll` for text, `printInt` base 10 for
   integers. That is exactly what `std.Io.Writer.print` does for those placeholders (`{s}` with
   no width is `alignBufferOptions` with no padding, which is `writeAll`; `{d}` is `printInt` with
   no padding), so output, including where truncation cuts, is byte-identical. A test compares
   the two at every buffer size from 0 to 40 bytes; any other format goes to std unchanged.
   `Bounded.print` uses it. Alone: x86_64 −156,832 bytes, aarch64 −231,736.
2. **Diagnostic collectors keep only the formatting generic** (`src/diag/diag.zig`). Slot setup,
   the sanitising pass (`put_end`) and the assertions are `noinline` helpers shared by every
   format. Same order of operations and the same assertions. On top of cut 1: x86_64 −294,992,
   aarch64 −172,080.

| Target | Before | After | Saved |
|---|---:|---:|---:|
| x86_64 | 4,188,936 | 3,749,352 | 439,584 (429 KiB) |
| aarch64 | 3,622,720 | 3,219,816 | 402,904 (393 KiB) |

The per-cut figures above were measured before the shared helpers gained the assertions that keep
tidy's two per function (12,240 bytes on x86_64, 912 on aarch64); the table is the final commit.

## Not done

- **Dropping the unwind tables** (`.eh_frame` and its header, 126 KB on x86_64) would change what
  a panic prints (its stack trace), so it is a behaviour change; not needed now.
- **Message text in `.rodata`** is product (error messages are part of the demo).
- **Direct `writer.print` calls** to stdout and stderr (command output) still instantiate std's
  formatter per call site. Routing them through `text.write_parts` the same way is the next lever
  if the headroom runs low again; it is mechanical once the pattern above is reviewed.
