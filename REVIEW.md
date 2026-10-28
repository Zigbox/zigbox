# Review checklist

The supervisor reviews every slice against this list, so run it yourself first, on your own diff, before you report. Each item is here because a review found it more than once. Say in your report which items your slice touched and what you checked; an item that does not apply needs no word.

## Interfaces that others read

- **A JSON schema only grows.** Under the same version (`zbx.store.ls/1`), never remove, rename or retype a member, and never change what it means. Add members beside the old ones. A change that cannot be additive is a new version (`/2`), with the old one still documented.
- **A record on disk is read by the next release, and by the one after.** Bump its version when the format changes, keep reading every older version, and test that with real text an older release wrote (not text your new code rendered).
- **Every new command, flag and diagnostic is in `help`, `zbx schema`, the goldens and the error pages** in the same commit. `zig build errors-site-check` catches pages; nothing catches the rest.

## Reading what you wrote, and what you did not

- **Parse accepts only what render can write.** Every bound that `render` or `save` asserts (a time under 2^40, a count, a length) is checked by `parse` too, and refused as malformed. Otherwise a damaged file reads as valid and crashes the next write. A fuzzer that damages text and re-renders it must exist for every record format.
- **A test fills memory with a known byte before checking that something wrote it.** Never rely on what `undefined` holds: Zig's own backend and LLVM leave different bytes there, and a check against `undefined` can pass without testing anything.
- **Names are read the way the code that acts on them reads them.** If the applier drops `.` parts or a trailing slash, so does every check that predicts what it will do (the layer fuzzer once judged `a/./b` differently from the applier).

## Image references

- **A digest is never a tag.** A reference with `@` names content, not a name; it is never stored, listed or matched as a tag.
- **Two spellings of one reference are one reference** (`alpine:3.20` and `docker.io/library/alpine:3.20`). Compare with `lock_file.same_reference`, never with `std.mem.eql`.

## Bounds and failures

- **Every bound is a named constant in `constants.zig`**, with a comptime relation to the buffers it sizes, and a test at the bound and one past it.
- **Every exit path is tested**, not only the clean one: a refusal, a signal, a timeout, SIGKILL of the child, and SIGKILL of `zbx` itself. Anything zbx starts or holds (a scope, a lock, a port, a helper process) is released on each of them.
- **Every failure is one coded diagnostic** with a cause and a fix (`DIAGNOSTICS.md`). An `errno` alone, an empty reason, or a line that blames the wrong layer is a bug, including in the test harness.

## Tests and gates

- **`zig build check` on the exact commit you report**, with its last line pasted. It runs every fuzzer with a fresh seed; when one fails, its seed is the last `fuzz:` line above, and the replay is `zig build fuzz -- <fuzzer> <seed> 2000`.
- **A test reachable from no test root never runs.** A new file of tests is imported from a root in `build.zig`'s test list, and you have seen it run (`zig build test --summary all`).
- **A fixture parsed from text is checked against real output**, captured from a real run, not written from what the code is believed to print.
