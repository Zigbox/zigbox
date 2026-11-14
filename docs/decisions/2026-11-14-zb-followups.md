# ZB-1 and ZB-2 follow-ups: foreign rpms refused, a narrow check, exec's `.lost` tested

*Decided 2026-11-14, by the slice (`claude/zb-followups`). Supersedes the parts of
[2026-11-13-zigcube-zb1-zb2.md](2026-11-13-zigcube-zb1-zb2.md) named below; the rest of that
file stands.*

## `dnf.write` refuses foreign rpms (`ForeignRpm`)

Replaces "`dnf.write` takes rpms `rpm.write` made; other bytes in a `Built` are a broken contract
(an assertion), not a refusal." Those bytes come from the caller (Zigcube), so they are now a
refusal, `pkg.Error.ForeignRpm`, before anything is written; `pkg.describe` gives its line.

Each rpm is written again from its package, with the build host its main header names and the
header signature its signature header carries, and compared whole. So a cut, a changed lead,
header, digest or payload, another package's rpm, or another architecture's (the package's or the
tree's) is refused. A first version compared only the main header; the new `dnf` fuzzer found that
a flipped byte of the build host then passed (the damaged name was read back and rebuilt the same
header, while the signature header's digests no longer matched), so the comparison is whole.

- The header signature's own bytes are not judged by `dnf.write`; `check_tree` with
  `signatures_required` reads them. One longer than `openpgp_signature_bytes_max` (1024) is
  `ForeignRpm`; `rpm.write` asserts that bound, and `rpm.Options.header_signature` says so.
- The rewrite runs in its own arena, freed before the next package: at most one rpm's rewrite
  (the rpm and its intermediates: file lists, cpio, gzip output, headers) is held at a time,
  beside the caller's tree.
- Only this Zigbox build's `rpm.write` output is accepted. An rpm an earlier Zigbox made can
  differ (payload compression, a header field), so a caller that keeps rpms across a Zigbox
  upgrade gets `ForeignRpm` for them and writes them again.
- `zig build fuzz -- dnf` damages signed and unsigned rpms and checks that only damage inside the
  signature's own bytes, or none, is accepted.

## `check_tree` exposes no OpenPGP surface

Replaces the `test_key` sentence and the `.test_key = false` in the example's `strict`.
`pkg.CheckOptions` has one field, `signatures_required`; `pkg.CheckError` is `CheckFailed` or
`OutOfMemory`; the surface test pins both. The check behind `zig build packages-check` also signs
with Zigbox's fixed test key (`-Dtest-key`), which vouches for nothing, so that option and the
OpenPGP errors it could raise stay inside Zigbox (`package_check.check`). The OpenPGP reader is
still compiled into a caller, since `signatures_required` has to read the signature files; none of
its names or errors is exported. The example becomes:

```zig
const strict: pkg.CheckOptions = .{ .signatures_required = true };
try pkg.check_tree(source.source(), memory, log, strict);
```

## `ExecHandle`'s size is asserted

Replaces "about 800 KiB" in the ZB-2 example. `@sizeOf(Handle)` is asserted at compile time, in
`src/runtime/exec.zig`, to be at most `constants.exec_handle_bytes_max` (640 KiB, unchanged); it is
about 400 KiB on x86_64 today. Keep it in static storage or on the heap.

## Exec's `.lost` is tested

Replaces "No test reaches exec's `.lost` ... that is open." `src/runtime/exec_worker_tests.zig`
fails the reap step once under a worker's exec: `exec_wait` gives `.lost`, `code()` null, and
`lost_diag` E0221 naming the reap; the command is killed and reaped, and the container lives.
