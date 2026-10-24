# Brief: M0 · Doctor, slices 4 and 5 (diagnostics retrofit)

Read `AGENTS.md`, `docs/STYLE.md`, [`DIAGNOSTICS.md`](../../DIAGNOSTICS.md) and [`M0-doctor.md`](M0-doctor.md) first. Slices 1 to 3 are built and reviewed. This brief adds two slices to M0. It does not start M1.

## Why

The live design doc (rev 42) changed one M0 ground rule. It used to say "a refused action must say what was refused and why, in one line". It now says **"Every failure follows the diagnostics standard below, from M0 onward"**, and the standard is `DIAGNOSTICS.md`. The owner decided that M0 is not done until it follows the standard. Where this brief and `M0-doctor.md` disagree, this brief wins. Where this brief and `DIAGNOSTICS.md` disagree, stop and report.

## Before slice 4: CI

Commit `Restore the CI workflow…` put back `.github/workflows/ci.yml` and `.github/actions/setup-zig/action.yml`, which were dropped when the code was ported from `DailyWombat/zigboxxx`. That push is the first CI run with KVM. Check the run for this branch, with the GitHub MCP tools:

- **All green:** report it. M0 slices 1 to 3 are demonstrated, but M0 stays open until slice 5's demo is green too.
- **Any job red:** root-cause it, fix it in its own commit, and stop for review before you start slice 4. "Flaky" is not a root cause.

## Environment

- Zig is not installed in a fresh cloud container. Install 0.17.0 from the `x86_64-linux` tarball and check it against the SHA-256 in `.github/actions/setup-zig/action.yml`.
- For a local TCG run of the demo: `apt-get update && apt-get install -y --no-install-recommends qemu-system-x86 qemu-utils`, then `zig build demo-m0 -Daccel=tcg`. It takes about 8 minutes; see `docs/demos/m0.md` for `-Dkeep-overlay` and `-Dreuse-overlay`.
- Read the pinned std before you use any API, especially the panic handler, `std.Io` and the writers.

## Fixed decisions

### Codes

- `ZBX-E01xx` (host and doctor): one code per doctor check. The cause and fix vary by what failed; the summary is fixed.
  - `E0101` userns: "can't create a user namespace" (the standard's own example; keep it)
  - `E0102` kernel, `E0103` cgroup, `E0104` overlay, `E0105` subid, `E0106` seccomp. You write the summaries: present tense, no full stop, under about 70 characters.
  - A check that could not run (unreadable file, probe timeout, probe crash) uses its check's code. Its cause says that it could not run and why. Its blame is `environment`.
- `ZBX-E00xx` (CLI usage, blame `user`): `E0001` unknown command, `E0002` missing command, `E0003` unexpected arguments, plus any others the parser needs. **`DIAGNOSTICS.md` has no `00xx` group.** Add the line "`00xx` CLI and general" to its Codes section. Say in your report that `Zigbox/zigcube` carries a copy of `DIAGNOSTICS.md` that must get the same change. You cannot push there; the supervisor does it.
- `ZBX-B0001`: internal bug (panic or broken invariant), blame `internal`.
- The registry is `src/diag/codes.zig`. Each entry has its code, severity, blame, summary and long explanation. A `comptime` check fails the build if a code is registered twice, has no explanation, or has the wrong prefix or kind letter. Using an unregistered code must not compile, so make codes an enum or something equally strong, not strings.

### Exit codes (these replace the brief's)

`0` ok · `1` user (all CLI usage errors; this used to be 2) · `2` environment (any doctor FAIL; this used to be 1, and a failing stdout or stderr also counts) · `70` internal. Put them in `constants.zig`. Assert that each diagnostic's blame decides its exit code. Do not decide the exit code separately at each call site.

### The `Diag` collector

- It lives in `src/diag/`, has a fixed size and never allocates. Every bound (the number of causes, the number of context pairs and the bytes per field) is in `constants.zig` with `comptime` relationship asserts. If a bound is exceeded, the text is truncated with a visible marker and an assertion-grade comment. It must never crash.
- The API follows the standard: functions return a plain Zig error and take a `*Diag`; inner layers call `diag.cause(...)`; outer layers call `diag.while_(...)`. Rendering happens only in `cli.zig`. Nothing below the CLI formats text for the user.
- Syscall errnos are translated into causes in one place, with the syscall name, the errno and a human explanation.

### Output

- **CLI errors**: stderr, in the standard's anatomy (`error[ZBX-E0001]: …`, `cause`, `fix`, `more   zbx explain E0001 · rerun with --verbose for the full cause chain`).
- **`zbx doctor`**: stdout keeps one status line per check. `ok   <name>  <detail>` is unchanged. A failing check becomes `FAIL <name>  <detail>  [ZBX-E01xx]`, and the `— fix:` text moves out of that line. Each failing check then gets one diagnostic block on stderr, in check order, with the fix as a runnable command. The live spec's demo still reads "that check fails with a one-line fix": the block's `fix` line is that one line.
- **Flags**: `-v`/`--verbose` adds the cause chain and the context. `--output json` writes each diagnostic to stderr as one JSON object per line, with the fields from the standard's table. The doctor stdout report does not change in JSON mode. The flags are global and may come before or after the command. Use the existing hand-written parser.
- **`zbx explain <code>`**: prints the registry's long explanation offline. It takes `E0101` or `ZBX-E0101`. An unknown code is itself a diagnostic (`E00xx`, blame `user`). Add it to `zbx help`.
- **Colour**: only when stderr is a TTY and `NO_COLOR` is unset. Output must read correctly with no colour at all.
- **Panic handler**: override the root panic so that a panic prints a `bug[ZBX-B0001]` block (no "saved bundle" line) and exits 70. The trace goes nowhere a user sees it by default (see the cuts below).

### Cuts (record each one in `docs/demos/m0.md`, under a "Cut from M0" heading)

- Bundles and `zbx bundle`, including the CI redaction check. M0 has no state directory and no secrets to redact.
- `zbx doctor --fix` (the standard's example uses it, but the fix shown is the `sysctl` command).
- Optional, if slice 5 runs long: generating `site/errors/<code>.html`. If you build it, make it a `zig build errors-site` step in Zig that writes into `site/` and is checked in CI. If you cut it, the `docs` field and the `more` line point to `zbx explain` only.

## Tests

- **Golden files**: for every registered code, one test that triggers it through the CLI against `host_sim` and compares the default, verbose and JSON output with files in `src/testdata/diag/`. Update the CLI snapshots in `src/testdata/` and the 42 doctor fixtures. The fixtures must now include each failing check's code and its stderr block.
- **No raw errors**: a test runs every failure case (every code, every doctor fixture, an injected panic if that can be done deterministically) and fails if any default or verbose output contains a stack-trace marker or a raw Zig error name (`error.` followed by an identifier).
- **Fuzzers**: the `doctor` fuzzer also asserts that every FAIL has a registered `E01xx` code, its diagnostic block and exit code 2. The `cli` fuzzer asserts that every non-zero exit has exactly one diagnostic and that its code's blame matches the exit code. Add a fuzzer for the `Diag` bounds (oversized and adversarial cause text).
- **Demo harness** (`src/testing/vm/checks.zig`): step 2 asserts `FAIL userns … [ZBX-E0101]`, the `error[ZBX-E0101]: can't create a user namespace` block, a fix naming the sysctl that was changed, and **exit 2**. The serial console merges stdout and stderr, so collect them in a way that keeps them apart, or assert on order. Add one more assertion: `zbx frobnicate` prints `error[ZBX-E0001]` and exits 1. Update `checks.zig`'s own unit tests to match.

## Slices (commit and stop for review after each; do not push)

**Slice 4 · Spec and diagnostics core.**
1. Refresh `docs/SPEC.md` from the live doc (https://claude.ai/artifact/6D9js8mxSLYmfuZe3rQ26w; Claude Docs id `2a300110-fac9-4994-82ce-6791e08952a4`, root node `9749ba10-3b2c`; read it with the Claude Docs connector's `read`, which returns XML of about 110 KB). Convert all of it, Parts I to III, to Markdown, and update the header line to the date and revision you read. This is a documentation-only commit of its own. If you cannot reach the doc, stop and report; do not hand-edit the old snapshot.
2. Fix the stale `docs/DEMO.md` references in `build.zig` and `src/testing/vm/main.zig`. Point them to `docs/demos/m0.md`.
3. `src/diag/`: the registry, `Diag`, and the default, verbose and JSON renderers; the new exit codes; the CLI usage errors moved onto it; global flags; `zbx explain`; the panic handler; golden and no-raw-error tests for the `E00xx` and `B0001` codes. `zig build`, `test`, `tidy` and every fuzzer for 10,000 iterations must pass.

**Slice 5 · Doctor and demo.** The doctor FAILs as `E01xx` diagnostics; the updated fixtures, goldens and fuzzers; the harness and demo assertions; `docs/demos/m0.md` updated (the steps, the exit codes, and the "Cut from M0" list); `zbx help`; and the errors site, unless it is cut. Run `zig build demo-m0 -Daccel=tcg` locally, from a fresh VM, and paste the tail of its output.

## Done means

- Everything in `M0-doctor.md`'s "Done means", plus the CI `demo-m0` job green on the pushed branch **with the slice 5 assertions**. Until then, M0 is "built, not demonstrated".
- Your report lists what you ran and its output, what you did not run and why, every deviation from this brief, and anything in the spec, this brief or `DIAGNOSTICS.md` that seemed wrong.
