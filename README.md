# Zigbox

A rootless, daemonless Linux container runtime, image store and builder, written in Zig, designed as if Docker were being invented today. Every milestone ends in a demo a person can watch work in under five minutes.

- **Design:** [docs/SPEC.md](docs/SPEC.md), a snapshot of the [live design doc](https://claude.ai/artifact/6D9js8mxSLYmfuZe3rQ26w).
- **How the code is written and tested:** [docs/STYLE.md](docs/STYLE.md) (TigerBeetle's TigerStyle, adapted).
- **Rules for contributors and agents:** [AGENTS.md](AGENTS.md).

## Status

*As of 2026-10-24. M0 slices 1–3 are demonstrated: `demo-m0` passed in CI with KVM ([run 2](https://github.com/Zigbox/zigbox/actions/runs/40048163873)), alongside build, tidy, test and all twelve fuzzers. M0 is not closed: the live design doc now requires the [diagnostics standard](DIAGNOSTICS.md) from M0 onward, so M0 gains two slices ([brief](docs/briefs/M0-diagnostics.md)). Slice 4, the diagnostics core, is built and reviewed.*

| Milestone | What it adds | Status |
| --- | --- | --- |
| **M0 · Doctor** | `zbx doctor`: is this host ready to run Zigbox? | **In progress**: slices 1–3 demonstrated in CI; slice 4 built and reviewed; slice 5 not started |
| M1 · Shell | Run a shell in a rootless, isolated root filesystem | Not started |
| M2 · Limits | cgroup limits, capabilities, seccomp, read-only root | Not started |
| M3 · Store | Content-addressed, deduplicated file trees | Not started |
| M4 · Pull | Pull and run public OCI images | Not started |
| M5 · Network | No network unless granted; published ports via `pasta` | Not started |
| M6 · State | Named, listed state volumes | Not started |
| M7 · Build | Hermetic, reproducible builds from a step DAG | Not started |
| M8 · Trust | Signatures, provenance and a run policy | Not started |
| S1–S5 | Stretch: microVMs, lazy start, egress grants, Dockerfile import, WASM | Not started |

### M0 in detail

M0 is built in five slices. Each is reviewed adversarially before it is pushed.

| Slice | Contents | Status |
| --- | --- | --- |
| 1 · Foundations | Zig 0.17.0 pinned; `build`, `test`, `tidy`, `fuzz` and `release` steps; limits in `src/constants.zig`; the host interface (`src/host.zig`) with real and simulated implementations; `zbx --version` and `zbx help`; the style checker; the seeded fuzz runner; release size gate (under 2 MiB) | **Built and reviewed.** Unit, snapshot and fuzz tests pass. Release binaries: x86_64 305 KB, aarch64 214 KB (stripped, static, ReleaseSafe). |
| 2 · Doctor logic | The six `zbx doctor` checks (kernel, user namespaces, cgroup delegation to the systemd user manager, overlayfs, subuid/subgid with `newuidmap`/`newgidmap`, seccomp); real probes in a forked child; parsers; 42 snapshot fixtures of real and broken hosts; 12 seeded fuzzers | **Built and reviewed.** Runs for real on the build container (root and ordinary users); verdicts on a real Ubuntu host await slice 3. Release binaries: x86_64 366 KB, aarch64 269 KB. |
| 3 · VM and CI | QEMU test VM harness in Zig, `zig build demo-m0`, GitHub Actions workflow, [demo document](docs/demos/m0.md) | **Built and reviewed.** `demo-m0` passed from a fresh VM under software emulation (TCG) in two independent runs (implementer and supervisor, about 8.5 minutes each): six `ok` lines, the right FAIL and fix for both sysctls, a static binary. **Demonstrated in CI** with KVM (run 2, `demo-m0` about 2 minutes). |
| 4 · Diagnostics core | `docs/SPEC.md` refreshed from the live doc; `src/diag/` (code registry, `Diag` collector, default, verbose and JSON output); exit codes from the standard; CLI errors as coded diagnostics; `zbx explain`; panic handler | **Built and reviewed.** CLI errors are coded diagnostics (`ZBX-E0001`–`E0009`, `B0001`) in text, verbose and JSON, with golden tests and a new `diag` fuzzer; exit codes 1 user, 2 environment, 70 bug; causes name the real errno. Local TCG demo passes; CI pending. Release binaries: x86_64 128 KB, aarch64 116 KB. |
| 5 · Doctor diagnostics | Each doctor FAIL as a `ZBX-E01xx` diagnostic; golden tests; `demo-m0` asserts codes and exit codes | Not started |

**What works today on this branch:** `zbx --version`, `zbx help`, clear one-line errors for bad input, and `zbx doctor`, which checks this host and names the fix for every failure. It has run only on the cgroup v1 build container so far; the M0 demo on a clean Ubuntu 24.04 VM is slice 3.

## Building

Requires Zig 0.17.0 exactly ([download](https://ziglang.org/download/)). There are no other dependencies.

```sh
zig build                          # zig-out/bin/zbx (debug)
zig build test                     # unit, snapshot and simulation tests
zig build tidy                     # formatting and mechanical style rules
zig build fuzz -- <fuzzer> [seed]  # one seeded fuzzer; prints its seed so failures replay
zig build release                  # static ReleaseSafe binaries for x86_64 and aarch64, size-checked
```

Linux only, by design. Running containers will need unprivileged user namespaces, cgroup v2 with user delegation and the `uidmap` package; `zbx doctor` checks all of this.

## License

MIT. See [LICENSE](LICENSE).
