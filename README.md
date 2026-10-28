# Zigbox

A rootless, daemonless Linux container runtime, image store and builder, written in Zig, designed as if Docker were being invented today. Every milestone ends in a demo a person can watch work in under five minutes.

- **Design:** [docs/SPEC.md](docs/SPEC.md), a snapshot of the [live design doc](https://claude.ai/artifact/6D9js8mxSLYmfuZe3rQ26w).
- **How the code is written and tested:** [docs/STYLE.md](docs/STYLE.md) (TigerBeetle's TigerStyle, adapted).
- **Rules for contributors and agents:** [AGENTS.md](AGENTS.md).

## Status

*As of 2026-10-28. **M0 to M5 are demonstrated.** `demo-m5` passed in an Ubuntu 24.04 VM with KVM ([run 63](https://github.com/Zigbox/zigbox/actions/runs/40751616386)), with `demo-m0` to `demo-m4` green in the same run: a container has no network unless granted (`wget` fails, and zbx says `network: none (grant with --net)`), `--net user` reaches the internet through `pasta` with DNS working behind systemd-resolved, `--publish 8080:80 nginx` answers `curl localhost:8080` from a listener the unprivileged user owns, the host's firewall rules are unchanged, and a published port is freed on every exit path, a crash of `zbx` included. The top-20 check now runs 16 of the 20 images ([run](https://github.com/Zigbox/zigbox/actions/runs/40740657844)). The owner tags `v0.0.0-m0` to `v0.0.0-m5`. M6 (state) is in progress; M4b (Mac) follows it, and needs an Apple Developer ID and an Apple Silicon runner.*

| Milestone | What it adds | Status |
| --- | --- | --- |
| **M0 · Doctor** | `zbx doctor`: is this host ready to run Zigbox? | **Demonstrated** in CI ([run 10](https://github.com/Zigbox/zigbox/actions/runs/40102173790)); every failure is a coded diagnostic |
| M1 · Shell | Run a shell in a rootless, isolated root filesystem | **Demonstrated** in CI ([run 24](https://github.com/Zigbox/zigbox/actions/runs/40137162669)): `demo-m1` in an Ubuntu 24.04 VM with KVM; all four slices green |
| M2 · Limits | cgroup limits, capabilities, seccomp, read-only root | **Demonstrated**: `demo-m2` passed in an Ubuntu 24.04 VM with KVM ([run 38](https://github.com/Zigbox/zigbox/actions/runs/40392815962)), with `demo-m0` and `demo-m1` green in the same run. [Brief](docs/briefs/M2-limits.md), [demo](docs/demos/m2.md). Five slices: the systemd scope and limit flags over a D-Bus client in Zig ([run 26](https://github.com/Zigbox/zigbox/actions/runs/40148646524)); exit reasons, cleanup, run record v2 ([run 28](https://github.com/Zigbox/zigbox/actions/runs/40193149219)); hardening: capability allowlist, `no_new_privs`, seccomp compiled to BPF, `--read-only` ([run 30](https://github.com/Zigbox/zigbox/actions/runs/40359277350)); the library for Zigcube with `run -d`, `stop`, `ps`, `schema`, `--timeout` ([run 33](https://github.com/Zigbox/zigbox/actions/runs/40379145533)); the VM demo ([run 38](https://github.com/Zigbox/zigbox/actions/runs/40392815962)). |
| M3 · Store | Content-addressed, deduplicated file trees | **Demonstrated**: `demo-m3` passed in an Ubuntu 24.04 VM with KVM ([run 46](https://github.com/Zigbox/zigbox/actions/runs/40480046060)), with `demo-m0`, `demo-m1` and `demo-m2` green in the same run and an upgrade test reading M2's run records. [Brief](docs/briefs/M3-store.md), [demo](docs/demos/m3.md). Five slices: trees and import ([run 41](https://github.com/Zigbox/zigbox/actions/runs/40418927198)); run by digest over a hardlink farm and overlayfs, and `zbx commit` with `zbx store diff` ([run 44](https://github.com/Zigbox/zigbox/actions/runs/40440579744), with the M2 scope-keeper fix); verify, gc by plan hash into a trash, restore and a store lock ([run 45](https://github.com/Zigbox/zigbox/actions/runs/40467489785)); the VM demo ([run 46](https://github.com/Zigbox/zigbox/actions/runs/40480046060)). |
| M4 · Pull | Pull public OCI images and run them by digest | **Demonstrated**: `demo-m4` passed in an Ubuntu 24.04 VM with KVM ([run 56](https://github.com/Zigbox/zigbox/actions/runs/40624651773)), with `demo-m0` to `demo-m3` green in the same run, an upgrade test reading M3's store, and a scripted agent that uses only `--output json`, `zbx schema` and `zbx explain`; the top-20 check passed on the same commit ([run](https://github.com/Zigbox/zigbox/actions/runs/40624666862): 13 pass; nginx, httpd and traefik want port 80, postgres, mysql and mariadb want a password variable, docker wants `mount`). [Brief](docs/briefs/M4-pull.md), [demo](docs/demos/m4.md). Five slices: references, the registry client, tokens and manifests ([run 48](https://github.com/Zigbox/zigbox/actions/runs/40523072890)); the docker.io mirror, a resumable blob cache, and layers applied into one store tree ([run 51](https://github.com/Zigbox/zigbox/actions/runs/40557878669)); image settings, `zbx.lock`, `zbx run <tag>` and `store du --by-image` ([run 52](https://github.com/Zigbox/zigbox/actions/runs/40604184049)); the top-20 check and seccomp under glibc, and the VM demo ([run 56](https://github.com/Zigbox/zigbox/actions/runs/40624651773)). |
| M5 · Network | No network unless granted; published ports via `pasta` | **Demonstrated**: `demo-m5` passed in an Ubuntu 24.04 VM with KVM ([run 63](https://github.com/Zigbox/zigbox/actions/runs/40751616386)), with `demo-m0` to `demo-m4` green in the same run, an upgrade test reading M4's store, records and lock, and a scripted agent driving M5's steps by JSON (its findings are in the demo document). [Brief](docs/briefs/M5-network.md), [demo](docs/demos/m5.md). Four slices: M4's carried-over notes (tags kept, `explain` and `lock show` as JSON, what ran; [run 59](https://github.com/Zigbox/zigbox/actions/runs/40712253270)); a network namespace per container, `--net none` by default and `--net host`, a real read-only `/sys`, generated `/etc` files ([run 60](https://github.com/Zigbox/zigbox/actions/runs/40726126464)); `pasta` for `--net user` and `--publish`, ports freed on every exit path, the `06xx` codes ([run 62](https://github.com/Zigbox/zigbox/actions/runs/40745019679)); the VM demo ([run 63](https://github.com/Zigbox/zigbox/actions/runs/40751616386)). |
| M6 · State | Named, listed state volumes | **In progress**: [brief](docs/briefs/M6-state.md). Slice 1 (M5's carried-over notes and `-e`) and slice 2 (state volumes) in progress |
| M7 · Build | Hermetic, reproducible builds from a step DAG | Not started |
| M8 · Trust | Signatures, provenance and a run policy | Not started |
| S1–S5 | Stretch: microVMs, lazy start, egress grants, Dockerfile import, WASM | Not started |

### M0 in detail

M0 was built in five slices. Each is reviewed adversarially before it is pushed.

| Slice | Contents | Status |
| --- | --- | --- |
| 1 · Foundations | Zig 0.17.0 pinned; `build`, `test`, `tidy`, `fuzz` and `release` steps; limits in `src/constants.zig`; the host interface (`src/host.zig`) with real and simulated implementations; `zbx --version` and `zbx help`; the style checker; the seeded fuzz runner; release size gate (under 2 MiB) | **Built and reviewed.** Unit, snapshot and fuzz tests pass. Release binaries: x86_64 305 KB, aarch64 214 KB (stripped, static, ReleaseSafe). |
| 2 · Doctor logic | The six `zbx doctor` checks (kernel, user namespaces, cgroup delegation to the systemd user manager, overlayfs, subuid/subgid with `newuidmap`/`newgidmap`, seccomp); real probes in a forked child; parsers; 42 snapshot fixtures of real and broken hosts; 12 seeded fuzzers | **Built and reviewed.** Runs for real on the build container (root and ordinary users); verdicts on a real Ubuntu host await slice 3. Release binaries: x86_64 366 KB, aarch64 269 KB. |
| 3 · VM and CI | QEMU test VM harness in Zig, `zig build demo-m0`, GitHub Actions workflow, [demo document](docs/demos/m0.md) | **Built and reviewed.** `demo-m0` passed from a fresh VM under software emulation (TCG) in two independent runs (implementer and supervisor, about 8.5 minutes each): six `ok` lines, the right FAIL and fix for both sysctls, a static binary. **Demonstrated in CI** with KVM (run 2, `demo-m0` about 2 minutes). |
| 4 · Diagnostics core | `docs/SPEC.md` refreshed from the live doc; `src/diag/` (code registry, `Diag` collector, default, verbose and JSON output); exit codes from the standard; CLI errors as coded diagnostics; `zbx explain`; panic handler | **Built and reviewed.** CLI errors are coded diagnostics (`ZBX-E0001`–`E0009`, `B0001`) in text, verbose and JSON, with golden tests and a new `diag` fuzzer; exit codes 1 user, 2 environment, 70 bug; causes name the real errno. Green in CI, `demo-m0` with KVM included ([run 5](https://github.com/Zigbox/zigbox/actions/runs/40096452657)). Release binaries: x86_64 128 KB, aarch64 116 KB. |
| 5 · Doctor diagnostics | Each doctor FAIL as a `ZBX-E01xx` diagnostic; golden tests; `demo-m0` asserts codes and exit codes | **Built, reviewed and demonstrated.** `FAIL <check> … [ZBX-E01xx]` on stdout, one diagnostic block per failure on stderr, exit 2; `demo-m0` asserts E0101 for both ways of disabling user namespaces, and E0001 with exit 1 for an unknown command; `site/errors/` pages generated from the registry and checked in CI. Release binaries: x86_64 173 KB, aarch64 156 KB. |

**What works today:** `zbx doctor` checks whether a host can run Zigbox and, for every problem, prints a coded diagnostic with the cause and a runnable fix (`zbx explain <code>` gives the long form, and `site/errors/` has the same pages for the web). `zbx --version`, `zbx help`, `-v` and `--output json` round it out. All of it has run in an Ubuntu 24.04 VM in CI.

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
