# Brief: M4b · Mac

This brief is for a Claude Code session running on the owner's Apple Silicon Mac, not in the cloud container that built M0 to M6. It is written to stand alone: everything you need is in this repository. The owner hands it to you; you are both the implementer and, for this milestone, your own first reviewer, and the owner reviews and merges the PR.

Read these first, in order:
- `AGENTS.md`, `REVIEW.md`, `docs/STYLE.md` and `DIAGNOSTICS.md`. Where AGENTS.md describes the cloud container (its environment facts, `vm/*` scratch branches, the `tester` user in `zig build check`), read "How this milestone differs" below instead.
- The M4b section of `docs/SPEC.md` (live doc rev 62; the live doc wins if they disagree), with "Production readiness" and "Agent operability".
- `docs/DECISIONS.md`: the M4b entries, and the M5 and M6 entries, whose features the Mac must carry (published ports, state volumes, `-e`, mounts).
- `docs/demos/m1.md` to `docs/demos/m6.md` for what the Linux `zbx` does, and `src/testing/vm/` for how the demos drive a VM today: the harness boots an Ubuntu guest under QEMU, and M4b's VM is a different, much smaller thing.

Do not start M7 or anything the spec defers: no Intel Macs, no Windows, no GUI, no per-container microVMs (stretch S1). Every Linux demo (`demo-m0` to `demo-m6`) and the top-20 check must keep passing on Linux CI.

## Goal and demo (from the spec, live doc rev 62)

A Mac user goes from `brew install zigbox` to a running container with no setup step.

1. On a clean Mac: `brew install zigbox`.
2. `zbx run alpine -- cat /etc/os-release` prints Alpine. The first run, VM boot included, takes under five seconds on Apple Silicon.
3. `zbx run --rootfs ~/demo/alpine -- touch /hello`; on the Mac, `ls ~/demo/alpine/hello` shows the file.
4. Leave it idle past the idle timeout: Activity Monitor shows no VM. The next `zbx run` brings it back.

Acceptance criteria:
- Nothing to set up between `brew install` and the first `zbx run`, and no administrator password prompt.
- The macOS binary is signed and notarized; Gatekeeper shows no warning.
- The M1 to M4 demos pass unchanged inside the VM, driven from macOS. If hosted macOS CI runners cannot nest virtualization, this runs on a self-hosted Apple Silicon runner.
- Every failure in the VM layer is a coded diagnostic with a fix, in a new code group added to DIAGNOSTICS.md (both repos) when M4b starts.
- Since M5 and M6 shipped before M4b, the Mac also carries them: `--publish` reaches the Mac's `localhost`, and `--state` volumes persist across VM stops. M5's spec says its acceptance criteria "then cover the Mac too".

## How this milestone differs

- **Two binaries.** The Linux `zbx` is unchanged and stays static, libc-free and `ReleaseSafe`: it runs inside the VM, built for `aarch64-linux` as today (`zig build release`). The new macOS `zbx` is `aarch64-macos`, links libSystem (macOS requires it; the spec allows it for this binary only), and is mostly a forwarder: it starts or finds the VM, forwards the command line, standard streams, signals, terminal size and exit code over vsock, and prints the result. It implements no container logic of its own.
- **No third-party code, still.** Virtualization.framework is an Objective-C API. Reach it from Zig through the Objective-C runtime (`objc_msgSend` and friends, declared `extern` by hand, with the framework linked by `-framework Virtualization`), or through `b.addTranslateC` where a plain C header serves; never through a third-party binding. Keep the Objective-C bridge in one small module with tests that run on macOS. If you find this impossible without a dependency, stop and report it to the owner; do not add one.
- **External programs.** Apple's `codesign`, `notarytool`, `stapler` and `xcrun`, and `brew` for the formula, are part of the release process, not of `zbx`. Name them in `docs/STYLE.md`'s list of allowed external programs, with what each is for, in your first slice.
- **Where you test.** This Mac is a valid test host, unlike the cloud container: you can run the real thing. Gates are still `zig build check` on the commit you report, but its non-root `tester` run and the Linux VM harness do not apply on macOS; make `check` skip what cannot run on macOS and say so in its PASS line, rather than failing. The Linux demos stay CI's job (`ci.yml` on the PR). macOS-only tests run here and, once it exists, on the Mac CI runner.
- **Commits and PR.** Work on a branch named `claude/m4b-mac` from `main`, commit in small steps with the attribution trailers your session gives you, and open one PR when slice 1 is done; push later slices to it. The owner merges. Never push to `main`.

## Fixed decisions

These follow the spec; anything marked **(propose)** is yours to settle with the owner before you build it, as a short note in the PR and a question to the owner, then an entry in `docs/DECISIONS.md` once answered.

### The VM

- **One VM per user,** booted lazily by the first command that needs it, stopped after an idle timeout (a named constant; **(propose)** a default, the spec implies minutes), never per container.
- **A small kernel plus an initramfs** carrying the Linux `zbx`, with a version that `zbx` checks against its own: a macOS `zbx` refuses to drive a VM image of another version, with a coded diagnostic, and replaces it. **(propose)** where the kernel comes from: building a pinned upstream kernel config in CI, or a distribution's arm64 kernel with virtio, vsock and virtiofs built in. Either way it is pinned by digest, and the build is reproducible from the repository.
- **Inside the VM, Zigbox is unchanged and fully rootless:** the initramfs's init starts the Linux `zbx` in a daemon-less forwarding mode as an unprivileged user with a subordinate id range, so the same user namespaces, cgroups (the init must give that user a delegated cgroup subtree, as systemd does on a host), seccomp and pasta work as on Linux. Anything the Linux `zbx` needs from the host (`newuidmap`, `pasta`, a cgroup v2 tree) is in the initramfs or set up by its init.
- **Storage.** **(propose)** The store and state volumes live on a disk image inside the VM, not on virtiofs: the store's hard links and the subordinate-id ownership of state data need a real Linux file system. The disk image lives in the user's Library (for example `~/Library/Application Support/zbx/`), grows sparse, and survives VM stops and `brew upgrade`.
- **The user's files.** The user's home directory is shared with virtiofs at the same path inside the VM, so `--rootfs ~/demo/alpine`, `--bind`, `--secret` and a project's `zbx.lock` work unchanged. Files a container writes through virtiofs appear owned by the Mac user.
- **Rosetta.** `amd64` images run through Rosetta's directory share when the user asks for `--platform linux/amd64` or an image has no arm64 variant; Rosetta not installed is a coded diagnostic with the command that installs it.
- **Network.** The VM gets Virtualization.framework's NAT network. `--publish HOST:CONTAINER` makes the published port reachable on the Mac's `localhost:HOST`, forwarded from the macOS `zbx` to the VM over vsock; nothing changes the Mac's firewall or routing, as on Linux.

### The macOS `zbx`

- **Every command** is forwarded, with its JSON output and exit codes unchanged; `--output json` documents are the Linux ones. Exit codes stay those of the Linux `zbx` plus the new VM-layer codes.
- **`zbx doctor` on macOS** checks the VM: whether it is running, its version against the binary's, file sharing, disk space for the disk image, Rosetta, and the virtualization entitlement. Each failing check is a coded diagnostic with a fix, in the new group.
- **Diagnostics.** A new group for the VM layer, **`10xx` macOS VM**, added to DIAGNOSTICS.md's list of groups. DIAGNOSTICS.md is shared with Zigcube: change Zigbox's copy (canonical) and say in the PR that Zigcube's needs the same line; do not edit the zigcube repository yourself unless the owner asks. Every failure: the framework's error translated into a cause and a fix, never an `NSError` dump.
- **Signing and distribution.** A Developer ID Application certificate and the `com.apple.security.virtualization` entitlement; notarization with `notarytool`, stapled. A Homebrew formula in a tap the owner names **(propose)**. No administrator password at install or first run.

## Slices (commit, report and wait for the owner after each)

1. **The bridge and a VM that boots.** The Objective-C bridge module with tests; a minimal kernel and initramfs that boot under Virtualization.framework from a small macOS `zbx` command (`zbx vm start`, `zbx vm stop`, `zbx vm status`); vsock up; the `10xx` group with its first codes. Measure the boot time and report it. The STYLE.md external-program list and the open **(propose)** decisions go to the owner in this slice.
2. **Forwarding.** The Linux `zbx` in its forwarding mode inside the VM; the macOS `zbx` forwarding the command line, streams, signals, terminal size and exit code; lazy boot on first use and stop on idle. Demo steps 2 and 4 by hand.
3. **Files and storage.** virtiofs for the home directory, the disk image for the store and state, Rosetta. Demo step 3; `demo-m3` and `demo-m6`'s state steps by hand inside the VM, driven from macOS.
4. **Network.** `--publish` forwarded to the Mac's `localhost`; M5's demo steps 2 and 3 driven from macOS.
5. **Release.** Signing, notarization, the Homebrew formula, `zbx doctor` on macOS, the macOS CI job on a self-hosted Apple Silicon runner (`runs-on` a label the owner sets up), running the M1 to M4 demos inside the VM driven from macOS, and `docs/demos/m4b.md` with the by-hand steps a stranger can follow on a clean Mac, cuts and failure modes: no virtualization entitlement, Rosetta missing, the disk image full, a VM of another version, the VM killed from Activity Monitor, and the Mac sleeping with a container running.

## Done means

- All gates pass on Linux CI (the PR), and `zig build check` passes on the Mac with what it skips named.
- The spec's four demo steps pass on a clean Mac (a fresh user account will do), recorded, and the macOS CI job is green on the self-hosted runner. Until then M4b is "built, not demonstrated".
- Each slice's report to the owner lists what you ran and its output, what you did not run and why, which REVIEW.md items you touched, every deviation from this brief, and anything in the spec, this brief or DIAGNOSTICS.md that seemed wrong.

## What the owner provides

- An Apple Developer ID (Application certificate) and the virtualization entitlement, in the Mac's keychain; an app-specific password or API key for `notarytool`, which you never print or commit.
- A self-hosted GitHub Actions runner on an Apple Silicon Mac, with a label for the job.
- A Homebrew tap repository, or the decision to create one.
