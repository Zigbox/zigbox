# M4b · Mac: the VM's kernel, image, lifecycle and size (slice 1)

*Decided 2026-10-29, on the slice 1 proposals.*

- **The kernel is Linux 6.18.59 (longterm), built from the upstream source** with a checked-in config fragment (`vm/kernel/config-arm64`, applied over `allnoconfig`), everything built in. The tarball is pinned by its SHA-256 and the resulting `Image` by its own (`vm/kernel/pin.zon`); the build fails if either differs.
- **The kernel and the initramfs are embedded in the macOS `zbx`** and unpacked on first use into `~/Library/Application Support/zbx/vm/<image version>/`. The image version is a digest over both, so an upgrade is a file swap and a version mismatch cannot ship.
- **The idle timeout is 5 minutes** (a named constant).
- **The VM boots with 4 vCPUs (or half the Mac's if fewer) and 2 GiB**, as named constants.
- **Sizing is a persisted setting, and the VM is never started explicitly by the user.** `zbx vm config --cpus N --memory SIZE` writes a small versioned record; every boot, explicit (`zbx vm start`, an optional pre-warm) or lazy from any command, reads it. A running machine keeps its size until it stops. The range is the named constants, Virtualization.framework's limits and the Mac's own CPUs and memory together.
- **The Homebrew tap is `Zigbox/homebrew-tap`.**
