# The VM harness is a public module, `zigbox_vm`

*Decided 2026-11-02, by the owner (a harness refactor, not a milestone).*

Zigcube's real-runtime smoke test (C2 slice 1) boots the same Ubuntu 24.04 guest as Zigbox's demos. Rather than a copy that drifts, `build.zig` exports the harness's generic parts as the module `zigbox_vm` (`src/testing/vm/lib/`, described in [vm-module.md](../vm-module.md)): cloud-init rendering from a `Config`, the pinned image and its cache, the QEMU session (KVM, TCG when asked), its console exec channel, copy-in and teardown. What is Zigbox's (the `demo` user and its subuid range, packages, the userns sysctl, the zbx routes, which demo runs) stays in `src/testing/vm/` and is passed in. The `demo-mN` steps are built on the module, and a test checks that the rendered seed is byte for byte the hand-written one it replaced. The guest channel stays the serial console, not SSH: it needs no external program beyond QEMU.
