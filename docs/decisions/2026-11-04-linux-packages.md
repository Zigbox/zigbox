# Linux packages: deb and rpm in the release after 0.3.0 (owner, 2026-11-04)

*Decided 2026-11-04, by the owner.*

Zigbox's next release (after 0.3.0, alongside M8) ships `zbx` as a `.deb` and an `.rpm` from a
signed apt and dnf repository. "There's no reason not to have an RPM if we have a DEB." The
packages are built with the standard library, not distro tooling; signing stays on the owner's
machine; the package does not edit `/etc/subuid`. The signing tool, the hosting and the tested
distributions are open questions for the owner. Detail: `docs/briefs/linux-packages.md`.
Zigcube's packages are a C3 input (Zigcube `docs/briefs/c3-linux-packages.md`).
