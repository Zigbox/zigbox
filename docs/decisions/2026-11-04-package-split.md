# Packages: one dev omnibus, and one package per role on Linux (owner, 2026-11-04)

*Decided 2026-11-04, by the owner.*

Refines `2026-11-04-linux-packages-in-m8.md`. M8 ships the `zigbox` package with `zbx` alone and a
package writer Zigcube can import. In Zigcube's C3, `zigbox` becomes the dev omnibus (`zbx`,
`zcube`, `zcube-server`, `zcube-agent`) and three packages carry one role each: `zigcube-cli`,
`zigcube-server`, `zigcube-agent` (which also carries `zbx`). On macOS, `zcube` joins `zbx` in the
Homebrew `zigbox` formula. Detail: `docs/briefs/linux-packages.md`; Zigcube
`docs/decisions/2026-11-04-package-split.md` and `docs/briefs/c3-linux-packages.md`.
