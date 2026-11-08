# M8 slice 6 (package writer): handoff after the first implementer

Status: the writers are built and checked against the real tools; the driver, build steps and docs are not.

Done (`src/package/`, all in the `zigbox_package` test root `src/package.zig`):
ar, tar, cpio newc, gzip; deb writer; rpm writer (header-only RSA signature slot, SHA-256 file digests);
OpenPGP v4 Ed25519 test key (detached, clearsign, armor); apt repo writer; dnf repo writer.
Checked: `dpkg-deb`, `rpm -K/-V`, install under `--root`, `rpm -Kv` after importing the test key, `gpg --verify`
for detached and clearsign signatures, dnf filelists/other byte-equal to `createrepo_c`, primary equal except the
`<time file>` attribute (fixed epoch by design), Packages fields against `apt-ftparchive`.

Traps found:
- rpm header data offsets must rise with the sorted tag order (`Header.finish` re-lays the data out).
- Region trailer covers `(entries+1)*16`. DIRINDEXES 1116, BASENAMES 1117, DIRNAMES 1118. No ARCHIVESIZE (1046) in the main header.
- tidy forbids `assert(a or b)` style compound asserts and lines over 100 columns; `[_]u8{x} ** N` does not parse, use `@splat`.
- Scratch drivers must live under `src/` (module path rule).

Part 2 (second implementer): done.
- `src/package_release.zig` (pure: build the whole tree, `round_of`), `src/package_check.zig` (tree against metadata,
  via a `Source` with a function pointer so tests use memory), `src/package_main.zig` (I/O, CLI, printed gpg commands).
- build.zig: `zigbox_package` module, `packages` and `packages-check` steps (`-Dsignatures`, `-Dtest-key`).
- Docs: `docs/releases/packaging.md`, README install section, `docs/demos/m8.md`, `docs/decisions/2026-11-08-package-bounds.md`.
- The debug-built tool is slow on a debug `zbx` (17 MB); the build step feeds it release binaries, so it is fast there.

Not done / for the supervisor:
- `.github/workflows/vm.yml` knows only m0-m7 and `all`; a `vm/m8-slice6` branch fails at "Which demo". No VM check ran.
- `.github/ci-changes.sh` does not list `src/package_*.zig` among the paths that need no demo; they would run the full set.
- The install host layout in the README (zigbox.org/apt, /rpm, keys) is intended, not live.
- `rpm`, `createrepo_c` and `dnf` are absent from this container, so the rpm side was not re-checked here.
