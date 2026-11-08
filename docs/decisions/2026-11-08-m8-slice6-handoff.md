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

Not done (next implementer starts here):
1. `src/package_main.zig` driver: `--version --zbx-x86_64 --zbx-aarch64 --license --out [--signatures dir] [--test-key] [--check]`;
   builds deb+rpm per arch (name `zigbox`, MIT, https://zigbox.org, `/usr/bin/zbx` 0755 + licence at the deb/rpm paths),
   writes `zig-out/packages/{apt,rpm/<basearch>,to-sign}`, prints the gpg commands. Signature file names chosen:
   `<rpmfile>.header.sig`, `InRelease`, `Release.gpg`, `repomd.<arch>.xml.asc`.
2. build.zig: `zigbox_package` module export, `packages` step (`-Dsignatures`, `-Dtest-key`), `packages-check` step.
3. `docs/releases/packaging.md` runbook (two gpg rounds, `rpmkeys --import`, `rpm -K`, `apt update`), README install commands.
4. `docs/demos/m8.md` slice 6 entry: createrepo_c time-attr difference, no PAYLOADDIGESTALT, Fedora rpm 6 needs the test key imported, VM check status.
5. Optional VM check (`vm/m8-slice6`): apt update against a repo signed with the test key. Harness changes go to the supervisor first.

Open for the owner: the maintainer string (placeholder "Zigbox project <packages@zigbox.org>" not yet written anywhere).
New internal bounds are in `src/constants.zig` ("Packages (M8, slice 6)").
