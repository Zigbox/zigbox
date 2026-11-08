# M8 slice 10 (pack and export): handoff

Status: PARTIAL. Built and unit-tested: the tar writer, gzip layer, config and manifest writers, the
pack record, the image record, `zbx store export --oci <source> DIR`, E0550 and E0557.

Not done: `zbx push --dry-run`, `zbx.export/1` in `zbx schema`, the `pack` fuzzer, the tar goldens
file and the `tar -tvv` / OCI-tool capture, the `src/push/` rule in `.github/ci-changes.sh`, the VM
check (`vm/m8-export`), the library export `zigbox.push`, the gc rule for pack records, and
`docs/demos/m8.md` text. The next slice agent starts with these.

## Decisions and deviations

- Entry order is depth-first with each directory's names sorted, not the byte order of the full
  path. Both are deterministic; the first avoids a global sort. Say so in the brief if it matters.
- `source.resolve` also accepts a bare tree digest with no image record (empty config); the brief
  says "a tree with an image record".
- A write failure of the export directory reuses E0417; no new code beyond E0550 and E0557.
- New bounds (constants.zig): `pack_links_max` 16384, `pack_link_paths_bytes` 1 MiB,
  `pack_config_bytes_max` 64 KiB, `pack_manifest_bytes_max` 4096, `pack_io_bytes` 256 KiB,
  `export_file_mode` 0o644. None is owner-approved yet; the supervisor decides.
- Tar mode and uid fields clamp to all sevens when too big; the real value is a pax record.

## Traps

- `Layer.finish()` returns the layer file's SHA-256, not the diff id.
- Registry order in `diag/codes.zig` must match the enum order.
- Diag goldens are blessed by running the test with an empty file and copying "instead found".
