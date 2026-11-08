# M8 slice 10: bounds and accepted deviations

Date: 2026-11-08. Supervisor decisions, recorded by the slice 10 implementer.

Internal bounds (constants.zig): `pack_links_max` 16384, `pack_link_paths_bytes` 1 MiB,
`pack_config_bytes_max` 64 KiB, `pack_manifest_bytes_max` 4096, `pack_io_bytes` 256 KiB,
`export_file_mode` 0o644.

Accepted deviations (review may revisit): depth-first per-directory sorted entry order;
`source.resolve` accepts a bare tree digest; E0417 reused for export write failures; clamped
mode/uid fields with the real value in pax. Also from this pass: gc deletes pack records
(`pack/<tree hex>-<version>`) of a dropped tree without trashing them and does not print their
count; `zbx push --dry-run --output json` equals the text line; no ci-changes table test.

Codes: only E0550 and E0557 registered; usage errors use E0006.
