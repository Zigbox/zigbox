# M8 slice 14: the derived binding and image record version 3

Date: 2026-11-09. Lane U, implementer note.

- **Record version 3** adds the config's labels (`.label_key`/`.label_value`, key order) or
  `.labels_unknown = true`. Older records read with labels unknown and derive nothing.
- **One encoder.** `build/result.zig` `encode_parts` serves both a result's `Config` and an image
  record, so the derived digest equals M7's by construction; `record_version` of the result stays 1.
- **Label bound 2 KiB / 32** (`image_labels_*`): 8 KiB would overflow the 80 KiB record buffer.
  Past the bound the labels are unknown, never refused: a deviation from the brief, no new refusal.
- **Exec** derives from the image record found by manifest binding, as run does; the run record's
  version is unchanged.
- **W0551** (tree annotation differs): registered like W0552, goldens and site pages included.
- **VM pins:** `image_record_version_m8 = 3` is what this zbx writes after a pull
  (`upgrade_m5.zig`); the pins for what old releases wrote stay 1 and 2.
- **Trap:** a build-step base in `compose.zig` records no labels, so it derives nothing.
- **Next:** CI result of `vm/all-slice14`; the supervisor updates README and site.
