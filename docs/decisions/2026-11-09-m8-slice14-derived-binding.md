# M8 slice 14: the derived binding and image record version 3

Date: 2026-11-09. Lane U, implementer note.

- **Record version 3** adds the config's labels (`.label_key`/`.label_value`, key order) or
  `.labels_unknown = true`. Older records read with labels unknown and derive nothing.
- **One encoder.** `build/result.zig` `encode_parts` serves both a result's `Config` and an image
  record, so the derived digest equals M7's by construction; `record_version` of the result stays 1.
- **Label bound 2 KiB / 32** (`image_labels_*`): 8 KiB would overflow the 80 KiB record buffer.
  Past the bound the labels are unknown, never refused: a deviation from the brief, no new refusal.
  The supervisor accepted the bound (2026-11-09); `docs/demos/m8.md` lists it with the other limits.
- **Exec** derives from the image record found by manifest binding, as run does; the run record's
  version is unchanged.
- **W0551** (tree annotation differs): registered like W0552, goldens and site pages included.
  `pull_tests.zig` pulls a manifest whose annotation claims another tree (fixture `claim_tree`)
  and checks the warning names both trees and the exit is 0.
- **VM pins:** `image_record_version_m8 = 3` is what this zbx writes after a pull
  (`upgrade_m5.zig`); the pins for what old releases wrote stay 1 and 2.
- **Trap:** a build-step base in `compose.zig` records no labels, so it derives nothing.
- **Next:** CI result of `vm/all-slice14`; the supervisor updates README and site.

## Fix round (review of PR 77)

- **Done:** labels read in their own bounded scanner pass (`registry/config.zig`), so they can
  only be forgotten, never refuse a pull (main accepted repeated keys and huge values; tests
  pin both). The manifest's `annotations` is read by a non-failing `jsonParse`. A result-bound
  line for a pulled image whose record derives nothing is `not_derived`, not `other_binding`
  (new value in the policy-check JSON `reason` enum). W0551 names both trees in its cause, puts
  the id-mode cause first, and its fix is a command. Bound tests at exactly 2 KiB, a pulled-image
  run gate test, an exec derived test.
- **Traps:** Zig 0.17 `"x" ** n` inside expressions needs `test_util.repeat`; diag context keys
  max 6 chars; tidy wants 2 assertions per function on average (I had to add a few).
