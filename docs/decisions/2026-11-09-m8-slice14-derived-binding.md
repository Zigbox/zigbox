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

## Paused by the supervisor (WIP handoff)

- **Done:** everything in the brief is in the commit: record v3, derive, verdict/gate/exec/policy
  check plumbing, W0551 with goldens and site pages, tests (round trip over random configs, every
  changed field, v2 derives none, verdict derived match, manifest annotation), VM pin
  `image_record_version_m8 = 3` in `upgrade_m5.zig`, docs/demos/m8.md. `zig build test` and
  `zig build tidy` passed before the commit.
- **Not run:** `zig build check` (stopped on request), the fuzzers (`fuzz -- lock`, peer), the VM
  run on `vm/all-slice14`, REVIEW.md on the diff.
- **Next:** run those; add a pull-level test for W0551 firing (only the manifest annotation parse
  is tested); check the self-tests in `checks_upgrade_m5.zig` still pass under the VM harness build.
- **Traps:** Zig 0.17 `"x" ** n` inside expressions needs `test_util.repeat`; diag context keys
  max 6 chars; tidy wants 2 assertions per function on average (I had to add a few).
