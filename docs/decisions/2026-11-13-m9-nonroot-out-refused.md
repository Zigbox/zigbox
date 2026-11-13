# M9: a non-root `.user` with a writable `/out` stays refused

Date: 2026-11-13 (supervisor decision, slice 2)

A step that runs as a non-root `.user` and writes `/out` would leave files owned by ids in the
child's subordinate range, which the parent cannot read back or hash without more namespace
work. Slice 2 keeps the existing `needs_root` refusal for that case. It is a recorded cut in
`docs/demos/m9.md`, to be revisited when the root-output tests (item 6) show what the guest
allows.
