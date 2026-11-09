# M8 slice 5 (Verify): handoff

Status: complete on `claude/m8-slice5-verify`. See the PR for `zig build check`, the fuzz run and
the VM run.

## Done
- Library: `trust/tree_check.zig`, `trust/peer.zig` (`store.export_trust`, `import_trust`,
  `prune_trust`, `count_orphans`), `trust/peer_tests.zig`.
- Diagnostics E0908, E0909, W0902, W0903 with goldens, explain text and pages.
- `verify_commands.zig`, `trust_commands.zig`, CLI wiring (`Parsed` struct in `cli.zig`),
  schemas `zbx.verify/1`, `zbx.trust/1`, `zbx.trust-prune/1`, `trust_orphans` in gc's JSON.
- Tests `trust/verify_trust_tests.zig`, the `peer` fuzzer's bundle property, the VM guest check.
- `docs/demos/m8.md` slice 5 part, `docs/decisions/2026-11-09-verify-absent-input-w0903.md`.

## Traps
- W0901 is slice 4's (provenance store full); verify's warning is W0903.
- Test binary static data is near the 2 GiB limit: heap-allocate `SimFs`/`HostSim`/workspaces in
  tests. Big workspaces in commands overlay unused memory (`@ptrCast`, comptime size asserts).
- `import` makes a root record: a test that wants gc to take a tree must `roots.remove` it.
- gc cannot run after a tree is deleted by hand (E0422); orphan a tree with gc itself.
- Sim hosts report owner 0; only the VM proves the tree check.

## Next
- Slice 14's derived-result binding for verify (cut here).
- Update README and `site/index.html` once `demo-m8` is green in CI (supervisor).
