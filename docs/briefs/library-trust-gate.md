# Library start behind the trust gate

*Owner-approved change, 2026-11-13 ([decision](../decisions/2026-11-13-library-trust-gate.md)).*

## Goal

`zigbox.start`, the start Zigcube's agent calls, runs the trust gate `zbx run` runs. The node's
policy then binds every container started on it, whichever door it came through. Before this
change, the library's start ran any tree, signed or not, and a node with `require_signature` in
`/etc/zbx/policy.zon` only enforced it from the command line and at `zbx exec`.

## Design

- One gate, `src/trust/start_gate.zig`, shared by `zbx run` (`cli.zig`, `check_policy`) and the
  library. It loads the same policy files (`gate.load`: `/etc/zbx/policy.zon`, then the user's),
  judges with `gate.judge_all`, and turns the tamper check on as soon as any policy file exists,
  with `verify = .always` forcing a full re-hash, as `zbx run` does.
- `zigbox.start(host, spec, options, handle, gate, diag)` is `run.start` behind the gate. The
  ungated `run.start` is no longer exported. `gate` is a `zigbox.GateWorkspace` (about 17 MiB) the
  caller owns and does not move during the start.
- The subject is the `Spec`'s tree (a prefix or an image name is resolved first, and the start
  runs the tree judged) and `Spec.binding`, kept only when the store's record of that result or
  manifest names the same tree; a name left unbound is bound to the manifest it resolved through.
  What was judged is what the run record keeps for the gate at `zbx exec`. A directory
  (`Spec.rootfs`) has no tree, so any check refuses it, as `--rootfs` is.
- `zigbox.exec_start(host, spec, options, handle, gate, diag)` is `exec.start` behind the gate
  `zbx exec` runs (`exec_gate.check`). `build.step.run_step` is no longer exported: it starts its
  base ungated, and only the build knows the lock's manifest to bind it to (review of #147).
- A refusal is `error.StartFailed` with `diag` set to the code `zbx run` gives (E0903 to E0907),
  before anything is made: no run record, scope or log.
- There is no opt-out. With no policy file, the gate reads the two policy paths and nothing else,
  and the start is the ungated start.
- No new codes, bounds or defaults.

## Slices

One slice: the shared gate, the library's start, the tests (verdict table through both doors,
the refusal's diagnostic, the no-policy read set), and these docs. Its review (#147) added the
gated `exec_start`, the binding check, the unexported `run_step`, and tests for each.

## Non-goals

- Gating the build step's start in the library: `run_step` is not exported instead.
- Zigcube's own refusal record: Zigcube maps the code (see the decision's note).
- A fuzzer for the gate: none existed, and the library path is covered by the table test.
