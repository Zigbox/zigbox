# The library's start and exec run the trust gates `zbx run` and `zbx exec` run

*Decided 2026-11-13, by the owner.*

## Decision

`zigbox.start` judges the container's tree against the node's policy before it starts it, exactly
as `zbx run` does (brief: [library-trust-gate](../briefs/library-trust-gate.md)):

- **Same policy files.** The node's own: `/etc/zbx/policy.zon`, then the calling user's file.
  Nothing the caller passes adds, removes or replaces a policy.
- **Same judgement and codes.** One shared gate (`src/trust/start_gate.zig`) for both doors, so
  the same image and policy give the same verdict and the same code, E0903 to E0907.
- **No opt-out.** There is no flag or option that skips the gate. A check the caller can switch
  off is not an independent judge.
- **Free when off.** With no policy file, the gate reads the two policy paths and nothing more,
  and the start is unchanged. A policy file that asks nothing (`any_checks` false) judges
  nothing either: the tree, the store and the image record are not read for it, and the `Spec`
  (its image and binding) is left as the caller gave it.
- **Tamper check as `zbx run`.** On when any policy file exists, even one that asks nothing
  (`zbx run` does the same, and the two must agree); `verify = .always` re-hashes
  every object. A caller's own `StartOptions.tree_check` still runs, after the tamper check.
- **Exec too.** `zigbox.exec_start` runs `zbx exec`'s gate (`exec_gate.check`) before the
  command starts: the container's tree and binding come from its run record.
- **No ungated start exported.** `run.start`, `exec.start` and `build.step.run_step` are
  internal. `run_step` starts a build step's base with no gate; `zbx build` judges each base,
  bound to the manifest its lock names, before the step, and only the build knows that binding.
  The rest of `zigbox.build.step` stays exported.

## Why

The system policy is what binds an agent to a rule (spec, "Limits an agent cannot flag its way
past"). Zigcube's agent starts containers through the library, not through `zbx run`, so until now
a node's `require_signature` did not bind the agent at all.

## Consequences

- **Signature change.** `zigbox.start` and `zigbox.exec_start` each take one more argument, a
  caller-owned `zigbox.GateWorkspace` (about 17 MiB, which must not move during the call, one
  start or exec at a time). `build.step.run_step` is no longer part of the library.
- **The binding is the store's.** `Spec.binding` counts only when the store backs it: a result
  binding when the store's result record names the tree started, a manifest binding when the
  store's image record does. Otherwise it is dropped, and the tree is judged as `zbx run` judges
  the bare tree. A name the caller leaves unbound is bound to the manifest it resolved through,
  with the result that manifest derives, as `zbx run` binds it. The `Spec` the start runs carries
  the binding judged, so the run record keeps it for the gate at exec.
- **Name to tree.** When a policy asks for something, an image name or prefix is resolved and the
  start runs, and records, the tree's full digest. With no policy, it runs as the caller gave it,
  so the image a run record shows depends on whether a policy existed at the start.
- **Wording.** The library's refusal names the tree's digest (or the result's), never an image
  name; `zbx run` of a full digest prints the same text.

## For Zigcube

The agent will now see this refusal from `zigbox.start` and `zigbox.exec_start`: `error.StartFailed`, with `diag.code` one
of E0903 to E0907 and nothing made on the node. The agent should map it to its own refusal record
(the container was refused by the node's policy, with the code and the rendered diagnostic), and
not retry it as a transient start failure. Nothing is made, so there is nothing to clean up.

### Upgrade note (for the next release's notes)

This is the first release whose library breaks callers. `zbx` itself behaves as before.

- **Breaks the build of a caller.** `zigbox.start` and `zigbox.exec_start` take a
  `*zigbox.GateWorkspace` before `diag`; `zigbox.build.step.run_step` is gone.
- **Changes what the agent may start.** On a node with a policy that asks for anything, an agent
  start or exec that passed before can now be refused (E0903 to E0907); on a node with any policy
  file, a damaged store object is refused (E0907).
- **Order.** 1. On each node with `require_signature` or `require_provenance`, sign the images
  the agent runs (and store their provenance). 2. Make the agent treat E0903 to E0907 from
  `start` and `exec_start` as final, and stop calling `run_step` (it builds through `zbx build`).
  3. Move Zigcube's pin to this release. Steps 2 and 3 land together, since the pin move breaks
  the agent's build until it passes the workspace.

## Open

- With no policy that asks for anything, the caller's binding is recorded as given, unchecked.
  If a policy is added later, `zbx exec` and `exec_start` judge the container on that binding,
  so a wrong one can make a statement count at exec that `zbx run` would not have counted.
  Checking the binding on every start would read the store when no policy exists, which "Free
  when off" rules out. A follow-up could check it at exec instead.
