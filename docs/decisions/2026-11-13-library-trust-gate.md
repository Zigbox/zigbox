# The library's start runs the trust gate `zbx run` runs

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
  nothing either: the tree, the store and the image record are not read for it.
- **Tamper check as `zbx run`.** On when any policy file exists, even one that asks nothing
  (`zbx run` does the same, and the two must agree); `verify = .always` re-hashes
  every object. A caller's own `StartOptions.tree_check` still runs, after the tamper check.

## Why

The system policy is what binds an agent to a rule (spec, "Limits an agent cannot flag its way
past"). Zigcube's agent starts containers through the library, not through `zbx run`, so until now
a node's `require_signature` did not bind the agent at all.

## Consequences

- **Signature change.** `zigbox.start` takes one more argument, a caller-owned
  `zigbox.GateWorkspace` (about 17 MiB, which must not move during the start). The ungated
  `run.start` is no longer part of the library.
- **The binding is the caller's.** `Spec.binding` says which result or manifest the tree is
  bound to; it is what `zbx exec`'s gate reads back later. A binding can only choose among
  statements about the same tree, so a wrong one makes fewer statements count and never lets an
  unsigned tree through. A caller that runs an image by name and leaves the binding `none` is
  judged on tree-only statements, where `zbx run` would bind the manifest.
- **Wording.** The library's refusal names the tree's digest (or the result's), never an image
  name; `zbx run` of a full digest prints the same text.

## For Zigcube

The agent will now see this refusal from `zigbox.start`: `error.StartFailed`, with `diag.code` one
of E0903 to E0907 and nothing made on the node. The agent should map it to its own refusal record
(the container was refused by the node's policy, with the code and the rendered diagnostic), and
not retry it as a transient start failure. Nothing is made, so there is nothing to clean up.

## Open

- `zigbox.exec_start` is not gated in the library (`zbx exec` gates in the CLI), and a build step's
  start (`zigbox.build`) runs trees the build made from judged bases. If Zigcube's agent calls
  `exec_start` directly, gating it is a follow-up.
