# M2 · Zigcube's diagnostic codes plug into Zigbox's diagnostics

*Decided 2026-10-26.*

Zigcube uses Zigbox's diagnostics machinery instead of keeping its own, and adds its own `ZC-` codes to it. A runtime failure on a node must reach `zcube why` intact, and both products must render diagnostics identically (DIAGNOSTICS.md, "Same model everywhere"). Today `Diag` is typed to the `ZBX-` code registry and the renderer hard-codes `ZBX-`, so a second registry cannot plug in.

**What changes:** a second product's registry plugs into the `Diag` data and the renderer without forking them. Zigcube's proposal (its `docs/diagnostics-plan.md`, option D) is a plain `Diagnostic` data type with JSON write and parse, and a `render` that takes a `Diagnostic` plus a product record (code prefix, command name, report URL, docs base) instead of a `*const Diag`. Each product keeps its own collector and registry. Settle the exact shape in the brief.

**When:** with the library slice (4), or a small slice just before it, so that the agent can carry `ZBX-` and `ZC-` diagnostics side by side from its first link.
