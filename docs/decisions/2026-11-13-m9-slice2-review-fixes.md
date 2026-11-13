# M9 slice 2 review fixes: signal stop, bind roots, and what stays open

*Decided 2026-11-13, by the slice 2 fix session.*

- **A SIGINT or SIGTERM stops a build through the normal abort path.** The build run catches both
  (`Host.catch_interrupts`), the scheduler sees `Interrupted`, and the step roots it added are
  removed (`Context.unroot`). The stop reuses E0419 (`store_diagnose.worker_ended`) with a
  `.report` sentence naming the signal, so no new code is registered. SIGKILL still leaves roots
  to the cache GC's age rule.
- **A bind's selection is rooted while its step runs**, and every holder of a root is counted per
  tree, so two steps sharing a tree release it only when the last holder ends.
- **Not done: counting root holders across processes.** Two `zbx build` processes on one store can
  still release a shared root early. Closing that needs a lock the cache does not have; recorded as
  a known limit in `docs/demos/m9.md`.
- A user that does not fit the settings block refuses with E0807 instead of asserting.

See `docs/demos/m9.md`, Rooting.
