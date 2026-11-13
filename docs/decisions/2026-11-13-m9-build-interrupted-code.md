# M9: a build stopped by a signal is E0808

*Decided 2026-11-13, by the supervisor (review of PR #134 on e515959).*

A `zbx build` stopped by SIGINT or SIGTERM used to report E0419 ("can't run the store worker")
with a `zbx doctor` hint: wrong, since nothing is broken and the user asked for the stop.

- New code **E0808**, "the build was stopped by a signal", severity error, blame user, exit 1.
  It is the next free build code: E0810 to E0819 are reserved for the Dockerfile import
  (`docs/briefs/M9-dockerfile-import.md`), E0808 and E0809 were unused.
- The message is one line naming the signal (SIGINT or SIGTERM) and saying the work of the
  unfinished steps was released, and one fix: run `zbx build` again (finished steps are cache
  hits). No `doctor` hint: there is nothing to diagnose.
- It is raised wherever the build checks for a stop: the start of a step, its input import,
  each copy entry's selection, an interrupted or pre-empted wait, the start of the image step
  and before the image's record is saved. A signal during the image's assembly is never exit 0.
- When another diagnostic was raised first (a failed step, then Ctrl-C while the others
  drain), that one is kept: the first diagnostic is the build's.
- A signal that arrives the instant the handler is installed, or before a wait, is the same
  outcome (it once tripped an assertion). A disposition the process inherited is restored when
  the build stops catching; an inherited SIG_IGN is never replaced, so `nohup` and a shell's
  ignored SIGINT still ignore it.
- Explain page: `site/errors/E0808.html`; goldens: `src/testdata/diag/E0808*.txt`.
