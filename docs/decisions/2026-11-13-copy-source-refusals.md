# Copy sources: unplain project paths and many-to-one copies are refused

*Decided 2026-11-13, by the slice (0.5.1 fixes).*

## Decision

Two `.copy` shapes that used to crash or silently lose files are now refused with one line:

- **A project source with an empty or `.` part** (`"."`, `"./a.txt"`, `"a/"`, `"a//b"`,
  `"a/./b"`) is refused when the build file is read, E0801. Before this, these passed the
  build-file check and then tripped an assertion when the project tree was collected (a panic
  in a release build). Paths are refused rather than normalised because a project source is
  matched against the project's files exactly as written, and quietly rewriting `"a/"` to `"a"`
  would change what a glob next to it means. The whole project is `.src = .{"*"}` with a `.to`
  ending in `/`. A `step:` source keeps accepting `.` and `/`, which mean that step's whole tree.
- **Sources that match more than one path, copied to a `.to` without a trailing `/`**, are
  refused, E0803, naming the count. Before this, each match was copied onto the same path and
  the last one won, with no message.

No new code is registered: both reuse the code that already covers the step (E0801 for a
build-file value, E0803 for a copy whose sources cannot be laid out as asked), and E0803's
explanation gains a sentence for the many-to-one case.

The spec does not name either case. The detail is in [docs/demos/m9.md](../demos/m9.md).
