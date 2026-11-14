# M9: `.src = .{"."}` copies the whole project again

*Implementer of slice 3b, 2026-11-14; ruled by the supervisor the same day (option A).*

**Context.** 0.5.1 (commit 6555fcb) refused a project copy source with an empty or `.` part
(E0801, `bad_project_source`), `.` included, because `input_tree.collect` asserted on it. Its fix
line told users to write `.src = .{"*"}` with a `.to` ending in `/` for the whole project. That
advice was misleading: `copy.zig` follows Docker's rule that a matched directory puts its
*contents* into `.to`, so `*` lays `src/a.txt` at `/app/a.txt`, not `/app/src/a.txt`, and files
of the same name in two top-level directories collide. The Dockerfile translator wrote `.` for
`COPY . <dest>`, so every such import stopped parsing.

**Decision.**

- The parser takes exactly `.src = .{"."}` from the project, meaning the whole project.
  `./x`, `a/./b`, `a/`, `a//b` and `./` stay refused (E0801). No new code, no bound changed.
- The input tree reads `.` as the glob `*` at the project's top: the same entries, the same
  excludes (`.exclude` and the step's, which a translated `.dockerignore` becomes), each taken
  whole. `collect` never keeps `.` as a path, and asserts it.
- `copy.select` already reads `.` as the whole tree, which lays its contents at `.to`: the result
  is Docker's `COPY .`.
- The translator writes `.` for the whole context (`.`, `./`, `/`) and every other context
  source in plain parts (`./x` → `x`, `a//b` → `a/b`, a trailing `/` dropped). A `..` part is
  left for the parser to refuse.
- E0801's `bad_project_source` fix now says `.` copies the whole project, and recommends `*` for
  nothing.

**Superseded.** The brief's `COPY . .` golden is unchanged in text (`.src = .{ "." }`) and parses
again; the "translate `.` to `*`" plan the supervisor first gave for this fix is overtaken by
this file.

**Release note (0.5.2).** "`.src = .{"."}` copies the whole project again; 0.5.1 refused it and
suggested `*`, which flattens directories."
