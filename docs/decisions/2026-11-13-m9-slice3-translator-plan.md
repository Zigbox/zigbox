# M9 slice 3: translator bounds and design (handoff, not yet built)

Date: 2026-11-13. Status: bounds added in `src/constants.zig`; design below is the plan the first
slice-3 implementer settled on before reaching the context ceiling. The next implementer may
change any of it, but should record the change here or in a new file.

## New user-visible bounds (flag for review)

These are new constants; none of the existing build bounds change.

| Constant | Value | Why |
| --- | --- | --- |
| `import_dockerfile_bytes_max` | 256 KiB | same as `build_file_bytes_max`; real Dockerfiles are far smaller |
| `import_dockerignore_bytes_max` | 64 KiB | `.dockerignore` becomes `.exclude`, at most `build_exclude_lines_max` lines |
| `import_instructions_max` | 2048 | `>= build_steps_max`; ARG/ENV/LABEL lines make no step |
| `import_stages_max` | 64 | `<= build_steps_max` |
| `import_words_max` | 256 | `>=` argv and copy-source bounds |
| `import_variables_max` | 256 | `>= build_config_env_max` |
| `import_scratch_bytes_max` | 256 KiB | substitution and heredoc output |
| `import_build_args_max` | 64 | `--build-arg` count |
| `import_report_lines_max` / `_bytes_max` | 1024 / 128 KiB | the W0810/W0811 report |

Exceeding any of them is E0815.

## Module layout

- `src/dockerfile/refusal.zig` (written): `Refusal {code, line, what, fix}`; `refuse(...)` fills
  it and returns `error.Refused`. The translator is pure; the CLI turns a Refusal into a Diag.
- `src/dockerfile/lines.zig`: parser directives (`syntax`, `escape`, `check`) only before the
  first instruction; logical lines (escape char plus trailing whitespace continues; comment and
  empty lines inside a continuation are skipped; joined with no separator); keyword enum; an
  unknown keyword is E0810; heredocs (`<<-?["']?NAME`), missing terminator is E0810.
- `src/dockerfile/words.zig`: JSON exec arrays, shell-word splitting, `$VAR`/`${VAR}`/
  `${VAR:-x}`/`${VAR:+x}` substitution, `--flag=value` parsing.
- `src/dockerfile/network.zig`: the brief's word table (apk add, apt-get, pip install, npm, go mod
  download, curl, wget, git clone, ...).
- `src/dockerfile/translate.zig`: stages, `--target` pruning, mapping, builds a `BuildFile` in
  memory, renders with notes, then parses its own output with `file.parse`; a refusal there is a
  programmer error (assert), so the fuzzer finds gaps.
- `src/dockerfile/report.zig`: text and `zbx.import/1` JSON report.
- `src/import_commands.zig`: the CLI; `src/fuzz_dockerfile.zig`; fixtures under
  `src/build/dockerfile_fixtures/`.
- `src/build/render.zig` needs a notes variant: a header plus one
  `// Dockerfile:<line>  <instruction>` comment before each step.

## Mapping rules settled

- Substitution only where Docker substitutes (ADD, COPY, ENV, EXPOSE, FROM, LABEL, STOPSIGNAL,
  USER, VOLUME, WORKDIR, ARG, ONBUILD-free) and in flag values; never in RUN, CMD, ENTRYPOINT,
  SHELL or HEALTHCHECK text. A referenced ARG declared with no value and no `--build-arg` is
  E0812; an undeclared name expands empty, as Docker does. ENV wins over ARG. Image env from the
  resolver feeds `$PATH` and similar. Platform args are global; inside a stage they need an ARG.
- Proxy args only from `--build-arg`, only into network steps' env, never into the config.
  `BUILDKIT_*` and `SOURCE_DATE_EPOCH` are ignored with W0811.
- Step env: the stage's ENVs plus in-scope ARG values. An ENV of a fixed key (HOME, TZ, LC_ALL,
  TERM, SOURCE_DATE_EPOCH, ZBX_BUILD_STEP) goes to the config only, noted under W0811.
- ENTRYPOINT resets an inherited CMD unless CMD was set earlier in the same stage (emit
  `.cmd = .{}`). Shell-form CMD/ENTRYPOINT/RUN become SHELL + text.
- WORKDIR is cleaned (`.`, `..`, repeated `/`); a relative WORKDIR or COPY destination resolves
  against the image workdir from the resolver, else `/`.
- Heredoc RUN: text only the marker gives argv = SHELL + body (`<<-` strips tabs); text before
  the marker gives the whole script to the shell; an interpreter after the marker, a shebang body
  or two heredocs is E0811.
- Cuts: `FROM scratch` with steps is E0811 (the builder has no scratch base; compose.zig resolves
  every base through the lock); a scratch target with config only becomes an image with no base.
  `RUN --mount=type=bind` from the context or an image is E0811 because the builder refuses those
  binds for good (graph.zig); record as a deviation in `docs/demos/m9.md`.
- Builder gaps to name in the report: copy `.chown`/`.chmod` and image sources are still E0802 at
  build time (slice 2 cut).

## Resolver

`translate` takes a resolver (context plus `resolve(ref) -> {env, workdir}`); the CLI's resolver
finds the reference in the lock, else pulls it (`pull.pull`) and `lock.put`s it
(`pull_commands.record_in_lock`). The translation lists the references it reached.

## Wiring checklist (mechanical parts can go to Haiku)

- `src/diag/codes.zig`: E0810..E0816, W0810, W0811, plus `can_end_run` (false for all).
- Diagnose functions, `src/diag_golden.zig` cases, `src/testdata/diag/*` goldens,
  `site/errors/<CODE>.html` and the index.
- `src/cli.zig`: `Command.import`, `command_named`, flags, dispatch, help text (stay under 16384
  bytes with the 512-byte margin test) and `src/testdata/help.stdout.txt`.
- `src/schemas.zig`: `import` schema; table count 39 -> 40 in `of()` and its test.
- `src/zigbox.zig`: `pub const dockerfile`; a second-caller library test registered in
  `src/main.zig`'s test block.
- `src/fuzz.zig` row `dockerfile`, plus `src/main.zig` fuzz test import.

## Std traps found

- Zig 0.17 rejects `"x" ** n`; use `const s: [n]u8 = @splat('x');`.
- `std.testing.expectError` needs an error union; for a plain error value use `expectEqual`.
