# Package writer bounds and maintainer string (M8 slice 6)

Decided by the supervisor, 2026-11-08.

- The bounds in `src/constants.zig`, "Packages (M8, slice 6)", are internal: they cap what the
  writers in `src/package/` accept (files per package, path, file and payload sizes, Recommends,
  description, repository metadata). None is a user-visible limit of `zbx`; a refusal names the
  bound in one line from `zig build packages`.
- The package maintainer, `constants.package_maintainer` = "Zigbox project <packages@zigbox.org>",
  is a supervisor assumption. The owner may change it: it is one constant, and a change alters the
  control file and the rpm header, so it changes the package bytes.
