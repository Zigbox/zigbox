# M8 slice 11 handoff

*Decided 2026-11-09, by the slice 11 implementer.*

Built: upload protocol, `zbx push <source> <dest:tag>` without credentials, E0551/E0555/E0556,
`zbx.push/1`, push fixture, registry fuzzer upload mode. See `docs/demos/m8.md` (slice 11).

Decisions and traps:
- `reference.parse` fills in `latest`, so "names a tag" is checked on the operand text
  (`parse_destination` in `src/push/run.zig`).
- `Net.call` asserts `has_body() == (body != null)`; POST opens send `upload.empty_body`.
- `check_range` trusts a missing Range header and refuses a shorter or odd one.
- The VM `put_file` limit is 1536 bytes, so the check is two scripts (`m8-export.sh`,
  `m8-push.sh`).
- The guest check uses the apt `docker-registry` package, not `zbx run registry:2`.
- `net.Read` is the shared alias for a source read result (tidy bans `usize` in struct fields).

Next (slice 12): credentials and the token flow; `Net` will need an auth header hook. The mount
path is only simulator-tested.
