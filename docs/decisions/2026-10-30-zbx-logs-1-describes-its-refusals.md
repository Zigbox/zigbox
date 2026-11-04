# `zbx.logs/1` describes its refusals: every document is checked against its command's schema

*Decided 2026-10-30, by the owner.*

- **`zbx schema logs` describes the error document a refused `logs --output json` prints** (E0402, E0217, and the rest), as `run`'s and `exec`'s schemas describe theirs: one object schema with no `$ref`, the diagnostic's members beside the record's, and `oneOf` to tell them apart. An agent can validate every document a command prints against that command's own schema. (The diagnostic is on stderr, the records on stdout, as before.)
- **Schemas only grow.** The record's members and its required ones (`schema`, `stream`, `time`, `text`) are unchanged, so the schema stays `zbx.logs/1`.
- The M6b agent test validates E0402 against the logs schema; its finding about this is gone.
