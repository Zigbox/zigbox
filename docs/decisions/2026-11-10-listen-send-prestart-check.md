# `--listen-send` is checked before the container starts

Date: 2026-11-10. Slice: M8b review fixes (PR 89).

## Decision

- A `--listen-send` value must be 1 to 10 digits and at most 2^31-1, and the descriptor must be an
  open Unix stream socket. Both are checked before `runtime.start`, and a refusal is E0606
  (`--listen is refused with these options`), exit 125. No new code is registered.
- E0609 now means only that the send itself failed after start (for example the peer closed its
  end). zbx then stops the container, waits for it, and the final record omits the listener.
- An open descriptor number cannot be reused by zbx's own opens, so the pre-start check also
  removes the fd collision the review found.

## Why

A value such as 4294967295 crashed zbx after the container had started, leaving it running.
E0606 already covers `--listen` option problems, so reusing it kept the change in scope.
E0606's summary and E0609's explanation changed; the generated errors site is updated with them.
