# Signing again changes nothing, whatever the clock says

*Decided 2026-11-08, by the supervisor, in review of PR #70 (M8 slice 2 part 2). Brief:
`docs/briefs/M8-trust.md`, "`zbx sign`".*

The brief says signing the same statement again changes nothing, because Ed25519 is
deterministic. That holds only while the statement is byte for byte the same, and every
statement carries `signedAt`. A second `zbx sign` a second later made a new line, so a CI job
that signs on every build filled the tree's eight lines and locked every other signer out, with
no command in this release to make room.

The decision:

- A signature by a key over the same subjects as a line already in the record counts as already
  present. The same subjects means the same tree, the same binding (none, the same result, or the
  same manifest under the same subject name and digest), and the same statement type.
- `zbx sign` then changes nothing. It reports the existing signature (`added: false`, "already
  signed by this key") and exits 0. That is the brief's "signing again changes nothing".
- `signedAt` stays in the statement, and the comparison ignores it.
- An existing line is never replaced or rewritten. The first signature's time is kept.

Two spellings of one image reference are one subject: the manifest subject's name is the
canonical, tagless `registry/repository@sha256:<digest>` of the operand (`REVIEW.md`, "Image
references"), so `alpine@sha256:X` and `docker.io/library/alpine@sha256:X` make one line.

Detail: `docs/demos/m8.md`, `src/trust/record.zig` (`signed_already`).
