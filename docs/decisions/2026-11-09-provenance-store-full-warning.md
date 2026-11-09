# W0901: the provenance store is full

*Decided 2026-11-09, by the supervisor (M8 slice 4 review).*

When a build finds the provenance store at `trust_records_max` records, it still succeeds and
writes no record for the new result. That used to be a plain line on stderr. It is now a warning
with a code, `ZBX-W0901` (the first warning in the trust range, 09xx), exit 0, printed once on
stderr after the build in the build's output mode (text, verbose, or JSON).

- **Why a code:** a plain line is not machine-readable and has no explain text or page, and a
  policy with `require_provenance` refuses the result afterwards (E0906 `missing`), so the user
  needs somewhere to read why.
- **Message:** one line naming `trust_records_max` and `require_provenance`; fix: remove records
  of results no longer needed, then build again (a cache hit writes the record).
- **Treatment:** registry entry and explanation, goldens (`src/testdata/diag/W0901.*`), error
  page, and the test that lowers the bound to three expects the code.
