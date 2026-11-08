# M8 slice 2, part 2a: where it stopped, and what part 2b starts from

Status: part 2a is committed and pushed to `claude/m8-slice2-part2`. It builds on part 1
(`claude/m8-slice2-sign`, PR #67). Part 2b is NOT started. The first context window ended while
part 2a was being finished, so by the context rule this is where the slice splits.

## Done in 2a
- `src/trust/dsse.zig`: PAE, `sign`, `render`, `verify`, `parse` (canonical base64 checked by
  re-encoding; members read in the writer's order; duplicates, extras and trailing bytes refused).
  `Work` (about 0.44 MB) is caller memory. Helpers `expect`, `expect_key`, `read_string` are shared.
- `src/trust/statement.zig`: in-toto Statement v1, subjects (`tree`, then optional `result` or a
  `<reference>` with `sha256`), `sign/v1` predicate, RFC 3339 time (`format_time`/`parse_time`).
  `parse` returns `Malformed` or `UnknownPredicate` (any predicate type but sign/v1: provenance
  is slice 4 and must extend it; its scratch sizing is a new bound for the supervisor).
- Tests: PAE published vector; an envelope equal to securesystemslib 1.6.0 output (seed bytes
  1..32; captured in this container in a venv); goldens; each field changes the payload; flipped
  bytes fail; malformed spellings; bounds at and one past (`statement_subjects_max` 2,
  `statement_bytes_max` 128 KiB, envelope one past).
- `src/fuzz_trust.zig`, registered in `fuzz.zig` as `trust`.
- Constants (approved values): `statement_subjects_max`, `statement_bytes_max`,
  `signatures_per_tree_max`, `trust_records_max`, `type_uri_base`.
  **Derived or internal, not approved numbers, flag to the supervisor:** `signed_at_text_bytes` (20),
  `signed_at_seconds_max` (year 9999), `payload_base64_bytes_max`, `envelope_overhead_bytes` (512),
  `envelope_bytes_max`, `signature_record_bytes_max`, and `sign_predicate_path`.

## Left for part 2b
1. The record (`src/trust/record.zig`): `trust/signatures/<tree hex>` JSONL, at most
   `signatures_per_tree_max` lines, `signature_record_bytes_max` bytes; parse accepts only what
   render writes (each line must `dsse.parse`, and re-render byte for byte); atomic write via
   `fs.write_atomic` under the store lock; the same line twice is a no-op; a 9th distinct line
   and `trust_records_max` are E0910; a damaged or newer record is E0903 (a newer statement
   shows as `UnknownPredicate`). A simulation test that crashes at every write and asserts old
   or new. Tests at each bound and one past.
2. `zbx sign <digest> [--key <name>] [--passphrase-file <path>]`: resolve result, tree, then
   `name@sha256:` manifest; the uncached tree check by factoring `check_object` out of
   `src/store/verify.zig` (it takes a `*Run`; the shared function wants a store, a workspace,
   and a damage sink) and `walk.objects`; open the key with `key_store.read_secret`, `key.open`
   and `passphrase.acquire`; `--output json` prints `zbx.sign/1`.
3. Codes E0903 and E0910 with explain text, error pages and goldens (`zig build errors-site-check`),
   `help`, `zbx schema` entry `zbx.sign/1`, `src/diag_golden.zig`, `docs/demos/m8.md`.
   Pattern: the `key` command in `src/cli.zig` and `src/trust/key_commands.zig`.
4. Cut recorded: provenance statements (slice 4).

## Traps found
- Zig 0.17 has no `**` array repetition (`zig fmt` rewrites it to `* *`): use `@splat`.
- A reader token's string slice lives in scratch and is clobbered by the next `next()`: copy
  before the next call (a fuzzer panic found this).
- `zig fmt` explodes long table literals into one very long line; tidy then fails: split tables
  into one entry per line yourself.
- `u3` cannot hold 8; `++` needs comptime values (use consts, not functions).
