# M8 slice 2: where it stopped, and what the next implementer starts from

Status: the #65 leftovers are committed (ddfa440). Slice 2 itself (json, dsse, statement, record,
`zbx sign`, E0903/E0910, trust fuzzer) is NOT started; the implementer reached its context
ceiling after the leftovers and reconnaissance.

## Leftovers (done)
- E0902 for a `.key` alone is classed by age: `key_leftover_age_seconds` (600) and a recent one
  says "wait", never `rm`. A `.pub` alone has its own cause. `key new` sweeps old temporaries
  (`.<name>.(key|pub).<16hex>.tmp`, regular files only, `key_sweep_max` = 32 per run).
- The race test uses `testing.tmpDir` (`dir.realPath(testing.io, &buf)` returns a length).
- Trap: diagnostics wrap at ~70 columns, so tests that match cause text must match short
  phrases that do not cross a wrap.
- New constants (`key_leftover_age_seconds`, `key_sweep_max`) are new bounds: flag to supervisor.

## Plan for slice 2 (recon done)
- Proposed bounds (need supervisor approval): json_depth_max 16, statement_subjects_max 2,
  statement_bytes_max 128 KiB, envelope_bytes_max = base64(statement) + fixed overhead
  (comptime assert), signatures_per_tree_max 8, signature_record_bytes_max 8*(envelope+1),
  trust_records_max 4096. `type_uri_base` = "https://zigbox.org". Codes E0903, E0910 to register.
- Hand-written schema-directed canonical JSON reader (std's scanner needs an allocator).
- Record: `trust/signatures/<tree hex>` JSONL, atomic via `fs.write_atomic` under the store
  lock (`store/lock.zig` hold/release); same line twice is a no-op; a 9th line is E0910.
- `zbx sign`: resolve result, tree, then `name@sha256:` manifest without pull or lock; run the
  uncached tree check by factoring `check_object` out of `store/verify.zig` and using
  `walk.objects`; open key via `key_store.read_secret`, `key.open`, `passphrase.acquire`.
- Wiring points: `src/cli.zig` (`key` command is the pattern), `src/main.zig` test imports,
  `src/schemas.zig` (`zbx.sign/1`), `src/diag_golden.zig`, `src/diag/codes.zig`,
  `src/fuzz.zig` + new `src/fuzz_trust.zig`, `docs/demos/m8.md`.
- Ed25519 in std 0.17: `KeyPair.generateDeterministic`, `sign(msg, noise)`,
  `Signature.verify(sig, msg, public_key)`.

## Update after part 1 (json.zig, committed)
- Done: `src/trust/json.zig` (Writer, Reader), `json_tests.zig` (golden, refusals, bounds),
  `src/fuzz_json.zig` (`zig build fuzz -- json`), `json_depth_max` in constants, and
  `2026-11-08-m8-trust-bounds.md` (supervisor assumptions). The leftovers got a missing test:
  `key_sweep_max` at the bound and one past; E0902's explanation now covers the recent and
  `.pub`-only causes.
- API for part 2 and lane U: `Writer.init(buffer)`; `begin_object/array`, `end_object/array`,
  `key`, `string`, `unsigned`, `integer`, `boolean`, and `member_string/unsigned/boolean/
  object/array` (a key and its value); `finish()` returns the bytes. Members are written in the
  caller's order. Errors: `Overflow`, `TooDeep`, `InvalidUtf8`; misuse (value without key,
  second root) is an assertion.
- Reader is a pull parser: `Reader.init(bytes)`, `next(scratch)` gives a `Token` (`key` and
  `string` slices live in `scratch` until the next call). It accepts only the writer's form, so
  accepted text re-renders to itself. It does NOT check duplicate keys or member order: the
  schema layer must read members in the writer's order (compare each `key` token to the
  expected name) and refuse anything else, then call `next` once more and require `.end`.
- Decisions: no `null` and no floats; negative numbers are `.negative` (never zero), others
  `.unsigned`. The brief says "std's scanner"; std's needs an allocator, so the reader is hand
  written.
- Trap: a string token longer than `scratch` is `TooLong`: size scratch from the field's bound.
- Next (part 2): base64, DSSE PAE, envelope, statement (add `statement_subjects_max`,
  `statement_bytes_max`, `signatures_per_tree_max`, `trust_records_max`, `type_uri_base` to
  constants when used), the record, `zbx sign`, E0903/E0910 (new codes: ask the supervisor
  only if their text alters a bound), and the trust fuzzer.
