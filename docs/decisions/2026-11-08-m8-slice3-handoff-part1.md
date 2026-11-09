# M8 slice 3, part 1: handoff

Done and committed on `claude/m8-slice3-policy`: the policy reader, the pure verdict, the gate
module, the gate in `zbx run`, codes E0904 and E0905 (goldens, pages, index), tests (policy,
verdict, gate against the sim store, one cli test that a refused run starts nothing).

## Decisions
- Every policy file that exists applies; a run passes each. No file means no checks.
- Binding: a tree-only statement counts for any run; a result-bound one only for a run of that
  result; a manifest-bound one only for a run of that manifest. The run's subject comes from
  `Prepared.manifest` (image), the operand digest (result), or nothing (bare tree).
- A directory (`--rootfs`) has no tree: refused under `require_signature`.
- Anything unreadable in a policy file is E0904; only "absent" is silent.
- `require_provenance = true` is E0904 until slice 4.
- `HostSim`'s default file system is empty rather than crashed (it made every sim run fail in
  the gate); nothing else depended on it being down.

## Traps
- `fs_sim` `put_*` asserts the path is absent: remove first. `key new` creates `~/.config/zbx`.
- Explanation lines in `codes.zig` are at most 76 columns; it is a comptime assert.
- Goldens have no regenerate mode; a temporary `std.debug.print` of the block gets the text.

## Next (part 2, and the rest of part 1's plan)
1. `zbx policy check [operand]` (`policy_commands.zig`, schema `zbx.policy/1`, help text,
   `command_named`, `operands_count`): print each file, rule, signature and why it counts.
2. Build-step gate: each step's base before its container starts; the refusal names the step.
3. Exec gate: needs the run record to carry the binding (record_version 8 to 9): ask the
   supervisor first, it is a format change.
4. Tamper check (E0907): the walk in the store child, `trust/verified/<tree hex>` with
   `(object id, inode, size, ctime_ns)`, `verify = "always"`, gc removing `verified` entries.
5. VM part in `src/testing/vm/main_m8.zig`.
