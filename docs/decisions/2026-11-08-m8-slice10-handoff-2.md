# M8 slice 10: handoff

Done: pack fuzzer, export and source.resolve CLI tests, goldens per entry kind, gc of pack
records, `zbx push --dry-run`, `zigbox.push`, ci rule, `demo-m8` VM check (main_m8.zig, vm.yml
`m8`). Next: slice 11 (upload, `zbx.push/1`). Traps: tidy bans compound asserts and 70+-line
test blocks; `**` repeat tripped a parse error; `put_file` is limited to 1536 bytes, so the VM
script is small; a `pgrep -f` waiter matches itself.
