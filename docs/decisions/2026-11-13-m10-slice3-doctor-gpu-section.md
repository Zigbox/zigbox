# M10 slice 3: doctor's GPU section

Decided 2026-11-13 (implementer, slice 3; assumption).

- The section appears only when something GPU-shaped exists (a CDI spec, a render node,
  `/dev/kfd` or the NVIDIA driver file). Every existing doctor golden is therefore unchanged.
- In text it is `gpu  ok|gap <kind> <subject>  <detail>` lines after the report; in
  `--output json` it is a `"gpu":[...]` array before the closing `]}`, present only when
  non-empty. The schema gains an optional `gpu` property.
- A GPU gap never changes the exit code: a host without a GPU is healthy.
- Items: spec, device, driver, node, fix. Each gap has one fix line. Bounds in `constants.zig`:
  `doctor_gpu_items_max` 24, subject 80 bytes, detail 160 bytes; items past the bound are
  counted, not printed.
- Spec directories are those of discovery (`$XDG_CONFIG_HOME/cdi` or `~/.config/cdi`,
  `/var/run/cdi`, `/etc/cdi`); a refused spec is shown with the reason.

# Handoff (slice 3 to slice 4)

- Help is 16383 of 16384 bytes: adding a flag needs trimming help or a bound change (ask).
- `sim.world.list_written` lists only `write_file`d files; tests of directory listings must
  write the nodes. `sim.groups`/`groups_count` are set after `sim_run.start`.
- The test binary's static data is near its bound: put big simulators on the heap.
- `fuzz_doctor` knows the GPU section (`report_part` cuts stdout at the first `gpu  ` line).
