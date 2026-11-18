# demo-s2: the fixture is made in the guest, the registry stays on the runner

*Decided 2026-11-18, by S2 slice 6 (the VM harness).*

The brief puts the registry and the fixture on the runner. demo-s2 keeps the registry there
(`src/testing/vm/registry_disk_s2.zig`: disk-backed, throttled to 40 MiB/s, with the byte counter
and the two faults), but the 3 GiB images are generated in the guest by `s2tool gen` and pushed
with the guest's own `zbx push`:

- Moving 6 GiB from the runner into the guest through the harness's HTTP server costs more time
  than generating it there, and the guest's disk would hold it twice.
- The push is part of what the demo shows: an image this `zbx` pushed is lazily startable.
- The generator is deterministic (`src/testing/vm/fixture_s2.zig`), so the runner computes every
  expected hash itself, and the script compares against those, not against anything the guest
  computed.

The guest drives the faults through `/control/...` on the registry, so each fault starts and ends
exactly around the command it is for. The guest reaches the registry through a loopback relay
(`s2tool forward`), because `zbx` sends plain HTTP only to a loopback registry; the relay adds no
throttle of its own.

The demo's steps continue after a failure, so one run shows every step; the demo fails if any
did. Detail: docs/demos/s2.md, "demo-s2".
