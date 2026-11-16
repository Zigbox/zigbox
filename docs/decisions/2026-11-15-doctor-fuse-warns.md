# zbx doctor's fuse check warns (W1203); it never fails

*Decided 2026-11-15, by the supervisor, on S2 slice 5b's question.*

S2 adds a `fuse` line to `zbx doctor` (`src/doctor.zig`): a probe child in a user and mount
namespace opens `/dev/fuse` and mounts FUSE, as `zbx run --lazy` does.

Only `--lazy` needs FUSE, and `--lazy` is an opt-in. So the check follows the net check's
precedent (pasta, which only `--net user` needs, is `W0102`): whatever the probe finds, the line
is `warn` with the new code `ZBX-W1203`, "lazy start (--lazy) is not possible on this host",
warning severity, environment blame, with the same causes and fixes as `E1201`. The exit status
of `zbx doctor` is unchanged. `zbx run --lazy` on such a host still refuses with `E1201`.

Rejected: (a) FAIL with `E1201`, which would turn every host without `/dev/fuse` (many
containers, some CI runners) into a failing doctor for a feature nobody asked for; (c) an
informational line with no code, which would leave `--output json` without a code or fixes.

`doctor.warns_only` names the two checks that only warn (`fuse`, `net`); they come last in the
report.
