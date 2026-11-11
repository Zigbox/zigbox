# M8 slice 8 rework: the push flake, `policy check` for E0906, no `zbx rm`

## The E0503 flake (2 of 6 demo runs)

`connect_host` in `src/host_real_net.zig` tried each address of a name in turn, each with the full
idle timeout. `localhost` resolves to `::1` and `127.0.0.1`; with `registry:2` listening on IPv4
only, a stalled `::1` attempt used the whole timeout before the second address was tried, and every
timeout was reported as "did not answer". The fix: the attempts start together (non-blocking
connects, polled), the first to complete wins and the others are closed. A timeout after the
connection is made is a new `registry.net.Stalled` (E0503 says the host answered and then stalled);
only the connect phase gives `TimedOut`. Run 245 still stalled once ("connected, then sent nothing
for 30 seconds"): a forwarder can complete the connect on both families at once and say nothing on
`::1`, so a race alone does not help. The IPv4 addresses are now started first, and a peer that
completes at once is taken on the first one started. Run 249's registry log shows what the stall is: the second blob's PUT reached `registry:2` at
once, and its 201 came 30.04 s later, when the client gave up. The client had written and flushed
the whole body (`exchange` in `src/host_real_net.zig`); pasta, which publishes the guest's port,
held the tail of the upload until the connection closed. The product is not at fault, and half
closing the socket would make Go's server treat the client as gone, so the product is unchanged
beyond the connect fix above. The demo's first push is retried once when, and only when, it is
that E0503 stall (`check_stalled_push`); the retry may find every blob, since the stalled push
had stored them. The report says so, and the demo's recorded output shows the stall when it
happens. No new code and no changed bound: E0503 keeps its number,
and the idle timeout is unchanged.

## `policy check` for a missing provenance (E0906)

`policy check` said "allowed" for a tree-only signature under `require_provenance` while `run`
refused with E0906. It now returns `refused_provenance`: text says E0906, JSON adds `code` and
`refusal`. The demo compares `policy check` with `run` in all three cases (allowed, E0905, E0906)
and fails on any crash, so the earlier `|| true` is gone.

## No `zbx rm`

The review asked the demo to remove containers with `zbx rm`. There is no such command (and no
`--rm`); adding one is new user-visible surface, so none was added without the supervisor's say.
The demo drops the ended containers' records by hand (`rm -rf` of the private store's
`containers`, `runs` and `logs`), because gc keeps the tree of an ended container whose layer is
still there. A `zbx rm` is the natural follow-up; with it the demo's `drop` becomes one command.

## CI

`want_all` in `.github/ci-changes.sh` no longer selects `demo-m8-packages`: a path no rule names
runs every VM demo but not the packages demo. The packages demo runs for the package files, the
harness, the VM guests, the build and the workflow (`want_everything`), as `docs/demos/m8.md` says.
Rows in `src/ci_changes_tests.zig` cover both.
