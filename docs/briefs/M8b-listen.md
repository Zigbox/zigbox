# Brief: M8b · Listener handoff (`--listen`)

Read these first:
- `AGENTS.md`, `REVIEW.md`, `docs/STYLE.md` and `DIAGNOSTICS.md`.
- `docs/decisions/2026-11-10-listener-handoff-m8b.md` (why this exists and when it merges).
- M5's network work: `docs/briefs/M5-network.md`, `src/runtime/spec.zig` (`Network`),
  `src/runtime/child.zig` (the setup child's steps, `.bring_up_loopback`), `src/runtime/run.zig`,
  `src/runtime/sim_run.zig` and the host model it drives, `docs/demos/m5.md`.
- Zigcube's need, for context only: the B3 section of `docs/briefs/botpike-first-customer.md` in
  `Zigbox/zigcube` (read it with `add_repo`, read access). Nothing in Zigcube changes here.

This is not part of M8. Work on the branch you were given; the pull request merges after M8's
release tag (the decision file). Every existing demo must keep passing, and `zbx run` without
`--listen` must not change by a byte (output, JSON, records): the goldens prove it.

## Goal and demo

A process that starts a container with no network gets, and alone holds, a TCP listener on the
container's loopback. The workload connects to it like any local service; it cannot accept on
it, close it, replace it, or reach anything else.

`zig build demo-m8b`, in the test VM, as the ordinary user (harness in `src/testing/vm/`, in Zig):

1. The harness makes a Unix socket pair, keeps one end, and runs
   `zbx run --net none --listen 127.0.0.1:8080 --listen-send 3 alpine:3.20 wget -qO- http://127.0.0.1:8080/`
   with the other end as descriptor 3. It receives the listener, accepts one connection, answers
   `hello from outside`, and the container prints that line.
2. Hostile checks, each run inside a container started the same way, each must fail and print why:
   `nc -l -p 8080` inside (the port is taken: `EADDRINUSE`); no socket of the listener appears in
   `/proc/self/fd` of the workload; a `127.0.0.1:9999` listener the harness opened on the host is
   not reachable from inside; `ss -tln` on the host shows no `:8080`.
3. Refusals, one coded line each: `--listen` with `--net host` or `--publish`; `--listen` without
   `--listen-send`; `--listen-send` naming a descriptor that is not a Unix socket; an address that
   is not loopback.
4. When the harness closes its end, a new `wget` in a still-running container is refused
   (`connection refused`), and the container is otherwise unharmed.

## Fixed decisions

- **Where the listener is made.** A new setup-child step, after `.bring_up_loopback` and before
  `execve` (AGENTS.md: all namespace work happens in that single-threaded child): `socket` with
  `SOCK_CLOEXEC`, `bind`, `listen` (backlog a constant), then sent to the parent over the existing
  child-to-parent channel, or a new socket pair made before `clone`, with `SCM_RIGHTS`. The child
  closes its copy before `execve`; `SOCK_CLOEXEC` is the second guard. Assert it in tests by
  listing the workload's descriptors.
- **Only with `--net none`.** Host networking would put the listener in the host's namespace and
  `pasta` would publish it; both are refused. Address: IPv4 loopback only (`127.0.0.1`), port 1 to
  65535; at most one listener per container (`listen_count_max = 1`, a constant, asserted).
- **The library first.** `run` options gain `listen: ?Listen` (address and port); the started
  container's handle carries the received descriptor, owned by the caller. Zigcube's agent links
  this; its supervisor holds the descriptor. No thread, no accept loop in Zigbox.
- **The command line hands it on.** `--listen ADDR:PORT --listen-send FD`: zbx sends the received
  listener with `SCM_RIGHTS` over the inherited Unix socket `FD`, then closes its own copy before
  waiting on the container. Exactly one send; if it fails, the container is stopped and the run
  fails with a coded line. Records and `zbx ps` say that a listener was handed out (address and
  port), never a descriptor number.
- **The Mac** (`src/macos_main.zig` forwarding): `--listen` is refused on the Mac with one coded
  line, because a descriptor cannot cross the VM. Not built there.
- **The seccomp profile does not change**: the workload never needs `accept` on a socket it does
  not hold; say so in the review notes if you find otherwise.

## Diagnostics

Codes `ZBX-E0606` to `ZBX-E0609` are approved for this milestone (network, `06xx`). Suggested:
- `E0606` `--listen` used with a network that is not `none`, or without `--listen-send`.
- `E0607` the listen address is not IPv4 loopback, or the port is out of range.
- `E0608` the listener could not be made inside the container (the syscall and errno as causes).
- `E0609` the listener could not be handed on (`--listen-send` is not a Unix socket, or the send
  failed); the container was stopped.
Each with `explain` text and the errors site regenerated (`zig build errors-site`). Ask before
registering any other.

## Tests

- Simulation: the host model gains the listener (socket, bind, listen, the send), with faults on
  each call; `sim_run` checks the descriptor is never in the workload's table and that a failed
  send stops the container.
- The `cli` fuzzer (or the run-options one) gains `--listen` and `--listen-send`.
- Goldens for each new error line and for `zbx run --help`.
- A real-kernel test that skips cleanly where rootless namespaces are unavailable (the cloud
  container is not a valid host; the VM demo is the real test).

## Slices (commit and push your branch about every 10 minutes; open the PR only when ready)

1. **The whole milestone in one slice**: library, setup-child step, command line, Mac refusal,
   codes, sim, fuzz, goldens, `demo-m8b` and `docs/demos/m8b.md`. Check the demo on CI's KVM
   runner via a `vm/all-m8b` scratch branch before the PR. Mechanical parts (the errors site
   regeneration, `--help` goldens, the README and site rows) may go to Haiku.

## Done means

`zig build check` PASS on the final commit, `demo-m8b` green on a `vm/*` run (link it), every
earlier demo green, the PR open and not merged (it waits for M8's tag).

## Non-goals

More than one listener; IPv6; UDP; a listener with any network but `none`; an accept loop, relay
or proxy in Zigbox; anything on the Mac beyond the refusal; Zigcube's side.
