# M8b demo: listener handoff (`--listen`)

Until the `demo-m8b` job is green in CI, M8b is built, not demonstrated.

`zbx run --net none --listen 127.0.0.1:8080 --listen-send FD` makes a listening TCP socket
inside the container's network namespace and sends it, once, over the Unix socket `FD` (an
SCM_RIGHTS message), then closes its own copy. The workload reaches it on `127.0.0.1:8080`; the
program that received it accepts the connections. Brief: `docs/briefs/M8b-listen.md`.

## The demo (`zig build demo-m8b`)

The harness side is Python in the guest (`src/testing/vm/m8b/*.py`): `socket.recv_fds` is the
receiving half of SCM_RIGHTS. Every assertion is a function of `checks_m8b.zig` with unit tests.

1. **hello**: the listener arrives, the harness accepts the container's `wget`, answers
   `hello from outside`, and the container prints it.
2. **hostile**: `nc -l -p 8080` inside gets "Address in use"; no socket is in the workload's
   `/proc/*/fd`; a host listener on `127.0.0.1:9999` is unreachable from inside; `ss -tln` on
   the host shows no `:8080`.
3. **refusals**, one coded line each, exit 125: `--net host`, `--publish` and no `--listen-send`
   (E0606), a `--listen-send` that is not a Unix socket (E0609), a non-loopback address (E0607).
4. **closed**: the harness closes its end; a new `wget` in the still-running container is
   refused and the container goes on.

## Deviations from the brief

- The harness is Python in the guest, not a Zig program; the fd number is the one Python
  chose, not a literal `3`.
- The container runs from `--rootfs` (the pinned Alpine minirootfs, as demo-m1), not `alpine:3.20`
  pulled from a registry.
- A `--listen-send` that is not a Unix socket is caught when the send fails, so it is E0609
  (the container is started, then stopped), not a refusal before the start.
- `-d` with `--listen` is refused under E0606; macOS refuses `--listen` under E0606 too.
- Records are version 10 only when a listener is set; a plain run writes version 9, unchanged.
  `zbx ps` shows the listener only when set, as address and port, never an fd.
- The channel between the container's setup child and zbx is a socketpair made before clone; the
  receiving step runs after the setup child's report.
- Not run here: the macOS unit test, and the demo itself (the cloud container has no KVM).
