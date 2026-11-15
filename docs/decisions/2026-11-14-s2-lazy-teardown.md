# The lazy run's FUSE teardown and handshake are bounded

*Decided 2026-11-14, by the slice (S2 slice 4 review fixes).*

## Teardown

Before this fix, `zbx run --lazy` joined its serving threads by waiting for the kernel to end the FUSE connection. The kernel does that only when the mount's last user is gone. Anything outside the container that still holds the mount would keep `zbx` waiting forever: an open file passed out over `SCM_RIGHTS`, or a process that entered the mount namespace. The server now ends the connection itself:

- The parent makes its `/dev/fuse` descriptor non-blocking. Each serving thread waits for a request with `poll` for at most `fuse_poll_ms` (100 ms), then looks at a stop flag (`serve.Serving.stop`).
- Once the container has exited, `lazy_server.Server.finish` sets the flag and joins the threads. A thread returns within one poll interval plus the request it is answering. Answering a request reads at most one chunk from the local store, so it is bounded too.
- `finish` then closes the descriptor. `zbx` holds the last reference to the connection's device file, because the setup child closed its copy after sending it. Closing it makes the kernel abort the connection (`fuse_dev_release` calls `fuse_abort_conn`).

What a holder outside sees: once `zbx` has returned (or was killed, which also closes the descriptor), a read of the mount that the page cache cannot answer fails with `ENOTCONN`. A request that was in flight when the connection aborted fails with `ECONNABORTED`/`EIO`. A `stat` or a read the page cache still holds may still succeed. Nothing the holder does can keep `zbx` running. The mount itself stays until its namespace ends, and with no server behind it, it serves nothing.

The S2 VM check exercises the paths that don't need a passed descriptor: `zbx` killed with SIGKILL while a reader is inside (the reader gets an error and nothing is left in `/proc/mounts`), and the container killed in the middle of a read (`zbx` returns). Passing a descriptor out over `SCM_RIGHTS` is not scripted. The stop-flag path that guarantees the bound is covered by the unit test of `Server` over a socket pair, which stops serving threads that never see the connection end.

## Handshake

`serve` used to wait for the kernel's `INIT` with no bound. It now makes at most `fuse_init_timeout_ms / fuse_poll_ms` waits (10 s in all). After that it refuses the run with `TimedOut`, which the run reports as E0205 with the cause "serving the image's tree to the container over FUSE failed: the kernel sent no FUSE INIT within 10 s". The server's other refusals get causes of their own under E0205, by the error. No new code is registered.

The two constants are internal and live in `constants.zig`. The supervisor was told about them before they were committed.
