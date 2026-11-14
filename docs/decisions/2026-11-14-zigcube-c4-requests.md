# Zigcube's C4 requests (ZB-5 to ZB-8): the contract

*Decided 2026-11-14, by the slice (`claude/zb-c4-requests`), for Zigcube's C4 brief. This file
is what Zigcube codes against; slice 2 and 3 add their sections here.*

## ZB-5: `zigbox.container_socket`

```zig
const fd = try zigbox.container_socket(host, "web", .tcp4, &diag);
defer close(fd);
```

`host` is the same `Host` as `exec_start` takes. `name` is a running container's name. The
return is a new, unconnected IPv4 TCP socket (`SOCK_STREAM`, close-on-exec) **made in the
container's network namespace**, or `error.SocketFailed` with the diagnostic in `diag`.

- **Who may call.** Any thread of a process that did not start the container, many times, at
  once. Like `exec_start`, the caller needs the agent's state directory (it finds the container
  by its record and PID 1 under /proc), the same uid, and the same cgroup driver's environment.
  It needs no handle of the container.
- **How.** Each call forks one short-lived helper (`Host.fork_child`): a single-threaded child
  of the caller, in the caller's own PID namespace, never the container's. It joins the
  container's user namespace, then its network namespace, makes the socket and sends it back over
  a Unix socketpair with `SCM_RIGHTS`, then exits; the call reaps it by pid before returning (so
  it never takes another child of the caller). Zigbox starts no thread and does no namespace
  work in a thread. The helper has no `PR_SET_PDEATHSIG` (it fires on the exit of the creating
  *thread*) and cannot block: three system calls and a send into an empty socketpair.
- **The workload cannot reach it.** The helper is not in the container's PID namespace, so
  `kill`, `ptrace` and `/proc` inside the container never see it. It lives for microseconds.
- **fd ownership.** The returned descriptor is the caller's alone, close-on-exec; Zigbox keeps
  nothing. It stays valid after the container's PID 1 exits (a socket in a dead namespace, as
  any socket is), and across the caller's adoption by a restarted agent: it is an ordinary
  descriptor of the caller's process, and no Zigbox state refers to it (ZB-8 tests this).
- **127.77.x.y is bindable.** The container's namespace is new, its `lo` is brought up by Zigbox
  at start, and with `lo` up the kernel treats all of 127.0.0.0/8 as local there: `bind` to
  `127.77.0.2:8080` works with no further setup, no `IP_FREEBIND` and no address added. The
  demo proves it in the VM.
- **No cap.** Each socket is a descriptor of the caller's, so its `RLIMIT_NOFILE` is the limit.
  M8b's `listen_count_max` (1) is for `--listen` and is unchanged.
- **Refused:** a container on the host's network (`--net host`), E0610, before any helper is
  forked. The container lookup's refusals are `exec`'s: E0701 (no state directory), E0402 (no
  such container), E0220 (stopped or lost).
- **Failure.** E0611: a step of the helper failed (`join_user`, `join_net`, `make_socket`,
  `send_socket`; the diagnostic names it with the errno). The usual cause is a caller of another
  uid. Nothing is left open or unreaped on any failure.
- **Linux only.** On macOS the caller runs inside the zbx VM, as for everything else.
- **Non-goals:** IPv6, UDP, Unix sockets, a persistent helper, any accept loop or proxy.

### Codes taken (after E0609)

| Code  | When |
|-------|------|
| E0610 | the container shares the host's network: a socket made in it would be the host's |
| E0611 | a step of making the socket failed (step and errno named) |

The explain text, goldens (`testdata/diag`) and the errors site carry both.

### Public names

`zigbox.container_socket` (the function), `zigbox.ContainerSocketKind` (`tcp4`),
`zigbox.ContainerSocketError` (`SocketFailed`), `zigbox.container_socket_module`.
