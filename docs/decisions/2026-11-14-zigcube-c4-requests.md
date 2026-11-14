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

## ZB-6: `Spec.hosts_file` and `--hosts-file PATH`

- **What.** The file at `hosts_file` is bind-mounted, read-only, at `/etc/hosts` in place of the
  generated one. It reuses the generated file's bind and remount steps with the host path as
  the source; there is no staged copy, so the plan has two steps fewer, and the two steps are
  not tolerant (the file is the caller's contract, a quiet fallback to the generated one would
  hide a broken mesh).
- **Only `--net none`.** With another network the runtime's own `/etc/hosts` is the right one;
  a given file there is refused rather than half-honoured. `resolv.conf` and the hostname are
  not rewritten.
- **Refused, E0612** (one line, before anything is made): not `--net none`, a path that is not
  absolute (or holds a NUL, or is over the path bound), missing, or not a regular file.
- **Semantics a caller must know.** The bind is of the host file itself. An in-place rewrite
  (open, truncate, write) is seen inside at once; replacing the path by a rename is not (the
  mount holds the old file). Zigcube's C4 should rewrite in place. The demo checks both.
- **Cut: the run record.** The record (version 10) is not bumped, so `zbx start` of a stopped
  container does not remember `--hosts-file`. Flagged for the supervisor; a record bump is a
  user-visible change that this release does not make.
- **Known wart.** A failed hosts-file bind step reads "binding the generated /etc/hosts". The
  run check (E0612) pre-empts the usual causes, so it is left.

### Code taken

| Code  | When |
|-------|------|
| E0612 | the hosts file cannot be bound at /etc/hosts (the four refusals above) |

## ZB-7: `zbx exec` joins the container's network namespace

A test, not a feature: the simulator test and demo step 4 (`net.py`) show that a command run by
`zbx exec` sees the container's own loopback (the server another exec started on 127.0.0.1:9100
answers, the host's 127.0.0.1:9100 refuses, one inet address). Writing it found a bug: `exec`
into a `--net host` container has no net-namespace handle, and `exec_child` took the null with
`.?`, which panicked. It now returns with the usual refusal. No behaviour of a working exec
changed.

## ZB-8: a ZB-5 socket survives adoption by a restarted agent

A test, not a feature: the simulator test and demo step 3 (`connect.py`) hold a socket made by
`container_socket`, kill and restart the agent that adopts the container, and connect on the
same socket. The socket is a descriptor of the caller's, so it never depended on the agent.

## Notes for the next implementer

- `HostReal.open_count` is a plain counter: use one `HostReal` per thread.
- The sim's `stat` reads `sim.files`; a bind source also needs `world.add_node`.
