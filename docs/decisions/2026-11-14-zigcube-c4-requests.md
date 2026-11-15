# Zigcube's C4 requests (ZB-5 to ZB-8): the contract

*Decided 2026-11-14, by the slice (`claude/zb-c4-requests`), for Zigcube's C4 brief. This file
is what Zigcube codes against; slice 2 and 3 add their sections here.*

## ZB-5: `zigbox.container_socket`

```zig
const fd = try zigbox.container_socket(host, "web", .tcp4, &diag);
defer close(fd);
```

`host` is the same `Host` as `exec_start` takes. `name` is a running container's name. The
return is a new, unconnected IPv4 TCP socket (`SOCK_STREAM`) **made in the container's network
namespace**, or `error.SocketFailed` with the diagnostic in `diag`. The descriptor the caller
receives is close-on-exec (`MSG_CMSG_CLOEXEC`): a child the caller later `exec`s does not
inherit it unless the caller clears the flag.

- **Who may call.** Any thread of a process that did not start the container, many times, at
  once, **each thread with a `Host` of its own** (one `HostReal` per thread: a `HostReal`
  holds per-call state such as the last errno; its open-file count is atomic, so a shared one
  does not corrupt the count, but its errors can be another thread's). Like `exec_start`, the caller needs the agent's state directory (it finds the container
  by its record and PID 1 under /proc), the same uid, and the same cgroup driver's environment.
  It needs no handle of the container. The caller must leave SIGCHLD at its default: a
  process that ignores it (`SIG_IGN`) has its helpers reaped by the kernel, the wait fails with
  `ECHILD`, and the call fails with E0611 at the step `reap_helper`.
- **How.** Each call forks one short-lived helper (`Host.fork_child`): a single-threaded child
  of the caller, in the caller's own PID namespace, never the container's. It joins the
  container's user namespace (skipped when it is the caller's own), then its network namespace,
  makes the socket and sends it back over a Unix socketpair with `SCM_RIGHTS`, then exits; the
  call reaps it by pid before returning (so it never takes another child of the caller). A
  wait that fails is tried once more, so a passing fault leaves no zombie. The helper's failure
  record is read only after it is reaped and only with a timeout, never to end of file: a copy
  of the pipe's write end in another thread's child cannot hold the call up.
- **The right container.** The container is found by its record and its PID 1, and its
  namespace files are opened by that pid. Then the container is checked alive again (PID 1 is
  still the container's, by its PID namespace and cgroup): the open files pin the namespaces,
  so a pid that ended and was reused between the lookup and the opens is caught, and the call
  is E0220. Without the check a reused pid could hand out a socket in a stranger's namespace.
  A simulator test reuses the pid at the first namespace open and expects E0220 and no helper.
  **Known limit, hosts with no cgroup scope** (no delegated cgroup v2, so the record has no
  scope): the check can then only ask that the pid be PID 1 of *some* PID namespace and not a
  zombie. A pid reused by another container's PID 1, of the same uid (the namespace files of
  another uid's process cannot be opened), passes it, and the socket is made in that
  container. The same holds for `exec` on such hosts, whose lookup this is. Closing it means
  pinning the process start time (`/proc/PID/stat` field 22) in the run record, a record
  format change (a version bump read by older and newer releases) left to its own change; on
  a host with a scope, the cgroup check already rules out another container.
  Zigbox starts no thread and does no namespace work in a thread. The helper has no
  `PR_SET_PDEATHSIG` (it fires on the exit of the creating *thread*) and cannot block: three
  system calls and a send into an empty socketpair.
- **The workload cannot reach it.** The helper is not in the container's PID namespace, so
  `kill`, `ptrace` and `/proc` inside the container never see it. It lives for microseconds.
  The demo's step 5 tries `kill` and `ptrace` on the supervisor's pid from inside (ESRCH both)
  and samples `/proc` inside while 3000 helpers come and go (the count never changes); at
  least three samples must start after the first helper and end before the last.
- **fd ownership.** The returned descriptor is the caller's alone, close-on-exec; Zigbox keeps
  nothing. It stays valid after the container's PID 1 exits (a socket in a dead namespace, as
  any socket is), and across the caller's adoption by a restarted agent: it is an ordinary
  descriptor of the caller's process, and no Zigbox state refers to it (ZB-8 tests this).
  It also survives the caller's own `execve` if the caller clears close-on-exec first.
- **127.77.x.y is bindable.** The container's namespace is new, its `lo` is brought up by Zigbox
  at start, and with `lo` up the kernel treats all of 127.0.0.0/8 as local there: `bind` to
  `127.77.0.2:8080` works with no further setup, no `IP_FREEBIND` and no address added. The
  demo proves it in the VM.
- **No cap.** Each socket is a descriptor of the caller's, so its `RLIMIT_NOFILE` is the limit.
  M8b's `listen_count_max` (1) is for `--listen` and is unchanged.
- **Only `--net none` (the default).** Refused with E0610 before any helper is forked: a
  container on the host's network (`--net host`), where a socket would be the host's, and one
  on pasta's network (`--net user`), whose namespace pasta routes and Zigcube's mesh does not.
  A record from before the network field is judged by its namespaces: one that shares the
  caller's network namespace is refused the same way. The container lookup's refusals are
  `exec`'s: E0701 (no state directory), E0402 (no such container), E0220 (stopped or lost).
- **A container that exits during the call.** Before its namespace files are open, the call
  is E0220. After, the helper may still join the namespaces (they live while the files are
  open) and the call returns a socket in a namespace with no process left; it is the same as a
  socket made just before the exit. What a caller sees then is that socket's own errors.
- **Failure.** E0611: a step failed, named with its errno. The helper's steps are `join_user`,
  `join_net`, `make_socket` and `send_socket`; the caller's own are `start_helper` (the
  socketpair, the pipe or the fork) and `reap_helper` (the wait for the helper; a failed wait is
  reported as this step, never as `send_socket`). The usual cause is a caller of another uid.
  Nothing is left open or unreaped on any failure.
- **Linux only.** On macOS the caller runs inside the zbx VM, as for everything else.
- **Non-goals:** IPv6, UDP, Unix sockets, a persistent helper, any accept loop or proxy.

### Codes taken (after E0609)

| Code  | When |
|-------|------|
| E0610 | the container is not `--net none` (it shares the host's network, or is on pasta's) |
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
  absolute (or holds a NUL, or is over the path bound), missing, not a regular file, or one
  this user cannot read (checked in the parent by reading its first byte, so a file the
  container could not read either is refused before the run, not at the bind).
- **Semantics a caller must know.** The bind is of the host file itself. An in-place rewrite
  (open, truncate, write) is seen inside at once; replacing the path by a rename is not (the
  mount holds the old file). Zigcube's C4 should rewrite in place. The demo checks both.
- **Not recorded.** The run record stays at version 10 and does not carry the path. Nothing
  that reads the record (`zbx ps`, a bundle, an agent that adopts the container) learns it, and
  Zigbox has no command that starts a stopped container again: a container run again gets the
  file only if it is given `--hosts-file` again. An agent that restarts must keep the path
  itself. A record bump is a user-visible change that this release does not make.
- **Known wart.** A failed hosts-file bind step reads "binding the generated /etc/hosts". The
  run check (E0612) pre-empts the usual causes, so it is left.

### Code taken

| Code  | When |
|-------|------|
| E0612 | the hosts file cannot be bound at /etc/hosts (the refusals above) |

## ZB-7: `zbx exec` joins the container's network namespace

A test, not a feature: the simulator test and the demo's `net.py` (the brief's step 6, the
demo's step 4) show that a command run by `zbx exec` sees the container's own loopback (the
server another exec started on 127.0.0.1:9100 answers, the host's 127.0.0.1:9100 refuses, one
inet address). Writing it found a bug: `exec` into a `--net host` container has no
net-namespace handle (the container's network is the host's, so there is nothing to join), and
`exec_child` took the null with `.?`, which panicked. It now skips the network join, so the
command runs in the host's network, as the container itself does; it is not refused. No
behaviour of a working exec changed.

## ZB-8: a ZB-5 socket survives adoption by a restarted agent

A test, not a feature. The socket is a descriptor of the caller's, so it never depended on
the agent. What runs:

- **Simulator** (`container_socket_tests.zig`): a socket is made, the starter's handle dropped,
  the container adopted by name; the socket is still the container's, and a second is made.
- **Demo step 3** (`connect.py`, the brief's step 7): the supervisor holds a socket. A separate
  agent process adopts the container and is killed with SIGKILL. The supervisor then restarts
  itself: it re-executes its own binary in place (same pid, a new image, so no Zigbox state of
  the old one is left), keeping only the held socket (close-on-exec cleared, its number passed
  on the command line). The new image adopts the container by name and connects the inherited
  socket to a server inside, which answers.

A process that is killed loses its descriptors, so "the supervisor is killed and the socket
survives" is not a thing any design offers; a restart that keeps the socket is an `execve`
(above), or a hand-off to another process over a Unix socket.

## Notes for the next implementer

- The sim's `stat` reads `sim.files`; a bind source also needs `world.add_node`.
