# Brief: Zigbox 0.5.2 · the four runtime features of Zigcube's C4 (ZB-5 to ZB-8)

Read first: `AGENTS.md`, `REVIEW.md`, `docs/STYLE.md`, `docs/decisions/2026-11-10-listener-handoff-m8b.md`,
`docs/decisions/2026-11-13-zigcube-zb1-zb2.md` (the pattern: a decision file that is the
contract, plus tests), `docs/decisions/2026-11-14-zigcube-c4-requests.md` (this work's contract)
and `docs/decisions/2026-11-14-release-0.5.2.md`.

Zigcube's C4 (the service mesh) has a per-replica supervisor, a multi-threaded process that did
not start the container. It needs: listeners inside the container on `127.77.x.y:P` made and
closed live, sockets inside the container that connect to `127.0.0.1:P`, and a hosts file it
rewrites in place. The workload must not be able to signal, trace or reach the supervisor or
Zigbox's helper. The names ZB-5 to ZB-8 avoid a clash with Zigcube's earlier ZB-1 and ZB-2.

## The four requests

- **ZB-5** `container_socket(host, name, .tcp4, diag) -> fd`: a new, unconnected IPv4 TCP
  socket made in a running container's network namespace, many times, from any thread of a
  process that did not start the container. How: one short-lived single-threaded helper per
  call (a fork of the caller, in the host's PID namespace, never in the container's), which
  joins the container's user then network namespaces, makes the socket and sends it back with
  `SCM_RIGHTS`, then exits and is reaped. `127.77.x.y` is bindable because `lo` is up in the
  container's namespace and the kernel treats all of `127.0.0.0/8` as local there; the demo
  proves it.
- **ZB-6** `Spec.hosts_file` and `--hosts-file PATH`: bind-mount a caller-owned file read-only at
  `/etc/hosts` in place of the generated one; only with `--net none`.
- **ZB-7** a test that exec (M6b) joins the container's network namespace.
- **ZB-8** a test that a ZB-5 socket survives the caller's adoption by a restarted agent.

## Slices

1. **ZB-5.** Host interface op, real and simulated; `runtime/container_socket.zig`; codes;
   `zigbox.container_socket`; unit and simulation tests (every failure step, a multi-threaded
   caller, no leak of descriptors or helpers); the decision files. No VM demo yet beyond a
   scratch-branch smoke if the harness allows.
2. **ZB-6.** Spec field, plan step, `--hosts-file`, refusals, `help`/schema/goldens/errors site,
   tests.
3. **ZB-7, ZB-8 and the demo.** The two tests, `demo-c4` (`docs/demos/c4.md`), run on a `vm/c4-*`
   branch, README and site rows.

Mechanical parts (errors-site regeneration, `--help` goldens, README and site rows) go to Haiku.

## Demo (`zig build demo-c4`, in the test VM, as the ordinary user)

A harness program (in `src/testing/vm/`) plays the supervisor, with two threads:

1. `zbx run -d --net none --hosts-file H alpine:3.20 sleep` (H a file the harness owns).
2. A listener: `container_socket(.tcp4)`, `bind 127.77.0.2:8080`, `listen`; `zbx exec` runs
   `wget -qO- http://127.77.0.2:8080/` and gets the harness's answer. It is closed and made
   again live (a second `127.77.0.3`), and the first is refused after close.
3. A connector: a server inside (`zbx exec ... nc -l`), the harness connects a
   `container_socket` socket to `127.0.0.1:P` and exchanges a line.
4. Hosts: the harness rewrites H in place; `zbx exec getent hosts svc.mesh` sees it at once. A
   rename-over (new inode) is documented as not seen.
5. Hostile: from inside, `kill -9 -1` and `strace`/`ptrace` find none of the supervisor's or
   helper's pids; `/proc` lists neither; a write to `/etc/hosts` is refused (read-only).
6. ZB-7: `zbx exec ... ip addr`/`wget 127.0.0.1` sees the container's loopback, not the host's.
7. ZB-8: a restarted agent (the harness drops its handles, adopts by name) still uses a socket
   it held from step 2.
8. Refusals as one line each: `container_socket` on a `--net host` container; `--hosts-file`
   without `--net none`; a missing or non-file hosts path; a stopped container.

## Fixed decisions

- Namespace work stays in a single-threaded child (the helper is a fork, so it is one);
  Zigbox starts no thread. The helper uses no `PR_SET_PDEATHSIG` (it fires when the creating
  *thread* exits, not the process) and is bounded: three syscalls and a send, none can block.
- No cap on sockets per container: each is a descriptor of the caller's, so the caller's
  `RLIMIT_NOFILE` is the cap. No change to `listen_count_max` (M8b's `--listen` is unchanged).
- Codes after E0609 only (decision file lists them). `zbx run` without the new flag does not
  change by a byte.

## Non-goals

IPv6, UDP, Unix sockets; a persistent helper process or a protocol between processes; any accept
loop, relay or proxy in Zigbox; a socket in a `--net host` or `--net user` container; the Mac
beyond the existing forwarding (the VM runs it like everything else); watching the hosts file;
rewriting `resolv.conf` or `hostname`; Zigcube's side.

## Done means

`zig build check` PASS on each slice's commit; `demo-c4` green on a `vm/*` run for the last
slice; every earlier demo green; the PR opened by the supervisor.
