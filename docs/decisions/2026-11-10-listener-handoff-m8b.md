# M8b: a listener handed out of `--net none`, for Zigcube's relay, after M8

*Decided 2026-11-10, by the owner ("Go, and record the Zigbox decision. We'll cut another Zigbox
with this after M8 goes out"); the details by the supervisor.*

Zigcube's B3 (the relay, `docs/briefs/botpike-first-customer.md` and `docs/briefs/b3.md` in
Zigcube) needs one change from Zigbox: a TCP listener on `127.0.0.1:<port>` inside a container's
own network namespace, held by the process that started the container and never by the workload.

## The decision

- It is a Zigbox milestone of its own, **M8b · Listener handoff**, briefed in
  `docs/briefs/M8b-listen.md`. It is outside M8's scope and is not added to M8.
- Work starts now, beside M8. Its pull request merges to `main` **only after M8's release tag**, so
  M8's release diff and its two release reviews do not include it. M8b then ships as the next
  Zigbox release, under the full release rule (AGENTS.md "Releases").
- Zigcube moves its Zigbox pin to that release before it wires the real runtime to the relay;
  until then Zigcube builds the relay against its fake runtime.
- The live design doc does not list M8b. It is a change requested by Zigcube, recorded here and in
  the brief; it alters no M0 to M8 goal or non-goal.

## Why a listener, not a socket bind-mounted in

The alternative (M6's host Unix socket under `--net none`) needs a process inside the container to
turn TCP into the socket, which puts a relay in the workload's reach and in every image. A socket
keeps the namespace it was created in, so a listener made by the container's setup child, after
`unshare` and before `execve`, accepts only connections from inside the container, while the
process that holds it stays outside. No veth, no host firewall or routing change (M5's rule), no
privilege.
