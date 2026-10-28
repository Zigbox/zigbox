# Brief: M5 · Network

Read these first:
- `AGENTS.md`, `docs/STYLE.md` and `DIAGNOSTICS.md`.
- The M5 section of `docs/SPEC.md`, with "Production readiness" and "Agent operability".
- `docs/DECISIONS.md`, the M5 entry and the M4 `/sys` decision, which M5 closes.
- `docs/demos/m4.md`: the image runs you build on, the top-20 results, and the agent test's findings.
- `pasta(1)` from the passt project (Ubuntu 24.04 ships it as the `passt` package). Read the manual for the version the VM installs; do not write its options from memory.

Do not start M6: no state volumes, no `-e`, no bind mounts. Container-to-container networks and egress allowlists are stretch goals. `demo-m0` to `demo-m4` must keep passing in every slice.

## Goal and demo (from the spec, live doc rev 59)

A container has no network unless granted, and a granted service is reachable from the host.

1. `zbx run alpine -- wget -qO- https://example.com` fails, and zbx says `network: none (grant with --net)`.
2. `zbx run --net user alpine -- wget -qO- https://example.com` prints the page.
3. `zbx run --publish 8080:80 nginx` in one terminal; `curl localhost:8080` on the host returns the nginx welcome page.
4. `ss -tlnp` on the host shows the listener owned by the presenter's user, and `sudo iptables -S` shows no rules added.

Acceptance criteria:
- No host firewall or routing changes, ever.
- A missing `pasta` is caught by `zbx doctor` and by a clear error at run.
- Published ports are released when the container exits, including on crash.
- The production-readiness checklist: an upgrade test against the merged M4 commit (`cd5adbc`), stable diagnostics, documented failure modes, and the agent test extended to M5's steps.

## Fixed decisions

### The network modes

- **`--net none` is the default.** Every container gets its own network namespace, owned by its user namespace, with only `lo`, brought up. Nothing else changes for a container that never touches the network.
- **`--net host`** shares the host's network namespace, as every run does today. It is explicit, and `run --output json` says which mode ran.
- **`--net user`** is rootless user-mode networking through `pasta`. zbx creates the namespace and `pasta` attaches to it; zbx never writes a host firewall rule, route or interface, and `pasta` needs no privilege.
- **`--publish HOST:CONTAINER`** (TCP; repeatable) implies `--net user`. `--publish` with an explicit `--net none` or `--net host` is a usage error that says why. `HOST` binds on the host's loopback and wildcard addresses as `pasta -t` does; ports below 1024 on the host are refused by the host, and the error says so.
- **The no-network hint.** When a run with the default network (no `--net` given) exits non-zero, zbx adds one line to stderr after the container's own output: `zbx: network: none (grant with --net)`. It is a note, not a diagnostic: the exit code is the container's. `run --output json` carries `"network":"none"` either way. A run with an explicit `--net none` never gets the hint.

### Inside the container

- **`/sys` is a real sysfs** in a container with its own network namespace (`none` and `user`), mounted read-only, so it shows the container's own network devices and not the host's. That closes the leak recorded in M4. `--net host` keeps the read-only bind of the host's `/sys`.
- **`/etc/hosts`** is generated: `localhost` for 127.0.0.1 and ::1, and the container's hostname. **`/etc/resolv.conf`** is generated as well: for `none`, no nameserver; for `host`, the host's file; for `user`, the address `pasta` forwards DNS on. Ubuntu's host `resolv.conf` names the stub resolver 127.0.0.53, which a container cannot reach; `pasta --dns-forward` covers that, and the brief's demo runs on Ubuntu, so this case is tested. Both files are bind-mounted over the image's, read-only, and never become part of a commit.
- **Port 80 inside the container works.** The container's root holds `CAP_NET_BIND_SERVICE` in its own user namespace, which owns the network namespace. The top-20 entries for nginx, httpd and traefik stop being "known" and are run with `--publish` and probed through the published port.

### pasta's lifecycle

- zbx starts `pasta` from the parent after the child has created its namespace and before the child execs. The child waits on a pipe until `pasta` reports the interface configured. A `pasta` that fails to start, or does not report ready within a bound, is a coded error, and the container never runs.
- **Ports are released on every exit path**: a clean exit, `zbx stop`, `--timeout`, SIGKILL of the container, and SIGKILL of `zbx` itself. `pasta` exits when the namespace it serves goes away; zbx also reaps it. The tests cover each path, including a crash of `zbx`.
- `pasta`'s output goes to the run's log, never to the container's stdout.

### Diagnostics (`06xx` network)

- `pasta` not on `PATH`; `pasta` too old for the options used (with the version found and the version needed); `pasta` failed to start (its own last line as the cause); a host port already in use; a host port the host refuses (below `net.ipv4.ip_unprivileged_port_start`); a `--publish` that does not parse. Each with a fix, goldens and an error page.
- `zbx doctor` gets a `net` line: `pasta` found and its version, or a warning with how to install it (`apt install passt`). A missing `pasta` is a warning, not a failure: `--net none` and `--net host` work without it.

### Closing M4's carried-over notes

These came from the M4 review and agent test, and the owner put them here.

- **An image record keeps its tags.** A record holds every tag it was pulled as (bounded, oldest dropped, with the bound in `constants.zig`); a pull by digest adds no tag and removes none. `store ls`, `store du --by-image` and the JSON list each tag. The record's version goes up, and M4's records still read (the upgrade test checks it).
- **`zbx explain --output json`** prints a `zbx.explain/1` document: the code, severity, blame, summary, explanation and the docs URL. `zbx schema explain` prints its schema.
- **`zbx lock show [--output json]`** prints the project's `zbx.lock`: its path and, per entry, the reference, manifest, platform and tree (`zbx.lock/1`). It only reads; the lock stays a file people edit and commit.
- **`run --output json` says what ran**: the reference as typed, the manifest and the tree for an image, the tree for a digest, the path for `--rootfs`, and the network mode and published ports.

## Slices (commit and stop for review after each; do not push to the working branch)

1. **M4's carried-over notes.** The tags list in image records with the version bump and the read of version 1; `explain --output json`; `lock show`; what ran in `run --output json`. Schemas, goldens, tests, and the `lock` fuzzer extended to the new record. The demo-m4 agent stops scraping the text of `zbx explain` and reading `zbx.lock` as text.
2. **The network namespace.** `--net none` by default and `--net host`; `lo` up; a real read-only sysfs; generated `/etc/hosts` and `/etc/resolv.conf`; the no-network hint; the `net` doctor line. `demo-m0` to `demo-m4` stay green: the top-20 harness probes servers on the host's loopback today, so it moves those images to `--net host` in this slice and to `--publish` in slice 3.
3. **pasta.** `--net user` and `--publish`, DNS through `pasta`, readiness, cleanup on every exit path, and the `06xx` codes. `passt` goes into the VM image (`src/testing/vm/cloud_init.zig`). Real checks in the VM through `vm/m5-*` scratch branches: `wget` through `--net user`, nginx through `--publish`, and a port freed after SIGKILL of `zbx`.
4. **VM, CI and the agent test.**
   - `zig build demo-m5`: the spec's four steps exactly, every assertion a unit-tested function. Step 4 runs `ss` as the demo user and `iptables -S` as root in the VM, and compares the rules before and after.
   - The acceptance checks: a missing `pasta` (removed from `PATH` for the check) caught by doctor and by run; a port released after each exit path.
   - The agent test extended to M5's steps, by JSON only.
   - The upgrade test against M4 (`cd5adbc`): M4's store, records and lock read by this binary, and an M4 image run with `--net none`.
   - The top-20 workflow runs nginx, httpd and traefik through `--publish`, with their reasons removed if they pass.
   - The `demo-m5` CI job; `docs/demos/m5.md` with the by-hand steps, cuts and failure modes: `pasta` missing or too old, a host port in use, a port below 1024, DNS through systemd-resolved, and a crash of `zbx` with a port published.

## Done means

- All gates pass (`zig build check`), and every fuzzer you touched runs at 10,000 iterations.
- `demo-m5` is green in CI, with `demo-m0` to `demo-m4` still green. Until then M5 is "built, not demonstrated".
- Your report lists what you ran and its output, what you did not run and why, every deviation from this brief, and anything in the spec, this brief or `DIAGNOSTICS.md` that seemed wrong.
