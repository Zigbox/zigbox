# A tour of zbx

> **Not yet verified for this release.** The commands were run with zbx 0.4.0 on 2026-11-11 in a
> cloud container, except: the **Build** section was not run to the end (its build file was refused
> with E0307 there), and the **Ports** output and the build cache behaviour come from recorded CI
> demos, not from a run for this guide. Nothing was run with 0.5.0.

One short example per command. Start from a host where `zbx doctor` passes
([Mac](try-mac.md), [Linux](try-linux.md)). The commands and output below were run with
`zbx 0.4.0` as an ordinary user on Linux, except where the note above or the text says otherwise.

<!-- owner: run on 2026-11-11 in a cloud container (cgroup v1, so every `zbx run` there also
printed warning W0301; it is left out below). Ports and build could not run there; those
sections cite CI. Re-run the page with 0.5.1. -->

## Check the host

```sh
zbx doctor
```

Seven checks, one line each; a failure ends with a code and, where there is one, the command that fixes it. See
[Try on Linux](try-linux.md#2-check-the-host). `zbx doctor --output json` prints the same as JSON.

## Pull and run

```
$ zbx pull alpine:3.20
sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e
$ zbx run alpine:3.20 -- cat /etc/os-release
NAME="Alpine Linux"
...
```

`zbx run` never pulls by itself: an image you have not pulled is refused with
[E0522](https://zigbox.org/errors/box/E0522). Images come from Docker Hub, GitHub's registry
(`ghcr.io`) and Amazon ECR.

A container has **no network** unless you grant one. Without a grant, only `lo` exists inside:

```
$ zbx run alpine:3.20 -- sh -c 'wget -q -T 3 -O- http://example.com >/dev/null && echo net-ok || echo no-net'
no-net
```

`--net user` gives it outbound access through `pasta`.

## Publish a port

```sh
zbx run -d --name web8080 --publish 8080:80 nginx:alpine
curl http://localhost:8080/
zbx stop web8080
```

`curl` gets "Welcome to nginx!". The listener belongs to your user (a `pasta` process); no
firewall rule changes, and the port is free again when the container stops. `--publish` implies
`--net user`.

*From the recorded CI run of the networking demo,
[run 40751616386](https://github.com/Zigbox/zigbox/actions/runs/40751616386).*

## Keep data with `--state`

A state volume is a named directory that outlives the container:

```
$ zbx run --state notes:/data alpine:3.20 -- sh -c 'date > /data/first; ls /data'
first
$ zbx run --state notes:/data alpine:3.20 -- cat /data/first
Wed Nov 11 19:50:51 UTC 2026
$ zbx state ls
NAME                           SIZE  CREATED              LAST USED            LAST CONTAINER       IN USE BY
notes                       8.0 KiB  2026-11-11 19:46:16  2026-11-11 19:50:51  zbx-059820           -
```

## Run in the background: ps, logs, exec, stop

```
$ zbx run -d --name web alpine:3.20 -- sh -c 'echo started; sleep 300'
web
$ zbx ps
NAME                     STATE             PID  STARTED              COMMAND
web                      running          1611  2026-11-11 19:50:52  sh -c echo started; sleep 300
$ zbx logs web
started
$ zbx exec web -- sh -c 'echo inside'
inside
$ zbx stop web
web stopped (killed), exit code 137
```

`zbx stop` sends SIGTERM, and SIGKILL after a grace period. Here `sh` runs as PID 1 with no
SIGTERM handler, so it was killed at once (exit code 137); a server that handles SIGTERM stops
cleanly. `zbx ps --all` also
lists stopped containers.

## Build an image

A build is described in `zbx.build.zon`, not a Dockerfile. Each step runs a command on a base
image with only the files it names as inputs, and writes its result to `/out`; the image adds
step results to a base:

```zig
.{
    .version = 1,
    .steps = .{
        .{
            .name = "page",
            .base = "alpine:3.20",
            .inputs = .{"index.html"},
            .run = .{ "sh", "-c", "mkdir -p /out/srv && cp index.html /out/srv/" },
        },
    },
    .image = .{
        .base = "alpine:3.20",
        .add = .{.{ .from = "page", .to = "/" }},
        .config = .{ .entrypoint = .{ "cat", "/srv/index.html" } },
    },
}
```

```sh
zbx build --graph     # the steps and their order, without building
zbx build             # builds, and prints the image's digest
zbx run <digest>
```

A second `zbx build` with no input changed reuses every step from the cache and prints the same
digest. A build needs cgroup v2: on a host without it, `zbx build` is refused with
[E0307](https://zigbox.org/errors/box/E0307).

<!-- owner: this build file was written for the guide and refused with E0307 in the cloud
container (cgroup v1); it was not run to the end. The cache and same-digest behaviour is from
the recorded build demo (docs/demos/m7.md, steps 1-2). Run it on a cgroup v2 host. -->

## Sign, set a policy, verify

Make a key, sign an image by its digest, and require signatures in your policy:

```
$ zbx key new tour --no-passphrase
key: tour
id: 51e043b61b2d7c7545a0d12bd074c9877e4d3548560c54e562c5355a24bc6f5c
public: zbx-ed25519:fe9dca62be757db1e8c0388ea1912f141dd9db82cbc4e3b97765deeb9f9e80f6
encryption: none
$ zbx sign --key tour alpine@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e
signed b3:2e478596e56b3c0f1748d14e505d5d289ead0bb0526cbd53b325baff01afe599
binding: manifest
key: tour  51e043b61b2d7c7545a0d12bd074c9877e4d3548560c54e562c5355a24bc6f5c
signatures: 2
```

Drop `--no-passphrase` for a real key. The policy lives in `~/.config/zbx/policy.zon`:

```zig
.{ .version = 1, .keys = .{ .{ .name = "tour", .public = "zbx-ed25519:fe9dca62be757db1e8c0388ea1912f141dd9db82cbc4e3b97765deeb9f9e80f6" } }, .require_signature = true }
```

With it in place, a signed image runs and an unsigned one is refused before it starts (exit
code 125):

```
$ zbx run alpine@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e -- echo signed-ok
signed-ok
$ zbx run busybox:1.36 -- true
error[ZBX-E0905]: no trusted signature covers what was to run
  cause  /home/tester/.config/zbx/policy.zon requires a signature
         (require_signature), and nothing has signed
         docker.io/library/busybox@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f
  fix    sign it with a key the policy lists:   zbx sign docker.io/library/busybox@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f
         or add the signer's key to the policy file
  more   zbx explain E0905 · rerun with --verbose for the full cause chain
  docs   https://zigbox.github.io/zigbox/errors/E0905.html
```

`zbx policy check <image>` says what the policy would decide, without running anything, and
`zbx verify <image>` checks the signatures and the files:

```
$ zbx verify alpine@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e
verify alpine@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e
tree: b3:2e478596e56b3c0f1748d14e505d5d289ead0bb0526cbd53b325baff01afe599
1 signatures: ok (2 signatures)
2 signer: ok (key 51e043b61b2d7c7545a0d12bd074c9877e4d3548560c54e562c5355a24bc6f5c)
3 tree: ok
4 provenance: skipped
5 inputs: skipped
6 build_file: skipped
```

Provenance, inputs and build file are checked for images you built; a pulled image has none.

## Push

`--dry-run` packs the image and prints the manifest digest it would upload:

```
$ zbx push --dry-run alpine:3.20
sha256:9256d6b2c335b69e33b75b0fd912323bc020e7fb28e6e37752da77042b77c1fd
```

Without it, name the destination registry, repository and tag:

```sh
zbx push alpine:3.20 registry.example/team/app:1.0
```

`--username` with `--password-file` or `--password-stdin` logs in; for Amazon ECR, `zbx` finds
your AWS credentials as `zbx pull` does. Pushing to a local registry is tested on every change
([a recorded run](https://github.com/Zigbox/zigbox/actions/runs/42929050026)); `push` runs on
Linux only so far.

## When something fails

Every error is a block like the E0905 above: a code, the cause, a fix you can paste, and a link.

```sh
zbx explain E0905                 # the long explanation, offline
zbx explain E0905 --output json   # the same, for a script or an agent
```

Codes starting with `E` are errors, `W` warnings, and `B` bugs in `zbx` (please
[report those](known-limits.md#reporting-a-problem)). Exit codes: 0 success, 1 your input or
setup was refused, 2 the host is not ready, 70 a bug; `zbx run` exits 125 instead when it fails
before the container starts, and otherwise with the container's own exit code. `zbx explain
<code>` names the exit code of each.
