# Archive key type: Ed25519 is accepted by all four guests

*Decided 2026-11-08, by M8 slice 7 (lane P).*

The package archive's signing key is **Ed25519**. Every guest we target accepts it, both on
repository metadata and on the rpm header signature.

## What was run

Run `demo-m8-packages` (`zig build demo-m8-packages`, or a push to `vm/m8-packages-<slug>`) on a
KVM runner, with the fixed test key (`-Dtest-key`, Ed25519). Each guest installs `zigbox` from the
signed repository, with no unsigned fallback; a refused signature fails the check. Run
https://github.com/Zigbox/zigbox/actions/runs/42504288000 (commit e4d6e84):

| guest | metadata | package | install | `zbx --version` |
|---|---|---|---|---|
| Ubuntu 24.04 | `apt update` accepts the `InRelease` | `dpkg` installs | installed | `zbx 0.3.1`, exit 0 |
| Debian 12 | `apt update` accepts the `InRelease` | `dpkg` installs | installed | `zbx 0.3.1`, exit 0 |
| Fedora 45 | `dnf makecache` with `repo_gpgcheck=1` accepts the repomd signature | `rpm -K`: digests signatures OK | installed | `zbx 0.3.1`, exit 0 |
| Rocky 9.8 | same as Fedora | same as Fedora | installed | `zbx 0.3.1`, exit 0 |

## Consequences

- No second key type (RSA) is needed for the supported guests. The RSA findings on #66 (RSA
  signatures refused; size limit too small for RSA 4096) do not affect these guests' acceptance.
- Fedora's rpm 6 needs the key imported (`rpmkeys --import`) before `rpm -K`; the install
  instructions already say to import it.
- Not covered: older rpm (RHEL 8, CentOS 7) and Debian 11 or older; they were not run.

## Pins

Debian 12 `genericcloud` 20261026-2643, Fedora Cloud Base 45-1.4, Rocky 9 GenericCloud 9.8-20260525.0,
each by URL and SHA-256 in `src/testing/vm/lib/guests.zon`.
