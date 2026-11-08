# M8 slice 7 handoff: the rpm and Debian guests

*Decided 2026-11-08, by M8 slice 7 (lane P).*

## What is there

- `zig build demo-m8-packages` (`src/testing/vm/main_m8_packages.zig`, checks in
  `checks_m8_packages.zig`) boots Ubuntu, Debian, Fedora and Rocky, installs the signed package
  from the test-key repository, runs `zbx --version` and `zbx doctor` as an ordinary user and
  prints one summary line per guest. `vm.yml`: a `vm/m8-packages-<slug>` branch runs it (`m8)`
  case; not part of `all`). Slice 8's full demo-m8 is separate.
- `zigbox_vm`: `image.debian_12`, `fedora_45`, `rocky_9` (pins in `lib/guests.zon`),
  `make_overlay_sized`, `cloud_init.Config.console_prompt`, `session.Seed.seed_id`.
  Ubuntu's seed and boot are unchanged.
- Result: [2026-11-08-archive-key-type.md](2026-11-08-archive-key-type.md).

## Traps

- **cloud-init before 23 (Debian 12 has 22.4.2):** `ds=nocloud` means dsmode local and the
  network stage then exits silently, leaving DataSourceNone. Use `seed_id = "nocloud-net"`.
- **Fedora and Rocky** have prompt `[root@host ~]#` and PROMPT_COMMAND; `console_prompt` rewrites
  both. Rocky's image is 10 GiB, so its overlay is 12G.
- `Session.run` wraps commands in `$( )`: a backgrounded server must redirect all fds of the
  whole group, or the pipe never closes.
- `zbx version` is not a command; use `zbx --version` (the first line is checked).
- `zbx doctor` exit codes in the guests are information, not a check: Rocky 9's kernel
  (5.14) is below Zigbox's 5.15 minimum (E0102) and its delegated cgroup lacks `cpu` (E0103);
  Debian 12 FAILs the cgroup check (no systemd user session for a `su` login). pasta is absent
  on Fedora and Rocky (warn). The check only requires that doctor ran.
- A guest's harness error is recorded as "stopped" and the other guests still run.

## Not done

- Not run: full demo-m8, aarch64 guests, RSA or other key types, older distributions.
- `.github/ci-changes.sh` path rules were not changed; the new files are under `src/testing/vm/`.
