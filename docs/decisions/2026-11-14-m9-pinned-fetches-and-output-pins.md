# M9: fetches pinned by hash, and output pins for network steps

*Decided 2026-11-14, by the owner (rulings 1 to 5, and the codes and bounds below). The details
and picks below them are the supervisor's and are marked as such.*

Docker builds fetch files and packages, and the same Dockerfile run a week later can give a
different image without saying so. M9 refused `ADD <url>` outright and listed hash-pinned fetches
as a non-goal. The owner ruled to bring a narrow, verifiable form of fetching into M9, and to make
drift in network steps visible.

**Rulings (owner).**

1. **Hash-pinned fetches are in M9** and leave the non-goals. A build file gets
   `.fetch = .{ .url, .sha256 }`. The parent downloads it, outside the sandbox, over HTTPS only;
   the bytes are verified and stored by content; a second build, or a host that already has the
   bytes, does not download again. The step that uses the file has no network. The key covers the
   SHA-256, not the URL. Dockerfile `ADD --checksum=sha256:<hex> <url> <dest>` maps to it.
   `ADD <url>` without a checksum stays `E0811`, with a fix to add `--checksum` or to import the
   fetch as a flagged `RUN curl`. The download size and the redirect count are bounded. A hash
   mismatch has its own code, naming the URL, the expected hash and the one received.
2. **Output pins are opt-in.** `.expect = "b3:<hex>"` on a network step, or `zbx build --pin`,
   which records each network step's first output digest in `zbx.lock`. When a step has a pin,
   the steps after it are keyed by the pinned digest. With neither, nothing changes: the
   `demo-m7` and M9 goldens stay as they are.
3. **Drift.** Under `--locked` or `--hermetic`, a pinned step whose output differs from its pin
   fails with a new code naming the step, the pinned digest and the new one. Otherwise a new
   warning names the same three, the new output is used, and everything after it rebuilds.
   `zbx build --locked` means no lock additions and every pin enforced. (No flag of that meaning
   existed on `zbx build` under another name.)
4. **`.output_exclude`**, per step. Pinned steps default to `/var/log`, `/var/cache` and `/tmp`
   (and `/var/lib/apt/lists`, the supervisor's pick below).
   The brief says what M7's timestamp rules cover and miss, checked against real package
   managers where that was possible.
5. **Mirror snapshots for apt and apk are out of scope.** Drift is reported loudly, not
   prevented.

**Reasons.** A fetch with a hash is as reproducible as a copied file, so refusing it pushed users
to a `RUN curl` that is neither checked nor hermetic. A pin turns "the mirror changed" from a
silent difference into a named step and two digests. Making both opt-in keeps every existing
build, key and golden as it is.

**Details the supervisor chose (the owner may overrule).** A fetch is a copy source, so a `RUN`
reaches the file through its chain or a `needs`, and no new mount kind is added. Remote-`ADD`
defaults follow Docker's (mode `0600`, owner `0:0`). Fetched bytes go to `blobs/sha256/`. Pins go
in `zbx.lock` as `.pins`, each with its file, step, key and output, and the lock becomes
`.version = 2` only when it has pins. A pin records its step's key, so a changed step is re-pinned
by `--pin` and refused as stale by `--locked`. Drift without `--locked` leaves the pin as it was.
`zbx build --hermetic` is `--locked`, plus a refusal (`E0814`) of unpinned network steps and of
cache steps. `--pin --locked` is `E0005`.

**Approved by the owner, 2026-11-14** (registered and added to `constants.zig` in slices 3b
and 3c).

- Codes: `E0820` a fetch could not be downloaded; `E0821` the fetched bytes do not match the hash;
  `E0822` a pinned step drifted, or its pin is stale, under `--locked` or `--hermetic`; `W0803` a
  pinned step drifted and the new output was used. The three errors are blame external, exit 3.
- Bounds: `build_fetch_bytes_max` 1 GiB; `build_fetch_redirects_max` 4 (equal to
  `registry_redirects_max`); fetch URLs within `registry_url_bytes_max` (2048 bytes); the idle
  timeout reused from `net_idle_timeout_ms`; `build_output_excludes_max` 32; `lock_pins_max` 256.

**Found while writing the brief.** BusyBox `adduser`, which the first draft of the M9 demo ran
in its final stage, writes the current day into `/etc/shadow` and ignores `SOURCE_DATE_EPOCH`, so
the demo's second-VM golden digest would change every day.

**The supervisor's picks on the open questions (2026-11-14).**

1. The fetched file is a copy source, as drafted.
2. `zbx build --hermetic` stays as defined above.
3. `/var/lib/apt/lists` joins the default `.output_exclude` list, with `/var/log`, `/var/cache`
   and `/tmp`: it is an index, not installed content, and its `InRelease` files carry the
   mirror's date.
4. A pin is changed by deleting it and running `zbx build --pin`. There is no `--repin` flag.
5. `.expect` on a step with `.caches` is refused (`E0801`); its output depends on a cache outside
   its key.
6. The demo's Dockerfile writes the `/etc/passwd`, `/etc/group` and `/etc/shadow` lines directly
   instead of running `adduser`. `zbx` normalises nothing in those files.
7. `E0820`–`E0822` are external errors, exit 3.

Detail: `docs/briefs/M9-dockerfile-import.md` (*Pinned fetches and output pins*, the mapping
table, *Diagnostics*, slices 3b and 3c, demo steps 7 and 8, *Spec notes*),
`docs/briefs/M9-dockerfile-flags.md` (the `ADD` rows), and `docs/SPEC.md` (M9).
