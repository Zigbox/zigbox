# Brief: M6 · State

Read these first:
- `AGENTS.md`, `REVIEW.md`, `docs/STYLE.md` and `DIAGNOSTICS.md`.
- The M6 section of `docs/SPEC.md`, with "Production readiness" and "Agent operability".
- `docs/DECISIONS.md`, the M6 entry, and the M3 entry on gc and its trash (state's trash follows it).
- `docs/demos/m5.md`: the network you build on, and the agent test's findings, which M6 closes.
- `docs/demos/m3.md`: how store work runs in a child inside the user's namespace, so that files owned by subordinate ids can be read, sized and removed.

Do not start M7: no build, no step DAG. Shared state between hosts, snapshots and backups to remote storage are Zigcube's (C7). `demo-m0` to `demo-m5` must keep passing in every slice.

## Goal and demo (from the spec, live doc rev 62)

Data that must outlive a container is named, typed and listed, never an anonymous directory.

1. `zbx run --state pgdata:/var/lib/postgresql/data --publish 5432:5432 -e POSTGRES_PASSWORD=demo postgres:16`.
2. From the host, `psql` in, create a table, insert a row.
3. Kill the container. Start it again with the same command; the row is still there.
4. `zbx state ls` shows `pgdata`, its size and the last container that used it.
5. Run without `--state`: data is gone after exit, as advertised.

Acceptance criteria:
- State volumes live outside the content store and are never garbage-collected implicitly.
- Ownership inside the container is correct without `chmod 777` workarounds.
- Secret mounts are read-only and excluded from `zbx commit`.
- The production-readiness checklist: an upgrade test against the merged M5 commit (`fd48d38`), stable diagnostics, documented failure modes, and the agent test extended to M6's steps.

## Fixed decisions

### State volumes

- **Where.** `$XDG_DATA_HOME/zbx/state/<name>/`, else `~/.local/share/zbx/state/<name>/`: beside the store, never inside it. Each volume is a directory `data/` and a small record (`state.zon`, versioned like every other record): created, last used, the last container that used it, and the path it was last mounted at. `store gc` never reads or removes anything under `state/`; test that.
- **Names.** Lowercase letters, digits, `.`, `-`, `_`, starting with a letter or digit, bounded in `constants.zig`. A name is never a path.
- **`--state NAME:PATH[:ro]`** (repeatable). The first use creates the volume, empty. The directory is made from inside the container's user namespace as the container's root, so a container user who `chown`s it (postgres's entrypoint does, to 999) owns it through the id map, with no `chmod 777`. Files in a volume are therefore owned by subordinate ids on the host, so every state command that reads or removes them (`ls` sizing, `rm`, `export`) runs its file work in a child in the user's namespace, as the store does.
- **One writer at a time.** A run holds its read-write volumes for its whole life: an exclusive lock on the volume's lock file, taken before the container starts and released when the run ends, on every exit path. A second run naming the volume read-write is refused with a coded error naming the container that holds it. `:ro` takes a shared lock and mounts the volume read-only: any number of readers, and no reader while a writer holds it.
- **Nothing implicit.** A volume is created only by `--state`, and removed only by `zbx state rm`.

### The state commands

- **`zbx state ls [--output json]`**: each volume's name, size on disk (counted in the namespace, hard links once), created, last used, and the last container that used it, with whether it is in use now and by which container.
- **`zbx state rm NAME`** moves the volume to a trash, as `store gc` does since M3; **`zbx state restore NAME`** brings it back until the trash expires (the same expiry as the store's trash, from `constants.zig`). A volume in use is refused. A restore whose name was meanwhile created again is refused, naming both.
- **`zbx state export NAME [-o FILE]`** writes a gzip-compressed POSIX tar (`.tar.gz`) to stdout or to `FILE`, with std's own writers (`std.tar.Writer`, `std.compress.flate` with the gzip container; read their source first). Owners and groups are written as the container sees them (postgres's 999, not the host's subordinate ids), so the archive restores anywhere. Modes, times, symlinks and hard links are kept; devices, sockets and fifos are skipped with one note each. A volume in use read-write is refused; exporting a consistent database is the database's own business. Refuse to write the archive to a terminal.
- The binary stays under the 4 MiB release limit with the compressor in; report its size.

### Other mounts

- **`--tmpfs PATH[:SIZE]`**: an empty tmpfs, gone at exit, with a default size bound from `constants.zig`. It counts against the container's memory limit, as the kernel does.
- **`--bind HOST:CTR`**: a read-only bind of a host directory or file. Always read-only: a writable host path is what `--state` is for. A missing host path is a coded error, never created.
- **`--secret HOST_FILE:CTR_PATH`**: a read-only bind of one host file, mode 0400 inside, owned by the container's root. Its contents never appear in a run record, a bundle, a log or JSON output; its path does. Like the generated `/etc` files of M5, a secret's mount point is never part of `zbx commit`; test that.
- Every mount target is an absolute container path without `..`; two mounts on one target are a usage error; a mount over `/proc`, `/sys`, `/dev` or a generated `/etc` file is refused.

### Environment variables

- **`-e NAME=VALUE`** sets a variable; **`-e NAME`** copies it from zbx's own environment, and is an error if it is unset there. `-e` overrides the image's `env`. Names follow POSIX; bounds are in `constants.zig`.
- **Values are never stored.** A run record, a bundle and JSON output carry the names of the variables set with `-e`, never their values, since they are where passwords go (the demo's `POSTGRES_PASSWORD`). `ps` and `inspect` show names only.
- The top-20 check runs postgres, mysql and mariadb with the password variable their entrypoint asks for; their "known" reasons go if they pass.

### Closing M5's carried-over notes

The owner put these here (from `docs/demos/m5.md`, the agent test's findings):

- **A failure says when the network was the likely cause.** When the no-network hint is printed, the exit line's JSON carries `"hint":"network_none"` (or a fuller `notes` array, if you find a better shape: say which). An explicit `--net none` carries no hint, as in text.
- **`run -d --output json` and `ps --output json`** carry the network mode and the published ports, as `run --output json` does.
- **A diagnostic's fix says what it needs.** Each fix may carry `"needs_root": true` and, when its command is an example to adapt rather than run, `"template": true`. Set them on the `06xx` fixes and anywhere else they are true. Schema and goldens follow; additive.
- **`zbx doctor --output json`** prints a `zbx.doctor/1` document with every check, including `net`, each with its status and, for a failure or warning, its code. A warning gets a `W01xx` code if it has none.
- **`zbx schema run`** is a single schema an agent can follow without resolving `$ref`s, or the schema documents a resolver-free form beside it. Choose and say why.

### Diagnostics

- `07xx` state: a bad volume name, a volume in use (naming the holder), a volume that does not exist (for `rm`, `export`, `restore`), a restore over an existing name, an expired or missing trash entry, a state directory that cannot be made or read, an export to a terminal or an unwritable file.
- Mounts and `-e` errors are usage errors (`00xx`) or runtime errors (`02xx`), whichever fits the existing groups: a missing bind source, a target over a protected path, an unset `-e NAME`.
- Every one with a cause and a fix, goldens and an error page.

## Slices (commit and stop for review after each; do not push to the working branch)

1. **M5's carried-over notes and `-e`.** Everything under "Closing M5's carried-over notes", and `-e` with its names-only rule. The demo-m5 agent uses the new JSON and stops reading text. demo-m5 must still pass.
2. **State volumes.** `--state`, the volume layout and record, creation in the namespace, the locks on every exit path, `state ls`, `state rm` with the trash, `state restore`, and the `07xx` codes they need. A test that `store gc` never touches `state/`. Real checks in the VM through `vm/*` scratch branches: postgres keeping a row across a SIGKILL and a rerun, its data owned by 999 inside.
3. **Other mounts and export.** `--tmpfs`, `--bind`, `--secret`, the mount-target rules, and `state export` to tar.gz. VM checks: a secret readable inside and absent from a commit and a bundle, a bind that cannot be written, an export that `tar -tzvf` lists with owner 999.
4. **VM, CI and the agent test.**
   - `zig build demo-m6`: the spec's five steps exactly, every assertion a unit-tested function. `psql` from the guest: add `postgresql-client` to the VM image.
   - The acceptance checks: gc leaves state alone; a second writer refused; a volume's lock released after each exit path (a clean exit, `zbx stop`, `--timeout`, SIGKILL of the container, SIGKILL of `zbx`); a secret read-only and absent from a commit.
   - The agent test extended to M6's steps, by JSON only.
   - The upgrade test against M5 (`fd48d38`): M5's store, records and lock read by this binary; an M5 run record without the new fields reads.
   - The top-20 workflow with the database password variables.
   - The `demo-m6` CI job; `docs/demos/m6.md` with the by-hand steps, cuts and failure modes: a volume in use, a disk full during a run or an export, a restore after the trash expired, a postgres killed mid-write and recovering, and a secret path that does not exist.

Slices 1 and 2 touch different code and may run in parallel; slice 3 follows 2.

## Done means

- All gates pass (`zig build check`), and every fuzzer you touched runs at 10,000 iterations. Record formats get a fuzzer that damages text and re-renders it (REVIEW.md).
- `demo-m6` is green in CI, with `demo-m0` to `demo-m5` still green. Until then M6 is "built, not demonstrated".
- Your report lists what you ran and its output, what you did not run and why, which REVIEW.md items you touched, every deviation from this brief, and anything in the spec, this brief or `DIAGNOSTICS.md` that seemed wrong.
