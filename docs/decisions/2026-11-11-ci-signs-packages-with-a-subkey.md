# CI signs the packages with a signing subkey; the primary key stays offline

*Decided 2026-11-11, by the owner.*

Supersedes the signing clause of [2026-11-04-package-signing-hosting.md](2026-11-04-package-signing-hosting.md)
("signed with `gpg` on the owner's machine ... never run by CI") and the clause of
[2026-11-10-packages-on-zigbox-org.md](2026-11-10-packages-on-zigbox-org.md) that says CI never
builds or signs the repository bytes. Hosting at zigbox.org is unchanged.

## Why

Signing on the owner's laptop made the laptop the key store and made each release two manual
rounds of `gpg` commands. The usual practice is an offline primary key and a signing-only subkey
used by the release automation.

## The decision

- **Keys.** The release key's primary (certification) key lives offline, on the owner's YubiKey
  with an offline backup. It is used only to create, renew and revoke subkeys. A signing-only
  subkey with an expiry of at most one year is stored as a secret of a protected GitHub Actions
  environment, `release`, which requires the owner's approval before a job can read it. Users
  trust the primary key's fingerprint; a subkey change needs nothing from them.
- **Workflow.** A release workflow runs on a `v*` tag (and on `workflow_dispatch` with a tag, to
  sign an existing release): `zig build packages`, the rpm header signatures, `zig build packages
  -Dsignatures=...`, the four metadata signatures, the final `packages` and `packages-check` runs,
  `gpg --verify` and `rpm -Kv` of every signed file with the public key, then it attaches
  `zigbox-repos.tar.gz` to the release and dispatches the zigbox.org deploy (`repository_dispatch`
  type `site`). `zig build packages` itself still never runs `gpg`.
- **Secrets.** The subkey is imported into a throwaway `GNUPGHOME` in the job and removed at its
  end; it is never printed, never written to the workspace and never passed as a command-line
  argument. Only the `release` environment's jobs can read it.
- **The gate stays.** The tag is still cut only from a release-gated commit; the owner's approval
  of the `release` environment run is the human step.
- **This lands before the next Zigbox release.** 0.4.0's archive is produced by the same workflow
  on `workflow_dispatch` once the subkey is in place, rather than by hand.
- The same applies to Zigcube's packages when C3 adds them.

Where: `docs/releases/packaging.md` (rewritten for the workflow), `docs/STYLE.md` (gpg becomes a
release-workflow program), `.github/workflows/release.yml`.
