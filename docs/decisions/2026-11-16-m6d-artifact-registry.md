# M6d: private pull from Google Artifact Registry, gcr.io included

*Decided 2026-11-16, by the owner. Brief: `docs/briefs/M6d-gar.md`.*

The owner's words, approving the full milestone with gcr.io in it:
**"Full version, GCR.io included, as 0.6.1"**

And, relayed by the supervisor the same day as a follow-up to that message:
**"Or 0.5.3 if it comes sooner"**

## What it decides

- **A new milestone, M6d · Private pull: Google Artifact Registry**, modelled on M6c (ECR). It
  pulls from `<region>-docker.pkg.dev` and from `gcr.io`, `us.gcr.io`, `eu.gcr.io` and
  `asia.gcr.io` (which Google now serves from Artifact Registry), with credentials from workload
  identity federation (an `external_account` file) or the GCE metadata server. Service-account
  key files are refused, naming workload identity federation as the fix. The full scope, and what
  is not in it, is in the brief.
- **The release.** M6d ships in the next release it is ready for (0.5.3 or 0.6.1). It does not
  wait for S2 or 0.6.0: it must not depend on S2 code (dormant on `main` until 0.6.0), so it
  branches from `main` and can release on the 0.5.x line.
- **The Non-goals line "Private registries"** in the design doc and `docs/SPEC.md` changes from
  "except authenticated pull from Amazon ECR (M6c, …)" to also except Google Artifact Registry
  and gcr.io (M6d). Pull with push's `--username` credentials, and every other private registry,
  stay out.
- **The credential layer is shared, not copied.** ECR and Artifact Registry use one
  caller-provided registry credential type in the pull client; `aws_credentials_resolve`, its
  exports and Zigcube's use of them do not change (brief, "One credential layer").

## Why

Zigcube nodes and users on Google Cloud keep their images in Artifact Registry, and gcr.io
references are still common in manifests and Dockerfiles. M6c built the shape (credentials from
the caller, resolved per pull, never written, coded failures), so M6d adds a second provider on
it rather than a second design.

## Supervisor defaults, 2026-11-16, the owner may override

The supervisor set these on review of the brief, so it has no open questions:
- **Codes:** a new range, `E0560`–`E0574`. M6c's unused `E0536`–`E0549` reservation is left alone.
  The slice 2 implementer registers the codes; none are registered now.
- **No plain access-token source** (no environment variable holding a token).
- **Workforce pools are refused** with a coded line.
- **A plain-HTTP `credential_source.url` is refused** (this includes Azure's managed identity endpoint).
- **The metadata server is asked only after an anonymous refusal**, so public pulls are unchanged.

The owner may revisit the plain access-token source and workforce pools.

Links: `docs/briefs/M6d-gar.md`, `docs/briefs/M6c-ecr.md`,
`docs/decisions/2026-11-09-m6c-slice1-credentials.md`,
`docs/decisions/2026-11-09-m8-slice12-credentials.md`.
