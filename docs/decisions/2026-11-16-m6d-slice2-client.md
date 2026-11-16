# M6d slice 2: Artifact Registry in the client

*Decided 2026-11-16, by the slice (M6d slice 2), for supervisor review.*

The choices slice 2 made that the brief ([M6d-gar.md](../briefs/M6d-gar.md)) left open, and the reasons.

## Anonymous first, the metadata server only on refusal

- Without `GOOGLE_APPLICATION_CREDENTIALS`, a pull from Artifact Registry or gcr.io starts anonymously, as today.
- If the realm answers `401` or `403`, the client calls a `RealmFallback` once. For the command line, that fallback is the GCE metadata server (`pull_google.fallback_for`). The client then retries the token request with Basic `oauth2accesstoken:<token>`.
- A public repository therefore never asks the metadata server, and a host off GCE never waits on it unless a pull is refused.
- With `GOOGLE_APPLICATION_CREDENTIALS` set, workload identity is resolved before the pull, and its answer is final: on failure there is no fallback to the metadata server.

## `pull.Request.google_fallback`, in addition to `pull.Request.google`

- The brief names only `pull.Request.google`, which carries a token resolved up front.
- The metadata step has to run *after* the anonymous refusal, so `Request` also gets `google_fallback: ?RealmFallback`, which defaults to null.
- This addition does not change the library: a library caller that sets neither field gets today's anonymous path, and one that sets `google` gets the token.
- `zbx run`'s lazy start sets `realm_fallback = null` after resolving, because the fallback's storage is wiped when the resolve step ends. The client never keeps a pointer to wiped storage.

## Blame and exit codes

The access token and repository refusals take the same blame as ECR's matching codes (E0530 to E0532):

| Code | Meaning | Blame | Exit |
| --- | --- | --- | --- |
| E0566 | Impersonation denied | user | 1 |
| E0568 | Repository denied, or missing at the realm | user | 1 |
| E0569 | Repository missing | user | 1 |
| E0567 | Access token refused | external | 3 |
| E0560 | No credentials | environment | 2 |
| E0561 | Credentials file unreadable | environment | 2 |
| E0564 | Subject token unreadable | environment | 2 |
| E0572 | A Google service failed | external | 3 |

The access token is refused when it expired or was revoked, both of which are Google's side.

## Missing-repository shapes (the owner's check is pending)

Following [2026-11-16-m6d-missing-repo-unverified.md](2026-11-16-m6d-missing-repo-unverified.md), every shape the owner's check could show is handled:

| Registry answer | Code |
| --- | --- |
| `403 DENIED` at the realm | E0568 |
| `403 DENIED` at the manifest | E0568 |
| `404 NAME_UNKNOWN` at the manifest | E0569 |

- E0568 reads "denied the pull …: the identity lacks `artifactregistry.repositories.downloadArtifacts`, or the repository does not exist", so it is right whichever shape Google uses.
- The permission name in E0568 comes from a fixed table, never from the message text.

## The same-host download redirect may carry the realm's Bearer

- The brief says the realm's Bearer token goes to the registry origin, and the existing same-origin rule covers the relative `/artifacts-downloads/…` redirect.
- Slice 1's `google_sim` counted any credential on that path as a leak, which is stricter than the brief. The simulation now counts only Basic or another `Authorization` header there.
- A redirect to `storage.googleapis.com` still gets no credential, and the simulation still checks that.

## VM check

- The brief asks for a `vm/m4` run, since M4 is the pull demo, and the supervisor's message names `vm/m6`.
- Both were pushed: `vm/m4-m6d-s2` and `vm/m6-m6d-s2`.
