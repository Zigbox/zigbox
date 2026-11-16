# Brief: M6d · Private pull from Google Artifact Registry

Read these first:
- `AGENTS.md`, `REVIEW.md`, `docs/STYLE.md` and `DIAGNOSTICS.md`.
- The M6d section of the live design doc (snapshot: `docs/SPEC.md`, "M6d · Private pull: Google Artifact Registry"), and its "Non-goals". If the live doc disagrees with this brief, stop and report; do not pick one.
- `docs/decisions/2026-11-16-m6d-artifact-registry.md` (the owner's decision and the release), `docs/briefs/M6c-ecr.md` (the shape this milestone follows), `docs/decisions/2026-11-09-m6c-slice1-credentials.md` and `docs/decisions/2026-11-09-m8-slice12-credentials.md`.
- `src/aws/` (`credentials.zig`, `parse.zig`, `aws_sim.zig`), `src/pull_aws.zig`, `src/registry/` (`client.zig`, `ecr_login.zig`, `auth.zig`, `net.zig`, `net_sim.zig`, `proxy.zig`), `src/push/credentials.zig` (`realm_allowed`) and `src/push/upload.zig` (Basic to the realm, then Bearer), `src/pull.zig`, `src/zigbox.zig` (the `aws_*` exports), `src/redact.zig`, `docs/demos/m6c.md`.

**Release and branch.** M6d ships in the next release it is ready for (0.5.3 or 0.6.1). It must not depend on S2 code, which is dormant on `main` until 0.6.0: branch from `main`, touch nothing S2 owns, and keep the milestone releasable on the 0.5.x line. If a slice seems to need S2, stop and ask the supervisor.

M6c (ECR pull) and M8's push lane are merged and share `net.zig`, `auth.zig` and the client with this milestone: keep their tests, fuzzers and demos green. `aws_credentials_resolve`, its exports and ECR pull and push do not change behaviour. No push here, no other private registry, no Mac work (below). Every existing demo, the top-20 check and the Mac demos must keep passing.

## Goal and demo (from the live doc)

A host pulls and runs an image from a private Google Artifact Registry repository, or from gcr.io, with the Google credentials it already has, and no secret ever leaves the request it was made for.

1. With no Google credentials (no `GOOGLE_APPLICATION_CREDENTIALS`, off GCE), `zbx pull <region>-docker.pkg.dev/<project>/zbx-demo/hello:latest` is refused with one line naming the sources tried and the fix.
2. With workload identity federation from GitHub Actions (`GOOGLE_APPLICATION_CREDENTIALS` naming an `external_account` file; no key file anywhere), the same pull succeeds; `zbx run` of it prints `hello`; `zbx.lock` holds the digest.
3. With the same credentials, `zbx pull gcr.io/<project>/hello:latest` succeeds (gcr.io served by the project's `gcr.io` Artifact Registry repository).
4. Pulling `<region>-docker.pkg.dev/<project>/zbx-denied/hello:latest`, a repository the identity may not read, is refused, naming the repository and the missing permission `artifactregistry.repositories.downloadArtifacts`.
5. No secret is anywhere: the OIDC subject token, the federated (STS) token, the access token and the registry's Bearer token are absent from every byte zbx wrote (output, `--output json`, `zbx.lock`, the store's image record, `zbx bundle`, the logs).

Acceptance criteria:
- Credentials go only where they are for: the subject token only to `sts.googleapis.com`; the federated token only to `iamcredentials.googleapis.com`; the access token only to the registry's same-host token realm, as Basic `oauth2accesstoken:<token>`; the realm's Bearer token only to the registry origin. Never to a redirect target on another host, and never to a mirror.
- The CI step's secrets (the runner's `ACTIONS_ID_TOKEN_REQUEST_TOKEN` and the OIDC token it returns) are never on a command line or echoed: `curl` reads the header from a 0600 file (`-H @file`) or stdin, the token enters the VM as a 0600 file, and `set -x` is off in that step.
- No secret is written to disk, put in a diagnostic, an argument list, a record or a bundle, and each buffer that held one is zeroed after use.
- Every failure is one coded line: no credentials, an unreadable credentials file, an unsupported credentials file (with service-account keys naming workload identity federation), the exchange refused, impersonation refused, the missing permission, a missing repository, the metadata server absent, an unsupported Google registry host.
- `zbx pull` of a public image, including public images on `*-docker.pkg.dev` and `gcr.io`, and its output and JSON, do not change (the goldens prove it). `zbx.lock` and the store formats do not change.
- The library takes credentials from its caller, so Zigcube's agent can pull from Artifact Registry (its `ensure_image`), exactly as from ECR.

## Fixed decisions

### Native, no helper programs

zbx gets Google access tokens itself, over the host interface. `docker-credential-gcr`, `gcloud` and `gke-gcloud-auth-plugin` are external programs, which STYLE.md does not allow. Don't shell out, and don't read `~/.docker/config.json` or `~/.config/gcloud`. No JWT signing is needed: workload identity federation and the metadata server hand back access tokens, and service-account keys (the only path that needs RS256) are out.

### Registries, recognised by host

- **Artifact Registry**: `<region>-docker.pkg.dev`, where `<region>` is a location name (lower-case letters, digits and hyphens, for example `us`, `europe`, `us-central1`, `europe-west4`). References are `<host>/<project>/<repository>/<image>[:tag|@digest]`.
- **gcr.io**: exactly `gcr.io`, `us.gcr.io`, `eu.gcr.io` and `asia.gcr.io`. These are served by Artifact Registry today (a `gcr.io` repository in the project). The token scope the registry asks for is not the reference path (checked 2026-11-16: `gcr.io/<project>/hello` asks for `repository:<project>/gcr.io/hello:pull`), so always request the scope the challenge names, never one built from the reference.
- **Other Google shapes** (`*.pkg.dev` that is not `<region>-docker`, any other `*.gcr.io` such as `k8s.gcr.io` or `marketplace.gcr.io`) never get credentials. They keep today's anonymous path, so a public pull that works now still works (`k8s.gcr.io` redirects to `registry.k8s.io`). When such a host refuses an anonymous pull, the refusal is the coded "unsupported Google registry host" line naming the supported hosts, not today's generic E0507.
- **`mirror.gcr.io`** is a public Docker Hub mirror (CI sets `ZBX_REGISTRY_MIRRORS=mirror.gcr.io`). It is not a private registry, never gets credentials and never changes behaviour.

### Registry auth

- Every recognised host challenges with `Bearer realm="https://<same host>/v2/token"` (checked 2026-11-16 for `us-docker.pkg.dev`, `us-central1-docker.pkg.dev`, and the four gcr.io hosts; `gcr.io` sends `service=gcr.io` unquoted, which the parser must accept).
- With an access token, the client sends `Authorization: Basic base64("oauth2accesstoken:<token>")` to the realm only, takes the Bearer token from the realm's JSON, and uses that Bearer on the registry origin. This is push's `--username` path (`src/push/upload.zig`): the access token never goes to the registry's `/v2/` endpoints, and Basic and Bearer are never sent together. Unlike ECR (whose token is Basic on the origin from the first request), nothing is sent before the first challenge.
- The realm must pass the existing realm rule (`realm_allowed`, today in `src/push/credentials.zig`): same host, HTTPS. A realm on another host is refused before any credential is sent.
- **Denials arrive at the realm.** Checked 2026-11-16: an anonymous token request for a private or missing repository gets `403` from the realm with code `DENIED` and a message naming `artifactregistry.repositories.downloadArtifacts`; a bad access token gets `401 UNAUTHORIZED`. Today both become E0507 (`token_refused`). Map them from the status and the error code to the coded lines below; the permission named in the diagnostic comes from a fixed table, never from the message text. Whether a missing repository answers `404 NAME_UNKNOWN` at the manifest or `403` at the realm with valid credentials was not checked: slice 1 checks it against the owner's project (by hand, recorded) and the simulation follows what it finds.
- **Redirects**: checked 2026-11-16, config blobs are served directly and layer blobs redirect (`302`) to a relative same-host path, `/artifacts-downloads/namespaces/…/downloads/…`, which serves them without auth. The existing rule (credentials go only to the origin the client started with) covers this; test both the same-host relative redirect and a simulated `storage.googleapis.com` host that fails any request carrying `Authorization`, since Google can move blobs to a storage host without notice.
- **Mirrors**: `ZBX_REGISTRY_MIRRORS` applies to docker.io only. Test that an Artifact Registry or gcr.io reference never reaches a mirror.

### Where credentials come from, in this order, the first that yields wins

1. **Workload identity federation.** `GOOGLE_APPLICATION_CREDENTIALS` names a JSON file with `"type": "external_account"`. Read it (bounded size, a constant), then:
   - **Subject token**: from `credential_source.file` (a path; text, or JSON with `format.type = "json"` and `format.subject_token_field_name`), or from `credential_source.url` (a `GET` with `credential_source.headers`, the same two formats; HTTPS only). The url form is how `google-github-actions/auth` writes the file on GitHub Actions; the file form is how GKE and the demo do it.
   - **Exchange**: `POST https://sts.googleapis.com/v1/token`, form-encoded: `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, the file's `audience` and `subject_token_type`, `requested_token_type=urn:ietf:params:oauth:token-type:access_token`, `scope=https://www.googleapis.com/auth/cloud-platform`, `subject_token`. The answer's `access_token` and `expires_in` are read with the bounded JSON reader.
   - **Impersonation**, when `service_account_impersonation_url` is present: `POST` it with the federated token as Bearer and body `{"scope":["https://www.googleapis.com/auth/cloud-platform"],"lifetime":"3600s"}`; read `accessToken` and `expireTime`.
   - **Refused, each with a coded line**: `token_url` other than `https://sts.googleapis.com/v1/token`; an impersonation URL whose host is not `iamcredentials.googleapis.com` or whose path is not `/v1/projects/-/serviceAccounts/<email>:generateAccessToken`; `universe_domain` other than `googleapis.com`; a workforce pool audience (`//iam.googleapis.com/locations/global/workforcePools/…`; supervisor default); `credential_source.executable`; `credential_source.environment_id` starting `aws`; `credential_source.certificate`; a plain-HTTP `credential_source.url`, including Azure's managed identity endpoint (supervisor default).
   - **Terminal.** As with M6c's web identity: once `GOOGLE_APPLICATION_CREDENTIALS` is set, a failure is reported and the metadata server is not tried.
   - **Other file types**: `"type": "service_account"` (a key file) is refused with a coded line that names workload identity federation as the fix and says key files are not supported. `"type": "authorized_user"` (gcloud user credentials) and anything else is refused as an unsupported credentials file, naming its type.
2. **The GCE metadata server.** `GET http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token` with `Metadata-Flavor: Google`. Plain HTTP to that link-local address only (by address, never `metadata.google.internal`, so DNS cannot redirect it), never through the proxy whatever `HTTPS_PROXY` or `NO_PROXY` say (M6c's `ProxyUse.never`), with a short connect and total timeout (constants, as `aws_imds_timeout_ms`). The response must carry `Metadata-Flavor: Google`, or the source is absent: an EC2 host answers on the same address, and its 404 or its missing header means "not GCE". Read `access_token` and `expires_in`.

**When the metadata server is asked** (supervisor default, 2026-11-16): only after an anonymous attempt is refused. A pull from a recognised host with no `GOOGLE_APPLICATION_CREDENTIALS` first goes anonymous, exactly as today; if the realm refuses it (`401` or `403`), zbx asks the metadata server once and retries the token request once with what it returns; if the metadata server is absent, the refusal is the "no Google credentials" line naming both sources. This keeps public Artifact Registry and gcr.io pulls off GCE free of a metadata probe and byte-identical to today. ECR's IMDS is asked up front because ECR has no public path; Artifact Registry does.

**A plain access-token source** (an environment variable holding a token, as `gcloud auth print-access-token` would fill) is **not** in M6d. It puts a secret in the environment, where it is visible to `/proc/<pid>/environ` and inherited by children, and both supported sources already cover CI, GKE and GCE. A developer on a laptop uses workload identity federation or pulls on a host with a service account. (Supervisor default, 2026-11-16.)

Not in M6d (record in `docs/demos/m6d.md`): service-account JSON key files, `authorized_user` and other gcloud ADC user credentials, executable-sourced and AWS-sourced external accounts, X.509 (`certificate`) sources, workforce pools, `~/.docker/config.json`, credential helpers, push to Artifact Registry, the Mac.

Credentials are looked up only for a recognised Google host, and resolved again for every pull. They are never cached, in memory beyond the pull or on disk.

### One credential layer, shared with ECR

Generalise the layer M6c built rather than copying it. The rule: the pull client knows registry credentials, not clouds; each provider resolves its own token and hands the client one value.

- **The client takes one credential union**, owned by the caller for the pull: `.ecr_basic` (M6c's token: Basic on the registry origin from the first request, unchanged) and `.realm_basic` (a username and secret: Basic to the same-host realm only, then Bearer; used here with `oauth2accesstoken`). Push's `upload.Credential` already has these two shapes (`.ecr` and `.basic`); the realm half (`realm_allowed`, the Basic token request) moves to `src/registry/auth.zig` and is shared by push and pull, with push's tests unchanged. The client's per-pull workspace keeps the Basic or Bearer value it sends and wipes it on every exit, as `client.workspace.basic` does today.
- **`pull.Request` keeps `aws`** and gains `google: ?*const GoogleToken = null` (an access token in a caller-provided buffer, with its expiry). Exactly one provider applies to a host, chosen by the host; the other is ignored. Do not change `aws`'s type or meaning: Zigcube's agent sets it today.
- **`aws_credentials_resolve`, `AwsEnv`, `AwsCredentials`, `AwsWorkspace` and `AwsTrace` keep their names, signatures and behaviour.** The shared parts move under them: the environment view (`AwsEnv` becomes an alias of a shared `CredentialEnv` with a provider's own fixed name list), the link-local metadata request (no proxy, fixed address, timeouts), the bounded JSON field reader in `src/aws/parse.zig`, and the Workspace and Trace shapes. The AWS tests and the `parse_aws` fuzzer are unchanged and green before and after the move.
- **The library gains `google_credentials_resolve(host, env, now_s, sources, workspace, token, trace)`**, the Google twin of `aws_credentials_resolve`, exported beside it with `GoogleEnv`, `GoogleToken`, `GoogleWorkspace` and `GoogleTrace`. `sources` is a mask (`.wif`, `.metadata`), so the CLI can ask for workload identity up front and the metadata server only after an anonymous refusal (above), and Zigcube's agent can choose. It returns a trace, not a diagnostic, as the AWS resolver does, and a `pull_google.zig` (the twin of `src/pull_aws.zig`) maps the trace to the coded lines.
- **Keep the scope and action explicit in the types**, as M6c did for push: a later Artifact Registry push needs only a different scope on the realm request.

### The network interface

M6c gave `net.zig` a method, extra headers and a bounded body; reuse them. `net.Head` reads a fixed set of response headers today and has no `Metadata-Flavor`; add it there (a fixed field, as `www_authenticate` is). Still one request, one response, no retries, no redirects; the client stays the only place that follows redirects. `net_sim.zig` gains these hosts: an Artifact Registry host and the gcr.io hosts (challenge, realm, manifest, blobs, the same-host relative blob redirect), `sts.googleapis.com`, `iamcredentials.googleapis.com`, a subject-token URL host, the GCE metadata server, and a `storage.googleapis.com` that fails any request carrying `Authorization`. Faults: subject token refused (`invalid_grant`), audience or pool wrong, impersonation denied (`403 PERMISSION_DENIED`), access token refused at the realm (`401`), repository denied at the realm (`403 DENIED`), repository missing, metadata server absent, slow, without `Metadata-Flavor`, or answering as EC2 does, and a 5xx from each.

### Time

The access token's expiry comes from `expires_in` (or `expireTime`), against the clock from the host interface (`host_sim` has one), never a direct call. One pull never needs a second token; an already-expired token from the caller is refused before it is sent.

### Secrets

- The subject token, the `credential_source.headers` values (on GitHub Actions they hold the runner's OIDC request token), the federated token, the access token, the Basic value and the registry's Bearer token are secrets. The project number, pool, provider and service-account email are not, but stay out of diagnostics except where a fix needs them.
- Each secret lives only in caller-provided buffers, which `std.crypto.secureZero` clears when the pull ends, on every path. The credentials file is read into such a buffer, since it can hold a header secret.
- **Extend `redact.zig` and its fuzzer** to cover Google access tokens (`ya29.`), the `oauth2accesstoken` Basic value (already covered by `Authorization: Basic`; add a test), `subject_token=` in a form body, and STS, IAM Credentials and metadata response bodies. A diagnostic built from a Google error carries the error's code (`invalid_grant`, `PERMISSION_DENIED`, `DENIED`), never its message text or a body.
- HTTPS only for every credentialed request. The loopback-HTTP exception stays a test-registry affordance and never carries credentials. The metadata server is the single plain-HTTP call, fixed to its link-local address.

### In the library

- The library does not read the environment, the credentials file or the metadata server on its own initiative. `google_credentials_resolve` does, over the host interface, with the environment passed in as a view. The CLI calls it for each pull from a recognised host; Zigcube's agent calls it the same way. Per-caller storage, no process-wide state, bounded memory, as in M6b and M6c.
- `zbx pull` and `zbx run <ref>` call it; nothing else changes for them.

### Not on the Mac yet

As in M6c: the macOS `zbx` forwards `pull` to the Linux guest, which has no Google credentials. Do not forward credentials over the forward protocol. Note it as a known gap in `docs/demos/m6d.md`.

### Diagnostics

Registry failures are `05xx`. Registered today: `E0501`–`E0535` and `E0550`–`E0558`; `E0536`–`E0549` are reserved for M6c and unused, and push holds `E0550`–`E0559`. M6d takes the new range `E0560`–`E0574` (supervisor default, 2026-11-16), in order; M6c's `E0536`–`E0549` reservation stays as it is. The codes below are registered by the slice 2 implementer, not before. Each code gets a cause, a fix, a golden and an error page. At least:
- No Google credentials, naming the two sources tried and the metadata server's state (absent, not GCE, no service account).
- Credentials file unreadable or too large, naming the variable and the path.
- Credentials file unsupported: a service-account key (naming workload identity federation as the fix), `authorized_user`, or an unsupported `external_account` source, naming the field.
- Subject token unreadable or empty (file or URL source), naming the source.
- Token exchange refused at STS, with Google's error code.
- Impersonation refused, naming the service account and `iam.serviceAccounts.getAccessToken` (the `roles/iam.workloadIdentityUser` binding).
- Access token refused by the registry (invalid or expired).
- Repository denied, naming the repository and `artifactregistry.repositories.downloadArtifacts`.
- Repository missing, naming the repository (and, for gcr.io, that the project needs a `gcr.io` repository).
- Unsupported Google registry host, naming the supported hosts.
- Workforce pool audience refused.

### CI (the owner sets up the Google side; the slice 3 implementer writes the workflow)

The owner's setup checklist (nothing here is a secret; zbx never asks for or handles a key):
1. One Google Cloud project with the Artifact Registry API and the IAM Credentials API enabled.
2. In one region, two Docker repositories: `zbx-demo`, holding a small `hello` image as an index for amd64 and arm64, and `zbx-denied`. Plus a `gcr.io` repository (location `us`, format Docker) holding the same `hello` image, so `gcr.io/<project>/hello` resolves.
3. A workload identity pool and an OIDC provider for `https://token.actions.githubusercontent.com`, with an attribute condition that admits only `Zigbox/zigbox`, and only pull requests from the repository, `main` and `vm/*` branches (map `assertion.repository` and `assertion.ref`).
4. Either a service account `zbx-pull` with `roles/artifactregistry.reader` on `zbx-demo` and the `gcr.io` repository only, and `roles/iam.workloadIdentityUser` for the pool's principal set; or the reader role granted to the principal set directly (no impersonation). Prefer impersonation: it is the common setup and exercises one more step. Nothing on `zbx-denied`.
5. No service-account keys anywhere. The organisation policy `iam.disableServiceAccountKeyCreation` is recommended.
6. Repository variables (not secrets, since they are not secret): `ZBX_GAR_PROVIDER` (the provider's full resource name), `ZBX_GAR_SERVICE_ACCOUNT` (the email, or empty), `ZBX_GAR_REGISTRY` (`<region>-docker.pkg.dev/<project>`), `ZBX_GCR_REGISTRY` (`gcr.io/<project>`).

The workflow:
- The job needs `permissions: id-token: write`. The runner fetches its OIDC token with `curl` from `ACTIONS_ID_TOKEN_REQUEST_URL` with `audience=//iam.googleapis.com/<provider>`, with no third-party action, and hands it into the VM as a file. Neither `ACTIONS_ID_TOKEN_REQUEST_TOKEN` nor the token is ever on a command line: `curl` takes the `Authorization` header from a 0600 file (`-H @file`) or from stdin, never `-H "Authorization: bearer $TOKEN"`; the token is written to a 0600 file and goes into the VM as that file; nothing is echoed, and `set -x` stays off in that step. The harness writes an `external_account` file with `credential_source.file` pointing at it (and the impersonation URL when `ZBX_GAR_SERVICE_ACCOUNT` is set). The `credential_source.url` form is tested in simulation only.
- Step 5 searches every byte zbx wrote for the OIDC token, the STS token and the access token. The harness learns the latter two only through a test helper in `src/testing/vm/` that runs zbx's own exchange, never from a log.
- A run with no OIDC token (a fork's pull request) does not run `demo-m6d` and says "not run" in the job summary. It is never reported as a pass.

## Slices (commit and stop for review after each; push to your own session branch as AGENTS.md says)

1. **The shared layer and the Google sources.** Move the shared parts out from under `src/aws/` with every AWS test and the `parse_aws` fuzzer unchanged and green; the host classifier (Artifact Registry, the four gcr.io hosts, other Google shapes, `mirror.gcr.io`); the `external_account` reader and its refusals; the file and URL subject-token sources; STS and impersonation; the metadata server with its proxy bypass and `Metadata-Flavor` check (`net.Head` gains the field); `google_credentials_resolve` and its exports; the new `net_sim` hosts and faults; secret buffers zeroed; a `parse_google` fuzzer over the credentials file, the STS, IAM Credentials and metadata responses, the realm's error body and the host classifier; `redact` extended. The by-hand check of the missing-repository answer (above), recorded in the handoff. Unit and simulation tests only; no VM check.
2. **Artifact Registry in the client.** The credential union with `.ecr_basic` unchanged and `.realm_basic` added; `realm_allowed` and the Basic token request moved to `auth.zig` and shared with push; anonymous first, then the metadata server on refusal; the challenge's scope used as given; the same-host and storage-host redirect tests; the mirror bypass test; the codes (`E0560` onward, registered here) with goldens and error pages; `pull.Request.google`; `zbx pull` and `zbx run` calling the resolver. An end-to-end simulation of the demo's five steps, and the public-pull goldens unchanged. The `registry`, `layer` and push fuzzers at 10,000 iterations. VM check: a `vm/m4` run green (`vm.yml`). In `zig build check`: `demo-m6c`'s simulation tests green and unchanged.
3. **VM, CI and docs.** `zig build demo-m6d` with the five steps exactly, every assertion a unit-tested pure function, step 5 a byte search of everything zbx wrote; the CI job and `m6d` in `vm.yml`'s picker; the agent test (JSON only, the library path with a token from a caller); `docs/demos/m6d.md` with the by-hand steps, the owner's setup above, the cuts and the failure modes (no credentials, a key file, impersonation not granted, the repository denied, a fork's PR). Include a by-hand check on a GCE instance for the metadata server, recorded as not run in CI.

The slices run one after another, in order. **Mechanical parts (Haiku):** the `vm.yml` picker entry and CI job boilerplate, threading `pull.Request.google` through call sites once its type exists, the exports in `src/zigbox.zig`, the error pages written from the goldens, the README and site status (supervisor).

## Supervisor defaults

The code range, no plain access-token source, workforce pools refused, plain-HTTP URL sources refused and the metadata server asked only after an anonymous refusal are supervisor defaults (2026-11-16, recorded in the decision file). The brief has no open questions; the owner may revisit the plain access-token source and workforce pools.

## Done means

- All gates pass (`zig build check`), and every fuzzer you touched or added runs at 10,000 iterations.
- `demo-m6d` is green in CI against the real Artifact Registry repositories, with every earlier demo still green. Until then M6d is "built, not demonstrated".
- Your report lists what you ran and its output, what you did not run and why, which REVIEW.md items you touched, every deviation from this brief, and anything in the spec, this brief or `DIAGNOSTICS.md` that seemed wrong.
