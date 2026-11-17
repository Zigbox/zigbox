# M6d demo: Artifact Registry and gcr.io through workload identity federation

**Status: built, not demonstrated.** `demo-m6d` has never run against Google. The owner has not
yet set up the Google project below, so every run so far (CI and `vm/m6d-*`) printed the
`NOT RUN` line and ran nothing. M6d stays "built, not demonstrated" until the `demo-m6d` job is
green against the real repositories.

The brief is [docs/briefs/M6d-gar.md](../briefs/M6d-gar.md). The harness is
`src/testing/vm/main_m6d.zig`, its checks are `checks_m6d.zig` (unit tests in
`checks_m6d_tests.zig`), and its guest helper is `src/testing/vm/m6d_fixture/`.

## What the demo shows

zbx pulls from Google's registries with a GitHub Actions OIDC token, which Google's STS exchanges
under workload identity federation (and IAM Credentials then exchanges for a service account's
token, when one is set). No key file exists anywhere. The guest is the Ubuntu 24.04 VM; the
user `demo` runs zbx.

1. **No credentials.** `zbx pull <gar>/zbx-demo/hello:latest` with no
   `GOOGLE_APPLICATION_CREDENTIALS`, and off GCE, is refused with E0560 naming the registry host.
   The guest is on a GitHub runner, whose Azure metadata service has no `Metadata-Flavor: Google`
   header, so zbx does not mistake it for GCE.
2. **Workload identity.** With `GOOGLE_APPLICATION_CREDENTIALS` naming an `external_account` file
   whose `credential_source.file` holds the OIDC token:
   - the pull of `<gar>/zbx-demo/hello:latest` succeeds, and `--output json` reports the same
     digest;
   - `zbx run --name m6d-hello` of it prints `hello`;
   - `zbx.lock` holds the reference and the digest.
   Then `zbx bundle --no-redact m6d-hello` and `zbx logs m6d-hello` write the run's records
   for step 5.
3. **gcr.io.** `zbx pull <gcr>/hello:latest` succeeds through the same file.
4. **Denied.** `zbx pull <gar>/zbx-denied/hello:latest` is refused with E0568, which names the
   repository `<project>/zbx-denied/hello` and the permission
   `artifactregistry.repositories.downloadArtifacts`.
5. **No token anywhere.** A byte search of every file under `/home/demo`, `/run/user/1000`,
   `/tmp` and `/var/tmp` (zbx's store, records, lock, bundle, saved stdout and stderr, and the
   journal written to `/var/tmp`) finds none of the OIDC tokens the harness served, and no
   Google access token or registry Basic value by its shape (`ya29.`, base64 of
   `oauth2accesstoken:`). The zbx binary, the helper and the secrets directory are excluded.

Two checks run before step 5:

- **Shapes.** The helper resolves a token through the same file, as zbx does, and checks that it
  starts with `ya29.`, the shape step 5 searches for. With impersonation it checks both the
  federated token and the service account's. This makes step 5's search for tokens nobody can know
  exactly (each zbx run exchanges its own) a checked claim.
- **Agent.** `helper agent <gar>/zbx-demo/hello:latest` is the library path. It resolves the token
  itself, as an agent would, and passes it to `pull.pull` through `pull.Request.google`. It prints
  one JSON document, which must match the CLI's `--output json` (same reference and digest).

## How the token gets into the VM

`ACTIONS_ID_TOKEN_REQUEST_TOKEN` and the OIDC token stay out of every command line and every log:

- The harness (the host side, in Zig) asks the runner for the token with `std.http`. The request
  token goes in the `Authorization` header, and the audience is
  `https://iam.googleapis.com/<provider>` (see the decision file below).
- The harness serves the token once, on the harness's HTTP server (`/m6d/oidc`).
- In the guest, `curl -o` writes it into `/home/demo/m6d-secrets/oidc-N`. The directory is 0700
  and owned by `demo`, and the file is 0600 (under `umask 077`). The file `oidc` is then replaced
  by an atomic rename.
- The route is blanked and the harness's copy zeroed as soon as the guest has it.
- A token is good for about 5 minutes, so the harness fetches a new one before a step when the
  last is more than 3 minutes old.

The guest console is copied into the job log, so zbx's output never goes to it directly. A
wrapper saves stdout and stderr to `/home/demo/m6d-out/<step>.out` and `.err`. The helper's
`mask` then prints them with every served OIDC token, and every token-shaped run, replaced by
`[masked]`.

## The owner's setup

Nothing here is a secret. zbx never asks for or handles a key.

1. A Google Cloud project with the Artifact Registry API and the IAM Credentials API enabled.
2. In one region, two Docker repositories:
   - `zbx-demo`, holding `hello:latest`;
   - `zbx-denied`, holding the same image.

   Plus a `gcr.io` repository (location `us`, format Docker) holding the same image, so
   `gcr.io/<project>/hello:latest` resolves.

   The image is a two-line Dockerfile, pushed as an index for amd64 and arm64 (the demo pulls
   amd64):
   ```
   FROM busybox
   CMD ["echo", "hello"]
   ```
   `docker buildx build --platform linux/amd64,linux/arm64 -t <region>-docker.pkg.dev/<project>/zbx-demo/hello:latest --push .`,
   then the same for `zbx-denied/hello:latest` and `gcr.io/<project>/hello:latest`. The image in
   `zbx-denied` matters: without it, E0568 would be about a missing image, not about a denial.
3. A workload identity pool with an OIDC provider:
   - issuer `https://token.actions.githubusercontent.com`;
   - the default allowed audience (the provider's own `https://iam.googleapis.com/...` name);
   - attribute mapping `google.subject=assertion.sub`, `attribute.repository=assertion.repository`
     and `attribute.ref=assertion.ref`;
   - an attribute condition that admits only this repository, on `main`, pull requests and
     `vm/*` branches:
     ```
     assertion.repository == 'zigbox/zigbox' &&
       (assertion.ref == 'refs/heads/main' || assertion.ref.startsWith('refs/pull/') ||
        assertion.ref.startsWith('refs/heads/vm/'))
     ```
4. One of two ways to grant access. Prefer the first: it is the common setup, and it exercises
   one more step (IAM Credentials).
   - **Impersonation.** A service account `zbx-pull` with `roles/artifactregistry.reader` on
     `zbx-demo` and on the `gcr.io` repository only, and `roles/iam.workloadIdentityUser` for
     the principal set
     `principalSet://iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<pool>/attribute.repository/zigbox/zigbox`.
   - **Direct.** `roles/artifactregistry.reader` granted to that principal set itself, on the
     same two repositories.

   Neither way grants anything on `zbx-denied`.
5. No service-account keys anywhere. The organisation policy
   `iam.disableServiceAccountKeyCreation` is recommended.
6. Repository variables (Settings, Secrets and variables, Actions, Variables). They are not
   secrets, because they are not secret:

   | Variable | Value |
   |---|---|
   | `ZBX_GAR_PROVIDER` | `projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>` |
   | `ZBX_GAR_SERVICE_ACCOUNT` | `zbx-pull@<project>.iam.gserviceaccount.com`, or unset for direct access |
   | `ZBX_GAR_REGISTRY` | `<region>-docker.pkg.dev/<project>` |
   | `ZBX_GCR_REGISTRY` | `gcr.io/<project>` |

   The harness checks their shape (`checks_m6d.check_config`): the provider is a full resource
   name with a numeric project, and no value is longer than 200 bytes. A malformed value is a
   `NOT RUN` line naming the problem, not a failure.

## Running it

- **CI.** The `demo-m6d` job in `ci.yml` runs when `.github/ci-changes.sh` selects it: the
  harness files, `.github/m6d-setup.sh`, and, through `want_from m4`, the registry, pull, Google
  and cloud code.
- **Scratch branch.** `git push origin HEAD:vm/m6d-<slug>` runs it in `vm.yml`. `vm/all-*` does
  not include it, because without the setup it would only print `NOT RUN`.
- **Both workflows give the job `id-token: write`.** `.github/m6d-setup.sh` decides first whether
  it runs. Without a variable, without an OIDC token, or on a fork's pull request, it prints one
  line, adds that line to the job summary, and the job passes:
  ```
  demo-m6d: NOT RUN: the repository variable ZBX_GAR_PROVIDER is not set (setup: docs/demos/m6d.md)
  ```
  A run that printed this is not a passed demo.
- **By hand** (a developer machine with KVM; this needs a GitHub OIDC token, so only from inside
  an Actions job): set the four variables and the runner's `ACTIONS_ID_TOKEN_REQUEST_URL` and
  `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, then run `zig build demo-m6d -Daccel=kvm`. The harness itself
  prints the same `NOT RUN` line and exits 3 when any of them is missing.

The demo ends with `demo-m6d: PASSED` or `demo-m6d: FAILED at STEP n: <reason>`.

## Failure modes

| What is wrong | What zbx says | Where it is checked |
|---|---|---|
| No credentials (no `GOOGLE_APPLICATION_CREDENTIALS`, not on GCE) | E0560: there are no Google credentials to pull from this registry | step 1, live |
| A service-account key file in `GOOGLE_APPLICATION_CREDENTIALS` | E0562: service account key files are not supported; zbx never reads the key | simulation and golden (`src/google/`), not live: the setup has no key |
| Impersonation not granted (`roles/iam.workloadIdentityUser` missing) | E0566: Google refused to impersonate the service account | simulation and golden; live only if the owner breaks the binding by hand |
| The provider refuses the token (wrong audience, attribute condition) | E0565: Google refused the workload identity token exchange | simulation and golden; a wrong setup shows it live |
| The repository is denied | E0568, naming the repository and `artifactregistry.repositories.downloadArtifacts` | step 4, live |
| A fork's pull request | no OIDC token: `NOT RUN: a fork's pull request gets no OIDC token`, job passes | `.github/m6d-setup.sh` |

## By hand on GCE: the metadata server (not run in CI)

CI runs on GitHub's runners, not on GCE, so zbx's second source (the metadata server, asked
only after an anonymous refusal) is covered by simulation only. To check it by hand:

1. Create an `e2-micro` instance (Ubuntu 24.04) whose service account has
   `roles/artifactregistry.reader` on `zbx-demo`, with the `cloud-platform` scope.
2. Copy a release `zbx` onto it. Enable unprivileged user namespaces if AppArmor restricts them
   (`sysctl kernel.apparmor_restrict_unprivileged_userns=0`).
3. As an ordinary user, with no `GOOGLE_APPLICATION_CREDENTIALS`:
   `zbx pull <region>-docker.pkg.dev/<project>/zbx-demo/hello:latest` must succeed, and
   `zbx run` of the same reference must print `hello`.
4. `zbx pull <region>-docker.pkg.dev/<project>/zbx-denied/hello:latest` must be refused with
   E0568.
5. `grep -rF ya29. ~/.local` must find nothing.

**Not run.** Nobody has run this; there is no GCE instance. Record the date, the zbx commit and
the output here when someone does.

## Scope cuts

- **Step 5 does not search for the exact registry Bearer token or STS token.** Each zbx run
  exchanges its own, and nothing outside zbx can learn them without logging them. Step 5 searches
  for the OIDC tokens exactly and for the shapes of the others: `ya29.` (checked live by the
  shape check) and the base64 of `oauth2accesstoken:`. The registry's Bearer token has no
  documented shape. It is covered by slice 2's simulation (`src/google/pull_tests.zig`), which
  searches the store and the records for the token it made.
- **The harness's `std.http` client keeps its own heap buffers,** which the harness cannot zero.
  The token buffers the harness owns are zeroed, and the process ends with the job.
- **`credential_source.url`** (the token from a URL rather than a file) is covered by simulation
  only, as the brief says.
- **arm64** is not pulled: the guest is amd64. The index's arm64 entry is only resolved past.
