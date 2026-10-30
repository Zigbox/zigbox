# Brief: M6c · Private pull from Amazon ECR

Read these first:
- `AGENTS.md`, `REVIEW.md`, `docs/STYLE.md` and `DIAGNOSTICS.md`.
- The M6c section of the live design doc, and its "Non-goals" (push stays out until after M8). **Spec status:** the snapshot `docs/SPEC.md` still lists private registries as a non-goal ("pull-only from public registries until after M8"). The owner decided on 2026-10-30 to bring authenticated ECR pull forward as M6c (`docs/DECISIONS.md`, "M6c"). If the live doc has no M6c section, or it disagrees with this brief, stop and report; do not pick one.
- `docs/DECISIONS.md`: the M6c entry, the M4 entries on pull, and the M6b entry on pull in the library.
- `src/registry/` (the client, `auth.zig`, `net.zig`, `net_sim.zig`, `proxy.zig`), `src/pull.zig` (the library entry the CLI and Zigcube's agent share), `src/redact.zig`, and `docs/demos/m4.md`.

Do not start M7. No push, no other private registry, no Mac work (below). `demo-m0` to `demo-m6b`, the top-20 check, and the Mac demos must keep passing.

## Goal and demo (proposed for the live doc)

A host pulls and runs an image from a private Amazon ECR repository with the AWS credentials it already has, and no secret ever leaves the request it was made for.

1. With no AWS credentials, `zbx pull <account>.dkr.ecr.<region>.amazonaws.com/zbx-demo:hello` is refused with one line naming the sources tried and the fix.
2. With a web identity (`AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE`, as GitHub Actions and EKS provide), the same pull succeeds; `zbx run` of it prints `hello`; `zbx.lock` holds the digest.
3. With static keys in the environment (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`), the same pull succeeds.
4. Pulling `zbx-denied`, a repository the role may not read, is refused, naming the repository and the IAM permission missing.
5. No secret is anywhere: the secret key, the session token, the web identity token and the ECR password are absent from every byte zbx wrote (output, `--output json`, `zbx.lock`, the store's image record, `zbx bundle`, the logs).

Acceptance criteria:
- Credentials go only where they are for: AWS keys sign only requests to that region's ECR API and STS endpoints; the ECR password goes only to that registry's origin, never to a redirect target on another host (ECR sends blobs to S3 by redirect), and never to a mirror.
- No secret is written to disk, put in a diagnostic, an argument list, a record or a bundle, and each buffer that held one is zeroed after use.
- Every failure is one coded line: no credentials, credentials refused, clock skew, a missing IAM permission, a missing repository, an unreadable token file, an unsupported AWS partition.
- `zbx pull` of a public image, and its output and JSON, do not change (the goldens prove it). `zbx.lock` and the store formats do not change.
- The library takes credentials from its caller, so Zigcube's agent can pull from ECR (its `ensure_image`).

## Fixed decisions

### Native, no helper programs

- **zbx signs AWS requests itself (SigV4, HMAC-SHA256 from `std.crypto`).** `docker-credential-ecr-login` and the `aws` CLI are external programs, which STYLE.md does not allow. Don't shell out, and don't read `~/.docker/config.json`.
- **Test SigV4 against published known answers**: the examples in AWS's Signature Version 4 documentation (`AKIDEXAMPLE`) and a few cases from the SigV4 test suite (`get-vanilla`, `get-vanilla-query-order-key-case`, `post-x-www-form-urlencoded`, `post-header-key-sort`), copied into `src/testdata/` with their source named in a comment. A signer tested only against itself is not tested.

### Where credentials come from, in this order, the first that yields wins

1. **The environment**: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, with `AWS_SESSION_TOKEN` if set.
2. **Web identity**: `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE` (and `AWS_ROLE_SESSION_NAME`, defaulting to `zbx`): read the token file and call STS `AssumeRoleWithWebIdentity` at the regional endpoint `sts.<region>.amazonaws.com`. The call is unsigned. Ask for JSON (`Accept: application/json`) if STS answers it; otherwise extract the four elements needed (`AccessKeyId`, `SecretAccessKey`, `SessionToken`, `Expiration`) with a bounded extractor. Do not write a general XML parser.
3. **EC2 instance metadata, IMDSv2 only**: `PUT /latest/api/token` (TTL 60 s), then the role name and its credentials from `/latest/meta-data/iam/security-credentials/`. Plain HTTP to `169.254.169.254` only, never through the proxy whatever `HTTPS_PROXY` or `NO_PROXY` say, with a short connect timeout (a constant, about 1 s) so a host off EC2 is not slowed. Never IMDSv1.

Not in M6c (record in `docs/demos/m6c.md`): `~/.aws/credentials` and `~/.aws/config` profiles, SSO, `credential_process` (an external program), ECS container credentials. A developer can run `export $(aws configure export-credentials --format env)` first.

Credentials are looked up only for an ECR reference, and resolved again for every pull. They are never cached, in memory beyond the pull or on disk. Instance credentials rotate, and Zigcube's agent runs for weeks.

### ECR

- **Recognised by host**: `<12 digits>.dkr.ecr.<region>.amazonaws.com`. The region comes from the host. Refuse `.amazonaws.com.cn`, `dkr.ecr-fips.` and other partitions with a coded line saying they are not supported yet, rather than signing for the wrong endpoint. `public.ecr.aws` is a public registry and goes through the anonymous path unchanged.
- **Token**: `POST https://api.ecr.<region>.amazonaws.com/`, `X-Amz-Target: AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken`, `Content-Type: application/x-amz-json-1.1`, body `{}`, signed for service `ecr`. The `authorizationToken` it returns is already base64 of `AWS:<password>`. Send it as `Authorization: Basic <token>` to the registry origin and to nothing else. It is valid for 12 hours, and one pull never needs a second one.
- **The client**: for an ECR reference, send Basic from the first request, and accept a `Basic` challenge where today only `Bearer` is read. A second `401` is a refusal, as now. For any other host, a Basic-only challenge stays today's refusal; its message now says ECR is supported and other private registries are not yet.
- **Redirects**: ECR redirects blob downloads to S3 presigned URLs, and S3 rejects a request that carries an `Authorization` header. The existing rule (the token goes only to the origin the client started with) covers Basic too: test it, with a simulated S3 host that fails any request carrying `Authorization`.
- **Mirrors**: `ZBX_REGISTRY_MIRRORS` applies to docker.io only. Test that an ECR reference never reaches a mirror.
- **Design the credential layer for push.** Push comes after M8 on the same auth path, so keep the scope and action a request is for explicit in the types. Implement pull only.

### The network interface grows, and still does one request

`net.zig`'s vtable gains a method (`GET`, `POST`, `PUT`), extra request headers and a bounded request body, for the STS, ECR and IMDS calls. It still makes one request and returns one response, with no retries and no redirects, and the client stays the only place that follows redirects. Authorization values are passed in and sent, and never stored, returned or put in an error, as the bearer token is today. `net_sim.zig` gains ECR, STS, IMDS and S3 hosts with faults: expired token, signature refused, clock skew, access denied, missing repository, IMDS absent or slow, an IMDS that answers v1 only, and a 5xx.

### Time

SigV4 needs the time. Take it from the host interface (`host_sim` has a clock), never from a direct call. A refusal for a request signed too far from AWS's clock (`SignatureDoesNotMatch` mentioning "Signature expired", or `InvalidSignatureException` with a time) is its own coded line, naming the host clock as the likely cause.

### Secrets

- The AWS secret key, the session token, the web identity token and the ECR password are secrets. The access key id and the account id are not, but don't print the key id either.
- Each secret lives only in caller-provided buffers, which `std.crypto.secureZero` clears when the pull ends, on every path.
- **Extend `redact.zig` and its fuzzer** to cover `AKIA` and `ASIA` key ids, `Authorization: Basic` and `AWS4-HMAC-SHA256` header values, `X-Amz-Security-Token`, and STS and ECR response bodies. A diagnostic built from an AWS error response carries the error's code name (`AccessDeniedException`, `ExpiredTokenException`), never its message text or a body.
- HTTPS only for every credentialed request. The loopback-HTTP exception stays a test-registry affordance and never carries credentials. IMDS is the single plain-HTTP call, and it is fixed to its link-local address.

### In the library

- `pull.Request` gains an optional AWS credentials value. The library does not read the environment, the token file or IMDS on its own initiative. A separate library function, `aws_credentials_resolve(host, env, region, out, diag)`, does the three-source lookup over the host interface, with the environment passed in as a view. The CLI calls it before each ECR pull, and Zigcube's agent calls it the same way. Per-caller storage, no process-wide state, bounded memory, as in M6b.
- `zbx pull` and `zbx run <ecr-ref>` call it; nothing else changes for them.

### Not on the Mac yet

The macOS `zbx` forwards `pull` to the Linux guest, which has no AWS credentials. Do not forward credentials over the forward protocol in M6c. That needs a decision about secrets crossing into the VM. The guest's "no AWS credentials" line is the behaviour; note it as a known gap in `docs/demos/m6c.md`.

### Diagnostics

Registry and pull failures are `04xx`: take the next free codes in `src/diag/codes.zig`. Each has a cause, a fix, a golden and an error page. At least:
- No AWS credentials, naming the three sources tried, plus IMDS's state (no role attached, unreachable, or v1 only).
- Credentials refused (invalid, or expired).
- Clock skew.
- `ecr:GetAuthorizationToken` denied, naming the permission.
- Repository denied (`ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`) or missing, naming the repository.
- Web identity token file unreadable or empty, naming the variable.
- Unsupported AWS partition or endpoint.

### CI (the owner sets up the AWS side; the slice 3 implementer writes the workflow)

- One AWS account and region. Two ECR repositories: `zbx-demo`, holding a small `hello` image as an index for amd64 and arm64, and `zbx-denied`.
- An IAM role trusted for GitHub OIDC from `Zigbox/zigbox` only, for pull requests from the repository, `main` and `vm/*` branches. Its permissions: `ecr:GetAuthorizationToken` on `*`, and `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer` and `ecr:BatchCheckLayerAvailability` on `zbx-demo` only. No long-lived keys anywhere.
- Repository variables (not secrets, since they are not secret) `ZBX_ECR_ROLE_ARN` and `ZBX_ECR_REGISTRY`. The job needs `permissions: id-token: write`.
- The runner fetches its OIDC token (audience `sts.amazonaws.com`) with `curl` from `ACTIONS_ID_TOKEN_REQUEST_URL`, with no third-party action, and hands it into the VM as a file. Step 2 uses it directly. For step 3, the harness exchanges it for temporary keys with zbx's own STS code (a test helper in `src/testing/vm/`) and runs the pull with the environment only.
- A run with no OIDC token (a fork's pull request) does not run `demo-m6c` and says "not run" in the job summary. It is never reported as a pass.

## Slices (commit and stop for review after each; do not push to the working branch)

1. **SigV4 and the credential sources.** The signer with its known-answer tests; the ECR host parser; the three sources over the host interface, with `net.zig`'s method, headers and body; the IMDS proxy bypass; STS and IMDS response parsing; `aws_credentials_resolve` in the library; the new `net_sim` hosts and faults; secret buffers zeroed; a `parse_aws` fuzzer over the STS, IMDS and ECR responses and the host parser; `redact` extended. Unit and simulation tests only; no VM check.
2. **ECR in the client.** GetAuthorizationToken, Basic to the origin only, the S3 redirect test, the mirror bypass test, every diagnostic with goldens and error pages, the Basic-only refusal reworded for other hosts, `pull.Request` with credentials, and `zbx pull` and `zbx run` calling the resolver. An end-to-end simulation of the demo's five steps. The `registry` and `layer` fuzzers at 10,000 iterations. VM check: `demo-m4` unchanged and green.
3. **VM, CI and docs.** `zig build demo-m6c` with the five steps exactly, every assertion a unit-tested pure function, step 5 a byte search of everything zbx wrote; the CI job and `m6c` in `vm.yml`'s picker; the agent test (JSON only, the library path with credentials from a caller); `docs/demos/m6c.md` with the by-hand steps, the AWS setup above, the cuts and the failure modes (clock skew, expired keys, no role on the instance, the repository denied, a fork's PR). Include a by-hand check on an EC2 instance for IMDSv2, recorded as not run in CI.

The slices run one after another, in order. **Mechanical parts (Haiku):** the `vm.yml` picker entry and CI job boilerplate, the error pages written from the goldens, the README and site status (supervisor).

## Done means

- All gates pass (`zig build check`), and every fuzzer you touched or added runs at 10,000 iterations.
- `demo-m6c` is green in CI against the real ECR repositories, with `demo-m0` to `demo-m6b` still green. Until then M6c is "built, not demonstrated".
- Your report lists what you ran and its output, what you did not run and why, which REVIEW.md items you touched, every deviation from this brief, and anything in the spec, this brief or `DIAGNOSTICS.md` that seemed wrong.
