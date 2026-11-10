# M6c slice 1: SigV4 and the credential sources

*Decided 2026-11-09, by the slice 1 implementer, for the supervisor to confirm.*

Slice 1 builds the signer, the credential sources and their simulated AWS, with no ECR call in
the client (that is slice 2). Where the brief left a choice, this is what the code does.

## Decisions

- **Web identity is terminal.** Once `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE` are both
  set, a failure of that source ends the resolve; it never falls through to the metadata
  service. Falling through would hand a pod the node's role when its own role failed.
- **The resolver reports a `Trace`, not a diagnostic.** `aws_credentials_resolve` returns
  `error.NoCredentials` and fills a `Trace` of one state per source (not configured, incomplete,
  disabled, unreadable, refused, no answer, malformed, expired, and for the metadata service
  `v1_only`, a 4xx on the token call, and `no_role`, a 404 on the role list) and, for a refusal,
  the AWS error code name. No code is registered in this slice; slice 2 maps the trace to its diagnostics.
- **Partial or malformed environment credentials are terminal** (review of PR #84). A key id
  without a secret (or the reverse, or a token alone), a value that is not a key, and an
  `AWS_SESSION_TOKEN` over its bound each end the resolve with the trace state `incomplete` or
  `malformed`; web identity and the metadata service are not tried. The rule is the same for every
  source: once the user has said which identity, zbx uses it or stops. The SDKs stop here too.
- **The STS region is the registry's region**, taken from the ECR host, so a pull never needs
  `AWS_REGION`. STS is called unsigned, on `sts.<region>.amazonaws.com`, with a form body.
- **Library shape** (review of PR #84). `zigbox.aws_credentials_resolve(host, env, region, now_s,
  workspace, credentials, trace)`: `env` is an `AwsEnv`, a view of name and value pairs the caller
  fills (the CLI with `Env.from_host`, which reads each value one byte past its bound so an
  over-long one is refused, not cut); the resolver never reads the process environment. The region
  and the clock (`now_s`) are the caller's. The brief's last parameter `diag` is the `Trace`.
  `src/aws_library_tests.zig` is the second caller.
- **Secret requests.** `net.Request.secret` marks a request whose body or answer holds a
  secret that no header carries (the STS call, all three metadata calls); the real network zeroes
  its buffers for it like for a bearer or secret header.
- **Other partitions** (`us-gov-`, `us-iso`, `eu-iso`, `cn-` regions) are `unsupported`, like
  `fips` and `.cn` hosts; slice 2 gives them the coded line.
- **The metadata service is version 2 only**: a PUT for a token (ttl 60 s), then GETs with it;
  never version 1, and never through a proxy (`ProxyUse.never`). A 1 s idle and 3 s total limit.
  `AWS_EC2_METADATA_DISABLED=true` turns it off.
- **Signing** double-encodes the path once (non-S3), decodes and re-encodes the query once, always
  signs `x-amz-date` and, with a session token, `x-amz-security-token`. It refuses `.`/`..` and
  empty path segments instead of normalising them. Checked against the published AWS test vectors,
  copied into `src/testdata/aws_sigv4/` with their source in `SOURCE.md` (the iam ListUsers
  example, get-vanilla, get-vanilla-query-order-key-case, post-x-www-form-urlencoded,
  post-header-key-sort, get-header-value-trim).
- **`Request.authorization`** carries the signed value as its own field, because `extra_headers`
  may not hold `Authorization`; headers marked `secret` are never logged, only counted.
- **The simulated ECR API checks signatures with the same signer.** That is fair because the
  signer has its own known-answer tests; the sim is there to prove the client sends what it signs.
- **Redaction** also covers `Signature=` values, `<Element>text</Element>` with a secret name (the
  token service's XML) and, through the existing rules, `X-Amz-Security-Token` and the AWS
  `Authorization` value. `redact` and its fuzzer plant all of these.
- **Sim faults.** STS and the metadata service have an `unavailable` mode (503, the state
  `refused` with its status); the net simulator logs each request's timeouts and the metadata
  tests check them against `aws_imds_timeout_ms` and `aws_imds_total_timeout_ms`.
- **Never printed**: AWS error message text and bodies. Only the error code name, and only when it
  is a short alphanumeric name.

## Cut from this slice

- The ECR `GetAuthorizationToken` call itself, the ECR v2 sim and the missing-repository fault
  (slice 2).
- The S3 host exists in the sim only to prove that credentials are never sent to it.

## Handoff

- The next slice starts from `aws_credentials_resolve(host, env, region, now_s, workspace, credentials, trace)` (the CLI builds `env` with `Env.from_host`)
  and `parse.parse_ecr_token`; `sigv4.sign` takes `Key` from `Credentials.key()`.
- `Workspace.wipe()` runs on every exit of `resolve`; keep the pattern for anything that holds a
  token (the web identity token, the response buffer, the form body).
- `AwsSim` counters (`imds_v1_served`, `leaked`, `s3_calls`) are the assertions to keep in any
  slice 2 test.
- `zig build test` takes over two minutes here: run it in the background.
