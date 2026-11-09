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
  disabled, unreadable, refused, no answer, malformed, expired) and, for a refusal, the AWS error
  code name. No code is registered in this slice; slice 2 maps the trace to its diagnostics.
- **Partial environment credentials** (a key id without a secret, or the reverse) are recorded as
  `incomplete` and the next source is tried. The AWS SDKs stop with an error here; zbx keeps going
  because a half-set environment is more often a leftover than an intent. The trace says so.
- **The STS region is the registry's region**, taken from the ECR host, so a pull never needs
  `AWS_REGION`. STS is called unsigned, on `sts.<region>.amazonaws.com`, with a form body.
- **The metadata service is version 2 only**: a PUT for a token (ttl 60 s), then GETs with it;
  never version 1, and never through a proxy (`ProxyUse.never`). A 1 s idle and 3 s total limit.
  `AWS_EC2_METADATA_DISABLED=true` turns it off.
- **Signing** double-encodes the path once (non-S3), decodes and re-encodes the query once, always
  signs `x-amz-date` and, with a session token, `x-amz-security-token`. It refuses `.`/`..` and
  empty path segments instead of normalising them. Checked against the published AWS test vectors
  (the iam ListUsers example, get-vanilla, get-vanilla-query-order-key-case, post-x-www-form-urlencoded).
- **`Request.authorization`** carries the signed value as its own field, because `extra_headers`
  may not hold `Authorization`; headers marked `secret` are never logged, only counted.
- **The simulated ECR API checks signatures with the same signer.** That is fair because the
  signer has its own known-answer tests; the sim is there to prove the client sends what it signs.
- **Redaction** also covers `Signature=` values, `<Element>text</Element>` with a secret name (the
  token service's XML) and, through the existing rules, `X-Amz-Security-Token` and the AWS
  `Authorization` value. `redact` and its fuzzer plant all of these.
- **Never printed**: AWS error message text and bodies. Only the error code name, and only when it
  is a short alphanumeric name.

## Cut from this slice

- The ECR `GetAuthorizationToken` call itself, the ECR v2 sim and the missing-repository fault
  (slice 2).
- The S3 host exists in the sim only to prove that credentials are never sent to it.

## Handoff

- The next slice starts from `credentials.resolve(host, region, workspace, credentials, trace)`
  and `parse.parse_ecr_token`; `sigv4.sign` takes `Key` from `Credentials.key()`.
- `Workspace.wipe()` runs on every exit of `resolve`; keep the pattern for anything that holds a
  token (the web identity token, the response buffer, the form body).
- `AwsSim` counters (`imds_v1_served`, `leaked`, `s3_calls`) are the assertions to keep in any
  slice 2 test.
- `zig build test` takes over two minutes here: run it in the background.
