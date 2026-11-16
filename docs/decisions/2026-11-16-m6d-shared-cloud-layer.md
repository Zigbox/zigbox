# The shared cloud credential layer (M6d slice 1)

Date: 2026-11-16. Status: decided by the M6d slice 1 implementer, for review.

## Decision

The parts AWS and Google share live in `src/cloud/`, and nothing else does:

- `cloud/env.zig`: `CredentialEnv(names)`, the caller's environment view with a fixed name list
  per provider. `AwsEnv` is `CredentialEnv` over the AWS names; `GoogleEnv` is over
  `GOOGLE_APPLICATION_CREDENTIALS`.
- `cloud/json.zig`: the bounded JSON field reader that was in `aws/parse.zig` (depth bound
  `cloud_json_depth_max`). It refuses escaped string values rather than decoding them; no field
  either provider reads needs one.
- `cloud/metadata.zig`: the link-local metadata request (fixed address, `ProxyUse.never`, a
  connect and a total timeout passed in by the provider, extra headers).

The Workspace and Trace types stay per provider (`aws/credentials.zig`, `google/credentials.zig`):
their fields differ, and a shared generic type would hide that. They follow one shape: a
caller-owned workspace that is wiped on every exit, and a trace that holds no secret.

The Google timeouts equal the AWS ones (1 s connect, 3 s total), for the same reason: a host
that is not on that cloud must not slow a pull down.

## Consequences

`aws_credentials_resolve` and its types keep their names, signatures and behaviour; the AWS tests
and `parse_aws` are unchanged. A third provider adds a name list and a metadata call, not a copy.
