# M6c: pulling from Amazon ECR

Status: slice 2 (the client). The demo's five steps run as a simulation in `src/aws/ecr_tests.zig`
(no credentials; web identity; static keys with the S3 redirect; `zbx-denied`; no secret in any
output, lock, store record or bundle). They are not yet run live against AWS.

## Cuts and known gaps

- No AWS profiles, SSO, `credential_process` or ECS task credentials. Export the keys of a profile
  first (`aws configure export-credentials --format env`).
- The macOS forward of the AWS environment is out of scope for this milestone.
- `zbx build` of a `FROM` on an ECR host does not resolve credentials yet: it raises E0527.
- Other private registries are still refused (E0507); only ECR is supported.
