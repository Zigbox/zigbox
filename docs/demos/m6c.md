# M6c: pulling from Amazon ECR

Status: slice 2 (the client). The demo's five steps run as a simulation in `src/aws/ecr_tests.zig`:
no credentials (E0527); a web identity and static keys, each through `zbx pull` and `zbx run`
(the container is started, `zbx.lock` holds the reference and the manifest's digest, the registry
saw the token, S3 saw none); `zbx-denied` (E0531 names the repository and both permissions); and
no secret in the output, `--output json`, the lock, the store disk, a `zbx bundle` or the pull's
memory after the command. The simulation does not print `hello`, since no container really runs;
that is slice 3's VM step. None of it has run live against AWS yet.

## Cuts and known gaps

- No AWS profiles, SSO, `credential_process` or ECS task credentials. Export the keys of a profile
  first (`aws configure export-credentials --format env`).
- The macOS forward of the AWS environment is out of scope for this milestone.
- `zbx build` of a `FROM` on an ECR host does not resolve credentials yet: it raises E0527, and its fix line says to `zbx pull` the base image first.
- Other private registries are still refused (E0507); only ECR is supported.
