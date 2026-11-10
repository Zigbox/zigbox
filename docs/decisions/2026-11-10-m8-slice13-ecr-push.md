# M8 slice 13: how ECR push is wired (handoff note)

*Decided 2026-11-10, by the slice 13 implementer, for the supervisor's review.*

- **The token is fetched by the caller, before the push.** `upload.push` takes a `net.Net` and no
  host or clock, so it cannot sign an AWS request. `push/ecr.zig` (`authorize`) makes the signed
  `GetAuthorizationToken` call with the credentials the caller gives and holds the token in its own
  `Workspace`; the caller passes it as `Options.ecr_token`. The upload copies it into its workspace
  as the Basic credential and zeroes that copy when it ends; the caller wipes the other.
- **Origin only.** The token rides the same `basic_for` rule as any Basic: the registry's origin,
  never an upload `Location` on another origin (S3). The ECR API call is the only other request
  that carries AWS material, and it is signed, not Basic.
- **A token is sent once.** A 401 to the ECR token is E0553 (it lasts 12 hours); there is no
  second exchange. A token handed in for a host that is not private ECR is ignored.
- **An explicit `--username` wins.** The user chose to send that password, so AWS is not asked.
- **No tagged `Credentials` union.** `Options.ecr_token` sits beside `credentials`; the push
  asserts nothing about both being set because only an ECR destination ever reads the token.
- **Codes.** E0552 (no credentials) and E0553 (refused / no push permission) gain ECR causes; a
  `NAME_UNKNOWN` on an ECR host is E0556 with the `aws ecr create-repository` fix, at the blob
  step as well as the manifest step (the brief assigns "ECR: repository does not exist" to E0556,
  so a missing repository is E0556 and not E0555). No new code is registered.
- **Permission is detected from the 403 `DENIED`.** An ECR token carries no scope, so the pull's
  scope check has no push counterpart; the fix names the five IAM actions.
- **Not done:** a run against a real repository (rides with M6c slice 3), a library-level
  `aws_credentials_resolve` + `push.ecr.authorize` demo in Zigcube.
