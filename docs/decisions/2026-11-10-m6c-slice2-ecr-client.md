# M6c slice 2: where the ECR pieces live

*Decided 2026-11-10, by the slice 2 implementer, for the supervisor's review.*

- **Credentials are resolved in the command line, the token call is in the library.** `zbx pull`
  and `zbx run` call `pull_aws.credentials_for`, which reads the environment, the web identity file
  and the instance metadata service, and only for a private ECR reference. `pull.Request.aws`
  carries the result to the library, whose `registry/ecr_login.zig` makes the signed
  `GetAuthorizationToken` call. A library caller that gives none gets E0527 (`none_given`). Nothing
  is cached: each pull resolves again, and `Storage.wipe` and `client.Workspace.wipe` zero every
  secret buffer on every path.
- **The ECR API host is `api.ecr.<region>.amazonaws.com`**; the signature's service name is `ecr`.
  `ecr_token.api_service` names the host label so the two are not confused.
- **The Basic token goes to the registry's origin only.** `request_following` attaches it only for
  a hop whose origin is the one the client started with, so the S3 redirect carries nothing. Such a
  request is marked `secret` so the network layer wipes its answer.
- **Codes E0527 to E0535** are taken (E0527 no credentials, E0528 refused, E0529 clock, E0530
  token call denied, E0531 repository denied, E0532 repository missing, E0533 web identity file,
  E0534 unsupported host or region, E0535 token rejected). E0536 to E0549 remain for slice 3.
- **E0507** (anonymous access refused) now says ECR is the one private registry zbx signs in to.
- **`errors_page_bytes_max` is 64 KiB (was 32 KiB).** The generated index page outgrew 32 KiB with
  nine more codes. It is a buffer of the `errors-site` tool, not a user-visible bound.
