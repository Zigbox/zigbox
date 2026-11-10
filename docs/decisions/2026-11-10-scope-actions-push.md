# Cut: no `Scope { repository, actions: { pull, push } }` type for a push

*Decided 2026-11-10, by the slice 13 follow-up (the review of #86 asked for it recorded); the supervisor can overrule.*

The M8 brief (Credentials) says M6c asked for scope and action in the types, "and a pull-only token is never offered for a push". No `Scope` type exists, from M6c or from slice 13. It is **cut**: not built here.

**Why.** A type needs something to carry. There are two kinds of push token, and neither has a scope field to type:

- A Bearer token from a realm is asked for with a scope the push builds itself (`auth.push_token_url`: `repository:<name>:pull,push`, plus `repository:<from>:pull` for a mount). The challenge's own scope is ignored, because it may be the pull scope of the refused request. The token is held in the push's own workspace slot (`Workspace.token`) and is never shared with the pull client, whose tokens live in a different module and type. A realm that grants less answers `insufficient_scope` and the push says E0553 with the scope.
- An ECR authorization token has no scope: it is the base64 of `AWS:<password>`, and what it may do is decided by the IAM identity behind it. No type can tell a pull-only grant from a push one. ECR says so at the first write, by `403 DENIED`, which the push maps to E0553 (`ecr_no_push`) naming the five IAM actions.

**Where the guarantee holds today.**

1. By construction, for Bearer: the push never asks a realm for any scope but pull and push, and never reuses a token from pull.
2. By type, for the credential kind: `upload.Options.credential` is the tagged union `Credential { none, basic, ecr }`, so a push carries at most one, and the ECR token is its own variant, filled only by `push/ecr.zig` for a push. A pull client's ECR token (`registry/ecr_login.zig`) cannot be passed without being named as `.ecr`.
3. At run time, for ECR: the registry's refusal, E0553.

**What would change this.** A second registry that returns the granted scope with the token (as a Bearer realm does) and a caller that holds tokens across operations. Zigcube holding one token for pull and push would be that caller; the type then belongs in the library surface, with the `Credential` union carrying it.
