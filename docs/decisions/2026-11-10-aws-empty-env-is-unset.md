# An empty AWS environment variable counts as unset

*Decided 2026-11-10, by the supervisor (ruling on a re-review finding of PR #84).*

The AWS credential resolver (`aws/credentials.zig`) treats an environment variable whose value is
empty as not set, for every variable it reads: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`AWS_SESSION_TOKEN`, `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_ROLE_SESSION_NAME` and
`AWS_EC2_METADATA_DISABLED`. The rule lives in `Env.get`, so it holds for the CLI's view and for a
library caller's view alike.

## Why

The AWS SDKs (botocore's `EnvProvider` among them) read an empty value as unset. A chart or a
`Dockerfile` that sets `AWS_SESSION_TOKEN=""`, or a CI step whose secret expands to `""`, must not
change which identity is used. Counting the empty value as "set" made `AWS_SESSION_TOKEN=""` alone
terminal (`environment: incomplete`) and blocked web identity in a pod where `aws` and the SDKs
work.

## What stays

Partial *non-empty* credentials are still terminal, as decided in
`2026-11-09-m6c-slice1-credentials.md`: a key id without a secret (or the reverse), a malformed
key, or a token over its bound is the answer, never a reason to fall through to another identity.
An empty value beside a non-empty partner is half a pair, so it is terminal too.

Related, same change: a value longer than its bound is read whole and refused as `malformed` (it
was dropped when it was more than one byte over).
