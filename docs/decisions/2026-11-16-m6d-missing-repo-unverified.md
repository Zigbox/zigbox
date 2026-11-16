# M6d: the missing-repository answer is not yet checked; the simulation carries every candidate

*Decided 2026-11-16, by the M6d slice 1 fix session, for the supervisor and the owner.*

## What was not done

The brief (`docs/briefs/M6d-gar.md`, "Denials arrive at the realm") has slice 1 check, by hand
and against the owner's project, how Artifact Registry answers a caller **with valid
credentials** that asks for a repository that does not exist. Slice 1 did not do it and did not
record it, and the fix session cannot: this container has no Google credentials (`gcloud auth
list` shows none). It stays open, for the owner.

What is known (checked 2026-11-16, anonymously): the realm answers `403 DENIED` for a private
repository and for a missing one alike, with a message naming
`artifactregistry.repositories.downloadArtifacts`, and `401 UNAUTHORIZED` for a bad token.

## The check to run

With an account that can read some repository in the project (`$P` the project, `$R` a region
such as `us`, `$T` an access token from `gcloud auth print-access-token`):

```
B=$(printf 'oauth2accesstoken:%s' "$T" | base64 -w0)
# 1. A token for a repository that does not exist.
curl -si -H "Authorization: Basic $B" \
  "https://$R-docker.pkg.dev/v2/token?scope=repository:$P/no-such-repo/x:pull&service=$R-docker.pkg.dev"
# 2. If 1 granted a token ($RT), the manifest.
curl -si -H "Authorization: Bearer $RT" \
  -H 'Accept: application/vnd.oci.image.index.v1+json' \
  "https://$R-docker.pkg.dev/v2/$P/no-such-repo/x/manifests/latest"
# 3. The same two for a repository that exists but the account may not read.
```

Record the status and the `errors[].code` of each answer (never the token), in a new decision
file that supersedes this one.

## What the simulation does meanwhile

`google_sim.RegistryFault` carries each candidate, so slice 2 can map all of them and test each:

- `missing_repo`: `403 DENIED` at the realm, as for a denied caller (the anonymous shape).
- `denied_at_manifest`: the realm grants a token; the manifest answers `403 DENIED`.
- `missing_at_manifest`: the realm grants a token; the manifest answers `404 NAME_UNKNOWN`.

When the check is done, slice 2 (or whoever records it) keeps the shape that was seen as the
missing-repository fault and keeps the others only if they map to a distinct, correct line.

## Other decisions this fix session made

- **A set `GOOGLE_APPLICATION_CREDENTIALS` stays terminal under any mask.** When the caller's
  mask leaves workload identity out but the variable is set, `resolve` neither reads the file nor
  asks the metadata server: `trace.workload_identity` is the new `State.not_asked`, and the
  result is `NoCredentials`. The brief's rule that a set variable never falls through holds
  whatever the caller asks for. Slice 2 maps `not_asked` to a coded line (the variable is set
  but the caller did not ask for it).
- **An absolute `expireTime` is held to the lifetime bound.** IAM Credentials states an absolute
  time; one more than `google_token_lifetime_max_s` past now is `malformed`, as an `expires_in`
  over the bound already was.
- **The mask's fields are `workload_identity` and `metadata`.** The brief writes `.wif`; the code
  spells it out, as the trace does. The brief is not edited.

## For slice 2

- The realm's `Basic` value (base64 of `oauth2accesstoken:` and a token at its bound) fits
  `net_header_value_bytes_max`; a comptime assert in `constants.zig` holds it.
- A refused file over a bound should say which bound; an escaped JSON value, which
  `cloud/json.zig` refuses rather than decodes, should read as unsupported, not malformed.
- Map `not_asked` and every `RegistryFault` above.
