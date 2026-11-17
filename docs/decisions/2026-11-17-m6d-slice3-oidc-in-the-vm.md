# M6d slice 3: how demo-m6d gets GitHub's OIDC token into the VM, and what step 5 searches for

*Decided 2026-11-17, by the slice (M6d slice 3). Details: [docs/demos/m6d.md](../demos/m6d.md).*

## The harness fetches the token, not a `curl` in the CI step

The brief has the CI step `curl` the token and hand it into the VM as a file. The harness
(`src/testing/vm/main_m6d.zig`) does it instead:

- It reads `ACTIONS_ID_TOKEN_REQUEST_URL` and `_TOKEN` from its environment.
- It asks with `std.http`, with the request token in the `Authorization` header.
- It serves the answer once to the guest, and the guest's `curl -o` writes it 0600 into a 0700
  directory.
- It then blanks the route and zeroes its buffers.

The reasons:

- **Expiry.** A GitHub OIDC token is good for about five minutes, and the demo takes longer
  (boot, provisioning, pulls). The harness fetches a new token before a step when the last one is
  more than three minutes old, at most `needles_max - shapes.len` times. A token fetched once
  before the VM boots would expire mid-demo.
- **Neither secret is on a command line or in a shell.** No `-H @file` dance and no `set -x`
  risk; the gate (`.github/actions/m6d-setup`) prints only names.

## The audience is `https://iam.googleapis.com/<provider>`

The brief writes `audience=//iam.googleapis.com/<provider>`. A provider's default allowed
audience, which the owner's checklist keeps, is the `https://` form. The `//` form is the STS
request's `audience` field, which zbx writes from the `external_account` file, not the OIDC
token's `aud`. The harness asks GitHub for the `https://` form.

## Step 5 searches for shapes, not the exact Bearer or STS tokens

Each zbx run exchanges its own tokens, and nothing outside zbx can learn them without logging
them. The brief's "test helper that runs zbx's own exchange" gets different tokens from those of
the pull it checks. So step 5 searches for:

- the OIDC tokens, exactly. zbx exchanged these, so they are the ones that would leak;
- the shapes `ya29.` (every Google access token) and the base64 of `oauth2accesstoken:` (the
  realm's Basic value).

A `shapes` check makes the first shape a checked claim: the helper resolves through the same
files and reports each token's class (`google_access`: starts with `ya29.`) and length, never a
byte of it, not even the prefix; its output is saved where step 5 searches (review, slice 3). The
registry's Bearer token has no documented shape, so its live coverage is zero: a cut, accepted by
the supervisor in the slice 3 review. It is left to slice 2's simulation, which knows the token
it issued.

## The console is masked in the guest

The harness copies the guest console into the job log. zbx's output is saved to files, and the
helper's `mask` prints them with every served OIDC token and every token-shaped run replaced by
`[masked]`. A leak still fails step 5's search, which reads the saved files, not the console.

## The job log masks every token the harness holds

On a runner (`GITHUB_ACTIONS=true`) the harness writes `::add-mask::<token>` to its own stdout
for the request token and for each OIDC token, as soon as it has it and before anything could
print it. The line goes to stdout, never on an argument list, and a value with a line break is
refused (it could not be masked). Outside Actions nothing is written, because there the line would
itself show the token.

## A demo not run is a warning and a green job; a lost token is a failure

On a fork's pull request, or while a repository variable is unset, the gate writes
`::warning::demo-m6d: NOT RUN (<reason>; setup: ...)` and the job-summary line
`demo-m6d: NOT RUN (<reason>)`, and the job stays green, so `main` stays green until the owner's
Google setup exists. A run that printed it is not a passed demo, and the README never counts it
as one. With the variables set and not a fork, missing `ACTIONS_ID_TOKEN_REQUEST_*` means the job
lost `id-token: write`: the gate fails (exit 1), not skips (supervisor, slice 3 review). In the
harness, a malformed variable is likewise a failure (exit 1), and only a missing one is `NOT RUN`
(exit 3).

## A library gap

`zigbox` exports no name for `host_real_net`'s memory type, which a library caller of
`HostReal` needs. The helper derives it with `@typeInfo` from `HostReal.network_memory`. Exporting
it is a small library change, left for a later slice. The harness changes nothing in `src/` outside
`src/testing/vm/`.
