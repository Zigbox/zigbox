# `zbx verify`: a policy file decides trust; `--key` and `--public` apply only without one

*Decided 2026-11-09, by the M8 slice 5 fix (review of PR #82), following the M8 brief's link 2.*

Link 2 of `zbx verify` asks whether some signer is trusted. When any policy file is present
(`/etc/zbx/policy.zon`, the user's), the keys those files list decide it, as `zbx run`'s gate
decides it: a signer must be listed by every policy file present. `--key <name>` and
`--public <text>` are then still read and checked for form, but they add nothing; a key they name
that the policies do not list fails link 2. With no policy file, they name the key to trust.

Reason: verify must not say a chain is trusted when `zbx run` on the same host refuses it (E0905).
Ignoring the flags was chosen over refusing them, so a script that passes `--key` everywhere keeps
working on hosts with and without a policy; the report names the key that was trusted.

Also from the same review: provenance that is signed for another result of the same tree is not a
broken link unless `--require-provenance` is given (link 4 is then skipped, like a tree with none),
and the JSON field of `zbx.trust-prune/1` is `dry_run`, as the brief says.
