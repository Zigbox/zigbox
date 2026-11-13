# Keyring renewal needs a user re-fetch until a keyring package exists

*Decided 2026-11-13, by the implementer of PR #129; the owner may overrule.*

## Problem

Users install the keyring once (`curl` into `/usr/share/keyrings/zigbox.gpg`). Nothing updates it,
so when the signing subkey reaches the expiry that file records, `apt update` fails with `EXPKEYSIG`
on every install, even when the owner renewed the subkey in time. dnf keeps the key it imported from
the `.repo` file's `gpgkey=` URL, so it has the same gap.

## Decision

Not in this PR: a `zigbox-archive-keyring` package (deb and rpm) in the repositories, installing the
keyring file so renewal reaches users through `apt upgrade`. It needs a second package in the
package tool, its metadata, signing and checks, and it changes the install commands. It is the
lasting fix and is recorded as a follow-up, before the first yearly renewal falls due.

Now, the runbook is honest about it (`docs/releases/packaging.md`, "Yearly renewal"):

- Renewal is also a user action. The owner renews at least 28 days before the expiry, which the
  refresh and `release-sign.sh` already enforce, and says so in the release notes (template in the
  runbook) and the install guide ("Renewing the keyring").
- The expiry policy is unchanged: one year, renewed by extending the same subkey. No new bound.

## Also in this change

`release-sign.sh` refuses a primary or signing subkey that expires within 28 days of the signing
time, with the weekly refresh's rule and messages, so a release cannot publish a signature whose
key lapses inside `Valid-Until` plus the renewal margin. `release-sign-test.sh` covers a 10-day
subkey.
