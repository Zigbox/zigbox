#!/usr/bin/env bash
# Runs .github/release-sign.sh with a throwaway key shaped like the release key: a certify-only
# RSA 4096 primary, one RSA 4096 signing subkey, a passphrase, and the secret export of the
# subkey alone (primary stubbed). Nothing is attached or dispatched; the key vouches for nothing.
# The fixed `-Dtest-key` of `zig build packages` is an Ed25519 key held inside the package
# tool and cannot be imported by gpg, so it cannot exercise the import and subkey checks.
# Usage: .github/release-sign-test.sh OUTPUT_DIR
set -euo pipefail

output=${1:?usage: release-sign-test.sh OUTPUT_DIR}
home=$(mktemp -d)
trap 'GNUPGHOME=$home gpgconf --kill gpg-agent 2>/dev/null || true; rm -rf "$home"' EXIT

passphrase=test-only-passphrase
gpg_home() { GNUPGHOME=$home gpg --batch --no-tty --pinentry-mode loopback \
  --passphrase "$passphrase" "$@" 2> /dev/null; }

gpg_home --quick-generate-key "Zigbox release test <test@invalid>" rsa4096 cert 1d
primary=$(GNUPGHOME=$home gpg --batch --list-keys --with-colons | awk -F: '$1 == "fpr" { print $10; exit }')
gpg_home --quick-add-key "$primary" rsa4096 sign 1d
subkey=$(GNUPGHOME=$home gpg --batch --list-keys --with-colons |
  awk -F: '$1 == "sub" { s = 1; next } $1 == "fpr" && s { print $10; exit }')

ZIGBOX_SIGNING_PASSPHRASE=$passphrase
ZIGBOX_SIGNING_FPR=$primary
export ZIGBOX_SIGNING_KEY ZIGBOX_SIGNING_PASSPHRASE ZIGBOX_SIGNING_FPR

# An export that still holds the secret primary key must be refused, with the reason.
ZIGBOX_SIGNING_KEY=$(gpg_home --armor --export-secret-keys "$primary")
if refusal=$("$(dirname "$0")/release-sign.sh" "$output/refused" 2>&1); then
  echo "release-sign-test: a key holding the secret primary was accepted" >&2
  exit 1
fi
grep -q 'holds the secret primary key' <<< "$refusal" || {
  echo "release-sign-test: wrong refusal for a full secret export: $refusal" >&2
  exit 1
}

ZIGBOX_SIGNING_KEY=$(gpg_home --armor --export-secret-subkeys "${subkey}!")
export ZIGBOX_SIGNING_KEY
# The same file the release runs.
"$(dirname "$0")/release-sign.sh" "$output"
