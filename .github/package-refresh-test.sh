#!/usr/bin/env bash
# Runs .github/package-refresh.sh with a throwaway key shaped like the release key (a certify-only
# RSA 4096 primary, one RSA 4096 signing subkey, a passphrase, the subkey exported alone), on an
# archive made by .github/release-sign.sh. It refreshes a tree and checks the result, then shows
# each refusal the script promises: a tampered Packages, a Release by a key outside the pin, an
# unsigned or tampered SHA256SUMS, an archive that is not the release's, one of another version,
# one older than the served InRelease, a revoked subkey whose revocation the archive's own keyring
# leaves out, a lapsed subkey and primary, and a revoked primary. The key vouches for nothing.
# Run from anywhere; it changes into the repository root, where zig builds.
# Usage: .github/package-refresh-test.sh OUTPUT_DIR
set -euo pipefail

output=$(realpath -m "${1:?usage: package-refresh-test.sh OUTPUT_DIR}")
here=$(dirname "$(realpath "$0")")
cd "$here/.."
work=$(mktemp -d)
home=$work/gnupg
other_home=$work/gnupg-other
mkdir -m 0700 "$home" "$other_home"
trap 'for h in "$home" "$other_home"; do GNUPGHOME=$h gpgconf --kill gpg-agent 2>/dev/null || true; done; rm -rf "$work"' EXIT

fail() { echo "package-refresh-test: $*" >&2; exit 1; }
passphrase=test-only-passphrase
gpg_in() { local h=$1; shift; GNUPGHOME=$h gpg --batch --no-tty --pinentry-mode loopback \
  --passphrase "$passphrase" "$@" 2> /dev/null; }
gpg_home() { gpg_in "$home" "$@"; }
listing_fpr() { GNUPGHOME=$home gpg --batch --list-keys --with-colons |
  awk -F: -v want="$1" '$1 == want { s = 1; next } $1 == "fpr" && s { print $10; exit }'; }

# A primary valid for 90 days, a signing subkey for 60: both outlast the 21-day Valid-Until, and
# the lapse and too-short tests move the signing time past one or the other.
gpg_home --quick-generate-key "Zigbox refresh test <test@invalid>" rsa4096 cert 90d
primary=$(GNUPGHOME=$home gpg --batch --list-keys --with-colons | awk -F: '$1 == "fpr" { print $10; exit }')
gpg_home --quick-add-key "$primary" rsa4096 sign 60d
subkey=$(listing_fpr sub)

export ZIGBOX_SIGNING_KEY ZIGBOX_SIGNING_PASSPHRASE=$passphrase ZIGBOX_SIGNING_FPR=$primary
ZIGBOX_SIGNING_KEY=$(gpg_home --armor --export-secret-subkeys "${subkey}!")

# The archive a release would hold, signed by the subkey with the same script the release runs.
now=$(date +%s)
ZIGBOX_SIGNED_AT=$((now - 86400)) .github/release-sign.sh "$work/release"
base=$work/release/zigbox-repos.tar.gz
mkdir "$work/base"
tar -xzf "$base" -C "$work/base"
version=$(find "$work/base/apt/dists/stable" -name Packages -exec sed -n 's/^Version: //p' {} + | sort -u)
[ -n "$version" ] || fail "the archive's Packages list no version"
tag=v$version

# A SHA256SUMS the way the release writes it (another asset's line, then the archive's), with its
# detached signature by the subkey.
make_sums() { # make_sums archive dir: dir/SHA256SUMS and dir/SHA256SUMS.asc by the current key
  mkdir -p "$2"
  { printf '%s  zbx-test-linux-x86_64.tar.gz\n' "$(printf 'asset' | sha256sum | cut -d' ' -f1)"
    printf '%s  zigbox-repos.tar.gz\n' "$(sha256sum < "$1" | cut -d' ' -f1)"; } > "$2/SHA256SUMS"
  gpg_home --yes -u "${current_subkey}!" -ab -o "$2/SHA256SUMS.asc" "$2/SHA256SUMS"
}
current_subkey=$subkey
make_sums "$base" "$work/sums"
published=$work/base/apt/dists/stable/InRelease

refresh() { # refresh archive sums published tag [outdir]
  .github/package-refresh.sh "$1" "${5:-$work/new}" "$2" "$3" "$4"
}
refuse() { # refuse pattern command...: the command must fail with a line holding the pattern
  local pattern=$1 refusal
  shift
  if refusal=$("$@" 2>&1); then fail "accepted, expected a refusal matching '$pattern'"; fi
  grep -q -- "$pattern" <<< "$refusal" || fail "wrong refusal for '$pattern': $refusal"
  [ "$(wc -l <<< "$refusal")" -le 2 ] || fail "the refusal is more than a line: $refusal"
}
at() { local time=$1; shift; ZIGBOX_SIGNED_AT=$time "$@"; } # at TIME command...: the signing time
repack() { # repack dir name: a copy of the base tree, changed by the caller, as work/name
  tar -czf "$work/$2" -C "$1" apt rpm zigbox-archive-keyring.gpg zigbox-archive-keyring.asc
}

# 1. The happy path: new Date, Valid-Until 21 days later, the packages untouched, the signed sums.
ZIGBOX_SIGNED_AT=$now refresh "$base" "$work/sums/SHA256SUMS" "$published" "$tag"
mkdir "$work/new-tree"
tar -xzf "$work/new/zigbox-repos.tar.gz" -C "$work/new-tree"
release=$work/new-tree/apt/dists/stable/Release
[ "$(date -u -d "$(sed -n 's/^Date: //p' "$release")" +%s)" -eq "$now" ] || fail "Date is not the signing time"
valid=$(date -u -d "$(sed -n 's/^Valid-Until: //p' "$release")" +%s)
[ "$((valid - now))" -eq 1814400 ] || fail "Valid-Until is not 21 days after Date"
diff -r "$work/base/apt/pool" "$work/new-tree/apt/pool" > /dev/null || fail "a package changed"
find "$work/base/apt/dists" -name 'Packages*' | while read -r file; do
  cmp -s "$file" "$work/new-tree/${file#"$work/base/"}" || fail "${file##*/} changed"
done
grep -q "^$(sha256sum < "$work/new/zigbox-repos.tar.gz" | cut -d' ' -f1)  zigbox-repos.tar.gz\$" \
  "$work/new/SHA256SUMS" || fail "SHA256SUMS does not list the new archive"
grep -q 'zbx-test-linux-x86_64.tar.gz' "$work/new/SHA256SUMS" || fail "another asset's line was lost"
check_home=$work/gnupg-check
mkdir -m 0700 "$check_home"
GNUPGHOME=$check_home gpg --batch --import "$work/new-tree/zigbox-archive-keyring.gpg" 2> /dev/null
GNUPGHOME=$check_home gpg --batch --verify "$work/new/SHA256SUMS.asc" "$work/new/SHA256SUMS" 2> /dev/null ||
  fail "the new SHA256SUMS.asc does not verify"
GNUPGHOME=$check_home gpg --batch --verify "$work/new-tree/apt/dists/stable/InRelease" 2> /dev/null ||
  fail "the new InRelease does not verify"
GNUPGHOME=$check_home gpgconf --kill gpg-agent 2>/dev/null || true
refreshed_inrelease=$work/new-tree/apt/dists/stable/InRelease

# 2. A tampered Packages file is refused before anything is signed.
cp -r "$work/base" "$work/tampered"
packages=$(find "$work/tampered/apt/dists" -name Packages | head -n 1)
printf 'Description: changed\n' >> "$packages"
repack "$work/tampered" tampered.tar.gz
make_sums "$work/tampered.tar.gz" "$work/sums-tampered"
refuse 'does not match the Release' refresh "$work/tampered.tar.gz" "$work/sums-tampered/SHA256SUMS" "$published" "$tag"

# 3. A Release signed by a key outside the pin: the archive's keyring is not what decides.
gpg_in "$other_home" --quick-generate-key "Someone else <else@invalid>" rsa2048 sign 1d
cp -r "$work/base" "$work/foreign"
gpg_in "$other_home" -abs --yes -o "$work/foreign/apt/dists/stable/Release.gpg" \
  "$work/foreign/apt/dists/stable/Release"
gpg_in "$other_home" --export > "$work/foreign/zigbox-archive-keyring.gpg"
repack "$work/foreign" foreign.tar.gz
make_sums "$work/foreign.tar.gz" "$work/sums-foreign"
refuse 'gpg --verify refused' refresh "$work/foreign.tar.gz" "$work/sums-foreign/SHA256SUMS" "$published" "$tag"

# 4. SHA256SUMS: tampered, unsigned, and one that does not list this archive.
cp -r "$work/sums" "$work/sums-bad"
printf 'x\n' >> "$work/sums-bad/SHA256SUMS"
refuse 'gpg --verify refused' refresh "$base" "$work/sums-bad/SHA256SUMS" "$published" "$tag"
rm "$work/sums-bad/SHA256SUMS.asc"
refuse 'SHA256SUMS.asc is missing' refresh "$base" "$work/sums-bad/SHA256SUMS" "$published" "$tag"
make_sums "$work/foreign.tar.gz" "$work/sums-other"
refuse 'not the zigbox-repos.tar.gz the signed SHA256SUMS lists' \
  refresh "$base" "$work/sums-other/SHA256SUMS" "$published" "$tag"

# 5. Another version than the tag, and an archive older than the InRelease the site serves.
refuse 'are not version 9.9.9 of v9.9.9' refresh "$base" "$work/sums/SHA256SUMS" "$published" v9.9.9
ZIGBOX_SIGNED_AT=$((now + 10)) refuse 'older than the one zigbox.org serves' \
  refresh "$base" "$work/sums/SHA256SUMS" "$refreshed_inrelease" "$tag"
ZIGBOX_SIGNED_AT=$now refuse 'not later than the archive' refresh "$work/new/zigbox-repos.tar.gz" "$work/new/SHA256SUMS" \
  "$refreshed_inrelease" "$tag"

# 6. A subkey that lapsed before the signing time, and a primary that did.
ZIGBOX_SIGNED_AT=$((now + 61 * 86400)) refuse 'no usable (unexpired, unrevoked) signing subkey' \
  refresh "$base" "$work/sums/SHA256SUMS" "$published" "$tag"
ZIGBOX_SIGNED_AT=$((now + 91 * 86400)) refuse 'primary key is revoked or expired' \
  refresh "$base" "$work/sums/SHA256SUMS" "$published" "$tag"

# 6b. A key that is valid at the signing time but expires before Valid-Until would sign metadata
# apt stops accepting while it is still current: refused with one line.
ZIGBOX_SIGNED_AT=$((now + 45 * 86400)) refuse 'signing subkey expires within 21 days' \
  refresh "$base" "$work/sums/SHA256SUMS" "$published" "$tag"
ZIGBOX_SIGNED_AT=$((now + 75 * 86400)) refuse 'primary key expires within 21 days' \
  refresh "$base" "$work/sums/SHA256SUMS" "$published" "$tag"

# 6c. The served InRelease's Date is read from the signed text only: a forged Date line in front
# of the clearsigned block must not hide that the archive is older than what is served.
{ printf 'Date: Thu, 01 Jan 1970 00:00:00 UTC\n'; cat "$refreshed_inrelease"; } > "$work/prefixed-InRelease"
ZIGBOX_SIGNED_AT=$((now + 10)) refuse 'older than the one zigbox.org serves' \
  refresh "$base" "$work/sums/SHA256SUMS" "$work/prefixed-InRelease" "$tag"

# 6d. The archive's hash is checked against the signed sums before it is read as an archive.
printf 'not an archive\n' > "$work/garbage.tar.gz"
refuse 'not the zigbox-repos.tar.gz the signed SHA256SUMS lists' \
  refresh "$work/garbage.tar.gz" "$work/sums/SHA256SUMS" "$published" "$tag"

# 6e. A half-finished upload (the runbook's recovery). `gh release upload --clobber` replaces one
# file at a time, so the release can hold the new archive with the old sums, or the new archive and
# sums with the old signature: the refresh refuses both, as it must. Re-uploading the three saved
# files of the failed run (the workflow's artifact) restores one signed set, and the next refresh
# accepts it.
refuse 'not the zigbox-repos.tar.gz the signed SHA256SUMS lists' at $((now + 10)) \
  refresh "$work/new/zigbox-repos.tar.gz" "$work/sums/SHA256SUMS" "$refreshed_inrelease" "$tag" "$work/mixed-out"
mkdir "$work/mixed"
cp "$work/new/SHA256SUMS" "$work/mixed/SHA256SUMS"
cp "$work/sums/SHA256SUMS.asc" "$work/mixed/SHA256SUMS.asc"
refuse 'gpg --verify refused' at $((now + 10)) \
  refresh "$work/new/zigbox-repos.tar.gz" "$work/mixed/SHA256SUMS" "$refreshed_inrelease" "$tag" "$work/mixed-out"
mkdir "$work/release-assets"
cp "$work/new/zigbox-repos.tar.gz" "$work/new/SHA256SUMS" "$work/new/SHA256SUMS.asc" "$work/release-assets/"
ZIGBOX_SIGNED_AT=$((now + 10)) refresh "$work/release-assets/zigbox-repos.tar.gz" \
  "$work/release-assets/SHA256SUMS" "$refreshed_inrelease" "$tag" "$work/recovered"
[ -s "$work/recovered/SHA256SUMS.asc" ] || fail "the recovered set was not refreshed"

# 7. The subkey leaks: the owner revokes it and adds another. The archive (and the keyring in it)
# is the attacker's, still with the old subkey and no revocation; the refresh must not accept it.
revoke_first_subkey() {
  printf 'key 1\nrevkey\ny\n0\nleaked in a test\n\ny\nsave\n' |
    GNUPGHOME=$home gpg --batch --no-tty --pinentry-mode loopback --passphrase "$passphrase" \
      --command-fd 0 --status-fd 2 --edit-key "$primary" 2> /dev/null > /dev/null
}
revoke_first_subkey
gpg_home --quick-add-key "$primary" rsa4096 sign 60d
new_subkey=$(GNUPGHOME=$home gpg --batch --list-keys --with-colons |
  awk -F: '$1 == "sub" && $2 != "r" { s = 1; next } $1 == "fpr" && s { print $10; exit }')
if [ -z "$new_subkey" ] || [ "$new_subkey" = "$subkey" ]; then fail "the replacement subkey was not made"; fi
ZIGBOX_SIGNING_KEY=$(gpg_home --armor --export-secret-subkeys "${new_subkey}!")
refuse 'gpg --verify refused' refresh "$base" "$work/sums/SHA256SUMS" "$published" "$tag"

# 8. The whole primary is revoked: the key in the secret is refused before anything is read.
printf 'revkey\ny\n0\nleaked in a test\n\ny\nsave\n' |
  GNUPGHOME=$home gpg --batch --no-tty --pinentry-mode loopback --passphrase "$passphrase" \
    --command-fd 0 --edit-key "$primary" > /dev/null 2>&1
ZIGBOX_SIGNING_KEY=$(gpg_home --armor --export-secret-subkeys "${new_subkey}!")
refuse 'primary key is revoked or expired' refresh "$base" "$work/sums/SHA256SUMS" "$published" "$tag"

mkdir -p "$output"
cp "$work/new/zigbox-repos.tar.gz" "$work/new/SHA256SUMS" "$work/new/SHA256SUMS.asc" "$output/"
echo "package-refresh-test: the refresh and every refusal behaved as promised"
