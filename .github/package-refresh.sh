#!/usr/bin/env bash
# Re-dates the apt metadata of a published release and signs it again, so `Valid-Until` stays in
# the future (docs/releases/packaging.md, "Keeping apt fresh"; decision 2026-11-12-apt-valid-
# until-and-refresh.md). Shell, not Zig, because the program that signs is gpg. It changes only
# `Release`, `InRelease` and `Release.gpg` (and re-exports the public keyring), plus the archive's
# line in `SHA256SUMS` and its signature; it never rebuilds a package. It signs again only what
# the owner's current key already signed and published: every old signature is checked against
# the public part of ZIGBOX_SIGNING_KEY (never the keyring that comes inside the archive), so a
# revoked subkey is not accepted, and a refresh never goes back in time.
# Usage: .github/package-refresh.sh OLD_ARCHIVE OUTPUT_DIR OLD_SHA256SUMS PUBLISHED_INRELEASE TAG
#   OLD_SHA256SUMS      the release's SHA256SUMS; its detached signature must sit beside it as
#                       OLD_SHA256SUMS.asc. A release without both is refused.
#   PUBLISHED_INRELEASE the InRelease zigbox.org serves now; the archive must not be older.
#   TAG                 the release tag (vX.Y.Z); the packages in the archive must be that version.
# Run from the repository root. Output: OUTPUT_DIR/zigbox-repos.tar.gz (the layout release-sign.sh
# writes), OUTPUT_DIR/SHA256SUMS with the new archive's line and a fresh SHA256SUMS.asc.
#
# Environment (never printed, never passed as an argument):
#   ZIGBOX_SIGNING_KEY, ZIGBOX_SIGNING_PASSPHRASE, ZIGBOX_SIGNING_FPR   as for release-sign.sh
#   ZIGBOX_SIGNED_AT   optional Unix seconds for Date (tests); default is now
# Needs zig, gpg, tar, sha256sum. No `set -x`: this script handles the key.
set -euo pipefail

usage="usage: package-refresh.sh OLD_ARCHIVE OUTPUT_DIR OLD_SHA256SUMS PUBLISHED_INRELEASE TAG"
archive=${1:?$usage}
output=${2:?$usage}
old_sums=${3:?$usage}
published=${4:?$usage}
tag=${5:?$usage}
: "${ZIGBOX_SIGNING_KEY:?ZIGBOX_SIGNING_KEY is not set}"
: "${ZIGBOX_SIGNING_PASSPHRASE:?ZIGBOX_SIGNING_PASSPHRASE is not set}"
: "${ZIGBOX_SIGNING_FPR:?ZIGBOX_SIGNING_FPR is not set}"
fail() { echo "package-refresh: $*" >&2; exit 1; }
case "$ZIGBOX_SIGNING_FPR" in
  *[!0-9A-Fa-f]* | "") fail "ZIGBOX_SIGNING_FPR is not a hex fingerprint" ;;
esac
primary=${ZIGBOX_SIGNING_FPR^^}
[ "${#primary}" -eq 40 ] || fail "ZIGBOX_SIGNING_FPR is not 40 hex digits"
signed_at=${ZIGBOX_SIGNED_AT:-$(date +%s)}
case "$signed_at" in *[!0-9]* | "") fail "ZIGBOX_SIGNED_AT is not Unix seconds" ;; esac
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "'$tag' is not a release tag"
version=${tag#v}
# Must equal apt_valid_seconds in src/constants.zig (21 days).
valid_seconds=1814400
[ -f "$old_sums" ] || fail "$old_sums is missing: a release without SHA256SUMS is not refreshed"
[ -f "$old_sums.asc" ] || fail "$old_sums.asc is missing: unsigned SHA256SUMS is not refreshed"
[ -f "$published" ] || fail "$published is missing: the served InRelease is needed to refuse a rollback"

work=$(mktemp -d)
signing_home=$work/gnupg-sign
verify_home=$work/gnupg-verify
tree=$work/tree
mkdir -m 0700 "$signing_home" "$verify_home"
mkdir "$tree"
cleanup() {
  local status=$?
  for home in "$signing_home" "$verify_home"; do
    GNUPGHOME=$home gpgconf --kill gpg-agent 2>/dev/null || true
  done
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

# The key first: it is the only thing every old signature is checked against. The passphrase goes
# in a 0600 file, the key on stdin; then only the one signing subkey of the pinned primary
# (the same listing release-sign.sh reads) is accepted, and it must not be revoked or expired.
gpg_sign() { GNUPGHOME=$signing_home gpg --batch --no-tty --pinentry-mode loopback \
  --passphrase-file "$signing_home/passphrase" "$@"; }
(umask 077 && printf '%s' "$ZIGBOX_SIGNING_PASSPHRASE" > "$signing_home/passphrase")
printf '%s\n' "$ZIGBOX_SIGNING_KEY" | gpg_sign --import 2> "$work/import.log" ||
  fail "gpg could not import ZIGBOX_SIGNING_KEY"
unset ZIGBOX_SIGNING_KEY ZIGBOX_SIGNING_PASSPHRASE
# Colon listing: field 2 validity (e expired, r revoked), 3 bits, 4 algorithm, 7 expiry in Unix
# seconds (empty: never), 12 capabilities, 15 `#` for a stubbed secret. Expiry is judged at the
# signing time, so a key that lapsed before it is refused even when gpg's own clock disagrees. A
# signature by a key that expires before `Valid-Until` stops verifying (apt: EXPKEYSIG) while the
# metadata is still current, so a key must also outlive the whole validity window.
listing=$(GNUPGHOME=$signing_home gpg --batch --list-secret-keys --with-colons 2>/dev/null)
subkey=$(awk -F: -v primary="$primary" -v at="$signed_at" -v window="$valid_seconds" '
  function dead(validity, expiry) { return validity == "e" || validity == "r" || (expiry != "" && expiry + 0 <= at) }
  function short(expiry) { return expiry != "" && expiry + 0 <= at + window }
  $1 == "sec" { section = "sec"; if ($3 != 4096 || $4 != 1) weak = 1; if ($15 != "#") plain = 1
                if (dead($2, $7)) lapsed = 1; else if (short($7)) brief = 1; next }
  $1 == "ssb" { section = dead($2, $7) ? "bad" : (index($12, "s") ? (short($7) ? "brief" : "sign") : "other")
                if (section == "brief") briefsub = 1
                if (section == "sign" && ($3 != 4096 || $4 != 1)) weak = 1; next }
  $1 == "fpr" && section == "sec" { top = $10; section = ""; next }
  $1 == "fpr" && section == "sign" { print $10; signs++; section = "" }
  END { if (top != primary) print "WRONG-PRIMARY"; if (weak) print "WEAK"; if (plain) print "PRIMARY-SECRET"
        if (lapsed) print "LAPSED-PRIMARY"; if (brief) print "SHORT-PRIMARY"
        if (briefsub && !signs) print "SHORT-SUBKEY" }
' <<< "$listing")
case "$subkey" in
  *WRONG-PRIMARY*) fail "the imported key is not by the primary key ZIGBOX_SIGNING_FPR" ;;
  *LAPSED-PRIMARY*) fail "the primary key is revoked or expired; the owner must renew or replace it" ;;
  *SHORT-PRIMARY*) fail "the primary key expires within 21 days of the signing time; the owner must renew it" ;;
  *SHORT-SUBKEY*) fail "the signing subkey expires within 21 days of the signing time; the owner must renew it" ;;
  *PRIMARY-SECRET*) fail "the imported key holds the secret primary key" ;;
  *WEAK*) fail "the primary and the signing subkey must be RSA 4096" ;;
  "") fail "the imported key has no usable (unexpired, unrevoked) signing subkey" ;;
esac
[ "$(wc -l <<< "$subkey")" -eq 1 ] || fail "the imported key has more than one signing subkey"
subkey=${subkey^^}
echo "package-refresh: signing subkey ${subkey: -16} of primary ${primary: -16}"

# What the old signatures are checked against: the public part of the owner's key, exported from
# the key just imported. It carries the owner's revocations and expiry; a keyring shipped in the
# archive (or anywhere else) is never imported, so it cannot vouch for a key the owner revoked.
verify_gpg() { GNUPGHOME=$verify_home gpg --batch --no-tty --status-fd 1 "$@" 2> /dev/null; }
check_signature() { # check_signature expected_subkey file...
  local expected=$1 status fields
  shift
  status=$(verify_gpg --verify "$@") || fail "gpg --verify refused $*"
  grep -q '^\[GNUPG:\] GOODSIG ' <<< "$status" || fail "no good signature on $*"
  fields=$(awk '$2 == "VALIDSIG" { print $3, $NF }' <<< "$status")
  [ -n "$fields" ] || fail "no valid signature on $*"
  [ "${fields#* }" = "$primary" ] || fail "$* is not by a subkey of ZIGBOX_SIGNING_FPR"
  [ "${fields% *}" != "$primary" ] || fail "$* is signed by the primary key, not a subkey"
  [ "${fields% *}" = "$expected" ] || fail "$* is not by the current signing subkey"
}
GNUPGHOME=$signing_home gpg --batch --export "$primary" > "$work/owner-keyring.gpg"
[ -s "$work/owner-keyring.gpg" ] || fail "the public key export is empty"
GNUPGHOME=$verify_home gpg --batch --import "$work/owner-keyring.gpg" 2> /dev/null ||
  fail "the owner's public key cannot be imported"

# The archive is the release's before a byte of it is read: the signed SHA256SUMS (by the current
# subkey) lists its hash. Only then is it listed or extracted, so every byte is the owner's.
check_signature "$subkey" "$old_sums.asc" "$old_sums"
archive_hash=$(sha256sum < "$archive" | cut -d' ' -f1)
grep -q "^$archive_hash  zigbox-repos.tar.gz\$" "$old_sums" ||
  fail "$archive is not the zigbox-repos.tar.gz the signed SHA256SUMS lists"

# The archive holds apt/, rpm/ and the keyring files, and nothing else (the same rule the release
# workflow checks): a listing with anything more is refused before it is extracted.
tar -tzf "$archive" > "$work/list" || fail "$archive is not a gzip tar archive"
if grep -Evq '^(apt/|rpm/|zigbox-archive-keyring\.(asc|gpg)$)' "$work/list" ||
  grep -Eq '(^|/)\.\.?(/|$)|^/' "$work/list" || grep -Eq 'to-sign|test-key|passphrase|secret' "$work/list"; then
  fail "$archive holds a path that a release archive must not"
fi
tar -xzf "$archive" -C "$tree" --no-same-owner
dists=$tree/apt/dists/stable
for file in Release InRelease Release.gpg; do
  [ -f "$dists/$file" ] || fail "$archive has no apt/dists/stable/$file"
done

# The old signatures: the Release, the archive's own sums and the Release the site serves must all
# be by the current subkey. An asset someone replaced is never given a fresh signature.
check_signature "$subkey" "$dists/Release.gpg" "$dists/Release"
check_signature "$subkey" "$dists/InRelease"
check_signature "$subkey" "$published"
# The served file's Date comes only from the text gpg authenticated, never from bytes around it.
verify_gpg --output "$work/served.txt" --verify "$published" > /dev/null || fail "gpg --verify refused $published"

# Every package file and index the Release lists is what it names: the sums are kept, so a stale
# or swapped file would be re-signed otherwise.
sums_ok() {
  local listed=0 hash size path
  while read -r hash size path; do
    listed=$((listed + 1))
    [ -f "$dists/$path" ] || fail "Release lists $path, which the archive lacks"
    [ "$(sha256sum < "$dists/$path" | cut -d' ' -f1)" = "$hash" ] || fail "$path does not match the Release"
    [ "$(wc -c < "$dists/$path")" -eq "$size" ] || fail "$path has another size than the Release says"
  done < <(awk '$0 == "SHA256:" { in_sums = 1; next } /^[^ ]/ { in_sums = 0 } in_sums { print $1, $2, $3 }' "$dists/Release")
  [ "$listed" -gt 0 ] || fail "the Release lists no files"
}
sums_ok

# Its packages are this tag's version.
versions=$(find "$dists" -name Packages -exec sed -n 's/^Version: //p' {} + | sort -u)
[ -n "$versions" ] || fail "the archive's Packages files list no version"
[ "$versions" = "$version" ] || fail "the archive's packages are not version $version of $tag"

# Never go back in time: the archive must not be older than what the site serves, and the new
# Date must be later than the archive's own.
date_of() { # date_of file: the first Date line, as Unix seconds
  local line
  line=$(sed -n 's/^Date: //p' "$1" | head -n 1)
  [ -n "$line" ] || fail "$1 has no Date"
  date -u -d "$line" +%s || fail "$1 has an unreadable Date"
}
old_date=$(date_of "$dists/Release")
published_date=$(date_of "$work/served.txt")
[ "$old_date" -ge "$published_date" ] || fail "the archive's Release is older than the one zigbox.org serves"
[ "$signed_at" -gt "$old_date" ] || fail "the signing time is not later than the archive's Date"

# Re-date, then sign the new Release. The tool deletes the stale InRelease and Release.gpg.
zig build packages-redate -Dsigned-at="$signed_at" -Dpackages-dir="$tree"
gpg_sign -u "${subkey}!" --clearsign -o "$dists/InRelease" "$dists/Release"
gpg_sign -u "${subkey}!" -abs -o "$dists/Release.gpg" "$dists/Release"
sums_ok

# Re-export the public keyring (it may carry a renewed subkey), then verify what is written in a
# home with the new keyring only, against the new Date and a Valid-Until 21 days later.
GNUPGHOME=$signing_home gpg --batch --export -a "$primary" > "$tree/zigbox-archive-keyring.asc"
cp "$work/owner-keyring.gpg" "$tree/zigbox-archive-keyring.gpg"
GNUPGHOME=$verify_home gpgconf --kill gpg-agent 2>/dev/null || true
rm -rf "$verify_home"
mkdir -m 0700 "$verify_home"
GNUPGHOME=$verify_home gpg --batch --import "$tree/zigbox-archive-keyring.gpg" 2> /dev/null
check_signature "$subkey" "$dists/Release.gpg" "$dists/Release"
check_signature "$subkey" "$dists/InRelease"
date_line=$(sed -n 's/^Date: //p' "$dists/Release")
valid_line=$(sed -n 's/^Valid-Until: //p' "$dists/Release")
[ "$(date -u -d "$date_line" +%s)" -eq "$signed_at" ] || fail "the Release Date is not the signing time"
[ "$(( $(date -u -d "$valid_line" +%s) - signed_at ))" -eq "$valid_seconds" ] ||
  fail "Valid-Until is not 21 days after Date"

mkdir -p "$output"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@"$signed_at" -cf - -C "$tree" \
  apt rpm zigbox-archive-keyring.gpg zigbox-archive-keyring.asc | gzip -n > "$output/zigbox-repos.tar.gz"
new_hash=$(sha256sum < "$output/zigbox-repos.tar.gz" | cut -d' ' -f1)
sed "s/^[0-9a-f]\{64\}  zigbox-repos.tar.gz\$/$new_hash  zigbox-repos.tar.gz/" "$old_sums" > "$output/SHA256SUMS"
grep -q "^$new_hash  zigbox-repos.tar.gz\$" "$output/SHA256SUMS" || fail "SHA256SUMS was not updated"
rm -f "$output/SHA256SUMS.asc"
gpg_sign -u "${subkey}!" -ab -o "$output/SHA256SUMS.asc" "$output/SHA256SUMS"
check_signature "$subkey" "$output/SHA256SUMS.asc" "$output/SHA256SUMS"
echo "package-refresh: Release dated $date_line, valid until $valid_line; wrote $output/zigbox-repos.tar.gz"
