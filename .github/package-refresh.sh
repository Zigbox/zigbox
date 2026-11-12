#!/usr/bin/env bash
# Re-dates the apt metadata of a published release and signs it again, so `Valid-Until` stays in
# the future (docs/releases/packaging.md, "Keeping apt fresh"; decision 2026-11-12-apt-valid-
# until-and-refresh.md). Shell, not Zig, because the program that signs is gpg. It changes only
# `Release`, `InRelease` and `Release.gpg` (and re-exports the public keyring); it never rebuilds
# a package, and it refuses an archive whose `Release` was not signed by the pinned primary key.
# Usage: .github/package-refresh.sh OLD_ARCHIVE OUTPUT_DIR [OLD_SHA256SUMS]
# Run from the repository root. Output: OUTPUT_DIR/zigbox-repos.tar.gz, the layout release-sign.sh
# writes. With OLD_SHA256SUMS (the release has one) it also writes SHA256SUMS with the new
# archive's line and a fresh detached SHA256SUMS.asc, because the archive's hash changed.
#
# Environment (never printed, never passed as an argument):
#   ZIGBOX_SIGNING_KEY, ZIGBOX_SIGNING_PASSPHRASE, ZIGBOX_SIGNING_FPR   as for release-sign.sh
#   ZIGBOX_SIGNED_AT   optional Unix seconds for Date (tests); default is now
# Needs zig, gpg, tar, sha256sum. No `set -x`: this script handles the key.
set -euo pipefail

archive=${1:?usage: package-refresh.sh OLD_ARCHIVE OUTPUT_DIR}
output=${2:?usage: package-refresh.sh OLD_ARCHIVE OUTPUT_DIR [OLD_SHA256SUMS]}
old_sums=${3:-}
: "${ZIGBOX_SIGNING_KEY:?ZIGBOX_SIGNING_KEY is not set}"
: "${ZIGBOX_SIGNING_PASSPHRASE:?ZIGBOX_SIGNING_PASSPHRASE is not set}"
: "${ZIGBOX_SIGNING_FPR:?ZIGBOX_SIGNING_FPR is not set}"
case "$ZIGBOX_SIGNING_FPR" in
  *[!0-9A-Fa-f]* | "") echo "package-refresh: ZIGBOX_SIGNING_FPR is not a hex fingerprint" >&2; exit 1 ;;
esac
primary=${ZIGBOX_SIGNING_FPR^^}
fail() { echo "package-refresh: $*" >&2; exit 1; }
[ "${#primary}" -eq 40 ] || fail "ZIGBOX_SIGNING_FPR is not 40 hex digits"
signed_at=${ZIGBOX_SIGNED_AT:-$(date +%s)}
case "$signed_at" in *[!0-9]* | "") fail "ZIGBOX_SIGNED_AT is not Unix seconds" ;; esac

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

# The old signatures first: the Release must be signed by a subkey of the pinned primary key, so
# a replaced asset is never given a fresh signature. The keyring is the archive's own; what makes
# it trusted is the fingerprint check on the signature, not the file.
verify_gpg() { GNUPGHOME=$verify_home gpg --batch --no-tty --status-fd 1 "$@" 2> /dev/null; }
check_signature() { # check_signature expected_subkey_or_empty file...
  local expected=$1 status fields
  shift
  status=$(verify_gpg --verify "$@") || fail "gpg --verify refused $*"
  grep -q '^\[GNUPG:\] GOODSIG ' <<< "$status" || fail "no good signature on $*"
  fields=$(awk '$2 == "VALIDSIG" { print $3, $NF }' <<< "$status")
  [ -n "$fields" ] || fail "no valid signature on $*"
  [ "${fields#* }" = "$primary" ] || fail "$* is not by a subkey of ZIGBOX_SIGNING_FPR"
  [ "${fields% *}" != "$primary" ] || fail "$* is signed by the primary key, not a subkey"
  [ -z "$expected" ] || [ "${fields% *}" = "$expected" ] || fail "$* is not by the signing subkey"
}
GNUPGHOME=$verify_home gpg --batch --import "$tree/zigbox-archive-keyring.gpg" 2> /dev/null ||
  fail "the archive's keyring cannot be imported"
check_signature "" "$dists/Release.gpg" "$dists/Release"
check_signature "" "$dists/InRelease"

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

# The key: passphrase in a 0600 file, key on stdin, then only the one signing subkey of the
# pinned primary (the same listing release-sign.sh reads).
gpg_sign() { GNUPGHOME=$signing_home gpg --batch --no-tty --pinentry-mode loopback \
  --passphrase-file "$signing_home/passphrase" "$@"; }
(umask 077 && printf '%s' "$ZIGBOX_SIGNING_PASSPHRASE" > "$signing_home/passphrase")
printf '%s\n' "$ZIGBOX_SIGNING_KEY" | gpg_sign --import 2> "$work/import.log" ||
  fail "gpg could not import ZIGBOX_SIGNING_KEY"
unset ZIGBOX_SIGNING_KEY ZIGBOX_SIGNING_PASSPHRASE
listing=$(GNUPGHOME=$signing_home gpg --batch --list-secret-keys --with-colons 2>/dev/null)
subkey=$(awk -F: -v primary="$primary" '
  $1 == "sec" { section = "sec"; if ($3 != 4096 || $4 != 1) weak = 1; if ($15 != "#") plain = 1; next }
  $1 == "ssb" { section = ($2 == "e" || $2 == "r") ? "bad" : (index($12, "s") ? "sign" : "other")
                if (section == "sign" && ($3 != 4096 || $4 != 1)) weak = 1; next }
  $1 == "fpr" && section == "sec" { top = $10; section = ""; next }
  $1 == "fpr" && section == "sign" { print $10; section = "" }
  END { if (top != primary) print "WRONG-PRIMARY"; if (weak) print "WEAK"; if (plain) print "PRIMARY-SECRET" }
' <<< "$listing")
case "$subkey" in
  *WRONG-PRIMARY*) fail "the imported key is not by the primary key ZIGBOX_SIGNING_FPR" ;;
  *PRIMARY-SECRET*) fail "the imported key holds the secret primary key" ;;
  *WEAK*) fail "the primary and the signing subkey must be RSA 4096" ;;
  "") fail "the imported key has no usable (unexpired, unrevoked) signing subkey" ;;
esac
[ "$(wc -l <<< "$subkey")" -eq 1 ] || fail "the imported key has more than one signing subkey"
subkey=${subkey^^}
echo "package-refresh: signing subkey ${subkey: -16} of primary ${primary: -16}"

# Re-date, then sign the new Release. The tool deletes the stale InRelease and Release.gpg.
zig build packages-redate -Dsigned-at="$signed_at" -Dpackages-dir="$tree"
gpg_sign -u "${subkey}!" --clearsign -o "$dists/InRelease" "$dists/Release"
gpg_sign -u "${subkey}!" -abs -o "$dists/Release.gpg" "$dists/Release"
sums_ok

# Re-export the public keyring (it may carry a renewed subkey), then verify what is written in a
# home with the new keyring only, against the new Date and a Valid-Until 21 days later.
GNUPGHOME=$signing_home gpg --batch --export -a "$primary" > "$tree/zigbox-archive-keyring.asc"
GNUPGHOME=$signing_home gpg --batch --export "$primary" > "$tree/zigbox-archive-keyring.gpg"
[ -s "$tree/zigbox-archive-keyring.gpg" ] || fail "the public key export is empty"
GNUPGHOME=$verify_home gpgconf --kill gpg-agent 2>/dev/null || true
rm -rf "$verify_home"
mkdir -m 0700 "$verify_home"
GNUPGHOME=$verify_home gpg --batch --import "$tree/zigbox-archive-keyring.gpg" 2> /dev/null
check_signature "$subkey" "$dists/Release.gpg" "$dists/Release"
check_signature "$subkey" "$dists/InRelease"
date_line=$(sed -n 's/^Date: //p' "$dists/Release")
valid_line=$(sed -n 's/^Valid-Until: //p' "$dists/Release")
[ "$(date -u -d "$date_line" +%s)" -eq "$signed_at" ] || fail "the Release Date is not the signing time"
[ "$(( $(date -u -d "$valid_line" +%s) - signed_at ))" -eq 1814400 ] ||
  fail "Valid-Until is not 21 days after Date"

mkdir -p "$output"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@"$signed_at" -cf - -C "$tree" \
  apt rpm zigbox-archive-keyring.gpg zigbox-archive-keyring.asc | gzip -n > "$output/zigbox-repos.tar.gz"
if [ -n "$old_sums" ]; then
  new_hash=$(sha256sum < "$output/zigbox-repos.tar.gz" | cut -d' ' -f1)
  grep -q '  zigbox-repos.tar.gz$' "$old_sums" || fail "$old_sums has no line for zigbox-repos.tar.gz"
  sed "s/^[0-9a-f]\{64\}  zigbox-repos.tar.gz\$/$new_hash  zigbox-repos.tar.gz/" "$old_sums" > "$output/SHA256SUMS"
  grep -q "^$new_hash  zigbox-repos.tar.gz\$" "$output/SHA256SUMS" || fail "SHA256SUMS was not updated"
  rm -f "$output/SHA256SUMS.asc"
  gpg_sign -u "${subkey}!" -ab -o "$output/SHA256SUMS.asc" "$output/SHA256SUMS"
  check_signature "$subkey" "$output/SHA256SUMS.asc" "$output/SHA256SUMS"
fi
echo "package-refresh: Release dated $date_line, valid until $valid_line; wrote $output/zigbox-repos.tar.gz"
