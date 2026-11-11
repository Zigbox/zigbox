#!/usr/bin/env bash
# Signs the Zigbox packages and writes zigbox-repos.tar.gz. Shell, not Zig, because the program
# that signs is gpg (docs/STYLE.md, "The Linux package release") and this is only the glue
# between `zig build packages` and gpg. Both the release workflow and its test job run this
# file, so the tested code is the released code. Usage: .github/release-sign.sh OUTPUT_DIR
#
# Environment (never printed, never passed as an argument):
#   ZIGBOX_SIGNING_KEY         ASCII-armored secret subkey export (primary stubbed)
#   ZIGBOX_SIGNING_PASSPHRASE  the subkey's passphrase
#   ZIGBOX_SIGNING_FPR         fingerprint of the primary key; every signature must be by one of
#                              its subkeys, or the script fails
# Output: OUTPUT_DIR/zigbox-repos.tar.gz, and OUTPUT_DIR/zigbox-archive-keyring.{gpg,asc}.
# Run from the repository root. Needs zig, gpg, rpm. See docs/releases/packaging.md.
set -euo pipefail
# No `set -x`: this script handles the key.

output=${1:?usage: release-sign.sh OUTPUT_DIR}
: "${ZIGBOX_SIGNING_KEY:?ZIGBOX_SIGNING_KEY is not set}"
: "${ZIGBOX_SIGNING_PASSPHRASE:?ZIGBOX_SIGNING_PASSPHRASE is not set}"
: "${ZIGBOX_SIGNING_FPR:?ZIGBOX_SIGNING_FPR is not set}"
case "$ZIGBOX_SIGNING_FPR" in
  *[!0-9A-Fa-f]* | "") echo "release-sign: ZIGBOX_SIGNING_FPR is not a hex fingerprint" >&2; exit 1 ;;
esac
primary=${ZIGBOX_SIGNING_FPR^^}
[ "${#primary}" -eq 40 ] || { echo "release-sign: ZIGBOX_SIGNING_FPR is not 40 hex digits" >&2; exit 1; }

fail() { echo "release-sign: $*" >&2; exit 1; }

work=$(mktemp -d)
signing_home=$work/gnupg-sign
verify_home=$work/gnupg-verify
signatures=$work/signatures
mkdir -m 0700 "$signing_home" "$verify_home" "$signatures"
packages=zig-out/packages

# Remove every trace of the key, also when a step fails. The agent holds the key in memory.
cleanup() {
  local status=$?
  for home in "$signing_home" "$verify_home"; do
    GNUPGHOME=$home gpgconf --kill gpg-agent 2>/dev/null || true
  done
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

gpg_sign() { GNUPGHOME=$signing_home gpg --batch --no-tty --pinentry-mode loopback \
  --passphrase-file "$signing_home/passphrase" "$@"; }

# The passphrase goes in a 0600 file in the throwaway home; the key comes in on stdin.
(umask 077 && printf '%s' "$ZIGBOX_SIGNING_PASSPHRASE" > "$signing_home/passphrase")
printf '%s\n' "$ZIGBOX_SIGNING_KEY" | gpg_sign --import 2> "$work/import.log" ||
  { echo "release-sign: gpg could not import ZIGBOX_SIGNING_KEY" >&2; exit 1; }

# The one signing subkey, which must belong to the primary key named by ZIGBOX_SIGNING_FPR.
# A colon listing: `sec`/`sec#` opens the key, then `fpr` is its fingerprint; `ssb` opens a
# subkey (field 2 validity, field 12 capabilities), then its `fpr`.
listing=$(GNUPGHOME=$signing_home gpg --batch --list-secret-keys --with-colons 2>/dev/null)
subkey=$(awk -F: -v primary="$primary" '
  $1 == "sec" { section = "sec"; next }
  $1 == "ssb" { section = ($2 == "e" || $2 == "r") ? "bad" : (index($12, "s") ? "sign" : "other"); next }
  $1 == "fpr" && section == "sec" { top = $10; section = ""; next }
  $1 == "fpr" && section == "sign" { print $10; section = "" }
  END { if (top != primary) print "WRONG-PRIMARY" }
' <<< "$listing")
case "$subkey" in
  *WRONG-PRIMARY*) fail "the imported key is not by the primary key ZIGBOX_SIGNING_FPR" ;;
  "") fail "the imported key has no usable (unexpired, unrevoked) signing subkey" ;;
esac
[ "$(wc -l <<< "$subkey")" -eq 1 ] || fail "the imported key has more than one signing subkey"
subkey=${subkey^^}
echo "release-sign: signing subkey ${subkey: -16} of primary ${primary: -16}"

sign_with() { gpg_sign -u "${subkey}!" "$@"; }

# Round 1: each rpm's header, a binary detached signature named <rpm>.header.sig.
rm -rf "$packages"
zig build packages
headers=("$packages"/to-sign/*.header)
[ -e "${headers[0]}" ] || fail "zig build packages wrote no rpm header to sign"
for header in "${headers[@]}"; do
  sign_with --detach-sign -o "$signatures/${header##*/}.sig" "$header"
done

# Round 2: embed the header signatures, then sign the repository metadata.
zig build packages -Dsignatures="$signatures"
release=$packages/apt/dists/stable/Release
sign_with --clearsign -o "$signatures/InRelease" "$release"
sign_with -abs -o "$signatures/Release.gpg" "$release"
for architecture in x86_64 aarch64; do
  sign_with -abs -o "$signatures/repomd.$architecture.xml.asc" \
    "$packages/rpm/$architecture/repodata/repomd.xml"
done

# Final run places the signatures; the check reads the whole tree back.
zig build packages -Dsignatures="$signatures"
zig build packages-check -Dsignatures="$signatures"

# The public key, in the two forms zigbox.org serves. Taken from the signing home, so it
# carries the subkey the signatures are by. The secret key never leaves that home.
GNUPGHOME=$signing_home gpg --batch --export -a "$primary" > "$packages/zigbox-archive-keyring.asc"
GNUPGHOME=$signing_home gpg --batch --export "$primary" > "$packages/zigbox-archive-keyring.gpg"
[ -s "$packages/zigbox-archive-keyring.asc" ] || fail "the public key export is empty"

# Verify every signature against the exported public key alone, in a home with no secret key.
verify_gpg() { GNUPGHOME=$verify_home gpg --batch --no-tty --status-fd 1 "$@" 2> /dev/null; }
GNUPGHOME=$verify_home gpg --batch --import "$packages/zigbox-archive-keyring.gpg" 2> /dev/null
# GOODSIG, then VALIDSIG <signing fpr> ... <primary fpr> (the last field): by a subkey of the
# primary and not by the primary itself.
check_gpg() {
  local status
  status=$(verify_gpg --verify "$@") || fail "gpg --verify refused $*"
  grep -q '^\[GNUPG:\] GOODSIG ' <<< "$status" || fail "no good signature on $*"
  local fields
  fields=$(awk '$2 == "VALIDSIG" { print $3, $NF }' <<< "$status")
  [ -n "$fields" ] || fail "no valid signature on $*"
  [ "${fields#* }" = "$primary" ] || fail "$* is not by a subkey of ZIGBOX_SIGNING_FPR"
  [ "${fields% *}" != "$primary" ] || fail "$* is signed by the primary key, not a subkey"
  [ "${fields% *}" = "$subkey" ] || fail "$* is not by the signing subkey"
}
check_gpg "$packages/apt/dists/stable/Release.gpg" "$release"
check_gpg "$packages/apt/dists/stable/InRelease"
for architecture in x86_64 aarch64; do
  check_gpg "$packages/rpm/$architecture/repodata/repomd.xml.asc" \
    "$packages/rpm/$architecture/repodata/repomd.xml"
done

# rpm: import the same public key into a throwaway rpm database, check every rpm's header.
rpmdb=$work/rpmdb
mkdir -m 0700 "$rpmdb"
rpmkeys --dbpath "$rpmdb" --import "$packages/zigbox-archive-keyring.asc"
rpms=("$packages"/rpm/*/*.rpm)
[ "${#rpms[@]}" -eq 2 ] || fail "expected two rpms, found ${#rpms[@]}"
for rpm_file in "${rpms[@]}"; do
  report=$(rpm --dbpath "$rpmdb" -Kv "$rpm_file") || fail "rpm -Kv refused $rpm_file"
  if grep -Eiq 'NOT OK|BAD|MISSING|NOKEY' <<< "$report"; then
    fail "rpm -Kv found a bad signature on $rpm_file"
  fi
  key_id=${subkey: -8}
  grep -Eiq "Signature, key ID ${key_id}: OK" <<< "$report" ||
    fail "$rpm_file has no header signature by the signing subkey"
done

mkdir -p "$output"
tar -czf "$output/zigbox-repos.tar.gz" -C "$packages" \
  apt rpm zigbox-archive-keyring.gpg zigbox-archive-keyring.asc
cp "$packages/zigbox-archive-keyring.gpg" "$packages/zigbox-archive-keyring.asc" "$output/"
echo "release-sign: every signature verified; wrote $output/zigbox-repos.tar.gz"
