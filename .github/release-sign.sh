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
#   ZIGBOX_SIGNED_AT           optional: the one signing time (Unix seconds) of the release; the
#                              workflow sets it once. Default: now.
# Output: OUTPUT_DIR/zigbox-repos.tar.gz, OUTPUT_DIR/zigbox-archive-keyring.{gpg,asc}, and
#   OUTPUT_DIR/assets/: every release asset but the Mac zip (tarballs, SBOM, debs, rpms, the
#   archive), SHA256SUMS over them and SHA256SUMS.asc, its detached signature by the subkey.
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
# Only gpg needed these, once. Unset them so that zig, rpm and tar do not inherit them.
unset ZIGBOX_SIGNING_KEY ZIGBOX_SIGNING_PASSPHRASE

# One signing time for every round: the `Release` Date and its Valid-Until (21 days later) are in
# the signed bytes, so the three builds must agree. ZIGBOX_SIGNED_AT (Unix seconds) is for tests.
signed_at=${ZIGBOX_SIGNED_AT:-$(date +%s)}
case "$signed_at" in *[!0-9]* | "") fail "ZIGBOX_SIGNED_AT is not Unix seconds" ;; esac

# A key must stay valid this long after the signing time: Valid-Until (21 days, constants.apt_valid_seconds)
# plus 7 days to renew it. The same rule and messages as package-refresh.sh.
renew_seconds=2419200

# The one signing subkey, which must belong to the primary key named by ZIGBOX_SIGNING_FPR.
# A colon listing: `sec` opens the key (field 15 is `#` when the primary secret is a stub), then `fpr` is its fingerprint; `ssb` opens a
# subkey (field 2 validity, field 3 bits, field 4 algorithm, field 12 capabilities), then its
# `fpr`. The policy is RSA 4096 (algorithm 1) for both, as published.
listing=$(GNUPGHOME=$signing_home gpg --batch --list-secret-keys --with-colons 2>/dev/null)
subkey=$(awk -F: -v primary="$primary" -v at="$signed_at" -v window="$renew_seconds" '
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
  *SHORT-PRIMARY*) fail "the primary key expires within 28 days of the signing time (21 days of Valid-Until plus 7 to renew); the owner must renew it" ;;
  *SHORT-SUBKEY*) fail "the signing subkey expires within 28 days of the signing time (21 days of Valid-Until plus 7 to renew); the owner must renew it" ;;
  *PRIMARY-SECRET*) fail "the imported key holds the secret primary key; export the subkey alone with --export-secret-subkeys (docs/releases/packaging.md)" ;;
  *WEAK*) fail "the primary and the signing subkey must be RSA 4096 (docs/releases/packaging.md)" ;;
  "") fail "the imported key has no usable (unexpired, unrevoked) signing subkey" ;;
esac
[ "$(wc -l <<< "$subkey")" -eq 1 ] || fail "the imported key has more than one signing subkey"
subkey=${subkey^^}
echo "release-sign: signing subkey ${subkey: -16} of primary ${primary: -16}"

sign_with() { gpg_sign -u "${subkey}!" "$@"; }

# Round 1: each rpm's header, a binary detached signature named <rpm>.header.sig.
rm -rf "$packages"
zig build packages -Dsigned-at="$signed_at"
headers=("$packages"/to-sign/*.header)
[ -e "${headers[0]}" ] || fail "zig build packages wrote no rpm header to sign"
for header in "${headers[@]}"; do
  sign_with --detach-sign -o "$signatures/${header##*/}.sig" "$header"
done

# Round 2: embed the header signatures, then sign the repository metadata.
zig build packages -Dsigned-at="$signed_at" -Dsignatures="$signatures"
release=$packages/apt/dists/stable/Release
sign_with --clearsign -o "$signatures/InRelease" "$release"
sign_with -abs -o "$signatures/Release.gpg" "$release"
for architecture in x86_64 aarch64; do
  sign_with -abs -o "$signatures/repomd.$architecture.xml.asc" \
    "$packages/rpm/$architecture/repodata/repomd.xml"
done

# Final run places the signatures; the check reads the whole tree back.
zig build packages -Dsigned-at="$signed_at" -Dsignatures="$signatures"
zig build packages-check -Dsigned-at="$signed_at" -Dsignatures="$signatures"

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

# The other release assets and SHA256SUMS over them, then SHA256SUMS signed by the same subkey
# (the key is still loaded) and verified against the public key alone. The signed time is also
# the timestamp of the tar entries and the SBOM, so the whole release has one time.
zig build release-assets -Dpackages-dir="$packages" -Drepos-archive="$output/zigbox-repos.tar.gz" \
  -Dsource-date-epoch="$signed_at"
assets=zig-out/release-assets
[ -s "$assets/SHA256SUMS" ] || fail "release-assets wrote no SHA256SUMS"
sign_with --detach-sign --armor -o "$assets/SHA256SUMS.asc" "$assets/SHA256SUMS"
check_gpg "$assets/SHA256SUMS.asc" "$assets/SHA256SUMS"
rm -rf "$output/assets"
cp -R "$assets" "$output/assets"
echo "release-sign: every signature verified; wrote $output/zigbox-repos.tar.gz and $output/assets"
