#!/usr/bin/env bash
# The last check of a release draft, before it is published: the directory holds exactly the
# release's assets, each one matches its sums, SHA256SUMS.asc is a good signature by a subkey of
# the pinned release key, the apt metadata has time left, and the Mac formula agrees with the zip.
# The release workflow's `prepare` job and the `test` job both run this file. Writes nothing
# outside DIR. Prints one `release: ...` line to stderr and exits 1 on the first refusal.
#
# Usage: .github/release-prepare-check.sh DIR VERSION TAG REPOSITORY KEYRING
#   DIR         the draft's assets, downloaded; nothing is written there
#   KEYRING     the pinned public key, from the repository (never one from the draft)
# Environment:
#   ZIGBOX_SIGNING_FPR   the pinned fingerprint of the primary key (40 hex digits, upper case)
#   ZIGBOX_NOW           optional: the current time (Unix seconds); default now. For the test.
set -euo pipefail
# No `set -x`.

dir=${1:?usage: release-prepare-check.sh DIR VERSION TAG REPOSITORY KEYRING}
VERSION=${2:?version}
TAG=${3:?tag}
repository=${4:?repository}
keyring=${5:?keyring}
: "${ZIGBOX_SIGNING_FPR:?ZIGBOX_SIGNING_FPR is not set}"
min_days=14

fail() { echo "release: $*" >&2; exit 1; }

[[ "$ZIGBOX_SIGNING_FPR" =~ ^[0-9A-F]{40}$ ]] || fail "the pinned fingerprint is not 40 upper-case hex digits"
[ -s "$keyring" ] || fail "the pinned public key $keyring is missing from the repository"
dir=$(cd "$dir" && pwd)
keyring=$(cd "$(dirname "$keyring")" && pwd)/$(basename "$keyring")
work=$(mktemp -d)
trap 'GNUPGHOME=$work/verify-home gpgconf --kill all 2> /dev/null || true; rm -rf "$work"' EXIT
cd "$dir"
zip="zbx-$VERSION-macos-universal.zip"

# SHA256SUMS names the Linux assets: the two tarballs, the SBOM, the archive, and one deb and one
# rpm per architecture, all by exact name.
[ -s SHA256SUMS ] || fail "the draft has no SHA256SUMS"
awk 'NF != 2 || $1 !~ /^[0-9a-f]+$/ || length($1) != 64 { bad = 1 } END { exit bad }' SHA256SUMS ||
  fail "SHA256SUMS is not in sha256sum format"
linux=$(awk '{ print $2 }' SHA256SUMS | sort)
named=$(printf '%s\n' "zbx-$VERSION-linux-x86_64.tar.gz" "zbx-$VERSION-linux-aarch64.tar.gz" \
  "zbx-$VERSION.cdx.json" zigbox-repos.tar.gz \
  "zigbox_${VERSION}_amd64.deb" "zigbox_${VERSION}_arm64.deb" \
  "zigbox-$VERSION-1.x86_64.rpm" "zigbox-$VERSION-1.aarch64.rpm" | sort)
[ "$linux" = "$named" ] || fail "SHA256SUMS does not name exactly: ${named//$'\n'/ }"
want=$(printf '%s\n' "$linux" SHA256SUMS SHA256SUMS.asc SHA256SUMS.macos \
  "$zip" "$zip.sha256" zigbox.rb | sort)
have=$(/bin/ls -A | sort)
if [ "$want" != "$have" ]; then
  echo "release: the draft's assets are not exactly:" >&2
  printf '%s\n' "$want" >&2
  echo "but:" >&2
  printf '%s\n' "$have" >&2
  exit 1
fi
# The Linux sums match every file, and the Mac sums name the zip and nothing else. --strict: a
# malformed line is an error, not a skipped file.
sha256sum -c --strict SHA256SUMS > /dev/null || fail "a file does not match SHA256SUMS"
sha256sum -c --strict SHA256SUMS.macos > /dev/null || fail "the zip does not match SHA256SUMS.macos"
[ "$(awk '{ print $2 }' SHA256SUMS.macos)" = "$zip" ] || fail "SHA256SUMS.macos does not name exactly $zip"

# SHA256SUMS.asc: good, by a subkey (not the primary) of the pinned primary key. The public key is
# the repository's, never the draft's: a keyring inside the release under test would carry no
# revocation of a leaked subkey. The key must also be the pinned one.
mkdir -m 0700 "$work/verify-home"
export GNUPGHOME=$work/verify-home
gpg --batch --no-tty --no-autostart --import "$keyring" 2> "$work/import.log" ||
  fail "gpg could not import the pinned public key $keyring"
primaries=$(gpg --batch --no-autostart --list-keys --with-colons 2> /dev/null |
  awk -F: '$1 == "pub" { p = 1; next } $1 == "sub" { p = 0; next } $1 == "fpr" && p { print $10; p = 0 }')
[ "$primaries" = "$ZIGBOX_SIGNING_FPR" ] || fail "the public key in the repository is not the pinned release key"
status=$(gpg --batch --no-tty --no-autostart --status-fd 1 --verify SHA256SUMS.asc SHA256SUMS 2> /dev/null) ||
  fail "gpg refused SHA256SUMS.asc"
[ "$(grep -c '^\[GNUPG:\] GOODSIG ' <<< "$status")" = 1 ] || fail "no single good signature on SHA256SUMS"
fields=$(awk '$2 == "VALIDSIG" { print $3, $NF }' <<< "$status")
[ "$(wc -l <<< "$fields")" = 1 ] || fail "SHA256SUMS.asc is not exactly one signature"
[ "${fields#* }" = "$ZIGBOX_SIGNING_FPR" ] || fail "SHA256SUMS.asc is not by a subkey of the pinned release key"
[ "${fields% *}" != "$ZIGBOX_SIGNING_FPR" ] || fail "SHA256SUMS.asc is signed by the primary key, not a subkey"
unset GNUPGHOME

sha256sum -c --strict "$zip.sha256" > /dev/null || fail "the zip does not match its .sha256"
zip_sha=$(cut -d ' ' -f 1 "$zip.sha256")
formula_sha=$(sed -n 's/^ *sha256 "\([0-9a-f]\{64\}\)"$/\1/p' zigbox.rb)
[ "$zip_sha" = "$formula_sha" ] || fail "the formula's sha256 is not the zip's"
grep -qxF "  url \"https://github.com/$repository/releases/download/$TAG/$zip\"" zigbox.rb ||
  fail "the formula's url is not this release's zip"
grep -qxF "  version \"$VERSION\"" zigbox.rb || fail "the formula's version is not $VERSION"
[ "$(unzip -Z1 "$zip")" = zbx ] || fail "the zip holds more than zbx"

# The archive: what packaging.md says and nothing else. Its files are covered by the verified
# SHA256SUMS, so the Valid-Until in its Release is the signed one.
tar -tzf zigbox-repos.tar.gz > "$work/list"
grep -q '^apt/dists/stable/InRelease$' "$work/list" || fail "the archive has no apt InRelease"
grep -q '^zigbox-archive-keyring.gpg$' "$work/list" || fail "the archive has no keyring"
! grep -Evq '^(apt/|rpm/|zigbox-archive-keyring\.(asc|gpg)$)' "$work/list" || fail "the archive holds an unexpected file"
! grep -Eq '(^|/)\.' "$work/list" || fail "the archive holds a dot file"
! grep -Eq 'to-sign|test-key|passphrase|secret' "$work/list" || fail "the archive holds a file named like a secret"

# Freshness, at publish time: a late re-run of another job must not publish an apt Release that is
# near its Valid-Until (apt refuses an expired one until the next weekly refresh).
valid=$(tar -xzOf zigbox-repos.tar.gz apt/dists/stable/Release | sed -n 's/^Valid-Until: //p')
[ -n "$valid" ] || fail "the archive's apt Release has no Valid-Until"
valid_at=$(date -u -d "$valid" +%s 2> /dev/null) || fail "the archive's Valid-Until is not a date"
now=${ZIGBOX_NOW:-$(date +%s)}
left=$(( (valid_at - now) / 86400 ))
if [ "$(( valid_at - now ))" -lt $(( min_days * 86400 )) ]; then
  fail "the archive's apt Release is valid for $left more days (fewer than $min_days days are not enough); re-run the linux job"
fi
echo "prepare: the draft's assets, sums and signature are as they should be"
