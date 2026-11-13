#!/usr/bin/env bash
# Runs .github/release-prepare-check.sh, the release's last gate, on a draft made from the output
# of release-sign-test.sh (throwaway key, real assets) plus a fake Mac zip and formula, and checks
# that it passes the honest draft and refuses each tamper with its reason. Nothing is attached.
# Usage: .github/release-prepare-test.sh SIGN_OUTPUT_DIR   (the directory release-sign-test.sh wrote)
set -euo pipefail

out=${1:?usage: release-prepare-test.sh SIGN_OUTPUT_DIR}
here=$(cd "$(dirname "$0")" && pwd)
check=$here/release-prepare-check.sh
work=$(mktemp -d)
trap 'GNUPGHOME=$work/other gpgconf --kill all 2>/dev/null || true; rm -rf "$work"' EXIT

die() { echo "release-prepare-test: $*" >&2; exit 1; }

cdx=$(ls "$out"/assets/zbx-*.cdx.json)
version=$(basename "$cdx" .cdx.json); version=${version#zbx-}
tag=v$version
repository=zigbox/zigbox
keyring=$out/zigbox-archive-keyring.gpg
fpr=$(gpg --batch --show-keys --with-colons "$keyring" |
  awk -F: '$1 == "fpr" { print $10; exit }')
zip=zbx-$version-macos-universal.zip

# The honest draft: the signed assets, and the Mac files the `mac` job attaches.
draft=$work/draft
mkdir "$draft"
cp "$out"/assets/* "$draft"/
(cd "$work" && printf 'zbx' > zbx && python3 -I -c \
  'import sys,zipfile; z=zipfile.ZipFile(sys.argv[1],"w"); z.write("zbx"); z.close()' "$draft/$zip")
(cd "$draft" && sha256sum "$zip" > "$zip.sha256" && cp "$zip.sha256" SHA256SUMS.macos)
cat > "$draft/zigbox.rb" <<RB
class Zigbox < Formula
  url "https://github.com/$repository/releases/download/$tag/$zip"
  sha256 "$(cut -d ' ' -f 1 "$draft/$zip.sha256")"
  version "$version"
end
RB

run() { # run DIR [env assignments]: the check, on DIR, with the real key; stderr and status kept
  local d=$1; shift
  env "ZIGBOX_SIGNING_FPR=$fpr" "$@" "$check" "$d" "$version" "$tag" "$repository" "$keyring" 2>&1
}
fresh() { rm -rf "$work/case"; cp -R "$draft" "$work/case"; echo "$work/case"; }
pass() { # pass NAME [env assignments]
  local name=$1; shift
  local d; d=$(fresh)
  run "$d" "$@" > "$work/log" || { cat "$work/log" >&2; die "refused the honest draft ($name)"; }
  echo "ok: accepted: $name"
}
refuse() { # refuse NAME PATTERN DIR [env assignments]
  local name=$1 pattern=$2 d=$3; shift 3
  if run "$d" "$@" > "$work/log"; then die "accepted: $name"; fi
  grep -q '^release: ' "$work/log" || { cat "$work/log" >&2; die "no one-line reason: $name"; }
  grep -q -- "$pattern" "$work/log" || { cat "$work/log" >&2; die "wrong reason: $name (wanted '$pattern')"; }
  echo "ok: refused: $name"
}

pass "the honest draft"

d=$(fresh); deb=$(ls "$d"/*_amd64.deb); printf 'x' >> "$deb"
refuse "a changed deb" 'does not match SHA256SUMS' "$d"

d=$(fresh); a=$(ls "$d"/*_amd64.deb); b=$(ls "$d"/*_arm64.deb)
mv "$a" "$d/tmp"; mv "$b" "$a"; mv "$d/tmp" "$b"
refuse "swapped debs" 'does not match SHA256SUMS' "$d"

# An edited tarball with its line in SHA256SUMS edited to match: only the signature catches it.
d=$(fresh); tgz=$(ls "$d"/zbx-*-linux-x86_64.tar.gz); printf 'x' >> "$tgz"
(cd "$d" && grep -v -F "${tgz##*/}" SHA256SUMS > s; sha256sum "${tgz##*/}" >> s; mv s SHA256SUMS)
refuse "an edited SHA256SUMS" 'gpg refused SHA256SUMS.asc' "$d"

d=$(fresh); rpms=("$d"/*.rpm); rm "${rpms[0]}"
refuse "a missing file" 'not exactly' "$d"

d=$(fresh); : > "$d/extra"
refuse "an extra file" 'not exactly' "$d"

d=$(fresh); rm "$d/SHA256SUMS.asc"
refuse "a missing signature" 'not exactly' "$d"

# A signature by a key that is not the release key, over the honest SHA256SUMS.
mkdir -m 0700 "$work/other"
GNUPGHOME=$work/other gpg --batch --no-tty --passphrase '' --pinentry-mode loopback \
  --quick-generate-key "Other <other@invalid>" rsa2048 sign 1d 2> /dev/null
d=$(fresh); rm "$d/SHA256SUMS.asc"
GNUPGHOME=$work/other gpg --batch --no-tty --detach-sign --armor -o "$d/SHA256SUMS.asc" "$d/SHA256SUMS" 2> /dev/null
refuse "a signature by another key" 'gpg refused SHA256SUMS.asc' "$d"

# The keyring is the repository's, not the draft's: the honest draft against another key's
# keyring, pinned to that key, is refused; and the pin must match the keyring.
GNUPGHOME=$work/other gpg --batch --export "$(GNUPGHOME=$work/other gpg --batch --list-keys --with-colons |
  awk -F: '$1 == "fpr" { print $10; exit }')" > "$work/other.gpg"
other_fpr=$(gpg --batch --show-keys --with-colons "$work/other.gpg" | awk -F: '$1 == "fpr" { print $10; exit }')
d=$(fresh)
if env "ZIGBOX_SIGNING_FPR=$other_fpr" "$check" "$d" "$version" "$tag" "$repository" "$work/other.gpg" \
  > "$work/log" 2>&1; then die "accepted: the draft against another key's keyring"; fi
grep -q 'gpg refused SHA256SUMS.asc' "$work/log" || { cat "$work/log" >&2; die "wrong reason: another key's keyring"; }
echo "ok: refused: the draft against another key's keyring"
d=$(fresh)
if env "ZIGBOX_SIGNING_FPR=$fpr" "$check" "$d" "$version" "$tag" "$repository" "$work/other.gpg" \
  > "$work/log" 2>&1; then die "accepted: a keyring that is not the pinned key"; fi
grep -q 'not the pinned release key' "$work/log" || { cat "$work/log" >&2; die "wrong reason: wrong keyring"; }
echo "ok: refused: a keyring that is not the pinned key"
if env "ZIGBOX_SIGNING_FPR=$fpr" "$check" "$(fresh)" "$version" "$tag" "$repository" "$work/none.gpg" \
  > "$work/log" 2>&1; then die "accepted: no keyring"; fi
grep -q 'missing from the repository' "$work/log" || { cat "$work/log" >&2; die "wrong reason: no keyring"; }
echo "ok: refused: no keyring in the repository"

d=$(fresh)
if env "ZIGBOX_SIGNING_FPR=${fpr:0:39}A" "$check" "$d" "$version" "$tag" "$repository" "$keyring" \
  > "$work/log" 2>&1; then die "accepted: a wrong pin"; fi
grep -q 'not the pinned release key' "$work/log" || { cat "$work/log" >&2; die "wrong reason: wrong pin"; }
echo "ok: refused: a wrong pinned fingerprint"

# Freshness, from the archive's own Valid-Until.
valid=$(tar -xzOf "$draft/zigbox-repos.tar.gz" apt/dists/stable/Release | sed -n 's/^Valid-Until: //p')
valid_at=$(date -u -d "$valid" +%s)
pass "14 days left" "ZIGBOX_NOW=$(( valid_at - 14 * 86400 ))"
d=$(fresh)
refuse "13 days left" 'fewer than 14 days are not enough' "$d" "ZIGBOX_NOW=$(( valid_at - 13 * 86400 ))"
refuse "an expired Release" 'fewer than 14 days are not enough' "$d" "ZIGBOX_NOW=$(( valid_at + 86400 ))"

echo "release-prepare-test: all cases passed"
