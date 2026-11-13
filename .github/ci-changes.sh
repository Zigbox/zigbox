#!/usr/bin/env bash
# Decides what ci.yml runs. Reads the changed paths, one per line, on stdin and writes
# `name=true|false` lines (to $GITHUB_OUTPUT, or stdout when that is unset):
#
#   code      the build, tidy, test, errors-site, fuzz and dbus-live jobs
#   demo_<d>  one VM demo, <d> in m0 m1 m2 m3 m4 m5 m6 m6b m7 m8 m8b
#   demo_m8_packages  the four-guest packages demo (demo-m8-packages): the package sources, the
#             packaging files and the packages harness (not the m8 demo's own rules)
#
# Environment: EVENT (github.event_name), HEAD_REF (the PR's head branch), LABELS (the PR's
# labels, space separated). See docs/decisions/2026-11-04-ci-affected-demos.md.
#
# The release workflow and its signing scripts select no demo. The rules err toward running.
# A path no rule below names runs every VM demo, but not the packages demo: that one runs only
# for the package files, the VM guests, the build and the workflow (docs/demos/m8.md).
set -euo pipefail

demos=(m0 m1 m2 m3 m4 m5 m6 m6b m7 m8 m8b)
declare -A want=()
want_packages=0

index_of() {
  local i
  for i in "${!demos[@]}"; do
    if [ "${demos[$i]}" = "$1" ]; then echo "$i"; return; fi
  done
  echo "changes: no demo $1" >&2
  exit 1
}

want_all() { local d; for d in "${demos[@]}"; do want[$d]=1; done; }
# Every demo and the packages demo: what the harness, the build or CI itself is made of.
want_everything() { want_all; want_packages=1; }
want_one() { want[$1]=1; }
# The demo and every later one: a demo repeats the parts of the demos before it.
want_from() {
  local i
  for ((i = $(index_of "$1"); i < ${#demos[@]}; i++)); do want[${demos[$i]}]=1; done
}

# Docs only: every path is a .md outside src/, or under site/ outside site/errors/ (the error
# pages are generated from the diagnostic registry and checked by the errors-site job).
is_docs() {
  case "$1" in
    src/*) return 1 ;;
    site/errors/*) return 1 ;;
    site/*) return 0 ;;
    *.md) return 0 ;;
  esac
  return 1
}

classify() {
  local p=$1 suffix
  case "$p" in
    # The release workflow, its own actions and the signing and refresh scripts run only after a push
    # to main (and the release test jobs on a throwaway key); no demo runs them, so they select none.
    .github/workflows/release.yml | .github/release-sign.sh | .github/release-sign-test.sh | \
      .github/release-prepare-check.sh | .github/release-prepare-test.sh | \
      .github/workflows/package-refresh.yml | .github/package-refresh.sh | \
      .github/package-refresh-test.sh | \
      .github/actions/setup-gh/* | .github/actions/find-draft/* | .github/actions/tap-formula/* | \
      .github/actions/mac-check-zip/*) return ;;
  esac
  case "$p" in
    # What the harness, the build or CI itself is made of: every demo.
    build.zig | build.zig.zon | .github/* | vm/* | src/testing/vm/lib/* | \
      src/testing/vm/alpine.zon | src/testing/vm/old_release.zon | src/testing/vm/zbx.lock | \
      src/testing/check.zig) want_everything; return ;;
  esac
  case "$p" in
    # Not part of any CI demo: the Mac build, the weekly top-20 run, the Z7 check, packaging, docs
    # and the site, and tests of the code (they never reach the zbx binary a demo runs).
    docs/demos/m*.md)
      suffix=${p#docs/demos/}; suffix=${suffix%.md}
      case "$suffix" in m0 | m1 | m2 | m3 | m4 | m5 | m6 | m6b | m7 | m8 | m8b) want_one "$suffix" ;; esac
      return ;;
    # The packages demo: the package sources, the packaging files and their harness. They set
    # no demo but demo-m8-packages.
    src/package.zig | src/package_*.zig | src/package/* | packaging/* | docs/releases/packaging.md) \
      want_packages=1; return ;;
    src/testing/vm/*m8_packages*) want_packages=1; return ;;
    src/mac/* | src/macos_main.zig | src/mac_release.zig | src/testing/mac* | \
      src/testing/vm/*top20* | src/testing/vm/*z7* | LICENSE | docs/* | site/* | *.md) return ;;
    src/*_tests.zig | src/*/*_tests.zig | src/fuzz*.zig | src/tidy.zig | src/errors_site.zig | \
      src/size_check.zig | src/testdata/* | src/*/fixtures/*) return ;;
    # A harness file named for a demo (checks_m3.zig, upgrade_m6b.zig, m7_project/): that demo and
    # every later one, which repeat its parts. The files named for no demo are shared.
    src/testing/vm/m8b/* | src/testing/vm/*_m8b.zig) want_one m8b; return ;;
    src/testing/vm/*_m8.zig | src/testing/vm/m8_*) want_one m8; return ;;
    src/testing/vm/m7_* | src/testing/vm/*_m7.zig) want_from m7; return ;;
    src/testing/vm/*_m6b.zig) want_from m6b; return ;;
    src/testing/vm/*_m6.zig) want_from m6; return ;;
    src/testing/vm/*_m5.zig) want_from m5; return ;;
    src/testing/vm/*_m4.zig) want_from m4; return ;;
    src/testing/vm/*_m3.zig) want_from m3; return ;;
    src/testing/vm/*_m2.zig) want_from m2; return ;;
    src/testing/vm/*_m1.zig) want_from m1; return ;;
    # The source areas only some demos exercise. Anything else under src/ is the runtime every
    # demo runs on.
    src/build/* | src/build_commands.zig) want_one m7; return ;;
    src/trust/* | src/push/*) want_one m8; return ;;
    src/registry/* | src/pull*.zig | src/lock_*.zig) want_from m4; return ;;
    src/state/* | src/*state*.zig) want_from m6; return ;;
    src/exec_commands.zig | src/logs_commands.zig | src/runtime/exec* | src/runtime/logfile.zig) want_from m6b; return ;;
    # Not src/doctor.zig: `doctor.subid_answer` chooses the id map of every container.
    src/doctor_fixtures.zig | src/image_diagnose.zig) want_one m0; return ;;
  esac
  want_all
}

docs_only=1
count=0
while IFS= read -r path; do
  [ -n "$path" ] || continue
  count=$((count + 1))
  is_docs "$path" || docs_only=0
  classify "$path"
done

full=0
if [ "${EVENT:-pull_request}" != pull_request ]; then full=1; fi
case "${HEAD_REF:-}" in claude/release-*) full=1 ;; esac
case " ${LABELS:-} " in *" full-ci "*) full=1 ;; esac
# No changed paths at all (a push with an empty diff) is not "docs only": run everything.
if [ "$count" -eq 0 ]; then full=1; fi

emit() { echo "$1=$2" >> "${GITHUB_OUTPUT:-/dev/stdout}"; }

if [ "$full" -eq 1 ]; then
  emit code true
  for d in "${demos[@]}"; do emit "demo_$d" true; done
  emit demo_m8_packages true
elif [ "$docs_only" -eq 1 ]; then
  emit code false
  for d in "${demos[@]}"; do emit "demo_$d" false; done
  emit demo_m8_packages false
else
  emit code true
  for d in "${demos[@]}"; do emit "demo_$d" "$([ -n "${want[$d]:-}" ] && echo true || echo false)"; done
  emit demo_m8_packages "$([ "$want_packages" -eq 1 ] && echo true || echo false)"
fi
