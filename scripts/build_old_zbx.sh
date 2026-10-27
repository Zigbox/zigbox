#!/bin/sh
# Builds the x86_64 release `zbx` of an older commit, for the upgrade test of `zig build
# demo-m3`: a git worktree of <commit> under .zig-cache, `zig build release` in it (the same
# pinned Zig), and the stripped binary copied to <output>. Usage: build_old_zbx.sh <commit> <out>.
set -eu
commit=$1
output=$2
tree=.zig-cache/zbx-old-tree
if ! git cat-file -e "$commit^{commit}" 2>/dev/null; then
    echo "build_old_zbx: commit $commit is not in this clone (CI needs fetch-depth: 0)" >&2
    exit 1
fi
git worktree prune
if [ ! -d "$tree" ]; then
    git worktree add --quiet --force --detach "$tree" "$commit" >&2
fi
git -C "$tree" checkout --quiet --detach "$commit"
(cd "$tree" && zig build release >&2)
cp "$tree/zig-out/release/x86_64-linux/zbx" "$output"
