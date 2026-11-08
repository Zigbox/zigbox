# Packaging a release: the owner's runbook

`zig build packages` writes the `zigbox` deb and rpm for x86_64 and aarch64 and the apt and dnf
repository trees around them under `zig-out/packages/`. It never runs `gpg` and never holds the
release key: the owner signs in two rounds, on a machine that has the key. The output is
reproducible: the same inputs give the same bytes.

Inputs are the release `zbx` binaries (`zig build release`), `build.zig.zon`'s version and
`LICENSE`; the step wires them itself.

## Round 1: sign each rpm's header

```sh
zig build packages
```

This writes unsigned rpms and `zig-out/packages/to-sign/<rpm>.header`, and prints one command per
architecture. Sign each header with a binary (not armored) detached signature, and name it
`<rpm file>.header.sig` in a directory of your choice:

Start every release with an empty `$SIGNATURES` directory: `gpg --batch -o` will not overwrite,
so a directory kept from the last release leaves its files in place, and the tool refuses them.

```sh
mkdir -p $SIGNATURES
gpg --batch --detach-sign -u $KEY -o $SIGNATURES/zigbox-X.Y.Z-1.x86_64.rpm.header.sig \
    zig-out/packages/to-sign/zigbox-X.Y.Z-1.x86_64.rpm.header
# the same for aarch64
```

An armored signature is refused with a one-line message.

## Round 2: sign the repository metadata

```sh
zig build packages -Dsignatures=$SIGNATURES
```

This embeds the header signatures in the rpms, rewrites the trees (the rpm digests in the dnf
metadata now cover the signed files) and prints the metadata commands:

```sh
gpg --batch --clearsign -u $KEY -o $SIGNATURES/InRelease zig-out/packages/apt/dists/stable/Release
gpg --batch -abs -u $KEY -o $SIGNATURES/Release.gpg zig-out/packages/apt/dists/stable/Release
gpg --batch -abs -u $KEY -o $SIGNATURES/repomd.x86_64.xml.asc \
    zig-out/packages/rpm/x86_64/repodata/repomd.xml
gpg --batch -abs -u $KEY -o $SIGNATURES/repomd.aarch64.xml.asc \
    zig-out/packages/rpm/aarch64/repodata/repomd.xml
```

Then run the same step once more, so the signatures are placed:

```sh
zig build packages -Dsignatures=$SIGNATURES
zig build packages-check -Dsignatures=$SIGNATURES
```

`packages-check` reads the tree back and fails, with one line per problem, if any placed file
disagrees with the metadata that names it (`Release` against `Packages`, `Packages` against the
debs, `repomd.xml` against `primary.xml`, `primary.xml` against the rpms), a signature file is
missing, or a signature file does not sign the file beside it (`InRelease` and `Release.gpg`
against `Release`, each `repomd.<arch>.xml.asc` against its `repomd.xml`; also refused when the
four are not all by one key). The signing run makes the same check before it writes anything, so a
swapped or stale file is refused at the point it is placed. The check compares the 16 digest bits
a signature records, so it catches a swapped or stale file, not a forged one; it does not verify
the signatures with the public key. Do that in the next section.

Each run deletes `apt/`, `rpm/` and `to-sign/` under the output directory first, so the files
of an earlier run never stay beside this one's.

## Verify before publishing

Check all six signed files, on both architectures, with the release public key
(`release-key.asc` is its armored export):

```sh
T=zig-out/packages
gpg --verify $T/apt/dists/stable/Release.gpg $T/apt/dists/stable/Release
gpg --verify $T/apt/dists/stable/InRelease
gpg --verify $T/rpm/x86_64/repodata/repomd.xml.asc $T/rpm/x86_64/repodata/repomd.xml
gpg --verify $T/rpm/aarch64/repodata/repomd.xml.asc $T/rpm/aarch64/repodata/repomd.xml
rpmkeys --import release-key.asc      # on a scratch host or --root
rpm -Kv $T/rpm/x86_64/zigbox-X.Y.Z-1.x86_64.rpm
rpm -Kv $T/rpm/aarch64/zigbox-X.Y.Z-1.aarch64.rpm
```

Each `gpg --verify` must say `Good signature` from the release key, and each `rpm -Kv` must show
the header signature as OK. Then publish exactly `apt/` and `rpm/` from the last `packages` run, and
nothing else: not `to-sign/`, and not the test key files. Publish the release public key (armored)
beside them, and as `.gpg` for apt's `signed-by=`. Check a client with `apt update` and
`dnf makecache`.

The `Release` file has a fixed `Date` and no `Valid-Until`, and `repomd.xml` a fixed `revision`
(reproducibility): a client cannot tell an old signed `InRelease` from a new one, so there is no
replay or freeze protection.

## CI and the test key

`-Dtest-key` signs everything with a fixed key that vouches for nothing, and writes its public key
as `zigbox-test-key.asc` and `zigbox-test-key.gpg` beside the trees. `zig build packages -Dtest-key`
then `zig build packages-check -Dtest-key` (which recomputes every signature; Ed25519 is
deterministic) is the whole pipeline without the owner. Never publish a tree made this way.

## Known differences

- Fedora's rpm 6 refuses a signature from a key it has not imported: import the key first
  (`rpmkeys --import`), also for the test key.
- The dnf `primary.xml` has a fixed `<time file>` epoch (reproducibility), so it differs from
  `createrepo_c`'s output in that one attribute. `filelists` and `other` are byte-equal.
- The rpm carries no `PAYLOADDIGESTALT`.
