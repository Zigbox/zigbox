# Brief: M8 · Trust and Linux packages

Read these first:
- `AGENTS.md`, `REVIEW.md`, `docs/STYLE.md` and `DIAGNOSTICS.md` (codes `09xx` are reserved for trust and policy; none is registered yet).
- The M8 section of `docs/SPEC.md` (snapshot of live doc rev 86; the M8 section, "Production readiness", "Agent operability" and Zigcube's C6 read the same in rev 91), and C6 in Part II, which reuses M8's checks on every node.
- `docs/briefs/linux-packages.md` and the decisions `2026-11-04-linux-packages.md`, `-linux-packages-in-m8.md`, `-package-split.md`, `-package-signing-hosting.md` and `-release-0.3.1.md`. They are settled. This brief folds them in and does not reopen them.
- `docs/demos/m3.md` (what a tree digest holds), `docs/demos/m7.md` (the build record, the result digest, the cut `build` root and why the image cache entry keeps the tree), `docs/decisions/2026-11-04-z4-image-record-peer.md` (image records to and from a peer), and Z9's `2026-11-04-z9-chunk-read-outside.md` on its branch (reading objects outside the store's namespace).
- `src/build/key.zig` and `src/build/cache.zig` (each cache entry keeps the key's preimage "so M8 can write provenance without rebuilding"), `src/build/result.zig`, `src/store/tree.zig`, `src/store/object.zig`, `src/store/verify.zig`, `src/store/walk.zig`, `src/store/images.zig`, `src/store/image_peer.zig`, `src/store/gc.zig`, `src/store/layout.zig`, `src/run_image.zig`, and `run_container` in `src/cli.zig`.

`demo-m0` to `demo-m7`, the top-20 check and the Mac demos must keep passing. M8 has two independent parts: **trust** (keys, signatures, provenance, policy and verify) and **packages** (the `zigbox` deb and rpm and their repositories). They share almost no code and run as two lanes of slices (see Slices).

## Goal and demo (from the spec, live doc rev 91, plus packages)

A host can refuse to run anything it cannot trace back to a trusted key and a recorded build. `zbx` installs from signed apt and dnf repositories.

1. Build and sign an image. `zbx inspect --provenance <digest>` shows its inputs and builder.
2. Enable the policy `require signature`. The signed image runs. An unsigned `alpine` is refused, and the refusal names the policy rule.
3. Tamper with one file in the stored tree. `zbx run` refuses, because the tree digest no longer matches the signature.
4. `zbx verify <digest>` walks offline from the signature to every input.
5. **(Packages, owner 2026-11-04.)** On Ubuntu 24.04, Debian 12, current Fedora and Rocky (or Alma) 9: add the repository and its key with the README's commands, `apt install zigbox` or `dnf install zigbox`, `zbx version` prints the release, an upgrade to a newer test build happens in place, and removing the package leaves the store. `apt update` and `dnf makecache` report no signature warning.

Acceptance criteria:
- Signatures are over tree digests, so they survive re-pulls and re-materialization.
- Policy refusals happen before any process starts. The brief reads this as "before any workload process". The store's namespace child, which every store command already uses, may run (spec note).
- The packages are byte-for-byte reproducible from a commit. They are built with the standard library and no distro tooling. CI never signs or publishes.
- The production-readiness checklist: an upgrade test against the latest tag (0.3.1 once it is cut, else 0.3.0) covering the store, run records and build cache it wrote; stable diagnostics; documented failure modes; the agent test.

## Threat model (fixed)

M8 is meant to stop three things:
- running a tree that no trusted key vouched for;
- running a tree whose bytes changed after it was signed (disk damage, a process writing into the store, a store or peer copy that was altered);
- treating a claim as a record. Provenance counts only when a trusted signature covers it.

M8 does not stop someone acting as the same Unix user. That person can edit the user's own policy, keys and store, or race the check against `execve`. The **system policy** `/etc/zbx/policy.zon` is owned by root and cannot be loosened by the user. It is what binds an agent or a user to a rule (spec, "Limits an agent cannot flag its way past"). Zigcube's agents run as root with node-local keys (C6). `docs/demos/m8.md` says all this in plain words.

## Fixed decisions (trust)

### Keys

- `zbx key new <name>` makes an Ed25519 key pair with `std.crypto.sign.Ed25519`. The key comes from the OS's random source; no deterministic seed is ever used outside tests. Names are `[a-z0-9-]`, at most 32 bytes. An existing name is refused (`E0902`), never overwritten.
- **Where** (open question 1, recommended): `$XDG_CONFIG_HOME/zbx/keys/` (default `~/.config/zbx/keys/`). The directory has mode `0700`. `<name>.key` holds the secret key with mode `0600`, and `<name>.pub` holds the public key. A secret key file readable by group or others is refused when used (`E0901`), as ssh does. The store is the wrong place for keys: peers write into it.
- **The key file** is a small versioned text record (`.version = 1`, `.algorithm = "ed25519"`, `.encryption = "none"`, `.secret = "<hex>"`). The `encryption` field exists from the first version, so a passphrase (open question 1) is a new value, not a new format.
- **The public key's text** is `zbx-ed25519:<64 hex>`. **The key id** is BLAKE3 over `"zbx-key\x00"` and the 32 public-key bytes, written as 64 hex digits, and always compared in full: no ids are matched by prefix (spec, Agent operability).
- `zbx key list` and `zbx key show <name>` print the name, id and public text, in text and in `--output json` (schema `zbx.key/1`). No command ever prints a secret key.

### What is signed

- **The statement** is a canonical, length-prefixed binary encoding, in the style of the build key. It holds:
  - the magic `"zbx-statement\x00"`;
  - a statement-format version;
  - the **subject tree digest** (always present);
  - an optional **binding**, one of: the M7 result digest, which commits to the tree and its config, or the image's manifest digest (`sha256:`), which commits to the OCI config;
  - an optional **provenance digest**;
  - the signer's key id;
  - a claimed signing time, in seconds.

  Ed25519 signs exactly these bytes. The statement is the same on every machine, so a signature made on one host verifies on another.
- **Why the binding.** The spec signs tree digests. A tree-only signature would let anyone run the signed tree with any entrypoint, user or environment. So `zbx sign <result digest>` and `zbx sign <name>@sha256:<manifest>` bind the config, and `zbx sign <tree digest>` signs the tree alone. At run time a statement with a binding counts only when the run uses that same result or manifest. A tree-only statement counts for any config (spec note).
- **`zbx sign <digest> [--key <name>]`** resolves the operand as `zbx run` does (a result digest, then a tree digest, then a digest image reference). It checks the tree first: the tree must be whole and every object must hash to its id (the run-time check below, uncached). Then it signs. A tree that is not whole is refused (`E0910`). Signing what you have not checked is how damage gets vouched for. When the subject has a provenance record, the statement names that record's digest. `--key` defaults to the only key when there is exactly one; otherwise it is required. `--output json` prints `zbx.sign/1`.
- **The signature record** is `trust/signatures/<tree hex>` in the store. It is a text record in the image-record style, holding up to `signatures_per_tree_max` (a constant, 8) entries. Each entry has the statement's fields, the public key and the signature. It is rewritten by atomic rename under the store lock. Signing the same statement again with the same key changes nothing. The record is keyed by the tree, so a re-pull of the same image, a new farm or another manifest for the same tree all find it.
- Verification uses `Signature.verify` (measured at about 120 µs per signature here), never a check written by hand.

### Provenance

- **What and when.** Every successful `zbx build` writes a provenance record for its result, whether the build was all hits or not. Everything in it comes from what the build already holds: each step's cache entry (the key preimage, which includes the base tree and its env, the input tree digest, each needed step's output digest, argv, env and network) and the build record. M7's step logs are not in it.
- **Fields** (`.version = 1`):
  - **subject:** the result digest and the tree digest.
  - **builder:** `zbx` version, release commit and platform, plus the BLAKE3 of the running `zbx` binary (read from `/proc/self/exe`).
  - **build file:** its project-relative path and the BLAKE3 of its bytes.
  - **lock:** the BLAKE3 of `zbx.lock`.
  - **bases:** each locked base as reference, manifest digest and tree digest.
  - **steps:** each step's name, key, input tree, `needs` with output digests, output tree and `network`.
  - **image assembly:** its key.
  - **times:** the build's start and end time.
  - **source:** optional, cuttable. The project's git commit and whether the tree is clean, read from `.git` directly (`HEAD`, refs and `packed-refs`; no `git` program) and present only when the project directory is a git checkout.

  None of this changes the result digest (M7). A record has at most `provenance_steps_max` steps (a constant, equal to M7's step bound) and `provenance_bytes_max` bytes.
- **Where.** `trust/provenance/<result hex>` in the store, written by atomic rename. The record's identity, its **provenance digest**, is BLAKE3 over its canonical bytes. A later build of the same result replaces the record: a comment changed in the build file is a new record for the same result. A signature names the provenance digest it saw, so a replaced record no longer satisfies `require provenance` until the result is signed again. `zbx inspect --provenance` says so.
- **`require provenance`** means *signed* provenance: a statement from a trusted key that names this tree's provenance digest, and a record present with that digest. An unsigned record is shown by `inspect`, but no policy accepts it.
- **`zbx inspect --provenance <digest>`** takes a result digest. Text form (the goldens hold full digests; they are shortened here):

```
$ zbx inspect --provenance b3:55077a8f…df62
result      b3:55077a8f…df62
tree        b3:91e04c1d…a7b0
builder     zbx 0.4.0 (63b2f33) linux/amd64  binary b3:0c9d…
build file  zbx.build.zon  b3:1c2f…
lock        zbx.lock       b3:77ab…
base        golang:1.23-alpine  sha256:4e1a…  tree b3:a1c3…
base        alpine:3.20         sha256:beef…  tree b3:2f7e…
step        compile  key 9f3e…  inputs b3:…  output b3:…
step        notice   key 41aa…  inputs b3:…  output b3:…
image       key 0d12…
built       2026-11-12T10:41:07Z, 10.2 s
source      git 4f2a9c1, clean
signed      demo  3b6a…(key id)  2026-11-12T10:41:30Z  covers this record
```

  `--output json` prints `zbx.provenance/1`. Its members are named after SLSA provenance v1: `buildDefinition.buildType`, `externalParameters` (the build file and lock), `resolvedDependencies` (the bases and inputs, with `{"blake3": …}` and `{"sha256": …}` digest sets), `runDetails.builder.id`, `runDetails.metadata` and `byproducts` (the steps). A later in-toto export is then a translation, not a redesign (open question 2).

### The policy file

- **Where.** `/etc/zbx/policy.zon` (the system file, written by root) and `$XDG_CONFIG_HOME/zbx/policy.zon` (the user's). Every file present applies, and a run must pass each one on its own. With no file present, nothing changes from 0.3: no check runs and nothing costs anything. Neither an environment variable nor a flag names another policy file, since that would be a way to flag past it.
- **What it says.** It is a restricted ZON, read with M7's hand-written, bounded build-file parser (the same reader, a different schema):

```zig
.{
    .version = 1,
    .keys = .{
        .{ .name = "release", .public = "zbx-ed25519:3b6a…" },
    },
    .require_signature = true,   // a trusted statement for the tree, binding matching
    .require_provenance = false, // a trusted statement naming a present provenance record
    .verify = "cached",          // "cached" (default) or "always": the tamper check below
}
```

  Bounds: `policy_keys_max` (16) and the file size. Both are in `constants.zig`. A key listed twice, an unknown field and a malformed public key are all refused with line and column (`E0904`). `require_provenance` implies a signature.
- **`zbx policy check <digest>`** prints the verdict `zbx run` would reach, with each file, each rule and each signature examined, and why each counts or not (untrusted key, binding for another config, bad signature). It runs nothing. Its JSON is `zbx.policy/1`. This is the preview an agent needs (spec, "Preview before acting"), and it is the same pure function `run` calls.

### Where the checks run

- **`zbx run`.** The check sits in `run_container` (`src/cli.zig`), after `run_image.prepare` has the tree and the result or manifest, and before `runtime.start` builds anything. A refusal leaves no run record, cgroup, scope or log behind, and exits 125.
  - The **policy verdict** is a pure function over the policy files, the tree's signature record and the provenance record. It is cheap.
  - The **tamper check** runs in the store's namespace child, because objects owned by container ids can only be read there; Z9 reads them outside only for one-chunk owners. It then reaches the materialization step that `image.prepare` already does. It is one store child, so there is no new process kind.
  - Order: verdict, then tamper check, then start.
- **A tag that is not in the lock** is pulled before the check (`run_image.zig`, `via_lock`). Pulling runs no image code, so this stays, and the check follows the pull.
- **`zbx exec`** (open question 3, recommended): the policy verdict on the container's tree and binding from its run record. There is no re-hash, because the container is running and its lower layer was checked when it started. A container started before the policy existed and not satisfying it is refused with the same code. Pausing or stopping it is not exec's business.
- **`zbx build`** (open question 3, recommended): each step's base is checked like a run's tree before the step's container starts, and a refusal names the step. A step is a container running the base image's code. Users who turn on `require_signature` sign their bases (`zbx sign alpine@sha256:…`). Cache hits run nothing and are not checked.
- **`zbx pull`** is not gated (open question 3).

### The tamper check (verify-on-run)

- **What.** It walks every object the tree reaches (`walk.objects`) and recomputes each object's id from its bytes, mode, owner and xattrs, as `store verify` does (shared code). Trees are already re-hashed on load. The first mismatch refuses the run with `E0907`, naming the path in the image, the object and what differs (bytes, mode or owner). Materialized farms are hardlinks to the objects, so the farm and the store are one inode and one check covers both.
- **The cost, measured.** `std.crypto.hash.Blake3` with pinned Zig 0.17.0, `ReleaseSafe`, on one thread of a 2.1 GHz Xeon (the cloud container) runs at:
  - **about 1.2 GB/s** for the shipped baseline-CPU x86_64 build;
  - 2.1 GB/s with native CPU features;
  - the same speed for 16 KiB pieces as for 256 MiB.

  So a full re-hash of a warm tree costs about 7 ms for `alpine` (8 MB), about 0.4 s for `postgres:16` (about 430 MB) and about 0.7 s for `golang:1.23` (about 800 MB). A cold page cache adds the disk read. The store child is single-threaded until `execve` (AGENTS.md), so the hash runs on one thread.
- **What we do** (open question 5, recommended: `cached`):
  - The first checked run of a tree hashes everything.
  - It then writes `trust/verified/<tree hex>`: one entry per object, holding `(object id, inode, size, ctime_ns)`, bounded by `entries_max`. Later runs `lstat` each object and compare all four fields for equality.
  - Any write, `chmod`, `chown`, link or unlink sets an inode's ctime to the current time. An unprivileged user cannot set ctime back. So an object whose fields changed is re-hashed, and only that object. A clock stepped backwards cannot forge equality.
  - Estimate: `lstat` costs about 1 to 2 µs warm, so about 20 to 40 ms for a 20,000-file image.
  - Spurious invalidation is the safe direction. A new farm (a new hardlink), gc removing a farm, and `materialize`'s one-time `utimensat` all bump ctime and cause a re-hash once.
  - `verify = "always"` re-hashes on every run.
  - The record is a cache, not a trust source. A damaged or newer record is ignored and rewritten. It is never a root, and gc removes it with its tree.
- **Accepted limit:** the gap between the check and `execve` (same-user race; see Threat model).

### `zbx verify <digest>`

Offline by construction: no registry, no network, no `zbx.lock` resolution. It walks the chain and stops at the first broken link (`E0908`), naming it:
1. the signature record exists, and each statement verifies against its public key;
2. at least one key is trusted by every policy file present. With no policy file, `--key <name>` or `--public <text>` names the key to trust. Without either, verify reports the signers and exits 1;
3. the tree is whole and every object hashes to its id, uncached;
4. the provenance record named by the statement is present and has that digest;
5. every input the record names (each base tree, each step's input and output tree, the image assembly's output) is present and sound;
6. if the build file and lock named by the record are in the working directory's project, their hashes match. If they are not, that is reported but is not a failure.

An input that is absent, because gc took it, is `W0901` (it cannot be checked offline) and fails only with `--strict`. A damaged input is `E0908`. Output: one line per link in text, and `zbx.verify/1` in JSON with every link's status. A simulation test asserts that `verify` makes no network or registry call (`host_sim` records them).

### Records, gc, export and import (open question 6, recommended)

- **gc.** Signature and provenance records are not roots, and **gc never removes them**. They are small and bounded (`trust_records_max`), and keeping them is what makes a signature survive gc followed by a re-pull of the same image (the spec's criterion). `trust/verified/` entries go with their tree. `zbx store gc` lists the orphan count. Pruning orphans is a later command.
- **Export and import.** `zbx trust export <digest>` writes the subject's signature and provenance records as one bounded text bundle on stdout. `zbx trust import <file>` stores it. Import checks the size, parses, verifies every signature cryptographically, and checks that each provenance digest a statement names matches the bundle's record. It then merges the entries into the local record under the store lock. A bundle with any bad signature is refused whole (`E0909`), writing nothing. Signatures by keys this host does not trust are kept, because trust is decided at run time by policy, not at import. Without push (a spec non-goal until after M8), this is how a signature made on a build machine reaches the host that pulls the same image.
- **For Zigcube.** `store.export_trust(store, memory, tree, out, failure)` and `store.import_trust(store, memory, text, tree, failure)` sit beside Z4's `export_image` and `import_image` in the library, with the same shape: caller memory, a `Refusal`, one coded diagnostic. Z4's functions do not change, so C2 keeps working. C6 calls the new pair when it fetches a tree from a peer, and the node's own policy check runs at exec (spec, "Trust checked twice").

### Diagnostics (`09xx`, each with cause, fix, goldens and an error page)

- `E0901` a key can't be used: missing, unreadable, malformed, of a newer format, or with a secret file readable by others (fix: `chmod 600 <path>`).
- `E0902` a key with that name already exists (fix: choose another name; the old key is never overwritten).
- `E0903` a signature or provenance record in the store is damaged or of a newer format (blame environment; fix: `zbx trust import` again or sign again; "upgrade zbx" for newer).
- `E0904` a policy file can't be read or parsed (its path, line, column and what was expected).
- `E0905` a run is refused because no trusted signature covers it. It names the policy file and the rule (`require_signature`), the digest, and in the cause each signature present and why it does not count. Fix: `zbx sign <digest>`, or add the signer's key to the named file. Exit 125.
- `E0906` a run is refused because no signed provenance covers it (`require_provenance`). It says whether the record is missing, unsigned or replaced since signing. Exit 125.
- `E0907` the tree no longer matches its digest (blame environment). It names the image path, the object and what differs. Fix: `zbx store verify`, then remove the damaged tree and pull or build again. Exit 125 from `run`.
- `E0908` `zbx verify` found a broken link (which link and why).
- `E0909` a trust bundle is refused (size, malformed, a bad signature, a provenance digest that does not match).
- `E0910` signing is refused: the digest is not in the store, or its tree is not whole or sound.
- `W0901` `zbx verify` could not check an input that is not in the store.

DIAGNOSTICS "Exit codes" applies: `run` uses 125 for its refusals, and every other command uses 1 or 2 by blame. Errors from the packaging step (`zig build packages`) are build-tool errors, one `package: ...` line each, like the harness's `VM-F` codes, and are not product codes.

### CLI and agents

New commands: `key new|list|show`, `sign`, `verify`, `trust export|import`, `policy check`, and the `--provenance` flag of `inspect`. Each has `help`, `zbx schema` (`zbx.key/1`, `zbx.sign/1`, `zbx.verify/1`, `zbx.trust/1`, `zbx.policy/1`, `zbx.provenance/1`), goldens, and the error documents of its refusals (REVIEW.md, "Every new command"). Nothing prompts. The agent test drives the trust part of the demo with JSON, `zbx policy check` and `zbx explain` only.

## Fixed decisions (packages, from linux-packages.md and the 2026-11-04 decisions)

- **One package, `zigbox`, per architecture** (`amd64`/`x86_64`, `arm64`/`aarch64`). It holds the static ReleaseSafe `zbx` from `zig build release` at `/usr/bin/zbx`, the licence (`/usr/share/doc/zigbox/copyright` or `/usr/share/licenses/zigbox/LICENSE`) and a man page if one exists by then. It has no maintainer scripts beyond what the formats require. Weak dependencies only: the deb says `Recommends: uidmap, passt`; the rpm says `Recommends: shadow-utils, passt`. `/etc/subuid` and `/etc/subgid` are not touched.
- **The package writer is a module, `zigbox_package`** (`src/package/`), exported from `build.zig` as `zigbox_vm` is, because Zigcube's C3 imports it from the pinned `zigbox` package to build the `zigbox` omnibus and the `zigcube-*` role packages. Its caller describes each package (name, version, architecture, files as `{path, mode, bytes or source path}`, recommends, summary and description). It knows nothing about `zbx`. It provides:
  - `ar`, and `tar` through `std.tar.Writer`;
  - `cpio` `newc`;
  - gzip through `std.compress.flate`;
  - the `.deb` writer (`debian-binary`, `control.tar.gz`, `data.tar.gz`);
  - the `.rpm` writer: lead, signature header, header with the file-list tags, `RECOMMENDNAME`, SHA-256 file digests and a SHA-256 payload digest, and a gzip'd cpio payload;
  - the apt repository writer (`dists/stable/Release`, `main/binary-<arch>/Packages` and `.gz`, `pool/`);
  - the dnf repository writer (per `$basearch`: `repodata/repomd.xml`, `primary.xml.gz`, `filelists.xml.gz`, `other.xml.gz`, all with SHA-256);
  - ASCII armor;
  - OpenPGP v4 Ed25519 signature packets (test signing; below).

  All output is reproducible: mtimes fixed at `SOURCE_DATE_EPOCH` (`constants.build_source_date_epoch`), entries sorted, owner `root:root`, and gzip with a fixed header. Every bound is in `constants.zig`.
- **`zig build packages`** writes `zig-out/packages/` with both packages per architecture, the two repository trees and a `to-sign/` list. Building twice gives identical bytes; a test asserts that.
- **Signing on the owner's machine, at release time only** (settled). It takes two rounds of `gpg`, because a signed rpm's file changes the repository's checksums:
  1. `zig build packages` writes unsigned rpms and prints the header-signing commands (`gpg --detach-sign` over each rpm's header bytes, written to `to-sign/`). The owner runs them.
  2. `zig build packages -Dsignatures=<dir>` embeds each header signature (`RPMSIGTAG_RSA`, 268, which carries any OpenPGP signature), recomputes nothing in the header, then writes `Release` and `repomd.xml` and prints the second round: `gpg --clearsign` (→ `InRelease`), `gpg -abs` (→ `Release.gpg`) and `gpg -abs repomd.xml` (→ `repomd.xml.asc`).
  3. A last `zig build packages-check -Dsignatures=<dir>` checks every placed file's digest against the metadata.

  The release step prints the commands; it never runs `gpg` (STYLE.md). The archive key is separate from M8's image keys. `docs/releases/packaging.md` is the owner's runbook.
- **Hosting: GitHub Pages** (settled), at `/apt` and `/rpm`, with `zigbox-archive-keyring.gpg` and `.asc` beside them. The README gains the install commands (`signed-by=` keyring for apt; a `.repo` file with `gpgcheck=1` and `repo_gpgcheck=1` for dnf). How the owner-signed tree reaches Pages without CI signing or building it is open question 8.
- **CI** builds the packages on every pull request that touches `src/package/` or the release step, checks reproducibility, and runs the packages demo. It signs with the **test key** (open question 7), never the archive key, and publishes nothing.

## In the library

`zigbox.trust` exports pure functions, with per-caller storage and no process-wide state:
- the statement encoding, `sign` and `verify`;
- the key and public-key text;
- the policy parser and the verdict function;
- the signature, provenance and trust-bundle records;
- the tamper check over a store.

Zigcube's C6 admission (server) and node check (agent) call the same verdict function. A test drives the verdict and `import_trust` from a caller other than the CLI, as M7's `build_library_tests.zig` does. `zigbox_package` is a separate module.

## Slices (commit and stop for review after each; do not push to the working branch)

Two lanes. **Lane T (trust)** is slices 1 to 4, in order. **Lane P (packages)** is slices 5 and 6, in order. The lanes run in parallel from the start, each in its own worktree with its own `ZIG_GLOBAL_CACHE_DIR` (AGENTS.md, Disk). Slice 7 starts when both lanes have merged. Every slice ends with `zig build check` PASS on the reported commit, and with the fuzzers it touched run as well.

1. **Keys and signatures (T).**
   - Work: `src/trust/`: the key file and its permission check, the key id, the public text, the statement encoding, the signature record (parse, render, atomic write under the store lock, `signatures_per_tree_max`), and `zbx key new|list|show`. Also `zbx sign` with the uncached tree check, which reuses `verify.zig`'s id recomputation by moving it into a shared function, not by copying it. Codes `E0901`, `E0902`, `E0903` and `E0910`. The `trust` record fuzzer: random and damaged records never crash parse, and are accepted only when they re-render to themselves (REVIEW.md, "Parse accepts only what render can write").
   - Tests: the statement is invariant under everything it does not cover and changed by each field it covers; there is a golden statement; a signature fails on any flipped byte of the statement, the key or the signature.
   - The simulator crashes at every write of the signature record and asserts that the record is either the old one or the new one.
   - *Mechanical, for Haiku:* the codes' registry boilerplate and error pages once their text is written; the `help`, `zbx schema` and `explain` entries; the golden files' copying; `src/trust/` in `ci-changes.sh` (running `m8`).
2. **Policy and the run gate (T).**
   - Policy: the policy file (path rules, the bounded ZON schema with M7's reader), the pure verdict, `zbx policy check`, and the gate in `run_container`, `exec` and the build scheduler (before a step's container starts).
   - Tamper check: the walk in the store child, the `trust/verified/` cache with its equality rule, `verify = "always"`, and gc removing `verified` entries with their tree.
   - Codes `E0904` to `E0907`.
   - Simulation tests:
     - over random policies, signatures and trees, a refused run never reaches `runtime.start` (the simulated host records every spawn) and leaves no record;
     - a tampered object is always found, whether its bytes, mode or owner changed, with or without the cache;
     - a ctime change always re-hashes that object.
   - A test at `policy_keys_max` and one past it.
   - VM check: start `src/testing/vm/main_m8.zig` with a part that signs a pulled `alpine`, runs it under `require_signature`, refuses an unsigned tree, and refuses after an object of the signed tree is changed. Push to `vm/m8-slice2`.
   - *Mechanical:* `m8` in `vm.yml`'s picker and `all` list, the `demo-m8` entry in `build.zig`'s demo table and `ci-changes.sh`'s demo list (as `m7`'s are), and the goldens.
3. **Provenance (T).**
   - Work: the provenance record (from cache entries, the build record and the running binary), written by `zbx build` on hits and misses; `zbx inspect --provenance` (text and `zbx.provenance/1`); `zbx sign` naming the provenance digest; `require_provenance` and `E0906`'s three causes; and the optional git source read (cuttable).
   - Tests: a provenance record is a function of the build's inputs and its times only; an all-hit build of an unchanged project writes the same record apart from its times; and the record of a build whose cache was written by 0.3.0 is complete, because the preimage format is unchanged.
   - Fuzzer: the `provenance` record fuzzer, with the same property as slice 1's.
   - *Mechanical:* the schema entry and goldens.
4. **Verify, export and import (T).**
   - Work: `zbx verify` (the six links, `W0901`, `--strict`, `--key`, `--public`, `E0908`); `zbx trust export|import` and `E0909`; `store.export_trust` and `store.import_trust` with the second-caller library test; and gc's orphan count.
   - Simulation test: `verify` never touches the network or the registry.
   - Peer fuzzer property: an imported bundle with any byte flipped is refused whole or re-verifies.
   - VM check: verify runs offline in the guest with its network link down.
   - *Mechanical:* the schema entries, goldens and the `explain` entries.
5. **The package writer and the repositories (P).**
   - Work: the `zigbox_package` module (ar, cpio, deb, rpm, the apt and dnf repository writers, armor, OpenPGP Ed25519 signature packets); `zig build packages`, `-Dsignatures=` and `packages-check`; the two-round signing commands; and `docs/releases/packaging.md`.
   - Unit tests:
     - golden bytes for a small package of each format, with the expected structure taken from a real `dpkg-deb -I` and `rpm -qpi --dump` of that file. REVIEW.md's "checked against real output" rule applies: capture them in the Ubuntu guest, or in this container if `dpkg-deb` and `rpm` are present, and say which;
     - reproducibility (two builds, identical bytes);
     - a header signature placed by `-Dsignatures` leaves the header digest unchanged.
   - A test-key OpenPGP signature made by the module verifies with `std.crypto.sign.Ed25519` over the OpenPGP hash input, as a pair assertion.
   - VM check, in the Ubuntu guest: the deb installs with `apt` from a repository the harness serves over its HTTP server, signed with the test key, and `apt update` prints no signature warning. Push to `vm/m8-packages`.
   - *Mechanical:* `src/package/` in `ci-changes.sh`; the README's install commands, copied from the runbook once it is checked.
6. **The rpm and Debian guests (P).** This slice can start beside slice 5 (booting the guests and provisioning with `dnf`) and finishes with slice 5's packages.
   - Harness: `zigbox_vm`'s image table gains Debian 12 (`genericcloud`), current Fedora (`Cloud Base Generic`) and Rocky 9 (`GenericCloud`) qcow2 images, each pinned by URL and SHA-256 as Ubuntu's is, with cloud-init's package step choosing `apt` or `dnf`. **Harness changes go to the supervisor first** (M7's rule: nothing changes inside `session.zig` or `harness.zig` without them). Zigcube uses this module, so the change is additive and `demo-z7` keeps passing.
   - The key-type probe: on each guest, a test-key Ed25519 signature on the repository metadata and on an rpm header is accepted (`apt update`, `dnf makecache`, `rpm -K`), or the guest's refusal is recorded. The result decides the archive key type (below) and is written to `docs/decisions/`.
   - The packages demo part runs on all four guests.
   - *Mechanical:* the image entries (URL and checksum copied from the distributions' published checksum files).
7. **The demo, CI and the agent test.**
   - `zig build demo-m8` (the trust steps below, exactly) and `zig build demo-m8-packages` (the four guests), with every assertion a unit-tested pure function in `checks_m8.zig`.
   - The upgrade test against the latest tag (0.3.1 if it is cut by then, else 0.3.0). Its store, run records and build cache are read; `zbx run` without a policy behaves as before; with a policy, its images are refused with `E0905`, not a crash; and a build reusing its cache entries writes complete provenance.
   - The agent test (JSON only); the two CI jobs (the packages job runs only when `ci-changes.sh` selects it); and `docs/demos/m8.md` with the by-hand steps, cuts and failure modes. The failure modes to cover: a lost key, a key file too open, a policy that refuses everything, a tampered object and how to recover, a provenance record replaced after signing, a missing input in verify, the disk full during a signature write, and a package upgrade with a container running.
   - *Mechanical:* the upgrade part copied from `upgrade_m7.zig`, with the tag in `old_release.zon`; the CI jobs copied from `demo-m7`'s; the README and site status lines after green runs.
   - **The Mac** (open question 4) is a separate, cuttable slice 8 for the Mac session: add `key`, `sign`, `verify`, `trust` and `policy` to `linux_commands` in `src/macos_main.zig`, with keys and the user's policy on the shared Mac home. It is not demonstrated.

Slices 1 and 2 are the riskiest (the statement is the contract; the gate is the promise) and are reviewed hardest. Slice 5's rpm writer is the riskiest of lane P: rpm's header format is poorly documented, so test against `rpm` itself early.

## The demo: `zig build demo-m8`

This is the Ubuntu 24.04 guest, the ordinary user, and M7's checked-in project (`src/testing/vm/m7_project/`) copied to `~/hello`. Images come through `mirror.gcr.io` with the blob cache. Parts in order: UPGRADE, SPEC, ACCEPT, AGENT. Assertions on codes, digests and verdicts are exact.

1. **Build and sign.** `zbx key new demo` prints the key id. `cd ~/hello && zbx build` gives the golden result digest from `m7_expected.zon`. `zbx sign <digest>` exits 0. `zbx inspect --provenance <digest> --output json` matches its schema and names the two bases by their locked manifest digests, the steps `compile` and `notice` with their input and output trees, the build file's hash, the `zbx` version and `signed: true` covering this record. The text form's base, step and builder lines match the golden apart from times.
2. **Policy.** Write `~/.config/zbx/policy.zon` with `demo`'s public key and `.require_signature = true`. `zbx run <digest>` prints `hello from zigbox`. `zbx pull alpine:3.20 && zbx run alpine:3.20 true` exits 125, and stderr starts `error[ZBX-E0905]:` and names `~/.config/zbx/policy.zon` and `require_signature`. `zbx ps -a` lists no new container, and no run record or scope was created (before and after listings compared).
3. **Tamper.** The harness finds the object of `/usr/local/bin/hello` through the store's own JSON listing, not by computing the path. It appends one byte as the user (`chmod u+w`, then `printf x >>`). `zbx run <digest>` exits 125 with `error[ZBX-E0907]` naming `/usr/local/bin/hello`, and `zbx store verify` names the same object. The byte is then truncated away: `zbx run` works again (the ctime changed, so it re-hashed).
4. **Verify, offline.** The guest's network link is taken down (privileged setup in the VM). `zbx verify <digest> --output json` exits 0, and every link from the signature to each base, each step's input and output tree and the build file reports `ok`. The link comes back up.

ACCEPT also checks:
- `zbx store rm` of `alpine:3.20`'s root, then `zbx store gc` and a re-pull. A signature made on the pulled `alpine` before the removal still makes `zbx run alpine:3.20 true` pass (survives re-pull).
- `require_provenance` refuses a tree-only signature (`E0906`).
- A statement that binds a result covers that result's config, not only its tree: a second result with the same tree and another entrypoint is refused under the first result's signature. A `-- <cmd>` override on the signed result stays allowed, since the command is the user's own.
- `zbx policy check` agrees with `run` on all three cases.
- A malformed policy is refused with `E0904` and its line and column.
- A step whose base is unsigned is refused under `require_signature`, naming the step.
- `zbx trust export` and `zbx trust import` into a second user's store make the image run there.

**`zig build demo-m8-packages`**: Ubuntu 24.04, Debian 12, current Fedora and Rocky 9, one after another. The harness's HTTP server serves the repository trees signed with the test key. On each guest, as root (privileged setup in the VM):
1. The README's commands for that distribution, then `apt update` or `dnf makecache` with no signature warning.
2. Install, and `zbx version` prints the build's version. As the ordinary user, with a subordinate range given: `zbx pull alpine:3.20 && zbx run alpine:3.20 echo ok` prints `ok`. This is cuttable to `zbx doctor` on a guest whose kernel or packages fall short (linux-packages.md, unknown 1).
3. Upgrade to a second build with a higher test version, in place, and `zbx version` changes.
4. Remove the package: `/usr/bin/zbx` is gone, and the user's store is still there.

`rpm -K` on the rpm reports the signature as valid on the two rpm guests.

**What the harness lacks today.** It has only the Ubuntu cloud image, and cloud-init provisioning is apt-only. Fedora's and Rocky's cloud images use cloud-init too, but booting them under the harness (console login, the NoCloud seed, `dnf` in provisioning) is untested. That is a **known unknown**: slice 6 settles it first. A second known unknown is **the archive key type**. RHEL 9's rpm may refuse EdDSA signatures, which would also make the Ed25519 test key useless there. Slice 6's probe answers it before the owner makes the archive key. Do not assume. If EdDSA is refused, the archive key is RSA 4096, and the CI test signature on the rpm guests falls back as open question 7 says.

## Non-goals

- Sigstore, keyless signing, OIDC identities and transparency logs (deferred by the spec).
- Signatures in registries (cosign or OCI referrers), push and OCI export: pull-only until after M8.
- Hardware keys, ssh-agent and PKCS#11; key rotation, expiry and revocation lists. Revocation is removing a key from the policy file.
- Thresholds (k-of-n signers) and policy scoped by image name or registry. Allowed source repositories are C6's.
- The agent-operability rules (deny `--net host`, deny mounting `$HOME`) in the policy file. The schema leaves room for them (spec note).
- An SBOM, and signing `zbx` release binaries with M8's own keys ("Trust in zbx itself").
- Zigcube's packages (C3), the Homebrew formula, maintainer scripts, editing `/etc/subuid`, publishing from CI, and any distribution beyond the four.
- Demonstrating M8 on the Mac.

## Scope that can be cut while keeping the demo

Record any cut in `docs/demos/m8.md`.
- **The git source** in provenance.
- **The `cached` tamper check**: keep `always` and document the measured cost. The demo still passes.
- **Exec and build gating** (open question 3): `run` alone is the spec.
- **`zbx trust export|import` as commands**: the library pair stays for Zigcube, and ACCEPT's two-user check goes.
- **`zbx key list|show`**: `key new` prints what the demo needs.
- **A full `zbx run` on Debian 12 or Rocky 9**: install, `zbx version` and `zbx doctor` there only.
- **rpm header signatures**: sign `repomd.xml` only (`repo_gpgcheck=1`, `gpgcheck=0`), if slice 6 finds the header signature costs more than a slice part. The demo's "no signature warning" holds; `rpm -K` goes.
- **Slice 8 (the Mac).**

## Open questions for the owner

Each has a recommendation and its cost. The brief is written as if each recommendation is taken; a different answer changes the named slice.

1. **Where keys live and how they are protected.** *Recommend* `~/.config/zbx/keys/`, files with mode `0600` and the directory `0700`, refused when looser, **unencrypted** in M8, with the format's `encryption` field reserved.
   - Cost: anyone who can read the user's home can sign. That is ssh's default threat model.
   - Alternative: passphrase encryption now, with argon2id and XChaCha20-Poly1305 (both in std), a `--passphrase-file` for no-terminal use, and a refusal (never a prompt) without one. About half a slice in slice 1, plus a golden and a failure mode.
   - Hardware keys and agents are non-goals.
   - Keys never live in the store, which peers write.
2. **Signature and provenance formats.** *Recommend our own:* a canonical binary statement signed with Ed25519, records as bounded text like the image records, and `zbx.provenance/1` JSON whose member names follow SLSA provenance v1.
   - Cost: no off-the-shelf verifier reads our signatures.
   - Alternative: in-toto statements in DSSE envelopes now. That means JSON as the signed bytes (no canonical form needed under DSSE, but a JSON writer whose output we sign) and roughly a slice more. The gain is small until push exists: in-toto subjects are usually `sha256`, ours are BLAKE3 trees, and the tools that read them pull from registries M8 cannot push to.
   - An `--output in-toto` export can be added later without changing what is stored.
3. **Does policy apply to `exec`, `build` and `pull`?** *Recommend:*
   - `exec`: the verdict only, no re-hash. It is cheap, and without it a container started before the policy escapes it.
   - `build`: each step's base, because a step runs image code. The cost is that users must sign their bases, and the check adds a slice-2 part.
   - `pull`: not gated. A pull runs no code, and refusing it would only block the "pull, then sign" flow.

   The cheaper alternative is `run` only (the spec's wording). It leaves both holes.
4. **The Mac.** *Recommend:* forward `key`, `sign`, `verify`, `trust` and `policy` to the Linux `zbx` (a mechanical change to `linux_commands`), with keys and the user's policy on the Mac home shared over virtiofs, so they outlive the VM's disk image. The Mac is **not** demonstrated, as M7 decided.
   - Note: `build` and `inspect` are not forwarded on the Mac yet (M7's slice 5 was cut), so provenance on the Mac waits for that.
   - Cost: slice 8, small. A risk: the forwarding protocol drops `XDG_*`, so the VM side needs a fixed path under the shared home.
5. **Verify-on-run.** *Recommend `cached`* (above): a full re-hash on the first checked run, then per-object `lstat` and equality on `(inode, size, ctime_ns)`, re-hashing only what changed. The tamper check runs only when a policy file exists.
   - Measured: BLAKE3 at about 1.2 GB/s on one thread of the shipped build, so a full re-hash is about 0.4 s for postgres and 0.7 s for golang (warm). The estimate for cached is 20 to 40 ms for 20,000 files.
   - Alternatives:
     - **Always:** simplest, and that cost every run.
     - **First run only:** cheap, but misses tamper after the first run, which fails demo step 3.
     - **fs-verity:** kernel-enforced, but needs ext4 or btrfs with verity enabled and is not available everywhere. A later option behind the same check.
6. **Signatures and provenance across gc, export, import and peer fetch.** *Recommend:* not roots and never collected (bounded, tiny); `zbx trust export|import` as a self-verifying bundle (bad signatures refused whole, untrusted keys kept); `store.export_trust` and `store.import_trust` beside Z4's pair, unchanged Z4.
   - Cost: orphan records accumulate up to `trust_records_max` until a prune command exists.
   - The alternative, removing them with their tree, breaks "survive re-pulls" after a gc.
7. **How CI shows "no signature warning" without the archive key** (new; it follows from "CI never signs"). *Recommend* the `zigbox_package` module's own OpenPGP Ed25519 signer with a **test key whose secret is checked in** (it vouches for nothing).
   - Each guest trusts only that test key, for the packages demo. This is where M8's Ed25519 work and the archive signing "share code" (decision `2026-11-04-linux-packages-in-m8.md`); with `gpg` chosen, it is the only real overlap.
   - Cost: an OpenPGP signature-packet writer, a slice-5 part.
   - If slice 6 finds RHEL 9 refuses EdDSA, the rpm guests fall back to `gpgcheck=0` and `repo_gpgcheck=0` in CI, and RSA signatures are checked only by the owner at release (`rpm -K` by hand, in the runbook).
   - The other options:
     - `gpg` in CI with a throwaway key: needs a STYLE.md change.
     - No signature checks in CI at all: the demo's "no warning" claim then goes unchecked.
8. **How the signed repository reaches Pages** (new; follows from the hosting decision). *Recommend:* the owner's release step uploads the signed `apt/` and `rpm/` trees as one release asset, as the Mac archive is uploaded. The existing Pages deploy job on `main` copies the latest release's asset in byte for byte. CI then deploys bytes the owner signed, and never builds or signs them.
   - Cost: a change to the Pages workflow, and a release-asset download in it.
   - Alternative: the owner pushes the trees to a `gh-pages` branch. That needs Pages switched from Actions to branch deploys, which would also move `site/`.

## Spec notes (flagged, not changed)

- **Packaging is not in the spec.** Neither the snapshot (rev 86) nor the live doc (rev 91) mentions deb, rpm, apt or dnf. The 2026-11-04 decisions put packages in M8 and say the live doc should gain them before this brief. It has not. The supervisor should add the scope, the demo step and the acceptance line above to M8 in the live doc.
- **The snapshot is behind.** `docs/SPEC.md` is rev 86, and the live doc is rev 91. The M8, Production readiness, Agent operability and C6 sections read the same in both. The live doc adds **M6c · Private pull (Amazon ECR)** and changes the Non-goals line ("Pull-only from public registries until after M8, except authenticated pull from Amazon ECR"), plus Part II text about the simulation instance. Under AGENTS.md this is a conflict to report, not one this brief resolves. Nothing in M8 depends on it. The supervisor should refresh the snapshot.
- **"Signatures are over tree digests"** leaves the run config (entrypoint, user, env) unsigned. The brief keeps the tree as the subject and lets a statement bind the result or manifest (Fixed decisions, "Why the binding"). The spec could say "over tree digests, optionally bound to the image's config".
- **"Policy refusals happen before any process starts."** The tamper check must read objects owned by container ids, which only the store's namespace child can do. The brief reads the criterion as "before any workload process". The spec could say so.
- **"Tamper with one file in the stored tree"** is also tampering with every materialized farm of it (hardlinks share the inode). The spec does not say what checking costs. The brief measured it (open question 5).
- **"Require provenance"** does not say whether the provenance must be signed. Unsigned provenance is a claim anyone can write, so the brief requires a trusted statement naming it.
- **"`zbx verify` walks to every input"**: inputs can be collected by gc after the build. The brief reports absent inputs as `W0901` and fails only on damage, or on absence with `--strict`.
- **Agent operability's policy file** ("a minimal form of M8's run policy, brought forward", denying `--net host` or mounting `$HOME`) was never built. M8's policy file is its natural home. The brief leaves the rules out (Non-goals) but keeps the schema open for them. The spec could move that bullet to M8 or later.
- **"Trust in zbx itself"** (signed releases, an SBOM) is partly met by M8's signed packages. The SBOM and M8-key signatures on release binaries are not in M8.
- **Current Fedora's rpm** may be rpm 6, which enforces signature checks by default. If so, the test key must be imported before the first install. Slice 6 checks this; the spec says nothing either way.
