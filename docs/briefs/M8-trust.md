# Brief: M8 · Trust, Linux packages and push

Read these first:
- `AGENTS.md`, `REVIEW.md`, `docs/STYLE.md` and `DIAGNOSTICS.md` (codes `09xx` are reserved for trust and policy; none is registered yet).
- The M8 section of `docs/SPEC.md` (the snapshot of live doc rev 91, since PR #55), and C6 in Part II, which reuses M8's checks on every node.
- `docs/briefs/linux-packages.md` and the decisions `2026-11-04-linux-packages.md`, `-linux-packages-in-m8.md`, `-package-split.md`, `-package-signing-hosting.md` and `-release-0.3.1.md`. They are settled. This brief folds them in and does not reopen them.
- `docs/decisions/2026-11-04-m8-owner-answers.md`: the owner's answers to this brief's questions (passphrase-encrypted keys, in-toto and DSSE now), and its "Follow-ups" section (our own type URIs under a proper project domain, since named `zigbox.org` in `docs/decisions/2026-11-04-project-domain-zigbox-org.md`, and the trust-record prune built in M8). This brief is written to them.
- For slices 1, 2 and 4: the [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md), in-toto's [Statement](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md), [DigestSet](https://github.com/in-toto/attestation/blob/main/spec/v1/digest_set.md), [envelope](https://github.com/in-toto/attestation/blob/main/spec/v1/envelope.md) and [bundle](https://github.com/in-toto/attestation/blob/main/spec/v1/bundle.md) pages, and [SLSA provenance v1](https://slsa.dev/spec/v1.0/provenance). Read them from the source; do not write them from memory.
- `docs/demos/m3.md` (what a tree digest holds), `docs/demos/m7.md` (the build record, the result digest, the cut `build` root and why the image cache entry keeps the tree), `docs/decisions/2026-11-04-z4-image-record-peer.md` (image records to and from a peer), and Z9's `2026-11-04-z9-chunk-read-outside.md` on its branch (reading objects outside the store's namespace).
- For lane U: the [OCI image spec](https://github.com/opencontainers/image-spec) (manifest, config, layer, image layout) and the [distribution spec](https://github.com/opencontainers/distribution-spec/blob/main/spec.md) (push, mount), Docker's [token auth](https://distribution.github.io/distribution/spec/auth/token/), `src/registry/` and `src/layer/apply.zig`, and the M6c brief (on branch `claude/gracious-heisenberg-thdbyp` until it merges).
- `src/build/key.zig` and `src/build/cache.zig` (each cache entry keeps the key's preimage "so M8 can write provenance without rebuilding"), `src/build/result.zig`, `src/store/tree.zig`, `src/store/object.zig`, `src/store/verify.zig`, `src/store/walk.zig`, `src/store/images.zig`, `src/store/image_peer.zig`, `src/store/gc.zig`, `src/store/layout.zig`, `src/run_image.zig`, and `run_container` in `src/cli.zig`.

`demo-m0` to `demo-m7`, the top-20 check and the Mac demos must keep passing. M8 has three independent parts: **trust** (keys, signatures, provenance, policy and verify), **packages** (the `zigbox` deb and rpm and their repositories) and, since 2026-11-08, **push** (`zbx push` and `zbx store export --oci`; decision `2026-11-08-push-in-m8.md`, issue #60). They share little code and run as three lanes of slices (see Slices).

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
- **Where** (owner): `$XDG_CONFIG_HOME/zbx/keys/` (default `~/.config/zbx/keys/`). The directory has mode `0700`. `<name>.key` holds the secret key with mode `0600`, and `<name>.pub` holds the public key. A secret key file readable by group or others is refused when used (`E0901`), as ssh does. The store is the wrong place for keys: peers write into it.
- **The key file** is a small versioned text record: `.version = 1`, `.algorithm = "ed25519"`, `.public = "zbx-ed25519:…"` and `.encryption`, which is one of two values:
  - `"argon2id-xchacha20poly1305"` (the default): `.kdf = .{ .t, .m_kib, .p, .salt }`, `.nonce` and `.sealed` (the 32-byte seed sealed with its tag, in hex). The key comes from argon2id (`std.crypto.pwhash.argon2`) over the passphrase and salt. The seed is sealed with `XChaCha20Poly1305` (`std.crypto.aead.chacha_poly`), with the public key text as associated data, so a sealed seed moved under another public key does not open. Defaults are named constants: `key_kdf_t` (3), `key_kdf_m_kib` (65536) and `key_kdf_p` (1, so argon2 runs on one thread). Parse refuses parameters above `key_kdf_m_kib_max` and `key_kdf_t_max`, so a hostile key file cannot make `sign` allocate or loop without bound. Salt and nonce come from the OS's random source.
  - `"none"`: `.secret = "<hex>"`. Written only by `zbx key new <name> --no-passphrase` (owner: allowed, but only when asked for; for CI, fixtures and Zigcube's node-local keys).

  Read the pinned std's `argon2` and `chacha_poly` source before using them (AGENTS.md); the parameter names above are ours, not std's.
- **The passphrase** comes from `--passphrase-file <path>` (its first line, without the newline, at most `passphrase_bytes_max`; a file readable by group or others is refused, as the key file is), or, when stdin and stderr are both a terminal, from the terminal with echo off (termios through `std.os.linux`, restored on every exit path). With neither, `key new` and `sign` refuse with `E0911` and never wait for input. `key new` without `--no-passphrase` asks twice on a terminal and refuses a mismatch. An empty passphrase is refused; use `--no-passphrase` to say so. A wrong passphrase is `E0911`, after argon2id has run in full.
- **The public key's text** is `zbx-ed25519:<64 hex>`. **The key id** is BLAKE3 over `"zbx-key\x00"` and the 32 public-key bytes, written as 64 hex digits, and always compared in full: no ids are matched by prefix (spec, Agent operability). The id is for people and listings. Inside an envelope, the public text itself is the `keyid` (below).
- `zbx key list` and `zbx key show <name>` print the name, id, public text and encryption (`passphrase` or `none`), in text and in `--output json` (schema `zbx.key/1`). They read only `.pub` files and never need a passphrase. No command ever prints a secret key.

### What is signed

Owner, 2026-11-04: in-toto Statement v1 in a DSSE envelope, signed with Ed25519, now. Every signature has this one shape.

- **The statement** is an in-toto Statement v1, written by our own bounded JSON writer (below):

```json
{"_type":"https://in-toto.io/Statement/v1",
 "subject":[{"name":"tree","digest":{"zbxTree":"91e04c1d…a7b0"}},
            {"name":"result","digest":{"zbxResult":"55077a8f…df62"}}],
 "predicateType":"https://slsa.dev/provenance/v1",
 "predicate":{…}}
```

  (Shown with whitespace; the payload has none.)
  - **Subjects.** The first subject is always the tree, `{"name":"tree","digest":{"zbxTree":"<64 hex>"}}`. in-toto's DigestSet allows algorithms outside its list, provided their encoding is documented. A tree digest is BLAKE3 over zbx's tree encoding (`docs/demos/m3.md`), not over a file, so the key is `zbxTree` (after the spec's `gitTree`), not `blake3`. `docs/demos/m8.md` documents it: 64 lowercase hex digits, no `b3:` prefix. Plain BLAKE3 over a file's bytes, as provenance uses, takes the key `blake3`.
  - **The binding** is an optional second subject: `{"name":"result","digest":{"zbxResult":"<hex>"}}` for an M7 result, which commits to the tree and its config; or `{"name":"<reference>","digest":{"sha256":"<hex>"}}` for an image manifest, which commits to the OCI config. The second form is the standard `sha256` key that OCI tools match. There are at most `statement_subjects_max` (2) subjects, the tree first, and anything else is refused at parse.
  - **Predicate.** When the subject has a provenance record, the statement **is** that record (`predicateType` `https://slsa.dev/provenance/v1`; see Provenance). Otherwise `predicateType` is our own sign type, `https://zigbox.org/attestation/sign/v1`, and the predicate is `{"signedAt":"<RFC 3339 UTC, seconds>"}`, a claim.
  - **Our type URIs** (owner: "a proper domain", not `zigbox.github.io`). The sign predicate type and the provenance `buildType` (below) are named constants in `constants.zig`, built from one `type_uri_base` (`"https://zigbox.org"`, the project domain: `docs/decisions/2026-11-04-project-domain-zigbox-org.md`) plus a fixed path (`/attestation/sign/v1`, `/build/v1`). Code, goldens, the demo and the tests read the constant and never spell the URI out, so the domain lives in one line. Once a signature has been made with a URI it is part of the format: changing it later is a format change.
- **The envelope** is DSSE: `{"payloadType":"application/vnd.in-toto+json","payload":"<base64>","signatures":[{"keyid":"zbx-ed25519:<64 hex>","sig":"<base64>"}]}`. It holds one signature; a second key makes a second envelope. `keyid` is DSSE's unauthenticated hint. We set it to the full public text, so anyone holding the envelope can check the signature without a key directory. Trust comes only from policy. Base64 is `std.base64.standard`, with padding, and nothing else is accepted.
- **The signed bytes** are DSSE's PAE: `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`, with `type` the payload type and `body` the payload bytes as stored. Ed25519 (`std.crypto.sign.Ed25519`) signs exactly these. Verification decodes the payload, verifies the signature over PAE of those bytes, and only then parses them. Nothing is re-serialized before the check.
- **The canonical JSON writer** (`src/trust/json.zig`) is ours, bounded and small. Members come in the order the schema gives, with no whitespace. Strings are UTF-8 checked at write and escape exactly `"`, `\` and bytes below 0x20 (as `\n`, `\t` and `\u00xx` in lowercase hex). There are integers only, no floats, and nesting is at most `json_depth_max`. DSSE needs no canonical form, since it signs bytes. We keep one so the same statement is the same bytes on every host, and so the reader accepts a payload or envelope only when our writer re-renders it byte for byte (REVIEW.md, "Parse accepts only what render can write"). It is not RFC 8785: members are in schema order, not sorted. Reading uses std's JSON scanner under fixed buffers, as `src/registry/` reads manifests. Payloads are at most `statement_bytes_max`, and envelopes at most `envelope_bytes_max` (the base64 of that plus a fixed overhead, computed in `constants.zig` with a `comptime` assert).
- **Why the binding.** The spec signs tree digests. A tree-only signature would let anyone run the signed tree with any entrypoint, user or environment. So `zbx sign <result digest>` and `zbx sign <name>@sha256:<manifest>` bind the config, and `zbx sign <tree digest>` signs the tree alone. in-toto says a predicate applies to each subject. Our policy reads the second subject as a narrowing: a statement with one counts only when the run uses that same result or manifest, and a tree-only statement counts for any config (spec note). A third-party tool will read the bound statement as covering the tree too. That reading is weaker, and harmless, since those tools do not run our trees.
- **`zbx sign <digest> [--key <name>] [--passphrase-file <path>]`** resolves the operand as `zbx run` does (a result digest, then a tree digest, then a digest image reference). It checks the tree first: the tree must be whole and every object must hash to its id (the run-time check below, uncached). A tree that is not whole is refused (`E0910`). Signing what you have not checked is how damage gets vouched for. Then it opens the key (`E0911` without a passphrase) and signs. When the operand is a result with a provenance record, it signs that record's exact bytes; otherwise it writes a `sign/v1` statement. `--key` defaults to the only key when there is exactly one; otherwise it is required. `--output json` prints `zbx.sign/1`.
- **The signature record** is `trust/signatures/<tree hex>` in the store. It is an in-toto bundle: JSON Lines, one envelope per line, at most `signatures_per_tree_max` (8) lines and `signature_record_bytes_max` bytes. It is rewritten by atomic rename under the store lock. Ed25519 is deterministic, so signing the same statement again with the same key gives the same line and changes nothing. A ninth distinct envelope is refused with `E0910`, naming the bound. The record is keyed by the tree, so a re-pull of the same image, a new farm or another manifest for the same tree all find it.
- Verification uses `Signature.verify` (measured at about 120 µs per signature here), never a check written by hand.

### Provenance

- **What and when.** Every successful `zbx build` writes a provenance record for its result, whether the build was all hits or not. Everything in it comes from what the build already holds: each step's cache entry (the key preimage, which includes the base tree and its env, the input tree digest, each needed step's output digest, argv, env and network) and the build record. M7's step logs are not in it.
- **Form.** The record is an in-toto Statement v1 with `predicateType` `https://slsa.dev/provenance/v1`, written by the canonical JSON writer. Its subjects are the tree and the result (`zbxTree`, then `zbxResult`), so signing it binds the result. Its predicate is SLSA v1 provenance: `buildDefinition` (`buildType` `https://zigbox.org/build/v1` (the constant above), `externalParameters`, `internalParameters`, `resolvedDependencies`) and `runDetails` (`builder.id`, `builder.version`, `metadata`, `byproducts`). Digest sets use `zbxTree` for trees, `sha256` for manifests and `blake3` for file bytes. Which field goes where is fixed in `docs/demos/m8.md` with a golden record. The content is:
  - **subject:** the tree digest and the result digest.
  - **builder:** `zbx` version, release commit and platform, plus the BLAKE3 of the running `zbx` binary (read from `/proc/self/exe`).
  - **build file:** its project-relative path and the BLAKE3 of its bytes.
  - **lock:** the BLAKE3 of `zbx.lock`.
  - **bases:** each locked base as reference, manifest digest and tree digest.
  - **steps:** each step's name, key, input tree, `needs` with output digests, output tree and `network`.
  - **image assembly:** its key.
  - **times:** the build's start and end time.
  - **source:** optional, cuttable. The project's git commit and whether the tree is clean, read from `.git` directly (`HEAD`, refs and `packed-refs`; no `git` program) and present only when the project directory is a git checkout.

  None of this changes the result digest (M7). A record has at most `provenance_steps_max` steps (a constant, equal to M7's step bound). Its bytes are at most `statement_bytes_max`, which is sized in `constants.zig` from `provenance_steps_max` and the longest field each step can hold, with a `comptime` assert. A build whose provenance would exceed it is a bug, not a refusal.
- **Where.** `trust/provenance/<result hex>` in the store holds the statement's payload bytes, unsigned, written by atomic rename. The record's identity, its **provenance digest**, is BLAKE3 over those bytes. A later build of the same result replaces the record: a comment changed in the build file is a new record for the same result.
- **Signing carries the provenance.** `zbx sign <result>` wraps the record's exact bytes in an envelope, so the signed provenance is in the signature record itself. The stored record is not needed to check it, and replacing the record does not void the signature: the signed provenance still truly describes a build of this exact result. `zbx inspect --provenance` says whether a signed envelope's payload is the stored record (same provenance digest) or an earlier build's.
- **`require provenance`** means *signed* provenance: an envelope from a trusted key whose statement has `predicateType` `https://slsa.dev/provenance/v1`, names this tree, and has a binding that matches the run. An unsigned record is shown by `inspect`, but no policy accepts it.
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
provenance  b3:e7d1…
signed      demo  3b6a…(key id)  this record
```

  `--output json` prints `zbx.provenance/1`: `{"schema":"zbx.provenance/1","provenance_digest":…,"statement":<the in-toto statement, as stored>,"signatures":[{"key_id":…,"public":…,"covers":"this record"|"earlier build"}]}`. The statement is embedded as stored, so a consumer that knows SLSA reads it directly.

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
    .require_provenance = false, // a trusted SLSA provenance statement for the tree, binding matching
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
- **`zbx exec`** (owner): the policy verdict on the container's tree and binding from its run record. There is no re-hash, because the container is running and its lower layer was checked when it started. A container started before the policy existed and not satisfying it is refused with the same code. Pausing or stopping it is not exec's business.
- **`zbx build`** (owner): each step's base is checked like a run's tree before the step's container starts, and a refusal names the step. A step is a container running the base image's code. Users who turn on `require_signature` sign their bases (`zbx sign alpine@sha256:…`). Cache hits run nothing and are not checked.
- **`zbx pull`** is not gated (owner).

### The tamper check (verify-on-run)

- **What.** It walks every object the tree reaches (`walk.objects`) and recomputes each object's id from its bytes, mode, owner and xattrs, as `store verify` does (shared code). Trees are already re-hashed on load. The first mismatch refuses the run with `E0907`, naming the path in the image, the object and what differs (bytes, mode or owner). Materialized farms are hardlinks to the objects, so the farm and the store are one inode and one check covers both.
- **The cost, measured.** `std.crypto.hash.Blake3` with pinned Zig 0.17.0, `ReleaseSafe`, on one thread of a 2.1 GHz Xeon (the cloud container) runs at:
  - **about 1.2 GB/s** for the shipped baseline-CPU x86_64 build;
  - 2.1 GB/s with native CPU features;
  - the same speed for 16 KiB pieces as for 256 MiB.

  So a full re-hash of a warm tree costs about 7 ms for `alpine` (8 MB), about 0.4 s for `postgres:16` (about 430 MB) and about 0.7 s for `golang:1.23` (about 800 MB). A cold page cache adds the disk read. The store child is single-threaded until `execve` (AGENTS.md), so the hash runs on one thread.
- **What we do** (owner: `cached`):
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
1. the signature record exists, and each envelope's signature verifies over PAE against the public key in its `keyid`;
2. at least one key is trusted by every policy file present. With no policy file, `--key <name>` or `--public <text>` names the key to trust. Without either, verify reports the signers and exits 1;
3. the tree is whole and every object hashes to its id, uncached;
4. a trusted envelope carries SLSA provenance for this tree. Its payload parses and re-renders to itself, and its subjects name this tree. Whether the stored record is the same bytes is reported, but is not a failure;
5. every input the signed provenance names (each base tree, each step's input and output tree, the image assembly's output) is present and sound;
6. if the build file and lock named by the signed provenance are in the working directory's project, their hashes match. If they are not, that is reported but is not a failure.

A tree signed without provenance stops after link 3 and says so; that passes unless `--require-provenance` is given.

An input that is absent, because gc took it, is `W0903` (it cannot be checked offline) and fails only with `--strict`. A damaged input is `E0908`. Output: one line per link in text, and `zbx.verify/1` in JSON with every link's status. A simulation test asserts that `verify` makes no network or registry call (`host_sim` records them).

### Records, gc, export and import (owner)

- **gc.** Signature and provenance records are not roots, and **gc never removes them**. They are small and bounded (`trust_records_max`), and keeping them is what makes a signature survive gc followed by a re-pull of the same image (the spec's criterion). `trust/verified/` entries go with their tree. `zbx store gc` prints the orphan count and names `zbx trust prune`. At `trust_records_max`, `sign` (`E0910`) and `import` (`E0909`) refuse, naming the bound and `zbx trust prune`.
- **Prune is in M8** (owner follow-up, 2026-11-04, superseding the earlier "defer prune to C5"). `zbx trust prune [--apply]` is the only thing that removes trust records, and only when asked:
  - **What is an orphan.** A signature record `trust/signatures/<tree hex>` whose tree is not in the store, and a provenance record `trust/provenance/<result hex>` whose result is not in the store or names a tree that is not. A record whose tree is present is never removed, whatever its signatures or keys. Policy plays no part: an untrusted signature on a present tree stays.
  - **Dry run by default.** Without `--apply`, prune lists each orphan (kind, digest, envelope count, bytes) and removes nothing. With `--apply`, it removes them. The default is the dry run because pruning gives up exactly what gc keeps: a pruned signature no longer covers a later re-pull of the same image. The listing names `zbx trust export <tree>` for keeping a record outside the store first.
  - **Under the store lock**, held from the presence check to the last unlink, as gc holds it, so a pull or build of the same tree is either already in the store (its record is kept) or waits.
  - **Bounded and crash-safe.** It reads at most `trust_records_max` entries per directory. Each record is one file removed by one `unlink`, so a crash leaves each record either present or gone, and a second run finishes the job. A damaged record of an absent tree is an orphan like any other and is removed; a damaged record of a present tree is kept and reported (`W0902`, "damaged trust record kept; its tree is in the store").
  - **Refusals** are the store's existing one-line ones (the store lock is busy, the store is missing or of a newer format). Prune adds no `E09xx` code, and one new warning, `W0902`. Output: one line per orphan and a summary line in text, `zbx.trust-prune/1` in JSON (`dry_run`, each orphan, the counts).
  - **Library:** `store.prune_trust(store, memory, apply, out, failure)`, beside the export and import pair, for Zigcube's nodes.
- **Export and import.** `zbx trust export <digest>` writes the tree's envelopes as an in-toto bundle (JSON Lines, `.intoto.jsonl`) on stdout, the same bytes as the signature record. Signed provenance travels inside its envelope, so nothing else is needed. `zbx trust import <file>` checks the size, parses each line, and verifies every signature over PAE against its `keyid`. It checks that each statement's first subject is a tree, and then merges the lines into that tree's record under the store lock. A bundle with any bad line or signature is refused whole (`E0909`), writing nothing. Signatures by keys this host does not trust are kept, because trust is decided at run time by policy, not at import. This is how a signature made on a build machine reaches the host that pulls the same image, whether the image was pushed by `zbx push` (lane U) or by another tool. Signatures are not stored in registries (Non-goals).
- **For Zigcube.** `store.export_trust(store, memory, tree, out, failure)` and `store.import_trust(store, memory, text, tree, failure)` sit beside Z4's `export_image` and `import_image` in the library, with the same shape: caller memory, a `Refusal`, one coded diagnostic. Z4's functions do not change, so C2 keeps working. C6 calls the new pair when it fetches a tree from a peer, and the node's own policy check runs at exec (spec, "Trust checked twice").

### Diagnostics (`09xx`, each with cause, fix, goldens and an error page)

- `E0901` a key can't be used: missing, unreadable, malformed, of a newer format, or with a secret file readable by others (fix: `chmod 600 <path>`).
- `E0902` a key with that name already exists (fix: choose another name; the old key is never overwritten).
- `E0903` a signature or provenance record in the store is damaged or of a newer format (blame environment; fix: `zbx trust import` again or sign again; "upgrade zbx" for newer).
- `E0904` a policy file can't be read or parsed (its path, line, column and what was expected).
- `E0905` a run is refused because no trusted signature covers it. It names the policy file and the rule (`require_signature`), the digest, and in the cause each signature present and why it does not count. Fix: `zbx sign <digest>`, or add the signer's key to the named file. Exit 125.
- `E0906` a run is refused because no signed provenance covers it (`require_provenance`). It says whether provenance is missing, present but unsigned by a trusted key, or signed for another binding. Exit 125.
- `E0907` the tree no longer matches its digest (blame environment). It names the image path, the object and what differs. Fix: `zbx store verify`, then remove the damaged tree and pull or build again. Exit 125 from `run`.
- `E0908` `zbx verify` found a broken link (which link and why).
- `E0909` a trust bundle is refused (size, a malformed envelope or statement, a bad signature, or `trust_records_max` reached).
- `E0910` signing is refused: the digest is not in the store, its tree is not whole or sound, or a bound (`signatures_per_tree_max`, `trust_records_max`) is reached.
- `E0911` a passphrase is needed and none is available (no `--passphrase-file` and no terminal), the passphrase file is too open or too long, or the passphrase does not open the key. Fix: pass `--passphrase-file`; a forgotten passphrase is a lost key.
- `W0903` `zbx verify` could not check an input that is not in the store.
- `W0902` `zbx trust prune` kept a damaged trust record because its tree is in the store (fix: `zbx trust import` again or sign again, as for `E0903`).

DIAGNOSTICS "Exit codes" applies: `run` uses 125 for its refusals, and every other command uses 1 or 2 by blame. Errors from the packaging step (`zig build packages`) are build-tool errors, one `package: ...` line each, like the harness's `VM-F` codes, and are not product codes.

### CLI and agents

New commands: `key new|list|show`, `sign`, `verify`, `trust export|import|prune`, `policy check`, and the `--provenance` flag of `inspect`. Each has `help`, `zbx schema` (`zbx.key/1`, `zbx.sign/1`, `zbx.verify/1`, `zbx.trust/1`, `zbx.trust-prune/1`, `zbx.policy/1`, `zbx.provenance/1`), goldens, and the error documents of its refusals (REVIEW.md, "Every new command"). Nothing prompts, with one exception: `key new` and `sign` read a passphrase from the terminal when both stdin and stderr are one and no `--passphrase-file` is given. Without a terminal they refuse. The agent test drives the trust part of the demo with JSON, `zbx policy check` and `zbx explain` only.

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
- **Hosting: zigbox.org** (owner, 2026-11-10, [decision](../decisions/2026-11-10-packages-on-zigbox-org.md); this supersedes GitHub Pages, and the Pages-workflow wording below now means the site deploy in `Zigbox/zigbox.github.io`), at `/apt` and `/rpm`, with `zigbox-archive-keyring.gpg` and `.asc` beside them. The README gains the install commands (`signed-by=` keyring for apt; a `.repo` file with `gpgcheck=1` and `repo_gpgcheck=1` for dnf). The owner-signed tree reaches Pages as one release asset (owner): the release step uploads the signed `apt/` and `rpm/` trees, as the Mac archive is uploaded, and the Pages deploy job on `main` copies the latest release's asset in byte for byte. CI deploys bytes the owner signed and never builds or signs them. This is a change to the Pages workflow (slice 8).
- **CI** builds the packages on every pull request that touches `src/package/` or the release step, checks reproducibility, and runs the packages demo. It signs with the **test key** (owner), never the archive key, and publishes nothing. The test key is `zigbox_package`'s own OpenPGP Ed25519 signer with a checked-in secret that vouches for nothing; each guest trusts only it, for the packages demo. If slice 7 finds RHEL 9 refuses EdDSA, the rpm guests fall back to `gpgcheck=0` and `repo_gpgcheck=0` in CI, and RSA signatures are checked only by the owner at release (`rpm -K` by hand, in the runbook).

## In the library

`zigbox.trust` exports pure functions, with per-caller storage and no process-wide state:
- the canonical JSON writer and reader, DSSE PAE, the envelope and the in-toto statement, `sign` and `verify`;
- the key file (sealing and opening with a caller-supplied passphrase; the terminal read stays in the CLI) and the public-key text;
- the policy parser and the verdict function;
- the signature record (an in-toto bundle) and the provenance statement;
- the tamper check over a store.

Zigcube's C6 admission (server) and node check (agent) call the same verdict function. A test drives the verdict and `import_trust` from a caller other than the CLI, as M7's `build_library_tests.zig` does. `zigbox_package` is a separate module. `zigbox.push` (lane U) exports `pack`, `export_layout` and `push`; Zigcube's builders call it.

## Slices (commit and stop for review after each; do not push to the working branch)

Three lanes. **Lane T (trust)** is slices 1 to 5, in order. **Lane P (packages)** is slices 6 and 7, in order. **Lane U (push and export)** is slices 10 to 14 (owner, 2026-11-08; "Lane U" below). It starts when slice 2's JSON writer has merged; slice 13 waits for M6c, and slice 14 for slice 3. The lanes run in parallel, each in its own worktree with its own `ZIG_GLOBAL_CACHE_DIR` (AGENTS.md, Disk). Slice 8 starts when lanes T and P and slices 10 to 12 have merged; 13 and 14 join it if merged by then, or are cut. Every slice ends with `zig build check` PASS on the reported commit, and with the fuzzers it touched run as well.

Sizes are relative to M7's slices (M is a typical M7 slice). The owner's answers added about a slice and a half to lane T: the passphrase makes keys a slice of their own, and DSSE, the JSON writer and the larger SLSA record make up the rest. The prune (owner follow-up) takes slice 5 from M to L.

| Slice | Lane | What | Size |
|---|---|---|---|
| 1 | T | Keys, with passphrase encryption | M |
| 2 | T | JSON writer, DSSE, statements, the signature record, `zbx sign` | L |
| 3 | T | Policy and the run gate, the tamper check | L |
| 4 | T | Provenance as an SLSA v1 statement, `inspect --provenance` | L |
| 5 | T | `zbx verify`, `trust export`, `import` and `prune` | L |
| 6 | P | The package writer and the repositories | L |
| 7 | P | The rpm and Debian guests | M |
| 8 | both | The demo, CI, the agent test, the Pages asset step | M |
| 9 | T | The Mac (cuttable, not demonstrated) | S |
| 10 | U | Pack and `zbx store export --oci` | L |
| 11 | U | The upload protocol, the test registry, `zbx push` | L |
| 12 | U | Credentials and write-scoped tokens (Docker Hub, GHCR) | M |
| 13 | U | ECR push on M6c (cuttable) | S/M |
| 14 | U | The derived binding (owner: build it, 2026-11-08) | M |

1. **Keys (T).**
   - Slice 1 needs no type URI and can start now.
   - Work: `src/trust/key.zig`: the key file (both encryptions, the bounded KDF parameters), its permission check, sealing and opening (argon2id, XChaCha20-Poly1305, the public text as associated data), the key id and the public text. `zbx key new [--no-passphrase] [--passphrase-file]`, `key list` and `key show`; the passphrase file's rules; and the terminal read with echo off, restored on every exit path. Codes `E0901`, `E0902` and `E0911`. The `key` record fuzzer: random and damaged key files never crash parse, never run argon2id with parameters above the bounds, and are accepted only when they re-render to themselves.
   - Tests: a sealed key opens with its passphrase and with nothing else; a flipped byte of the salt, nonce, sealed seed or public text fails to open; a golden key file made from a fixed seed and salt (tests only) opens to the golden public text; `--no-passphrase` writes `"none"` and `key show` says so; no passphrase and no terminal refuses without reading stdin (the simulated host records every read); a passphrase file readable by others is refused.
   - Measure argon2id with the default parameters in the shipped build on this container and in the VM, and record the cost in `docs/demos/m8.md`. If it is over about 1 s, propose lower defaults to the supervisor; do not change them alone.
   - *Mechanical, for Haiku:* the codes' registry boilerplate and error pages once their text is written; the `help`, `zbx schema` (`zbx.key/1`) and `explain` entries; the golden files' copying; `src/trust/` in `ci-changes.sh` (running `m8`).
2. **Statements and signing (T).**
   - **The project domain is `zigbox.org`** (`docs/decisions/2026-11-04-project-domain-zigbox-org.md`): the slice writes `type_uri_base = "https://zigbox.org"`. A golden or test that spells the URI out instead of reading the constant is a review finding.
   - **First part, mergeable alone:** `src/trust/json.zig` (the canonical writer and the bounded reader) uses no type URI, so it is reviewed and merged first. Lane U's config and manifest writers depend on it (2026-11-08).
   - Work: `src/trust/json.zig` (above); base64 and DSSE PAE; the envelope; the in-toto statement, with its subjects, binding and the `sign/v1` predicate; the signature record as an in-toto bundle (parse, render, atomic write under the store lock, `signatures_per_tree_max`, `signature_record_bytes_max`); and `zbx sign` with the uncached tree check. The check reuses `verify.zig`'s id recomputation, moved into a shared function rather than copied. Codes `E0903` and `E0910`. The `trust` record fuzzer: random and damaged envelopes, payloads and records never crash parse, and are accepted only when they re-render to themselves.
   - Tests:
     - PAE matches DSSE's published test vector (`DSSEv1 29 http://example.com/HelloWorld 11 hello world`);
     - an Ed25519 envelope made by us is checked against a reference implementation's output for the same key and payload. Capture it once with the DSSE reference or `in-toto`'s Python library, in this container or in the guest, and say which; REVIEW.md's "checked against real output" applies;
     - a golden statement and a golden envelope;
     - the payload changes with each field it covers, and a signature fails on any flipped byte of the payload, the payload type, the key or the signature;
     - the JSON writer escapes every byte below 0x20, refuses invalid UTF-8, and stops at `json_depth_max`.
   - The simulator crashes at every write of the signature record and asserts that the record is either the old one or the new one.
   - *Mechanical:* `zbx.sign/1` in `zbx schema`, the goldens, and the error pages.
3. **Policy and the run gate (T).**
   - Policy: the policy file (path rules, the bounded ZON schema with M7's reader), the pure verdict over envelopes (trusted key, subjects, binding, predicate type), `zbx policy check`, and the gate in `run_container`, `exec` and the build scheduler (before a step's container starts).
   - Tamper check: the walk in the store child, the `trust/verified/` cache with its equality rule, `verify = "always"`, and gc removing `verified` entries with their tree.
   - Codes `E0904`, `E0905` and `E0907` (`E0906` waits for slice 4's provenance).
   - Simulation tests:
     - over random policies, envelopes and trees, a refused run never reaches `runtime.start` (the simulated host records every spawn) and leaves no record;
     - a tampered object is always found, whether its bytes, mode or owner changed, with or without the cache;
     - a ctime change always re-hashes that object.
   - A test at `policy_keys_max` and one past it.
   - VM check: start `src/testing/vm/main_m8.zig` with a part that makes a key with a passphrase file, signs a pulled `alpine`, runs it under `require_signature`, refuses an unsigned tree, and refuses after an object of the signed tree is changed. Push to `vm/m8-slice3`.
   - *Mechanical:* `m8` in `vm.yml`'s picker and `all` list, the `demo-m8` entry in `build.zig`'s demo table and `ci-changes.sh`'s demo list (as `m7`'s are), and the goldens.
4. **Provenance (T).**
   - Work: the provenance statement (SLSA v1, built from cache entries, the build record and the running binary), written by `zbx build` on hits and misses; `zbx inspect --provenance` (text and `zbx.provenance/1`); `zbx sign` wrapping the stored record's bytes; `require_provenance` and `E0906`'s three causes; and the optional git source read (cuttable). `docs/demos/m8.md` gains the SLSA field map and the `zbxTree`, `zbxResult` and `blake3` digest-set encodings.
   - Tests:
     - a provenance record is a function of the build's inputs and its times only;
     - an all-hit build of an unchanged project writes the same record apart from its times;
     - the record of a build whose cache was written by 0.3.0 is complete, because the preimage format is unchanged;
     - a record at `provenance_steps_max` steps with every field at its longest fits `statement_bytes_max`;
     - a golden record checks against the SLSA v1 provenance JSON schema, captured once with a real validator; say where.
   - Fuzzer: the `provenance` statement fuzzer, with the same property as slice 2's.
   - *Mechanical:* the schema entry and goldens.
5. **Verify, export, import and prune (T).**
   - Work: `zbx verify` (the six links, `W0903`, `--strict`, `--require-provenance`, `--key`, `--public`, `E0908`); `zbx trust export|import` and `E0909`; `store.export_trust` and `store.import_trust` with the second-caller library test; gc's orphan count; and `zbx trust prune [--apply]` with `W0902` and `store.prune_trust` (Records, gc, export and import).
   - Simulation tests:
     - `verify` never touches the network or the registry;
     - over random stores, prune never removes a record whose tree (or, for provenance, whose result and its tree) is present, and without `--apply` removes nothing;
     - the simulator crashes at every prune `unlink`, and a second run leaves exactly the records whose trees are present.
   - A test at `trust_records_max` orphans.
   - Peer fuzzer property: an imported bundle with any byte flipped is refused whole or re-verifies.
   - VM check: verify runs offline in the guest with its network link down.
   - *Mechanical:* the schema entries (`zbx.trust-prune/1` among them), goldens, the `explain` entries and `W0902`'s registry entry and page.
6. **The package writer and the repositories (P).**
   - Work: the `zigbox_package` module (ar, cpio, deb, rpm, the apt and dnf repository writers, armor, OpenPGP Ed25519 signature packets); `zig build packages`, `-Dsignatures=` and `packages-check`; the two-round signing commands; and `docs/releases/packaging.md`.
   - Unit tests:
     - golden bytes for a small package of each format, with the expected structure taken from a real `dpkg-deb -I` and `rpm -qpi --dump` of that file. REVIEW.md's "checked against real output" rule applies: capture them in the Ubuntu guest, or in this container if `dpkg-deb` and `rpm` are present, and say which;
     - reproducibility (two builds, identical bytes);
     - a header signature placed by `-Dsignatures` leaves the header digest unchanged.
   - A test-key OpenPGP signature made by the module verifies with `std.crypto.sign.Ed25519` over the OpenPGP hash input, as a pair assertion.
   - VM check, in the Ubuntu guest: the deb installs with `apt` from a repository the harness serves over its HTTP server, signed with the test key, and `apt update` prints no signature warning. Push to `vm/m8-packages`.
   - *Mechanical:* `src/package/` in `ci-changes.sh`; the README's install commands, copied from the runbook once it is checked.
7. **The rpm and Debian guests (P).** This slice can start beside slice 6 (booting the guests and provisioning with `dnf`) and finishes with slice 6's packages.
   - Harness: `zigbox_vm`'s image table gains Debian 12 (`genericcloud`), current Fedora (`Cloud Base Generic`) and Rocky 9 (`GenericCloud`) qcow2 images, each pinned by URL and SHA-256 as Ubuntu's is, with cloud-init's package step choosing `apt` or `dnf`. **Harness changes go to the supervisor first** (M7's rule: nothing changes inside `session.zig` or `harness.zig` without them). Zigcube uses this module, so the change is additive and `demo-z7` keeps passing.
   - The key-type probe: on each guest, a test-key Ed25519 signature on the repository metadata and on an rpm header is accepted (`apt update`, `dnf makecache`, `rpm -K`), or the guest's refusal is recorded. The result decides the archive key type (below) and is written to `docs/decisions/`.
   - The packages demo part runs on all four guests.
   - *Mechanical:* the image entries (URL and checksum copied from the distributions' published checksum files).
8. **The demo, CI and the agent test.**
   - `zig build demo-m8` (the trust steps below, exactly, with the PUSH part from lane U) and `zig build demo-m8-packages` (the four guests), with every assertion a unit-tested pure function in `checks_m8.zig`.
   - The upgrade test against the latest tag (0.3.1 if it is cut by then, else 0.3.0). Its store, run records and build cache are read; `zbx run` without a policy behaves as before; with a policy, its images are refused with `E0905`, not a crash; and a build reusing its cache entries writes complete provenance.
   - The agent test (JSON only, passphrase by file); the two CI jobs (the packages job runs only when `ci-changes.sh` selects it); the Pages deploy's copy of the latest release's signed-repository asset; and `docs/demos/m8.md` with the by-hand steps, cuts and failure modes. The failure modes to cover: a lost key or forgotten passphrase, a key file too open, no passphrase without a terminal, a policy that refuses everything, a tampered object and how to recover, a provenance record replaced after signing, a missing input in verify, the disk full during a signature write, orphan records and what pruning them gives up (a pruned signature no longer covers a re-pull), and a package upgrade with a container running.
   - *Mechanical:* the upgrade part copied from `upgrade_m7.zig`, with the tag in `old_release.zon`; the CI jobs copied from `demo-m7`'s; the README and site status lines after green runs.
9. **The Mac (owner: yes; cuttable, not demonstrated).** For the Mac session: add `key`, `sign`, `verify`, `trust` and `policy` to `linux_commands` in `src/macos_main.zig`, with keys and the user's policy on the shared Mac home under a fixed path (the forwarding protocol drops `XDG_*`). The terminal passphrase read is not forwarded: on the Mac, `--passphrase-file` (a path under the shared home) or a `--no-passphrase` key. `build` and `inspect` are not forwarded yet (M7's slice 5 was cut), so provenance on the Mac waits for that.

### Lane U: push and export (owner, 2026-11-08)

The owner's words: "Unless there's a reason not to put push in 8, in it goes." The reasons, blockers and costs are in `docs/decisions/2026-11-08-push-in-m8.md`. Issue #60 (Botpike) asked for `zbx store export --oci`, so export comes first (slice 10) and push builds on it.

**Fixed decisions (push).**
- **One image, one layer.** The packer turns a tree and its config into an OCI image manifest (`application/vnd.oci.image.manifest.v1+json`). The image has one gzip layer of the whole tree, an OCI config, and no index. The source is a result digest (its tree and `Config`), a tree with an image record (its tree and `Settings`), or an image reference. The platform is the host's. Labels are written only from a result.
- **The layer tar** has its own writer, `src/layer/tar_write.zig`, because `std.tar.Writer` writes neither owners nor pax records. It is the inverse of `apply.zig`:
  - entries in byte order of path, each directory before its contents;
  - ustar headers, with a pax record only for a long path or link name and for each kept xattr (`SCHILY.xattr.`);
  - owners from the tree, empty user and group names, mode bits as stored;
  - mtime `store_mtime_seconds` for every entry;
  - each further path of a hard-linked object as a link entry to the first;
  - two zero blocks, and no padding past them.

  Nothing on the host leaks in: no host name, user name, time or umask.
- **Compression.** std's gzip (`std.compress.flate`), one stream, no intermediate flush, a fixed window and buffer, and the header std writes (no name, mtime 0). Measured here: about 48 MB/s at level 6 and 90 MB/s at level 1. The output does not depend on how the input is chunked. zstd layers are out (Non-goals).
- **Config and manifest** are written by the canonical JSON writer (slice 2's first part, below), with members in a fixed order. The config holds `architecture`, `os`, `config` (`Entrypoint`, `Cmd`, `Env`, `WorkingDir`, `User`, `Labels`, each only when set), and `rootfs` (`layers`, with one `diff_id`: the sha256 of the uncompressed tar). There is no `created` and no `history`. The manifest carries two annotations: the tree digest and the layer-writer version. Their keys are `org.zigbox.tree` and `org.zigbox.layer-writer`, named constants next to the type URIs.
- **Digest stability** holds per `layer_writer_version` (a constant, starting at 1). The same tree, config and platform give the same layer, config and manifest bytes on every host, and so repeat pushes are no-ops. Golden digests for a fixed tree guard against unnoticed change. A deliberate change, or a Zig upgrade that changes std's gzip output, bumps the version and is noted in the release. **Round trip:** `zbx pull` of a pushed manifest gives back the same tree digest when both stores are in the same id mode (owners kept, or squashed to 0 by `squash_owner`). `docs/demos/m8.md` states both promises, as issue #60 asked.
- **The pack record.** `pack/<tree hex>-<writer version>` in the store holds the layer's digest, diff_id and size, so a second push or export of the same tree does not compress again. The layer, config and manifest bytes go into the blob cache (`blobs/sha256`). gc removes a pack record with its tree. The pushed or exported manifest gets an image record (manifest digest, tree and settings), so that `zbx run`, `zbx sign <ref>@sha256:<manifest>` and `trust export` find it on the host that made it.
- **Export.** `zbx store export --oci <source> DIR` writes an OCI image layout (`oci-layout`, `index.json` naming the one manifest, `blobs/sha256/`). `DIR` must not exist, or must be an empty directory. `--output json` prints `zbx.export/1`: the manifest, config and layer digests and the total size. This is issue #60's form.
- **The upload protocol** (distribution spec v1.1), per blob, config then layer:
  1. `HEAD /v2/<name>/blobs/<digest>`: a 200 means the blob exists and is skipped.
  2. Otherwise `POST /v2/<name>/blobs/uploads/?mount=<digest>&from=<repo>` when another repository on the same registry is known to hold it. A known holder is a tag of this image record on the same registry. A 201 means mounted. A 202 means the registry declined, and the upload goes on in the session it opened.
  3. Otherwise `POST` opens a session, and the blob goes up in `PATCH` chunks of `push_chunk_bytes`. Each `Location` is followed, relative or absolute, and each `Range` is checked against the bytes sent.
  4. `PUT <location>?digest=<digest>` closes the session.

  Then `PUT /v2/<name>/manifests/<tag>`. Its returned `Docker-Content-Digest` must equal ours. The manifest goes up only after every blob it names is confirmed. Retries and timeouts reuse pull's bounds. `src/registry/net.zig` gains the methods, request bodies streamed from a file, and the `Location`, `Range` and `Content-Range` headers. It stays one module.
- **Destinations.** The destination is a reference with a tag (`ghcr.io/o/r:v1`). Pushing by digest only is refused (owner, 2026-11-08). `ZBX_REGISTRY_MIRRORS` is never used for push. Loopback hosts use plain HTTP, as pull does (`reference.zig`).
- **Credentials.** A push takes at most one credential:
  - `--username <name>` with `--password-file <path>` (the file `0600` and the user's, as for key passphrases) or `--password-stdin`;
  - or, for ECR, M6c's credential sources (slice 13).

  There is no environment variable for the password (as for key passphrases) and no `config.json` or credential helper (Non-goals). The secret sits in one fixed buffer of `push_credential_bytes_max` and is zeroed after the push (`std.crypto.secureZero`). It never appears in a diagnostic, a log, JSON output, the store or a file. A registry that answers `Basic` gets it only at its own origin, over TLS or loopback. A registry that answers `Bearer` gets it only at the token realm, which must use https and satisfy the realm rule (below). The token asks for `repository:<name>:pull,push`, and also `repository:<from>:pull` for a mount. The bearer token goes only to the registry's origin, never to an upload `Location` or a redirect on another origin, which gets no `Authorization` header. M6c asked for scope and action in the types: `Scope` is `{ repository, actions: { pull, push } }`, and a pull-only token is never offered for a push.
- **The realm rule (owner, 2026-11-08).** A realm whose host is the registry's host, or a known pair (`registry-1.docker.io` with `auth.docker.io`), is allowed, and so is loopback in tests. Any other realm host is refused with `E0554` before the password is sent. A registry cannot send a user's password to a third host by naming it in a challenge.
- **Tags and `zbx.lock`.** A push adds the destination reference as a tag on the pushed image's record, as pull does. It never writes `zbx.lock`, which records what a project *uses*. A consumer's `zbx pull` of the pushed reference locks it as usual (owner, 2026-11-08). The lock format is unchanged.
- **Signatures reach the pulling host** by `zbx trust export` and `trust import`, as now. No registry storage (Non-goals). Three cases on the pulling host:
  - A tree-only signature counts for the pulled image in the same id mode.
  - A manifest-bound signature (`zbx sign <ref>@sha256:<m>` on the builder after the push) counts for runs of that manifest.
  - A result-bound signature, and so signed provenance, counts only with slice 14.
- **Library.** `zigbox.push` exports `pack` (store and source to `Packed`: the three digests, diff_id and sizes), `export_layout`, and `push` (store, network, `Packed`, destination, `Credentials`) returning a per-blob report. `Credentials` is a tagged union, `none`, `basic` or `ecr`, of caller-owned slices that the library never copies past the call. Zigcube's builders call it with credentials they hold. A second-caller test drives `pack` and `push` against the test registry, as `build_library_tests.zig` does.
- **Diagnostics (`05xx`; owner approved the codes, 2026-11-08; each slice registers the codes it first uses).** `E0527`–`E0549` stay free for M6c, and push takes `0550`–`0559`:

  | Code | Refusal |
  |---|---|
  | `E0550` | The source cannot be packed: no such digest, or its tree is not whole. |
  | `E0551` | The destination is not pushable: no tag, digest only, or not a reference. |
  | `E0552` | The registry wants credentials and none were given. |
  | `E0553` | The registry or realm refused the credentials, or granted no `push` scope. Names the registry and the scope, never the secret. |
  | `E0554` | The token realm's host is not allowed by the realm rule. |
  | `E0555` | The registry refused a blob upload (status, or a digest or range mismatch). |
  | `E0556` | The registry refused the manifest (its error code; ECR: the repository does not exist). |
  | `E0557` | The export directory exists and is not empty. |
  | `E0558` | The password file is unsafe (open to others, or over the bound). |
  | `W0550` | The destination tag names a manifest with the same tree but another layer-writer version: the digest changed. |
  | `W0551` | A pulled image's tree differs from its tree annotation: different id modes (slice 14). |

- **Bounds and defaults (owner, 2026-11-08):**
  - gzip level 6, the std default;
  - `push_chunk_bytes`: 8 MiB;
  - `push_credential_bytes_max`: 4 KiB for the username and the password together;
  - the realm rule as above;
  - a tag is required;
  - push never writes `zbx.lock`.

**Slices (lane U).** Lane U runs in its own worktree once slice 2's JSON writer has merged (below). Slices 10, 11 and 12 go in order. Slice 13 waits for M6c to merge. Slice 14 waits for slice 3's verdict function.

10. **Pack and export (U).**
   - Work: `tar_write.zig`; the gzip stream; the config and manifest writers; the pack record; image records for packed manifests; `zbx store export --oci` with `zbx.export/1`; `zbx push --dry-run` (packs and prints the digests without the network); `layer_writer_version`; and codes `E0550` and `E0557`.
   - Tests:
     - golden bytes and digests for a fixed tree covering every entry kind (directory, file, symlink, hard link, a long path, a kept xattr);
     - two packs give identical bytes, and so do packs through different buffer sizes;
     - `apply.zig` of the packed layer gives back the same tree digest, in both id modes;
     - the golden layer's `tar -tvv` listing, and the layout read by a real OCI tool, captured once in the guest or this container. Say which (REVIEW.md, "checked against real output").
   - Fuzzer: `pack`. A random tree packs and re-applies to the same digest, and the tar writer never writes past its header bounds.
   - VM check: export in the guest as two users, with identical digests. Push to `vm/m8-export`.
   - *Mechanical:* `zbx.export/1` in `zbx schema`, the goldens, `src/push/` in `ci-changes.sh`, and the help entry.
   - Size: L.
11. **The upload protocol (U).**
   - Work: `net.zig`'s HEAD, POST, PATCH and PUT, with streamed bodies and the new headers; the upload sequence and mount; the manifest PUT and its digest check; `zbx push` without credentials (loopback, or a registry that allows anonymous push); `zbx.push/1` (per blob: `exists`, `mounted` or `uploaded`, then the manifest digest); and codes `E0551`, `E0555` and `E0556`.
   - The test registry: `src/testing/vm/push_fixture.zig` accepts uploads into fixed arrays. Faults are named by repository, as `registry_fixture.zig`'s are:
     - relative and absolute `Location`;
     - a 202 without `Range`, and a short `Range`;
     - a refused chunk (416);
     - a digest mismatch at close;
     - a declined mount;
     - `MANIFEST_INVALID`, `MANIFEST_BLOB_UNKNOWN`, and 429;
     - an upload `Location` on another origin. The simulator's network and `registry_server.zig` both serve it.
   - Simulation tests:
     - over random faults, a push either ends with the manifest and every blob it names present, or fails with a code;
     - the manifest is never PUT before its blobs are confirmed;
     - a repeat push sends no blob bytes.
   - Fuzzer: the `registry` fuzzer gains upload answers (`Location`, `Range`, error bodies).
   - Library test: the second-caller test of `zigbox.push`.
   - VM check: in the guest, `zbx run -d --publish 5000:5000 registry:2` (pulled through the mirror; a real registry, not ours). Then push the M7 result to `localhost:5000`, push again (all `exists`), and pull as a second user: the tree digest is unchanged. Push to `vm/m8-push`.
   - *Mechanical:* `zbx.push/1` in `zbx schema`, the goldens, and the error pages once their text is written.
   - Size: L.
12. **Credentials and write-scoped tokens (U).**
   - Work: the credential flags and the password file's rules; the `Basic` challenge; the Bearer exchange with `Basic` at the realm and the push scope; the realm rule; the origin-only rule for tokens; zeroing; and codes `E0552`, `E0553`, `E0554` and `E0558`. Docker Hub (`registry-1.docker.io` via `auth.docker.io`) and GHCR (`ghcr.io/token`) are the targets.
   - Tests:
     - the simulated host records every byte written to stdout, stderr, files and logs, and every request with its host and headers. Over random runs with a marker password, the marker appears only in requests to the allowed host;
     - a realm on another host is refused before any credential is sent;
     - a token granted `pull` only gives `E0553` naming `push`;
     - redirects and upload `Location`s on another origin carry no `Authorization`.
   - Captured answers: Docker Hub's and GHCR's 401 challenges and token responses, recorded once by hand without secrets, as fixtures.
   - VM check (owner allowed it, 2026-11-08): the `vm.yml` job gets `packages: write` and pushes to `ghcr.io/zigbox/zigbox-demo:<run id>` with `GITHUB_TOKEN` via `--password-stdin`. Push to `vm/m8-push-ghcr`. Docker Hub is checked by hand (no CI account), with the steps in `docs/demos/m8.md`.
   - Review: for secrets, as slice 1 is.
   - *Mechanical:* error pages and the help text.
   - Size: M.
13. **ECR push (U; after M6c merges; cuttable).**
   - Work: M6c's credential sources and `GetAuthorizationToken` with `Scope.actions.push`; the ECR token used as `Basic` at the registry origin; and `E0556`'s ECR cause (the repository must exist, since ECR does not create it).
   - Tests: recorded ECR answers, with no AWS account in CI. A by-hand run against a real repository is recorded in `docs/demos/m8.md`, or the cut is.
   - *Mechanical:* fixtures copied from M6c's.
   - Size: S/M.
14. **The derived binding (U; owner: build it, 2026-11-08).**
   - Work: pull keeps `Labels`, so the image record goes to version 3 (version 2 still reads). For a run of a pulled manifest, the verdict derives the `zbxResult` from the tree and the recorded settings and labels, as M7 computes it. A result-bound statement, including signed provenance, counts when the derived result matches. Pull checks the tree annotation and warns `W0551` on a mismatch.
   - Tests:
     - the derived result of a pushed-then-pulled result equals the original, for random configs;
     - any changed config field changes it;
     - a version 2 record reads, and derives no result.
   - Without this slice, `require_provenance` does not hold for pushed images. The brief says so in `docs/demos/m8.md`.
   - *Mechanical:* the record version's goldens.
   - Size: M.

The lane is about four M7 slices: 10 (L), 11 (L), 12 (M), 13 (S/M), 14 (M), plus the PUSH part of slice 8. Slice 12 is reviewed hardest in the lane (credentials), and slice 10 next (the digests are a promise).

Slices 2 and 3 are the riskiest (the statement is the contract; the gate is the promise) and are reviewed hardest. Slice 1 is small but is reviewed for the secret's handling: no secret or passphrase in a diagnostic, a log or a JSON output, and no secret left in a buffer after use (`std.crypto.secureZero`). Slice 6's rpm writer is the riskiest of lane P: rpm's header format is poorly documented, so test against `rpm` itself early.

## The demo: `zig build demo-m8`

This is the Ubuntu 24.04 guest, the ordinary user, and M7's checked-in project (`src/testing/vm/m7_project/`) copied to `~/hello`. Images come through `mirror.gcr.io` with the blob cache. Parts in order: UPGRADE, SPEC, PUSH, ACCEPT, AGENT. Assertions on codes, digests and verdicts are exact.

1. **Build and sign.** `zbx key new demo --passphrase-file ~/pass` (a `0600` file the harness writes) prints the key id and its encryption, `passphrase`. `cd ~/hello && zbx build` gives the golden result digest from `m7_expected.zon`. `zbx sign <digest> --passphrase-file ~/pass` exits 0. `zbx inspect --provenance <digest> --output json` matches its schema and is an in-toto statement with `predicateType` `https://slsa.dev/provenance/v1`, names the two bases by their locked manifest digests, the steps `compile` and `notice` with their input and output trees, the build file's hash, the `zbx` version and `signed: true` covering this record. The text form's base, step and builder lines match the golden apart from times.
2. **Policy.** Write `~/.config/zbx/policy.zon` with `demo`'s public key and `.require_signature = true`. `zbx run <digest>` prints `hello from zigbox`. `zbx pull alpine:3.20 && zbx run alpine:3.20 true` exits 125, and stderr starts `error[ZBX-E0905]:` and names `~/.config/zbx/policy.zon` and `require_signature`. `zbx ps -a` lists no new container, and no run record or scope was created (before and after listings compared).
3. **Tamper.** The harness finds the object of `/usr/local/bin/hello` through the store's own JSON listing, not by computing the path. It appends one byte as the user (`chmod u+w`, then `printf x >>`). `zbx run <digest>` exits 125 with `error[ZBX-E0907]` naming `/usr/local/bin/hello`, and `zbx store verify` names the same object. The byte is then truncated away: `zbx run` works again (the ctime changed, so it re-hashed).
4. **Verify, offline.** The guest's network link is taken down (privileged setup in the VM). `zbx verify <digest> --output json` exits 0, and every link from the signature to each base, each step's input and output tree and the build file reports `ok`. The link comes back up.

**PUSH** (lane U). Settled by slice 11:
- `zbx run -d --publish 5000:5000 registry:2` runs a real registry in the guest, pulled through the mirror.
- `zbx store export --oci <digest> ~/out --output json` prints the golden manifest digest (a new field in `m7_expected.zon`).
- `zbx push <digest> localhost:5000/hello:demo` prints the same digest. A second push reports every blob `exists`.
- `zbx sign localhost:5000/hello:demo@sha256:<m> --passphrase-file ~/pass`, then `trust export` and, as a second user, `trust import`, `zbx pull localhost:5000/hello:demo` (the tree digest is the built tree's) and `zbx run` under `require_signature` prints `hello from zigbox`.
- With slice 14: `require_provenance` passes there too.
- The same push to GHCR on CI with `GITHUB_TOKEN` (owner allowed it, 2026-11-08).

ACCEPT also checks:
- `zbx store rm` of `alpine:3.20`'s root, then `zbx store gc` and a re-pull. A signature made on the pulled `alpine` before the removal still makes `zbx run alpine:3.20 true` pass (survives re-pull).
- `require_provenance` refuses a tree-only signature (`E0906`).
- A statement that binds a result covers that result's config, not only its tree: a second result with the same tree and another entrypoint is refused under the first result's signature. A `-- <cmd>` override on the signed result stays allowed, since the command is the user's own.
- `zbx policy check` agrees with `run` on all three cases.
- A malformed policy is refused with `E0904` and its line and column.
- A step whose base is unsigned is refused under `require_signature`, naming the step.
- `zbx trust export` and `zbx trust import` into a second user's store make the image run there.
- **Prune.** After the re-pull check, `alpine:3.20`'s root is removed and gc run again. `zbx trust prune --output json` lists `alpine`'s signature record as an orphan, with `dry_run: true`, and the record is still there. `zbx trust prune --apply` removes it and keeps the signed result's records, `zbx store gc` then reports no orphans, and after a re-pull `zbx run alpine:3.20 true` exits 125 with `E0905`: the pruned signature is gone.
- `zbx sign` with stdin from `/dev/null` and no `--passphrase-file` exits 1 with `E0911` at once, and a wrong passphrase file gives `E0911` too. Neither writes a record.
- The exported bundle is one envelope per line, and its `payloadType` is `application/vnd.in-toto+json`.

**`zig build demo-m8-packages`**: Ubuntu 24.04, Debian 12, current Fedora and Rocky 9, one after another. The harness's HTTP server serves the repository trees signed with the test key. On each guest, as root (privileged setup in the VM):
1. The README's commands for that distribution, then `apt update` or `dnf makecache` with no signature warning.
2. Install, and `zbx version` prints the build's version. As the ordinary user, with a subordinate range given: `zbx pull alpine:3.20 && zbx run alpine:3.20 echo ok` prints `ok`. This is cuttable to `zbx doctor` on a guest whose kernel or packages fall short (linux-packages.md, unknown 1).
3. Upgrade to a second build with a higher test version, in place, and `zbx version` changes.
4. Remove the package: `/usr/bin/zbx` is gone, and the user's store is still there.

`rpm -K` on the rpm reports the signature as valid on the two rpm guests.

**What the harness lacks today.** It has only the Ubuntu cloud image, and cloud-init provisioning is apt-only. Fedora's and Rocky's cloud images use cloud-init too, but booting them under the harness (console login, the NoCloud seed, `dnf` in provisioning) is untested. That is a **known unknown**: slice 7 settles it first. A second known unknown is **the archive key type**. RHEL 9's rpm may refuse EdDSA signatures, which would also make the Ed25519 test key useless there. Slice 7's probe answers it before the owner makes the archive key. Do not assume. If EdDSA is refused, the archive key is RSA 4096, and the CI test signature on the rpm guests falls back as the packages decisions above say.

## Non-goals

- Sigstore, keyless signing, OIDC identities and transparency logs (deferred by the spec).
- Signatures in registries (cosign, OCI referrers or the `subject` field). Signatures travel by `trust export` and `trust import`.
- For push (lane U): multi-platform indexes; zstd layers; keeping a pulled image's original layers; deleting tags or manifests; OCI tar export and OCI import; `docker login`, `config.json` and credential helpers; a password from an environment variable; and pull from private registries with push credentials (decision `2026-11-08-push-in-m8.md`).
- Hardware keys, ssh-agent and PKCS#11; key rotation, expiry and revocation lists. Revocation is removing a key from the policy file.
- Thresholds (k-of-n signers) and policy scoped by image name or registry. Allowed source repositories are C6's.
- The agent-operability rules (deny `--net host`, deny mounting `$HOME`) in the policy file. The schema leaves room for them (spec note).
- An SBOM, and signing `zbx` release binaries with M8's own keys ("Trust in zbx itself").
- Zigcube's packages (C3), the Homebrew formula, maintainer scripts, editing `/etc/subuid`, publishing from CI, and any distribution beyond the four.
- Demonstrating M8 on the Mac.
- Changing a key's passphrase, a passphrase from an environment variable, and an agent that caches unlocked keys.
- Other in-toto predicates (SBOM, VSA, test results), and reading envelopes signed by anything but our Ed25519 keys (cosign or sigstore bundles, ECDSA, RSA). Import refuses them with `E0909`.

## Scope that can be cut while keeping the demo

Record any cut in `docs/demos/m8.md`.
- **The git source** in provenance.
- **The `cached` tamper check**: keep `always` and document the measured cost. The demo still passes.
- **Exec and build gating**: `run` alone is the spec. The owner chose the gating, so cutting it needs the owner.
- **`zbx trust export|import` as commands**: the library pair stays for Zigcube, and ACCEPT's two-user check goes.
- **`zbx key list|show`**: `key new` prints what the demo needs.
- **A full `zbx run` on Debian 12 or Rocky 9**: install, `zbx version` and `zbx doctor` there only.
- **rpm header signatures**: sign `repomd.xml` only (`repo_gpgcheck=1`, `gpgcheck=0`), if slice 7 finds the header signature costs more than a slice part. The demo's "no signature warning" holds; `rpm -K` goes.
- **The terminal passphrase read**: keep `--passphrase-file` only. The demo already uses the file.
- **Slice 9 (the Mac).**

Not cuttable (owner, 2026-11-04): passphrase encryption of keys, and in-toto statements in DSSE envelopes.

Not cuttable (owner, 2026-11-08): slice 14, the derived binding.

## Owner decisions

The owner answered this brief's eight questions on 2026-11-04. The answers and what each changed are in `docs/decisions/2026-11-04-m8-owner-answers.md`. In short:
1. Keys are passphrase-encrypted, with `--no-passphrase` allowed only when asked for.
2. in-toto Statement v1 in DSSE envelopes, now, with SLSA v1 provenance.
3. `exec` and `build` are gated, and `pull` is not.
4. The Mac forwards the trust commands and is not demonstrated (slice 9).
5. Verify-on-run is `cached`.
6. gc never collects trust records; `zbx trust prune` removes orphans when asked, in M8 (follow-up, superseding "defer prune to C5").
7. CI signs with a checked-in test key.
8. The signed repositories reach Pages as a release asset.

The brief above is written to these answers. It also made the smaller choices they left open, and the owner answered six follow-ups on them the same day (decision file, "Follow-ups"): our `sign/v1` and `build/v1` type URIs go under a proper project domain, not `zigbox.github.io`, and the owner has yet to name it (blocker for slice 2); the `zbxTree` digest key, signed provenance surviving a rebuild, the `keyid` as the full public text and argon2id's defaults (64 MiB, 3 passes, measured in slice 1) are accepted; and the prune is built in M8. The `zbxResult` name and allowing an unencrypted key only with `--no-passphrase` stand as written.

## Spec notes (flagged, not changed)

- **Push and export are in M8** (owner, 2026-11-08). SPEC.md's snapshot says so (this branch). The live doc should gain the same, since it wins over the snapshot (AGENTS.md).
- **M6c's brief gives its codes as `04xx`**, which is the store's range. Registry codes are `05xx`, and lane U leaves `E0527`–`E0549` to M6c.

- **Packaging is not in the spec.** The spec (rev 91) does not mention deb, rpm, apt or dnf. The 2026-11-04 decisions put packages in M8 and say the live doc should gain them before this brief. It has not. The supervisor should add the scope, the demo step and the acceptance line above to M8 in the live doc.
- **"Signatures are over tree digests"** leaves the run config (entrypoint, user, env) unsigned. The brief keeps the tree as the subject and lets a statement bind the result or manifest (Fixed decisions, "Why the binding"). The spec could say "over tree digests, optionally bound to the image's config".
- **"Policy refusals happen before any process starts."** The tamper check must read objects owned by container ids, which only the store's namespace child can do. The brief reads the criterion as "before any workload process". The spec could say so.
- **"Tamper with one file in the stored tree"** is also tampering with every materialized farm of it (hardlinks share the inode). The spec does not say what checking costs. The brief measured it (Fixed decisions, "The tamper check").
- **"Require provenance"** does not say whether the provenance must be signed. Unsigned provenance is a claim anyone can write, so the brief requires a trusted envelope carrying it.
- **"`zbx verify` walks to every input"**: inputs can be collected by gc after the build. The brief reports absent inputs as `W0903` and fails only on damage, or on absence with `--strict`.
- **Agent operability's policy file** ("a minimal form of M8's run policy, brought forward", denying `--net host` or mounting `$HOME`) was never built. M8's policy file is its natural home. The brief leaves the rules out (Non-goals) but keeps the schema open for them. The spec could move that bullet to M8 or later.
- **Formats.** The spec does not name a signature or provenance format. The owner chose in-toto Statement v1 in DSSE envelopes, with SLSA v1 provenance (decision `2026-11-04-m8-owner-answers.md`). The live doc could say so.
- **"Trust in zbx itself"** (signed releases, an SBOM) is partly met by M8's signed packages. The SBOM and M8-key signatures on release binaries are not in M8.
- **Current Fedora's rpm** may be rpm 6, which enforces signature checks by default. If so, the test key must be imported before the first install. Slice 6 checks this; the spec says nothing either way.
