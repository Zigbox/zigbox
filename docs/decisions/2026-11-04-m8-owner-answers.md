# M8: the owner's answers to the brief's open questions

*Decided 2026-11-04, by the owner (answers) and the supervisor (what each changes).*

The M8 brief (`docs/briefs/M8-trust.md`, PR #54) asked the owner eight questions. The answers are quoted below, then what each one changes. The brief has been rewritten to read as decided; this file is the record of why.

## 1. Where keys live and how they are protected

**Answer:** "Add passphrase now."

**What changes:**
- Keys still live in `$XDG_CONFIG_HOME/zbx/keys/` (directory `0700`, `<name>.key` `0600`, refused when looser). That part of the recommendation stands.
- The secret key is **encrypted with a passphrase in M8**. The key is derived with argon2id (`std.crypto.pwhash.argon2`) and the secret sealed with XChaCha20-Poly1305 (`std.crypto.aead.chacha_poly.XChaCha20Poly1305`), both from std. The key file records `.encryption = "argon2id-xchacha20poly1305"`, the argon2id parameters and salt, the nonce and the sealed secret. The parameters are stored per file, so later defaults can change without a new format. The public key is the associated data, so a sealed secret moved under another public key fails to open.
- A passphrase comes from `--passphrase-file <path>` (the file's first line; a file readable by group or others is refused, as the key file is) or, when stdin and stderr are a terminal, from the terminal with echo off. **With neither, zbx refuses (`E0911`); it never waits for input.** This is the one place zbx reads a terminal, and agents always pass `--passphrase-file`.
- **An unencrypted key is still allowed, but only by asking for it:** `zbx key new <name> --no-passphrase` writes `.encryption = "none"`. `key show` and `key list` print the encryption, so an unencrypted key is visible. The reason: CI, test fixtures and Zigcube's node-local keys (C6, root on a node) have no one to type a passphrase and nowhere better to keep a passphrase file than beside the key. Without the flag, `key new` requires a passphrase.
- New code `E0911` (no passphrase available, or it does not open the key). A forgotten passphrase is a lost key; `docs/demos/m8.md` says so under failure modes.
- Slice 1 grows from "keys and signatures" to "keys", a whole slice (brief, Slices).

## 2. Signature and provenance formats

**Answer:** "Let's in-toto/DSSE now. We'll have to."

**What changes:** every signature is a **DSSE envelope** ([DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)) holding an **in-toto Statement v1** ([statement.md](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)), signed with Ed25519. The brief's own binary statement is gone.

- **Payload type** `application/vnd.in-toto+json` ([envelope.md](https://github.com/in-toto/attestation/blob/main/spec/v1/envelope.md)).
- **The signed bytes** are DSSE's PAE: `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`, over the payload exactly as stored. The payload is canonical JSON written by our own bounded writer (members in schema order, no whitespace, integers only, a fixed string escape set). DSSE needs no canonical form, since it signs bytes, not a JSON value. We keep one anyway so that the same statement is the same bytes on every machine, and so parse can accept only what render writes. It is not RFC 8785 (JCS): members are in schema order, not sorted.
- **Subjects.** The first subject is always the tree: `{"name": "tree", "digest": {"zbxTree": "<64 hex>"}}`. in-toto's DigestSet ([digest_set.md](https://github.com/in-toto/attestation/blob/main/spec/v1/digest_set.md)) allows algorithms outside its list (its example is `{"somecoolhash": "abcd"}`) on the condition that "new algorithms MUST document how the value is encoded". BLAKE3 is not on the list. The supervisor had suggested a `blake3` key, but a bare `blake3` would read as BLAKE3 over a file's bytes, and a tree digest is BLAKE3 over zbx's tree object encoding (`docs/demos/m3.md`). So the key is `zbxTree`, after the spec's own `gitTree`, and its value is 64 lowercase hex digits. Plain BLAKE3 over a file's bytes (the build file, the lock, the `zbx` binary in provenance) does use the key `blake3`, with the same encoding.
- **Does in-toto allow BLAKE3?** Yes, as a custom algorithm, and nothing in the spec contradicts that. It is **not** one of the named algorithms. The texts, as read on 2026-11-04 from `in-toto/attestation` `main`:
  - [ResourceDescriptor](https://github.com/in-toto/attestation/blob/main/spec/v1/resource_descriptor.md) says only that `digest` is a DigestSet: "A set of cryptographic digests of the contents of the resource or artifact."
  - [DigestSet](https://github.com/in-toto/attestation/blob/main/spec/v1/digest_set.md), "Supported algorithms": `sha256`, `sha224`, `sha384`, `sha512`, `sha512_224`, `sha512_256`, `sha3_224`, `sha3_256`, `sha3_384`, `sha3_512`, `shake128`, `shake256`, `blake2b`, `blake2s`, `ripemd160`, `sm3`, `gost`, `sha1`, `md5`, then `dirHash` and `gitCommit`, `gitTree`, `gitBlob`, `gitTag`. The list has BLAKE2 and no BLAKE3.
  - DigestSet, "Guidelines": "It is RECOMMENDED to use at least `sha256` for compatibility between producers and consumers, unless a different hash algorithm is more conventional"; "Consumers MUST only accept algorithms that they consider secure and MUST ignore unrecognized or unaccepted algorithms"; "**New algorithms MUST document how the value is encoded, e.g. URL-safe base64, lowercase hex, etc.**"
  - DigestSet, "Examples": "`{"somecoolhash": "abcd"}` uses a non-predefined algorithm".
  - The reference Go library (`go/v1/resource_descriptor.go`, `Validate`): "use of custom, unsupported algorithms is allowed and does not not generate validation errors". Its known-algorithm table has no BLAKE3 either.

  So BLAKE3 is allowed, with two consequences. First, we must document our encoding, which `docs/demos/m8.md` does. Second, a third-party consumer is told to *ignore* a key it does not recognize, so a statement whose only subject digest is BLAKE3-based gives that tool nothing to match. That is acceptable, because those tools do not run our trees. The `sha256` manifest binding is the one subject they can match. The key name stays `zbxTree` rather than `blake3`, for the reason given above: the value is not BLAKE3 over a file's bytes.
- **The binding** is an optional second subject: `{"name": "result", "digest": {"zbxResult": "<hex>"}}` for an M7 result, or `{"name": "<reference>", "digest": {"sha256": "<manifest hex>"}}` for an image manifest. The manifest uses the standard `sha256` key, so OCI tools can match it. in-toto says a predicate applies to each subject. Our policy reads a second subject as a narrowing: a statement with one counts only for a run of that result or manifest, and a statement with only the tree counts for any config. A third-party tool will read the bound statement as covering the tree too, which is a weaker reading. It is harmless, because those tools do not run our trees. Statements have at most `statement_subjects_max` (2) subjects, tree first.
- **Predicate types.** With provenance, the statement **is** the provenance: `predicateType` `https://slsa.dev/provenance/v1`, and the predicate is SLSA v1 provenance. Without it (a tree, a pulled image, or a result built before 0.4), `predicateType` is our own `https://zigbox.github.io/zigbox/attestation/sign/v1`, and its predicate holds only a claimed `signedAt` time.
- **The provenance digest** is BLAKE3 over the provenance statement's payload bytes. `zbx build` writes that payload, unsigned, to `trust/provenance/<result hex>`. `zbx sign` wraps those exact bytes in an envelope, so the signed provenance carries itself rather than naming a record by digest. `require_provenance` is met by a trusted envelope whose predicate is SLSA v1 for this tree, with its binding matching. Rebuilding the same result later replaces the stored record, but it no longer voids the signature: the signed provenance still truly describes a build of this exact result. `inspect --provenance` says whether the signed provenance and the stored record are the same bytes.
- **The key id in the envelope.** DSSE's `keyid` is an unauthenticated hint. We set it to the full public key text `zbx-ed25519:<64 hex>`, so that `trust import` and `verify` can check every signature without a key directory. Trust still comes only from the policy's key list.
- **Records are still per tree.** `trust/signatures/<tree hex>` is an in-toto bundle, JSON Lines with one envelope per line, holding at most `signatures_per_tree_max` lines. `zbx trust export` writes the same format (`.intoto.jsonl`). So "an `--output in-toto` export later" is moot.
- **Cost:** a bounded canonical JSON writer, DSSE PAE, base64, and parse-to-render checks on payloads and envelopes. That makes a slice of its own (the new slice 2). Provenance becomes the larger SLSA document (slice 4 grows).

## 3. Policy on `exec`, `build` and `pull`

**Answer:** "Yes." The recommendation stands: `exec` gets the verdict without a re-hash, each `build` step's base is checked, and `pull` is not gated.

## 4. The Mac

**Answer:** "Yes." The recommendation stands. `key`, `sign`, `verify`, `trust` and `policy` are forwarded to the Linux `zbx`, with keys and the user's policy on the shared Mac home. This is a separate, cuttable slice (now slice 9), and it is not demonstrated. `--passphrase-file` paths are forwarded like any other path under the shared home. A terminal passphrase prompt is not forwarded: on the Mac, `--passphrase-file` or a `--no-passphrase` key is required.

## 5. Verify-on-run

**Answer:** "Yes." The recommendation stands: `cached`, a full re-hash on the first checked run, then `lstat` equality on `(inode, size, ctime_ns)`, and `verify = "always"` available.

## 6. Signatures and provenance across gc, export, import and peer fetch

**Answer:** "Defer prune to C5."

**What changes:** the recommendation stands (records are not roots, gc never removes them, export and import as a self-verifying bundle, `store.export_trust` and `store.import_trust` beside Z4's pair). Orphan records accumulate, bounded by `trust_records_max`, and `zbx store gc` reports how many there are. **The prune command is deferred to Zigcube's C5.** C5 is a Zigcube milestone, not a Zigbox one. The prune belongs in whichever Zigbox milestone or release C5 pins, and that is for the supervisor to name when C5 is briefed. Until then the orphan count is shown and nothing removes orphans. If a store reaches `trust_records_max`, signing and import refuse with `E0909`/`E0910`, naming the bound.

## 7. How CI shows "no signature warning"

**Answer:** "Good enough for now." The recommendation stands: `zigbox_package` has its own OpenPGP Ed25519 signer, with a test key whose secret is checked in. If slice 7 (formerly 6) finds that RHEL 9 refuses EdDSA, the rpm guests fall back as the brief describes.

## 8. How the signed repository reaches Pages

**Answer:** "Yes." The recommendation stands: the owner uploads the signed `apt/` and `rpm/` trees as one release asset, and the Pages deploy on `main` copies the latest release's asset in byte for byte.
