# Linux packages are part of M8 (owner, 2026-11-04)

*Decided 2026-11-04, by the owner.*

Refines `2026-11-04-linux-packages.md`: the deb and rpm packages of `zbx` are part of M8 (Trust),
not only shipped in the same release. Zigcube's packages and its signed macOS `zcube` are part of
C3. M8's Ed25519 signing work and the archive signer share code. SPEC's M8 section does not list
packaging yet; the live design doc should gain it before M8's brief is written. Detail:
`docs/briefs/linux-packages.md`.
