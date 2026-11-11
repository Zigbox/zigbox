# The 0.5.0 Mac build is signed by the owner; CI signing comes after

Date: 2026-11-11. Owner's call, on the supervisor's proposal.

0.5.0 ships a Mac build. 0.4.0 shipped without one, so the tap is still at 0.3.1 and 0.5.0 is
the first Mac release that carries M8. The Mac build is signed as it was for 0.1.0 to 0.3.1: the
owner runs `zig build mac-release -Dnotarize` on their own Mac, with the Developer ID certificate
in its keychain and the notarytool profile, after the tag, and uploads the zip to the release.
The supervisor then bumps the Homebrew formula in `Zigbox/homebrew-tap` (version, URL,
SHA-256).

Before the tag, the `mac` workflow must be green on the commit the release is cut from, on the
self-hosted runner, and the real-Mac checks of M8 slice 9 listed in `docs/demos/m8.md` must have
run on a Mac, since none of them has run yet.

Moving the Mac signing into the release workflow (a Developer ID `.p12` and a notary API key as
secrets of the `release` environment, used on the self-hosted runner), as the package signing
moved (2026-11-11-ci-signs-packages-with-a-subkey.md), comes after 0.5.0. It is left out of 0.5.0
because minimizing the time to release is an overall constraint
(2026-11-11-minimize-time-to-release.md).
