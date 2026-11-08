# The OpenPGP signature bound is 1024 bytes

Date: 2026-11-08. Approved by the supervisor in the slice 6 re-fix brief.

`openpgp_signature_bytes_max` (`src/constants.zig`) is the most bytes one binary OpenPGP
signature (an rpm header signature, tag 268) or detached signature the packager holds. It was
512, enough for the Ed25519 test key (144 bytes) and nothing else. M8's brief names RSA 4096 as
the archive key if RHEL 9 refuses EdDSA, and a genuine RSA 4096 header signature does not fit.

## Measurement

Real gpg 2.4.4 signatures over the same text, `gpg --detach-sign`, SHA-512:

| Key | Signature bytes |
| --- | --- |
| Ed25519 | 144 |
| RSA 4096 | 566 in the review's run, 591 here (the signer's user id subpacket varies) |

The bytes are the 512-byte RSA signature value itself plus 54 to 79 bytes of packet header,
issuer fingerprint, creation time, signer's user id and issuer key id.

## Margin

1024 leaves about 430 bytes over the larger RSA 4096 measurement, room for a notation or a
policy URL subpacket. RSA 8192 (about 1100 bytes) is not supported, and is refused with the
bound named. The bound is tested at 1024 bytes (accepted) and 1025 (refused), in
`src/package_main.zig`.
