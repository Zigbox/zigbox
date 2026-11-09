# Known answers for the SigV4 signer

These files are copied, byte for byte, from outside this code; the signer never produced them.

- `*.req` and `*.authz` (`get-vanilla`, `get-vanilla-query-order-key-case`,
  `post-x-www-form-urlencoded`, `post-header-key-sort`, `get-header-value-trim`): AWS's SigV4 test
  suite, `aws-sig-v4-test-suite`, in the copy that botocore keeps at
  https://github.com/boto/botocore/tree/develop/tests/unit/auth/aws4_testsuite (each case is a
  directory of that name). Key `AKIDEXAMPLE` / `wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY`,
  region `us-east-1`, service `service`, time `20150830T123600Z`.
- `signing-key.hex` and `iam-list-users.signature`: the derived signing key and the IAM
  `ListUsers` signature of AWS's "Signature Version 4 signing process" documentation
  (https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html and
  https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv4-create-signed-request.html),
  service `iam`, same key and time.
