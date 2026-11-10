# M8 slice 13 starts after M6c's client, before its live demo

*Decided 2026-11-10, by the supervisor; recorded by the slice 13 implementer.*

M6c's code slices 1 and 2 (SigV4, the credential sources, the ECR pull client) are merged. Only the
live AWS demo, slice 3, remains. Slice 13 (ECR push) therefore starts now, against recorded ECR
answers (`aws_sim.zig` and the upload test registry); there is no AWS account in CI.

The by-hand run against a real ECR repository rides with M6c slice 3 and has not been done. Until
it is, nothing about ECR push is reported as demonstrated against AWS.

This does not supersede `2026-11-10-m6c-slice2-ecr-client.md`; it builds on it. Push uses the same
credential sources and the same `GetAuthorizationToken` call, and owns codes E0550 to E0559
(E0536 to E0549 stay free for slice 3).
