# M10's four owner decisions

Date: 2026-11-11. Decided by the owner, accepting the supervisor's recommendations in
`docs/briefs/M10-gpu.md`.

1. The real-GPU run (slice 3) uses an AWS `g4dn.xlarge` (one NVIDIA T4) in the account set up for
   M6c, started by hand for the run and stopped after. A vCPU quota increase for G instances may be
   needed first; the supervisor asks the owner before slice 3 starts.
2. NVIDIA is supported first, through CDI. AMD and Intel are supported through render nodes
   (`--gpu dri`) only; no ROCm-specific work.
3. A run with devices keeps the user's supplementary groups by default, with no flag, so that
   group-owned device nodes (`render`, `video`) are usable rootless.
4. The milestone is M10. It does not depend on M9 and starts after 0.5.0.

The brief stops being a draft with this decision.
