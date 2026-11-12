# Docker parity: what is a goal and what is not

*Decided 2026-11-11, owner.*

The question was what Zigbox still needs for practical parity with Docker. Anything that needs
several containers to cooperate (compose, service discovery between containers, restart policy
across services) belongs to Zigcube and is not counted here.

**Goals**

- **Dockerfile import.** Stretch S4 becomes a goal. `zbx import` translates a Dockerfile into a
  `zbx.build.zon` that the user reads and commits, and `zbx build` builds it as it builds any build
  file. A Dockerfile is never executed directly, so the spec's "Dockerfile execution" non-goal stands.
  Steps that are not hermetic (network, unpinned downloads, cache mounts) are flagged. The brief
  follows a survey of real-world Dockerfiles.
- **GPU access.** This reverses "GPU passthrough" in the spec's non-goals, for Zigbox containers
  only. Its scope comes in its own brief. Zigcube's CS4 (GPU allocation and gang scheduling) is
  unchanged.
- **Pull.** Docker Hub, GHCR and ECR, which already work, are enough for now. Pull from other
  private registries is parked: it is not a goal, and the spec's "private registries except ECR"
  non-goal stands.

**Non-goals** (confirmed)

- Windows.
- Intel Macs. M4b stays Apple Silicon only.
- Docker's socket API, and drop-in CLI or flag compatibility.

The live design doc and `docs/SPEC.md` are brought in line with this at the next spec sync. Until
then, where they disagree with this file, this file holds for these three goals.
