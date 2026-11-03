# M4 · A 4 MB binary, and a docker.io mirror for PR CI

*Decided 2026-10-27, after M4 slice 1.*

- **The release size limit is 4 MB**, up from 2 MB (live doc rev 54). std's TLS client and its crypto are about 550 KB, and gzip, zstd and tar follow in slice 2. Splitting the pull code into a second binary or shipping `ReleaseSmall` (assertions off) were rejected. The size is still checked on every CI run, so growth stays visible.
- **PR CI reaches docker.io through a mirror.** Docker Hub's anonymous limit ran out after about 20 resolves from one address, and GitHub runners share egress addresses. zbx gets a registry-mirror setting, as Docker's `registry-mirrors` does: a pull of a docker.io image tries the mirror first, then falls back to Docker Hub. PR CI's `demo-m4` points docker.io at `mirror.gcr.io`, with blobs cached. The weekly top-20 run and the by-hand demo use real Docker Hub, so its token flow stays tested.
