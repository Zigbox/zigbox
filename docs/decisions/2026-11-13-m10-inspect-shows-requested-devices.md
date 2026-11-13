# M10 inspect shows the requested GPU devices

*Decided 2026-11-13, by the owner.*

Decision: in M10 slice 3 (Zigbox/zigbox pull request #135), `zbx inspect` shows the GPU devices the
user asked for (`--gpu` and `--device` as given), not the resolved device set.

Status: accepted by the owner in writing on 2026-11-13.

Consequence: a later slice may add the resolved set. Until then, inspect output must not claim to be
the resolved set.
