# Zigcube's restart: C1 includes local mode; Zigcube drives

*Decided 2026-10-30.*

- **C1 includes local mode** (live doc rev 76): zcube-server on SQLite with one agent on the same machine, started by one command, on Linux and macOS (the agent in the zbx machine), with services reaching each other by name where the service file grants it, a single-node form of C4 without WireGuard. C1's demo gains a step: an app and postgres on a laptop, from one file.
- **Zigcube's own session drives the restart**, from orders written into the zigcube repository (`docs/restart.md`).
- **The owner reviews the revised `Runtime` contract** before Zigcube builds on it; the orders carry it as a draft.
- **Pull goes into the `zigbox` library in M6b** (its slice 4), because Zigcube's agent cannot fetch an image without it: it lives in the CLI's code today. `zbx pull` becomes a thin caller with unchanged output.
