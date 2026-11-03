# M4 · Pull: the lockfile, the top-20 check, and /sys

*Decided 2026-10-27.*

- **`zbx.lock` lives in the project directory**: the nearest one up from the working directory, as with `Cargo.lock`. `zbx pull` adds or updates the entry for the tag. `zbx run <tag>` runs the locked digest and refuses, naming both digests, when the lock and the store disagree; it never re-pulls silently. Without a lockfile, `run <tag>` resolves the tag and writes one. Live doc rev 53.
- **The top-20 acceptance check runs weekly and on demand**, in its own workflow. `demo-m4` on every PR uses only alpine and the two python images, from a cached blob store. M4 is demonstrated once both the `demo-m4` job and one top-20 run are green, with the run linked.
- **`/sys` is the host's, bound read-only**, until M5 gives each container its own network namespace and a real sysfs can be mounted. Podman does the same when running rootless without its own netns. It shows the host's network devices; that leak is recorded in `docs/demos/m4.md` and closes in M5.
