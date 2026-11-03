# Local dev: zbx runs one thing; more than one is Zigcube's

*Decided 2026-10-29.*

- **No Compose equivalent in zbx, ever.** zbx runs one container at a time. To run more than one service, even on one laptop, install the Zigcube server (SQLite store, one agent on the same machine): "if you want to run more than one thing, do it right". Live doc rev 64 says so in Non-goals and in Part II's opening.
- **Zigbox adds only the local primitives both need**, as a new milestone **M6b · Dev loop** before M7: writable mounts, `zbx logs`, `zbx exec`, all three in the library for Zigcube's agent.
- **Writable mounts only under the project directory** (the one holding `zbx.lock`, else the working directory).
- **Ownership: written as the container's root, refused otherwise.** Most dev images run as root, so a file the container writes is the host user's. For an image whose user is not root, a writable mount is refused, naming the user and the fix (`--user 0`, new in M6b, or a read-only `--bind`); no subordinate-owned file ever lands in a project. Rejected: id-mapped mounts (they need privilege over the host file system that rootless zbx lacks; `zbx doctor` only reports whether the kernel allows them), a keep-id map of the image's user to the host user (it changes how the store's trees are owned; a milestone of its own if real use asks), and chown at exit (too late for a dev loop, and wrong after a crash). Live doc rev 68.
- **Zigcube's single-node path is an early target**: services reaching each other by name on one machine, a single-node form of C4's DNS and grants without WireGuard. Zigcube's session scopes it when Zigcube restarts.
