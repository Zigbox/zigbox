# Port forwards in `zigbox_vm`: explicit host ports, loopback by default

*Decided 2026-11-04, by the Z7 slice (for Zigcube's demo-c2, which sends peer traffic guest -> host -> guest).*

`Seed.forwards` is a list of `Forward{ host_address, host_port, guest_port }`, rendered into the `-netdev user,id=net0,hostfwd=tcp:A.B.C.D:H-:G` argument. With no forwards the argument is the old `user,id=net0`, byte for byte (a snapshot test pins the whole command line).

- **Host port 0 is refused (`VM-F002`).** QEMU would pick a free port, but the harness runs with `-monitor none` and has no channel to read it back. Adding the monitor or parsing `info usernet` just for this costs more than the caller choosing ports, and a caller that wants a free port can ask the kernel for one itself (bind to port 0, read it, close it, pass it). Revisit if a caller finds that racy.
- **The address defaults to 127.0.0.1.** A forward is for the harness and its sibling guests, not the network. A caller can name another address.
- **Duplicate host ports are refused even on different addresses** (`VM-F004`): `0.0.0.0` overlaps all of them, and the rule is simpler than the overlap test.
- **At most `limits.forwards_max` (8) forwards per guest** (`VM-F001`); guest port 0 is refused (`VM-F003`).
- **Refusals** print one `vm: VM-Fnnn: ...` line on the session's output and return `error.BadForward` before the server or QEMU starts. The `VM-F` codes belong to the test harness, not to `DIAGNOSTICS.md`'s product codes.

The VM check is `zig build demo-z7`: a guest listener reached from the host through a forward. Detail: [vm-module.md](../vm-module.md).
