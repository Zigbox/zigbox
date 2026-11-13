# M10 slice 4: `handle_bytes_max` raised from 480 KiB to 768 KiB

Status: decided by the slice 4 implementer; the supervisor should confirm (a bound changed).

`run.Handle` now holds `cdi_scratch`, the stack scratch that `gpu.probe_nvidia` used to take on its
own stack frame (a #135 review item: gpu.zig's stack scratch). Moving it into the handle keeps
every frame small, and the comptime assert `@sizeOf(Handle) <= handle_bytes_max` needed room for it.
The handle lives in the parent, never crosses `execve`, and is allocated once per run, so the
cost is address space only. 768 KiB is the smallest round bound that fits with headroom.

Also decided in this slice: `zbx doctor` prints no separate node line for an openable device (the
`gpu  ok  device ... every node can be opened by you` line says it); the demo checks that line.
