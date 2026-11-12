# Device path limit

*Decided 2026-11-12, by the supervisor, on the review of PR #125 (M10 slice 1).*

## Decision

`device_path_bytes_max` stays 48 for slice 1. It covers `/dev/dri/renderD*`, `/dev/nvidia*`,
`/dev/fuse`, `/dev/kvm`, `/dev/net/tun` and `/dev/bus/usb/NNN/NNN`.

By-id and by-path names are not supported: they are symlinks, and/or contain `:`, which
`--device` refuses. The user gives the node the name points to (`renderD128`).

Raising the bound, or allowing `:`, is a new decision.

## Reason

The run record keeps the device paths in one string; 16 paths of at most 48 bytes keep its
worst case inside 64 KiB without escapes. The reviewer accepted the bound; the user-visible
cost is the `:` ban, recorded as a scope cut in `docs/demos/m10.md`.
