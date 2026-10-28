//! State volumes (M6): data that must outlive a container, named, typed and listed, never an
//! anonymous directory (docs/briefs/M6-state.md).
//!
//! ## Layout
//!
//! Per user, beside the store and never inside it: `$XDG_DATA_HOME/zbx/state`, or
//! `~/.local/share/zbx/state`. `zbx store gc` never reads or removes anything here.
//!
//!     <name>/data/                 the volume's files, bound into the container
//!     <name>/state.zon             its record (`record.zig`): made, last used, by which
//!                                  container, at which path
//!     <name>/lock                  flock (`lock.zig`): exclusive for a writer, shared for `:ro`
//!     .trash/<name>@<seconds>/     what `zbx state rm` moved, the whole volume directory, until
//!                                  `store_trash_seconds` have passed (the store's expiry)
//!
//! `<name>` and the lock and record are the user's own files. `data/` is made by the container's
//! root inside the container's user namespace, so its contents belong to the ids the container
//! gives them, which on the host are the user's subordinate ids: every command that reads or
//! removes them (`state ls` counting a size, `state rm`, `state restore`) does its file work in
//! the store's namespace child (`store/namespace.zig`), with the container's id map.
//!
//! ## Nothing implicit
//!
//! A volume is made only by the first run that names it (`--state NAME:PATH[:ro]`), and removed
//! only by `zbx state rm`, which moves it to the trash; `zbx state restore` brings the newest
//! trash of a name back until it expires. A later `zbx state rm` empties expired trash.

pub const volume = @import("volume.zig");
pub const record = @import("record.zig");
pub const lock = @import("lock.zig");
pub const holders = @import("holders.zig");
pub const diagnose = @import("diagnose.zig");
pub const usage = @import("usage.zig");

test {
    _ = volume;
    _ = record;
    _ = lock;
    _ = holders;
    _ = diagnose;
    _ = usage;
}
