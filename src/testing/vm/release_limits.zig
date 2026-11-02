//! The limits of Zigbox's own VM checks that the VM module has no part in: the release binary's
//! size, and how much of an ELF file the checks read. Kept apart from `limits.zig` because the
//! zbx test root (src/main.zig) reaches `checks.zig`, and that root has no `zigbox_vm` import.

const std = @import("std");
const assert = std.debug.assert;

/// Size of a binary the harness reads to inspect its ELF headers.
pub const elf_bytes_max: u32 = 8 * 1024 * 1024;
pub const program_headers_max: u32 = 64;
pub const dynamic_entries_max: u32 = 256;
/// The M4 blob cache disk: room for the demo's images (about 150 MB of blobs) with headroom.
pub const blob_cache_size_text = "1G";

/// The release size limit: a static binary under 4 MiB (the spec's criterion since rev 54; 2 MiB
/// before). It must match `release_size_limit_bytes` in `build.zig`.
pub const binary_bytes_max: u64 = 4 * 1024 * 1024;

comptime {
    // A binary at the limit can still be read.
    assert(binary_bytes_max <= elf_bytes_max);
    assert(program_headers_max > 0);
    assert(dynamic_entries_max > 0);
}
