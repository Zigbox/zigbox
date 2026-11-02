//! Every limit of the Zigbox VM demos: the VM module's own (`zigbox_vm.limits`), and the ones of
//! Zigbox's release checks (`release_limits.zig`), under one name so a demo file needs one import.

const std = @import("std");
const vm = @import("zigbox_vm");
const release = @import("release_limits.zig");

pub const console_bytes_max = vm.limits.console_bytes_max;
pub const command_output_bytes_max = vm.limits.command_output_bytes_max;
pub const command_bytes_max = vm.limits.command_bytes_max;
pub const http_connections_max = vm.limits.http_connections_max;
pub const http_request_bytes_max = vm.limits.http_request_bytes_max;
pub const http_routes_max = vm.limits.http_routes_max;
pub const http_body_bytes_max = vm.limits.http_body_bytes_max;
pub const poll_step_ms = vm.limits.poll_step_ms;
pub const tcg_timeout_factor = vm.limits.tcg_timeout_factor;
pub const boot_timeout_kvm_s = vm.limits.boot_timeout_kvm_s;
pub const command_timeout_kvm_s = vm.limits.command_timeout_kvm_s;
pub const shutdown_timeout_s = vm.limits.shutdown_timeout_s;
pub const download_chunk_bytes = vm.limits.download_chunk_bytes;
pub const overlay_size_text = vm.limits.overlay_size_text;
pub const guest_memory_mib = vm.limits.guest_memory_mib;
pub const guest_cpus = vm.limits.guest_cpus;

pub const elf_bytes_max = release.elf_bytes_max;
pub const program_headers_max = release.program_headers_max;
pub const dynamic_entries_max = release.dynamic_entries_max;
pub const blob_cache_size_text = release.blob_cache_size_text;
pub const binary_bytes_max = release.binary_bytes_max;

comptime {
    // A release binary at the limit can still be served to the guest.
    std.debug.assert(binary_bytes_max < http_body_bytes_max);
    std.debug.assert(elf_bytes_max >= binary_bytes_max);
}
