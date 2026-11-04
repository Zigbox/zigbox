//! Every limit of the VM module, with its unit last, and comptime checks on how they relate.
//! The module is test tooling, but docs/STYLE.md still asks for a bound on everything. Limits
//! that belong to one package's demos (Zigbox's release-binary size, its blob cache) live with
//! that package, not here.

const std = @import("std");
const assert = std.debug.assert;

/// Everything the guest console prints is kept (and echoed to our stdout). A full boot plus
/// provisioning is well under a megabyte; the rest is headroom for a failure's own noise.
pub const console_bytes_max: u32 = 16 * 1024 * 1024;
/// The output of one guest command.
pub const command_output_bytes_max: u32 = 64 * 1024;
pub const command_bytes_max: u32 = 1024;
pub const http_connections_max: u32 = 4;
pub const http_request_bytes_max: u32 = 8 * 1024;
/// The seed's three routes (user-data, meta-data, vendor-data) and the caller's files.
pub const http_routes_max: u32 = 8;
pub const seed_routes: u32 = 3;
/// One served file: a release binary or a rootfs tarball.
pub const http_body_bytes_max: u32 = 8 * 1024 * 1024;
pub const poll_step_ms: u32 = 200;

/// Seconds. The guest runs about this many times slower under TCG than under KVM.
pub const tcg_timeout_factor: u32 = 8;
pub const boot_timeout_kvm_s: u32 = 300;
pub const command_timeout_kvm_s: u32 = 60;
pub const shutdown_timeout_s: u32 = 60;
pub const download_chunk_bytes: u32 = 64 * 1024;
pub const overlay_size_text = "8G";
pub const guest_memory_mib: u32 = 2048;
pub const guest_cpus: u32 = 2;
/// Extra raw disks a guest can be given (`/dev/vdb` onward).
pub const disks_max: u32 = 4;
/// TCP forwards from the host into one guest (`Seed.forwards`).
pub const forwards_max: u32 = 8;
/// One `,hostfwd=tcp:255.255.255.255:65535-:65535` argument, with room to spare.
pub const forward_argument_bytes_max: u32 = 64;
/// The refusal line for a bad forward (`forward.describe`).
pub const forward_message_bytes_max: u32 = 160;

/// The rendered cloud-init user data and meta data.
pub const user_data_bytes_max: u32 = 16 * 1024;
pub const meta_data_bytes_max: u32 = 256;
pub const packages_max: u32 = 32;
pub const sysctls_max: u32 = 16;
pub const hostname_bytes_max: u32 = 63;
/// A file copied in by typing it: base64 in pieces on the console.
pub const put_file_bytes_max: u32 = 1536;

comptime {
    assert(console_bytes_max >= 1024 * 1024);
    assert(command_output_bytes_max < console_bytes_max);
    assert(command_bytes_max < 4096); // The tty line discipline truncates longer lines.
    assert(poll_step_ms > 0);
    assert(forwards_max > 0);
    assert(forwards_max <= 64); // A guest with more forwards than this wants a real network.
    assert(forward_argument_bytes_max >= ",hostfwd=tcp:255.255.255.255:65535-:65535".len);
    assert(tcg_timeout_factor >= 1);
    assert(boot_timeout_kvm_s * tcg_timeout_factor < 24 * 60 * 60);
    assert(guest_memory_mib >= 1024);
    assert(http_connections_max >= 2); // cloud-init may fetch two files at once.
    assert(seed_routes < http_routes_max);
    assert(user_data_bytes_max <= http_body_bytes_max);
    assert(hostname_bytes_max + 64 < meta_data_bytes_max);
    // base64 of the largest file fits the encode buffer of `put_file` (4/3 of it, rounded up).
    assert(std.base64.standard.Encoder.calcSize(put_file_bytes_max) <= 2048);
}
