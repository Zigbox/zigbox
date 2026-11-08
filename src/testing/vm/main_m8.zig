//! The M8 slice 10 check (`zbx store export --oci`), run in a real Ubuntu 24.04 VM: one tree is
//! imported and exported as two different users, and the two layouts must be byte-identical.
//! Every blob must also hash to its own file name, and the layer must read back with the guest's
//! own `tar` and `gzip`, which are not ours. This is the slice's check, not the M8 demo, which
//! needs the registry upload (slice 11). `zig build demo-m8`, or `-Daccel=tcg`.

const std = @import("std");
const Io = std.Io;
const harness = @import("harness.zig");
const session_mod = @import("session.zig");

const Session = session_mod.Session;
const H = harness;

const script_path = "/root/m8-export.sh";
const marker = "m8-export: identical";
const timeout_s: u32 = 300;

/// The whole check, as one script: it prints `marker` as its last line when every step held.
const script = body ++ "echo '" ++ marker ++ "'\n";

const body =
    \\set -eu
    \\trap 'cat /tmp/err-* 2>/dev/null' EXIT
    \\useradd -m -s /bin/sh demo2
    \\mkdir -p /srv/m8/tree/sub /srv/m8/tree/empty
    \\printf 'hello\n' > /srv/m8/tree/sub/a.txt
    \\printf '#!/bin/sh\n' > /srv/m8/tree/run.sh
    \\chmod 755 /srv/m8/tree/run.sh
    \\ln -s sub/a.txt /srv/m8/tree/link
    \\chmod -R a+rX /srv/m8
    \\for u in demo demo2; do
    \\  z="runuser -u $u -- env HOME=/home/$u /usr/local/bin/zbx"
    \\  d=$($z store import /srv/m8/tree 2>/tmp/err-i$u)
    \\  m=$($z store export --oci "$d" /tmp/out-$u 2>/tmp/err-e$u)
    \\  echo "$u: tree $d manifest $m"
    \\  echo "$m" > /tmp/manifest-$u
    \\done
    \\diff -r /tmp/out-demo /tmp/out-demo2
    \\cmp /tmp/manifest-demo /tmp/manifest-demo2
    \\cd /tmp/out-demo
    \\for f in blobs/sha256/*; do
    \\  h=$(sha256sum "$f" | cut -d' ' -f1)
    \\  [ "$h" = "$(basename "$f")" ] || { echo "bad blob $f"; exit 1; }
    \\done
    \\grep -q imageLayoutVersion oci-layout
    \\for f in blobs/sha256/*; do
    \\  if gzip -t "$f" 2>/dev/null; then tar -tvzf "$f"; fi
    \\done
    \\true
;

pub fn main(init: std.process.Init) !u8 {
    harness.demo_name = "demo-m8";
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const options = H.parse_options(init) catch |err| {
        try out.print("demo-m8: bad arguments ({s})\n", .{@errorName(err)});
        return 2;
    };
    const started = session_mod.now_ms();
    demo(init, out, options) catch |err| {
        if (err == error.NoKvm) return 1;
        try out.print("\ndemo-m8: FAILED ({s})\n", .{@errorName(err)});
        return 1;
    };
    try out.print("\ndemo-m8: PASSED in {d} s\n", .{(session_mod.now_ms() - started) / 1000});
    return 0;
}

fn demo(init: std.process.Init, out: *Io.Writer, options: H.Options) !void {
    const image = @import("image.zig");
    const accel = harness.choose_accel(options.accel, H.kvm_usable(init.io)) catch |err| {
        if (err == error.NoKvm) {
            try out.print("demo-m8: /dev/kvm is not usable here; add -Daccel=tcg\n", .{});
        }
        return err;
    };
    const binary = try H.check_binaries(init, out, options);
    const base = try image.ensure(init, options.cache_dir, out);
    const arena = init.arena.allocator();
    const format = "{s}/overlay-demo-m8.qcow2";
    const overlay = try std.fmt.allocPrint(arena, format, .{options.cache_dir});
    if (!options.reuse_overlay) try image.make_overlay(init, base, overlay);
    var session: Session = undefined;
    try session_mod.start(&session, init, out, overlay, accel, .{ .binary = binary });
    defer session.deinit();
    var timer = H.Timer.start();
    try H.provision(&session, out, &timer, options.reuse_overlay);
    try export_check(&session, out);
    try session.shutdown();
}

fn export_check(session: *Session, out: *Io.Writer) !void {
    const copied = try session.copy_in(.{
        .route = "/zbx",
        .guest_path = "/usr/local/bin/zbx",
        .mode = "755",
    });
    try H.show(out, "install zbx", copied);
    if (copied.status != 0) return error.InstallFailed;
    try session.put_file(script_path, script);
    const result = try session.run("sh " ++ script_path ++ " 2>&1", timeout_s);
    try H.show(out, "export as two users", result);
    if (result.status != 0) return error.ExportCheckFailed;
    if (std.mem.indexOf(u8, result.output, marker) == null) return error.ExportCheckFailed;
}

test "the script ends with the marker the check looks for" {
    try std.testing.expect(std.mem.endsWith(u8, script, marker ++ "'\n"));
}

test "the script fits a put_file" {
    try std.testing.expect(script.len <= @import("zigbox_vm").limits.put_file_bytes_max);
}
