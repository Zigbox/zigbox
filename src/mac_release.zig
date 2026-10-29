//! `zig build mac-release`: the macOS release of `zbx`, in steps that stop at the first one that
//! fails. It is run by the build with the ReleaseSafe binary (the VM image is inside it):
//!
//!   1. copy the binary to a staging directory in the output directory;
//!   2. `codesign` it with the hardened runtime, a secure timestamp and `vm/zbx.entitlements`;
//!   3. `codesign --verify --strict` and `codesign -d --entitlements -`, shown;
//!   4. `ditto` the binary, alone at the top of the archive, into `zbx-<version>-macos-arm64.zip` (a zip, because `notarytool` takes a zip
//!      and Homebrew unpacks one; a bare Mach-O cannot be stapled, so it travels in an archive);
//!   5. with `--notarize`: `xcrun notarytool submit --keychain-profile <profile> --wait`. No
//!      profile, or one the keychain does not have, is refused before anything is submitted;
//!   6. write `<archive>.sha256` and the Homebrew formula with the version, URL and hash filled.
//!
//! The identity `-` signs ad hoc (no timestamp, no certificate: for trying the script). Nothing
//! secret is read, printed or logged: the keychain holds the certificate and the notary profile,
//! and this tool passes only their names.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

pub const default_identity = "Developer ID Application: Alex Zuzin (56A872L679)";
pub const default_profile = "zbx-notary";
const release_url = "https://github.com/Zigbox/zigbox/releases/download";

const Arguments = struct {
    binary: []const u8 = "",
    entitlements: []const u8 = "",
    formula: []const u8 = "",
    out: []const u8 = "",
    version: []const u8 = "",
    identity: []const u8 = default_identity,
    profile: []const u8 = default_profile,
    notarize: bool = false,
};

pub fn archive_name(buffer: []u8, version: []const u8) []const u8 {
    assert(version.len > 0);
    // Cannot fail: a version of at most 32 bytes and fixed words fit the buffer.
    return std.fmt.bufPrint(buffer, "zbx-{s}-macos-arm64.zip", .{version}) catch unreachable;
}

/// True for the ad-hoc identity, which has no certificate and so no secure timestamp.
pub fn is_ad_hoc(identity: []const u8) bool {
    return std.mem.eql(u8, identity, "-");
}

/// The words `codesign` is run with, after the program name.
pub fn sign_arguments(identity: []const u8, entitlements: []const u8, binary: []const u8, out: *[12][]const u8) []const []const u8 {
    assert(identity.len > 0);
    const timestamp: []const u8 = if (is_ad_hoc(identity)) "--timestamp=none" else "--timestamp";
    const words = [_][]const u8{
        "--force", "--options", "runtime", timestamp, "--entitlements", entitlements,
        "--sign",  identity,    binary,
    };
    @memcpy(out[0..words.len], &words);
    return out[0..words.len];
}

/// Fills `@VERSION@`, `@URL@` and `@SHA256@` in the formula template.
pub fn fill_formula(
    arena: std.mem.Allocator,
    template: []const u8,
    version: []const u8,
    url: []const u8,
    sha256: []const u8,
) ![]u8 {
    assert(sha256.len == 64);
    const first = try std.mem.replaceOwned(u8, arena, template, "@VERSION@", version);
    const second = try std.mem.replaceOwned(u8, arena, first, "@URL@", url);
    return std.mem.replaceOwned(u8, arena, second, "@SHA256@", sha256);
}

pub fn main(init: std.process.Init) !u8 {
    var buffer: [1024]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stderr(), init.io, &buffer);
    const log = &file_writer.interface;
    defer log.flush() catch {};
    const arguments = parse_arguments(init) orelse {
        try log.print("mac_release: usage: --binary F --entitlements F --formula F --out DIR " ++
            "--version V [--identity NAME|-] [--profile NAME] [--notarize]\n", .{});
        return 2;
    };
    run(init, &arguments, log) catch |err| {
        try log.print("mac_release: stopped: {s}\n", .{@errorName(err)});
        return 1;
    };
    return 0;
}

fn parse_arguments(init: std.process.Init) ?Arguments {
    var iterator = init.minimal.args.iterate();
    _ = iterator.next();
    var result: Arguments = .{};
    while (iterator.next()) |name| {
        if (std.mem.eql(u8, name, "--notarize")) {
            result.notarize = true;
            continue;
        }
        const value = iterator.next() orelse return null;
        if (std.mem.eql(u8, name, "--binary")) result.binary = value;
        if (std.mem.eql(u8, name, "--entitlements")) result.entitlements = value;
        if (std.mem.eql(u8, name, "--formula")) result.formula = value;
        if (std.mem.eql(u8, name, "--out")) result.out = value;
        if (std.mem.eql(u8, name, "--version")) result.version = value;
        if (std.mem.eql(u8, name, "--identity")) result.identity = value;
        if (std.mem.eql(u8, name, "--profile")) result.profile = value;
    }
    if (result.binary.len == 0 or result.out.len == 0 or result.version.len == 0) return null;
    if (result.entitlements.len == 0 or result.formula.len == 0) return null;
    return result;
}

fn exec(io: Io, log: *Io.Writer, argv: []const []const u8) !void {
    assert(argv.len > 0);
    try log.print("mac_release: {s}", .{argv[0]});
    for (argv[1..]) |word| try log.print(" {s}", .{word});
    try log.print("\n", .{});
    try log.flush();
    var child = try std.process.spawn(io, .{ .argv = argv });
    switch (try child.wait(io)) {
        .exited => |code| if (code == 0) return,
        else => {},
    }
    return error.CommandFailed;
}

/// Whether the keychain has a notary profile of this name: `notarytool history` exits 0 with one.
fn profile_exists(io: Io, profile: []const u8) bool {
    const argv = [_][]const u8{
        "/usr/bin/xcrun",     "notarytool", "history",
        "--keychain-profile", profile,
    };
    var child = std.process.spawn(io, .{
        .argv = &argv,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return false;
    const result = child.wait(io) catch return false;
    return switch (result) {
        .exited => |code| code == 0,
        else => false,
    };
}

fn run(init: std.process.Init, arguments: *const Arguments, log: *Io.Writer) !void {
    const io = init.io;
    const arena = init.arena.allocator();
    if (arguments.notarize) {
        // Refused before anything is built or signed: a release that cannot be notarized is not
        // worth signing for.
        if (arguments.profile.len == 0 or is_ad_hoc(arguments.identity)) {
            try log.print("mac_release: notarization needs a signing identity and a keychain " ++
                "profile (--profile, default {s}); an ad-hoc signature cannot be notarized\n", .{default_profile});
            return error.NotarizationRefused;
        }
        if (!profile_exists(io, arguments.profile)) {
            try log.print("mac_release: the keychain has no notary profile '{s}'. Store one " ++
                "with: xcrun notarytool store-credentials {s} (it asks for the Apple ID and " ++
                "an app-specific password, or an API key, and keeps them in the keychain)\n", .{ arguments.profile, arguments.profile });
            return error.NotarizationRefused;
        }
    }
    const dir = Io.Dir.cwd();
    try dir.createDirPath(io, arguments.out);
    // The archive holds the binary alone, at its top: it is made from this directory's contents.
    const stage = try std.fmt.allocPrint(arena, "{s}/stage", .{arguments.out});
    try dir.createDirPath(io, stage);
    const signed = try std.fmt.allocPrint(arena, "{s}/zbx", .{stage});
    try Io.Dir.copyFile(dir, arguments.binary, dir, signed, io, .{});
    var words: [12][]const u8 = undefined;
    const tail = sign_arguments(arguments.identity, arguments.entitlements, signed, &words);
    var argv: [14][]const u8 = undefined;
    argv[0] = "/usr/bin/codesign";
    @memcpy(argv[1 .. 1 + tail.len], tail);
    try exec(io, log, argv[0 .. 1 + tail.len]);
    try exec(io, log, &.{ "/usr/bin/codesign", "--verify", "--strict", "--verbose=2", signed });
    try exec(io, log, &.{ "/usr/bin/codesign", "-d", "--entitlements", "-", signed });

    var name_buffer: [96]u8 = undefined;
    const name = archive_name(&name_buffer, arguments.version);
    const archive = try std.fmt.allocPrint(arena, "{s}/{s}", .{ arguments.out, name });
    try exec(io, log, &.{ "/usr/bin/ditto", "-c", "-k", "--norsrc", stage, archive });
    if (arguments.notarize) {
        try exec(io, log, &.{
            "/usr/bin/xcrun",     "notarytool",      "submit", archive,
            "--keychain-profile", arguments.profile, "--wait",
        });
        // A Mach-O on its own cannot be stapled, and the archive is not a bundle either: the
        // ticket stays with Apple, and Gatekeeper asks for it the first time a quarantined copy
        // runs. Nothing is stapled.
        try log.print("mac_release: notarized; the ticket is not stapled (a bare binary has no " ++
            "place for one)\n", .{});
    }
    const bytes = try dir.readFileAlloc(io, archive, arena, .limited(1 << 30));
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    const sum_path = try std.fmt.allocPrint(arena, "{s}.sha256", .{archive});
    const sum_line = try std.fmt.allocPrint(arena, "{s}  {s}\n", .{ &hex, name });
    try dir.writeFile(io, .{ .sub_path = sum_path, .data = sum_line });
    const template = try dir.readFileAlloc(io, arguments.formula, arena, .limited(1 << 20));
    const url = try std.fmt.allocPrint(arena, "{s}/v{s}/{s}", .{ release_url, arguments.version, name });
    const formula = try fill_formula(arena, template, arguments.version, url, &hex);
    const formula_path = try std.fmt.allocPrint(arena, "{s}/zigbox.rb", .{arguments.out});
    try dir.writeFile(io, .{ .sub_path = formula_path, .data = formula });
    try log.print("mac_release: {s}\nmac_release: sha256 {s}\nmac_release: formula {s}\n", .{ archive, &hex, formula_path });
}

test "the archive is named for the version and the ad-hoc identity has no timestamp" {
    // Goal: the two small rules of the script. Method: a name, and the codesign words for each
    // kind of identity.
    var buffer: [96]u8 = undefined;
    try std.testing.expectEqualStrings("zbx-0.1.0-macos-arm64.zip", archive_name(&buffer, "0.1.0"));
    var words: [12][]const u8 = undefined;
    const ad_hoc = sign_arguments("-", "e.plist", "zbx", &words);
    try std.testing.expectEqualStrings("--timestamp=none", ad_hoc[3]);
    const real = sign_arguments(default_identity, "e.plist", "zbx", &words);
    try std.testing.expectEqualStrings("--options", real[1]);
    try std.testing.expectEqualStrings("runtime", real[2]);
    try std.testing.expectEqualStrings("--timestamp", real[3]);
    try std.testing.expectEqualStrings(default_identity, real[7]);
    try std.testing.expect(is_ad_hoc("-"));
    try std.testing.expect(!is_ad_hoc(default_identity));
}

test "the formula template is filled in all three places" {
    // Goal: no placeholder is left in the formula. Method: a template that uses each twice.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const filled = try fill_formula(arena_state.allocator(), "@VERSION@ @URL@ @SHA256@ @VERSION@", "1.2.3", "https://x/y.zip", sha);
    try std.testing.expectEqualStrings("1.2.3 https://x/y.zip " ++ sha ++ " 1.2.3", filled);
    try std.testing.expect(std.mem.indexOfScalar(u8, filled, '@') == null);
}
