//! The pure judgements of the packages check (`main_m8_packages.zig`): what a guest's package
//! tools printed, and whether that means they accepted the test-key signatures. Kept apart from
//! the VM driver so each is a unit-tested function over text captured from real runs, and so the
//! key-type probe (docs/decisions/2026-11-08-archive-key-type.md) rests on one definition of
//! "accepted".

const std = @import("std");
const assert = std.debug.assert;

pub const Family = enum { apt, dnf };

/// What a guest's tool made of the test key's Ed25519 signature. `not_run` means the probe never
/// ran (the guest stopped first): no evidence either way, and it fails the guest like `refused`.
pub const Verdict = enum { accepted, refused, not_run };

/// `apt-get update` against the test repository: accepted when it exits 0, fetched the
/// repository's `InRelease` and printed no `W:` or `E:` line (apt's own warnings and errors,
/// among them "The repository ... is not signed" and "NO_PUBKEY").
pub fn apt_update_verdict(output: []const u8, status: u8) Verdict {
    if (status != 0) return .refused;
    var fetched = false;
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "W: ")) return .refused;
        if (std.mem.startsWith(u8, line, "E: ")) return .refused;
        if (std.mem.indexOf(u8, line, "stable InRelease") != null) fetched = true;
    }
    if (fetched) return .accepted;
    return .refused;
}

/// `dnf makecache` with `repo_gpgcheck=1`: accepted when it exits 0 and says it built the
/// cache, with no `warning:` line (a weak-key or signature notice). A signature dnf cannot check
/// ends it with `Error: ...` and a non-zero status.
pub fn dnf_makecache_verdict(output: []const u8, status: u8) Verdict {
    if (status != 0) return .refused;
    var created = false;
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |line| {
        const text = std.mem.trimStart(u8, line, " \t\r");
        if (std.mem.startsWith(u8, text, "warning:")) return .refused;
        if (std.mem.startsWith(u8, text, "Warning:")) return .refused;
        if (std.mem.indexOf(u8, text, "Metadata cache created") != null) created = true;
    }
    if (created) return .accepted;
    return .refused;
}

/// `rpm -K <file>` after the key was imported: accepted when it exits 0 and the line ends in
/// `digests signatures OK` (rpm 4.16 and 6 both print that; a signature rpm cannot check prints
/// `NOT OK` or `NOKEY` in its place).
pub fn rpm_check_verdict(output: []const u8, status: u8) Verdict {
    if (status != 0) return .refused;
    if (std.mem.indexOf(u8, output, "NOT OK") != null) return .refused;
    if (std.mem.indexOf(u8, output, "NOKEY") != null) return .refused;
    if (std.mem.indexOf(u8, output, "digests signatures OK") != null) return .accepted;
    return .refused;
}

/// What one guest showed, for the pass or fail of the check.
pub const Outcome = struct {
    metadata: Verdict,
    package: Verdict,
    installed: bool,
    zbx_ran: bool,
};

/// A guest passes only when it accepted the test key's signature on the repository metadata and
/// on the package, installed from the signed repository, and `zbx` ran. A refused signature is
/// a failure, whatever else worked: an unsigned install would hide a signature nobody checked.
pub fn guest_passed(outcome: Outcome) bool {
    if (outcome.metadata != .accepted) return false;
    if (outcome.package != .accepted) return false;
    return outcome.installed and outcome.zbx_ran;
}

/// `zbx --version` prints `zbx <version>` on its first line, then a build line.
pub fn version_ok(output: []const u8, version: []const u8) bool {
    assert(version.len > 0);
    const end = std.mem.indexOfScalar(u8, output, '\n') orelse output.len;
    const line = std.mem.trim(u8, output[0..end], " \r\n");
    if (line.len != 4 + version.len) return false;
    return std.mem.startsWith(u8, line, "zbx ") and std.mem.endsWith(u8, line, version);
}

/// `zbx doctor` ran and judged: exit 0 (every check ok) or 2 (a check failed, with its report).
/// Any other status, or no report, means the binary did not run properly on this guest. Whether
/// the guest passes every check is information for the log, not the packages check.
pub fn doctor_ran(output: []const u8, status: u8) bool {
    if (status != 0 and status != 2) return false;
    return output.len > 0;
}

test "apt update: a clean fetch is accepted; a warning, an error or a bad status is not" {
    // Goal: the refusals apt actually prints (NO_PUBKEY, "not signed", the weak-digest warning)
    // all count as refused. Method: texts as apt 2.6 (Debian 12) and 2.7 (Ubuntu 24.04) print.
    const clean = "Get:1 http://127.0.0.1:8081/apt stable InRelease [900 B]\n" ++
        "Get:2 http://127.0.0.1:8081/apt stable/main amd64 Packages [479 B]\n" ++
        "Fetched 1379 B in 0s (6342 kB/s)\nReading package lists...\n";
    try std.testing.expectEqual(Verdict.accepted, apt_update_verdict(clean, 0));
    try std.testing.expectEqual(Verdict.refused, apt_update_verdict(clean, 100));
    const no_key = "Get:1 http://127.0.0.1:8081/apt stable InRelease [900 B]\n" ++
        "Err:1 http://127.0.0.1:8081/apt stable InRelease\n  The following signatures " ++
        "couldn't be verified because the public key is not available: NO_PUBKEY 1234\n" ++
        "W: GPG error: http://127.0.0.1:8081/apt stable InRelease: NO_PUBKEY 1234\n" ++
        "E: The repository 'http://127.0.0.1:8081/apt stable InRelease' is not signed.\n";
    try std.testing.expectEqual(Verdict.refused, apt_update_verdict(no_key, 100));
    try std.testing.expectEqual(Verdict.refused, apt_update_verdict(no_key, 0));
    const warned = clean ++ "W: Some index files failed to download.\n";
    try std.testing.expectEqual(Verdict.refused, apt_update_verdict(warned, 0));
    const no_fetch = "Reading package lists...\n";
    try std.testing.expectEqual(Verdict.refused, apt_update_verdict(no_fetch, 0));
    try std.testing.expectEqual(Verdict.refused, apt_update_verdict("", 0));
}

test "dnf makecache: the cache line with status 0 is accepted, an Error line is not" {
    // Goal: a repo_gpgcheck failure is never read as accepted. Method: dnf 4 and dnf5 outputs.
    const good = "Zigbox test repository     5.0 kB/s | 1.5 kB  00:00\nMetadata cache created.\n";
    try std.testing.expectEqual(Verdict.accepted, dnf_makecache_verdict(good, 0));
    try std.testing.expectEqual(Verdict.refused, dnf_makecache_verdict(good, 1));
    const bad = "Zigbox test repository     5.0 kB/s | 1.5 kB  00:00\n" ++
        "Error: Failed to download metadata for repo 'zigbox-test': GPG verification is " ++
        "enabled, but GPG signature is not available.\n";
    try std.testing.expectEqual(Verdict.refused, dnf_makecache_verdict(bad, 1));
    try std.testing.expectEqual(Verdict.refused, dnf_makecache_verdict(bad, 0));
    try std.testing.expectEqual(Verdict.refused, dnf_makecache_verdict("", 0));
    const warned = "warning: Signature uses a weak digest\n" ++ good;
    try std.testing.expectEqual(Verdict.refused, dnf_makecache_verdict(warned, 0));
    const warned_late = good ++ "Warning: key is weak\n";
    try std.testing.expectEqual(Verdict.refused, dnf_makecache_verdict(warned_late, 0));
}

test "rpm -K: only digests and signatures OK is accepted" {
    // Goal: a missing key or a signature rpm cannot check is a refusal. Method: the three
    // shapes of rpm 4.16 output.
    const ok = "/srv/zigbox/rpm/x86_64/zigbox-0.3.1-1.x86_64.rpm: digests signatures OK\n";
    try std.testing.expectEqual(Verdict.accepted, rpm_check_verdict(ok, 0));
    try std.testing.expectEqual(Verdict.refused, rpm_check_verdict(ok, 1));
    const nokey = "/srv/z.rpm: digests SIGNATURES NOT OK\n";
    try std.testing.expectEqual(Verdict.refused, rpm_check_verdict(nokey, 1));
    try std.testing.expectEqual(Verdict.refused, rpm_check_verdict(nokey, 0));
    const missing = "/srv/z.rpm: DIGESTS SIGNATURES NOKEY\n";
    try std.testing.expectEqual(Verdict.refused, rpm_check_verdict(missing, 0));
    try std.testing.expectEqual(Verdict.refused, rpm_check_verdict("/srv/z.rpm: digests OK\n", 0));
}

test "zbx version and doctor judgements" {
    // Goal: the version is matched whole, not as a prefix; doctor's two statuses are the only
    // ones that mean it ran.
    try std.testing.expect(version_ok("zbx 0.3.1\n", "0.3.1"));
    try std.testing.expect(version_ok("zbx 0.3.1\nbuild: safe x86_64-linux\n", "0.3.1"));
    try std.testing.expect(!version_ok("zbx 0.3.10\n", "0.3.1"));
    try std.testing.expect(!version_ok("zbx 0.3.1 extra\n", "0.3.1"));
    try std.testing.expect(!version_ok("", "0.3.1"));
    try std.testing.expect(!version_ok("xzbx 0.3.1", "0.3.1"));
    try std.testing.expect(doctor_ran("kernel ok\n", 0));
    try std.testing.expect(doctor_ran("cgroup FAIL\n", 2));
    try std.testing.expect(!doctor_ran("kernel ok\n", 1));
    try std.testing.expect(!doctor_ran("kernel ok\n", 127));
    try std.testing.expect(!doctor_ran("", 0));
}

test "a guest passes only with both signatures accepted, the install done and zbx run" {
    // Goal: a refused signature fails the check even when everything else worked (no unsigned
    // fallback, supervisor decision on slice 7). Method: flip each field of a passing outcome.
    const good: Outcome = .{
        .metadata = .accepted,
        .package = .accepted,
        .installed = true,
        .zbx_ran = true,
    };
    try std.testing.expect(guest_passed(good));
    var bad = good;
    bad.metadata = .refused;
    try std.testing.expect(!guest_passed(bad));
    bad = good;
    bad.package = .refused;
    try std.testing.expect(!guest_passed(bad));
    bad = good;
    bad.metadata = .not_run;
    try std.testing.expect(!guest_passed(bad));
    bad = good;
    bad.package = .not_run;
    try std.testing.expect(!guest_passed(bad));
    bad = good;
    bad.installed = false;
    try std.testing.expect(!guest_passed(bad));
    bad = good;
    bad.zbx_ran = false;
    try std.testing.expect(!guest_passed(bad));
}
