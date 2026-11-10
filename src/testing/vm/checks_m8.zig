//! The assertions of the M8 demo (docs/briefs/M8-trust.md, "The demo"), as pure functions over
//! the text a command printed, each with unit tests: the key, the provenance record, the policy
//! and tamper refusals, offline `verify`, the prune and the passphrase refusals. The parts that
//! run in the guest (`trust_m8.zig`, `agent_m8.zig`, `upgrade_m8.zig`) print whole outputs; nothing
//! here touches a VM. The packages demo's assertions are in `checks_m8_packages.zig`.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Error = error{
    /// `zbx key new` did not print the key, its id and its encryption.
    KeyWrong,
    /// A provenance record is not the one the build must have written.
    ProvenanceWrong,
    /// A refusal is missing, or does not say what the brief requires.
    RefusalWrong,
    /// `zbx verify` did not report every link ok.
    VerifyWrong,
    /// A listing that must be unchanged changed.
    ListingChanged,
    /// A store object could not be found in the listing.
    NoObject,
    /// `trust prune` did not report what the brief requires.
    PruneWrong,
    /// A bundle line is not a DSSE envelope of an in-toto statement.
    BundleWrong,
    /// A script printed no evidence block of the name the check reads.
    EvidenceMissing,
    /// A build's output is not the cache hit or the result the test needs.
    BuildWrong,
    /// `policy check` and `run` disagree, or `policy check` crashed.
    AgreementWrong,
    /// The store listing, tree digest, gc report or record count is not what the demo needs.
    StoreWrong,
    /// A push did not report what the brief requires.
    PushWrong,
    OutOfMemory,
};

fn is_hex(text: []const u8, length: usize) bool {
    if (text.len != length) return false;
    for (text) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return false;
    }
    return true;
}

/// `b3:` and 64 hex digits.
pub fn is_b3(text: []const u8) bool {
    return std.mem.startsWith(u8, text, "b3:") and is_hex(text[3..], 64);
}

fn is_sha256(text: []const u8) bool {
    return std.mem.startsWith(u8, text, "sha256:") and is_hex(text[7..], 64);
}

/// The first line of `text` that starts with `prefix`, without it.
fn line_value(text: []const u8, prefix: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, prefix)) continue;
        return std.mem.trim(u8, line[prefix.len..], " \r");
    }
    return null;
}

/// The version of `zbx --version`, which prints `zbx <version>`.
pub fn version_of(stdout: []const u8) Error![]const u8 {
    const line = std.mem.trim(u8, stdout, " \r\n");
    if (!std.mem.startsWith(u8, line, "zbx ")) return error.ProvenanceWrong;
    const version = line[4..];
    if (version.len == 0 or std.mem.indexOfScalar(u8, version, ' ') != null) {
        return error.ProvenanceWrong;
    }
    return version;
}

test "the version is read from --version" {
    try std.testing.expectEqualStrings("0.3.1", try version_of("zbx 0.3.1\n"));
    try std.testing.expectError(error.ProvenanceWrong, version_of("0.3.1"));
    try std.testing.expectError(error.ProvenanceWrong, version_of("zbx \n"));
}

// ---- Step 1: the key and the provenance ----------------------------------------------------

/// `zbx key new demo --passphrase-file ...` prints the name, the key id, the public key and
/// `encryption: passphrase`. Returns the key id.
pub fn check_key_new(stdout: []const u8, name: []const u8) Error![]const u8 {
    const named = line_value(stdout, "key:") orelse return error.KeyWrong;
    if (!std.mem.eql(u8, named, name)) return error.KeyWrong;
    const id = line_value(stdout, "id:") orelse return error.KeyWrong;
    if (!is_hex(id, 64)) return error.KeyWrong;
    const public = line_value(stdout, "public:") orelse return error.KeyWrong;
    if (!std.mem.startsWith(u8, public, "zbx-ed25519:")) return error.KeyWrong;
    const encryption = line_value(stdout, "encryption:") orelse return error.KeyWrong;
    if (!std.mem.eql(u8, encryption, "passphrase")) return error.KeyWrong;
    return id;
}

/// The public key text of `zbx key show <name> --output json`.
pub fn public_of_key_show(stdout: []const u8) ?[]const u8 {
    const at = std.mem.indexOf(u8, stdout, "\"public\":\"") orelse return null;
    const rest = stdout[at + 10 ..];
    const end = std.mem.indexOfScalar(u8, rest, '"') orelse return null;
    return rest[0..end];
}

const Base = struct { reference: []const u8, manifest: []const u8, tree: []const u8 };
const Step = struct {
    name: []const u8,
    key: []const u8,
    input: []const u8,
    output: []const u8,
    network: bool,
};
const Signature = struct { key: []const u8, id: []const u8, signed: []const u8 };
const Provenance = struct {
    schema: []const u8,
    result: []const u8,
    tree: []const u8,
    record: []const u8,
    build_file: struct { name: []const u8, digest: []const u8 },
    builder: struct { version: []const u8, platform: []const u8, zbx: []const u8 },
    bases: []const Base,
    steps: []const Step,
    signatures: []const Signature,
};

/// What the first build's `zbx inspect --provenance --output json` must say: the schema, the
/// result, two bases named by their locked manifest digests, the steps `compile` and `notice`
/// with their input and output trees, the build file's hash, the `zbx` version, and a signature
/// that covers this record (`signed` is "this record").
pub fn check_provenance(
    arena: Allocator,
    stdout: []const u8,
    result: []const u8,
    zbx_version: []const u8,
) Error!void {
    const options: std.json.ParseOptions = .{ .ignore_unknown_fields = true };
    const doc = std.json.parseFromSliceLeaky(Provenance, arena, stdout, options) catch
        return error.ProvenanceWrong;
    if (!std.mem.eql(u8, doc.schema, "zbx.provenance/1")) return error.ProvenanceWrong;
    if (!std.mem.eql(u8, doc.result, result)) return error.ProvenanceWrong;
    if (!is_b3(doc.tree) or !is_b3(doc.record)) return error.ProvenanceWrong;
    if (!is_b3(doc.build_file.digest)) return error.ProvenanceWrong;
    if (!std.mem.endsWith(u8, doc.build_file.name, "zbx.build.zon")) return error.ProvenanceWrong;
    if (!std.mem.eql(u8, doc.builder.version, zbx_version)) return error.ProvenanceWrong;
    if (!is_b3(doc.builder.zbx)) return error.ProvenanceWrong;
    if (doc.bases.len != 2) return error.ProvenanceWrong;
    for (doc.bases) |base| {
        if (!is_sha256(base.manifest) or !is_b3(base.tree)) return error.ProvenanceWrong;
        if (std.mem.indexOf(u8, base.reference, "alpine") == null and
            std.mem.indexOf(u8, base.reference, "golang") == null) return error.ProvenanceWrong;
    }
    try expect_step(doc.steps, "compile");
    try expect_step(doc.steps, "notice");
    for (doc.signatures) |one| {
        if (std.mem.eql(u8, one.signed, "this record")) return;
    }
    return error.ProvenanceWrong;
}

fn expect_step(steps: []const Step, name: []const u8) Error!void {
    for (steps) |step| {
        if (!std.mem.eql(u8, step.name, name)) continue;
        if (!is_b3(step.input) or !is_b3(step.output) or !is_b3(step.key)) break;
        return;
    }
    return error.ProvenanceWrong;
}

/// The text form names the bases, the steps and the builder, each on a labelled line.
pub fn check_provenance_text(stdout: []const u8, zbx_version: []const u8) Error!void {
    const builder = line_value(stdout, "builder") orelse return error.ProvenanceWrong;
    if (!std.mem.startsWith(u8, builder, "zbx ")) return error.ProvenanceWrong;
    if (!std.mem.startsWith(u8, builder[4..], zbx_version)) return error.ProvenanceWrong;
    if (std.mem.count(u8, stdout, "\nbase ") != 2) return error.ProvenanceWrong;
    if (std.mem.indexOf(u8, stdout, "\nstep        compile") == null) return error.ProvenanceWrong;
    if (std.mem.indexOf(u8, stdout, "\nstep        notice") == null) return error.ProvenanceWrong;
}

// ---- Steps 2 and 3: the policy and the tamper check ----------------------------------------

fn flatten(buffer: []u8, text: []const u8) []const u8 {
    var length: usize = 0;
    var space = false;
    for (text) |byte| {
        const blank = byte == ' ' or byte == '\n' or byte == '\r';
        if (blank and space) continue;
        space = blank;
        if (length == buffer.len) break;
        buffer[length] = if (blank) ' ' else byte;
        length += 1;
    }
    return buffer[0..length];
}

fn refusal(stderr: []const u8, status: u8, code: []const u8, wants: []const []const u8) Error!void {
    if (status != 125) return error.RefusalWrong;
    var head: [32]u8 = undefined;
    // 32 bytes hold the prefix.
    const text = std.fmt.bufPrint(&head, "error[ZBX-{s}]: ", .{code}) catch unreachable;
    if (!std.mem.startsWith(u8, stderr, text)) return error.RefusalWrong;
    if (std.mem.indexOf(u8, stderr, "errno") != null) return error.RefusalWrong;
    var buffer: [8192]u8 = undefined;
    const flat = flatten(&buffer, stderr);
    for (wants) |want| {
        if (std.mem.indexOf(u8, flat, want) == null) return error.RefusalWrong;
    }
}

/// An image no trusted signature covers: exit 125, `E0905`, the policy file and the rule named.
pub fn check_policy_refusal(stderr: []const u8, status: u8, policy_path: []const u8) Error!void {
    return refusal(stderr, status, "E0905", &.{ policy_path, "require_signature" });
}

/// A changed object: exit 125, `E0907`, the path in the image named.
pub fn check_tamper_refusal(stderr: []const u8, status: u8, path: []const u8) Error!void {
    return refusal(stderr, status, "E0907", &.{path});
}

/// `zbx store verify` after the change names the damaged object (the id the `E0907` shows is
/// its first twelve hex digits).
pub fn check_store_verify_names(output: []const u8, object_id: []const u8) Error!void {
    if (std.mem.indexOf(u8, output, "\"damaged\":0") != null) return error.RefusalWrong;
    if (std.mem.indexOf(u8, output, object_id[0..12]) == null) return error.RefusalWrong;
}

/// A listing taken before and after a refused run is the same, byte for byte.
pub fn check_unchanged(before: []const u8, after: []const u8) Error!void {
    if (!std.mem.eql(u8, before, after)) return error.ListingChanged;
}

/// The object to change: the largest file the `find -printf '%s %p\n'` listing names (the
/// hello binary is the largest object of the result). Returns its path.
pub fn largest_object(listing: []const u8) Error![]const u8 {
    var best: ?[]const u8 = null;
    var best_size: u64 = 0;
    var lines = std.mem.splitScalar(u8, listing, '\n');
    while (lines.next()) |line| {
        const space = std.mem.indexOfScalar(u8, line, ' ') orelse continue;
        const size = std.fmt.parseInt(u64, line[0..space], 10) catch continue;
        if (best == null or size > best_size) {
            best = std.mem.trim(u8, line[space + 1 ..], "\r");
            best_size = size;
        }
    }
    return best orelse error.NoObject;
}

/// The 64-hex object id a store path ends in (its file name, without a suffix).
pub fn object_id_of_path(path: []const u8) Error![]const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return error.NoObject;
    const name = path[slash + 1 ..];
    if (name.len < 12) return error.NoObject;
    return name;
}

// ---- Step 4: verify, offline ---------------------------------------------------------------

const Link = struct { n: u32, name: []const u8, status: []const u8 };
const Counts = struct { checked: u32 = 0, not_in_store: u32 = 0 };
const Verify = struct { schema: []const u8, ok: bool, links: []const Link, inputs: Counts = .{} };
/// The most inputs verify may find missing: the two base trees, which a build does not keep
/// (their pulled trees differ from the build's), so link 5 is `partial` on them (ZBX-W0903).
const bases_missing_max: u32 = 2;

/// `zbx verify --output json` exits 0 and every link is `ok`; link 5 may be `partial` for the
/// base trees alone, never for a step's tree.
pub fn check_verify_ok(arena: Allocator, stdout: []const u8, status: u8) Error!void {
    if (status != 0) return error.VerifyWrong;
    const options: std.json.ParseOptions = .{ .ignore_unknown_fields = true };
    const doc = std.json.parseFromSliceLeaky(Verify, arena, stdout, options) catch
        return error.VerifyWrong;
    if (!std.mem.eql(u8, doc.schema, "zbx.verify/1") or !doc.ok) return error.VerifyWrong;
    if (doc.links.len != 6) return error.VerifyWrong;
    const names = [_][]const u8{
        "signatures", "signer", "tree", "provenance", "inputs", "build_file",
    };
    for (doc.links, names, 1..) |link, name, n| {
        if (link.n != n or !std.mem.eql(u8, link.name, name)) return error.VerifyWrong;
        if (std.mem.eql(u8, link.status, "ok")) continue;
        const bases_only = n == 5 and std.mem.eql(u8, link.status, "partial") and
            doc.inputs.not_in_store <= bases_missing_max;
        if (!bases_only) return error.VerifyWrong;
    }
}

// ---- ACCEPT: prune, passphrases, the bundle ------------------------------------------------

const Prune = struct {
    schema: []const u8,
    dry_run: bool,
    orphans: u32,
    removed: u32,
    damaged: u32,
};

/// `zbx trust prune --output json`: the dry run lists `orphans` and removes nothing.
pub fn check_prune_dry(arena: Allocator, stdout: []const u8, orphans: u32) Error!void {
    const doc = try parse_prune(arena, stdout);
    if (!doc.dry_run or doc.orphans != orphans or doc.removed != 0) return error.PruneWrong;
}

/// `zbx trust prune --apply --output json` removed `removed` records and keeps the rest.
pub fn check_prune_applied(arena: Allocator, stdout: []const u8, removed: u32) Error!void {
    const doc = try parse_prune(arena, stdout);
    if (doc.dry_run or doc.removed != removed or doc.damaged != 0) return error.PruneWrong;
}

fn parse_prune(arena: Allocator, stdout: []const u8) Error!Prune {
    const options: std.json.ParseOptions = .{ .ignore_unknown_fields = true };
    const doc = std.json.parseFromSliceLeaky(Prune, arena, stdout, options) catch
        return error.PruneWrong;
    if (!std.mem.eql(u8, doc.schema, "zbx.trust-prune/1")) return error.PruneWrong;
    return doc;
}

/// A refusal of `zbx sign` (or any command) that exits 1 with the code on the first line and
/// no `errno`: the missing or wrong passphrase, `E0911`.
pub fn check_exit1_code(stderr: []const u8, status: u8, code: []const u8) Error!void {
    if (status != 1) return error.RefusalWrong;
    var head: [32]u8 = undefined;
    // 32 bytes hold the prefix.
    const text = std.fmt.bufPrint(&head, "error[ZBX-{s}]: ", .{code}) catch unreachable;
    if (!std.mem.startsWith(u8, stderr, text)) return error.RefusalWrong;
    if (std.mem.indexOf(u8, stderr, "errno") != null) return error.RefusalWrong;
}

/// A bundle is one envelope per line, each with the in-toto `payloadType`.
pub fn check_bundle(bundle: []const u8) Error!void {
    var lines: u32 = 0;
    var parts = std.mem.splitScalar(u8, bundle, '\n');
    while (parts.next()) |line| {
        if (line.len == 0) continue;
        lines += 1;
        if (line[0] != '{') return error.BundleWrong;
        const want = "\"payloadType\":\"application/vnd.in-toto+json\"";
        if (std.mem.indexOf(u8, line, want) == null) return error.BundleWrong;
    }
    if (lines == 0) return error.BundleWrong;
}

// ---- The upgrade test ----------------------------------------------------------------------

/// A policy that refuses what v0.3.1 pulled is an `E0905` refusal, exit 125, and not a crash:
/// the message is one line saying what was refused.
pub fn check_old_image_refused(stderr: []const u8, status: u8, policy_path: []const u8) Error!void {
    return check_policy_refusal(stderr, status, policy_path);
}

/// A build that reused the old binary's cache wrote complete provenance: the record lists every
/// step of the build file and a base for each.
pub fn check_cached_provenance(
    arena: Allocator,
    stdout: []const u8,
    result: []const u8,
    step_name: []const u8,
    bases: usize,
) Error!void {
    const options: std.json.ParseOptions = .{ .ignore_unknown_fields = true };
    const doc = std.json.parseFromSliceLeaky(Provenance, arena, stdout, options) catch
        return error.ProvenanceWrong;
    if (!std.mem.eql(u8, doc.result, result)) return error.ProvenanceWrong;
    if (doc.bases.len != bases) return error.ProvenanceWrong;
    try expect_step(doc.steps, step_name);
}

/// The result digest a `--output json` build printed in its `build_result` line.
pub fn build_result(stdout: []const u8) Error![]const u8 {
    const at = std.mem.lastIndexOf(u8, stdout, "\"build_result\":{\"digest\":\"") orelse
        return error.BuildWrong;
    const rest = stdout[at + "\"build_result\":{\"digest\":\"".len ..];
    const end = std.mem.indexOfScalar(u8, rest, '"') orelse return error.BuildWrong;
    if (!is_b3(rest[0..end])) return error.BuildWrong;
    return rest[0..end];
}

/// The build with this binary found the step in the cache the old binary wrote: its
/// `zbx.build/1` line for the step says `hit`, and no step missed.
pub fn check_old_cache_hit(stdout: []const u8, step_name: []const u8) Error!void {
    var buffer: [128]u8 = undefined;
    const want = std.fmt.bufPrint(&buffer, "\"step\":\"{s}\",\"cache\":\"hit\"", .{
        step_name,
    }) catch return error.BuildWrong; // A step name that long is not the demo's.
    if (std.mem.indexOf(u8, stdout, want) == null) return error.BuildWrong;
    if (std.mem.indexOf(u8, stdout, "\"cache\":\"miss\"") != null) return error.BuildWrong;
}

const golden_digest = "b3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn sample_provenance(signed: []const u8, bases: u32) [2400]u8 {
    var buffer: [2400]u8 = @splat(0);
    const second = if (bases == 2)
        ",{\"reference\":\"x/golang:1.23-alpine\",\"manifest\":\"sha256:" ++ rep("ab", 32) ++
            "\",\"tree\":\"" ++ golden_digest ++ "\"}"
    else
        "";
    _ = std.fmt.bufPrint(&buffer, "{{\"schema\":\"zbx.provenance/1\",\"result\":\"{s}\"," ++
        "\"tree\":\"{s}\",\"record\":\"{s}\",\"build_file\":{{\"name\":\"/h/zbx.build.zon\"," ++
        "\"digest\":\"{s}\"}},\"lock\":null,\"builder\":{{\"version\":\"0.4.0\"," ++
        "\"platform\":\"linux/amd64\",\"zbx\":\"{s}\"}},\"started\":1,\"finished\":2," ++
        "\"bases\":[{{\"reference\":\"x/alpine:3.20\",\"manifest\":\"sha256:{s}\"," ++
        "\"tree\":\"{s}\"}}{s}],\"steps\":[{{\"name\":\"compile\",\"key\":\"{s}\",\"base\":1," ++
        "\"input\":\"{s}\",\"needs\":{{}},\"output\":\"{s}\",\"network\":false}}," ++
        "{{\"name\":\"notice\",\"key\":\"{s}\",\"base\":0,\"input\":\"{s}\",\"needs\":{{}}," ++
        "\"output\":\"{s}\",\"network\":false}}],\"image\":{{\"key\":\"{s}\",\"base\":0}}," ++
        "\"signatures\":[{{\"key\":\"zbx-ed25519:aa\",\"id\":\"bb\",\"signed\":\"{s}\"}}]}}\n", .{
        golden_digest,          golden_digest, golden_digest, golden_digest, golden_digest,
        comptime rep("cd", 32), golden_digest, second,        golden_digest, golden_digest,
        golden_digest,          golden_digest, golden_digest, golden_digest, golden_digest,
        signed,
    }) catch unreachable; // The buffer is sized for the longest fixture.
    return buffer;
}

fn text_of(buffer: *const [2400]u8) []const u8 {
    return std.mem.sliceTo(buffer, 0);
}

test "the key's lines are read, and a missing encryption is refused" {
    // Goal: the output of `key new` is checked line by line.
    const ok = "key: demo\nid: " ++ rep("ab", 32) ++ "\npublic: zbx-ed25519:" ++ rep("cd", 32) ++
        "\nencryption: passphrase\n";
    try std.testing.expectEqualStrings(&comptime rep("ab", 32), try check_key_new(ok, "demo"));
    try std.testing.expectError(error.KeyWrong, check_key_new(ok, "other"));
    const clear = "key: demo\nid: " ++ rep("ab", 32) ++
        "\npublic: zbx-ed25519:aa\nencryption: none\n";
    try std.testing.expectError(error.KeyWrong, check_key_new(clear, "demo"));
    try std.testing.expectError(error.KeyWrong, check_key_new("", "demo"));
    const short = "key: demo\nid: abc\npublic: zbx-ed25519:a\nencryption: passphrase\n";
    try std.testing.expectError(error.KeyWrong, check_key_new(short, "demo"));
}

test "the public key is cut out of key show" {
    const json = "{\"keys\":[{\"name\":\"demo\",\"public\":\"zbx-ed25519:abc\",\"x\":1}]}";
    try std.testing.expectEqualStrings("zbx-ed25519:abc", public_of_key_show(json).?);
    try std.testing.expect(public_of_key_show("{}") == null);
}

test "a provenance record is checked for bases, steps, version and signature" {
    // Goal: the record of the brief's step 1 passes; each thing it names is needed.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const good = sample_provenance("this record", 2);
    try check_provenance(arena, text_of(&good), golden_digest, "0.4.0");
    try std.testing.expectError(
        error.ProvenanceWrong,
        check_provenance(arena, text_of(&good), golden_digest, "0.3.1"),
    );
    try std.testing.expectError(
        error.ProvenanceWrong,
        check_provenance(arena, text_of(&good), "b3:" ++ rep("00", 32), "0.4.0"),
    );
    const earlier = sample_provenance("an earlier build", 2);
    try std.testing.expectError(
        error.ProvenanceWrong,
        check_provenance(arena, text_of(&earlier), golden_digest, "0.4.0"),
    );
    const one_base = sample_provenance("this record", 1);
    try std.testing.expectError(
        error.ProvenanceWrong,
        check_provenance(arena, text_of(&one_base), golden_digest, "0.4.0"),
    );
    try std.testing.expectError(
        error.ProvenanceWrong,
        check_provenance(arena, "{}", golden_digest, "0.4.0"),
    );
    try check_cached_provenance(arena, text_of(&good), golden_digest, "compile", 2);
    try check_cached_provenance(arena, text_of(&one_base), golden_digest, "compile", 1);
    try std.testing.expectError(
        error.ProvenanceWrong,
        check_cached_provenance(arena, text_of(&one_base), golden_digest, "compile", 2),
    );
    try std.testing.expectError(
        error.ProvenanceWrong,
        check_cached_provenance(arena, text_of(&good), golden_digest, "absent", 2),
    );
}

test "the result digest is cut out of the build_result line" {
    const line = "{\"schema\":\"zbx.build/1\",\"build_result\":{\"digest\":\"" ++
        golden_digest ++ "\"}}\n";
    try std.testing.expectEqualStrings(golden_digest, try build_result(line));
    try std.testing.expectError(error.BuildWrong, build_result(""));
    const short = "\"build_result\":{\"digest\":\"x\"}";
    try std.testing.expectError(error.BuildWrong, build_result(short));
}

test "a build is a cache hit only when its step hit and nothing missed" {
    const hit = "{\"schema\":\"zbx.build/1\",\"step\":\"probe\",\"cache\":\"hit\"}\n" ++
        "{\"schema\":\"zbx.build/1\",\"step\":\"image\",\"cache\":\"hit\"}\n";
    try check_old_cache_hit(hit, "probe");
    const miss = "{\"schema\":\"zbx.build/1\",\"step\":\"probe\",\"cache\":\"miss\"}\n";
    try std.testing.expectError(error.BuildWrong, check_old_cache_hit(miss, "probe"));
    try std.testing.expectError(error.BuildWrong, check_old_cache_hit(hit, "other"));
    const mixed = hit ++ miss;
    try std.testing.expectError(error.BuildWrong, check_old_cache_hit(mixed, "probe"));
    try std.testing.expectError(error.BuildWrong, check_old_cache_hit("", "probe"));
}

test "the provenance text names two bases, two steps and the builder" {
    const text = "result      b3:x\nbuilder     zbx 0.4.0  linux/amd64  b3:y\n" ++
        "base        0  alpine:3.20\n            sha256:z\nbase        1  golang\n" ++
        "step        compile  base 1\nstep        notice  base 0\n";
    try check_provenance_text(text, "0.4.0");
    try std.testing.expectError(error.ProvenanceWrong, check_provenance_text(text, "0.3.1"));
    try std.testing.expectError(error.ProvenanceWrong, check_provenance_text("", "0.4.0"));
}

test "the policy refusal names the file and the rule, and carries no errno" {
    // Goal: exit 125, E0905, the policy path and require_signature, even when the text wraps.
    const text = "error[ZBX-E0905]: no trusted signature covers what was to run\n" ++
        "  cause  /home/demo/.config/zbx/policy.zon requires a signature\n" ++
        "         (require_signature), and nothing has signed alpine\n";
    const path = "/home/demo/.config/zbx/policy.zon";
    try check_policy_refusal(text, 125, path);
    try std.testing.expectError(error.RefusalWrong, check_policy_refusal(text, 1, path));
    const wrong = check_policy_refusal(text, 125, "/x/policy.zon");
    try std.testing.expectError(error.RefusalWrong, wrong);
    try std.testing.expectError(error.RefusalWrong, check_policy_refusal("", 125, path));
    const dump = text ++ "errno 13\n";
    try std.testing.expectError(error.RefusalWrong, check_policy_refusal(dump, 125, path));
    try check_old_image_refused(text, 125, path);
}

test "the tamper refusal names the path; store verify names the object" {
    const text = "error[ZBX-E0907]: a file of the image in the store was changed\n" ++
        "  cause  /usr/local/bin/hello (object 0123456789ab) has bytes that are not the image's\n";
    try check_tamper_refusal(text, 125, "/usr/local/bin/hello");
    try std.testing.expectError(error.RefusalWrong, check_tamper_refusal(text, 125, "/usr/bin/x"));
    const wrong = check_tamper_refusal(text, 0, "/usr/local/bin/hello");
    try std.testing.expectError(error.RefusalWrong, wrong);
    try check_store_verify_names("damaged: /ab/0123456789abcdef", "0123456789abcdef00");
    try std.testing.expectError(
        error.RefusalWrong,
        check_store_verify_names("damaged: /ab/ffffffffffff", "0123456789abcdef00"),
    );
    try std.testing.expectError(
        error.RefusalWrong,
        check_store_verify_names("{\"damaged\":0}", "0123456789abcdef00"),
    );
}

test "the object to change is the largest, found by listing" {
    try std.testing.expectEqualStrings(
        "/s/objects/ab/cd",
        try largest_object("12 /s/a\n2048000 /s/objects/ab/cd\n900 /s/b\n"),
    );
    try std.testing.expectError(error.NoObject, largest_object(""));
    try std.testing.expectError(error.NoObject, largest_object("junk\n"));
    const id = try object_id_of_path("/s/ab/cdef012345678");
    try std.testing.expectEqualStrings("cdef012345678", id);
    try std.testing.expectError(error.NoObject, object_id_of_path("/s/ab/c"));
    try check_unchanged("a\nb\n", "a\nb\n");
    try std.testing.expectError(error.ListingChanged, check_unchanged("a\n", "a\nb\n"));
}

test "verify offline needs all six links ok and exit 0" {
    // Goal: every link of the verify chain, in order, reports ok.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const head = "{\"schema\":\"zbx.verify/1\",\"subject\":\"b3:x\",\"ok\":true,\"links\":[";
    const names = [_][]const u8{
        "signatures", "signer", "tree", "provenance", "inputs", "build_file",
    };
    var buffer: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try writer.writeAll(head);
    for (names, 1..) |name, n| {
        if (n > 1) try writer.writeByte(',');
        try writer.print("{{\"n\":{d},\"name\":\"{s}\",\"status\":\"ok\"}}", .{ n, name });
    }
    try writer.writeAll("]}");
    const good = writer.buffered();
    try check_verify_ok(arena, good, 0);
    try std.testing.expectError(error.VerifyWrong, check_verify_ok(arena, good, 1));
    const ok_tail = "\"status\":\"ok\"}]";
    const bad = try std.mem.replaceOwned(u8, arena, good, ok_tail, "\"status\":\"failed\"}]");
    try std.testing.expectError(error.VerifyWrong, check_verify_ok(arena, bad, 0));
    try std.testing.expectError(error.VerifyWrong, check_verify_ok(arena, "{}", 0));
    // Link 5 partial on the two base trees is allowed; on more, or on another link, it is not.
    const ok5 = "\"inputs\",\"status\":\"ok\"";
    const part5 = "\"inputs\",\"status\":\"partial\"";
    const counts = ",\"inputs\":{\"checked\":4,\"not_in_store\":2}}";
    const partial = try std.mem.replaceOwned(u8, arena, good[0 .. good.len - 1], ok5, part5);
    const two = try std.mem.concat(arena, u8, &.{ partial, counts });
    try check_verify_ok(arena, two, 0);
    const many = try std.mem.replaceOwned(u8, arena, two, "_store\":2", "_store\":3");
    try std.testing.expectError(error.VerifyWrong, check_verify_ok(arena, many, 0));
    const ok2 = "\"signer\",\"status\":\"ok\"";
    const part2 = "\"signer\",\"status\":\"partial\"";
    const other = try std.mem.replaceOwned(u8, arena, two, ok2, part2);
    try std.testing.expectError(error.VerifyWrong, check_verify_ok(arena, other, 0));
}

test "prune is a dry run first, and then removes" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const dry = "{\"schema\":\"zbx.trust-prune/1\",\"dry_run\":true,\"orphans\":1," ++
        "\"damaged\":0,\"removed\":0,\"truncated\":false,\"entries\":[]}";
    try check_prune_dry(arena, dry, 1);
    try std.testing.expectError(error.PruneWrong, check_prune_dry(arena, dry, 2));
    const applied = "{\"schema\":\"zbx.trust-prune/1\",\"dry_run\":false,\"orphans\":1," ++
        "\"damaged\":0,\"removed\":1,\"truncated\":false,\"entries\":[]}";
    try check_prune_applied(arena, applied, 1);
    try std.testing.expectError(error.PruneWrong, check_prune_applied(arena, dry, 1));
    try std.testing.expectError(error.PruneWrong, check_prune_dry(arena, applied, 1));
    try std.testing.expectError(error.PruneWrong, check_prune_dry(arena, "nope", 1));
}

test "a missing passphrase is E0911 with exit 1, and the bundle is one envelope per line" {
    const text = "error[ZBX-E0911]: the key's passphrase is missing, unusable or wrong\n";
    try check_exit1_code(text, 1, "E0911");
    try std.testing.expectError(error.RefusalWrong, check_exit1_code(text, 125, "E0911"));
    try std.testing.expectError(error.RefusalWrong, check_exit1_code(text, 1, "E0905"));
    const line = "{\"payloadType\":\"application/vnd.in-toto+json\",\"payload\":\"e30=\"}\n";
    try check_bundle(line ++ line);
    try std.testing.expectError(error.BundleWrong, check_bundle(""));
    try std.testing.expectError(error.BundleWrong, check_bundle("{\"payloadType\":\"x\"}\n"));
    try std.testing.expectError(error.BundleWrong, check_bundle("junk\n"));
}

// ---- ACCEPT8: the evidence the shell scripts print ------------------------------------------
//
// A script only runs commands. For each it prints `@@ev NAME RC`, the stdout, `@@err`, the
// stderr and `@@end`; everything the demo asserts is read back from those blocks by the pure
// functions below.

/// One captured command: its exit status, stdout and stderr.
pub const Evidence = struct { rc: u8, out: []const u8, err: []const u8 };

/// The block `name` of `output`; the block layout is described above.
pub fn evidence(output: []const u8, name: []const u8) Error!Evidence {
    var head: [64]u8 = undefined;
    const needle = std.fmt.bufPrint(&head, "@@ev {s} ", .{name}) catch return error.EvidenceMissing;
    var from: usize = 0;
    const at = while (std.mem.indexOfPos(u8, output, from, needle)) |found| {
        if (found == 0 or output[found - 1] == '\n') break found;
        from = found + 1;
    } else return error.EvidenceMissing;
    const rest = output[at + needle.len ..];
    const line_end = std.mem.indexOfScalar(u8, rest, '\n') orelse return error.EvidenceMissing;
    const rc = std.fmt.parseInt(u8, rest[0..line_end], 10) catch return error.EvidenceMissing;
    const body = rest[line_end + 1 ..];
    const split = std.mem.indexOf(u8, body, "\n@@err\n") orelse return error.EvidenceMissing;
    const tail = body[split + 7 ..];
    const end = std.mem.indexOf(u8, tail, "\n@@end") orelse return error.EvidenceMissing;
    return .{ .rc = rc, .out = body[0..split], .err = tail[0..end] };
}

/// The text after `key` up to the next quote: the first string member of that name.
fn string_after(text: []const u8, key: []const u8) ?[]const u8 {
    const at = std.mem.indexOf(u8, text, key) orelse return null;
    const rest = text[at + key.len ..];
    const end = std.mem.indexOfScalar(u8, rest, '"') orelse return null;
    return rest[0..end];
}

/// The `tree` a command printed as JSON: a `b3:` digest.
pub fn tree_of(text: []const u8) Error![]const u8 {
    const tree = string_after(text, "\"tree\":\"") orelse return error.StoreWrong;
    if (!is_b3(tree)) return error.StoreWrong;
    return tree;
}

fn ran(e: Evidence) Error!void {
    if (e.rc != 0) return error.RefusalWrong;
}

/// `zbx run` refused for want of a signed provenance: `E0906`, the file and the rule named.
pub fn check_provenance_refusal(e: Evidence, policy_path: []const u8) Error!void {
    return refusal(e.err, e.rc, "E0906", &.{ policy_path, "requires signed provenance" });
}

/// `policy check --output json` beside the `run` it previews: a run that started is allowed
/// and exits 0; a refused one (`code`, exit 125) is `allowed:false` with that code and exit 1.
/// A crash (any other status) or text on stderr with an errno fails.
pub fn check_agrees(run: Evidence, check: Evidence, code: ?[]const u8) Error!void {
    if (std.mem.indexOf(u8, check.err, "errno") != null) return error.AgreementWrong;
    if (code == null) {
        if (run.rc != 0 or check.rc != 0) return error.AgreementWrong;
        if (std.mem.indexOf(u8, check.out, "\"allowed\":true}") == null) {
            return error.AgreementWrong;
        }
        return;
    }
    if (run.rc != 125 or check.rc != 1) return error.AgreementWrong;
    if (std.mem.indexOf(u8, check.out, "\"allowed\":false}") == null) return error.AgreementWrong;
    var want: [48]u8 = undefined;
    // The buffer is sized for the longest code.
    const text = std.fmt.bufPrint(
        &want,
        "\"code\":\"ZBX-{s}\"",
        .{code.?},
    ) catch unreachable; // the buffer fits the longest code
    if (std.mem.indexOf(u8, check.out, text) == null) return error.AgreementWrong;
}

/// `store ls --output json` lists the tree.
pub fn check_tree_listed(e: Evidence, tree: []const u8) Error!void {
    try ran(e);
    if (!is_b3(tree) or std.mem.indexOf(u8, e.out, tree) == null) return error.StoreWrong;
}

/// `store ls --output json` no longer lists the tree: the removal and gc really took it.
pub fn check_tree_gone(e: Evidence, tree: []const u8) Error!void {
    try ran(e);
    if (!is_b3(tree) or e.out.len == 0 or std.mem.indexOf(u8, e.out, tree) != null) {
        return error.StoreWrong;
    }
}

/// A pull printed the tree the store held before.
pub fn check_pull_tree(e: Evidence, tree: []const u8) Error!void {
    try ran(e);
    if (!std.mem.eql(u8, try tree_of(e.out), tree)) return error.StoreWrong;
}

/// Two `inspect --provenance` documents name the same tree (the same image, two results).
pub fn check_same_tree(first: Evidence, second: Evidence) Error!void {
    try ran(first);
    try ran(second);
    if (!std.mem.eql(u8, try tree_of(first.out), try tree_of(second.out))) return error.StoreWrong;
}

/// `store gc --output json` (the plan) says `trust_orphans` is exactly `count`.
pub fn check_gc_orphans(e: Evidence, count: u32) Error!void {
    try ran(e);
    const key = "\"trust_orphans\":";
    const at = std.mem.indexOf(u8, e.out, key) orelse return error.StoreWrong;
    var end = at + key.len;
    while (end < e.out.len and std.ascii.isDigit(e.out[end])) end += 1;
    const got = std.fmt.parseInt(u32, e.out[at + key.len .. end], 10) catch return error.StoreWrong;
    if (got != count) return error.StoreWrong;
}

/// A record count printed by `wc -l`.
pub fn check_count(e: Evidence, count: u32) Error!void {
    try ran(e);
    const got = std.fmt.parseInt(u32, std.mem.trim(u8, e.out, " \n"), 10) catch
        return error.StoreWrong;
    if (got != count) return error.StoreWrong;
}

const PruneEntry = struct { kind: []const u8, fate: []const u8, digest: []const u8 };
const PruneList = struct {
    schema: []const u8,
    dry_run: bool,
    orphans: u32,
    removed: u32,
    damaged: u32,
    entries: []const PruneEntry,
};

/// The dry run lists exactly one orphan, the signature record of `tree`, and removes nothing.
pub fn check_prune_listing(arena: Allocator, e: Evidence, tree: []const u8) Error!void {
    try ran(e);
    const options: std.json.ParseOptions = .{ .ignore_unknown_fields = true };
    const doc = std.json.parseFromSliceLeaky(PruneList, arena, e.out, options) catch
        return error.PruneWrong;
    if (!std.mem.eql(u8, doc.schema, "zbx.trust-prune/1")) return error.PruneWrong;
    if (!doc.dry_run or doc.orphans != 1 or doc.removed != 0 or doc.damaged != 0) {
        return error.PruneWrong;
    }
    if (doc.entries.len != 1) return error.PruneWrong;
    const entry = doc.entries[0];
    if (!std.mem.eql(u8, entry.digest, tree)) return error.PruneWrong;
    if (!std.mem.eql(u8, entry.kind, "signature")) return error.PruneWrong;
    if (!std.mem.eql(u8, entry.fate, "orphan")) return error.PruneWrong;
}

/// `--apply` removed exactly one record and damaged none.
pub fn check_prune_one_removed(arena: Allocator, e: Evidence) Error!void {
    try ran(e);
    try check_prune_applied(arena, e.out, 1);
    const options: std.json.ParseOptions = .{ .ignore_unknown_fields = true };
    const doc = std.json.parseFromSliceLeaky(PruneList, arena, e.out, options) catch
        return error.PruneWrong;
    if (doc.orphans != 1) return error.PruneWrong;
}

/// A refused build whose base image is unsigned: `E0905`, the base named, no errno.
pub fn check_base_refused(e: Evidence, base_name: []const u8) Error!void {
    if (e.rc == 0 or std.mem.indexOf(u8, e.err, "errno") != null) return error.RefusalWrong;
    if (!std.mem.startsWith(u8, e.err, "error[ZBX-E0905]: ")) return error.RefusalWrong;
    var buffer: [128]u8 = undefined;
    // The buffer holds any base name the demo uses.
    const want = std.fmt.bufPrint(
        &buffer,
        "nothing has signed {s}@",
        .{base_name},
    ) catch unreachable; // the buffer fits any demo base name
    var flat_buffer: [8192]u8 = undefined;
    const flat = flatten(&flat_buffer, e.err);
    if (std.mem.indexOf(u8, flat, want) == null) return error.RefusalWrong;
}

/// A malformed policy: `E0904`, with the line and the column.
pub fn check_malformed_policy(e: Evidence) Error!void {
    return refusal(e.err, e.rc, "E0904", &.{"line 2, column"});
}

const Push = struct {
    schema: []const u8,
    manifest: []const u8,
    destination: []const u8,
    blobs: []const struct { digest: []const u8, outcome: []const u8, size: u64 },
};

fn parse_push(arena: Allocator, e: Evidence) Error!Push {
    try ran(e);
    const options: std.json.ParseOptions = .{ .ignore_unknown_fields = true };
    const doc = std.json.parseFromSliceLeaky(Push, arena, e.out, options) catch
        return error.PushWrong;
    if (!std.mem.eql(u8, doc.schema, "zbx.push/1")) return error.PushWrong;
    if (!std.mem.startsWith(u8, doc.manifest, "sha256:") or doc.blobs.len == 0) {
        return error.PushWrong;
    }
    return doc;
}

/// Two pushes of the same result: the same manifest digest and destination, the first sent
/// something, and the second found every blob already there.
pub fn check_push_pair(arena: Allocator, first: Evidence, second: Evidence) Error!void {
    const one = try parse_push(arena, first);
    const two = try parse_push(arena, second);
    if (!std.mem.eql(u8, one.manifest, two.manifest)) return error.PushWrong;
    if (!std.mem.eql(u8, one.destination, two.destination)) return error.PushWrong;
    var sent: u32 = 0;
    for (one.blobs) |blob| {
        if (std.mem.eql(u8, blob.outcome, "uploaded")) sent += 1;
    }
    if (sent == 0) return error.PushWrong;
    for (two.blobs) |blob| {
        if (!std.mem.eql(u8, blob.outcome, "exists")) return error.PushWrong;
    }
}

/// The command printed exactly the greeting and exited 0.
pub fn check_greeting(e: Evidence) Error!void {
    try ran(e);
    if (!std.mem.eql(u8, std.mem.trim(u8, e.out, "\n"), "hello from zigbox")) {
        return error.RefusalWrong;
    }
}

const private_policy = "/home/demo/ac/zbx/policy.zon";
const second_policy = "/home/demo2/.config/zbx/policy.zon";

/// Script 1: signed alpine runs with provenance off and `policy check` agrees; with provenance
/// required the run is `E0906` and `policy check` agrees.
pub fn check_a1(arena: Allocator, output: []const u8) Error!void {
    _ = arena;
    const pull = try evidence(output, "pull1");
    const tree = try tree_of(pull.out);
    try ran(pull);
    try check_tree_listed(try evidence(output, "ls0"), tree);
    try check_agrees(try evidence(output, "run1"), try evidence(output, "chk1"), null);
    const refused = try evidence(output, "run2");
    try check_provenance_refusal(refused, private_policy);
    try check_agrees(refused, try evidence(output, "chk2"), "E0906");
}

/// Script 2: the signature survives `store rm`, gc and a re-pull: the tree is really gone
/// before the pull, the pull brings back the same tree, and the run passes with `policy check`.
pub fn check_a2(arena: Allocator, output: []const u8) Error!void {
    _ = arena;
    const tree = std.mem.trim(u8, (try evidence(output, "tree")).out, " \n");
    try ran(try evidence(output, "rm1"));
    try check_tree_gone(try evidence(output, "ls1"), tree);
    try check_pull_tree(try evidence(output, "pull2"), tree);
    try check_agrees(try evidence(output, "run3"), try evidence(output, "chk3"), null);
}

/// Script 3: prune. gc counts one orphan before, the dry run names `alpine`'s record and removes
/// nothing, `--apply` removes exactly it, gc counts none after, and the re-pulled image is
/// `E0905` with `policy check` agreeing.
pub fn check_a3(arena: Allocator, output: []const u8) Error!void {
    const tree = std.mem.trim(u8, (try evidence(output, "tree")).out, " \n");
    try ran(try evidence(output, "sign2"));
    try check_count(try evidence(output, "n0"), 2);
    try ran(try evidence(output, "rm2"));
    try check_gc_orphans(try evidence(output, "orph0"), 1);
    try check_prune_listing(arena, try evidence(output, "dry"), tree);
    try check_count(try evidence(output, "n1"), 2);
    try check_prune_one_removed(arena, try evidence(output, "app"));
    try check_count(try evidence(output, "n2"), 1);
    try check_gc_orphans(try evidence(output, "orph1"), 0);
    try ran(try evidence(output, "pull3"));
    const refused = try evidence(output, "run4");
    try check_policy_refusal(refused.err, refused.rc, private_policy);
    try check_agrees(refused, try evidence(output, "chk4"), "E0905");
}

/// Script 4: a step whose base is unsigned is refused, naming the step; a malformed policy is
/// `E0904` with its line and column.
pub fn check_a4(arena: Allocator, output: []const u8) Error!void {
    _ = arena;
    try check_base_refused(try evidence(output, "bld"), "alpine");
    try check_malformed_policy(try evidence(output, "run5"));
}

/// Script 5: the registry takes the push twice; the second finds every blob.
pub fn check_b1(arena: Allocator, output: []const u8) Error!void {
    try check_push_pair(arena, try evidence(output, "push1"), try evidence(output, "push2"));
}

/// Script 6: a second result with the same tree and another entrypoint is pushed, and the
/// exported bundle is one envelope per line.
pub fn check_b2(arena: Allocator, output: []const u8) Error!void {
    const built = try evidence(output, "bld2");
    try ran(built);
    try check_same_tree(try evidence(output, "ins1"), try evidence(output, "ins2"));
    _ = try parse_push(arena, try evidence(output, "push3"));
    const bundle = try evidence(output, "exp");
    try ran(bundle);
    try check_bundle(bundle.out);
}

/// Script 7: as the second user, the pulled image is refused before the trust import (and
/// `policy check` agrees), runs after it (and agrees), the second result is refused under the
/// first one's signature (and agrees), and `-- <cmd>` on the signed result stays allowed.
pub fn check_b3(arena: Allocator, output: []const u8) Error!void {
    _ = arena;
    const before = try evidence(output, "run_before");
    try check_policy_refusal(before.err, before.rc, second_policy);
    try check_agrees(before, try evidence(output, "chk_before"), "E0905");
    try ran(try evidence(output, "import"));
    const after = try evidence(output, "run_after");
    try check_greeting(after);
    try check_agrees(after, try evidence(output, "chk_after"), null);
    const other = try evidence(output, "run_other");
    try check_policy_refusal(other.err, other.rc, second_policy);
    try check_agrees(other, try evidence(output, "chk_other"), "E0905");
    try check_greeting(try evidence(output, "run_override"));
}

/// One block as a script prints it (a test fixture).
fn block(
    comptime name: []const u8,
    comptime rc: []const u8,
    comptime out: []const u8,
    comptime err: []const u8,
) []const u8 {
    return "@@ev " ++ name ++ " " ++ rc ++ "\n" ++ out ++ "\n@@err\n" ++ err ++ "\n@@end\n";
}

/// `text` repeated `count` times (a test fixture).
fn rep(comptime text: []const u8, comptime count: usize) [text.len * count]u8 {
    var buffer: [text.len * count]u8 = undefined;
    for (0..count) |n| @memcpy(buffer[n * text.len ..][0..text.len], text);
    return buffer;
}

const t_a = "b3:" ++ rep("a", 64);
const t_b = "b3:" ++ rep("b", 64);
const allowed_json = "{\"files\":[],\"allowed\":true}\n";
fn refused_json(comptime code: []const u8) []const u8 {
    return "{\"files\":[{\"code\":\"ZBX-" ++ code ++ "\"}],\"allowed\":false}\n";
}
fn refused_text(
    comptime code: []const u8,
    comptime path: []const u8,
    comptime rule: []const u8,
) []const u8 {
    return "error[ZBX-" ++ code ++ "]: refused\n  while  checking against the policy " ++ path ++
        "\n  cause  " ++ rule ++ " is on\n";
}

test "an evidence block is found by its exact name, with empty and full streams" {
    const output = comptime "noise\n" ++ block("run1", "0", "", "") ++
        block("run10", "125", "o\n", "e") ++ block("tail", "3", "x", "y");
    const one = try evidence(output, "run1");
    try std.testing.expectEqual(@as(u8, 0), one.rc);
    try std.testing.expectEqualStrings("", one.out);
    const ten = try evidence(output, "run10");
    try std.testing.expectEqual(@as(u8, 125), ten.rc);
    try std.testing.expectEqualStrings("o\n", ten.out);
    try std.testing.expectEqualStrings("e", ten.err);
    try std.testing.expectEqualStrings("y", (try evidence(output, "tail")).err);
    try std.testing.expectError(error.EvidenceMissing, evidence(output, "run"));
    try std.testing.expectError(error.EvidenceMissing, evidence("@@ev run1 0\nx", "run1"));
    try std.testing.expectError(error.EvidenceMissing, evidence("x@@ev a 0\n", "a"));
}

test "policy check agrees with run on the three cases, and a crash does not" {
    const ok: Evidence = .{ .rc = 0, .out = "", .err = "" };
    const check_ok: Evidence = .{ .rc = 0, .out = allowed_json, .err = "" };
    try check_agrees(ok, check_ok, null);
    const no: Evidence = .{ .rc = 125, .out = "", .err = "" };
    const check_no: Evidence = .{ .rc = 1, .out = refused_json("E0905"), .err = "" };
    try check_agrees(no, check_no, "E0905");
    const check_six: Evidence = .{ .rc = 1, .out = refused_json("E0906"), .err = "" };
    try check_agrees(no, check_six, "E0906");
    const wrong = error.AgreementWrong;
    try std.testing.expectError(wrong, check_agrees(no, check_six, "E0905"));
    try std.testing.expectError(wrong, check_agrees(ok, check_no, null));
    try std.testing.expectError(wrong, check_agrees(no, check_ok, "E0905"));
    // A crash is not exit 1: the old `|| true` would have hidden it.
    const crashed: Evidence = .{ .rc = 139, .out = check_no.out, .err = "" };
    try std.testing.expectError(wrong, check_agrees(no, crashed, "E0905"));
    const zero: Evidence = .{ .rc = 0, .out = check_no.out, .err = "" };
    try std.testing.expectError(wrong, check_agrees(no, zero, "E0905"));
    const noisy: Evidence = .{ .rc = 0, .out = allowed_json, .err = "errno 2" };
    try std.testing.expectError(wrong, check_agrees(ok, noisy, null));
}

test "the tree must be gone before the pull and the same after it" {
    const gone: Evidence = .{ .rc = 0, .out = "{\"roots\":[]}", .err = "" };
    const there: Evidence = .{ .rc = 0, .out = "{\"roots\":[\"" ++ t_a ++ "\"]}", .err = "" };
    try check_tree_gone(gone, t_a);
    try check_tree_listed(there, t_a);
    try std.testing.expectError(error.StoreWrong, check_tree_gone(there, t_a));
    try std.testing.expectError(error.StoreWrong, check_tree_listed(gone, t_a));
    const silent: Evidence = .{ .rc = 0, .out = "", .err = "" };
    try std.testing.expectError(error.StoreWrong, check_tree_gone(silent, t_a));
    const pulled: Evidence = .{ .rc = 0, .out = "{\"tree\":\"" ++ t_a ++ "\"}", .err = "" };
    try check_pull_tree(pulled, t_a);
    try std.testing.expectError(error.StoreWrong, check_pull_tree(pulled, t_b));
    const other: Evidence = .{ .rc = 0, .out = "{\"tree\":\"" ++ t_b ++ "\"}", .err = "" };
    try check_same_tree(pulled, pulled);
    try std.testing.expectError(error.StoreWrong, check_same_tree(pulled, other));
}

test "counts are exact: ten orphans are not one, thirteen removals are not one" {
    const one: Evidence = .{ .rc = 0, .out = "{\"x\":1,\"trust_orphans\":1}\n", .err = "" };
    const ten: Evidence = .{ .rc = 0, .out = "{\"trust_orphans\":10}\n", .err = "" };
    const none: Evidence = .{ .rc = 0, .out = "{\"x\":1}\n", .err = "" };
    try check_gc_orphans(one, 1);
    try std.testing.expectError(error.StoreWrong, check_gc_orphans(ten, 1));
    try std.testing.expectError(error.StoreWrong, check_gc_orphans(none, 0));
    try std.testing.expectError(error.StoreWrong, check_gc_orphans(one, 0));
    const two: Evidence = .{ .rc = 0, .out = "2\n", .err = "" };
    try check_count(two, 2);
    try std.testing.expectError(error.StoreWrong, check_count(two, 1));
    const twelve: Evidence = .{ .rc = 0, .out = "12\n", .err = "" };
    try std.testing.expectError(error.StoreWrong, check_count(twelve, 2));
}

test "prune lists exactly the signature record of the tree, and removes exactly one" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const entry = "{\"kind\":\"signature\",\"fate\":\"orphan\",\"digest\":\"" ++ t_a ++ "\"}";
    const head = "{\"schema\":\"zbx.trust-prune/1\",\"dry_run\":";
    const dry: Evidence = .{ .rc = 0, .err = "", .out = head ++
        "true,\"orphans\":1,\"damaged\":0,\"removed\":0,\"truncated\":false,\"entries\":[" ++
        entry ++ "]}" };
    try check_prune_listing(arena, dry, t_a);
    try std.testing.expectError(error.PruneWrong, check_prune_listing(arena, dry, t_b));
    const ten = try std.mem.replaceOwned(u8, arena, dry.out, "\"orphans\":1,", "\"orphans\":10,");
    const many: Evidence = .{ .rc = 0, .out = ten, .err = "" };
    try std.testing.expectError(error.PruneWrong, check_prune_listing(arena, many, t_a));
    const applied: Evidence = .{ .rc = 0, .err = "", .out = head ++
        "false,\"orphans\":1,\"damaged\":0,\"removed\":1,\"truncated\":false,\"entries\":[]}" };
    try check_prune_one_removed(arena, applied);
    const text = try std.mem.replaceOwned(
        u8,
        arena,
        applied.out,
        "\"removed\":1",
        "\"removed\":13",
    );
    const thirteen: Evidence = .{ .rc = 0, .out = text, .err = "" };
    try std.testing.expectError(error.PruneWrong, check_prune_one_removed(arena, thirteen));
    try std.testing.expectError(error.PruneWrong, check_prune_one_removed(arena, dry));
}

test "a push pair has one manifest, and the second finds every blob" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const m = "sha256:" ++ rep("1", 64);
    const head = "{\"blobs\":[{\"digest\":\"sha256:" ++ rep("2", 64) ++ "\",\"outcome\":\"";
    const tail = "\",\"size\":5}],\"destination\":\"localhost:5000/m8/hello:demo\",\"manifest\":\"";
    const end = "\",\"schema\":\"zbx.push/1\"}\n";
    const up: Evidence = .{ .rc = 0, .out = head ++ "uploaded" ++ tail ++ m ++ end, .err = "" };
    const there: Evidence = .{ .rc = 0, .out = head ++ "exists" ++ tail ++ m ++ end, .err = "" };
    try check_push_pair(arena, up, there);
    try std.testing.expectError(error.PushWrong, check_push_pair(arena, up, up));
    try std.testing.expectError(error.PushWrong, check_push_pair(arena, there, there));
    const m2 = "sha256:" ++ rep("3", 64);
    const moved: Evidence = .{ .rc = 0, .out = head ++ "exists" ++ tail ++ m2 ++ end, .err = "" };
    try std.testing.expectError(error.PushWrong, check_push_pair(arena, up, moved));
    const failed: Evidence = .{ .rc = 1, .out = there.out, .err = "" };
    try std.testing.expectError(error.RefusalWrong, check_push_pair(arena, up, failed));
}

test "an unsigned base names its image; a malformed policy names its line" {
    const text = "error[ZBX-E0905]: refused\n" ++
        "  cause  /p requires a signature, and nothing has signed\n" ++
        "         alpine@sha256:1\n";
    const refused: Evidence = .{ .rc = 125, .out = "", .err = text };
    try check_base_refused(refused, "alpine");
    try std.testing.expectError(error.RefusalWrong, check_base_refused(refused, "other"));
    const built: Evidence = .{ .rc = 0, .out = "", .err = text };
    try std.testing.expectError(error.RefusalWrong, check_base_refused(built, "alpine"));
    const bad: Evidence = .{
        .rc = 125,
        .out = "",
        .err = refused_text("E0904", "/p", "line 2, column 3"),
    };
    try check_malformed_policy(bad);
    try std.testing.expectError(error.RefusalWrong, check_malformed_policy(refused));
}

test "script 1 needs the E0906 refusal and every policy check beside its run" {
    const run_ok = comptime block("run1", "0", "", "");
    const chk_ok = comptime block("chk1", "0", allowed_json, "");
    const refused = comptime refused_text("E0906", private_policy, "requires signed provenance");
    const run_six = comptime block("run2", "125", "", refused);
    const chk_six = comptime block("chk2", "1", refused_json("E0906"), "");
    const prefix = comptime block("pull1", "0", "{\"tree\":\"" ++ t_a ++ "\"}", "") ++
        block("ls0", "0", "[\"" ++ t_a ++ "\"]", "");
    const good = prefix ++ run_ok ++ chk_ok ++ run_six ++ chk_six;
    try check_a1(std.testing.allocator, good);
    // The check missing, or crashed: refused.
    const chk_gone = prefix ++ run_ok ++ chk_ok ++ run_six;
    try std.testing.expectError(error.EvidenceMissing, check_a1(std.testing.allocator, chk_gone));
    const chk_bad = comptime block("chk2", "139", refused_json("E0906"), "");
    const crashed = comptime prefix ++ run_ok ++ chk_ok ++ run_six ++ chk_bad;
    try std.testing.expectError(error.AgreementWrong, check_a1(std.testing.allocator, crashed));
    const chk_off = comptime block("chk2", "1", refused_json("E0905"), "");
    const wrong = comptime prefix ++ run_ok ++ chk_ok ++ run_six ++ chk_off;
    try std.testing.expectError(error.AgreementWrong, check_a1(std.testing.allocator, wrong));
}

test "script 2 refuses a tree that was never gone or a different one after the pull" {
    const tree = comptime block("tree", "0", t_a ++ "\n", "") ++ block("rm1", "0", "", "");
    const tail = comptime block("run3", "0", "", "") ++ block("chk3", "0", allowed_json, "");
    const gone = comptime block("ls1", "0", "[]", "");
    const same = comptime block("pull2", "0", "{\"tree\":\"" ++ t_a ++ "\"}", "");
    try check_a2(std.testing.allocator, tree ++ gone ++ same ++ tail);
    const kept = comptime block("ls1", "0", "[\"" ++ t_a ++ "\"]", "");
    try std.testing.expectError(error.StoreWrong, check_a2(std.testing.allocator, tree ++ kept ++
        same ++ tail));
    const other = comptime block("pull2", "0", "{\"tree\":\"" ++ t_b ++ "\"}", "");
    try std.testing.expectError(error.StoreWrong, check_a2(std.testing.allocator, tree ++ gone ++
        other ++ tail));
}

test "script 7 refuses the second result under the first one's signature" {
    const refused = comptime refused_text("E0905", second_policy, "require_signature");
    const pre = comptime block("run_before", "125", "", refused) ++
        block("chk_before", "1", refused_json("E0905"), "") ++
        block("import", "0", "", "");
    const after = comptime block("run_after", "0", "hello from zigbox\n", "") ++
        block("chk_after", "0", allowed_json, "");
    const other = comptime block("run_other", "125", "", refused) ++
        block("chk_other", "1", refused_json("E0905"), "");
    const over = comptime block("run_override", "0", "hello from zigbox\n", "");
    try check_b3(std.testing.allocator, pre ++ after ++ other ++ over);
    const ran_other = comptime block("run_other", "0", "hello from zigbox\n", "") ++
        block("chk_other", "0", allowed_json, "");
    try std.testing.expectError(error.RefusalWrong, check_b3(std.testing.allocator, pre ++ after ++
        ran_other ++ over));
    const blocked = comptime block("run_override", "125", "", refused);
    try std.testing.expectError(error.RefusalWrong, check_b3(std.testing.allocator, pre ++ after ++
        other ++ blocked));
}
