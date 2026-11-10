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
const Verify = struct { schema: []const u8, ok: bool, links: []const Link };

/// `zbx verify --output json` exits 0 and every one of the six links is `ok`.
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
        if (!std.mem.eql(u8, link.status, "ok")) return error.VerifyWrong;
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
) Error!void {
    const options: std.json.ParseOptions = .{ .ignore_unknown_fields = true };
    const doc = std.json.parseFromSliceLeaky(Provenance, arena, stdout, options) catch
        return error.ProvenanceWrong;
    if (!std.mem.eql(u8, doc.result, result)) return error.ProvenanceWrong;
    if (doc.bases.len != 2) return error.ProvenanceWrong;
    try expect_step(doc.steps, "compile");
    try expect_step(doc.steps, "notice");
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
    try check_cached_provenance(arena, text_of(&good), golden_digest);
    try std.testing.expectError(
        error.ProvenanceWrong,
        check_cached_provenance(arena, text_of(&one_base), golden_digest),
    );
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

/// `text` repeated `count` times (a test fixture).
fn rep(comptime text: []const u8, comptime count: usize) [text.len * count]u8 {
    var buffer: [text.len * count]u8 = undefined;
    for (0..count) |n| @memcpy(buffer[n * text.len ..][0..text.len], text);
    return buffer;
}
