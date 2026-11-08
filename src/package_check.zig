//! `zig build packages-check`: every placed file of the output tree agrees with the metadata that
//! names it (apt `Release` and `Packages`, dnf `repomd.xml` and `primary.xml`), and, once the
//! tree is signed, every signature file is there. With the test key the signatures are checked
//! by recomputing them (Ed25519 is deterministic and the signature time is fixed).
//! The files come from a `Source`, so a test can use memory and the tool can use the disk.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const constants = @import("constants.zig");
const package = @import("package.zig");
const model = package.model;
const rpm = package.rpm;
const openpgp = package.openpgp;
const release = @import("package_release.zig");

pub const Options = struct {
    /// The tree is expected to carry every signature file (a signed release).
    signatures_required: bool,
    /// Recompute the signatures with the fixed test key and compare.
    test_key: bool,
};

pub const Error = error{CheckFailed} || release.Error;

/// Where the files of the tree come from: `read_fn(context, path)` is the bytes or null.
pub const Source = struct {
    context: *anyopaque,
    read_fn: *const fn (context: *anyopaque, path: []const u8) ?[]const u8,
};

const Checker = struct {
    source: Source,
    memory: Allocator,
    log: *std.Io.Writer,
    failures: u32 = 0,
    files_checked: u32 = 0,

    fn fail(self: *Checker, comptime format: []const u8, arguments: anytype) void {
        self.failures += 1;
        self.log.print("packages-check: " ++ format ++ "\n", arguments) catch {}; // Nowhere else.
    }

    fn read(self: *Checker, path: []const u8) ?[]const u8 {
        const bytes = self.source.read_fn(self.source.context, path);
        if (bytes == null) self.fail("{s} is missing", .{path});
        return bytes;
    }

    fn join(self: *Checker, left: []const u8, right: []const u8) Error![]u8 {
        return std.fmt.allocPrint(self.memory, "{s}{s}", .{ left, right }) catch
            return error.OutOfMemory;
    }

    /// The file at `path` has the digest (and size, when given) the metadata records.
    fn check_file(self: *Checker, path: []const u8, digest: []const u8, size: ?u64) ?[]const u8 {
        const bytes = self.read(path) orelse return null;
        self.files_checked += 1;
        if (!std.mem.eql(u8, &model.digest_hex(bytes), digest)) {
            self.fail("{s} does not match its recorded sha256", .{path});
        }
        if (size) |expected| {
            if (expected != bytes.len) self.fail("{s} is not its recorded size", .{path});
        }
        return bytes;
    }
};

fn field(line: []const u8, name: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, line, name)) return null;
    return line[name.len..];
}

/// `Release` sums every `Packages` file; each `Packages` stanza sums its pool file.
fn check_apt(checker: *Checker) Error!void {
    const text = checker.read(release.apt_release_path) orelse return;
    var lines = std.mem.splitScalar(u8, text, '\n');
    var in_sums = false;
    while (lines.next()) |line| {
        if (std.mem.eql(u8, line, "SHA256:")) {
            in_sums = true;
        } else if (in_sums and line.len > 0 and line[0] == ' ') {
            try check_release_line(checker, line);
        }
    }
    if (!in_sums) checker.fail("{s} has no SHA256 section", .{release.apt_release_path});
}

fn check_release_line(checker: *Checker, line: []const u8) Error!void {
    var words = std.mem.tokenizeScalar(u8, line, ' ');
    const digest = words.next() orelse return checker.fail("a Release line is empty", .{});
    const size_text = words.next() orelse
        return checker.fail("a Release line has no size", .{});
    const name = words.next() orelse return checker.fail("a Release line has no name", .{});
    const size = std.fmt.parseInt(u64, size_text, 10) catch
        return checker.fail("a Release size is not a number: {s}", .{size_text});
    const path = try checker.join("apt/dists/stable/", name);
    const bytes = checker.check_file(path, digest, size) orelse return;
    if (std.mem.endsWith(u8, name, "/Packages")) try check_packages(checker, bytes);
}

fn check_packages(checker: *Checker, text: []const u8) Error!void {
    var stanzas = std.mem.splitSequence(u8, text, "\n\n");
    while (stanzas.next()) |stanza| {
        if (std.mem.trim(u8, stanza, "\n").len == 0) continue;
        try check_stanza(checker, stanza);
    }
}

fn check_stanza(checker: *Checker, stanza: []const u8) Error!void {
    var filename: ?[]const u8 = null;
    var size: ?u64 = null;
    var digest: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, stanza, '\n');
    while (lines.next()) |line| {
        if (field(line, "Filename: ")) |value| filename = value;
        if (field(line, "SHA256: ")) |value| digest = value;
        if (field(line, "Size: ")) |value| size = std.fmt.parseInt(u64, value, 10) catch null;
    }
    const name = filename orelse return checker.fail("a Packages stanza has no Filename", .{});
    const path = try checker.join("apt/", name);
    if (digest == null or size == null) {
        return checker.fail("the Packages stanza for {s} lacks Size or SHA256", .{path});
    }
    _ = checker.check_file(path, digest.?, size.?);
}

/// `repomd.xml` sums each metadata file; `primary.xml` sums each rpm.
fn check_dnf(checker: *Checker, index: usize) Error!void {
    const arch = release.architectures[index].rpm_name();
    const base = try std.fmt.allocPrint(checker.memory, "rpm/{s}/", .{arch});
    const path = try checker.join(base, "repodata/repomd.xml");
    const text = checker.read(path) orelse return;
    var digest: []const u8 = "";
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " ");
        const open = "<checksum type=\"sha256\">";
        if (std.mem.startsWith(u8, line, open)) {
            const end = std.mem.indexOf(u8, line, "</checksum>") orelse continue;
            digest = line[open.len..end];
        }
        const location = "<location href=\"";
        if (std.mem.startsWith(u8, line, location)) {
            const end = std.mem.indexOfPos(u8, line, location.len, "\"") orelse continue;
            const name = try checker.join(base, line[location.len..end]);
            const bytes = checker.check_file(name, digest, null) orelse continue;
            if (std.mem.endsWith(u8, name, "-primary.xml.gz")) {
                try check_primary(checker, base, bytes);
            }
        }
    }
    if (digest.len == 0) checker.fail("{s} records no checksum", .{path});
}

fn check_primary(checker: *Checker, base: []const u8, gzipped: []const u8) Error!void {
    var input: std.Io.Reader = .fixed(gzipped);
    var window: [constants.package_gzip_window_bytes]u8 = undefined;
    var decompress: std.compress.flate.Decompress = .init(&input, .gzip, &window);
    const text = decompress.reader.allocRemaining(
        checker.memory,
        .limited(constants.repo_metadata_bytes_max),
    ) catch return checker.fail("{s}primary.xml.gz does not decompress", .{base});
    const marker = "pkgid=\"YES\">";
    var from: usize = 0;
    while (std.mem.indexOfPos(u8, text, from, marker)) |at| {
        const start = at + marker.len;
        const digest = text[start..@min(text.len, start + 64)];
        const location = "<location href=\"";
        const where = std.mem.indexOfPos(u8, text, start, location) orelse
            return checker.fail("a primary.xml package has no location", .{});
        const name_start = where + location.len;
        const name_end = std.mem.indexOfPos(u8, text, name_start, "\"") orelse
            return checker.fail("a primary.xml location is not closed", .{});
        const path = try checker.join(base, text[name_start..name_end]);
        if (checker.check_file(path, digest, null)) |found| check_rpm(checker, path, found);
        from = name_end;
    }
}

fn check_rpm(checker: *Checker, path: []const u8, bytes: []const u8) void {
    const parts = rpm.split(bytes) orelse return checker.fail("{s} is not an rpm", .{path});
    if (!std.mem.endsWith(u8, path, ".rpm")) checker.fail("{s} is not named .rpm", .{path});
    if (parts.payload.len == 0) checker.fail("{s} has no payload", .{path});
}

/// A signed release has all five signature files.
fn check_signature_files(checker: *Checker) Error!void {
    const names = [_][]const u8{ release.apt_in_release_path, release.apt_release_gpg_path };
    for (names) |path| _ = checker.read(path);
    for (0..release.architectures.len) |index| {
        const repomd = try release.repomd_path(checker.memory, index);
        _ = checker.read(try checker.join(repomd, ".asc"));
    }
}

fn expect_signature(checker: *Checker, path: []const u8, expected: []const u8) void {
    const found = checker.read(path) orelse return;
    if (!std.mem.eql(u8, found, expected)) {
        checker.fail("{s} is not the test key's signature", .{path});
    }
}

fn check_test_signatures(checker: *Checker) Error!void {
    const key = openpgp.test_key();
    const memory = checker.memory;
    const text = checker.read(release.apt_release_path) orelse return;
    const detached = try openpgp.sign_detached(memory, key, text);
    const in_release = try openpgp.clearsign(memory, key, text);
    expect_signature(checker, release.apt_in_release_path, in_release);
    const release_gpg = try openpgp.armor(memory, "PGP SIGNATURE", detached);
    expect_signature(checker, release.apt_release_gpg_path, release_gpg);
    for (0..release.architectures.len) |index| {
        const path = try release.repomd_path(memory, index);
        const repomd = checker.read(path) orelse continue;
        const signed = try openpgp.sign_detached(memory, key, repomd);
        const armored = try openpgp.armor(memory, "PGP SIGNATURE", signed);
        expect_signature(checker, try checker.join(path, ".asc"), armored);
    }
}

/// Checks a whole tree. Every problem is one line on `log`; `error.CheckFailed` when any.
pub fn check(
    source: Source,
    memory: Allocator,
    log: *std.Io.Writer,
    options: Options,
) Error!void {
    var checker: Checker = .{ .source = source, .memory = memory, .log = log };
    try check_apt(&checker);
    for (0..release.architectures.len) |index| try check_dnf(&checker, index);
    if (options.signatures_required) try check_signature_files(&checker);
    if (options.test_key) try check_test_signatures(&checker);
    if (checker.files_checked == 0) assert(checker.failures > 0);
    if (checker.failures > 0) return error.CheckFailed;
}

/// A tree in memory, for the tests.
const MemorySource = struct {
    files: []const model.TreeFile,

    fn read(context: *anyopaque, path: []const u8) ?[]const u8 {
        const self: *MemorySource = @ptrCast(@alignCast(context));
        for (self.files) |file| {
            if (std.mem.eql(u8, file.path, path)) return file.bytes;
        }
        return null;
    }

    fn source(self: *MemorySource) Source {
        return .{ .context = self, .read_fn = read };
    }
};

const test_inputs: release.Inputs = .{
    .version = "1.2.3",
    .zbx = .{ "x86 binary", "arm binary" },
    .license = "MIT licence\n",
};

test "a built tree passes, and flipping one byte of a placed rpm fails" {
    // Goal: the check accepts what the builder writes and notices a changed file.
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const memory = arena.allocator();
    const files = try release.build(memory, &test_inputs, .{ .test_key = true });
    var sink: std.Io.Writer.Allocating = .init(memory);
    var source: MemorySource = .{ .files = files };
    const strict: Options = .{ .signatures_required = true, .test_key = true };
    try check(source.source(), memory, &sink.writer, strict);
    try std.testing.expectEqual(@as(usize, 0), sink.written().len);

    const tampered = try memory.dupe(model.TreeFile, files);
    for (tampered) |*file| {
        if (std.mem.endsWith(u8, file.path, ".rpm")) {
            const copy = try memory.dupe(u8, file.bytes);
            copy[copy.len - 1] ^= 1;
            file.bytes = copy;
            break;
        }
    }
    source = .{ .files = tampered };
    try std.testing.expectError(
        error.CheckFailed,
        check(source.source(), memory, &sink.writer, strict),
    );
    const message = "does not match its recorded sha256";
    try std.testing.expect(std.mem.indexOf(u8, sink.written(), message) != null);
}

test "an unsigned tree passes unless signatures are required" {
    // Goal: round one's output is checkable, and a release without its signatures is refused.
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const memory = arena.allocator();
    const files = try release.build(memory, &test_inputs, .{});
    var sink: std.Io.Writer.Allocating = .init(memory);
    var source: MemorySource = .{ .files = files };
    const loose: Options = .{ .signatures_required = false, .test_key = false };
    try check(source.source(), memory, &sink.writer, loose);
    const strict: Options = .{ .signatures_required = true, .test_key = false };
    try std.testing.expectError(
        error.CheckFailed,
        check(source.source(), memory, &sink.writer, strict),
    );
    const message = "apt/dists/stable/InRelease is missing";
    try std.testing.expect(std.mem.indexOf(u8, sink.written(), message) != null);
}
