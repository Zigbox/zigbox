//! demo-m6d's guest helper: a static program that links the `zigbox` module, served to the guest.
//! It prints no secret, ever: counts, paths, offsets and the names of states only.
//!
//!   helper shapes <label> <credentials-file> [<label> <credentials-file>]
//!       Resolves a token through each workload identity file (the library call, as the agent
//!       makes it) and says its class and length (shape.zig): whether it starts with the shape
//!       the scan searches for, so that step 5's search for tokens it cannot know exactly (each
//!       zbx run exchanges its own) is a checked claim. No byte of a token is printed, not even
//!       its prefix. The tokens are wiped, never written.
//!   helper agent <reference>
//!       The library path: resolves the token from GOOGLE_APPLICATION_CREDENTIALS itself and
//!       pulls with it (`pull.Request.google`). Prints one JSON document, nothing else.
//!   helper mask <secrets-dir> <file>
//!       Prints `file` (zbx's saved output) with every OIDC token in the secrets directory and
//!       every token shape masked (mask.zig): the console is copied into the job log.
//!   helper scan <secrets-dir> <exclude>[,<exclude>...] <root>...
//!       Searches every regular file under the roots, but the excluded paths and the secrets
//!       directory, for each OIDC token in the secrets directory (`oidc-*`) and each token shape.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const Io = std.Io;
const zigbox = @import("zigbox");
const scan = @import("scan.zig");
const mask = @import("mask.zig");
const shape = @import("shape.zig");

const HostReal = zigbox.host_real.HostReal;
const Diag = zigbox.diag.Diag;
/// `zigbox` exports no name for the real network's memory; the field's type names it.
const NetworkMemory = @typeInfo(@typeInfo(@FieldType(HostReal, "network_memory"))
    .optional.child).pointer.child;

const line_bytes_max = 512;
/// The longest saved output `mask` prints; zbx's are a few KiB.
const shown_bytes_max = 256 * 1024;
const render_bytes = 16 * 1024;
/// `oidc-*` files the scan reads as needles: the shapes take the rest of `needles_max`.
const oidc_tokens_max = scan.needles_max - scan.shapes.len;

var network_memory: NetworkMemory = undefined;
var facts: zigbox.Facts = undefined;
var pull_workspace: zigbox.pull.Workspace = undefined;
var import_workspace: zigbox.store.import.Workspace = undefined;
var pull_result: zigbox.pull.Result = undefined;
var google_workspace: zigbox.GoogleWorkspace = undefined;
var google_token: zigbox.GoogleToken = .{};
var scanner: scan.Scanner = .{};
var chunk: [scan.chunk_bytes]u8 = undefined;
var needle_storage: [oidc_tokens_max][scan.needle_bytes_max]u8 = undefined;
var shown: [shown_bytes_max]u8 = undefined;
var masked: [mask.out_bytes(shown_bytes_max)]u8 = undefined;

fn say(comptime format: []const u8, args: anytype) void {
    var buffer: [line_bytes_max]u8 = undefined;
    const text = std.fmt.bufPrint(&buffer, format ++ "\n", args) catch return;
    _ = linux.write(1, text.ptr, text.len);
}

pub fn main(init: std.process.Init) u8 {
    const args = init.minimal.args.toSlice(init.arena.allocator()) catch return 2;
    if (args.len < 2) return usage();
    const command: []const u8 = args[1];
    network_memory.init();
    var real: HostReal = .{ .environ = init.minimal.environ, .network_memory = &network_memory };
    if (std.mem.eql(u8, command, "shapes")) return shapes(real.interface(), args[2..]);
    if (std.mem.eql(u8, command, "agent")) {
        if (args.len != 3) return usage();
        return agent(real.interface(), args[2]);
    }
    if (std.mem.eql(u8, command, "mask")) {
        if (args.len != 4) return usage();
        return mask_file(init.io, args[2], args[3]);
    }
    if (std.mem.eql(u8, command, "scan")) {
        if (args.len < 5) return usage();
        return scan_roots(init.io, args[2], args[3], args[4..]);
    }
    return usage();
}

fn usage() u8 {
    say("usage: helper shapes|agent|mask|scan ...", .{});
    return 2;
}

/// Resolves through `path` alone, as the agent does; on failure says which step and state.
fn resolve_with(host: zigbox.host.Host, path: []const u8, label: []const u8) bool {
    assert(path.len > 0);
    const pairs = [_]zigbox.GoogleEnv.Pair{
        .{ .name = "GOOGLE_APPLICATION_CREDENTIALS", .value = path },
    };
    const env: zigbox.GoogleEnv = .{ .pairs = &pairs };
    var trace: zigbox.GoogleTrace = .{};
    const sources: zigbox.GoogleSources = .{ .workload_identity = true };
    zigbox.google_credentials_resolve(
        host,
        env,
        host.time_now(),
        sources,
        &google_workspace,
        &google_token,
        &trace,
    ) catch {
        say("shapes: {s} token: not resolved ({t} at {t})", .{
            label, trace.workload_identity, trace.step,
        });
        return false;
    };
    assert(google_token.len > 0);
    return true;
}

fn shapes(host: zigbox.host.Host, pairs: []const [:0]const u8) u8 {
    if (pairs.len == 0 or pairs.len % 2 != 0) return usage();
    defer google_token.wipe();
    var index: usize = 0;
    while (index < pairs.len) : (index += 2) {
        const label = pairs[index];
        if (label.len == 0 or label.len > 32) return usage();
        if (!resolve_with(host, pairs[index + 1], label)) return 1;
        var buffer: [shape.line_bytes_max]u8 = undefined;
        // The class and the length only: no byte of the token, not even its prefix.
        const class = shape.classify(google_token.text());
        const line = shape.shape_line(&buffer, label, google_token.text());
        google_token.wipe();
        say("{s}", .{line});
        if (class != .google_access) return 1;
    }
    assert(google_token.len == 0);
    return 0;
}

fn agent(host: zigbox.host.Host, reference: []const u8) u8 {
    assert(reference.len > 0);
    var pairs: [zigbox.GoogleEnv.names.len]zigbox.GoogleEnv.Pair = undefined;
    const env = zigbox.GoogleEnv.from_host(host, &pairs);
    const path = env.get("GOOGLE_APPLICATION_CREDENTIALS") orelse {
        say("agent: GOOGLE_APPLICATION_CREDENTIALS is not set", .{});
        return 1;
    };
    defer google_token.wipe();
    if (!resolve_with(host, path, "agent")) return 1;
    const request: zigbox.pull.Request = .{
        .reference = reference,
        .platform = .{},
        .mirrors = "",
        .google = &google_token,
    };
    var diag: Diag = undefined;
    diag.reset();
    zigbox.pull.pull(
        host,
        &facts,
        &request,
        null,
        &pull_workspace,
        &import_workspace,
        &pull_result,
        &diag,
    ) catch {
        var buffer: [render_bytes]u8 = undefined;
        const text = zigbox.render.render(&diag, .text, false, &buffer);
        say("agent: {s}", .{std.mem.sliceTo(text, '\n')});
        return 1;
    };
    const digest = pull_result.manifest_digest.text();
    const tree = pull_result.tree.text();
    say("{{\"schema\":\"zbx-demo.m6d-agent/1\",\"reference\":\"{s}\",\"manifest_digest\":" ++
        "\"{s}\",\"tree\":\"{s}\",\"token_source\":\"{t}\"}}", .{
        reference, &digest, &tree, google_token.source,
    });
    return 0;
}

// ---- Step 5 ----------------------------------------------------------------------------------

const Tally = struct {
    files: u64 = 0,
    bytes: u64 = 0,
    skipped: u64 = 0,
    hits: u64 = 0,
};

/// The OIDC tokens the harness served (`oidc-*` in `secrets`) into `needles`: their count, which
/// may be 0, or null when the directory or a token cannot be read.
fn load_tokens(io: Io, secrets: []const u8, needles: *[scan.needles_max][]const u8) ?u32 {
    assert(secrets.len > 0);
    var dir = Io.Dir.openDirAbsolute(io, secrets, .{ .iterate = true }) catch return null;
    defer dir.close(io);
    var count: u32 = 0;
    var iterator = dir.iterate();
    while (iterator.next(io) catch return null) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.startsWith(u8, entry.name, "oidc-")) continue;
        if (count == oidc_tokens_max) return null;
        const file = dir.openFile(io, entry.name, .{}) catch return null;
        defer file.close(io);
        const read = file.readPositionalAll(io, &needle_storage[count], 0) catch return null;
        const token = std.mem.trim(u8, needle_storage[count][0..read], " \r\n");
        if (token.len < scan.needle_bytes_min) return null;
        if (token.len >= scan.needle_bytes_max) return null;
        needles[count] = token;
        count += 1;
    }
    assert(count <= oidc_tokens_max);
    return count;
}

fn mask_file(io: Io, secrets: []const u8, path: []const u8) u8 {
    assert(path.len > 0);
    defer std.crypto.secureZero(u8, std.mem.sliceAsBytes(&needle_storage));
    var needles: [scan.needles_max][]const u8 = undefined;
    const count = load_tokens(io, secrets, &needles) orelse {
        say("mask: the OIDC tokens in {s} could not be read", .{secrets});
        return 1;
    };
    const file = Io.Dir.openFileAbsolute(io, path, .{}) catch {
        say("mask: {s} could not be opened", .{path});
        return 1;
    };
    defer file.close(io);
    const read = file.readPositionalAll(io, &shown, 0) catch {
        say("mask: {s} could not be read", .{path});
        return 1;
    };
    if (read == shown.len) {
        say("mask: {s} is longer than {d} bytes; not shown", .{ path, shown.len });
        return 1;
    }
    const text = mask.mask_secrets(shown[0..read], needles[0..count], &masked);
    _ = linux.write(1, text.ptr, text.len);
    return 0;
}

fn scan_roots(io: Io, secrets: []const u8, excludes: []const u8, roots: []const [:0]const u8) u8 {
    assert(roots.len > 0);
    defer std.crypto.secureZero(u8, std.mem.sliceAsBytes(&needle_storage));
    var needles: [scan.needles_max][]const u8 = undefined;
    const tokens = load_tokens(io, secrets, &needles) orelse 0;
    if (tokens == 0) {
        say("scan: no OIDC token could be read in {s}", .{secrets});
        return 1;
    }
    var count = tokens;
    for (scan.shapes) |prefix| {
        needles[count] = prefix;
        count += 1;
    }
    scanner.init(needles[0..count]);
    say("needles {d}", .{count});
    var tally: Tally = .{};
    for (roots) |root| {
        const before = tally.files;
        scan_root(io, root, secrets, excludes, &tally);
        say("root {s} files {d}", .{ root, tally.files - before });
    }
    say("files {d} bytes {d} skipped {d}", .{ tally.files, tally.bytes, tally.skipped });
    if (tally.hits == 0 and tally.skipped == 0) {
        say("scan: clean", .{});
        return 0;
    }
    say("scan: FOUND {d}", .{tally.hits});
    return 1;
}

fn scan_root(
    io: Io,
    root: []const u8,
    secrets: []const u8,
    excludes: []const u8,
    tally: *Tally,
) void {
    assert(root.len > 0);
    var dir = Io.Dir.openDirAbsolute(io, root, .{ .iterate = true }) catch {
        say("SKIP {s} (not opened)", .{root});
        tally.skipped += 1;
        return;
    };
    defer dir.close(io);
    var walker = dir.walk(std.heap.page_allocator) catch {
        tally.skipped += 1;
        return;
    };
    defer walker.deinit();
    var path_buffer: [4096]u8 = undefined;
    while (true) {
        const entry = (walker.next(io) catch {
            say("SKIP {s} (a directory under it could not be read)", .{root});
            tally.skipped += 1;
            return;
        }) orelse break;
        if (entry.kind != .file) continue; // Directories, links, sockets: nothing to read.
        const path = std.fmt.bufPrint(&path_buffer, "{s}/{s}", .{ root, entry.path }) catch {
            tally.skipped += 1;
            continue;
        };
        if (scan.excluded(path, secrets, excludes)) continue;
        scan_file(io, entry.dir, entry.basename, path, tally);
    }
}

fn scan_file(io: Io, dir: Io.Dir, name: []const u8, path: []const u8, tally: *Tally) void {
    assert(name.len > 0);
    const file = dir.openFile(io, name, .{}) catch {
        say("SKIP {s} (not opened)", .{path});
        tally.skipped += 1;
        return;
    };
    defer file.close(io);
    scanner.reset();
    var offset: u64 = 0;
    while (true) {
        const read = file.readPositional(io, &.{&chunk}, offset) catch {
            say("SKIP {s} (not read)", .{path});
            tally.skipped += 1;
            return;
        };
        if (read == 0) break;
        _ = scanner.feed(chunk[0..read]);
        offset += read;
    }
    tally.files += 1;
    tally.bytes += offset;
    if (scanner.first) |hit| {
        say("HIT {s} needle={d} offset={d}", .{ path, hit.needle, hit.offset });
        tally.hits += 1;
    }
}
