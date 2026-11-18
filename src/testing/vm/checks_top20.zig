//! The top-20 run's judgement as pure functions over the text the guest printed, each
//! unit-tested with right and wrong input. The commands that print the text are in
//! main_top20.zig. One image gives one `Result`, and a `Result` gives one line.

const std = @import("std");
const assert = std.debug.assert;

pub const Verdict = enum {
    /// The default command ended with 0, or was still running when `--timeout` stopped it.
    pass,
    /// It did not, and the list gives the reason an image like this cannot run rootless.
    known,
    /// It did not, and nothing explains it: the run fails.
    fail,
};

/// What the probe of a long-running server found. `none`: the image has no probe, or it did not
/// stay up long enough to be asked.
pub const Probe = enum { none, ok, failed };

/// What the guest showed for one image.
pub const Observed = struct {
    pulled: bool,
    /// zbx's exit code for the run; 0 when the pull failed and no run was tried.
    status: u8,
    /// The run's stderr (or the pull's, when it failed).
    stderr: []const u8,
    probe: Probe = .none,
};

pub const Result = struct {
    ref: []const u8,
    pulled: bool,
    ran: bool,
    status: u8,
    probe: Probe = .none,
    verdict: Verdict,
    /// Syscall names that returned EPERM and are not on the seccomp allowlist; empty if none
    /// or not looked for.
    seccomp: []const u8,
    /// One line: why it failed, or why it is known not to run, or "-" for a pass.
    reason: []const u8,
};

/// `zbx run --timeout` ended the container: the report says so. The exit code is the program's
/// answer to SIGTERM, which varies (redis 0, mongo 143, registry 2), so it is not asked.
pub fn stopped_by_timeout(stderr: []const u8) bool {
    return std.mem.indexOf(u8, stderr, "zbx: stopped: timed out after") != null;
}

/// zbx failed before the command started (125) or could not start it (126, 127 from zbx).
pub fn command_started(status: u8) bool {
    return status < 125 or status > 127;
}

/// A server that is still up when the timeout stops it has run, unless its probe was asked and
/// got no answer: up but not serving is not a pass.
pub fn judge(observed: Observed, known: []const u8) Verdict {
    // A reason explains a run that fails; it never excuses a pull that did.
    if (!observed.pulled) return .fail;
    const up = observed.status == 0 or stopped_by_timeout(observed.stderr);
    if (up and observed.probe != .failed) return .pass;
    return if (known.len > 0) .known else .fail;
}

/// A probe, as `top20.zon` writes it: "port|send|expect". The guest connects to 127.0.0.1:port,
/// writes `send` (printf escapes) and looks for `expect` in the first bytes of the answer; an
/// empty `expect` means a connection is enough.
pub const ProbeSpec = struct {
    port: u16,
    send: []const u8,
    expect: []const u8,
};

/// The host port a server's probed port is published on (`--publish HOST:PORT`): 20000 above it,
/// so that it is above net.ipv4.ip_unprivileged_port_start (1024) and clear of the ports the
/// guest's own services use; a port too high for that keeps its number.
pub fn published_port(port: u16) u16 {
    std.debug.assert(port > 0);
    const offset: u16 = 20000;
    if (port > std.math.maxInt(u16) - offset) return port;
    const result = port + offset;
    std.debug.assert(result >= 1024);
    return result;
}

pub fn parse_probe(text: []const u8) ?ProbeSpec {
    if (text.len == 0) return null;
    var parts = std.mem.splitScalar(u8, text, '|');
    const port_text = parts.next() orelse return null;
    const send = parts.next() orelse return null;
    const expect = parts.next() orelse return null;
    if (parts.next() != null) return null;
    const port = std.fmt.parseInt(u16, port_text, 10) catch return null;
    if (port == 0) return null;
    return .{ .port = port, .send = send, .expect = expect };
}

/// The last non-empty line of `text`, trimmed; "-" if there is none. A failed container's last
/// word is usually its reason; zbx's own refusals are one line.
pub fn last_line(text: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, text, " \r\n\t");
    if (trimmed.len == 0) return "-";
    const start = if (std.mem.lastIndexOfScalar(u8, trimmed, '\n')) |at| at + 1 else 0;
    return std.mem.trim(u8, trimmed[start..], " \r\t");
}

/// The first line of `text` that starts with `prefix`, or null.
pub fn first_line_with(text: []const u8, prefix: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \r\t");
        if (std.mem.startsWith(u8, trimmed, prefix)) return trimmed;
    }
    return null;
}

/// Splits the guest's one line of EPERM syscall names (space separated) into those that are not
/// in `allowed`: the filter's own refusals. The others (a name the allowlist has) were refused
/// by something else, such as a missing capability. Writes the names, space separated, into
/// `out` and returns them.
pub fn seccomp_suspects(names: []const u8, allowed: []const []const u8, out: []u8) []const u8 {
    assert(out.len >= 2);
    var length: usize = 0;
    var words = std.mem.tokenizeAny(u8, names, " \r\n\t");
    while (words.next()) |word| {
        if (is_allowed(word, allowed)) continue;
        const room = out.len - length;
        if (word.len + 1 > room) break;
        if (length > 0) {
            out[length] = ' ';
            length += 1;
        }
        @memcpy(out[length..][0..word.len], word);
        length += word.len;
    }
    assert(length <= out.len);
    return out[0..length];
}

fn is_allowed(name: []const u8, allowed: []const []const u8) bool {
    for (allowed) |entry| {
        if (std.mem.eql(u8, entry, name)) return true;
    }
    return false;
}

/// The result line: fixed fields first, so a script can cut it at " | ".
pub fn format_line(buffer: []u8, result: Result) std.fmt.BufPrintError![]const u8 {
    assert(result.ref.len > 0);
    const seccomp = if (result.seccomp.len > 0) result.seccomp else "none";
    var exit_buffer: [8]u8 = undefined;
    const exit = if (result.pulled)
        try std.fmt.bufPrint(&exit_buffer, "{d}", .{result.status})
    else
        "-";
    return std.fmt.bufPrint(
        buffer,
        "{s} | pulled={s} | ran={s} | exit={s} | {s} | seccomp={s} | probe={s} | {s}",
        .{
            result.ref,
            yes_no(result.pulled),
            yes_no(result.ran),
            exit,
            @tagName(result.verdict),
            seccomp,
            @tagName(result.probe),
            result.reason,
        },
    );
}

/// The text of a manifest digest as zbx prints it: `sha256:` and 64 lowercase hex digits.
pub fn is_digest(text: []const u8) bool {
    const prefix = "sha256:";
    if (text.len != prefix.len + 64) return false;
    if (!std.mem.startsWith(u8, text, prefix)) return false;
    for (text[prefix.len..]) |char| {
        switch (char) {
            '0'...'9', 'a'...'f' => {},
            else => return false,
        }
    }
    return true;
}

/// A pinned entry of `top20.zon` names the floating entry's image by digest and nothing else:
/// `nginx:latest` pins as `nginx@sha256:...`. A digest is never a tag (REVIEW.md), so a pin with
/// a tag in it, or one of another image, is refused when the harness compiles.
pub fn pinned_matches(floating: []const u8, pinned: []const u8) bool {
    if (std.mem.indexOfScalar(u8, floating, '@') != null) return false;
    const colon = std.mem.indexOfScalar(u8, floating, ':') orelse return false;
    const at = std.mem.indexOfScalar(u8, pinned, '@') orelse return false;
    if (!std.mem.eql(u8, floating[0..colon], pinned[0..at])) return false;
    return is_digest(pinned[at + 1 ..]);
}

/// The digest a pinned reference names: the text after its `@`.
pub fn pinned_digest(pinned: []const u8) []const u8 {
    const at = std.mem.indexOfScalar(u8, pinned, '@').?;
    const digest = pinned[at + 1 ..];
    assert(at > 0);
    assert(is_digest(digest));
    return digest;
}

/// The reference a pulled image is run by. A tag runs by its name (the pull locked it). A pin
/// names the multi-arch index, but `zbx run` finds an image by the platform manifest it was
/// pulled as (a run by the index digest is refused with E0522), so a pin runs by the manifest
/// digest its pull printed on stdout: the same content, one level down. Null when the pull
/// printed no digest or the buffer is too small.
pub fn run_reference(buffer: []u8, pulled: []const u8, stdout: []const u8) ?[]const u8 {
    assert(pulled.len > 0);
    const at = std.mem.indexOfScalar(u8, pulled, '@') orelse return pulled;
    const manifest = last_line(stdout);
    if (!is_digest(manifest)) return null;
    const text = std.fmt.bufPrint(buffer, "{s}@{s}", .{ pulled[0..at], manifest }) catch
        return null;
    assert(std.mem.indexOfScalar(u8, text, '@').? == at);
    assert(std.mem.endsWith(u8, text, manifest));
    return text;
}

/// The `index_digest` of `zbx pull --resolve-only --output json` (`zbx.pull.resolve/1`): the
/// digest the floating tag names now. Null when the text has none (a single-manifest tag, whose
/// member is null, or output that is not the object).
pub fn index_digest_of(json: []const u8) ?[]const u8 {
    if (std.mem.indexOf(u8, json, "\"schema\":\"zbx.pull.resolve/1\"") == null) return null;
    const member = "\"index_digest\":\"";
    const found = std.mem.indexOf(u8, json, member) orelse return null;
    const start = found + member.len;
    const end = std.mem.indexOfScalarPos(u8, json, start, '"') orelse return null;
    assert(end >= start);
    const digest = json[start..end];
    return if (is_digest(digest)) digest else null;
}

/// Where the floating tag points now, against the pin: the same index, another one, or not
/// known (the resolve failed or printed no index digest).
pub const Tag = enum { same, moved, unknown };

pub fn tag_of(now: ?[]const u8, pinned: []const u8) Tag {
    const digest = now orelse return .unknown;
    assert(is_digest(digest));
    return if (std.mem.eql(u8, digest, pinned_digest(pinned))) .same else .moved;
}

/// What a floating and a pinned result say together. A failure of the floating tag alone, while
/// the pin runs, is the image's change upstream; a failure of the pin is the runtime's, since the
/// pin's content has not changed since it last passed. The same content judged two ways is
/// neither: the run is not repeatable.
pub const Change = enum {
    ok,
    known,
    upstream_moved,
    regression,
    regression_pinned,
    flaky,

    pub fn text(change: Change) []const u8 {
        return switch (change) {
            .ok => "ok",
            .known => "known",
            .upstream_moved => "upstream image moved",
            .regression => "runtime regression",
            .regression_pinned => "runtime regression (pinned only)",
            .flaky => "flaky (same content, different results)",
        };
    }
};

pub fn classify(floating: Verdict, pinned: Verdict, tag: Tag) Change {
    if (floating == .fail) {
        if (pinned == .fail) return .regression;
        return if (tag == .same) .flaky else .upstream_moved;
    }
    if (pinned == .fail) return if (tag == .same) .flaky else .regression_pinned;
    if (floating == pinned) return if (floating == .pass) .ok else .known;
    // A pass on one and a known reason on the other: the two contents behave differently.
    return if (tag == .same) .flaky else .upstream_moved;
}

/// One image's comparison: the floating reference, both verdicts, where the tag points and its
/// current index digest when the resolve gave one.
pub const Compare = struct {
    ref: []const u8,
    floating: Verdict,
    pinned: Verdict,
    tag: Tag,
    now: ?[]const u8,
};

/// The comparison line, then the tag's current digest when it moved, so that a refresh of the
/// pins can start there.
pub fn format_compare(buffer: []u8, compare: Compare) std.fmt.BufPrintError![]const u8 {
    assert(compare.ref.len > 0);
    if (compare.tag != .unknown) assert(compare.now != null);
    const change = classify(compare.floating, compare.pinned, compare.tag);
    const head = try std.fmt.bufPrint(buffer, "{s} | floating={s} | pinned={s} | tag={s} | {s}", .{
        compare.ref,
        @tagName(compare.floating),
        @tagName(compare.pinned),
        @tagName(compare.tag),
        change.text(),
    });
    if (compare.tag != .moved) return head;
    const tail = try std.fmt.bufPrint(buffer[head.len..], " | now {s}", .{compare.now.?});
    return buffer[0 .. head.len + tail.len];
}

fn yes_no(flag: bool) []const u8 {
    return if (flag) "yes" else "no";
}

const testing = std.testing;

test "a run passes on exit 0 or on the harness's own timeout, and on nothing else" {
    // Goal: the verdict of one image. Method: each way a run can end.
    const ok: Observed = .{ .pulled = true, .status = 0, .stderr = "" };
    try testing.expectEqual(Verdict.pass, judge(ok, ""));
    const timed: Observed = .{
        .pulled = true,
        .status = 143,
        .stderr = "zbx: stopped: timed out after 20000 ms\n",
    };
    try testing.expectEqual(Verdict.pass, judge(timed, ""));
    // The program's answer to SIGTERM may be any code.
    const answered: Observed = .{
        .pulled = true,
        .status = 2,
        .stderr = "zbx: stopped: timed out after 30000 ms\n",
    };
    try testing.expectEqual(Verdict.pass, judge(answered, ""));
    // 143 without the report is the container's own SIGTERM exit, not our timeout.
    const termed: Observed = .{ .pulled = true, .status = 143, .stderr = "" };
    try testing.expectEqual(Verdict.fail, judge(termed, ""));
    const failed: Observed = .{ .pulled = true, .status = 1, .stderr = "boom\n" };
    try testing.expectEqual(Verdict.fail, judge(failed, ""));
    try testing.expectEqual(Verdict.known, judge(failed, "needs a password"));
    // A reason does not hide a pass.
    try testing.expectEqual(Verdict.pass, judge(ok, "needs a password"));
    const unpulled: Observed = .{ .pulled = false, .status = 0, .stderr = "error[ZBX-E0505]" };
    try testing.expectEqual(Verdict.fail, judge(unpulled, ""));
    try testing.expectEqual(Verdict.fail, judge(unpulled, "needs a password"));
}

test "a server that is up but does not answer its probe does not pass" {
    // Goal: the probe is part of the verdict. Method: a stopped-by-timeout run with each probe
    // outcome.
    const base: Observed = .{
        .pulled = true,
        .status = 143,
        .stderr = "zbx: stopped: timed out after 30000 ms\n",
    };
    var observed = base;
    observed.probe = .ok;
    try testing.expectEqual(Verdict.pass, judge(observed, ""));
    observed.probe = .none;
    try testing.expectEqual(Verdict.pass, judge(observed, ""));
    observed.probe = .failed;
    try testing.expectEqual(Verdict.fail, judge(observed, ""));
    try testing.expectEqual(Verdict.known, judge(observed, "listens on 80"));
}

test "a probe is port, what to send and what to expect" {
    // Goal: the zon string. Method: a good one, an empty expect, and malformed ones.
    const spec = parse_probe("6379|PING\\r\\n|PONG").?;
    try testing.expectEqual(@as(u16, 6379), spec.port);
    try testing.expectEqualStrings("PING\\r\\n", spec.send);
    try testing.expectEqualStrings("PONG", spec.expect);
    try testing.expectEqualStrings("", parse_probe("27017||").?.expect);
    try testing.expect(parse_probe("") == null);
    try testing.expect(parse_probe("0||") == null);
    try testing.expect(parse_probe("80|x") == null);
    try testing.expect(parse_probe("80|x|y|z") == null);
    try testing.expect(parse_probe("http|x|y") == null);
}

test "the command started unless zbx itself failed" {
    // Goal: `ran` in the result line. Method: the edges of the 125 to 127 range.
    try testing.expect(command_started(0));
    try testing.expect(command_started(124));
    try testing.expect(!command_started(125));
    try testing.expect(!command_started(127));
    try testing.expect(command_started(128));
    try testing.expect(command_started(255));
}

test "the last line of the stderr is the reason" {
    // Goal: the reason column. Method: empty, one line, several lines and trailing blanks.
    try testing.expectEqualStrings("-", last_line(""));
    try testing.expectEqualStrings("-", last_line("\n \n"));
    try testing.expectEqualStrings("one", last_line("one\n"));
    try testing.expectEqualStrings("two", last_line("one\ntwo\n\n"));
    try testing.expectEqualStrings("error[ZBX-E0501]: x", first_line_with(
        "warning: y\n  error[ZBX-E0501]: x\nmore\n",
        "error[",
    ).?);
    try testing.expect(first_line_with("nothing\n", "error[") == null);
}

test "only a syscall the allowlist lacks is the filter's refusal" {
    // Goal: tell a seccomp EPERM from any other. Method: one name of each kind, and a buffer
    // too small for all of them.
    const allowed = [_][]const u8{ "setgroups", "openat", "read" };
    var out: [64]u8 = undefined;
    const got = seccomp_suspects("setgroups fchmodat2 openat cachestat\n", &allowed, &out);
    try testing.expectEqualStrings("fchmodat2 cachestat", got);
    try testing.expectEqualStrings("", seccomp_suspects("", &allowed, &out));
    try testing.expectEqualStrings("", seccomp_suspects("openat read", &allowed, &out));
    var small: [10]u8 = undefined;
    const cut = seccomp_suspects("fchmodat2 cachestat", &allowed, &small);
    try testing.expectEqualStrings("fchmodat2", cut);
}

test "a result is one line with the fields in a fixed order" {
    // Goal: the line a script cuts at " | ". Method: a pass, a seccomp failure, an unpulled image.
    var buffer: [256]u8 = undefined;
    const pass: Result = .{
        .ref = "alpine:latest",
        .pulled = true,
        .ran = true,
        .status = 0,
        .verdict = .pass,
        .seccomp = "",
        .reason = "-",
    };
    try testing.expectEqualStrings(
        "alpine:latest | pulled=yes | ran=yes | exit=0 | pass | seccomp=none | probe=none | -",
        try format_line(&buffer, pass),
    );
    var seccomp = pass;
    seccomp.status = 1;
    seccomp.verdict = .fail;
    seccomp.seccomp = "fchmodat2";
    seccomp.reason = "Operation not permitted";
    try testing.expectEqualStrings(
        "alpine:latest | pulled=yes | ran=yes | exit=1 | fail | seccomp=fchmodat2 | " ++
            "probe=none | Operation not permitted",
        try format_line(&buffer, seccomp),
    );
    var unpulled = pass;
    unpulled.pulled = false;
    unpulled.ran = false;
    unpulled.verdict = .fail;
    try testing.expectEqualStrings(
        "alpine:latest | pulled=no | ran=no | exit=- | fail | seccomp=none | probe=none | -",
        try format_line(&buffer, unpulled),
    );
}

test "a probed port is published 20000 above, and a high one as it is" {
    // Goal: every probed port of top20.zon has a host port a user may bind. Method: the ports
    // the list probes, the edge where 20000 more would not fit, and the highest.
    try std.testing.expectEqual(@as(u16, 20080), published_port(80));
    try std.testing.expectEqual(@as(u16, 47017), published_port(27017));
    try std.testing.expectEqual(@as(u16, 65535), published_port(45535));
    try std.testing.expectEqual(@as(u16, 45536), published_port(45536));
    try std.testing.expectEqual(@as(u16, 65535), published_port(65535));
}

test "a pin names its floating entry's image by a digest, never by a tag" {
    // Goal: the compile-time check of top20.zon's pins. Method: a good pin, and each way one
    // can be wrong: another image, a tag, a short or upper-case digest, a floating digest.
    const digest = "sha256:" ++ "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    try testing.expect(is_digest(digest));
    try testing.expect(pinned_matches("nginx:latest", "nginx@" ++ digest));
    try testing.expect(pinned_matches("openjdk:28-ea-jdk-slim", "openjdk@" ++ digest));
    try testing.expect(!pinned_matches("nginx:latest", "httpd@" ++ digest));
    try testing.expect(!pinned_matches("nginx:latest", "nginx:latest"));
    try testing.expect(!pinned_matches("nginx:latest", "nginx:latest@" ++ digest));
    try testing.expect(!pinned_matches("nginx:latest", "nginx@" ++ digest[0..70]));
    const upper = "sha256:" ++ "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    try testing.expect(!pinned_matches("nginx:latest", "nginx@" ++ upper));
    try testing.expect(!pinned_matches("nginx@" ++ digest, "nginx@" ++ digest));
    try testing.expect(!is_digest("sha512:" ++ digest["sha256:".len..]));
    try testing.expectEqualStrings(digest, pinned_digest("nginx@" ++ digest));
}

test "a pin runs by the manifest digest its pull printed, a tag by its name" {
    // Goal: the run reference of each list. Method: the stdout of a real pull by index digest
    // (hello-world, 2026-11-18: the warning went to stderr, the platform manifest to stdout), a
    // tag, a pull that printed no digest, and a buffer too small.
    var buffer: [160]u8 = undefined;
    const index = "hello-world@sha256:" ++
        "1e4c05b897a751332ce85c7e9449da2d93514ea2dea6dbb0e2753c9e949b2bfa";
    const stdout = "sha256:d1a8d0a4eeb63aff09f5f34d4d80505e0ba81905f36158cc3970d8e07179e59e\n";
    try testing.expectEqualStrings(
        "hello-world@sha256:d1a8d0a4eeb63aff09f5f34d4d80505e0ba81905f36158cc3970d8e07179e59e",
        run_reference(&buffer, index, stdout).?,
    );
    try testing.expectEqualStrings("redis:latest", run_reference(&buffer, "redis:latest", "").?);
    try testing.expect(run_reference(&buffer, index, "") == null);
    try testing.expect(run_reference(&buffer, index, "sha256:12\n") == null);
    var small: [20]u8 = undefined;
    try testing.expect(run_reference(&small, index, stdout) == null);
}

test "the floating tag's index digest is read from the resolve's JSON" {
    // Goal: the `tag=` field. Method: the output of a real `zbx pull --resolve-only --output json
    // hello-world:latest` (2026-11-18, its config and layers cut), a single manifest (null), and
    // text that is not the object.
    const real = "{\"schema\":\"zbx.pull.resolve/1\",\"reference\":" ++
        "\"docker.io/library/hello-world:latest\",\"registry\":\"docker.io\"," ++
        "\"repository\":\"library/hello-world\",\"index_digest\":\"sha256:" ++
        "1e4c05b897a751332ce85c7e9449da2d93514ea2dea6dbb0e2753c9e949b2bfa\"," ++
        "\"manifest_digest\":\"sha256:" ++
        "d1a8d0a4eeb63aff09f5f34d4d80505e0ba81905f36158cc3970d8e07179e59e\"," ++
        "\"manifest_size\":1023,\"platform\":\"linux/amd64\",\"layers\":[]}\n";
    const now = index_digest_of(real).?;
    try testing.expectEqualStrings(
        "sha256:1e4c05b897a751332ce85c7e9449da2d93514ea2dea6dbb0e2753c9e949b2bfa",
        now,
    );
    const single = "{\"schema\":\"zbx.pull.resolve/1\",\"index_digest\":null}";
    try testing.expect(index_digest_of(single) == null);
    try testing.expect(index_digest_of("error[ZBX-E0505]: \"index_digest\":\"x\"") == null);
    const pin = "hello-world@sha256:" ++
        "1e4c05b897a751332ce85c7e9449da2d93514ea2dea6dbb0e2753c9e949b2bfa";
    try testing.expectEqual(Tag.same, tag_of(now, pin));
    const other = "sha256:" ++ "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    try testing.expectEqual(Tag.moved, tag_of(other, pin));
    try testing.expectEqual(Tag.unknown, tag_of(null, pin));
}

test "floating against pinned tells an image that moved from a runtime regression" {
    // Goal: the class of every pair of verdicts. Method: each pair, with the tag moved, the same
    // or unknown where that changes the answer.
    try testing.expectEqual(Change.ok, classify(.pass, .pass, .moved));
    try testing.expectEqual(Change.known, classify(.known, .known, .same));
    try testing.expectEqual(Change.upstream_moved, classify(.fail, .pass, .moved));
    try testing.expectEqual(Change.upstream_moved, classify(.fail, .known, .unknown));
    try testing.expectEqual(Change.flaky, classify(.fail, .pass, .same));
    try testing.expectEqual(Change.regression, classify(.fail, .fail, .moved));
    try testing.expectEqual(Change.regression, classify(.fail, .fail, .same));
    try testing.expectEqual(Change.regression_pinned, classify(.pass, .fail, .moved));
    try testing.expectEqual(Change.regression_pinned, classify(.known, .fail, .unknown));
    try testing.expectEqual(Change.flaky, classify(.pass, .fail, .same));
    try testing.expectEqual(Change.upstream_moved, classify(.known, .pass, .moved));
    try testing.expectEqual(Change.flaky, classify(.pass, .known, .same));
}

test "the comparison line names the class, and the tag's digest when it moved" {
    // Goal: the job summary's comparison line. Method: a moved tag, the same one, an unknown.
    var buffer: [256]u8 = undefined;
    const other = "sha256:" ++ "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const moved: Compare = .{
        .ref = "nginx:latest",
        .floating = .fail,
        .pinned = .pass,
        .tag = .moved,
        .now = other,
    };
    try testing.expectEqualStrings(
        "nginx:latest | floating=fail | pinned=pass | tag=moved | upstream image moved | now " ++
            other,
        try format_compare(&buffer, moved),
    );
    var same = moved;
    same.floating = .pass;
    same.tag = .same;
    try testing.expectEqualStrings(
        "nginx:latest | floating=pass | pinned=pass | tag=same | ok",
        try format_compare(&buffer, same),
    );
    var unknown = moved;
    unknown.tag = .unknown;
    unknown.now = null;
    unknown.pinned = .fail;
    try testing.expectEqualStrings(
        "nginx:latest | floating=fail | pinned=fail | tag=unknown | runtime regression",
        try format_compare(&buffer, unknown),
    );
}
