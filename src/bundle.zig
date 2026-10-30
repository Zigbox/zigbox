//! Diagnostic bundles (DIAGNOSTICS.md, "Bundles: the kitchen sink, only when needed"): one
//! `.tar.gz` with everything needed to diagnose a run without a back-and-forth. `zbx bundle`
//! writes one on request; a `bug` diagnostic from a failed run writes one by itself.
//!
//! Everything is bounded and nothing allocates. The files are staged in a fixed buffer (each cut
//! at `bundle_file_bytes_max`, and the manifest says so), redacted on the way in (redact.zig),
//! then written through std's tar writer into std's gzip compressor, which writes into a second
//! fixed buffer. The bundle is saved under a temporary name and renamed, so a full disk leaves
//! no half file. A bundle never leaves the machine.
//!
//! Layout of a bundle, in a directory named like the file without `.tar.gz`:
//!   MANIFEST.txt     every file below and why it is there; what was cut; what was redacted
//!   run-record.zon   the run's record (name, rootfs, command, labels, times, how it ended)
//!   diagnostic.json  the diagnostic the run ended with, as `--output json` prints it (if any)
//!   execs.txt        the recent execs into the container: command and exit, no environment
//!   version.txt      the zbx version and how it was built
//!   mapping.txt      the id mapping mode of the run, and the uid and gid of the user
//!   doctor.json      `zbx doctor`, run in-process: one line per check, then each failure
//!   uname.txt, os-release.txt, cgroup.txt   kernel, distribution and cgroup layout
//!   environment.txt  the names of the environment variables; their values are redacted
//!
//! The panic handler does not write a bundle, on purpose. A bundle needs a `Host`, which a panic
//! cannot reach safely (the vtable and its context may be what broke), about 700 KiB of stack
//! on top of whatever is left, and std's compressor, whose own assertions would be a second
//! panic inside the handler. `diag/panic.zig` keeps its fixed buffer and its one write, and a
//! panic is reported without a `saved` line. A `bug` that the code raises as a diagnostic, from
//! a run that has a record, does get a bundle (`attach_to_bug`, called by cli.zig).

const std = @import("std");
const assert = std.debug.assert;
const build_options = @import("build_options");
const constants = @import("constants.zig");
const doctor = @import("doctor.zig");
const host_mod = @import("host.zig");
const redact = @import("redact.zig");
const diag_errors = @import("diag/errors.zig");
const render = @import("diag/render.zig");
const Diag = @import("diag/diag.zig").Diag;
const records = @import("runtime/records.zig");
const exec_history = @import("runtime/exec_history.zig");
const logfile = @import("runtime/logfile.zig");

const Host = host_mod.Host;
const flate = std.compress.flate;

pub const Request = struct {
    /// The run to collect; null for the newest record.
    name: ?[]const u8,
    /// Replace secrets (the default). Off only for `--no-redact`.
    redact: bool,
};

/// Where a bundle went.
pub const Saved = struct {
    path: [constants.state_path_bytes_max + 128]u8,
    len: u32,

    pub fn slice(saved: *const Saved) []const u8 {
        assert(saved.len > 0);
        return saved.path[0..saved.len];
    }
};

/// The reason is in the diagnostic.
pub const Error = error{BundleFailed};

const manifest_bytes_max: u32 = 8 * 1024;

const File = struct {
    name: []const u8,
    why: []const u8,
    start: u32,
    len: u32,
    /// Cut at a bound: the source was longer than what is kept.
    cut: bool,
    redactions: u32,
};

/// All the memory a bundle needs. One of these lives on the stack of `write`.
/// Everything a bundle needs (about a megabyte: staged files, the compressor's tables, the
/// redaction mask, the doctor's facts). The caller owns it, so bundles on two threads share
/// nothing; keep it off the stack.
pub const Workspace = struct {
    stage: [constants.bundle_stage_bytes_max]u8,
    used: u32,
    raw: [constants.bundle_file_bytes_max]u8,
    files: [constants.bundle_files_max]File,
    count: u32,
    manifest_len: u32,
    secrets: [constants.bundle_secrets_max][]const u8,
    secrets_count: u32,
    redact: bool,
    redactions: u32,
    gz: [constants.bundle_gz_bytes_max]u8,
    window: [flate.max_window_len]u8,
    mask: redact.Mask,
    /// Room for the doctor check the bundle includes.
    facts: doctor.Facts,
    /// Room for the container's exec history (`runtime/exec_history.zig`).
    execs: exec_history.Scratch,

    fn reset(ws: *Workspace, redacting: bool) void {
        ws.used = manifest_bytes_max;
        ws.count = 0;
        ws.manifest_len = 0;
        ws.secrets_count = 0;
        ws.redact = redacting;
        ws.redactions = 0;
        assert(ws.used < ws.stage.len);
    }

    /// Stages `source` as a file of the bundle: redacted unless `trusted` (text this file built
    /// itself, already safe) or redaction is off, and cut at the bounds.
    fn add(ws: *Workspace, name: []const u8, why: []const u8, source: []const u8, cut: bool) void {
        assert(ws.count < constants.bundle_files_max - 1); // One slot is the manifest's.
        assert(name.len > 0);
        const room = @min(constants.bundle_file_bytes_max, ws.stage.len - ws.used);
        const target = ws.stage[ws.used..][0..room];
        var length: u32 = 0;
        var was_cut = cut;
        var redactions: u32 = 0;
        if (room == 0) {
            was_cut = true;
        } else if (ws.redact) {
            const secrets = ws.secrets[0..ws.secrets_count];
            const result = redact.redact_with(&ws.mask, source, target, secrets);
            length = result.len;
            redactions = result.redactions;
            was_cut = was_cut or result.truncated;
        } else {
            length = @intCast(@min(source.len, room));
            @memcpy(target[0..length], source[0..length]);
            was_cut = was_cut or length < source.len;
        }
        ws.push(name, why, length, was_cut, redactions);
    }

    /// Stages text that is safe as it is.
    fn add_trusted(
        ws: *Workspace,
        name: []const u8,
        why: []const u8,
        source: []const u8,
        cut: bool,
    ) void {
        assert(ws.count < constants.bundle_files_max - 1);
        const room = @min(constants.bundle_file_bytes_max, ws.stage.len - ws.used);
        const length: u32 = @intCast(@min(source.len, room));
        @memcpy(ws.stage[ws.used..][0..length], source[0..length]);
        ws.push(name, why, length, cut or length < source.len, 0);
    }

    fn push(
        ws: *Workspace,
        name: []const u8,
        why: []const u8,
        length: u32,
        cut: bool,
        n: u32,
    ) void {
        assert(ws.used + length <= ws.stage.len);
        ws.files[ws.count] = .{
            .name = name,
            .why = why,
            .start = ws.used,
            .len = length,
            .cut = cut,
            .redactions = n,
        };
        ws.count += 1;
        ws.used += length;
        ws.redactions += n;
    }

    fn content(ws: *const Workspace, file: *const File) []const u8 {
        assert(file.start >= manifest_bytes_max); // The manifest's room comes first.
        assert(file.start + file.len <= ws.used);
        return ws.stage[file.start..][0..file.len];
    }
};

// ---- The workspace: the caller's, one bundle at a time per workspace ----------------------

comptime {
    // The workspace is about 700 KiB with the compressor and the mask, far more than a thread's
    // or a small `ulimit -s` stack holds, so the caller provides it. This is the bound.
    assert(@sizeOf(Workspace) <= constants.bundle_workspace_bytes_max);
    assert(constants.bundle_workspace_bytes_max > 64 * 1024);
}

// ---- The UTC timestamp ---------------------------------------------------------------------

/// "2026-10-23T22-41-07Z": the form DIAGNOSTICS.md shows, with '-' for ':' so it is a file name.
pub fn timestamp(seconds: u64, buffer: *[constants.timestamp_bytes]u8) []const u8 {
    const since: std.time.epoch.EpochSeconds = .{ .secs = seconds };
    const year_day = since.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_time = since.getDaySeconds();
    const format = "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}-{d:0>2}-{d:0>2}Z";
    // Cannot fail: years up to 9999 are 20 bytes; a larger one is not a clock this host has.
    const text = std.fmt.bufPrint(buffer, format, .{
        year_day.year,
        month_day.month.numeric(),
        @as(u32, month_day.day_index) + 1,
        day_time.getHoursIntoDay(),
        day_time.getMinutesIntoHour(),
        day_time.getSecondsIntoMinute(),
    }) catch unreachable; // The text is 20 bytes for every year below 10000.
    assert(text.len == constants.timestamp_bytes);
    return text;
}

// ---- The sources ---------------------------------------------------------------------------

fn stage_system_files(ws: *Workspace, host: Host, mapping: []const u8) void {
    assert(ws.count > 0); // The record, or its absence, is already in.
    var writer = std.Io.Writer.fixed(&ws.raw);
    // Cannot fail: a few short lines into a buffer of 32 KiB.
    const builtin = @import("builtin");
    writer.print("zbx {s}\nbuild: {s} {s}-linux\n", .{
        build_options.version, @tagName(builtin.mode), @tagName(builtin.cpu.arch),
    }) catch unreachable; // Same bound.
    ws.add_trusted("version.txt", "the zbx version and how it was built", writer.buffered(), false);
    writer = std.Io.Writer.fixed(&ws.raw);
    // Cannot fail: as above.
    writer.print("ids: {s}\nuid: {d}\ngid: {d}\n", .{ mapping, host.uid(), host.gid() }) catch
        unreachable;
    const why = "how ids were mapped into the container, and who ran zbx";
    ws.add_trusted("mapping.txt", why, writer.buffered(), false);
    stage_uname(ws, host);
    stage_file(ws, host, "/etc/os-release", "os-release.txt", "the distribution");
    stage_file(ws, host, "/proc/self/cgroup", "cgroup.txt", "the cgroup layout of the zbx process");
}

/// The kernel release and machine. The host name is left out: it names the machine, and
/// nothing in a diagnosis needs it.
fn stage_uname(ws: *Workspace, host: Host) void {
    assert(ws.count < constants.bundle_files_max - 1);
    assert(ws.used >= manifest_bytes_max);
    var writer = std.Io.Writer.fixed(&ws.raw);
    if (host.uname()) |name| {
        // Cannot fail: two short fields into a buffer of 32 KiB.
        const format = "release: {s}\nmachine: {s}\n";
        const args = .{ name.release.slice(), name.machine.slice() };
        writer.print(format, args) catch unreachable; // Same.
    } else |_| {
        writer.writeAll("unavailable: uname failed\n") catch unreachable; // Same bound.
    }
    const why = "the kernel release and machine (not the host name)";
    ws.add_trusted("uname.txt", why, writer.buffered(), false);
}

fn stage_file(
    ws: *Workspace,
    host: Host,
    path: []const u8,
    name: []const u8,
    why: []const u8,
) void {
    assert(path.len > 0);
    const prefix = host.read_prefix(path, &ws.raw) catch {
        var writer = std.Io.Writer.fixed(&ws.raw);
        // Cannot fail: a path of at most a few dozen bytes into a buffer of 32 KiB.
        writer.print("unavailable: {s} could not be read\n", .{path}) catch unreachable;
        ws.add_trusted(name, why, writer.buffered(), false);
        return;
    };
    ws.add(name, why, prefix.bytes, prefix.truncated);
}

/// The container's recent execs (M6b): when each started, how long it ran, how it ended and its
/// command. The history keeps no environment, so no value of an exec's `-e` can be here; the
/// commands are redacted like every other file. A container that was never exec'd into has
/// none, and the bundle says so.
fn stage_execs(ws: *Workspace, host: Host, runs: *const records.Dir, name: []const u8) void {
    assert(ws.count < constants.bundle_files_max - 1);
    assert(name.len > 0);
    const file = "execs.txt";
    const why = "the recent execs into the container: command and exit, never the environment";
    var writer = std.Io.Writer.fixed(&ws.raw);
    const logs = logfile.dir_of(runs) orelse return;
    exec_history.read(host.log_files(), &logs, name, &ws.execs) catch |err| {
        // Cannot fail: a short line into a buffer of 32 KiB.
        writer.print("unavailable: the exec history could not be read ({s})\n", .{
            @errorName(err),
        }) catch unreachable;
        return ws.add_trusted(file, why, writer.buffered(), false);
    };
    const history = &ws.execs.history;
    // Cannot fail: as above.
    writer.print("{d} recent execs of {s}, oldest first (at most {d} are kept)\n", .{
        history.count, name, constants.exec_history_entries_max,
    }) catch unreachable;
    var cut = false;
    for (history.slice()) |*entry| {
        write_exec(&writer, entry) catch {
            cut = true;
            break;
        };
    }
    ws.add(file, why, writer.buffered(), cut);
}

fn write_exec(writer: *std.Io.Writer, entry: *const exec_history.Entry) std.Io.Writer.Error!void {
    assert(entry.ended >= entry.started);
    assert(entry.command_len > 0);
    var stamp: [constants.timestamp_bytes]u8 = undefined;
    try writer.print("{s}  {d}s  ", .{ timestamp(entry.started, &stamp), entry.ended - entry.started });
    switch (entry.exit) {
        .exited => |code| try writer.print("exited {d}", .{code}),
        .signaled => |number| try writer.print("signal {d}", .{number}),
        .lost => try writer.writeAll("lost"),
    }
    try writer.print("  {s}\n", .{entry.command_text()});
}

/// The names of the environment variables. The values are never copied: with redaction on each
/// shows as `[redacted:env]`; only `--no-redact` keeps them.
fn stage_environment(ws: *Workspace, host: Host) void {
    assert(ws.count < constants.bundle_files_max - 1);
    assert(ws.used >= manifest_bytes_max);
    var writer = std.Io.Writer.fixed(&ws.raw);
    var index: u32 = 0;
    var cut = false;
    while (index < constants.environment_entries_max) : (index += 1) {
        const entry = host.environment_at(index) orelse break;
        const value = if (ws.redact) "[redacted:env]" else entry.value;
        writer.print("{s}={s}\n", .{ entry.name, value }) catch {
            cut = true;
            break;
        };
    } else cut = true;
    const text = writer.buffered();
    const why = "the environment variables of zbx; values are redacted unless --no-redact";
    if (ws.redact) {
        ws.add_trusted("environment.txt", why, text, cut);
    } else {
        ws.add("environment.txt", why, text, cut);
    }
}

/// Secret-named variables whose values are scrubbed wherever they appear in the bundle.
fn collect_secrets(ws: *Workspace, host: Host) void {
    assert(ws.redact); // Without redaction nothing is scrubbed, so nothing is collected.
    assert(ws.secrets_count == 0);
    var index: u32 = 0;
    while (index < constants.environment_entries_max) : (index += 1) {
        const entry = host.environment_at(index) orelse break;
        if (redact.secret_kind(entry.name) == null) continue;
        if (entry.value.len < constants.secret_value_bytes_min) continue;
        if (entry.value.len > constants.secret_value_bytes_max) continue;
        if (ws.secrets_count == constants.bundle_secrets_max) break;
        ws.secrets[ws.secrets_count] = entry.value;
        ws.secrets_count += 1;
    }
}

/// `zbx doctor`, in-process, as JSON lines: each check, then the diagnostic of each failure.
fn stage_doctor(ws: *Workspace, host: Host) void {
    assert(ws.count < constants.bundle_files_max - 1);
    assert(ws.used >= manifest_bytes_max);
    var report: doctor.Report = undefined;
    doctor.inspect(host, &ws.facts, &report);
    var writer = std.Io.Writer.fixed(&ws.raw);
    var cut = false;
    for (&report.checks) |*check| {
        write_check(&writer, check) catch {
            cut = true;
            break;
        };
    }
    const why = "the host checks of `zbx doctor`, one JSON object per line";
    ws.add("doctor.json", why, writer.buffered(), cut);
}

fn write_check(writer: *std.Io.Writer, check: *const doctor.Check) std.Io.Writer.Error!void {
    assert(check.detail.len > 0);
    assert((check.status != .ok) == (check.diag.code != null));
    try writer.print("{{\"check\":\"{s}\",\"status\":\"{s}\",\"detail\":", .{
        @tagName(check.id), @tagName(check.status),
    });
    try write_json_string(writer, check.detail.slice());
    try writer.writeAll("}\n");
    if (check.status == .ok) return;
    var buffer: [constants.output_bytes_max]u8 = undefined;
    try writer.writeAll(render.render(&check.diag, .json, false, &buffer));
}

pub fn write_json_string(writer: *std.Io.Writer, text: []const u8) std.Io.Writer.Error!void {
    assert(writer.buffer.len > 0);
    assert(text.len <= constants.file_bytes_max);
    try writer.writeByte('"');
    for (text) |byte| {
        switch (byte) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            0x20...0x21, 0x23...0x5b, 0x5d...0x7e => try writer.writeByte(byte),
            else => try writer.print("\\u{x:0>4}", .{byte}),
        }
    }
    try writer.writeByte('"');
}

fn mapping_text(parsed: ?*const records.Parsed) []const u8 {
    if (parsed) |found| assert(found.name_len > 0);
    const found = parsed orelse return "unknown";
    const ids = found.ids orelse return "unknown";
    return switch (ids) {
        .single => "single",
        .full => "full",
    };
}

/// The run record and the diagnostic in it. Returns the mapping mode the record names.
fn stage_record(
    ws: *Workspace,
    host: Host,
    dir: *const records.Dir,
    name: []const u8,
    diag: *Diag,
) Error![]const u8 {
    assert(ws.count == 0);
    var path_storage: [constants.state_path_bytes_max + 80]u8 = undefined;
    const path = records.record_path(dir, name, &path_storage);
    const prefix = host.read_prefix(path, &ws.raw) catch |err| {
        if (err == error.NotFound) return no_record(diag, name, dir.text());
        var writer = std.Io.Writer.fixed(&ws.raw);
        // Cannot fail: a short line into a buffer of 32 KiB.
        writer.writeAll("unavailable: the run record could not be read\n") catch unreachable;
        ws.add_trusted("run-record.zon", "the run record (unreadable)", writer.buffered(), false);
        return "unknown";
    };
    var parsed: records.Parsed = undefined;
    const readable = !prefix.truncated and prefix.bytes.len > 0;
    const ok = readable and if (records.parse(prefix.bytes, &parsed)) true else |_| false;
    const why = "the run's record: name, rootfs, command, labels, times, how it ended";
    ws.add("run-record.zon", why, prefix.bytes, prefix.truncated);
    if (!ok) return "unknown";
    if (parsed.diagnostic_len > 0) {
        const note = "the diagnostic the run ended with, as `--output json` prints it";
        ws.add("diagnostic.json", note, parsed.diagnostic_slice(), false);
    }
    return mapping_text(&parsed);
}

// ---- The manifest --------------------------------------------------------------------------

fn write_manifest(ws: *Workspace, stem: []const u8, name: []const u8) void {
    const out = ws.stage[0..manifest_bytes_max];
    var writer = std.Io.Writer.fixed(out);
    // Cannot fail: eleven files with short lines are far below the manifest's 8 KiB; the
    // comptime check in this file proves it.
    write_manifest_text(&writer, ws, stem, name) catch unreachable;
    const text = writer.buffered();
    assert(text.len > 0);
    ws.manifest_len = @intCast(text.len);
}

fn write_manifest_text(
    writer: *std.Io.Writer,
    ws: *const Workspace,
    stem: []const u8,
    name: []const u8,
) std.Io.Writer.Error!void {
    assert(stem.len > name.len);
    assert(ws.count <= constants.bundle_files_max - 1);
    try writer.print("zbx diagnostic bundle {s}\n", .{stem});
    try writer.print("zbx {s}, run \"{s}\"\n\n", .{ build_options.version, name });
    if (ws.redact) {
        try writer.print(
            "redaction: on (values replaced: {d}, shown as [redacted:<kind>])\n",
            .{ws.redactions},
        );
        try writer.writeAll("  a net, not a proof: a secret with an innocent name can pass\n");
    } else {
        try writer.writeAll(
            "redaction: OFF (--no-redact): secrets are in this bundle as they were\n",
        );
    }
    try writer.writeAll("review every file before you share this bundle; zbx never uploads it\n\n");
    try writer.writeAll("files:\n");
    try writer.writeAll("  MANIFEST.txt\n    this list\n");
    for (ws.files[0..ws.count]) |*file| {
        try writer.print("  {s} ({d} bytes)\n    {s}\n", .{ file.name, file.len, file.why });
        if (file.cut) try writer.writeAll(
            "    cut at a bound: the source was longer than what is kept\n",
        );
        if (file.redactions > 0) try writer.print("    values redacted: {d}\n", .{file.redactions});
    }
}

comptime {
    // The manifest: a header of a few hundred bytes and, per file, a line of at most 160 and two
    // notes of 80.
    const per_file = 160 + 80 + 80;
    assert(1024 + constants.bundle_files_max * per_file < manifest_bytes_max);
}

// ---- Compression ---------------------------------------------------------------------------

const CompressError = error{TooBig};

/// The bundle as a gzip'd tar, in `ws.gz`. Every file is under a directory named `stem`.
fn compress(ws: *Workspace, stem: []const u8, now: u64) CompressError![]const u8 {
    var out = std.Io.Writer.fixed(&ws.gz);
    var gzip = flate.Compress.Huffman.init(&out, &ws.window, .gzip) catch return error.TooBig;
    var archive: std.tar.Writer = .{ .underlying_writer = &gzip.writer };
    const options: std.tar.Writer.Options = .{ .mode = 0o644, .mtime = now };
    archive.setRoot(stem) catch return error.TooBig;
    const manifest = ws.stage[0..ws.manifest_len];
    archive.writeFileBytes("MANIFEST.txt", manifest, options) catch return error.TooBig;
    for (ws.files[0..ws.count]) |*file| {
        archive.writeFileBytes(file.name, ws.content(file), options) catch return error.TooBig;
    }
    archive.finishPedantically() catch return error.TooBig;
    gzip.finish() catch return error.TooBig;
    const bytes = out.buffered();
    assert(bytes.len > 18); // A gzip header and footer.
    return bytes;
}

// ---- Saving --------------------------------------------------------------------------------

/// The bundles directory next to the runs directory: "<state>/zbx/bundles".
fn bundles_dir(runs: *const records.Dir) records.Dir {
    const suffix = "/runs";
    const text = runs.path[0..runs.len];
    assert(std.mem.endsWith(u8, text, suffix));
    var dir: records.Dir = undefined;
    const base = text[0 .. text.len - suffix.len];
    const joined = std.fmt.bufPrint(
        &dir.path,
        "{s}/{s}",
        .{ base, constants.bundles_dir_name },
    ) catch
        unreachable; // The runs path fits with "runs"; "bundles" is 2 bytes longer, and the
    // buffer has the state_path_bytes_max + 1 of the runs directory, whose path was bounded
    // by the suffix it carries.
    dir.len = @intCast(joined.len);
    dir.path[dir.len] = 0;
    dir.existing_len = runs.existing_len;
    assert(dir.existing_len <= dir.len);
    return dir;
}

fn save(
    host: Host,
    runs: *const records.Dir,
    stem: []const u8,
    bytes: []const u8,
    saved: *Saved,
    diag: *Diag,
) Error!void {
    assert(bytes.len <= constants.write_bytes_max);
    const dir = bundles_dir(runs);
    var final_storage: [constants.state_path_bytes_max + 128]u8 = undefined;
    var temporary_storage: [constants.state_path_bytes_max + 128]u8 = undefined;
    const base = dir.path[0..dir.len];
    const final = std.fmt.bufPrintSentinel(
        &final_storage,
        "{s}/{s}.tar.gz",
        .{ base, stem },
        0,
    ) catch
        return path_too_long(diag, base);
    const format = "{s}/.{s}.tar.gz.tmp";
    const temporary = std.fmt.bufPrintSentinel(&temporary_storage, format, .{ base, stem }, 0) catch
        return path_too_long(diag, base);
    records.ensure(host, &dir) catch |err| {
        return write_failed(diag, dir.text(), err, host.last_errno());
    };
    host.write_file(temporary, bytes) catch |err| {
        const errno = host.last_errno(); // Before the cleanup below changes it.
        host.remove_file(temporary) catch {}; // A partial file must not stay.
        return write_failed(diag, final, err, errno);
    };
    host.rename(temporary, final) catch |err| {
        const errno = host.last_errno();
        host.remove_file(temporary) catch {}; // Same.
        return write_failed(diag, final, err, errno);
    };
    @memcpy(saved.path[0..final.len], final);
    saved.len = @intCast(final.len);
}

// ---- The diagnostics -----------------------------------------------------------------------

fn no_state(diag: *Diag) Error {
    assert(diag.code == null);
    diag.raise(.E0701);
    diag.while_("looking for the state directory", .{});
    diag.cause("neither XDG_STATE_HOME nor HOME names an absolute directory", .{});
    diag.fix(.{ .sentence = "name one:", .command = "export XDG_STATE_HOME=$HOME/.local/state" });
    return error.BundleFailed;
}

fn no_record(diag: *Diag, name: []const u8, directory: []const u8) Error {
    assert(diag.code == null);
    assert(directory.len > 0);
    diag.raise(.E0703);
    diag.while_("looking for the run record", .{});
    diag.cause("there is no record of a run named '{s}' in {s}", .{ name, directory });
    diag.context("name", "{s}", .{name});
    diag.fix(.{ .sentence = "bundle the most recent run:", .command = "zbx bundle --last" });
    return error.BundleFailed;
}

fn no_runs(diag: *Diag, directory: []const u8) Error {
    assert(diag.code == null);
    assert(directory.len > 0);
    diag.raise(.E0704);
    diag.while_("looking for the most recent run", .{});
    diag.cause("there is no run record that can be read in {s}", .{directory});
    diag.fix(.{
        .sentence = "run something first:",
        .command = "zbx run --rootfs ./alpine -- /bin/sh",
    });
    return error.BundleFailed;
}

fn path_too_long(diag: *Diag, directory: []const u8) Error {
    assert(diag.code == null);
    assert(directory.len > 0);
    diag.raise(.E0702);
    diag.while_("choosing the bundle's file name", .{});
    diag.cause("the path under {s} is too long", .{directory});
    diag.fix(.{
        .sentence = "use a shorter state directory:",
        .command = "export XDG_STATE_HOME=$HOME/.zstate",
    });
    return error.BundleFailed;
}

fn write_failed(diag: *Diag, path: []const u8, err: host_mod.Error, errno: u16) Error {
    assert(diag.code == null);
    assert(path.len > 0);
    assert(errno < 4096);
    diag.raise(.E0702);
    diag.while_("saving the bundle", .{});
    diag_errors.cause_host_error(diag, "writing the bundle", err, errno);
    diag.context("path", "{s}", .{path});
    if (err == error.NoSpace) {
        diag.fix(.{
            .sentence = "free space on that disk, or use another:",
            .command = "export XDG_STATE_HOME=/path/with/room",
        });
    } else {
        diag.fix_with(
            "check that you can write there:",
            "ls -ld {s}",
            .{std.fs.path.dirname(path) orelse path},
        );
    }
    return error.BundleFailed;
}

fn too_big(diag: *Diag) Error {
    assert(diag.code == null);
    assert(constants.bundle_gz_bytes_max > constants.bundle_stage_bytes_max);
    diag.raise(.E0702);
    diag.while_("compressing the bundle", .{});
    diag.cause("the bundle does not fit in {d} bytes", .{constants.bundle_gz_bytes_max});
    diag.fix(.{ .sentence = "report this; the files are bounded, so it is a bug in zbx" });
    return error.BundleFailed;
}

/// `--no-redact` was given: a warning, not a failure.
pub fn unredacted_warning(diag: *Diag) void {
    assert(diag.code == null);
    defer assert(diag.entry().severity == .warning);
    diag.raise(.W0701);
    diag.while_("choosing what to keep in the bundle", .{});
    diag.cause("--no-redact keeps environment values and secrets in the bundle", .{});
    diag.fix(
        .{ .sentence = "read every file in it before you share it, or leave --no-redact out" },
    );
}

// ---- The entry points ----------------------------------------------------------------------

/// Writes a bundle for `request` and says where it went. The reason for a failure is in `diag`.
pub fn write(
    host: Host,
    ws: *Workspace,
    request: Request,
    saved: *Saved,
    diag: *Diag,
) Error!void {
    // An empty name is a user's mistake (`zbx bundle ""`), refused below as an unknown run.
    if (request.name) |name| assert(name.len <= constants.arg_bytes_max);
    assert(diag.code == null);
    var dir: records.Dir = undefined;
    if (!records.locate(host, &dir)) return no_state(diag);
    var name_storage: [constants.container_name_bytes_max]u8 = undefined;
    const name = request.name orelse blk: {
        const length = records.newest(host, &dir, &name_storage) orelse
            return no_runs(diag, dir.text());
        break :blk name_storage[0..length];
    };
    if (spec_mod.name_problem(name) != null) return no_record(diag, name, dir.text());
    ws.reset(request.redact);
    if (ws.redact) collect_secrets(ws, host);
    const mapping = try stage_record(ws, host, &dir, name, diag);
    stage_execs(ws, host, &dir, name);
    stage_system_files(ws, host, mapping);
    stage_environment(ws, host);
    stage_doctor(ws, host);
    const now = host.time_now();
    var stamp: [constants.timestamp_bytes]u8 = undefined;
    var stem_storage: [constants.bundle_name_bytes_max]u8 = undefined;
    const format = "{s}-{s}";
    // Cannot fail: a timestamp and a name of at most 63 bytes.
    const stem = std.fmt.bufPrint(&stem_storage, format, .{ timestamp(now, &stamp), name }) catch
        unreachable;
    write_manifest(ws, stem, name);
    const bytes = compress(ws, stem, now) catch return too_big(diag);
    try save(host, &dir, stem, bytes, saved, diag);
}

/// For a `bug` diagnostic from the run called `name`: writes a redacted bundle and puts its path
/// in the bug's `saved` line. A bundle that cannot be written leaves the bug as it was; the
/// bug is the news, not the bundle.
pub fn attach_to_bug(host: Host, ws: *Workspace, name: []const u8, bug: *Diag) void {
    assert(bug.code != null);
    assert(bug.entry().severity == .bug);
    var saved: Saved = undefined;
    var ignored: Diag = undefined;
    ignored.reset();
    write(host, ws, .{ .name = name, .redact = true }, &saved, &ignored) catch return;
    bug.save_bundle(saved.slice());
}

const spec_mod = @import("runtime/spec.zig");
