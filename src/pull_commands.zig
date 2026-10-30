//! `zbx pull`. `zbx pull --resolve-only <reference>` asks the registry what the reference names
//! for this machine's platform and prints the digest of that image's manifest (the digest a lock
//! file records), without fetching any layer. Text is the digest on a line; `--output json` is
//! one object (`zbx schema pull-resolve`).
//!
//! `zbx pull <reference>` goes on: it is a thin caller of the library's `pull.pull`
//! (`pull.zig`), which downloads the config and the layers into the store's blob cache (a cut
//! download resumes), unpacks the layers into one tree, imports it, and records the image. What
//! stays here is what belongs to the command line: the environment (`ZBX_REGISTRY_MIRRORS`,
//! `ZBX_PLATFORM`, `ZBX_PLATFORM_FALLBACK`), the project's `zbx.lock`, the rendering of warnings
//! and of the result. It prints the manifest digest (the same line as the resolve), or with
//! `--output json` the object `zbx.pull/1`.

const std = @import("std");
const assert = std.debug.assert;
const bundle = @import("bundle.zig");
const constants = @import("constants.zig");
const doctor = @import("doctor.zig");
const errors = @import("diag/errors.zig");
const fs_mod = @import("store/fs.zig");
const host_mod = @import("host.zig");
const image_diagnose = @import("image_diagnose.zig");
const images = @import("store/images.zig");
const import = @import("store/import.zig");
const lock_file = @import("lock_file.zig");
const manifest = @import("registry/manifest.zig");
const pull_lib = @import("pull.zig");
const reference_mod = @import("registry/reference.zig");
const render_diag = @import("diag/render.zig");
const Diag = @import("diag/diag.zig").Diag;
const Host = host_mod.Host;

pub const Error = error{ Failed, OutputFailed };

/// What the command line's pull works in: the library's memory, the text of the JSON result and
/// the project's lock.
pub const Workspace = struct {
    library: pull_lib.Workspace,
    output: [constants.pull_output_bytes_max]u8,
    /// The project's zbx.lock, read before the pull and updated after it.
    locking: lock_file.Workspace,
};

pub const Args = struct {
    reference: []const u8,
    json: bool,
};

/// How warnings are written, and whether the result is.
pub const Output = struct {
    mode: render_diag.Mode,
    color: bool,
    json: bool,
    /// The pull is a step of something else (a run that has no lock): its result is not printed.
    quiet: bool = false,
};

/// The request the command line makes: the reference as typed, the platform the macOS zbx sets
/// in the virtual machine and the mirrors, all read from the environment here and nowhere in the
/// library.
fn request_of(host: Host, text: []const u8) pull_lib.Request {
    assert(text.len <= constants.arg_bytes_max);
    const mirrors = host.environment("ZBX_REGISTRY_MIRRORS", constants.registry_mirrors_bytes_max);
    return .{
        .reference = text,
        .platform = platform_of(host),
        .mirrors = mirrors orelse "",
    };
}

/// `ZBX_PLATFORM` (`linux/amd64` or `linux/arm64`) replaces the machine's platform, and
/// `ZBX_PLATFORM_FALLBACK` names one to use when an image has none for it. The macOS zbx sets
/// them in the virtual machine (`--platform`, and Rosetta); a value that is not one of the two
/// is ignored, because nothing but zbx sets them.
fn platform_of(host: Host) pull_lib.Platform {
    const limit: u32 = 32;
    var platform: pull_lib.Platform = .{};
    if (host.environment("ZBX_PLATFORM", limit)) |text| {
        platform.architecture = manifest.architecture_of_platform(text);
    }
    if (host.environment("ZBX_PLATFORM_FALLBACK", limit)) |text| {
        platform.fallback = manifest.architecture_of_platform(text);
    }
    return platform;
}

pub fn run_resolve(host: Host, args: Args, workspace: *Workspace, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(args.reference.len <= constants.arg_bytes_max);
    assert(@sizeOf(Workspace) > constants.pull_output_bytes_max);
    const library = &workspace.library;
    pull_lib.resolve(host, &request_of(host, args.reference), library, diag) catch {
        return error.Failed;
    };
    const text = render(args.json, &library.reference, &library.resolved, &workspace.output);
    host.write_all(.stdout, text) catch |err| {
        errors.output_failed(diag, .stdout, err, host.last_errno());
        return error.OutputFailed;
    };
}

/// `zbx pull <reference>`: the library's pull between the lock's two steps. A lock that cannot
/// be read ends the pull before any work (a digest reference needs no lock); the lock is updated
/// when the image is in the store; then the result is written.
pub fn run_pull(
    host: Host,
    args: Args,
    output: Output,
    facts: *doctor.Facts,
    workspace: *Workspace,
    import_workspace: *import.Workspace,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    assert(args.reference.len <= constants.arg_bytes_max);
    const library = &workspace.library;
    pull_lib.parse_reference(library, args.reference, diag) catch return error.Failed;
    try check_lock(host, workspace, diag);
    var reporter: Reporter = .{ .host = host, .output = output };
    const progress: pull_lib.Progress = .{ .context = &reporter, .call = report_event };
    var result: pull_lib.Result = undefined;
    pull_lib.pull(
        host,
        facts,
        &request_of(host, args.reference),
        progress,
        library,
        import_workspace,
        &result,
        diag,
    ) catch return error.Failed;
    const locked = try record_in_lock(host, args.reference, workspace, &result, diag);
    if (output.quiet) return;
    const text = render_result(args.json, args.reference, workspace, &result, locked);
    host.write_all(.stdout, text) catch |err| {
        errors.output_failed(diag, .stdout, err, host.last_errno());
        return error.OutputFailed;
    };
}

const Reporter = struct {
    host: Host,
    output: Output,
};

/// The command line shows warnings, as they come, and nothing else of the pull's progress.
fn report_event(context: *anyopaque, event: pull_lib.Event) void {
    const reporter: *const Reporter = @ptrCast(@alignCast(context));
    const diag = switch (event) {
        .warning => |warning| warning,
        .resolved, .blob => return,
    };
    assert(diag.code != null);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const text = render_diag.render(diag, reporter.output.mode, reporter.output.color, &buffer);
    // A warning that cannot be written is lost, and the pull goes on: it is only a warning.
    reporter.host.write_all(.stderr, text) catch return;
}

/// Reads zbx.lock before any work, if the pull is going to record in it (a digest reference
/// needs no lock): a lock that can not be read ends the pull now.
fn check_lock(host: Host, workspace: *Workspace, diag: *Diag) Error!void {
    assert(workspace.library.reference.registry_len > 0);
    assert(diag.code == null);
    if (workspace.library.reference.digest != null) return;
    const locking = &workspace.locking;
    var failure: lock_file.Failure = undefined;
    lock_file.open_project(host, host.filesystem(), locking, &failure) catch {
        const path = if (locking.located.len > 0) locking.located.text() else lock_file.file_name;
        image_diagnose.lock_failure(diag, path, failure);
        return error.Failed;
    };
}

fn render(
    json: bool,
    reference: *const reference_mod.Reference,
    resolved: *const manifest.Resolved,
    buffer: *[constants.pull_output_bytes_max]u8,
) []const u8 {
    assert(resolved.layer_count <= constants.registry_layers_max);
    assert(buffer.len == constants.pull_output_bytes_max);
    var writer = std.Io.Writer.fixed(buffer);
    // Cannot fail: the buffer holds the largest result (128 layers, the constants assert it).
    if (json) write_json(&writer, reference, resolved) catch unreachable else {
        writer.print("{s}\n", .{&resolved.manifest_digest.text()}) catch unreachable; // Same.
    }
    const text = writer.buffered();
    assert(text.len > 0);
    assert(text[text.len - 1] == '\n');
    return text;
}

fn write_json(
    writer: *std.Io.Writer,
    reference: *const reference_mod.Reference,
    resolved: *const manifest.Resolved,
) std.Io.Writer.Error!void {
    assert(resolved.manifest_size > 0);
    assert(resolved.layer_count <= constants.registry_layers_max);
    var formatted: reference_mod.Formatted = undefined;

    const shown = reference.format(&formatted);
    try writer.print("{{\"schema\":\"zbx.pull.resolve/1\",\"reference\":\"{s}\",", .{shown});
    try writer.print("\"registry\":\"{s}\",", .{reference.registry()});
    try writer.print("\"repository\":\"{s}\",", .{reference.repository()});
    try writer.writeAll("\"index_digest\":");
    if (resolved.index_digest) |digest| {
        try writer.print("\"{s}\",", .{&digest.text()});
    } else {
        try writer.writeAll("null,");
    }
    const manifest_text = resolved.manifest_digest.text();
    try writer.print("\"manifest_digest\":\"{s}\",", .{&manifest_text});
    try writer.print("\"manifest_size\":{d},", .{resolved.manifest_size});
    try writer.print("\"platform\":\"linux/{s}\",", .{resolved.architecture.name()});
    const config_text = resolved.config_digest.text();
    try writer.print("\"config_digest\":\"{s}\",", .{&config_text});
    try writer.print("\"config_size\":{d},\"layers\":[", .{resolved.config_size});
    for (resolved.layers[0..resolved.layer_count], 0..) |layer, index| {
        if (index > 0) try writer.writeAll(",");
        const digest_text = layer.digest.text();
        const kind = @tagName(layer.kind);
        try writer.print("{{\"digest\":\"{s}\",\"size\":{d},", .{ &digest_text, layer.size });
        try writer.print("\"kind\":\"{s}\"}}", .{kind});
    }
    try writer.writeAll("]}\n");
}

/// Adds the image to zbx.lock (unless the reference was a digest, which needs none). Whether this
/// made the file, or null if the lock was not touched. The pull has already recorded the image in
/// the store, so a lock that cannot be written leaves the image there.
fn record_in_lock(
    host: Host,
    written: []const u8,
    workspace: *Workspace,
    result: *const pull_lib.Result,
    diag: *Diag,
) Error!?bool {
    assert(written.len > 0);
    assert(result.layer_count > 0);
    if (workspace.library.reference.digest != null) return null;
    const fs = host.filesystem();
    const locking = &workspace.locking;
    var failure: lock_file.Failure = undefined;
    lock_file.open_project(host, fs, locking, &failure) catch {
        const path = if (locking.located.len > 0) locking.located.text() else lock_file.file_name;
        image_diagnose.lock_failure(diag, path, failure);
        return error.Failed;
    };
    const existed = locking.located.exists;
    locking.lock.put(written, result.manifest_digest, result.platform(), result.tree) catch |err| {
        const too_long: fs_mod.Failure = .{ .err = error.FileTooLarge, .errno = 0 };
        failure = if (err == error.Full) .full else .{ .write = too_long };
        image_diagnose.lock_failure(diag, locking.located.text(), failure);
        return error.Failed;
    };
    lock_file.save(host, fs, locking, &failure) catch {
        image_diagnose.lock_failure(diag, locking.located.text(), failure);
        return error.Failed;
    };
    return !existed;
}

fn render_result(
    json: bool,
    written: []const u8,
    workspace: *Workspace,
    result: *const pull_lib.Result,
    locked: ?bool,
) []const u8 {
    assert(workspace.output.len == constants.pull_output_bytes_max);
    assert(result.layer_count > 0);
    const buffer = &workspace.output;
    var writer = std.Io.Writer.fixed(buffer);
    const resolved = &workspace.library.resolved;
    // Cannot fail: the buffer holds the largest result (128 layers, the constants assert it).
    if (!json) {
        writer.print("{s}\n", .{&resolved.manifest_digest.text()}) catch unreachable; // Sized.
        return writer.buffered();
    }
    write_pull_json(&writer, written, workspace, result, locked) catch unreachable; // Same bound.
    return writer.buffered();
}

fn write_pull_json(
    writer: *std.Io.Writer,
    written: []const u8,
    workspace: *const Workspace,
    result: *const pull_lib.Result,
    locked: ?bool,
) std.Io.Writer.Error!void {
    const library = &workspace.library;
    assert(library.resolved.layer_count <= constants.registry_layers_max);
    assert(result.layer_count == library.resolved.layer_count);
    const resolved = &library.resolved;
    const reference = &library.reference;
    try writer.writeAll("{\"schema\":\"zbx.pull/1\",\"reference\":");
    try bundle.write_json_string(writer, written);
    try writer.print(",\"registry\":\"{s}\",\"repository\":\"{s}\",", .{
        reference.registry(), reference.repository(),
    });
    try writer.print("\"manifest_digest\":\"{s}\",\"platform\":\"{s}\",", .{
        &resolved.manifest_digest.text(), result.platform(),
    });
    try writer.print("\"tree\":\"{s}\",\"config\":{{\"digest\":\"{s}\",\"cache\":\"{s}\"}},", .{
        result.tree.text(), &resolved.config_digest.text(), @tagName(library.fetched.config),
    });
    try writer.writeAll("\"layers\":[");
    for (resolved.layers[0..resolved.layer_count], 0..) |blob, index| {
        if (index > 0) try writer.writeAll(",");
        try writer.print("{{\"digest\":\"{s}\",\"size\":{d},\"cache\":\"{s}\"}}", .{
            &blob.digest.text(), blob.size, @tagName(library.fetched.layers[index]),
        });
    }
    const counts = result.counts;
    try writer.print("],\"files\":{d},\"directories\":{d},\"symlinks\":{d},\"bytes\":{d},", .{
        counts.files, counts.directories, counts.symlinks, counts.bytes,
    });
    try writer.print("\"special_skipped\":{d},\"xattrs_skipped\":{d},", .{
        counts.special_skipped, counts.xattrs_skipped,
    });
    try write_settings(writer, result.settings);
    try writer.writeAll(",\"lock\":");
    if (locked) |created| {
        try writer.writeAll("{\"path\":");
        try bundle.write_json_string(writer, workspace.locking.located.text());
        try writer.print(",\"created\":{}}}", .{created});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll("}\n");
}

/// The image's settings as the member "image": what it runs by default.
fn write_settings(
    writer: *std.Io.Writer,
    settings: *const images.Settings,
) std.Io.Writer.Error!void {
    assert(settings.count(.env) <= constants.env_vars_count_max);
    assert(settings.used <= settings.bytes.len);
    const json = bundle.write_json_string;
    try writer.writeAll("\"image\":{");
    inline for (.{ .entrypoint, .cmd }) |list| {
        try writer.print("\"{s}\":[", .{@tagName(list)});
        for (0..settings.count(list)) |index| {
            if (index > 0) try writer.writeAll(",");
            try json(writer, settings.word(list, @intCast(index)));
        }
        try writer.writeAll("],");
    }
    try writer.writeAll("\"env\":[");
    for (0..settings.count(.env)) |index| {
        if (index > 0) try writer.writeAll(",");
        try json(writer, settings.word(.env, @intCast(index)));
    }
    try writer.writeAll("],\"workdir\":");
    try json(writer, settings.get(.workdir));
    try writer.writeAll(",\"user\":");
    try json(writer, settings.get(.user));
    try writer.writeAll("}");
}
