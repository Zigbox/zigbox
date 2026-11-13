//! `zbx import`: reads a Dockerfile and its `.dockerignore`, translates them with
//! `zigbox.dockerfile.translate` and writes `zbx.build.zon` (docs/briefs/M9-dockerfile-import.md).
//! What stays here is what the library must not do: the reading, the pulls that pin each base
//! image in `zbx.lock`, the writing and the report. A refusal exits 1 and writes nothing, the
//! lock included: the lock is changed in memory while the translation runs and saved only once
//! the translation succeeded.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const doctor = @import("doctor.zig");
const errors = @import("diag/errors.zig");
const fs_mod = @import("store/fs.zig");
const host_mod = @import("host.zig");
const image_diagnose = @import("image_diagnose.zig");
const images = @import("store/images.zig");
const import = @import("store/import.zig");
const import_diagnose = @import("import_diagnose.zig");
const layout = @import("store/layout.zig");
const lock_file = @import("lock_file.zig");
const manifest = @import("registry/manifest.zig");
const pull_commands = @import("pull_commands.zig");
const pull_lib = @import("pull.zig");
const reference_mod = @import("registry/reference.zig");
const render_diag = @import("diag/render.zig");
const report_mod = @import("dockerfile/report.zig");
const store_diagnose = @import("store/diagnose.zig");
const translate = @import("dockerfile/translate.zig");
const Diag = @import("diag/diag.zig").Diag;
const Host = host_mod.Host;
const Store = layout.Store;

pub const Error = error{ Failed, OutputFailed };

pub const NetworkRule = translate.NetworkRule;

pub const dockerfile_default = "Dockerfile";
pub const output_default = "zbx.build.zon";

/// What `import` was given: every option, as typed. `build_args` are `NAME=VALUE`.
pub const Args = struct {
    dockerfile: ?[]const u8 = null,
    context: ?[]const u8 = null,
    target: ?[]const u8 = null,
    build_args: [constants.import_build_args_max][]const u8 = @splat(""),
    build_args_count: u32 = 0,
    network: translate.NetworkRule = .detect,
    hermetic: bool = false,
    output: ?[]const u8 = null,
    force: bool = false,
};

/// How the report and the warnings are written.
pub const Output = struct {
    mode: render_diag.Mode,
    color: bool,
    json: bool,
};

/// The memory an import works in; the caller's, and static: the translation's workspace is
/// large. The pulls use the pull command's workspace and the store's import workspace.
pub const Workspace = struct {
    translating: translate.Workspace,
    dockerfile: [constants.import_dockerfile_bytes_max + 1]u8,
    dockerignore: [constants.import_dockerignore_bytes_max + 1]u8,
    build_args: [constants.import_build_args_max]translate.BuildArg,
    pinning: Pinning,
    report: [constants.import_report_bytes_max]u8,
};

/// The resolver's state: what it pulls with, and whether it changed the lock.
const Pinning = struct {
    host: Host,
    facts: *doctor.Facts,
    store: *const Store,
    pulling: *pull_commands.Workspace,
    importing: *import.Workspace,
    diag: *Diag,
    image: images.Image,
    result: pull_lib.Result,
    env: [constants.env_vars_count_max][]const u8,
    changed: bool,
};

/// What the command line gives the import besides its arguments.
pub const Pulls = struct {
    facts: *doctor.Facts,
    pulling: *pull_commands.Workspace,
    importing: *import.Workspace,
};

const Path = [constants.path_bytes_max + 1]u8;

/// `zbx import`.
pub fn run(
    host: Host,
    args: *const Args,
    workspace: *Workspace,
    pulls: Pulls,
    output: Output,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    assert(args.build_args_count <= constants.import_build_args_max);
    const fs = host.filesystem();
    const dockerfile_name = args.dockerfile orelse dockerfile_default;
    var out_path: Path = undefined;
    const out_name = args.output orelse default_output(&out_path, args.context);
    if (!args.force) {
        if (exists(fs, out_name)) {
            import_diagnose.output_exists(diag, out_name);
            return error.Failed;
        }
    }
    const dockerfile = try read_input(fs, dockerfile_name, &workspace.dockerfile, diag, false);
    const dockerignore = try read_dockerignore(fs, args, dockerfile_name, workspace, diag);
    const locking = &pulls.pulling.locking;
    var lock_failed: lock_file.Failure = undefined;
    lock_file.open_project(host, fs, locking, &lock_failed) catch {
        const path = if (locking.located.len > 0) locking.located.text() else lock_file.file_name;
        image_diagnose.lock_failure(diag, path, lock_failed);
        return error.Failed;
    };
    var store: Store = undefined;
    if (!store.locate(host)) {
        store_diagnose.no_data_directory(diag);
        return error.Failed;
    }
    const pinning = &workspace.pinning;
    pinning.* = .{
        .host = host,
        .facts = pulls.facts,
        .store = &store,
        .pulling = pulls.pulling,
        .importing = pulls.importing,
        .diag = diag,
        .image = undefined,
        .result = undefined,
        .env = undefined,
        .changed = false,
    };
    defer pulls.pulling.aws.wipe();
    const options: translate.Options = .{
        .dockerfile = dockerfile,
        .dockerfile_name = dockerfile_name,
        .dockerignore = dockerignore,
        .build_args = split_build_args(args, &workspace.build_args),
        .target = args.target,
        .platform = try platform_of(host, diag),
        .network = args.network,
        .hermetic = args.hermetic,
        .resolver = .{ .context = pinning, .resolve = resolve },
    };
    const ws = &workspace.translating;
    const built = translate.translate(ws, &options) catch |err| {
        if (err == error.Refused) import_diagnose.refused(diag, &ws.refusal, dockerfile_name);
        assert(diag.code != null); // An unresolved reference raised its own.
        return error.Failed;
    };
    if (pinning.changed) try save_lock(host, fs, locking, diag);
    try write_output(host, fs, out_name, built, diag);
    try report(host, ws, out_name, workspace, output, diag);
}

/// `<context>/zbx.build.zon`, or the bare name for the working directory.
fn default_output(buffer: *Path, context: ?[]const u8) []const u8 {
    assert(buffer.len == constants.path_bytes_max + 1);
    assert(output_default.len > 0);
    const given = context orelse return output_default;
    const directory = std.mem.trimEnd(u8, given, "/");
    if (directory.len == 0) return "/" ++ output_default;
    return std.fmt.bufPrint(buffer, "{s}/{s}", .{ directory, output_default }) catch {
        return output_default; // A context too long for a path fails when it is read.
    };
}

fn exists(fs: fs_mod.Fs, path: []const u8) bool {
    var storage: Path = undefined;
    const text = terminated(&storage, path) orelse return false;
    _ = fs.lstat(text) catch return false;
    return true;
}

fn terminated(buffer: *Path, path: []const u8) ?[:0]const u8 {
    assert(path.len > 0);
    return std.fmt.bufPrintSentinel(buffer, "{s}", .{path}, 0) catch return null;
}

/// Reads a whole input file into `buffer` (one byte larger than the bound, so a file at the
/// bound is told from one past it). A `.dockerignore` that is not there is `missing_ok`.
fn read_input(
    fs: fs_mod.Fs,
    path: []const u8,
    buffer: []u8,
    diag: *Diag,
    missing_ok: bool,
) Error![]const u8 {
    assert(buffer.len > 1);
    var storage: Path = undefined;
    const text = terminated(&storage, path) orelse {
        import_diagnose.read_failed(diag, path, .bad_path);
        return error.Failed;
    };
    if (fs.read_whole(text, buffer)) |bytes| return bytes else |err| switch (err) {
        error.NotFound => {
            if (missing_ok) return buffer[0..0];
            import_diagnose.read_failed(diag, path, .missing);
        },
        error.FileTooLarge => import_diagnose.read_failed(diag, path, .too_large),
        else => import_diagnose.read_failed(diag, path, .unreadable),
    }
    return error.Failed;
}

/// `<Dockerfile>.dockerignore` if there, else `<context>/.dockerignore`, else nothing.
fn read_dockerignore(
    fs: fs_mod.Fs,
    args: *const Args,
    dockerfile_name: []const u8,
    workspace: *Workspace,
    diag: *Diag,
) Error![]const u8 {
    var beside: Path = undefined;
    const name = std.fmt.bufPrint(&beside, "{s}.dockerignore", .{dockerfile_name}) catch "";
    const buffer = &workspace.dockerignore;
    if (name.len > 0) {
        if (exists(fs, name)) return read_input(fs, name, buffer, diag, false);
    }
    var inside: Path = undefined;
    const directory = std.mem.trimEnd(u8, args.context orelse ".", "/");
    const second = std.fmt.bufPrint(&inside, "{s}/.dockerignore", .{directory}) catch return "";
    return read_input(fs, second, buffer, diag, true);
}

fn split_build_args(args: *const Args, storage: []translate.BuildArg) []const translate.BuildArg {
    assert(storage.len == constants.import_build_args_max);
    assert(args.build_args_count <= storage.len);
    for (args.build_args[0..args.build_args_count], 0..) |text, index| {
        const equals = std.mem.indexOfScalar(u8, text, '=') orelse text.len;
        const value = if (equals < text.len) text[equals + 1 ..] else "";
        storage[index] = .{ .name = text[0..equals], .value = value };
        assert(storage[index].name.len > 0); // The command line checked it.
    }
    return storage[0..args.build_args_count];
}

/// The host's platform: `ZBX_PLATFORM` as a pull reads it, else the machine's.
fn platform_of(host: Host, diag: *Diag) Error!translate.Platform {
    assert(diag.code == null);
    const set = pull_commands.platform_of(host);
    const architecture = set.architecture orelse found: {
        const uname = host.uname() catch {
            errors.output_failed(diag, .stderr, error.IoFailed, host.last_errno());
            return error.OutputFailed;
        };
        break :found manifest.architecture_of_machine(uname.machine.slice()) orelse .amd64;
    };
    return .{ .os = "linux", .architecture = architecture.name(), .variant = "" };
}

fn save_lock(host: Host, fs: fs_mod.Fs, locking: *lock_file.Workspace, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(locking.lock.count <= constants.lock_entries_max);
    var failure: lock_file.Failure = undefined;
    lock_file.save(host, fs, locking, &failure) catch {
        image_diagnose.lock_failure(diag, locking.located.text(), failure);
        return error.Failed;
    };
}

fn write_output(
    host: Host,
    fs: fs_mod.Fs,
    path: []const u8,
    bytes: []const u8,
    diag: *Diag,
) Error!void {
    assert(bytes.len > 0);
    var final_storage: Path = undefined;
    var temporary_storage: Path = undefined;
    var directory_storage: Path = undefined;
    const slash = std.mem.lastIndexOfScalar(u8, path, '/');
    const directory_text = if (slash) |at| (if (at == 0) "/" else path[0..at]) else ".";
    const final = terminated(&final_storage, path);
    const directory = terminated(&directory_storage, directory_text);
    const temporary = std.fmt.bufPrintSentinel(&temporary_storage, "{s}.{d}.tmp", .{
        path, host.own_pid(),
    }, 0) catch null;
    var failure: fs_mod.Failure = .{ .err = error.FileTooLarge, .errno = 0 };
    if (final != null and directory != null and temporary != null) {
        fs.write_atomic_stamped(
            temporary.?,
            final.?,
            directory.?,
            bytes,
            0o644,
            false,
            &failure,
        ) catch {
            import_diagnose.output_failed(diag, path, &failure);
            return error.Failed;
        };
        return;
    }
    import_diagnose.output_failed(diag, path, &failure);
    return error.Failed;
}

/// The report, then the two warnings. Text goes to stderr; `--output json` puts the document on
/// stdout and the warnings, as ever, on stderr.
fn report(
    host: Host,
    ws: *const translate.Workspace,
    out_name: []const u8,
    workspace: *Workspace,
    output: Output,
    diag: *Diag,
) Error!void {
    var writer = std.Io.Writer.fixed(&workspace.report);
    if (output.json) {
        report_mod.render_json(&ws.report, out_name, &writer) catch return too_large(diag);
        try emit(host, .stdout, writer.buffered(), diag);
    } else {
        report_mod.render_text(&ws.report, out_name, &writer) catch return too_large(diag);
        try emit(host, .stderr, writer.buffered(), diag);
    }
    var names: [constants.diag_field_bytes_max]u8 = undefined;
    var warning: Diag = undefined;
    warning.reset();
    const flagged = ws.report.flagged_count();
    if (flagged > 0) {
        import_diagnose.not_hermetic(&warning, flagged_names(&names, &ws.report), flagged);
        try warn(host, &warning, output, &workspace.report, diag);
    }
    const dropped = ws.report.dropped_count;
    if (dropped > 0) {
        warning.reset();
        import_diagnose.dropped(&warning, dropped_names(&names, &ws.report), dropped);
        try warn(host, &warning, output, &workspace.report, diag);
    }
}

fn too_large(diag: *Diag) Error {
    // The report buffer holds `import_report_bytes_max`, which the report's bounds fit in.
    errors.output_failed(diag, .stderr, error.NoSpace, 0);
    return error.OutputFailed;
}

fn emit(host: Host, comptime stream: host_mod.Stream, bytes: []const u8, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(bytes.len <= constants.import_report_bytes_max);
    host.write_all(stream, bytes) catch |err| {
        errors.output_failed(diag, stream, err, host.last_errno());
        return error.OutputFailed;
    };
}

fn warn(host: Host, warning: *const Diag, output: Output, buffer: []u8, diag: *Diag) Error!void {
    assert(buffer.len >= constants.output_bytes_max);
    const text = render_diag.render(warning, output.mode, output.color, buffer);
    try emit(host, .stderr, text, diag);
}

/// Words joined by `, ` into `buffer`, with `...` where the room ends.
const Joined = struct {
    buffer: []u8,
    len: u32 = 0,
    full: bool = false,

    fn add(joined: *Joined, parts: []const []const u8) void {
        if (joined.full) return;
        var needed: usize = if (joined.len > 0) 2 else 0;
        for (parts) |part| needed += part.len;
        if (joined.len + needed + 3 > joined.buffer.len) {
            joined.full = true;
            @memcpy(joined.buffer[joined.len..][0..3], "...");
            joined.len += 3;
            return;
        }
        if (joined.len > 0) {
            @memcpy(joined.buffer[joined.len..][0..2], ", ");
            joined.len += 2;
        }
        for (parts) |part| {
            @memcpy(joined.buffer[joined.len..][0..part.len], part);
            joined.len += @intCast(part.len);
        }
    }

    fn text(joined: *const Joined) []const u8 {
        assert(joined.len <= joined.buffer.len);
        return joined.buffer[0..joined.len];
    }
};

fn flagged_names(buffer: []u8, report_of: *const report_mod.Report) []const u8 {
    var joined: Joined = .{ .buffer = buffer };
    for (report_of.steps_slice()) |*step| {
        if (!step.flagged()) continue;
        const net = step.network orelse "";
        const net_why = if (step.matched) "net, matched " else "net, ";
        const why = if (step.network != null) net_why else "";
        const cache = if (step.cache) (if (step.network != null) ", cache" else "cache") else "";
        const bind = if (step.bind) ", bind" else "";
        joined.add(&.{ step.name_text(), " (", why, net, cache, bind, ")" });
    }
    assert(joined.len > 0);
    return joined.text();
}

fn dropped_names(buffer: []u8, report_of: *const report_mod.Report) []const u8 {
    var joined: Joined = .{ .buffer = buffer };
    for (report_of.dropped_slice()) |*dropped| {
        var line: [12]u8 = undefined;
        const at = std.fmt.bufPrint(&line, ":{d} ", .{dropped.line}) catch unreachable; // Fits.
        joined.add(&.{ dropped.what_text(), at, "(", dropped.became_text(), ")" });
    }
    assert(joined.len > 0);
    return joined.text();
}

/// The translation's resolver: the image's env and workdir, from the lock and the store, or
/// from a pull that pins the reference.
fn resolve(context: *anyopaque, reference: []const u8) error{Unresolved}!translate.ImageFacts {
    const pinning: *Pinning = @ptrCast(@alignCast(context));
    assert(pinning.diag.code == null);
    const settings = settings_of(pinning, reference) catch return error.Unresolved;
    const count = settings.count(.env);
    assert(count <= pinning.env.len);
    for (0..count) |index| pinning.env[index] = settings.word(.env, @intCast(index));
    return .{ .env = pinning.env[0..count], .workdir = settings.get(.workdir) };
}

fn settings_of(pinning: *Pinning, reference: []const u8) error{Failed}!*const images.Settings {
    const lock = &pinning.pulling.locking.lock;
    if (lock.find(reference)) |at| {
        const entry = &lock.entries[at];
        var errno: u16 = 0;
        const image = &pinning.image;
        images.load(pinning.store, entry.manifest, image, &errno) catch |first| {
            if (first != error.NotFound) return unreadable(pinning, errno);
            try pull_locked(pinning, reference, entry);
            images.load(pinning.store, entry.manifest, image, &errno) catch |err| {
                if (err != error.NotFound) return unreadable(pinning, errno);
                image_diagnose.lock_failure(pinning.diag, lock_file.file_name, .unreadable);
                return error.Failed;
            };
        };
        return &image.settings;
    }
    return pull_new(pinning, reference);
}

fn unreadable(pinning: *Pinning, errno: u16) error{Failed} {
    const operation = "reading the base image's record";
    store_diagnose.write_failed(pinning.diag, pinning.store, operation, error.IoFailed, errno);
    return error.Failed;
}

/// An image the lock names and the store lacks, by its locked manifest digest.
fn pull_locked(
    pinning: *Pinning,
    reference: []const u8,
    entry: *const lock_file.Entry,
) error{Failed}!void {
    const library = &pinning.pulling.library;
    pull_lib.parse_reference(library, reference, pinning.diag) catch return error.Failed;
    var text: [constants.reference_bytes_max]u8 = undefined;
    const by_digest = std.fmt.bufPrint(&text, "{s}/{s}@{s}", .{
        library.reference.registry(), library.reference.repository(), &entry.manifest.text(),
    }) catch {
        image_diagnose.lock_failure(pinning.diag, lock_file.file_name, .unreadable);
        return error.Failed;
    };
    const mirrors = pinning.host.environment(
        "ZBX_REGISTRY_MIRRORS",
        constants.registry_mirrors_bytes_max,
    );
    const request: pull_lib.Request = .{
        .reference = by_digest,
        .platform = .{ .architecture = manifest.architecture_of_platform(entry.platform_text()) },
        .mirrors = mirrors orelse "",
    };
    pull_lib.pull(
        pinning.host,
        pinning.facts,
        &request,
        null,
        library,
        pinning.importing,
        &pinning.result,
        pinning.diag,
    ) catch return error.Failed;
}

/// An image the lock does not name: pulled as `zbx pull` would, and pinned in the lock in
/// memory; the file is written when the translation succeeds.
fn pull_new(pinning: *Pinning, reference: []const u8) error{Failed}!*const images.Settings {
    const library = &pinning.pulling.library;
    const diag = pinning.diag;
    pull_lib.parse_reference(library, reference, diag) catch return error.Failed;
    const request = pull_commands.request_of(
        pinning.host,
        reference,
        pinning.pulling,
        diag,
    ) catch return error.Failed;
    pull_lib.pull(
        pinning.host,
        pinning.facts,
        &request,
        null,
        library,
        pinning.importing,
        &pinning.result,
        diag,
    ) catch return error.Failed;
    const result = &pinning.result;
    const lock = &pinning.pulling.locking.lock;
    lock.put(reference, result.manifest_digest, result.platform(), result.tree) catch {
        image_diagnose.lock_failure(diag, pinning.pulling.locking.located.text(), .full);
        return error.Failed;
    };
    pinning.changed = true;
    return result.settings;
}

comptime {
    assert(@sizeOf(reference_mod.Reference) > 0);
}
