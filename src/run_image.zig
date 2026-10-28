//! `zbx run <name>`: what a name means, and what the image it names runs. The name is a tag or a
//! digest reference, not a tree digest (the cli decides that by its shape).
//!
//!   - A digest reference (`alpine@sha256:...`) needs no lock: the store's record of that manifest.
//!   - A tag is looked up in `zbx.lock`. The lock's entry is checked against the store: the
//!     record of the locked manifest must exist (`E0520`) and must have the locked tree
//!     (`E0519`). Both refusals name the digests; neither pulls.
//!   - Without any `zbx.lock` the image is pulled, the lock is written next to the working
//!     directory, and a warning says so (`W0503`). With a lock that lacks the name: `E0522`.
//!
//! Then the image's settings become what the container is started with, as Docker does: the
//! entrypoint, then the command (the words after `--` replace the image's cmd), the image's
//! environment, its working directory, and its user resolved against its own files.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const doctor = @import("doctor.zig");
const host_mod = @import("host.zig");
const image_diagnose = @import("image_diagnose.zig");
const image_find = @import("store/image_find.zig");
const image_user = @import("image_user.zig");
const images = @import("store/images.zig");
const import = @import("store/import.zig");
const lock_file = @import("lock_file.zig");
const namespace = @import("store/namespace.zig");
const open = @import("store/open.zig");
const pull_commands = @import("pull_commands.zig");
const reference_mod = @import("registry/reference.zig");
const registry_diagnose = @import("registry/diagnose.zig");
const spec = @import("runtime/spec.zig");
const store_diagnose = @import("store/diagnose.zig");
const Diag = @import("diag/diag.zig").Diag;
const Digest = @import("store/digest.zig").Digest;
const Host = host_mod.Host;
const Sha256 = @import("registry/digest.zig").Sha256;
const Store = @import("store/layout.zig").Store;

pub const Error = error{
    /// The reason is in the diagnostic.
    Failed,
    /// A pull the run started failed in the store's child, which wrote its own diagnostic.
    PullFailed,
};

/// The caller's memory, about 1.1 MiB beyond the pull's: keep it in static storage.
pub const Workspace = struct {
    memory: image_find.Memory,
    image: images.Image,
    user: image_user.Workspace,
    words: [constants.command_words_count_max][]const u8,
    env: [constants.env_vars_count_max]spec.Label,
    tree: [constants.store_digest_text_bytes]u8,
    home: [image_user.home_bytes_max + 5]u8,
};

/// What the services of a run have: the host, the memory of a pull, and where a warning goes.
pub const Services = struct {
    host: Host,
    facts: *doctor.Facts,
    pull: *pull_commands.Workspace,
    import_workspace: *import.Workspace,
    output: pull_commands.Output,
    warn: ?namespace.Warn,
};

/// What the container is started with.
pub const Prepared = struct {
    /// The tree to run on, "b3:" and 64 hex digits.
    tree: []const u8,
    command: []const []const u8,
    env: []const spec.Label,
    workdir: []const u8,
    user: ?spec.User,
};

const Record = enum { ok, absent, unreadable };

fn load_record(
    store: *const Store,
    present: bool,
    manifest: Sha256,
    ws: *Workspace,
    diag: *Diag,
) Error!Record {
    assert(diag.code == null);
    if (!present) return .absent;
    var errno: u16 = 0;
    images.load(store, manifest, &ws.image, &errno) catch |err| switch (err) {
        error.NotFound => return .absent,
        else => {
            const cause = if (err == error.Unreadable) error.IoFailed else error.FileTooLarge;
            store_diagnose.cannot_read(diag, store, "reading the image record", cause, errno);
            return error.Failed;
        },
    };
    return .ok;
}

/// Finds the image `operand` names and prepares what the container is started with.
pub fn prepare(
    services: *const Services,
    ws: *Workspace,
    operand: []const u8,
    given: []const []const u8,
    out: *Prepared,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    assert(operand.len > 0);
    assert(operand.len <= constants.arg_bytes_max);
    var store: Store = undefined;
    if (!store.locate(services.host)) {
        store_diagnose.no_data_directory(diag);
        return error.Failed;
    }
    const present = open.check(&store, .existing, diag) catch return error.Failed;
    var reference: reference_mod.Reference = undefined;
    reference_mod.parse(operand, &reference) catch |err| {
        registry_diagnose.bad_reference(diag, operand, err);
        return error.Failed;
    };
    if (reference.digest) |manifest| {
        const found = try load_record(&store, present, manifest, ws, diag);
        if (found != .ok) {
            image_diagnose.not_locked(diag, operand, null);
            return error.Failed;
        }
    } else {
        try via_lock(services, ws, &store, present, operand, &reference, diag);
    }
    try compose(&store, ws, given, out, diag);
}

fn via_lock(
    services: *const Services,
    ws: *Workspace,
    store: *Store,
    present: bool,
    operand: []const u8,
    reference: *const reference_mod.Reference,
    diag: *Diag,
) Error!void {
    assert(reference.digest == null);
    const locking = &services.pull.unpack.locking;
    var failure: lock_file.Failure = undefined;
    lock_file.open_project(services.host, store.fs, locking, &failure) catch {
        image_diagnose.lock_failure(diag, located_path(locking), failure);
        return error.Failed;
    };
    var made = false;
    if (!locking.located.exists) {
        try pull_without_lock(services, operand, diag);
        lock_file.open_project(services.host, store.fs, locking, &failure) catch {
            image_diagnose.lock_failure(diag, located_path(locking), failure);
            return error.Failed;
        };
        made = true;
    }
    const path = located_path(locking);
    const index = locking.lock.find(operand) orelse {
        image_diagnose.not_locked(diag, operand, path);
        return error.Failed;
    };
    const entry = locking.lock.entries[index];
    const now_present = present or made;
    const found = try load_record(store, now_present, entry.manifest, ws, diag);
    if (found != .ok) {
        try report_absent(store, ws, operand, path, entry.manifest, reference, diag);
        return error.Failed;
    }
    if (!ws.image.tree.eql(entry.tree)) {
        image_diagnose.lock_mismatch(diag, operand, path, entry.tree, ws.image.tree);
        return error.Failed;
    }
    if (made) warn_created(services, operand, path);
}

fn located_path(locking: *const lock_file.Workspace) []const u8 {
    assert(locking.located.len <= constants.path_bytes_max);
    if (locking.located.len == 0) return lock_file.file_name;
    return locking.located.text();
}

/// The lock names a manifest the store does not have; says what it does have under the name.
fn report_absent(
    store: *const Store,
    ws: *Workspace,
    operand: []const u8,
    path: []const u8,
    wanted: Sha256,
    reference: *const reference_mod.Reference,
    diag: *Diag,
) Error!void {
    assert(operand.len > 0);
    var by: image_find.ByReference = .{ .text = operand };
    image_find.scan(store, &ws.memory, &ws.image, &by) catch {};
    var pull_text: [constants.reference_bytes_max + 80]u8 = undefined;
    const by_digest = std.fmt.bufPrint(&pull_text, "{s}/{s}@{s}", .{
        reference.registry(), reference.repository(), &wanted.text(),
    }) catch operand;
    image_diagnose.locked_absent(
        diag,
        operand,
        path,
        wanted,
        if (by.found) by.manifest else null,
        by_digest,
    );
}

fn pull_without_lock(services: *const Services, operand: []const u8, diag: *Diag) Error!void {
    assert(operand.len > 0);
    var quiet = services.output;
    quiet.quiet = true;
    const args: pull_commands.Args = .{ .reference = operand, .json = false };
    const code = pull_commands.run_pull(
        services.host,
        args,
        quiet,
        services.facts,
        services.pull,
        services.import_workspace,
        diag,
    ) catch return error.Failed;
    if (code != constants.exit_ok) return error.PullFailed;
}

fn warn_created(services: *const Services, operand: []const u8, path: []const u8) void {
    assert(path.len > 0);
    const warn = services.warn orelse return;
    var warning: Diag = undefined;
    warning.reset();
    image_diagnose.lock_created(&warning, operand, path);
    warn.call(warn.context, &warning);
}

// ---- What the image runs -------------------------------------------------------------------

fn compose(
    store: *const Store,
    ws: *Workspace,
    given: []const []const u8,
    out: *Prepared,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    const image = &ws.image;
    const settings = &image.settings;
    ws.tree = image.tree.text();
    out.tree = &ws.tree;
    var count: usize = 0;
    for (0..settings.count(.entrypoint)) |index| {
        if (count == ws.words.len) return too_many_words(image, diag);
        ws.words[count] = settings.word(.entrypoint, @intCast(index));
        count += 1;
    }
    if (given.len > 0) {
        for (given) |word| {
            if (count == ws.words.len) return too_many_words(image, diag);
            ws.words[count] = word;
            count += 1;
        }
    } else {
        for (0..settings.count(.cmd)) |index| {
            if (count == ws.words.len) return too_many_words(image, diag);
            ws.words[count] = settings.word(.cmd, @intCast(index));
            count += 1;
        }
    }
    if (count == 0) {
        image_diagnose.no_command(diag, image.reference_text());
        return error.Failed;
    }
    out.command = ws.words[0..count];
    const workdir = settings.get(.workdir);
    if (spec.workdir_problem(workdir) or (workdir.len > 0 and workdir[0] != '/')) {
        image_diagnose.config_refused(
            diag,
            image.config,
            "has a working directory that is not an absolute path",
        );
        return error.Failed;
    }
    out.workdir = workdir;
    out.user = null;
    var home: ?[]const u8 = null;
    if (settings.get(.user).len > 0) {
        const resolved = try image_user.resolve(
            store,
            &ws.user,
            image.tree,
            settings.get(.user),
            diag,
        );
        if (resolved.user.uid != 0 or resolved.user.gid != 0) {
            out.user = resolved.user;
            const copy = resolved.home_text();
            @memcpy(ws.home[0..copy.len], copy);
            home = ws.home[0..copy.len];
        }
    }
    try environment(ws, home, out, diag);
}

fn too_many_words(image: *const images.Image, diag: *Diag) Error {
    assert(diag.code == null);
    image_diagnose.config_refused(
        diag,
        image.config,
        "gives a command of more words than a container can be started with",
    );
    return error.Failed;
}

/// The image's variables as labels, with HOME of the user the image runs as, unless it sets one.
fn environment(ws: *Workspace, home: ?[]const u8, out: *Prepared, diag: *Diag) Error!void {
    assert(ws.image.settings.used <= ws.image.settings.bytes.len);
    const settings = &ws.image.settings;
    var count: usize = 0;
    var has_home = false;
    for (0..settings.count(.env)) |index| {
        const variable = settings.word(.env, @intCast(index));
        const equals = std.mem.indexOfScalar(u8, variable, '=') orelse {
            image_diagnose.config_refused(
                diag,
                ws.image.config,
                "has an environment entry that is not NAME=value",
            );
            return error.Failed;
        };
        if (count == ws.env.len) {
            image_diagnose.config_refused(
                diag,
                ws.image.config,
                "has more environment variables than a container can be started with",
            );
            return error.Failed;
        }
        ws.env[count] = .{ .key = variable[0..equals], .value = variable[equals + 1 ..] };
        if (std.mem.eql(u8, ws.env[count].key, "HOME")) has_home = true;
        count += 1;
    }
    if (home != null and !has_home and count < ws.env.len) {
        ws.env[count] = .{ .key = "HOME", .value = home.? };
        count += 1;
    }
    out.env = ws.env[0..count];
}
