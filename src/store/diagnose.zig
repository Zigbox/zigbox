//! The store's diagnostics, in one place: each function raises one registered code and fills in
//! the causes, context and fixes (DIAGNOSTICS.md). The store code below this file reports
//! failures as plain Zig errors plus the facts; nothing under `store/` formats text for a user.
//!
//! A path from the user's tree is shown as the diagnostic collector sanitises it (non-printable
//! bytes become '?'), and is offered in a runnable fix only when it needs no quoting.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const errors = @import("../diag/errors.zig");
const host_mod = @import("../host.zig");
const text_util = @import("../text.zig");
const Diag = @import("../diag/diag.zig").Diag;
const digest_mod = @import("digest.zig");
const layout = @import("layout.zig");

const Digest = digest_mod.Digest;

/// True if a path can go inside single quotes in a command exactly as it is.
fn quotable(path: []const u8) bool {
    assert(path.len <= constants.file_bytes_max);
    if (path.len == 0) return false;
    for (path) |byte| {
        if (byte == '\'' or !text_util.is_printable(byte)) return false;
    }
    assert(std.mem.indexOfScalar(u8, path, '\'') == null);
    return true;
}

fn echo_of(storage: *[constants.arg_echo_bytes_max]u8, argument: []const u8) []const u8 {
    assert(argument.len <= constants.file_bytes_max);
    assert(storage.len == constants.arg_echo_bytes_max);
    return text_util.sanitise(storage, argument);
}

/// ZBX-E0421: neither XDG_DATA_HOME nor HOME gives a place for the store.
pub fn no_data_directory(diag: *Diag) void {
    assert(diag.code == null);
    diag.raise(.E0421);
    diag.while_("finding the store", .{});
    diag.cause("neither XDG_DATA_HOME nor HOME names an absolute directory to keep it in", .{});
    diag.fix(.{ .sentence = "name one:", .command = "export XDG_DATA_HOME=$HOME/.local/share" });
    assert(diag.fixes.count > 0);
}

/// ZBX-E0412: the text is not a digest or a usable prefix of one.
pub fn bad_digest(diag: *Diag, text: []const u8) void {
    assert(text.len <= constants.file_bytes_max);
    assert(diag.code == null);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, text);
    diag.raise(.E0412);
    diag.while_("reading a digest", .{});
    if (std.mem.startsWith(u8, text, "b3:") or text.len < constants.store_digest_text_bytes) {
        diag.cause(
            "'{s}' is not 12 to 64 lowercase hex digits (with or without b3:)",
            .{echo},
        );
    } else {
        diag.cause("'{s}' is longer than a digest: b3: and 64 lowercase hex digits", .{echo});
    }
    diag.context("arg", "{s}", .{echo});
    diag.fix(.{ .sentence = "list the digests the store keeps:", .command = "zbx store ls" });
}

/// ZBX-E0410: the store has no tree that starts like this.
pub fn unknown_digest(diag: *Diag, text: []const u8) void {
    assert(text.len <= constants.file_bytes_max);
    assert(diag.code == null);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, text);
    diag.raise(.E0410);
    diag.while_("looking for a tree in the store", .{});
    diag.cause("no tree in the store has a digest that starts with '{s}'", .{echo});
    diag.context("arg", "{s}", .{echo});
    diag.fix(.{ .sentence = "list the trees the store keeps:", .command = "zbx store ls" });
}

/// ZBX-E0411: the prefix names several trees; two of them are shown.
pub fn ambiguous_digest(diag: *Diag, text: []const u8, first: Digest, second: Digest) void {
    assert(diag.code == null);
    assert(!first.eql(second));
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, text);
    diag.raise(.E0411);
    diag.while_("looking for a tree in the store", .{});
    diag.cause("'{s}' starts the digests of more than one tree, for example", .{echo});
    diag.cause("{s} and {s}", .{ first.text(), second.text() });
    diag.context("arg", "{s}", .{echo});
    diag.fix(
        .{ .sentence = "give more digits, or the whole digest from:", .command = "zbx store ls" },
    );
}

/// ZBX-E0413: `store.zon` cannot be used.
pub fn format_unusable(diag: *Diag, store: *const layout.Store, format: layout.Format) void {
    assert(diag.code == null);
    assert(format != .ok);
    assert(format != .absent);
    diag.raise(.E0413);
    diag.while_("opening the store", .{});
    switch (format) {
        .too_new => |version| diag.cause(
            "the store's format is version {d}; this zbx reads up to {d}",
            .{ version, constants.store_format_version },
        ),
        .unreadable => |errno| if (errno == 0) {
            diag.cause("store.zon is not a format file zbx wrote", .{});
        } else {
            diag.cause("store.zon cannot be read (errno {d})", .{errno});
        },
        .ok, .absent => unreachable, // Asserted above.
    }
    diag.context("path", "{s}", .{store.root_text()});
    if (quotable(store.root_text())) {
        diag.fix_with(
            "use the zbx that wrote it, or set the store aside to start a new one:",
            "mv '{s}' '{s}.old'",
            .{ store.root_text(), store.root_text() },
        );
    } else {
        diag.fix(
            .{ .sentence = "use the zbx that wrote it, or set the store aside to start a new one" },
        );
    }
}

/// What was wrong with the directory to import.
pub const SourceFault = union(enum) {
    /// The kernel refused a call on the path.
    failed: struct { err: host_mod.Error, errno: u16 },
    /// The top path is not a directory.
    not_directory,
    /// The top path is a symlink; the store reads directories, and does not follow the link.
    symlink,
};

/// ZBX-E0414: the source cannot be read.
pub fn source_unreadable(
    diag: *Diag,
    path: []const u8,
    operation: []const u8,
    fault: SourceFault,
) void {
    assert(path.len > 0);
    assert(diag.code == null);
    diag.raise(.E0414);
    diag.while_("reading the directory to import", .{});
    switch (fault) {
        .not_directory => diag.cause("'{s}' is not a directory", .{path}),
        .symlink => diag.cause(
            "'{s}' is a symlink; import the directory it points to, not the link",
            .{path},
        ),
        .failed => |failed| {
            var what: [constants.path_bytes_max + 32]u8 = undefined;
            const operation_text = std.fmt.bufPrint(&what, "{s} {s}", .{ operation, path }) catch
                operation; // A path over the bound is cut by the diagnostic anyway.
            errors.cause_host_error(diag, operation_text, failed.err, failed.errno);
            switch (failed.err) {
                error.NotFound => diag.cause("'{s}' does not exist", .{path}),
                error.AccessDenied => diag.cause(
                    "you cannot read '{s}': permission denied (or its owner is not mapped)",
                    .{path},
                ),
                else => {},
            }
        },
    }
    diag.context("path", "{s}", .{path});
    if (quotable(path)) {
        diag.fix_with("look at it:", "ls -ld -- '{s}'", .{path});
    } else {
        diag.fix(.{ .sentence = "check the path and its permissions" });
    }
}

/// Which import limit was passed.
pub const Limit = enum {
    entries,
    name,
    depth,
    target,
    file_size,
    arena,
    tree_bytes,
    xattrs,
    path,

    fn words(limit: Limit) []const u8 {
        assert(@tagName(limit).len > 0);
        assert(@tagName(limit).len < 16);
        return switch (limit) {
            .entries => "has more than 16384 entries",
            .name => "has a name longer than 255 bytes",
            .depth => "is nested more than 64 levels deep",
            .target => "is a symlink with a target longer than 4095 bytes",
            .file_size => "is a file larger than 4 GiB",
            .arena => "needs more working memory than the 16 MiB an import has",
            .tree_bytes => "has entries that encode to more than 4 MiB",
            .xattrs => "has attributes that do not fit",
            .path => "is longer than 4095 bytes once a name is added",
        };
    }
};

/// ZBX-E0415: a limit of the import.
pub fn too_big(diag: *Diag, limit: Limit, path: []const u8) void {
    assert(path.len > 0);
    assert(diag.code == null);
    diag.raise(.E0415);
    diag.while_("importing the directory", .{});
    // A path that is itself the problem can be 4000 bytes long: show its end.
    const shown_max = 80;
    if (path.len > shown_max) {
        diag.cause("'...{s}' {s}", .{ path[path.len - shown_max ..], limit.words() });
    } else {
        diag.cause("'{s}' {s}", .{ path, limit.words() });
    }
    diag.context("path", "{s}", .{path});
    diag.fix(
        .{ .sentence = "split the directory, or leave out what the root filesystem does not need" },
    );
}

/// ZBX-E0416 for a full disk and ZBX-E0417 for any other write failure. `written` is what this
/// process had put in the store before the failure.
pub fn write_failed(
    diag: *Diag,
    store: *const layout.Store,
    operation: []const u8,
    err: host_mod.Error,
    errno: u16,
) void {
    assert(operation.len > 0);
    assert(diag.code == null);
    const full = err == error.NoSpace;
    diag.raise(if (full) .E0416 else .E0417);
    diag.while_("writing the store", .{});
    errors.cause_host_error(diag, operation, err, errno);
    if (full) {
        diag.cause(
            "{d} objects ({d} bytes) were written before the disk filled; they are whole and kept",
            .{ store.objects_written, store.bytes_written },
        );
    }
    diag.context("path", "{s}", .{store.root_text()});
    if (full) {
        diag.fix_with(
            "free space on the disk that holds the store, then run the same command again:",
            "df -h '{s}'",
            .{store.root_text()},
        );
    } else {
        diag.fix(
            .{
                .sentence = "check that you can write to the store directory, and the disk",
            },
        );
    }
}

/// ZBX-E0418: a file's two reads disagreed.
pub fn changed_while_importing(diag: *Diag, path: []const u8) void {
    assert(path.len > 0);
    assert(diag.code == null);
    diag.raise(.E0418);
    diag.while_("importing the directory", .{});
    diag.cause("'{s}' was written to between zbx's two reads of it", .{path});
    diag.context("path", "{s}", .{path});
    diag.fix(
        .{
            .sentence = "stop what writes to the directory, or import a copy, then run it again",
        },
    );
}

/// What went wrong with the worker process.
pub const WorkerFault = union(enum) {
    /// The child was killed by this signal.
    signaled: u8,
    /// A step of creating it failed.
    step: struct { name: []const u8, err: host_mod.Error, errno: u16 },
    /// `newuidmap` or `newgidmap` refused the map.
    helper: struct { name: []const u8, status: host_mod.ExitStatus, output: []const u8 },
};

/// ZBX-E0419: the child that does the store's work did not finish.
pub fn worker_ended(diag: *Diag, fault: WorkerFault) void {
    assert(diag.fixes.count == 0);
    assert(diag.code == null);
    diag.raise(.E0419);
    diag.while_("starting the store worker", .{});
    switch (fault) {
        .signaled => |number| diag.cause("it was killed by signal {d}", .{number}),
        .step => |step| {
            errors.cause_host_error(diag, step.name, step.err, step.errno);
            diag.cause("the user namespace the store works in could not be set up", .{});
        },
        .helper => |helper| {
            switch (helper.status) {
                .exited => |code| diag.cause("{s} ended with status {d}", .{ helper.name, code }),
                .signaled => |number| diag.cause(
                    "{s} was killed by signal {d}",
                    .{ helper.name, number },
                ),
            }
            if (helper.output.len > 0) diag.cause("{s} said: {s}", .{ helper.name, helper.output });
        },
    }
    diag.fix(.{ .sentence = "see what this host allows:", .command = "zbx doctor" });
}

/// ZBX-E0420: the tree exists but nothing keeps it.
pub fn not_a_root(diag: *Diag, digest: Digest) void {
    assert(digest.bytes.len == constants.store_digest_bytes);
    assert(diag.code == null);
    diag.raise(.E0420);
    diag.while_("dropping a root", .{});
    diag.cause(
        "{s} is a tree in the store but not a root, so there is nothing to drop",
        .{digest.text()},
    );
    diag.context("digest", "{s}", .{digest.text()});
    diag.fix(.{ .sentence = "list the roots:", .command = "zbx store ls" });
}

/// ZBX-E0423: a read of the store failed. `step` says what was being read.
pub fn cannot_read(
    diag: *Diag,
    store: *const layout.Store,
    step: []const u8,
    err: host_mod.Error,
    errno: u16,
) void {
    assert(step.len > 0);
    assert(diag.code == null);
    diag.raise(.E0423);
    diag.while_("reading the store", .{});
    errors.cause_host_error(diag, step, err, errno);
    diag.context("path", "{s}", .{store.root_text()});
    diag.fix(
        .{ .sentence = "check that the directory belongs to you and that its disk is healthy" },
    );
}

/// ZBX-E0422: a tree reached from another is missing or damaged. `what` is the walk's failure.
pub fn tree_damaged(diag: *Diag, where: Digest, kind: []const u8) void {
    assert(kind.len > 0);
    assert(diag.code == null);
    diag.raise(.E0422);
    diag.while_("walking the trees of the store", .{});
    diag.cause("tree {s} {s}", .{ where.text(), kind });
    diag.context("digest", "{s}", .{where.text()});
    diag.fix(
        .{
            .sentence = "import the directory again to write what is missing, or restore a backup",
        },
    );
}

/// ZBX-W0410: something that is not a file, a directory or a symlink.
pub fn skipped_file(diag: *Diag, path: []const u8, kind: []const u8) void {
    assert(path.len > 0);
    assert(diag.code == null);
    diag.raise(.W0410);
    diag.while_("importing the directory", .{});
    diag.cause(
        "'{s}' is a {s}; the store keeps files, directories and symlinks only",
        .{ path, kind },
    );
    diag.context("path", "{s}", .{path});
    diag.fix(
        .{
            .sentence = "nothing to do if a container makes its own /dev; else remove it",
        },
    );
}

/// ZBX-W0410, once at the end: the warnings after the first few were counted, not shown.
pub fn more_skipped(diag: *Diag, count: u32) void {
    assert(diag.code == null);
    assert(count > 0);
    diag.raise(.W0410);
    diag.while_("importing the directory", .{});
    diag.cause(
        "{d} more files or attributes were left out; only the first few are shown",
        .{count},
    );
    diag.fix(.{ .sentence = "nothing to do unless the container needs them" });
}

pub const XattrFault = enum { namespace, name_too_long, value_too_long, too_many, unreadable };

/// ZBX-W0411: an attribute was left out.
pub fn skipped_xattr(diag: *Diag, path: []const u8, name: []const u8, fault: XattrFault) void {
    assert(name.len > 0);
    assert(diag.code == null);
    diag.raise(.W0411);
    diag.while_("importing the directory", .{});
    const why: []const u8 = switch (fault) {
        .namespace => "only user.* and security.capability are kept",
        .name_too_long => "its name is longer than 255 bytes",
        .value_too_long => "its value is longer than 4096 bytes",
        .too_many => "a file keeps at most 16 attributes",
        .unreadable => "it could not be read",
    };
    diag.cause("attribute '{s}' of '{s}' was left out: {s}", .{ name, path, why });
    diag.context("path", "{s}", .{path});
    diag.context("attr", "{s}", .{name});
    diag.fix(
        .{
            .sentence = "nothing to do unless the container needs it; the digest does not cover it",
        },
    );
}

const testing = std.testing;

test "a path that needs quoting is not put in a runnable fix" {
    // Goal: a fix command is safe to copy. Method: a plain path, one with a quote, an empty one.
    try testing.expect(quotable("./alpine"));
    try testing.expect(quotable("/srv/my dir"));
    try testing.expect(!quotable("it's"));
    try testing.expect(!quotable(""));
    try testing.expect(!quotable("a\nb"));
}
