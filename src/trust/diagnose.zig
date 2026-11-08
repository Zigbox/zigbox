//! The key diagnostics, `ZBX-E0901`, `E0902` and `E0911`: one function per failure, each with
//! its cause and a fix (DIAGNOSTICS.md). Nothing here decides, and nothing here is given a
//! secret: a passphrase and a key's bytes never reach a message, only names and paths.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const text_util = @import("../text.zig");
const Diag = @import("../diag/diag.zig").Diag;
const errors = @import("../diag/errors.zig");
const store = @import("key_store.zig");

const path_echo_bytes = constants.store_path_bytes_max;

fn echo_of(storage: []u8, text: []const u8) []const u8 {
    assert(storage.len >= constants.arg_echo_bytes_max);
    return text_util.sanitise(storage, text);
}

/// ZBX-E0901: the key cannot be used. `path` is the file or directory the problem is with.
pub fn unusable(diag: *Diag, name: []const u8, path: []const u8, failure: store.Failure) void {
    assert(diag.code == null);
    var name_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    var path_storage: [path_echo_bytes]u8 = undefined;
    const name_echo = echo_of(&name_storage, name);
    const path_echo = echo_of(&path_storage, path);
    diag.raise(.E0901);
    diag.while_("using the key '{s}'", .{name_echo});
    switch (failure.problem) {
        .missing => diag.cause("there is no key file at {s}", .{path_echo}),
        .malformed => diag.cause("{s} is not a zbx key file", .{path_echo}),
        .newer => diag.cause("{s} was written by a newer zbx than this one", .{path_echo}),
        .secret_too_open => diag.cause("{s} can be read by other users", .{path_echo}),
        .dir_too_open => diag.cause("{s} can be read by other users", .{path_echo}),
        .dir_not_real => diag.cause(
            "{s} is a symbolic link or not a directory; zbx keeps keys only in a real directory",
            .{path_echo},
        ),
        .no_home => diag.cause(
            "neither XDG_CONFIG_HOME nor HOME names an existing directory to keep keys in",
            .{},
        ),
        .path_too_long => diag.cause("the key's path is longer than zbx handles", .{}),
        .unreadable, .exists => cause_io(diag, path_echo, failure),
    }
    diag.context("key", "{s}", .{name_echo});
    diag.context("path", "{s}", .{path_echo});
    fix_unusable(diag, name_echo, path_echo, failure.problem);
    assert(diag.code.? == .E0901);
}

fn cause_io(diag: *Diag, path: []const u8, failure: store.Failure) void {
    assert(path.len > 0);
    assert(failure.errno < 4096);
    if (failure.errno == 0) {
        diag.cause("{s} could not be read or written", .{path});
        return;
    }
    const err = host_mod.error_for_errno(failure.errno);
    errors.cause_host_error(diag, "reading or writing the key", err, failure.errno);
}

fn fix_unusable(diag: *Diag, name: []const u8, path: []const u8, problem: store.Problem) void {
    assert(name.len > 0);
    switch (problem) {
        .secret_too_open => diag.fix_with("make it private to you:", "chmod 600 {s}", .{path}),
        .dir_too_open => diag.fix_with("make it private to you:", "chmod 700 {s}", .{path}),
        .dir_not_real => diag.fix(.{
            .sentence = "replace it with a real directory, moving the keys into it",
        }),
        .missing => diag.fix(.{
            .sentence = "see the keys there are, or make one:",
            .command = "zbx key list",
        }),
        .newer => diag.fix(.{ .sentence = "use the zbx that wrote it, or a newer one" }),
        .malformed => diag.fix(.{
            .sentence = "restore the file from a copy, or make a new key and trust that:",
            .command = "zbx key new <name>",
            .template = true,
        }),
        .no_home => diag.fix(.{
            .sentence = "set XDG_CONFIG_HOME to a directory you own, for example:",
            .command = "XDG_CONFIG_HOME=$HOME/.config zbx key list",
        }),
        .path_too_long, .unreadable, .exists => diag.fix(.{
            .sentence = "check the directory's permissions and free space, then run it again",
        }),
    }
    assert(diag.fixes.count > 0);
}

/// ZBX-E0902: a key of that name exists, and is never overwritten.
pub fn name_exists(diag: *Diag, name: []const u8, dir: []const u8, orphan: bool) void {
    assert(diag.code == null);
    var name_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    var dir_storage: [path_echo_bytes]u8 = undefined;
    const name_echo = echo_of(&name_storage, name);
    const dir_echo = echo_of(&dir_storage, dir);
    diag.raise(.E0902);
    diag.while_("making the key '{s}'", .{name_echo});
    if (orphan) {
        diag.cause("{s}/{s}.key has no {s}.pub beside it; an interrupted 'zbx key new' left it", .{
            dir_echo,
            name_echo,
            name_echo,
        });
    } else {
        diag.cause("a key named '{s}' is already in {s}; zbx never overwrites a key", .{
            name_echo,
            dir_echo,
        });
    }
    diag.context("key", "{s}", .{name_echo});
    diag.context("path", "{s}", .{dir_echo});
    diag.fix(.{
        .sentence = "choose another name:",
        .command = "zbx key new <name>",
        .template = true,
    });
    if (orphan) {
        diag.fix_with("or, if that key was never used, remove the leftover:", "rm {s}/{s}.key", .{
            dir_echo,
            name_echo,
        });
    }
    assert(diag.code.? == .E0902);
}

pub const PassphraseProblem = enum {
    /// Needed, and neither a file nor a terminal was available.
    unavailable,
    /// The file or the terminal gave nothing.
    empty,
    /// The two entries on the terminal differ.
    mismatch,
    /// The file can be read by group or others.
    file_too_open,
    /// The first line is longer than `passphrase_bytes_max`.
    too_long,
    /// The file could not be read.
    file_unreadable,
    /// The file is not there.
    file_missing,
    /// The path is a symbolic link; zbx reads the file itself, not what a link points to.
    file_is_link,
    /// It does not open the key.
    wrong,
    /// Ctrl-C (or end of input) at the prompt.
    cancelled,
};

/// ZBX-E0911: the passphrase is missing, unusable or wrong. `path` is the passphrase file, for
/// the problems that are about it. The passphrase itself is never an argument.
pub fn passphrase(
    diag: *Diag,
    name: []const u8,
    path: []const u8,
    problem: PassphraseProblem,
) void {
    assert(diag.code == null);
    var name_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    var path_storage: [path_echo_bytes]u8 = undefined;
    const name_echo = echo_of(&name_storage, name);
    const path_echo = echo_of(&path_storage, path);
    diag.raise(.E0911);
    diag.while_("getting the passphrase for the key '{s}'", .{name_echo});
    switch (problem) {
        .unavailable => diag.cause(
            "the key needs a passphrase, and there is no terminal to ask on and no " ++
                "--passphrase-file",
            .{},
        ),
        .empty => diag.cause("the passphrase is empty; a key needs at least one character", .{}),
        .mismatch => diag.cause("the two passphrases differ; nothing was done", .{}),
        .file_too_open => diag.cause("{s} can be read by other users", .{path_echo}),
        .too_long => if (path.len == 0) diag.cause(
            "the passphrase is longer than {d} bytes",
            .{constants.passphrase_bytes_max},
        ) else diag.cause(
            "the first line of {s} is longer than {d} bytes",
            .{ path_echo, constants.passphrase_bytes_max },
        ),
        .file_unreadable => diag.cause("{s} could not be read", .{path_echo}),
        .file_missing => diag.cause("there is no file {s}", .{path_echo}),
        .file_is_link => diag.cause(
            "{s} is a symbolic link; name the file it points to instead",
            .{path_echo},
        ),
        .wrong => diag.cause("that passphrase does not open the key", .{}),
        .cancelled => diag.cause("the passphrase was not entered; nothing was done", .{}),
    }
    diag.context("key", "{s}", .{name_echo});
    if (path.len > 0) diag.context("path", "{s}", .{path_echo});
    fix_passphrase(diag, path_echo, problem);
    assert(diag.code.? == .E0911);
}

fn fix_passphrase(diag: *Diag, path: []const u8, problem: PassphraseProblem) void {
    switch (problem) {
        .file_too_open => diag.fix_with("make it private to you:", "chmod 600 {s}", .{path}),
        .wrong => diag.fix(.{
            .sentence = "try again; a forgotten passphrase is a lost key, and there is no recovery",
        }),
        else => diag.fix(.{
            .sentence = "give the passphrase in a file only you can read:",
            .command = "zbx key new <name> --passphrase-file <file>",
            .template = true,
        }),
    }
    assert(diag.fixes.count > 0);
}

/// ZBX-E0005 for a key name that cannot name a key.
pub fn bad_name(diag: *Diag, name: []const u8) void {
    assert(diag.code == null);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, name);
    diag.raise(.E0005);
    diag.while_("reading the command line", .{});
    diag.cause("'{s}' cannot name a key; use up to {d} lowercase letters, digits and '-'", .{
        echo,
        constants.key_name_bytes_max,
    });
    diag.context("arg", "{s}", .{echo});
    diag.fix(.{ .sentence = "for example:", .command = "zbx key new release" });
}
