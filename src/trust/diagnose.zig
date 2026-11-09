//! The key diagnostics, `ZBX-E0901`, `E0902` and `E0911`, and the signing ones, `E0903` and
//! `E0910`: one function per failure, each with
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
const key_mod = @import("key.zig");
const policy_mod = @import("policy.zig");
const peer = @import("peer.zig");
const verdict = @import("verdict.zig");

const path_echo_bytes = constants.store_path_bytes_max;

/// A name, `@sha256:` and 64 digits, or `b3:` and 64 digits, with room for the name.
const digest_echo_bytes = 256;

comptime {
    assert(digest_echo_bytes >= constants.oci_digest_text_bytes + 128);
}

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

/// What the name's files are, for E0902.
pub const Taken = enum {
    /// Both files.
    whole,
    /// A `.key` alone, written a moment ago: another run may be finishing it.
    secret_recent,
    /// A `.key` alone for long enough that no run is finishing it.
    secret_stale,
    /// A `.pub` alone.
    public_only,
};

/// ZBX-E0902: a key of that name exists, and is never overwritten. The `rm` advice is given
/// only for a leftover no live run can own: a `.key` alone that is old, or a `.pub` alone.
pub fn name_exists(diag: *Diag, name: []const u8, dir: []const u8, taken: Taken) void {
    assert(diag.code == null);
    var name_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    var dir_storage: [path_echo_bytes]u8 = undefined;
    const name_echo = echo_of(&name_storage, name);
    const dir_echo = echo_of(&dir_storage, dir);
    diag.raise(.E0902);
    diag.while_("making the key '{s}'", .{name_echo});
    switch (taken) {
        .whole => diag.cause("a key named '{s}' is already in {s}; zbx never overwrites a key", .{
            name_echo,
            dir_echo,
        }),
        .secret_recent => diag.cause(
            "{s}/{s}.key has no {s}.pub beside it yet; another 'zbx key new {s}' is probably " ++
                "still writing it",
            .{ dir_echo, name_echo, name_echo, name_echo },
        ),
        .secret_stale => diag.cause(
            "{s}/{s}.key has no {s}.pub beside it; an interrupted 'zbx key new' left it",
            .{ dir_echo, name_echo, name_echo },
        ),
        .public_only => diag.cause(
            "{s}/{s}.pub has no {s}.key beside it; the secret half of that key is gone",
            .{ dir_echo, name_echo, name_echo },
        ),
    }
    diag.context("key", "{s}", .{name_echo});
    diag.context("path", "{s}", .{dir_echo});
    diag.fix(.{
        .sentence = "choose another name:",
        .command = "zbx key new <name>",
        .template = true,
    });
    switch (taken) {
        .whole => {},
        .secret_recent => diag.fix(.{
            .sentence = "or wait a few minutes and run it again: the leftover is named then",
        }),
        .secret_stale => diag.fix_with(
            "or, if that key was never used, remove the leftover:",
            "rm {s}/{s}.key",
            .{ dir_echo, name_echo },
        ),
        .public_only => diag.fix_with(
            "or, if you removed the secret on purpose, remove the public half:",
            "rm {s}/{s}.pub",
            .{ dir_echo, name_echo },
        ),
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

/// What is wrong with a signature record, for E0903.
pub const RecordProblem = enum { damaged, newer };

/// ZBX-E0903: the signature record of a tree cannot be used. `path` is the record's file.
pub fn record_unusable(diag: *Diag, path: []const u8, problem: RecordProblem) void {
    assert(diag.code == null);
    var path_storage: [path_echo_bytes]u8 = undefined;
    const path_echo = echo_of(&path_storage, path);
    diag.raise(.E0903);
    diag.while_("reading the signatures of a tree", .{});
    switch (problem) {
        .damaged => diag.cause("{s} is damaged: a line of it is not a signed statement", .{
            path_echo,
        }),
        .newer => diag.cause("{s} was written by a newer zbx than this one", .{path_echo}),
    }
    diag.context("path", "{s}", .{path_echo});
    switch (problem) {
        .damaged => diag.fix_with("remove it, then sign again:", "rm {s}", .{path_echo}),
        .newer => diag.fix(.{ .sentence = "use the zbx that wrote it, or a newer one" }),
    }
    assert(diag.code.? == .E0903);
}

/// Why `zbx sign` refused, for E0910.
pub const Refusal = enum {
    /// The digest names no result, tree or image in the store.
    not_in_store,
    /// A file object of the tree is not in the store.
    object_missing,
    /// A file object of the tree is not what its name says.
    object_damaged,
    /// A tree or an object could not be read (the errno says why).
    unreadable,
    /// The tree has more entries than zbx walks.
    too_large,
    /// The tree already has `signatures_per_tree_max` signatures.
    tree_full,
    /// The store already has `trust_records_max` signed trees.
    store_full,
};

/// What differs in the file the tamper check found.
const too_large_fix = std.fmt.comptimePrint(
    "zbx checks at most {d} files, directories and links in an image, and only so many " ++
        "directories side by side; run a smaller image, or one that is less wide",
    .{constants.store_walk_entries_max},
);

const farm_fix = "remove the image's directory under cache/ in the data directory (named by its " ++
    "digest) and run again; zbx builds it afresh from the checked files";

pub const Tampered = enum { bytes, mode, owner, missing, unreadable, too_large, farm };

/// ZBX-E0907: a file object of the tree to run no longer matches its name. `path` is the file's
/// path in the image (empty if it was not found), `object` the object's hex id.
pub fn tampered(
    diag: *Diag,
    path: []const u8,
    object: []const u8,
    what: Tampered,
    errno: u16,
) void {
    assert(diag.code == null);
    assert(errno < 4096);
    assert(object.len > 0);
    var path_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const path_echo = echo_of(&path_storage, if (path.len > 0) path else "(unnamed)");
    const short = object[0..@min(object.len, 12)];
    diag.raise(.E0907);
    diag.while_("checking the files of the image before running it", .{});
    switch (what) {
        .bytes => diag.cause(
            "{s} (object {s}) has bytes that are not the image's",
            .{ path_echo, short },
        ),
        .mode => diag.cause(
            "{s} (object {s}) has a mode that is not the image's",
            .{ path_echo, short },
        ),
        .owner => diag.cause(
            "{s} (object {s}) has an owner that is not the image's",
            .{ path_echo, short },
        ),
        .too_large => diag.cause(
            "the image has more files or nested directories than zbx checks",
            .{},
        ),
        .farm => diag.cause(
            "{s} in the image's materialized directory is not the image's",
            .{path_echo},
        ),
        .missing => diag.cause("{s} (object {s}) is missing from the store", .{ path_echo, short }),
        .unreadable => if (errno == 0) {
            diag.cause("{s} (object {s}) could not be read", .{ path_echo, short });
        } else {
            const err = host_mod.error_for_errno(errno);
            errors.cause_host_error(diag, "reading a file of the image", err, errno);
        },
    }
    diag.context("path", "{s}", .{path_echo});
    diag.context("object", "{s}", .{short});
    switch (what) {
        .too_large => diag.fix(.{ .sentence = too_large_fix }),
        .farm => diag.fix(.{ .sentence = farm_fix }),
        else => diag.fix(.{
            .sentence = "remove the damaged tree and pull or build it again; " ++
                "this shows the damage:",
            .command = "zbx store verify",
        }),
    }
    assert(diag.code.? == .E0907);
}

/// ZBX-E0910: signing was refused, and nothing was written. `operand` is what was named.
pub fn sign_refused(diag: *Diag, operand: []const u8, refusal: Refusal, errno: u16) void {
    assert(diag.code == null);
    assert(errno < 4096);
    var operand_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const operand_echo = echo_of(&operand_storage, operand);
    diag.raise(.E0910);
    diag.while_("signing '{s}'", .{operand_echo});
    switch (refusal) {
        .not_in_store => diag.cause(
            "the store has no build result, tree or image with that digest",
            .{},
        ),
        .object_missing => diag.cause("part of the tree is missing from the store", .{}),
        .object_damaged => diag.cause("a file of the tree in the store is damaged", .{}),
        .unreadable => if (errno == 0) {
            diag.cause("the tree could not be read", .{});
        } else {
            const err = host_mod.error_for_errno(errno);
            errors.cause_host_error(diag, "reading the tree", err, errno);
        },
        .too_large => diag.cause("the tree has more entries than zbx checks", .{}),
        .tree_full => diag.cause(
            "the tree already has {d} signatures, none of them by this key over this, " ++
                "and that is the most it keeps",
            .{constants.signatures_per_tree_max},
        ),
        .store_full => diag.cause(
            "the store already holds signatures for {d} trees, the most it keeps",
            .{constants.trust_records_max},
        ),
    }
    diag.context("arg", "{s}", .{operand_echo});
    switch (refusal) {
        .not_in_store, .object_missing, .object_damaged, .too_large => diag.fix(.{
            .sentence = "pull or build it again, then sign it",
        }),
        .unreadable => diag.fix(.{
            .sentence = "check the store's permissions and free space, then run it again",
        }),
        .tree_full => diag.fix(.{
            .sentence = "to start the tree's record again, remove its file under " ++
                "trust/signatures in the store (its signatures are lost), then sign again",
        }),
        .store_full => diag.fix(.{
            .sentence = "run 'zbx trust prune' to see the records whose trees are gone, " ++
                "then 'zbx trust prune --apply' to remove them",
        }),
    }
    assert(diag.code.? == .E0910);
}

/// ZBX-E0006 for `zbx sign` without `--key` when the keys do not say which: none, or several.
pub fn key_choice(diag: *Diag, count: u32) void {
    assert(diag.code == null);
    diag.raise(.E0006);
    diag.while_("choosing the key to sign with", .{});
    if (count == 0) {
        diag.cause("there is no key to sign with", .{});
        diag.fix(.{ .sentence = "make one:", .command = "zbx key new <name>", .template = true });
    } else {
        diag.cause("there is more than one key, and --key does not say which to sign with", .{});
        diag.fix(.{
            .sentence = "name one of them:",
            .command = "zbx sign <digest> --key <name>",
            .template = true,
        });
    }
    diag.context("cmd", "sign", .{});
    assert(diag.code.? == .E0006);
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

/// What is wrong with a policy file, for E0904.
pub const PolicyFault = union(enum) {
    /// The file could not be read; the errno says why (0 when not known).
    unreadable: u16,
    /// The system file is not root's, or others can write it.
    not_root: struct { uid: u32, mode: u16 },
    /// The file was read and its text is not a policy.
    problem: policy_mod.Problem,
};

fn problem_expected(kind: policy_mod.Kind) []const u8 {
    return switch (kind) {
        .syntax => "this is not part of the form of a policy file",
        .unknown_field => "no such field in a policy file",
        .duplicate_field => "this field is given twice",
        .missing_version => "the file has no .version = 1",
        .bad_version => "the only version is 1",
        .newer_version => "the version is newer than this zbx reads",
        .bad_string => "a string here has no escapes and no control characters",
        .bad_name => "a key's name is lower-case letters, digits and '-', at most 32",
        .bad_public => "a public key reads zbx-ed25519: and 64 hex digits",
        .key_twice => "this key, or its name, is listed twice",
        .too_many_keys => "more keys than a policy lists",
        .bad_verify => "verify is \"cached\" or \"always\"",
        .too_large => "the file is larger than a policy file may be",
    };
}

/// ZBX-E0904: a policy file cannot be used. `path` is the file.
pub fn policy_unusable(diag: *Diag, path: []const u8, system: bool, fault: PolicyFault) void {
    assert(diag.code == null);
    var path_storage: [path_echo_bytes]u8 = undefined;
    const path_echo = echo_of(&path_storage, path);
    diag.raise(.E0904);
    diag.while_("reading the policy {s}", .{path_echo});
    switch (fault) {
        .unreadable => |errno| if (errno == 0) {
            diag.cause("{s} could not be read", .{path_echo});
        } else {
            const err = host_mod.error_for_errno(errno);
            errors.cause_host_error(diag, "reading the policy file", err, errno);
        },
        .not_root => |owner| diag.cause(
            "{s} is owned by uid {d} with mode {o:0>4}; a system policy must be owned by root " ++
                "and writable by no one else, or anyone who can write it can switch it off",
            .{ path_echo, owner.uid, owner.mode },
        ),
        .problem => |problem| {
            var detail_storage: [constants.arg_echo_bytes_max]u8 = undefined;
            const detail = echo_of(&detail_storage, problem.detail_text());
            if (problem.line == 0) {
                diag.cause("{s}: {s}", .{ path_echo, problem_expected(problem.kind) });
            } else if (detail.len > 0) {
                diag.cause("{s} line {d}, column {d}: '{s}': {s}", .{
                    path_echo,
                    problem.line,
                    problem.column,
                    detail,
                    problem_expected(problem.kind),
                });
            } else {
                diag.cause("{s} line {d}, column {d}: {s}", .{
                    path_echo,
                    problem.line,
                    problem.column,
                    problem_expected(problem.kind),
                });
            }
        },
    }
    diag.context("path", "{s}", .{path_echo});
    switch (fault) {
        .unreadable => if (system) {
            diag.fix(.{ .sentence = "ask the administrator to make it readable, or to remove it" });
        } else {
            diag.fix(.{ .sentence = "make the file readable by you, or remove it" });
        },
        .not_root => diag.fix(.{
            .sentence = "as root, make it root's and not writable by others:",
            .command = "chown root:root /etc/zbx/policy.zon && chmod 644 /etc/zbx/policy.zon",
            .needs_root = true,
        }),
        .problem => diag.fix(.{
            .sentence = "correct the file where it says; \"zbx explain E0904\" shows its form",
        }),
    }
    assert(diag.code.? == .E0904);
}

pub fn reason_text(reason: verdict.Reason) []const u8 {
    return switch (reason) {
        .counts => "it counts",
        .malformed => "it is not a statement this zbx can read",
        .bad_signature => "its signature does not verify",
        .untrusted_key => "the policy does not list that key",
        .other_tree => "it is about another tree",
        .other_predicate => "it says something this zbx does not know",
        .other_binding => "it is bound to another result or image than this run's",
        .not_derived => "it is bound to a result, and this image's record does not keep its " ++
            "labels, so the result it was made from cannot be checked; pull the image again",
    };
}

/// How many signatures E0905 names, one cause each; the rest are counted.
const signatures_named_max: u32 = 4;

/// What E0905 says about the run it refused.
pub const Unsigned = struct {
    /// The digest of what was to run, as the user would give it to `zbx sign`.
    digest: []const u8,
    /// The policy file whose rule was not met.
    policy_path: []const u8,
    /// The record's lines, judged.
    report: *const verdict.Report,
    /// The policy, to name the keys it lists.
    policy: *const policy_mod.Policy,
    /// The run has no tree to sign (a directory given as `--rootfs`).
    no_tree: bool,
    /// The build step whose base was judged; empty for a run.
    step: []const u8 = "",
};

/// ZBX-E0905: a run is refused because no trusted signature covers it.
pub fn unsigned(diag: *Diag, what: *const Unsigned) void {
    assert(diag.code == null);
    assert(what.report.count <= constants.signatures_per_tree_max);
    // The digest is a command to copy: it must not be cut short as an argument echo is.
    var digest_storage: [constants.reference_bytes_max]u8 = undefined;
    var path_storage: [path_echo_bytes]u8 = undefined;
    const digest = echo_of(&digest_storage, what.digest);
    const path = echo_of(&path_storage, what.policy_path);
    diag.raise(.E0905);
    if (what.step.len > 0) {
        var step_storage: [constants.arg_echo_bytes_max]u8 = undefined;
        const step = echo_of(&step_storage, what.step);
        diag.while_("checking the base of step '{s}', {s}, against the policy {s}", .{
            step, digest, path,
        });
    } else if (what.no_tree) {
        diag.while_("checking the directory run against the policy {s}", .{path});
    } else {
        diag.while_("checking {s} against the policy {s}", .{ digest, path });
    }
    if (what.no_tree) {
        const asks = if (what.policy.require_signature)
            "a signature (require_signature)"
        else
            "signed provenance (require_provenance)";
        diag.cause("{s} requires {s} and a directory has no tree to sign", .{ path, asks });
    } else if (what.report.count == 0) {
        diag.cause("{s} requires a signature (require_signature), and nothing has signed {s}", .{
            path,
            digest,
        });
    } else {
        diag.cause("{s} requires a signature (require_signature), and none of the {d} on {s} " ++
            "counts", .{ path, what.report.count, digest });
    }
    const shown = @min(what.report.count, signatures_named_max);
    for (what.report.lines[0..shown]) |line| {
        const text = key_mod.public_text(line.public);
        const listed = what.policy.trusted(&line.public);
        const name: []const u8 = if (listed) |found| found.name_text() else "";
        // The first 16 hex digits identify a key to a reader; the full text is `zbx key show`'s.
        const prefix_bytes = key_mod.public_prefix.len + 16;
        if (name.len > 0) {
            diag.cause("signed by '{s}': {s}", .{ name, reason_text(line.reason) });
        } else {
            diag.cause("signed by {s}: {s}", .{ text[0..prefix_bytes], reason_text(line.reason) });
        }
    }
    if (what.report.count > shown) {
        diag.cause("{d} more signatures are not listed", .{what.report.count - shown});
    }
    diag.context("digest", "{s}", .{digest});
    diag.context("policy", "{s}", .{path});
    if (!what.no_tree) {
        diag.fix_with("sign it with a key the policy lists:", "zbx sign {s}", .{digest});
        diag.fix(.{ .sentence = "or add the signer's key to the policy file" });
    } else {
        diag.fix(.{ .sentence = "run an image, or a build result, that has been signed" });
    }
    assert(diag.code.? == .E0905);
}

/// Why E0906: the ways a policy's `require_provenance` is not met.
pub const ProvenanceCause = enum {
    /// No provenance statement is signed for the tree, and none is stored.
    missing,
    /// A record of the build is stored, or a provenance line is present, but no trusted key
    /// has signed it.
    unsigned,
    /// A trusted key signed a provenance statement, but for another result than this run's.
    other_binding,
    /// The run is not of a build result or of an image that derives one (a build step's base, a
    /// tree digest), and only a build result carries provenance.
    not_a_result,
    /// The run is of an image whose record does not keep the labels its derived result needs
    /// (slice 14), so whether provenance covers it cannot be checked.
    not_derived,
};

/// What E0906 says about the run it refused.
pub const ProvenanceRefused = struct {
    digest: []const u8,
    policy_path: []const u8,
    cause: ProvenanceCause,
    /// The step whose base this is; empty for a run.
    step: []const u8 = "",
};

/// ZBX-E0906: a run is refused because no trusted signed provenance covers it.
pub fn provenance_missing(diag: *Diag, what: *const ProvenanceRefused) void {
    assert(diag.code == null);
    assert(what.policy_path.len > 0);
    var digest_storage: [constants.reference_bytes_max]u8 = undefined;
    var path_storage: [path_echo_bytes]u8 = undefined;
    const digest = echo_of(&digest_storage, what.digest);
    const path = echo_of(&path_storage, what.policy_path);
    diag.raise(.E0906);
    if (what.step.len > 0) {
        var step_storage: [constants.arg_echo_bytes_max]u8 = undefined;
        const step = echo_of(&step_storage, what.step);
        diag.while_("checking the base of step '{s}', {s}, against the policy {s}", .{
            step, digest, path,
        });
    } else {
        diag.while_("checking {s} against the policy {s}", .{ digest, path });
    }
    const need = "{s} requires signed provenance, but ";
    switch (what.cause) {
        .missing => diag.cause(need ++ "{s} has none stored", .{ path, digest }),
        .unsigned => diag.cause(need ++ "no listed key signed the provenance of {s}", .{
            path, digest,
        }),
        .other_binding => diag.cause(need ++ "the signed provenance is not of {s}", .{
            path, digest,
        }),
        .not_a_result => diag.cause(need ++ "{s} is not a build result, and only a result " ++
            "built by zbx carries provenance", .{ path, digest }),
        .not_derived => diag.cause(need ++ "{s} is an image whose record does not keep its " ++
            "labels, so the result it was made from cannot be checked", .{ path, digest }),
    }
    diag.context("digest", "{s}", .{digest});
    diag.context("policy", "{s}", .{path});
    switch (what.cause) {
        .missing => diag.fix(.{ .sentence = "build it with this zbx, then sign the result" }),
        .unsigned => diag.fix_with(
            "sign the result with a key the policy lists:",
            "zbx sign {s}",
            .{digest},
        ),
        .other_binding => diag.fix(.{ .sentence = "run the result whose provenance was signed" }),
        .not_a_result => diag.fix(.{
            .sentence = "run a result built with zbx build and signed, or lift require_provenance",
        }),
        .not_derived => diag.fix(.{ .sentence = "pull the image again" }),
    }
    assert(diag.code.? == .E0906);
}

/// The links `zbx verify` walks, in order (docs/briefs/M8-trust.md, "`zbx verify <digest>`").
pub const VerifyLink = enum(u8) {
    signature = 1,
    signer,
    tree,
    provenance,
    inputs,
    build_file,

    pub fn words(link: VerifyLink) []const u8 {
        return switch (link) {
            .signature => "the signatures",
            .signer => "a trusted signer",
            .tree => "the tree",
            .provenance => "the provenance",
            .inputs => "the inputs",
            .build_file => "the build file",
        };
    }
};

/// What is wrong at the link; `VerifyBroken.detail` completes the sentence.
pub const VerifyCause = enum {
    /// Link 1: the store holds no signature for the tree.
    no_record,
    /// Link 2: no signer is trusted. Detail: the signers' ids, or "none".
    no_trusted_signer,
    /// Link 3: part of the tree is missing, damaged, unreadable or too large.
    tree_missing,
    tree_damaged,
    tree_unreadable,
    tree_too_large,
    /// Link 4: `--require-provenance` and no trusted signed provenance covers the tree.
    no_provenance,
    /// Link 4: a trusted line carries provenance that is not about this tree (or result).
    provenance_other,
    /// Link 5: an input is damaged. Detail: which one.
    input_damaged,
    /// Link 5: `--strict` and an input is not in the store. Detail: which one.
    input_absent,
    /// Link 6: the build file or the lock differs from the signed hash. Detail: which.
    build_file_changed,
};

pub const VerifyBroken = struct {
    operand: []const u8,
    link: VerifyLink,
    cause: VerifyCause,
    detail: []const u8 = "",
    errno: u16 = 0,
};

/// ZBX-E0908: `zbx verify` found a broken link; links before it held.
pub fn verify_broken(diag: *Diag, what: *const VerifyBroken) void {
    assert(diag.code == null);
    assert(what.errno < 4096);
    var operand_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    var detail_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const operand = echo_of(&operand_storage, what.operand);
    const detail = echo_of(&detail_storage, what.detail);
    diag.raise(.E0908);
    diag.while_("verifying {s}, link {d} ({s})", .{
        operand, @backingInt(what.link), what.link.words(),
    });
    switch (what.cause) {
        .no_record => diag.cause("the store has no signature for the tree", .{}),
        .no_trusted_signer => diag.cause(
            "no signer is trusted (signers: {s}), and no policy file, --key or --public " ++
                "names one that counts",
            .{detail},
        ),
        .tree_missing => diag.cause("part of the tree is missing from the store", .{}),
        .tree_damaged => diag.cause("a file of the tree in the store is damaged", .{}),
        .tree_unreadable => errors.cause_host_error(
            diag,
            "reading the tree",
            host_mod.error_for_errno(what.errno),
            what.errno,
        ),
        .tree_too_large => diag.cause("the tree has more entries than zbx checks", .{}),
        .no_provenance => diag.cause(
            "no trusted signature covers signed provenance of the tree, and " ++
                "--require-provenance was given",
            .{},
        ),
        .provenance_other => diag.cause(
            "the signed provenance is not about this tree and result ({s})",
            .{detail},
        ),
        .input_damaged => diag.cause("{s} is damaged in the store", .{detail}),
        .input_absent => diag.cause("{s} is not in the store, and --strict was given", .{detail}),
        .build_file_changed => diag.cause("{s} differs from what was signed", .{detail}),
    }
    diag.context("arg", "{s}", .{operand});
    diag.context("link", "{d}", .{@backingInt(what.link)});
    switch (what.cause) {
        .no_record => diag.fix_with(
            "sign it, or import the signer's bundle:",
            "zbx sign {s}",
            .{operand},
        ),
        .no_trusted_signer => diag.fix(.{
            .sentence = "trust a signer: list its key in a policy file, or pass --key <name> " ++
                "or --public <text>",
        }),
        .tree_missing, .tree_damaged, .tree_too_large, .input_damaged => diag.fix(.{
            .sentence = "run 'zbx store verify', remove what is damaged, then pull or build again",
        }),
        .tree_unreadable => diag.fix(.{
            .sentence = "check the store's permissions and disk, then run it again",
        }),
        .no_provenance, .provenance_other => diag.fix(.{
            .sentence = "build it with this zbx and sign the result with 'zbx sign <result>'",
        }),
        .input_absent => diag.fix(.{
            .sentence = "pull or build the input again, or leave out --strict",
        }),
        .build_file_changed => diag.fix(.{
            .sentence = "restore the file that was signed, or build and sign again",
        }),
    }
    assert(diag.code.? == .E0908);
}

/// Which input W0903 could not check.
pub fn verify_absent_input(diag: *Diag, operand: []const u8, input: []const u8) void {
    assert(diag.code == null);
    var operand_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    var input_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const operand_echo = echo_of(&operand_storage, operand);
    const input_echo = echo_of(&input_storage, input);
    diag.raise(.W0903);
    diag.while_("verifying {s}, link 5 (the inputs)", .{operand_echo});
    diag.cause("{s} is not in the store, so it cannot be checked offline", .{input_echo});
    diag.context("arg", "{s}", .{operand_echo});
    diag.fix(.{ .sentence = "pull or build the input again to check it, or use --strict to fail" });
    assert(diag.code.? == .W0903);
}

/// ZBX-E0909 for a trust bundle or a signature record that `zbx trust export` or `import` did
/// not take; a busy store, a failed read and a failed write are E0436, E0423 and E0417 as
/// elsewhere, and an unusable local record is E0903.
pub fn trust_refused(diag: *Diag, failure: *const peer.Failure, what: []const u8) void {
    assert(diag.code == null);
    assert(failure.refusal != .busy);
    assert(failure.refusal != .store_failed);
    assert(failure.refusal != .unreadable);
    assert(failure.refusal != .write_failed);
    assert(failure.refusal != .local_unusable);
    var what_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&what_storage, what);
    diag.raise(.E0909);
    diag.while_("{s}", .{echo});
    switch (failure.refusal) {
        .no_record => diag.cause("the store has no signature for that tree", .{}),
        .too_large => diag.cause(
            "the bundle is {d} bytes, more than the {d} any record has",
            .{ failure.size, constants.signature_record_bytes_max },
        ),
        .malformed => diag.cause(
            "the text is not a bundle this zbx reads: a line is not an envelope, its " ++
                "signature does not verify, or its statement is not about one tree",
            .{},
        ),
        .newer => diag.cause("a statement in the bundle is of a form from a newer zbx", .{}),
        .tree_full => diag.cause(
            "the tree would hold more than {d} signatures, the most it keeps",
            .{constants.signatures_per_tree_max},
        ),
        .store_full => diag.cause(
            "the store already holds signatures for {d} trees (trust_records_max)",
            .{constants.trust_records_max},
        ),
        .busy, .store_failed, .unreadable, .write_failed, .local_unusable => unreachable,
    }
    switch (failure.refusal) {
        .no_record => diag.fix(.{ .sentence = "sign the tree, or import a bundle for it" }),
        .tree_full => diag.fix(.{ .sentence = "keep the record the store has" }),
        .store_full => diag.fix(.{
            .sentence = "run 'zbx trust prune' to see the records whose trees are gone, " ++
                "then 'zbx trust prune --apply'",
        }),
        .newer => diag.fix(.{ .sentence = "upgrade zbx, then import again" }),
        else => diag.fix(.{
            .sentence = "export the bundle again with 'zbx trust export <tree>' where it was made",
        }),
    }
    assert(diag.code.? == .E0909);
}

/// ZBX-E0909: the bundle file to import could not be read.
pub fn bundle_unreadable(diag: *Diag, path: []const u8, err: host_mod.Error, errno: u16) void {
    assert(diag.code == null);
    assert(path.len > 0);
    var path_storage: [path_echo_bytes]u8 = undefined;
    const echo = echo_of(&path_storage, path);
    diag.raise(.E0909);
    diag.while_("importing a bundle of signatures", .{});
    errors.cause_host_error(diag, "reading the bundle file", err, errno);
    diag.context("path", "{s}", .{echo});
    diag.fix(.{ .sentence = "check the file's name and that you can read it" });
    assert(diag.code.? == .E0909);
}

/// ZBX-W0902: prune kept a damaged record because its tree is in the store.
pub fn prune_kept_damaged(diag: *Diag, path: []const u8) void {
    assert(diag.code == null);
    var path_storage: [path_echo_bytes]u8 = undefined;
    const echo = echo_of(&path_storage, path);
    diag.raise(.W0902);
    diag.while_("pruning the trust records", .{});
    diag.cause("{s} is damaged, or of a newer zbx, but its tree is in the store, so it was kept", .{
        echo,
    });
    diag.context("path", "{s}", .{echo});
    diag.fix(.{
        .sentence = "import the tree's bundle again or sign it again; upgrade zbx if newer",
    });
    assert(diag.code.? == .W0902);
}
