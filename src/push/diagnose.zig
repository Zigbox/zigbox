//! The diagnostics of packing and exporting.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const errors = @import("../diag/errors.zig");
const host_mod = @import("../host.zig");
const text_util = @import("../text.zig");
const Diag = @import("../diag/diag.zig").Diag;
const Sha256 = @import("../registry/digest.zig").Sha256;
const export_mod = @import("export.zig");
const pack = @import("pack.zig");
const fs_mod = @import("../store/fs.zig");

fn echo_of(storage: *[constants.arg_echo_bytes_max]u8, argument: []const u8) []const u8 {
    assert(argument.len <= constants.file_bytes_max);
    return text_util.sanitise(storage, argument);
}

/// ZBX-E0550: `operand` cannot be packed. `why` is a sentence naming the reason.
pub fn cannot_pack(diag: *Diag, operand: []const u8, why: []const u8) void {
    assert(diag.code == null);
    assert(why.len > 0);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, operand);
    diag.raise(.E0550);
    diag.while_("packing an image", .{});
    diag.cause("'{s}' cannot be packed: {s}", .{ echo, why });
    diag.context("source", "{s}", .{echo});
    diag.fix(.{ .sentence = "list what the store keeps:", .command = "zbx store ls" });
    assert(diag.code.? == .E0550);
}

/// ZBX-E0550 for a pack that stopped: the reason is the packer's sentence.
pub fn pack_stopped(diag: *Diag, operand: []const u8, failure: *const pack.Failure) void {
    assert(diag.code == null);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    if (failure.stop == .write) {
        diag.raise(.E0417);
        diag.while_("packing an image", .{});
        errors.cause_host_error(diag, failure.stop.sentence(), error.IoFailed, failure.errno);
        diag.context("source", "{s}", .{echo_of(&storage, operand)});
        diag.fix(.{ .sentence = "check that you can write to the store directory, and the disk" });
        return;
    }
    cannot_pack(diag, operand, failure.stop.sentence());
    diag.context("tree", "{s}", .{failure.digest.text()});
}

/// ZBX-E0557, or ZBX-E0417 when the directory could not be written.
pub fn export_stopped(diag: *Diag, dir: []const u8, failure: *const export_mod.Failure) void {
    assert(diag.code == null);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, dir);
    if (failure.stop == .write) {
        diag.raise(.E0417);
        diag.while_("writing the export directory", .{});
        var operation: [constants.arg_echo_bytes_max + 48]u8 = undefined;
        const what = std.fmt.bufPrint(&operation, "writing the export directory '{s}'", .{
            echo,
        }) catch unreachable; // Sized for the echo and the words.
        errors.cause_host_error(diag, what, failure.err, failure.errno);
        diag.context("path", "{s}", .{echo});
        diag.fix(.{ .sentence = "check that the directory's parent exists, that you can write" ++
            " there, and the disk" });
        return;
    }
    if (failure.stop == .damaged) {
        diag.raise(.E0550);
        diag.while_("writing an OCI layout", .{});
        diag.cause("stored blob {s} is damaged (not its digest) and was dropped", .{
            failure.digest.text(),
        });
        diag.context("path", "{s}", .{echo});
        diag.fix(.{ .sentence = "run the same command again, which makes the blob again" });
        return;
    }
    diag.raise(.E0557);
    diag.while_("writing an OCI layout", .{});
    const what = if (failure.stop == .not_empty) "is not empty" else "is not a directory";
    diag.cause("'{s}' {s}, and an export never writes into what is there", .{ echo, what });
    diag.context("path", "{s}", .{echo});
    diag.fix(.{ .sentence = "name a directory that does not exist, or an empty one" });
    assert(diag.code.? == .E0557);
}

/// What a registry's refusal of an upload says.
pub const Refusal = struct {
    /// The step, as a phrase: "closing the upload".
    step: []const u8,
    status: u16,
    /// The registry's own code ("BLOB_UPLOAD_INVALID"); empty for none.
    code: []const u8,
    /// A sentence about what zbx saw, for a refusal that is not a status; empty for none.
    detail: []const u8,
    retry_after: []const u8,
};

fn refusal_fix(diag: *Diag, refusal: Refusal) void {
    assert(refusal.status >= 200);
    switch (refusal.status) {
        401, 403 => diag.fix(.{ .sentence = "check the user and the password file given with" ++
            " --username and --password-file, and that they may write to this repository" }),
        429 => diag.fix(.{ .sentence = "wait, then run the same command again; what the" ++
            " registry already holds is not sent twice" }),
        else => diag.fix(.{ .sentence = "run the same command again; what the registry already" ++
            " holds is not sent twice" }),
    }
}

fn refusal_context(diag: *Diag, host: []const u8, refusal: Refusal) void {
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    diag.context("host", "{s}", .{echo_of(&storage, host)});
    diag.context("status", "{d}", .{refusal.status});
    if (refusal.code.len > 0) diag.context("code", "{s}", .{refusal.code});
    if (refusal.retry_after.len > 0) {
        diag.context("retry", "{s}", .{echo_of(&storage, refusal.retry_after)});
    }
}

/// ZBX-E0555: the registry refused a step of a blob's upload.
pub fn blob_refused(diag: *Diag, host: []const u8, digest: Sha256, refusal: Refusal) void {
    assert(diag.code == null);
    assert(refusal.step.len > 0);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const shown = echo_of(&storage, host);
    const name = digest.text();
    diag.raise(.E0555);
    diag.while_("pushing an image", .{});
    diag.cause("{s} refused {s} for blob {s}: it answered {d}", .{
        shown,
        refusal.step,
        name[0 .. "sha256:".len + 12],
        refusal.status,
    });
    if (refusal.detail.len > 0) diag.cause("{s}", .{refusal.detail});
    refusal_context(diag, host, refusal);
    diag.context("blob", "{s}", .{&name});
    refusal_fix(diag, refusal);
    assert(diag.code.? == .E0555);
}

/// What a blob that would take too many pieces is sent in.
pub const Pieces = struct {
    pieces: u64,
    chunk: u32,
};

/// ZBX-E0555: a blob would take more requests than one upload may; nothing was sent.
pub fn too_many_pieces(diag: *Diag, host: []const u8, digest: Sha256, sent: Pieces) void {
    assert(diag.code == null);
    assert(sent.pieces > constants.push_chunks_max);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const name = digest.text();
    diag.raise(.E0555);
    diag.while_("pushing an image", .{});
    diag.cause("blob {s} would go to {s} in {d} pieces of {d} bytes; zbx sends at most {d}", .{
        name[0 .. "sha256:".len + 12],
        echo_of(&storage, host),
        sent.pieces,
        sent.chunk,
        constants.push_chunks_max,
    });
    diag.context("blob", "{s}", .{&name});
    diag.context("chunk", "{d}", .{sent.chunk});
    diag.fix(.{ .sentence = "push with a larger piece size" });
    assert(diag.code.? == .E0555);
}

/// ZBX-W0552: the registry holds the image, and this host's store could not record the tag.
pub fn tag_not_recorded(diag: *Diag, destination: []const u8, failure: fs_mod.Failure) void {
    assert(diag.code == null);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const shown = echo_of(&storage, destination);
    var words: [constants.arg_echo_bytes_max + 48]u8 = undefined;
    const operation = std.fmt.bufPrint(
        &words,
        "recording '{s}' in this host's store",
        .{shown},
    ) catch "recording the tag in this host's store";
    diag.raise(.W0552);
    diag.while_("pushing an image", .{});
    errors.cause_host_error(diag, operation, failure.err, failure.errno);
    diag.context("tag", "{s}", .{shown});
    diag.fix(.{
        .sentence = "the registry has the image; fix the store, then push again to record the tag",
    });
    assert(diag.code.? == .W0552);
}

/// ZBX-E0556: the registry refused the manifest, or answered with another digest.
pub fn manifest_refused(diag: *Diag, host: []const u8, tag: []const u8, refusal: Refusal) void {
    assert(diag.code == null);
    assert(refusal.step.len > 0);
    var host_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    var tag_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const shown = echo_of(&host_storage, host);
    const tag_shown = echo_of(&tag_storage, tag);
    diag.raise(.E0556);
    diag.while_("pushing an image", .{});
    diag.cause("{s} refused the manifest for tag '{s}': it answered {d}", .{
        shown,
        tag_shown,
        refusal.status,
    });
    if (refusal.detail.len > 0) diag.cause("{s}", .{refusal.detail});
    refusal_context(diag, host, refusal);
    refusal_fix(diag, refusal);
    assert(diag.code.? == .E0556);
}

/// ZBX-E0550: a blob the push has to send is not in the store, or is not its digest.
pub fn blob_unreadable(diag: *Diag, digest: Sha256) void {
    assert(diag.code == null);
    diag.raise(.E0550);
    diag.while_("pushing an image", .{});
    diag.cause("stored blob {s} is missing or damaged", .{&digest.text()});
    diag.context("blob", "{s}", .{&digest.text()});
    diag.fix(.{ .sentence = "run the same command again, which packs the image afresh" });
    assert(diag.code.? == .E0550);
}

/// ZBX-E0551: the destination of a push is not usable.
pub fn destination_refused(diag: *Diag, operand: []const u8, why: []const u8) void {
    assert(diag.code == null);
    assert(why.len > 0);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, operand);
    diag.raise(.E0551);
    diag.cause("'{s}' cannot be pushed to: {s}", .{ echo, why });
    diag.context("dest", "{s}", .{echo});
    diag.fix(.{ .sentence = "name a registry, a repository and a tag:" ++
        " registry.example/team/app:1.0" });
    assert(diag.code.? == .E0551);
}

// ---- Credentials (slice 12) ----------------------------------------------------------------

/// ZBX-E0552: the registry wants credentials and none were given. Nothing was sent to a token
/// service.
pub fn no_credentials(diag: *Diag, host: []const u8, repository: []const u8) void {
    assert(diag.code == null);
    var host_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    var repo_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const shown = echo_of(&host_storage, host);
    diag.raise(.E0552);
    diag.while_("pushing an image", .{});
    diag.cause("{s} wants credentials to push, and none were given", .{shown});
    diag.context("host", "{s}", .{shown});
    diag.context("repo", "{s}", .{echo_of(&repo_storage, repository)});
    diag.fix(.{
        .sentence = "give a user and a password file only you can read:",
        .command = "zbx push <image> <dest> --username <user> --password-file <file>",
        .template = true,
    });
    assert(diag.code.? == .E0552);
}

/// ZBX-E0552 for an Amazon ECR registry: the push was given no AWS credentials. The library
/// reads no environment of its own, so its caller resolves them and passes the token in.
pub fn no_ecr_credentials(diag: *Diag, host: []const u8, repository: []const u8) void {
    assert(diag.code == null);
    var host_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    var repo_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const shown = echo_of(&host_storage, host);
    diag.raise(.E0552);
    diag.while_("pushing an image", .{});
    diag.cause("{s} is an Amazon ECR registry and the push was given no AWS credentials", .{shown});
    diag.context("host", "{s}", .{shown});
    diag.context("repo", "{s}", .{echo_of(&repo_storage, repository)});
    diag.fix(.{
        .sentence = "give zbx AWS credentials (zbx push finds them as zbx pull does), or call" ++
            " aws_credentials_resolve and pass the ECR token in",
    });
    assert(diag.code.? == .E0552);
}

/// ZBX-E0556 for an Amazon ECR registry that has no such repository: ECR does not create one
/// on push.
pub fn ecr_repository_missing(
    diag: *Diag,
    host: []const u8,
    repository: []const u8,
    region: []const u8,
) void {
    assert(diag.code == null);
    var host_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    var repo_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const shown = echo_of(&host_storage, host);
    const repo_shown = echo_of(&repo_storage, repository);
    diag.raise(.E0556);
    diag.while_("pushing an image", .{});
    diag.cause("{s} has no repository '{s}', and Amazon ECR does not create one on push", .{
        shown,
        repo_shown,
    });
    diag.context("host", "{s}", .{shown});
    diag.context("repo", "{s}", .{repo_shown});
    diag.context("code", "NAME_UNKNOWN", .{});
    diag.fix_with(
        "create the repository, then push again:",
        "aws ecr create-repository --repository-name {s} --region {s}",
        .{ repo_shown, region },
    );
    diag.mark_last_fix_template();
    assert(diag.code.? == .E0556);
}

/// What the registry or its token service said to the credentials.
pub const CredentialsRefusal = enum {
    /// The registry, or the realm, answered the user and password with 401 or 403.
    refused,
    /// The token the realm granted does not allow `push` to the repository (it granted `pull`).
    no_push_scope,
    /// The token service answered, and what it sent is no token.
    token_unusable,
    /// The registry's challenge is neither Basic nor Bearer, or is not there.
    no_challenge,
    /// Amazon ECR did not accept the authorization token AWS issued (it lasts 12 hours).
    ecr_refused,
    /// Amazon ECR accepted the token and the AWS identity may not push to the repository.
    ecr_no_push,
};

/// The IAM actions a push to Amazon ECR needs on the repository (`ecr:GetAuthorizationToken` is
/// separate, on `*`).
pub const ecr_push_actions = "ecr:BatchCheckLayerAvailability, ecr:InitiateLayerUpload, " ++
    "ecr:UploadLayerPart, ecr:CompleteLayerUpload, ecr:PutImage";

/// ZBX-E0553: the registry or its token service refused the credentials, or granted no push
/// scope. The username and the password are never named.
pub fn credentials_refused(
    diag: *Diag,
    host: []const u8,
    repository: []const u8,
    refusal: CredentialsRefusal,
) void {
    assert(diag.code == null);
    var host_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    var repo_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const shown = echo_of(&host_storage, host);
    const repo_shown = echo_of(&repo_storage, repository);
    diag.raise(.E0553);
    diag.while_("pushing an image", .{});
    switch (refusal) {
        .refused => diag.cause("{s} refused the credentials", .{shown}),
        .no_push_scope => diag.cause(
            "{s} would not let these credentials push to '{s}' (no 'push' scope): " ++
                "they may only pull",
            .{ shown, repo_shown },
        ),
        .token_unusable => diag.cause(
            "{s}'s token service answered with no token zbx can use",
            .{shown},
        ),
        .no_challenge => diag.cause(
            "{s} wants credentials, and asks for them in a way zbx does not speak (it speaks" ++
                " Basic and Bearer)",
            .{shown},
        ),
        .ecr_refused => diag.cause(
            "{s} did not accept the authorization token AWS issued for this push",
            .{shown},
        ),
        .ecr_no_push => diag.cause(
            "{s} would not let this AWS identity push to '{s}': it may not write to the" ++
                " repository, or the authorization token may have expired (ECR answers both" ++
                " the same way)",
            .{ shown, repo_shown },
        ),
    }
    diag.context("host", "{s}", .{shown});
    diag.context("repo", "{s}", .{repo_shown});
    if (refusal == .no_push_scope) diag.context("scope", "push", .{});
    if (refusal == .ecr_no_push) diag.context("perm", "{s}", .{ecr_push_actions});
    switch (refusal) {
        .ecr_refused => diag.fix(.{
            .sentence = "run the command again, and check that the AWS credentials are current" ++
                " and belong to the account that owns the registry",
        }),
        .ecr_no_push => diag.fix(.{
            .sentence = "run the command again, which fetches a fresh token (it lasts 12 hours);" ++
                " if it is refused again, allow ecr:BatchCheckLayerAvailability," ++
                " ecr:InitiateLayerUpload, ecr:UploadLayerPart, ecr:CompleteLayerUpload and" ++
                " ecr:PutImage on the repository in the role's policy",
        }),
        .no_push_scope => diag.fix(.{
            .sentence = "use credentials that may push to this repository (a token with write" ++
                " access), or push to a repository you own",
        }),
        else => diag.fix(.{
            .sentence = "check the user and the password file; many registries want an access" ++
                " token, not an account password",
        }),
    }
    assert(diag.code.? == .E0553);
}

/// Why a realm may not be sent the password.
pub const RealmProblem = enum {
    /// The realm is on a host that is neither the registry's nor a known pair.
    other_host,
    /// The realm is not a URL zbx can use.
    not_a_url,
    /// The realm is plain `http` and not on loopback.
    plain_http,
};

/// ZBX-E0554: the token service a registry named may not be sent the password. `realm` is the
/// realm's host for `other_host` and `plain_http`, and the realm's text for `not_a_url`.
pub fn realm_refused(
    diag: *Diag,
    registry: []const u8,
    realm: []const u8,
    problem: RealmProblem,
) void {
    assert(diag.code == null);
    var registry_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    var realm_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const shown = echo_of(&registry_storage, registry);
    const realm_shown = echo_of(&realm_storage, realm);
    diag.raise(.E0554);
    diag.while_("pushing an image", .{});
    switch (problem) {
        .other_host => diag.cause(
            "{s} named the token service {s}, which is not {s}, nor a service it is known to" ++
                " use; the password was not sent",
            .{ shown, realm_shown, shown },
        ),
        .not_a_url => diag.cause(
            "{s} named a token service '{s}', which is not a URL zbx can use; the password" ++
                " was not sent",
            .{ shown, realm_shown },
        ),
        .plain_http => diag.cause(
            "{s} named the token service {s} over plain http, which zbx speaks only on" ++
                " loopback; the password was not sent",
            .{ shown, realm_shown },
        ),
    }
    diag.context("host", "{s}", .{shown});
    diag.context("realm", "{s}", .{realm_shown});
    diag.fix(.{ .sentence = switch (problem) {
        .other_host => "push to a registry whose token service is on its own host; zbx sends a" ++
            " password only there",
        .not_a_url => "ask the registry's operator to name its token service by an https URL;" ++
            " zbx cannot push to it as it is",
        .plain_http => "ask the registry's operator to serve its token service over https;" ++
            " zbx sends a password only over TLS",
    } });
    assert(diag.code.? == .E0554);
}

/// What is wrong with the password file or the standard input, for E0558.
pub const PasswordProblem = enum {
    /// The file can be read by group or others.
    file_too_open,
    /// The first line, with the user name, is longer than `push_credential_bytes_max`.
    too_long,
    empty,
    file_missing,
    file_unreadable,
    file_is_link,
    /// Standard input is a terminal: a password typed there would show.
    stdin_is_terminal,
    stdin_unreadable,
    /// A user name with a colon cannot be sent with Basic authentication.
    user_has_colon,
};

/// ZBX-E0558: the password file is unsafe or unusable. `path` is empty for standard input. The
/// password itself is never an argument.
pub fn password_unsafe(diag: *Diag, path: []const u8, problem: PasswordProblem) void {
    assert(diag.code == null);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const shown = echo_of(&storage, path);
    diag.raise(.E0558);
    diag.while_("reading the password for a push", .{});
    switch (problem) {
        .file_too_open => diag.cause("{s} can be read by other users", .{shown}),
        .too_long => diag.cause(
            "the user and the password are over {d} bytes together",
            .{constants.push_credential_bytes_max},
        ),
        .empty => diag.cause("the password is empty; a password needs at least one character", .{}),
        .file_missing => diag.cause("there is no file {s}", .{shown}),
        .file_unreadable => diag.cause("{s} could not be read", .{shown}),
        .file_is_link => diag.cause(
            "{s} is a symbolic link; name the file it points to instead",
            .{shown},
        ),
        .stdin_is_terminal => diag.cause(
            "standard input is a terminal, where the password would show as it is typed",
            .{},
        ),
        .stdin_unreadable => diag.cause("standard input could not be read", .{}),
        .user_has_colon => diag.cause(
            "the user name has a ':', which Basic login cannot carry",
            .{},
        ),
    }
    if (path.len > 0) diag.context("path", "{s}", .{shown});
    switch (problem) {
        .file_too_open => diag.fix_with("make it private to you:", "chmod 600 {s}", .{shown}),
        .stdin_is_terminal => diag.fix(.{
            .sentence = "pipe the password in, or give a file only you can read:",
            .command = "zbx push <image> <dest> --username <user> --password-file <file>",
            .template = true,
        }),
        else => diag.fix(.{
            .sentence = "give the password as the first line of a file only you can read:",
            .command = "zbx push <image> <dest> --username <user> --password-file <file>",
            .template = true,
        }),
    }
    assert(diag.code.? == .E0558);
}
