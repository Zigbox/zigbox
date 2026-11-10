//! The ECR step of a push (M8 slice 13): for a destination on a private Amazon ECR host, ask ECR
//! for an authorization token with the AWS credentials the caller gave, and hold it in the
//! caller's `Workspace` to be handed to the upload as `Options.ecr_token` (it is sent as `Basic`
//! to the registry's own origin, and to no other: `upload.zig`). For any other host this does
//! nothing and the push is what it was.
//!
//! The token is a secret: it is in no diagnostic, log or output, and `wipe` zeroes it. The
//! upload copies it into its own workspace, which it zeroes when the push ends, so the caller's
//! copy is the caller's to wipe. Credentials are never looked for here: the command line resolves
//! them (`store_commands.zig`) and the library's caller does so with `aws_credentials_resolve`.
//! ECR creates no repository on push, so the push does not either (E0556).

const std = @import("std");
const assert = std.debug.assert;
const aws_diagnose = @import("../aws/diagnose.zig");
const constants = @import("../constants.zig");
const credentials_mod = @import("../aws/credentials.zig");
const diagnose = @import("diagnose.zig");
const ecr = @import("../aws/ecr.zig");
const ecr_login = @import("../registry/ecr_login.zig");
const ecr_token = @import("../aws/ecr_token.zig");
const host_mod = @import("../host.zig");
const Diag = @import("../diag/diag.zig").Diag;

pub const Error = error{Failed};

comptime {
    assert(constants.aws_response_bytes_max >= constants.aws_ecr_token_bytes_max * 2);
    assert(constants.aws_ecr_token_bytes_max <= constants.push_basic_bytes_max);
}

/// The memory the token request works in, and the token it gives. About 28 KiB.
pub const Workspace = struct {
    response: [constants.aws_response_bytes_max]u8,
    token: [constants.aws_ecr_token_bytes_max]u8,
    token_len: u32,

    pub fn reset(workspace: *Workspace) void {
        workspace.token_len = 0;
    }

    /// The token, empty when the destination is not a private ECR host.
    pub fn text(workspace: *const Workspace) []const u8 {
        assert(workspace.token_len <= workspace.token.len);
        return workspace.token[0..workspace.token_len];
    }

    pub fn wipe(workspace: *Workspace) void {
        std.crypto.secureZero(u8, &workspace.response);
        std.crypto.secureZero(u8, &workspace.token);
        workspace.token_len = 0;
        assert(workspace.token[0] == 0);
    }
};

/// Whether `registry` is a private ECR host zbx signs for: a push to it needs AWS credentials.
pub fn needs_aws(registry: []const u8) bool {
    return switch (ecr.classify(registry)) {
        .private => true,
        .other, .public, .unsupported => false,
    };
}

/// Gives `workspace` the ECR authorization token for `registry` when it is a private ECR host,
/// using `aws`; any other host is left alone (the token stays empty). An ECR host of a kind zbx
/// does not sign for, or a private one with no credentials given, is a coded refusal.
pub fn authorize(
    host: host_mod.Host,
    aws: ?*const credentials_mod.Credentials,
    registry: []const u8,
    repository: []const u8,
    workspace: *Workspace,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    assert(registry.len > 0);
    workspace.reset();
    const private = switch (ecr.classify(registry)) {
        .other, .public => return,
        .unsupported => {
            aws_diagnose.unsupported_host(diag, registry);
            return error.Failed;
        },
        .private => |found| found,
    };
    const given = aws orelse {
        diagnose.no_ecr_credentials(diag, registry, repository);
        return error.Failed;
    };
    var failure: ecr_token.Failure = undefined;
    const length = ecr_token.fetch(
        host,
        private.region,
        given.key(),
        host.time_now(),
        &workspace.response,
        &workspace.token,
        &failure,
    ) catch {
        workspace.wipe();
        ecr_login.failed(host, given, private.region, &failure, diag);
        return error.Failed;
    };
    assert(length > 0);
    assert(length <= workspace.token.len);
    workspace.token_len = length;
}
