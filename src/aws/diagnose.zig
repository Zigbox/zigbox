//! The AWS side of an ECR pull's diagnostics (ZBX-E0527 to E0534): each function raises one
//! registered code and fills in the causes, context and fixes (DIAGNOSTICS.md). What an AWS
//! service said is shown only as its error code name; its message and body are never an argument
//! here, and neither is a key, a token or a password.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const credentials_mod = @import("credentials.zig");
const ecr_token = @import("ecr_token.zig");
const text_util = @import("../text.zig");
const Diag = @import("../diag/diag.zig").Diag;

const State = credentials_mod.State;
const Trace = credentials_mod.Trace;

const echo_bytes_max = 96;

fn echo_of(storage: *[echo_bytes_max]u8, text: []const u8) []const u8 {
    assert(text.len <= constants.path_bytes_max);
    return text_util.sanitise(storage, text);
}

/// The word for where credentials came from.
pub fn source_text(source: credentials_mod.Source) []const u8 {
    return switch (source) {
        .environment => "the environment's keys",
        .web_identity => "the web identity's role",
        .instance_metadata => "the instance's role",
    };
}

/// What a source did, in a few words for the context line.
fn state_text(state: State, status: u16) []const u8 {
    assert(status <= 599);
    return switch (state) {
        .not_configured => "not set",
        .incomplete => "only part of it is set",
        .v1_only => if (status == 403)
            "the token request was refused (403), a proxy or version 1 only"
        else
            "it gives no version 2 token (version 1 only)",
        .no_role => "answered, with no role attached to the instance",
        .disabled => "switched off by AWS_EC2_METADATA_DISABLED",
        .used => "used",
        .unreadable => "the token file can't be read",
        .refused => "refused",
        .no_answer => "no answer",
        .malformed => "not usable",
        .expired => "expired",
    };
}

/// ZBX-E0527: the three sources gave no credentials. `trace` says what each did.
pub fn no_credentials(diag: *Diag, registry: []const u8, trace: *const Trace) void {
    assert(diag.code == null);
    var storage: [echo_bytes_max]u8 = undefined;
    const shown = echo_of(&storage, registry);
    diag.raise(.E0527);
    diag.cause("no AWS credentials were found to pull from {s}", .{shown});
    diag.context("host", "{s}", .{shown});
    diag.context("env", "{s}", .{state_text(trace.environment, trace.status)});
    diag.context("web", "{s}", .{state_text(trace.web_identity, trace.status)});
    diag.context("imds", "{s}", .{state_text(trace.instance_metadata, trace.status)});
    fixes_for_none(diag, trace);
    assert(diag.code != null);
}

fn fixes_for_none(diag: *Diag, trace: *const Trace) void {
    assert(diag.code != null);
    if (trace.environment == .incomplete or trace.environment == .malformed) {
        diag.fix(.{ .sentence = "set both AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, whole" });
    } else if (trace.instance_metadata == .no_role) {
        diag.fix(.{
            .sentence = "attach an IAM role to this instance, or pass keys in the environment",
        });
    } else if (trace.instance_metadata == .v1_only) {
        diag.fix(.{
            .sentence = "make the instance metadata service answer version 2 (zbx never uses 1)",
        });
    } else {
        diag.fix(.{
            .sentence = "set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY (and AWS_SESSION_TOKEN)",
        });
    }
    diag.fix(.{
        .sentence = "or set AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE for a web identity",
    });
    diag.fix(.{
        .sentence = "or export the keys of a profile first:",
        .command = "export $(aws configure export-credentials --format env)",
    });
}

/// ZBX-E0527, for a caller that gave the pull no credentials at all (the library's pull, which
/// reads no environment of its own).
pub fn none_given(diag: *Diag, registry: []const u8) void {
    assert(diag.code == null);
    var storage: [echo_bytes_max]u8 = undefined;
    const shown = echo_of(&storage, registry);
    diag.raise(.E0527);
    diag.cause("{s} is an Amazon ECR registry and the pull was given no AWS credentials", .{shown});
    diag.context("host", "{s}", .{shown});
    diag.fix(.{
        .sentence = "resolve credentials first (aws_credentials_resolve) and give them to the pull",
    });
    assert(diag.code != null);
}

/// ZBX-E0533: the web identity token file could not be used.
pub fn web_identity_file(diag: *Diag, path: []const u8) void {
    assert(diag.code == null);
    var storage: [echo_bytes_max]u8 = undefined;
    const shown = echo_of(&storage, path);
    diag.raise(.E0533);
    diag.cause(
        "AWS_WEB_IDENTITY_TOKEN_FILE ({s}) can't be read, or holds no token",
        .{shown},
    );
    diag.context("var", "AWS_WEB_IDENTITY_TOKEN_FILE", .{});
    diag.fix(.{
        .sentence = "check that the file exists, is readable by this user, and is not empty",
    });
    diag.fix(.{ .sentence = "in GitHub Actions the job needs 'permissions: id-token: write'" });
    assert(diag.code != null);
}

/// ZBX-E0528: AWS refused the credentials; `code` is its error code name (maybe empty).
pub fn refused(diag: *Diag, source: credentials_mod.Source, status: u16, code: []const u8) void {
    assert(diag.code == null);
    assert(status <= 599);
    var storage: [echo_bytes_max]u8 = undefined;
    const name = echo_of(&storage, code);
    diag.raise(.E0528);
    if (name.len > 0) {
        diag.cause("AWS refused {s}: {s}", .{ source_text(source), name });
    } else {
        diag.cause("AWS refused {s} (status {d})", .{ source_text(source), status });
    }
    diag.context("status", "{d}", .{status});
    if (name.len > 0) diag.context("aws", "{s}", .{name});
    diag.fix(.{ .sentence = "check that the keys are current: temporary keys expire" });
    diag.fix(.{ .sentence = "get new credentials, then run the command again" });
    assert(diag.code != null);
}

/// ZBX-E0528 for a web identity or a metadata service that was set up and then refused or gave
/// credentials already out of date; the trace says which.
pub fn source_failed(diag: *Diag, trace: *const Trace) void {
    assert(diag.code == null);
    const source: credentials_mod.Source = if (trace.web_identity != .not_configured)
        .web_identity
    else
        .instance_metadata;
    refused(diag, source, trace.status, trace.code());
}

/// ZBX-E0529: the signature's time is too far from AWS's.
pub fn clock_skew(diag: *Diag, host: []const u8) void {
    assert(diag.code == null);
    var storage: [echo_bytes_max]u8 = undefined;
    const shown = echo_of(&storage, host);
    diag.raise(.E0529);
    diag.cause("{s} refused the request: this machine's clock is too far from AWS's", .{shown});
    diag.context("host", "{s}", .{shown});
    diag.fix(.{ .sentence = "set the clock right, then run the command again" });
    diag.fix(.{
        .sentence = "turn on time synchronisation:",
        .command = "timedatectl set-ntp true",
        .needs_root = true,
    });
    assert(diag.code != null);
}

/// ZBX-E0530: the identity may not call `ecr:GetAuthorizationToken`.
pub fn token_denied(diag: *Diag, code: []const u8) void {
    assert(diag.code == null);
    var storage: [echo_bytes_max]u8 = undefined;
    const name = echo_of(&storage, code);
    diag.raise(.E0530);
    diag.cause("the AWS identity may not call ecr:GetAuthorizationToken", .{});
    if (name.len > 0) diag.context("aws", "{s}", .{name});
    diag.context("perm", "ecr:GetAuthorizationToken", .{});
    diag.fix(.{
        .sentence = "allow ecr:GetAuthorizationToken on resource \"*\" in the role's policy",
    });
    assert(diag.code != null);
}

/// ZBX-E0534: the host is an ECR host of a kind zbx does not sign for.
pub fn unsupported_host(diag: *Diag, registry: []const u8) void {
    assert(diag.code == null);
    var storage: [echo_bytes_max]u8 = undefined;
    const shown = echo_of(&storage, registry);
    diag.raise(.E0534);
    diag.cause("{s} is an Amazon ECR host of a kind zbx does not support yet", .{shown});
    diag.context("host", "{s}", .{shown});
    diag.fix(.{
        .sentence = "use <account>.dkr.ecr.<region>.amazonaws.com in the standard AWS partition",
    });
    assert(diag.code != null);
}

/// ZBX-E0534: the region of the host is not one the resolver signs for.
pub fn unsupported_region(diag: *Diag, registry: []const u8, reason: []const u8) void {
    assert(diag.code == null);
    var storage: [echo_bytes_max]u8 = undefined;
    const shown = echo_of(&storage, registry);
    diag.raise(.E0534);
    diag.cause("{s}: {s}", .{ shown, reason });
    diag.context("host", "{s}", .{shown});
    diag.fix(.{
        .sentence = "use <account>.dkr.ecr.<region>.amazonaws.com in the standard AWS partition",
    });
    assert(diag.code != null);
}

test "a failure's code name is the only AWS text in a diagnostic" {
    // Goal: AWS's message never reaches a diagnostic. Method: build each AWS diagnostic from a
    // code name and look for what no one may print.
    var diag: Diag = undefined;
    diag.reset();
    refused(&diag, .environment, 400, "ExpiredTokenException");
    try std.testing.expectEqual(@as(?@import("../diag/codes.zig").Code, .E0528), diag.code);
    var trace: Trace = .{};
    trace.instance_metadata = .v1_only;
    trace.status = 404;
    diag.reset();
    no_credentials(&diag, "123456789012.dkr.ecr.us-east-1.amazonaws.com", &trace);
    try std.testing.expect(diag.last_cause() != null);
    _ = ecr_token.target_name;
}
