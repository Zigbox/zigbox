//! The Google side of a pull's diagnostics (ZBX-E0560 to E0572): each function raises one
//! registered code and fills in the causes, context and fixes (DIAGNOSTICS.md). What a Google
//! service said is shown only as its error code (`invalid_grant`, `PERMISSION_DENIED`,
//! `DENIED`); its message and body are never an argument here, and neither is a token. The
//! permission a fix names comes from a fixed table, never from the message.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const credentials_mod = @import("credentials.zig");
const parse = @import("parse.zig");
const text_util = @import("../text.zig");
const Diag = @import("../diag/diag.zig").Diag;

const State = credentials_mod.State;
const MetadataState = credentials_mod.MetadataState;
const Trace = credentials_mod.Trace;

const echo_bytes_max = 96;

pub const credentials_variable = "GOOGLE_APPLICATION_CREDENTIALS";
/// The permission a pull needs on an Artifact Registry repository.
pub const download_permission = "artifactregistry.repositories.downloadArtifacts";
/// The permission impersonation needs on the service account.
pub const impersonation_permission = "iam.serviceAccounts.getAccessToken";
pub const supported_hosts = "<region>-docker.pkg.dev, gcr.io, us.gcr.io, eu.gcr.io, asia.gcr.io";

const fix_federation = "point GOOGLE_APPLICATION_CREDENTIALS at a workload identity " ++
    "federation file";

fn echo_of(storage: *[echo_bytes_max]u8, text: []const u8) []const u8 {
    assert(text.len <= constants.path_bytes_max);
    return text_util.sanitise(storage, text);
}

/// What workload identity federation did, in a few words for the context line.
fn workload_text(state: State) []const u8 {
    return switch (state) {
        .not_configured => "GOOGLE_APPLICATION_CREDENTIALS is not set",
        .not_asked => "not asked",
        .unreadable => "the credentials file can't be read",
        .unsupported => "the credentials file is not supported",
        .subject_unreadable => "the subject token can't be read",
        .refused => "refused",
        .no_answer => "no answer",
        .malformed => "not usable",
        .expired => "expired",
        .used => "used",
    };
}

/// What the metadata server did, in a few words for the context line.
fn metadata_text(state: MetadataState) []const u8 {
    return switch (state) {
        .not_asked => "not asked",
        .absent => "absent (not on Google Compute Engine)",
        .not_gce => "something answered that is not Google Compute Engine",
        .no_service_account => "no service account is attached to the instance",
        .refused => "refused",
        .malformed => "not usable",
        .expired => "expired",
        .used => "used",
    };
}

/// ZBX-E0560: neither source gave an access token, and the registry refused an anonymous pull.
pub fn no_credentials(diag: *Diag, registry: []const u8, trace: *const Trace) void {
    assert(diag.code == null);
    assert(trace.workload_identity != .used);
    var storage: [echo_bytes_max]u8 = undefined;
    const shown = echo_of(&storage, registry);
    diag.raise(.E0560);
    diag.cause("no Google credentials were found to pull from {s}", .{shown});
    diag.context("host", "{s}", .{shown});
    diag.context("wif", "{s}", .{workload_text(trace.workload_identity)});
    diag.context("gce", "{s}", .{metadata_text(trace.metadata)});
    if (trace.metadata == .no_service_account) {
        diag.fix(.{ .sentence = "attach a service account that may read the repository " ++
            "to this instance" });
        diag.fix(.{ .sentence = "or " ++ fix_federation });
    } else {
        diag.fix(.{ .sentence = fix_federation });
        diag.fix(.{ .sentence = "or pull on Google Compute Engine with a service account" });
    }
    assert(diag.code != null);
}

/// ZBX-E0560, for a caller that gave the pull no Google access token (the library's pull, which
/// reads no environment of its own), or one that left workload identity out of its sources
/// while GOOGLE_APPLICATION_CREDENTIALS is set (`not_asked`).
pub fn none_given(diag: *Diag, registry: []const u8, variable_set: bool) void {
    assert(diag.code == null);
    assert(registry.len > 0);
    var storage: [echo_bytes_max]u8 = undefined;
    const shown = echo_of(&storage, registry);
    diag.raise(.E0560);
    if (variable_set) {
        diag.cause("GOOGLE_APPLICATION_CREDENTIALS is set, and the pull did not ask for " ++
            "workload identity", .{});
    } else {
        diag.cause("{s} refused an anonymous pull, and the pull was given no Google " ++
            "credentials", .{shown});
    }
    diag.context("host", "{s}", .{shown});
    diag.fix(.{ .sentence = "a library caller resolves a token with " ++
        "google_credentials_resolve and passes it in" });
    assert(diag.code != null);
}

/// ZBX-E0561: the credentials file can't be read, or is larger than its bound.
pub fn file_unreadable(diag: *Diag, path: []const u8) void {
    assert(diag.code == null);
    assert(path.len <= constants.path_bytes_max);
    var storage: [echo_bytes_max]u8 = undefined;
    const shown = echo_of(&storage, path);
    diag.raise(.E0561);
    diag.cause("GOOGLE_APPLICATION_CREDENTIALS ({s}) can't be read, or is larger than {d} bytes", .{
        shown,
        constants.google_credentials_file_bytes_max,
    });
    diag.context("var", "{s}", .{credentials_variable});
    diag.context("max", "{d} bytes", .{constants.google_credentials_file_bytes_max});
    diag.fix(.{ .sentence = "check that the file exists and is readable by this user" });
    assert(diag.code != null);
}

/// ZBX-E0562: the credentials file is a service-account key, which zbx does not use.
pub fn key_file(diag: *Diag, path: []const u8) void {
    assert(diag.code == null);
    assert(path.len <= constants.path_bytes_max);
    var storage: [echo_bytes_max]u8 = undefined;
    const shown = echo_of(&storage, path);
    diag.raise(.E0562);
    diag.cause("{s} is a service account key file; zbx does not use key files", .{shown});
    diag.context("var", "{s}", .{credentials_variable});
    diag.fix(.{ .sentence = "use workload identity federation: an external_account file, " ++
        "with no key" });
    diag.fix(.{ .sentence = "then delete the key: anyone who has it is the service account" });
    assert(diag.code != null);
}

/// What an unsupported credentials file has that zbx does not use.
fn unsupported_text(reason: parse.Refusal) []const u8 {
    return switch (reason) {
        .malformed => "it is not an external_account file zbx can read " ++
            "(a value with JSON escapes is not supported)",
        .service_account_key, .workforce_pool => unreachable, // Codes of their own.
        .authorized_user => "it holds gcloud user credentials (authorized_user)",
        .other_type => "its type is not external_account",
        .token_url => "its token_url is not https://sts.googleapis.com/v1/token",
        .impersonation_url => "its service_account_impersonation_url is not " ++
            "iamcredentials.googleapis.com's generateAccessToken",
        .universe_domain => "its universe_domain is not googleapis.com",
        .executable => "its credential_source is an executable",
        .aws => "its credential_source is AWS (environment_id)",
        .certificate => "its credential_source is a certificate",
        .plain_http_url => "its credential_source.url is plain HTTP",
        .no_source => "its credential_source has neither a file nor a url",
    };
}

/// ZBX-E0563: the credentials file is one zbx does not support; `trace` says why.
pub fn unsupported_file(diag: *Diag, path: []const u8, trace: *const Trace) void {
    assert(diag.code == null);
    assert(trace.workload_identity == .unsupported);
    var storage: [echo_bytes_max]u8 = undefined;
    const shown = echo_of(&storage, path);
    var type_storage: [echo_bytes_max]u8 = undefined;
    const type_name = echo_of(&type_storage, trace.file_type());
    diag.raise(.E0563);
    diag.cause("{s} can't be used: {s}", .{ shown, unsupported_text(trace.unsupported) });
    diag.context("var", "{s}", .{credentials_variable});
    if (type_name.len > 0) diag.context("type", "{s}", .{type_name});
    diag.fix(.{ .sentence = "use an external_account file with a credential_source file " ++
        "or HTTPS url" });
    assert(diag.code != null);
}

/// ZBX-E0564: the subject token could not be read from its file or URL, or is empty.
pub fn subject_unreadable(diag: *Diag, source: parse.SourceKind, status: u16) void {
    assert(diag.code == null);
    assert(status <= 599);
    diag.raise(.E0564);
    const where: []const u8 = if (source == .file) "file" else "url";
    diag.cause("the subject token from the credential_source {s} can't be read, or is empty, " ++
        "or is larger than {d} bytes", .{ where, constants.google_subject_token_bytes_max });
    diag.context("source", "{s}", .{where});
    if (status != 0) diag.context("status", "{d}", .{status});
    diag.fix(.{ .sentence = "check that the token is there and current: an OIDC token " ++
        "lasts minutes" });
    diag.fix(.{ .sentence = "in GitHub Actions the job needs 'permissions: id-token: write'" });
    assert(diag.code != null);
}

/// ZBX-E0565: STS refused the token exchange; `code` is Google's error code (maybe empty).
pub fn exchange_refused(diag: *Diag, status: u16, code: []const u8) void {
    assert(diag.code == null);
    assert(status <= 599);
    var storage: [echo_bytes_max]u8 = undefined;
    const name = echo_of(&storage, code);
    diag.raise(.E0565);
    if (name.len > 0) {
        diag.cause("sts.googleapis.com refused the token exchange: {s}", .{name});
    } else diag.cause("sts.googleapis.com refused the token exchange (status {d})", .{status});
    diag.context("status", "{d}", .{status});
    if (name.len > 0) diag.context("google", "{s}", .{name});
    diag.fix(.{ .sentence = "check the provider's audience and attribute condition " ++
        "against the subject token" });
    assert(diag.code != null);
}

/// ZBX-E0566: IAM Credentials refused to impersonate the service account.
pub fn impersonation_refused(diag: *Diag, trace: *const Trace) void {
    assert(diag.code == null);
    assert(trace.step == .impersonation);
    var storage: [echo_bytes_max]u8 = undefined;
    const name = echo_of(&storage, trace.code());
    var account_storage: [echo_bytes_max]u8 = undefined;
    const account = echo_of(&account_storage, trace.account());
    diag.raise(.E0566);
    diag.cause("the federated identity may not impersonate {s}", .{account});
    diag.context("status", "{d}", .{trace.status});
    if (name.len > 0) diag.context("google", "{s}", .{name});
    diag.context("perm", "{s}", .{impersonation_permission});
    diag.fix(.{ .sentence = "grant the pool's principal roles/iam.workloadIdentityUser " ++
        "on the service account" });
    assert(diag.code != null);
}

/// ZBX-E0567: the registry refused the access token, or it ran out before it was sent.
pub fn token_refused(diag: *Diag, registry: []const u8, expired: bool) void {
    assert(diag.code == null);
    assert(registry.len > 0);
    var storage: [echo_bytes_max]u8 = undefined;
    const shown = echo_of(&storage, registry);
    diag.raise(.E0567);
    if (expired) {
        diag.cause("the Google access token for {s} expired before it was sent", .{shown});
    } else diag.cause("{s} refused the Google access token", .{shown});
    diag.context("host", "{s}", .{shown});
    diag.fix(.{ .sentence = "get a new access token, then run the command again" });
    diag.fix(.{ .sentence = "check that this machine's clock is right" });
    assert(diag.code != null);
}

/// ZBX-E0568: the identity may not read the repository, or the repository does not exist (the
/// registry answers the two alike).
pub fn repository_denied(diag: *Diag, registry: []const u8, repository: []const u8) void {
    assert(diag.code == null);
    assert(repository.len > 0);
    var storage: [echo_bytes_max]u8 = undefined;
    const shown = echo_of(&storage, registry);
    var repository_storage: [echo_bytes_max]u8 = undefined;
    const repo = echo_of(&repository_storage, repository);
    diag.raise(.E0568);
    diag.cause("{s} denied the pull of {s}: the identity lacks {s}, or the repository does " ++
        "not exist", .{ shown, repo, download_permission });
    diag.context("host", "{s}", .{shown});
    diag.context("repo", "{s}", .{repo});
    diag.context("perm", "{s}", .{download_permission});
    diag.fix(.{ .sentence = "grant roles/artifactregistry.reader on the repository " ++
        "to the identity" });
    diag.fix(.{ .sentence = "and check the repository's name and region" });
    assert(diag.code != null);
}

/// ZBX-E0569: the registry says the repository does not exist (`NAME_UNKNOWN`).
pub fn repository_missing(
    diag: *Diag,
    registry: []const u8,
    repository: []const u8,
    gcr: bool,
) void {
    assert(diag.code == null);
    assert(repository.len > 0);
    var storage: [echo_bytes_max]u8 = undefined;
    const shown = echo_of(&storage, registry);
    var repository_storage: [echo_bytes_max]u8 = undefined;
    const repo = echo_of(&repository_storage, repository);
    diag.raise(.E0569);
    diag.cause("{s} has no repository {s}", .{ shown, repo });
    diag.context("host", "{s}", .{shown});
    diag.context("repo", "{s}", .{repo});
    if (gcr) {
        diag.fix(.{ .sentence = "the project needs an Artifact Registry repository named " ++
            "gcr.io, in the host's location" });
    } else diag.fix(.{ .sentence = "check the project, the repository's name and the region" });
    assert(diag.code != null);
}

/// ZBX-E0570: a Google registry host zbx does not authenticate to refused an anonymous pull.
pub fn unsupported_host(diag: *Diag, registry: []const u8) void {
    assert(diag.code == null);
    assert(registry.len > 0);
    var storage: [echo_bytes_max]u8 = undefined;
    const shown = echo_of(&storage, registry);
    diag.raise(.E0570);
    diag.cause("{s} refused an anonymous pull, and zbx sends Google credentials only to " ++
        "the supported hosts", .{shown});
    diag.context("host", "{s}", .{shown});
    diag.context("hosts", "{s}", .{supported_hosts});
    diag.fix(.{ .sentence = "pull from one of " ++ supported_hosts });
    assert(diag.code != null);
}

/// ZBX-E0571: the credentials file's audience is a workforce pool.
pub fn workforce_pool(diag: *Diag, path: []const u8) void {
    assert(diag.code == null);
    assert(path.len <= constants.path_bytes_max);
    var storage: [echo_bytes_max]u8 = undefined;
    const shown = echo_of(&storage, path);
    diag.raise(.E0571);
    diag.cause("{s} names a workforce pool; zbx supports workload identity pools only", .{shown});
    diag.context("var", "{s}", .{credentials_variable});
    diag.fix(.{ .sentence = "use a workload identity pool's provider as the audience" });
    assert(diag.code != null);
}

/// Which credential service a failure was at.
pub const Service = enum { subject_url, sts, iam, metadata };

fn service_text(service: Service) []const u8 {
    return switch (service) {
        .subject_url => "the subject token URL",
        .sts => "sts.googleapis.com",
        .iam => "iamcredentials.googleapis.com",
        .metadata => "the metadata server",
    };
}

/// What went wrong with a credential service.
pub const Failure = enum { no_answer, refused, malformed, expired };

/// ZBX-E0572: a credential service did not answer, refused with no more to say, or answered
/// with a token that is not usable or already out of date.
pub fn service_failed(diag: *Diag, service: Service, failure: Failure, status: u16) void {
    assert(diag.code == null);
    assert(status <= 599);
    diag.raise(.E0572);
    const what = service_text(service);
    switch (failure) {
        .no_answer => diag.cause("{s} did not answer", .{what}),
        .refused => diag.cause("{s} refused the request (status {d})", .{ what, status }),
        .malformed => diag.cause("{s} answered with no usable token", .{what}),
        .expired => diag.cause("{s} answered with a token already out of date", .{what}),
    }
    diag.context("step", "{s}", .{what});
    if (status != 0) diag.context("status", "{d}", .{status});
    if (failure == .expired) diag.fix(.{ .sentence = "check that this machine's clock is right" });
    diag.fix(.{ .sentence = "run the command again; if it repeats, the service or a proxy " ++
        "is at fault" });
    assert(diag.code != null);
}

test "a failure's code is the only Google text in a diagnostic" {
    // Goal: Google's message never reaches a diagnostic. Method: build the diagnostics that carry
    // a code and check the code is there and nothing else was asked for.
    var diag: Diag = undefined;
    diag.reset();
    exchange_refused(&diag, 400, "invalid_grant");
    try std.testing.expectEqual(@as(?@import("../diag/codes.zig").Code, .E0565), diag.code);
    var trace: Trace = .{};
    trace.metadata = .absent;
    diag.reset();
    no_credentials(&diag, "us-docker.pkg.dev", &trace);
    try std.testing.expect(diag.last_cause() != null);
}
