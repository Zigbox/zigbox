//! The command line's Google step of a pull (M6d, slice 2): for an Artifact Registry or gcr.io
//! reference, find the access token and hand it to the library's pull. For any other host it does
//! nothing and reads nothing.
//!
//! With `GOOGLE_APPLICATION_CREDENTIALS` naming an `external_account` file, workload identity
//! federation is asked up front and its answer is the answer. A file that cannot be read or is not
//! one zbx uses asks nothing of the network: the pull goes anonymously, as 0.5.2's did, and the
//! file's refusal is raised only when the registry's realm refuses (`fallback_for`). Without the
//! variable, the pull goes anonymously, and the metadata server is asked once, only when the
//! realm refuses. The metadata server is never asked while the variable is set. The token is
//! looked up for every pull, never cached, and wiped when the command ends (`Storage.wipe`). A
//! failure is a coded diagnostic built from the resolver's trace, never a token or a Google
//! message.

const std = @import("std");
const assert = std.debug.assert;
const client_mod = @import("registry/client.zig");
const credentials_mod = @import("google/credentials.zig");
const diagnose = @import("google/diagnose.zig");
const hosts = @import("google/hosts.zig");
const host_mod = @import("host.zig");
const Diag = @import("diag/diag.zig").Diag;

pub const Error = error{Failed};

/// What the token is found in and kept in. Static storage; wiped by the caller.
pub const Storage = struct {
    pairs: [credentials_mod.Env.names.len]credentials_mod.Env.Pair,
    workspace: credentials_mod.Workspace,
    token: credentials_mod.Token,
    trace: credentials_mod.Trace,
    /// The host the fallback asks through; set by `fallback_for`.
    host: host_mod.Host,
    /// The credentials file was refused before any request (`trace` says why): the refusal is
    /// raised by the fallback, only if the anonymous pull is refused. Set by `token_for`.
    file_deferred: bool,

    pub fn wipe(storage: *Storage) void {
        storage.workspace.wipe();
        storage.token.wipe();
        // The pairs point into the host's environment, which is not ours to zero.
        assert(storage.token.len == 0);
    }
};

/// The token for a pull from `registry` when workload identity is set up: null when the host is
/// not a credentialed Google host or `GOOGLE_APPLICATION_CREDENTIALS` is not set (nothing was
/// asked), or when its file cannot be read or is not one zbx uses (`file_deferred`); the token in
/// `storage` when it is.
pub fn token_for(
    host: host_mod.Host,
    registry: []const u8,
    storage: *Storage,
    diag: *Diag,
) Error!?*const credentials_mod.Token {
    assert(diag.code == null);
    assert(registry.len > 0);
    storage.file_deferred = false;
    if (!hosts.classify(registry).credentialed()) return null;
    const env = credentials_mod.Env.from_host(host, &storage.pairs);
    if (env.get(credentials_mod.credentials_variable) == null) return null;
    const sources: credentials_mod.Sources = .{ .workload_identity = true };
    credentials_mod.resolve(
        host,
        env,
        host.time_now(),
        sources,
        &storage.workspace,
        &storage.token,
        &storage.trace,
    ) catch {
        if (file_refused(&storage.trace)) {
            // Nothing was sent anywhere: a public image still pulls anonymously.
            assert(storage.token.len == 0);
            storage.file_deferred = true;
            return null;
        }
        const path = env.get(credentials_mod.credentials_variable) orelse "";
        workload_failed(registry, path, &storage.trace, diag);
        return error.Failed;
    };
    assert(storage.token.len > 0);
    return &storage.token;
}

/// Whether workload identity failed on the credentials file itself, before any request.
fn file_refused(trace: *const credentials_mod.Trace) bool {
    return switch (trace.workload_identity) {
        .unreadable, .unsupported => true,
        else => false,
    };
}

/// The step after an anonymous refusal, for a credentialed Google host without a token: asked by
/// the client once, after the realm refused. The file's refusal when `token_for` deferred one,
/// otherwise the metadata server. Null for any other host. Called after `token_for`.
pub fn fallback_for(
    host: host_mod.Host,
    registry: []const u8,
    storage: *Storage,
) ?client_mod.RealmFallback {
    assert(registry.len > 0);
    if (!hosts.classify(registry).credentialed()) return null;
    storage.host = host;
    if (storage.file_deferred) return .{ .context = storage, .call = file_refusal };
    return .{ .context = storage, .call = metadata_token };
}

/// The deferred refusal of the credentials file: no token, and the file's code in `diag`.
fn file_refusal(context: *anyopaque, registry: []const u8, diag: *Diag) ?[]const u8 {
    assert(diag.code == null);
    const storage: *Storage = @ptrCast(@alignCast(context));
    assert(storage.file_deferred);
    assert(file_refused(&storage.trace));
    const env = credentials_mod.Env.from_host(storage.host, &storage.pairs);
    const path = env.get(credentials_mod.credentials_variable) orelse "";
    workload_failed(registry, path, &storage.trace, diag);
    return null;
}

fn metadata_token(context: *anyopaque, registry: []const u8, diag: *Diag) ?[]const u8 {
    assert(diag.code == null);
    const storage: *Storage = @ptrCast(@alignCast(context));
    const host = storage.host;
    const env = credentials_mod.Env.from_host(host, &storage.pairs);
    const sources: credentials_mod.Sources = .{ .metadata = true };
    credentials_mod.resolve(
        host,
        env,
        host.time_now(),
        sources,
        &storage.workspace,
        &storage.token,
        &storage.trace,
    ) catch {
        metadata_failed(registry, &storage.trace, diag);
        return null;
    };
    assert(storage.token.len > 0);
    return storage.token.text();
}

/// Raises the diagnostic for workload identity that gave no token: the step that failed, and why.
fn workload_failed(
    registry: []const u8,
    path: []const u8,
    trace: *const credentials_mod.Trace,
    diag: *Diag,
) void {
    assert(diag.code == null);
    const service = service_of(trace.step);
    switch (trace.workload_identity) {
        .not_configured, .used => unreachable,
        .not_asked => diagnose.none_given(diag, registry, true),
        .unreadable => diagnose.file_unreadable(diag, path),
        .unsupported => switch (trace.unsupported) {
            .service_account_key => diagnose.key_file(diag, path),
            .workforce_pool => diagnose.workforce_pool(diag, path),
            else => diagnose.unsupported_file(diag, path, trace),
        },
        .subject_unreadable => diagnose.subject_unreadable(
            diag,
            trace.subject_source,
            trace.status,
        ),
        // A 5xx is the service failing, not refusing this identity.
        .refused => if (trace.status >= 500) {
            diagnose.service_failed(diag, service, .refused, trace.status);
        } else switch (trace.step) {
            .subject_token => diagnose.subject_unreadable(diag, trace.subject_source, trace.status),
            .exchange => diagnose.exchange_refused(diag, trace.status, trace.code()),
            .impersonation => diagnose.impersonation_refused(diag, trace),
            .none, .credentials_file => {
                diagnose.service_failed(diag, .sts, .refused, trace.status);
            },
        },
        .no_answer => if (trace.step == .subject_token) {
            diagnose.subject_unreadable(diag, trace.subject_source, trace.status);
        } else diagnose.service_failed(diag, service, .no_answer, trace.status),
        .malformed => diagnose.service_failed(diag, service, .malformed, trace.status),
        .expired => diagnose.service_failed(diag, service, .expired, trace.status),
    }
    assert(diag.code != null);
}

fn service_of(step: credentials_mod.Step) diagnose.Service {
    return switch (step) {
        .subject_token => .subject_url,
        .impersonation => .iam,
        .none, .credentials_file, .exchange => .sts,
    };
}

/// Raises the diagnostic for a metadata server that gave no token after an anonymous refusal.
fn metadata_failed(registry: []const u8, trace: *const credentials_mod.Trace, diag: *Diag) void {
    assert(diag.code == null);
    switch (trace.metadata) {
        .used => unreachable,
        .not_asked, .absent, .not_gce, .no_service_account => {
            diagnose.no_credentials(diag, registry, trace);
        },
        .refused => diagnose.service_failed(diag, .metadata, .refused, trace.status),
        .malformed => diagnose.service_failed(diag, .metadata, .malformed, trace.status),
        .expired => diagnose.service_failed(diag, .metadata, .expired, trace.status),
    }
    assert(diag.code != null);
}
