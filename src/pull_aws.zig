//! The command line's AWS step of a pull (M6c, slice 2): for a reference on a private Amazon ECR
//! host, find the AWS credentials (environment, web identity, instance role: `aws/credentials.zig`)
//! and hand them to the library's pull. For any other host it does nothing and reads nothing.
//!
//! Credentials are looked up for every pull, never cached, and wiped when the command ends
//! (`Storage.wipe`). A failure is a coded diagnostic built from the resolver's trace: which of
//! the three sources was set up and what it did, never a key or an AWS message.

const std = @import("std");
const assert = std.debug.assert;
const aws_diagnose = @import("aws/diagnose.zig");
const credentials_mod = @import("aws/credentials.zig");
const ecr = @import("aws/ecr.zig");
const host_mod = @import("host.zig");
const Diag = @import("diag/diag.zig").Diag;

pub const Error = error{Failed};

/// What the credentials are found in and kept in. Static storage; wiped by the caller.
pub const Storage = struct {
    pairs: [credentials_mod.Env.names.len]credentials_mod.Env.Pair,
    workspace: credentials_mod.Workspace,
    credentials: credentials_mod.Credentials,
    trace: credentials_mod.Trace,

    pub fn wipe(storage: *Storage) void {
        assert(storage.pairs.len > 0);
        storage.workspace.wipe();
        storage.credentials.wipe();
        // The pairs point into the host's environment, which is not ours to zero.
        storage.pairs = undefined;
        assert(storage.pairs.len > 0);
    }
};

/// The credentials for a pull from `registry`: null when it is not a private ECR host (nothing
/// was read), the credentials in `storage` when it is. A host ECR of a kind zbx does not sign for
/// also gives null: the pull itself refuses it (E0534).
pub fn credentials_for(
    host: host_mod.Host,
    registry: []const u8,
    storage: *Storage,
    diag: *Diag,
) Error!?*const credentials_mod.Credentials {
    assert(diag.code == null);
    assert(registry.len > 0);
    const private = switch (ecr.classify(registry)) {
        .other, .public, .unsupported => return null,
        .private => |found| found,
    };
    const env = credentials_mod.Env.from_host(host, &storage.pairs);
    credentials_mod.resolve(
        host,
        env,
        private.region,
        host.time_now(),
        &storage.workspace,
        &storage.credentials,
        &storage.trace,
    ) catch |err| {
        failed(err, registry, env, &storage.trace, diag);
        return error.Failed;
    };
    assert(storage.credentials.access_key_id_len > 0);
    return &storage.credentials;
}

/// Raises the diagnostic for a resolver that gave nothing. A web identity that was set up is the
/// answer, so its failure is the one told; then an instance role that refused or expired; else
/// the plain "no credentials" with what each source did.
fn failed(
    err: credentials_mod.Error,
    registry: []const u8,
    env: credentials_mod.Env,
    trace: *const credentials_mod.Trace,
    diag: *Diag,
) void {
    assert(diag.code == null);
    switch (err) {
        error.UnsupportedRegion => {
            aws_diagnose.unsupported_region(diag, registry, credentials_mod.reason(err));
        },
        error.NoCredentials => {
            if (trace.web_identity == .unreadable) {
                const path = env.get("AWS_WEB_IDENTITY_TOKEN_FILE") orelse "";
                aws_diagnose.web_identity_file(diag, path);
            } else if (told_by_aws(trace.web_identity) or told_by_aws(trace.instance_metadata)) {
                aws_diagnose.source_failed(diag, trace);
            } else aws_diagnose.no_credentials(diag, registry, trace);
        },
    }
    assert(diag.code != null);
}

fn told_by_aws(state: credentials_mod.State) bool {
    return state == .refused or state == .expired;
}
