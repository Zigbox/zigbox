//! `zbx sign` (M8): signs a tree that is in the store, so that `zbx run --require-signed` and
//! `zbx verify` can later say who vouched for it (docs/briefs/M8-trust.md).
//!
//! The operand names what is signed: the digest of a build result (the signature binds the
//! result and its tree), a tree's own digest, or `name@sha256:...` of an image in the store (the
//! signature binds the manifest, under its canonical name, and the image's tree). Nothing is
//! signed that is not whole and sound: every file object of the tree is checked against its name
//! without a cache (`verify.check_object_alone`), because a signature over a tree with a missing
//! or damaged file would vouch for something nobody can run.
//!
//! The record of the tree (`record.zig`) is read, a line added and the file replaced under the
//! store lock, so two signers cannot lose each other's line. Signing the same subjects with the
//! same key again changes nothing, whatever the time: `record.signed_already` ignores `signedAt`
//! (docs/decisions/2026-11-08-sign-idempotence.md).
//!
//! No secret reaches a diagnostic, a log or the output: the passphrase, the seed and the key
//! record are zeroed with `secureZero` before the function ends.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const build_diagnose = @import("../build/diagnose.zig");
const Diag = @import("../diag/diag.zig").Diag;
const errors = @import("../diag/errors.zig");
const json = @import("../bundle.zig");
const lock = @import("../store/lock.zig");
const open = @import("../store/open.zig");
const reference_mod = @import("../registry/reference.zig");
const registry_diagnose = @import("../registry/diagnose.zig");
const result = @import("../build/result.zig");
const store_diagnose = @import("../store/diagnose.zig");
const trees = @import("../store/trees.zig");
const verify = @import("../store/verify.zig");
const walk = @import("../store/walk.zig");
const images = @import("../store/images.zig");
const diagnose = @import("diagnose.zig");
const dsse = @import("dsse.zig");
const key = @import("key.zig");
const key_store = @import("key_store.zig");
const passphrase_mod = @import("passphrase.zig");
const record_mod = @import("record.zig");
const statement = @import("statement.zig");

const Digest = @import("../store/digest.zig").Digest;
const PathBuf = @import("../store/fs.zig").PathBuf;
const Host = host_mod.Host;
const Store = @import("../store/layout.zig").Store;

pub const Error = error{Failed};

pub const Args = struct {
    /// A build result, a tree, or `name@sha256:...`.
    operand: []const u8,
    /// The key's name; null for the only key there is.
    key: ?[]const u8 = null,
    /// The file whose first line is the key's passphrase.
    passphrase_file: ?[]const u8 = null,
};

pub const Output = struct {
    json: bool,
};

/// The caller's memory, several MiB: keep it in static storage.
pub const Workspace = struct {
    verify: verify.Workspace,
    tree_buffer: [constants.store_tree_bytes_max]u8,
    stack: [constants.image_import_stack_max]Digest,
    record: record_mod.Record,
    record_work: record_mod.Work,
    dsse: dsse.Work,
    envelope: [constants.envelope_bytes_max]u8,
    payload: [statement.render_bytes_max]u8,
    result: result.Record,
    result_bytes: [constants.build_result_bytes_max + 1]u8,
    image: images.Image,
    secret_bytes: [constants.key_file_bytes_max + 1]u8,
    listing: key_store.Listing,
};

/// What the operand named.
const Subject = struct {
    tree: Digest,
    statement: statement.Statement,
};

const Job = struct {
    host: Host,
    ws: *Workspace,
    args: Args,
    output: Output,
    store: Store,
    diag: *Diag,
};

pub fn run(host: Host, ws: *Workspace, args: Args, output: Output, diag: *Diag) Error!u8 {
    assert(diag.code == null);
    assert(args.operand.len > 0);
    var job: Job = .{
        .host = host,
        .ws = ws,
        .args = args,
        .output = output,
        .store = undefined,
        .diag = diag,
    };
    if (!job.store.locate(host)) {
        store_diagnose.no_data_directory(diag);
        return error.Failed;
    }
    const present = open.check(&job.store, .existing, diag) catch return error.Failed;
    if (!present) return refused(&job, .not_in_store, 0);
    const subject = try resolve(&job);
    var secret: Secret = undefined;
    defer secret.wipe();
    try open_key(&job, &secret);
    try sign_under_lock(&job, &subject, &secret);
    return 0;
}

/// E0910, and the failure to return.
fn refused(job: *const Job, why: diagnose.Refusal, errno: u16) Error {
    diagnose.sign_refused(job.diag, job.args.operand, why, errno);
    return error.Failed;
}

// ---- What is named ----

fn resolve(job: *Job) Error!Subject {
    const operand = job.args.operand;
    const now = job.host.time_now();
    if (std.mem.indexOfScalar(u8, operand, '@') != null) return resolve_image(job, now);
    const digest = Digest.parse(operand) orelse {
        store_diagnose.bad_digest(job.diag, operand);
        return error.Failed;
    };
    var errno: u16 = 0;
    const store = &job.store;
    result.load(store, digest, &job.ws.result, &job.ws.result_bytes, &errno) catch |err| {
        switch (err) {
            error.NotFound => return resolve_tree(job, digest, now),
            error.Damaged, error.Newer => {
                build_diagnose.result_unusable(job.diag, digest, err == error.Newer);
                return error.Failed;
            },
            error.Unreadable => return unreadable(job, "reading the build result", errno),
        }
    };
    const tree = job.ws.result.tree;
    return .{ .tree = tree, .statement = .for_result(tree.bytes, digest.bytes, now) };
}

fn resolve_tree(job: *Job, digest: Digest, now: u64) Error!Subject {
    const found = trees.has(&job.store, digest) catch {
        return unreadable(job, "looking for the tree", job.store.fs.last_errno());
    };
    if (!found) return refused(job, .not_in_store, 0);
    return .{ .tree = digest, .statement = .for_tree(digest.bytes, now) };
}

fn resolve_image(job: *Job, now: u64) Error!Subject {
    const operand = job.args.operand;
    var reference: reference_mod.Reference = undefined;
    reference_mod.parse(operand, &reference) catch |err| {
        registry_diagnose.bad_reference(job.diag, operand, err);
        return error.Failed;
    };
    const manifest = reference.digest orelse return refused(job, .not_in_store, 0);
    var errno: u16 = 0;
    images.load(&job.store, manifest, &job.ws.image, &errno) catch |err| switch (err) {
        error.NotFound => return refused(job, .not_in_store, 0),
        error.Unreadable => return unreadable(job, "reading the image record", errno),
        else => {
            store_diagnose.cannot_read(
                job.diag,
                &job.store,
                "reading the image record",
                error.FileTooLarge,
                errno,
            );
            return error.Failed;
        },
    };
    const tree = job.ws.image.tree;
    // Two spellings of one reference are one subject: the name is the canonical repository
    // without its tag, as the digest alone says which manifest.
    var name_buffer: reference_mod.Formatted = undefined;
    const name = std.fmt.bufPrint(&name_buffer, "{s}/{s}@{s}", .{
        reference.registry(), reference.repository(), &manifest.text(),
    }) catch unreachable; // The registry, the repository and a digest fit `Formatted`.
    return .{
        .tree = tree,
        .statement = .for_manifest(tree.bytes, name, manifest.bytes, now),
    };
}

fn unreadable(job: *const Job, step: []const u8, errno: u16) Error {
    store_diagnose.cannot_read(job.diag, &job.store, step, error.IoFailed, errno);
    return error.Failed;
}

// ---- The tree ----

/// Checks every file object a tree names, the first damage ending the walk's use.
const Checker = struct {
    store: *const Store,
    ws: *verify.Workspace,
    /// Null while the tree is sound.
    found: ?Found = null,

    const Found = struct { why: diagnose.Refusal, errno: u16 };

    pub fn object(checker: *Checker, ref: *const walk.ObjectRef) void {
        if (checker.found != null) return;
        const fs = checker.store.fs;
        var path: PathBuf = undefined;
        const listed = fs.lstat(checker.store.chunks_path(&path, ref.id));
        if (listed) |_| {
            return checker.check(ref, true);
        } else |err| {
            if (err == error.NotFound) return checker.check(ref, false);
            checker.found = .{ .why = .unreadable, .errno = fs.last_errno() };
        }
    }

    fn check(checker: *Checker, ref: *const walk.ObjectRef, has_list: bool) void {
        if (checker.found != null) return;
        var bytes: u64 = 0;
        const damage = verify.check_object_alone(
            checker.store,
            &checker.ws.scratch,
            ref.id,
            has_list,
            &bytes,
        ) orelse return;
        checker.found = switch (damage.kind) {
            // The walk reports a missing tree itself but not a missing file object, which
            // `check_object_alone` meets as a failed `lstat`.
            .unreadable => if (damage.errno != 0 and
                host_mod.error_for_errno(damage.errno) == error.NotFound)
                .{ .why = .object_missing, .errno = 0 }
            else
                .{ .why = .unreadable, .errno = damage.errno },
            else => .{ .why = .object_damaged, .errno = 0 },
        };
    }
};

/// Walks the tree and checks each file object. A refusal is in `diag`.
fn check_tree(job: *Job, tree: Digest) Error!void {
    var checker: Checker = .{ .store = &job.store, .ws = &job.ws.verify };
    var failure: walk.Failure = undefined;
    const ws = job.ws;
    walk.objects(
        &job.store,
        &ws.tree_buffer,
        &ws.stack,
        null,
        tree,
        &checker,
        constants.store_walk_entries_max,
        &failure,
    ) catch {
        return switch (failure.kind) {
            .missing => refused(job, .object_missing, 0),
            .damaged => refused(job, .object_damaged, 0),
            .unreadable => refused(job, .unreadable, failure.errno),
            .too_many_entries, .stack_full => refused(job, .too_large, 0),
        };
    };
    if (checker.found) |found| return refused(job, found.why, found.errno);
}

// ---- The key ----

const Secret = struct {
    record: key.Record,
    seed: [constants.key_seed_bytes]u8,
    name: [constants.key_name_bytes_max]u8,
    name_len: u8,
    id: key.IdText,

    fn wipe(secret: *Secret) void {
        std.crypto.secureZero(u8, std.mem.asBytes(secret));
    }

    fn name_slice(secret: *const Secret) []const u8 {
        assert(secret.name_len > 0);
        return secret.name[0..secret.name_len];
    }
};

/// The key to sign with, opened: `--key`, or the only key there is.
fn open_key(job: *Job, secret: *Secret) Error!void {
    const ws = job.ws;
    secret.name_len = 0;
    var paths: key_store.Paths = undefined;
    var failure: key_store.Failure = .{ .problem = .no_home };
    if (!key_store.locate(job.host, &paths)) {
        diagnose.unusable(job.diag, job.args.key orelse "", "", failure);
        return error.Failed;
    }
    const fs = job.host.filesystem();
    const name = try chosen_name(job, &paths, &failure);
    std.crypto.secureZero(u8, &ws.secret_bytes);
    defer std.crypto.secureZero(u8, &ws.secret_bytes);
    secret.record = key_store.read_secret(fs, &paths, name, &ws.secret_bytes, &failure) catch {
        return key_unusable(job, &paths, name, failure);
    };
    @memcpy(secret.name[0..name.len], name);
    secret.name_len = @intCast(name.len);
    secret.id = key.key_id(secret.record.public);
    var phrase: passphrase_mod.Passphrase = undefined;
    phrase.length = 0;
    defer phrase.wipe();
    if (secret.record.body == .passphrase) {
        var problem: diagnose.PassphraseProblem = undefined;
        const file = job.args.passphrase_file;
        passphrase_mod.acquire(job.host, file, name, false, &phrase, &problem) catch {
            diagnose.passphrase(job.diag, name, file orelse "", problem);
            return error.Failed;
        };
    }
    const given: ?[]const u8 = if (phrase.length > 0) phrase.text() else null;
    secret.seed = key.open(std.heap.page_allocator, &secret.record, given) catch |err| {
        if (err == error.OutOfMemory) {
            const cause: key_store.Failure = .{ .problem = .unreadable, .errno = 12 };
            diagnose.unusable(job.diag, name, "memory for the key's passphrase hash", cause);
        } else {
            diagnose.passphrase(job.diag, name, "", .wrong);
        }
        return error.Failed;
    };
}

/// `--key`, or the name of the only key; E0006 when there is none or more than one to take.
fn chosen_name(
    job: *Job,
    paths: *const key_store.Paths,
    failure: *key_store.Failure,
) Error![]const u8 {
    if (job.args.key) |name| {
        if (!key.name_valid(name)) {
            diagnose.bad_name(job.diag, name);
            return error.Failed;
        }
        return name;
    }
    const listing = &job.ws.listing;
    key_store.list(job.host.filesystem(), paths, listing, failure) catch {
        diagnose.unusable(job.diag, "", paths.dir.text(), failure.*);
        return error.Failed;
    };
    if (listing.count != 1 or listing.truncated) {
        diagnose.key_choice(job.diag, listing.count);
        return error.Failed;
    }
    return listing.name(0);
}

fn key_unusable(
    job: *const Job,
    paths: *const key_store.Paths,
    name: []const u8,
    failure: key_store.Failure,
) Error {
    var path: PathBuf = undefined;
    const text: []const u8 = blk: {
        if (failure.problem == .dir_too_open or failure.problem == .dir_not_real) {
            break :blk paths.dir.text();
        }
        key_store.file_path(paths, name, ".key", &path) catch break :blk paths.dir.text();
        break :blk path.text();
    };
    diagnose.unusable(job.diag, name, text, failure);
    return error.Failed;
}

// ---- Signing ----

fn sign_under_lock(job: *Job, subject: *const Subject, secret: *const Secret) Error!void {
    try store_diagnose.hold(job.diag, &job.store, .exclusive, "sign", "signing");
    defer lock.release(&job.store);
    try check_tree(job, subject.tree);
    const ws = job.ws;
    const known = try load_record(job, subject.tree);
    const public = secret.record.public;
    if (record_mod.signed_already(&ws.record_work, &ws.record, public, &subject.statement)) {
        return put_result(job, subject, secret, .present);
    }
    if (known == .absent) try check_room(job);
    const payload = statement.render(&ws.payload, &subject.statement);
    const envelope = dsse.sign(&ws.dsse, &ws.envelope, secret.seed, payload) catch {
        diagnose.unusable(job.diag, secret.name_slice(), "", .{ .problem = .malformed });
        return error.Failed;
    };
    const added = ws.record.add(envelope) catch return refused(job, .tree_full, 0);
    if (added == .added) try save_record(job, subject.tree);
    try put_result(job, subject, secret, added);
}

const Known = enum { absent, present };

/// Reads the tree's record into the workspace; an absent one is an empty record.
fn load_record(job: *Job, tree: Digest) Error!Known {
    const ws = job.ws;
    var errno: u16 = 0;
    record_mod.load(&job.store, &ws.record_work, tree, &ws.record, &errno) catch |err| {
        var path: PathBuf = undefined;
        const text = record_mod.record_path(&job.store, &path, tree);
        switch (err) {
            error.NotFound => {
                ws.record.clear();
                return .absent;
            },
            error.Damaged => diagnose.record_unusable(job.diag, text, .damaged),
            error.Newer => diagnose.record_unusable(job.diag, text, .newer),
            error.Unreadable => {
                store_diagnose.cannot_read(
                    job.diag,
                    &job.store,
                    "reading the signatures",
                    error.IoFailed,
                    errno,
                );
            },
        }
        return error.Failed;
    };
    return .present;
}

/// True when `count` records leave no room for a new one under `trust_records_max`.
pub fn is_full(count: u32) bool {
    return count >= constants.trust_records_max;
}

/// A new record must leave room under `trust_records_max`.
fn check_room(job: *Job) Error!void {
    var errno: u16 = 0;
    const count = record_mod.count_records(&job.store, &errno) catch |err| {
        store_diagnose.cannot_read(job.diag, &job.store, "counting the signatures", err, errno);
        return error.Failed;
    };
    if (is_full(count)) return refused(job, .store_full, 0);
}

fn save_record(job: *Job, tree: Digest) Error!void {
    var failure: @import("../store/fs.zig").Failure = undefined;
    record_mod.save(&job.store, tree, &job.ws.record, &failure) catch |err| {
        store_diagnose.write_failed(
            job.diag,
            &job.store,
            "writing the signatures",
            err,
            failure.errno,
        );
        return error.Failed;
    };
}

// ---- Output ----

fn put(job: *const Job, text: []const u8) Error!void {
    assert(text.len <= constants.output_bytes_max);
    job.host.write_all(.stdout, text) catch |err| {
        errors.output_failed(job.diag, .stdout, err, job.host.last_errno());
        return error.Failed;
    };
}

fn binding_word(subject: *const Subject) []const u8 {
    return switch (subject.statement.binding) {
        .none => "none",
        .result => "result",
        .manifest => "manifest",
    };
}

fn put_result(
    job: *const Job,
    subject: *const Subject,
    secret: *const Secret,
    added: record_mod.Added,
) Error!void {
    var buffer: [constants.output_bytes_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    const tree = subject.tree.text();
    const count = job.ws.record.count;
    // Cannot fail, any of these: a digest, a name, an id and a short operand fit the buffer.
    if (job.output.json) {
        writer.print("{{\"schema\":\"zbx.sign/1\",\"tree\":\"{s}\",\"binding\":\"{s}\",", .{
            &tree, binding_word(subject),
        }) catch unreachable; // Same bound.
        writer.writeAll("\"subject\":") catch unreachable; // Same bound.
        json.write_json_string(&writer, job.args.operand) catch unreachable; // Same bound.
        writer.print(",\"key\":\"{s}\",\"id\":\"{s}\",\"added\":{},\"signatures\":{d}}}\n", .{
            secret.name_slice(), &secret.id, added == .added, count,
        }) catch unreachable; // Same bound.
    } else {
        const note = if (added == .added) "" else " (already signed by this key)";
        writer.print("signed {s}\nbinding: {s}\nkey: {s}  {s}\nsignatures: {d}{s}\n", .{
            &tree, binding_word(subject), secret.name_slice(), &secret.id, count, note,
        }) catch unreachable; // Same bound.
    }
    try put(job, writer.buffered());
}
