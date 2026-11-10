//! `zbx verify` (M8): walks the chain from the signature to every input, offline, and stops at
//! the first broken link (docs/briefs/M8-trust.md, "`zbx verify <digest>`"):
//!
//!   1. the tree has a signature record (reading it verifies every envelope's signature);
//!   2. some signer is trusted: by every policy file present, or by `--key` or `--public`;
//!   3. the tree is whole and every object hashes to its id, uncached (`tree_check.zig`);
//!   4. a trusted envelope carries signed provenance of this tree; whether the stored record is
//!      the same bytes is reported, not a failure;
//!   5. every tree the signed provenance names is in the store and sound; an absent one is a
//!      warning (`W0903`) and fails only with `--strict`;
//!   6. the build file and `zbx.lock` of the working directory's project hash as the provenance
//!      says; where they are not there it is reported and is not a failure.
//!
//! Nothing here touches the network, a registry or a clock: the store, the policy files and the
//! working directory are all it reads. The report goes to stdout, a failure's diagnostic to
//! stderr. A tree signed without provenance stops after link 3 and passes, unless
//! `--require-provenance` was given.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const build_diagnose = @import("../build/diagnose.zig");
const Diag = @import("../diag/diag.zig").Diag;
const doctor = @import("../doctor.zig");
const namespace = @import("../store/namespace.zig");
const render = @import("../diag/render.zig");
const errors = @import("../diag/errors.zig");
const json = @import("../bundle.zig");
const lock = @import("../store/lock.zig");
const open = @import("../store/open.zig");
const reference_mod = @import("../registry/reference.zig");
const registry_diagnose = @import("../registry/diagnose.zig");
const result = @import("../build/result.zig");
const store_diagnose = @import("../store/diagnose.zig");
const trees = @import("../store/trees.zig");
const images = @import("../store/images.zig");
const diagnose = @import("diagnose.zig");
const dsse = @import("dsse.zig");
const gate = @import("gate.zig");
const key = @import("key.zig");
const key_store = @import("key_store.zig");
const provenance = @import("provenance.zig");
const provenance_store = @import("provenance_store.zig");
const record_mod = @import("record.zig");
const statement = @import("statement.zig");
const tree_check = @import("tree_check.zig");

const Digest = @import("../store/digest.zig").Digest;
const PathBuf = @import("../store/fs.zig").PathBuf;
const Host = host_mod.Host;
const Store = @import("../store/layout.zig").Store;

pub const Error = error{Failed};

pub const Args = struct {
    /// A build result, a tree, or `name@sha256:...`.
    operand: []const u8,
    /// The name of a key of the user's whose public half is trusted for this run.
    key: ?[]const u8 = null,
    /// The public key's text (`ed25519:...`), trusted for this run.
    public: ?[]const u8 = null,
    /// An input that is not in the store fails the verify.
    strict: bool = false,
    /// A tree signed without provenance fails the verify.
    require_provenance: bool = false,
};

pub const Output = struct {
    json: bool,
    mode: render.Mode = .text,
    color: bool = false,
};

/// The most distinct trees link 5 looks at: every base, and the input, the output and the needs'
/// outputs of every step.
pub const inputs_max: u32 = constants.provenance_bases_max +
    constants.provenance_steps_max * (2 + constants.build_step_needs_max);

/// Where an input came from, for the message.
const Origin = enum { base, step_input, step_output, need_output };

const Input = struct {
    tree: Digest,
    origin: Origin,
    /// Index into the record's `bases`, or `steps`.
    index: u32,
};

const Bytes = [constants.store_digest_bytes]u8;
const Link = diagnose.VerifyLink;
const links_count = 6;

const Status = enum { unreached, ok, skipped, absent, failed };

const Stored = enum { not_asked, same, differs, absent };

/// What each link found; the output is rendered from it alone.
const Report = struct {
    status: [links_count]Status,
    signers: [constants.signatures_per_tree_max][constants.key_public_bytes]u8,
    signer_count: u32,
    lines: u32,
    trusted: [constants.key_public_bytes]u8,
    has_trusted: bool,
    stored: Stored,
    checked: u32,
    not_in_store: u32,
    build_file: Status,
    lock: Status,

    fn clear(report: *Report) void {
        report.status = @splat(.unreached);
        report.signer_count = 0;
        report.lines = 0;
        report.has_trusted = false;
        report.stored = .not_asked;
        report.checked = 0;
        report.not_in_store = 0;
        report.build_file = .unreached;
        report.lock = .unreached;
    }

    fn set(report: *Report, link: Link, status: Status) void {
        report.status[@backingInt(link) - 1] = status;
    }
};

/// The caller's memory, several MiB: keep it off the stack.
pub const Workspace = struct {
    tree: tree_check.Work,
    record: record_mod.Record,
    record_work: record_mod.Work,
    dsse: dsse.Work,
    policies: gate.Memory,
    signed: provenance.Record,
    again: [constants.statement_bytes_max]u8,
    stored: provenance_store.Work,
    result: result.Record,
    result_bytes: [constants.build_result_bytes_max + 1]u8,
    image: images.Image,
    inputs: [inputs_max]Input,
    file: [constants.lock_file_bytes_max + 1]u8,
    report: Report,
};

/// The keys `--key` and `--public` name.
const Explicit = struct {
    keys: [2][constants.key_public_bytes]u8,
    count: u32,
};

const Job = struct {
    host: Host,
    ws: *Workspace,
    args: Args,
    output: Output,
    store: Store,
    diag: *Diag,
    explicit: Explicit,
    /// What the operand named: the tree, and the result when it named one.
    tree: Digest,
    result: ?Digest,
};

const Child = struct {
    host: Host,
    ws: *Workspace,
    args: Args,
    output: Output,
};

/// `run`, in the store's user namespace, where the objects' owners are as they were hashed.
pub fn run_in_namespace(
    host: Host,
    facts: *doctor.Facts,
    ws: *Workspace,
    args: Args,
    output: Output,
    diag: *Diag,
) Error!u8 {
    assert(diag.code == null);
    assert(args.operand.len > 0);
    var child: Child = .{ .host = host, .ws = ws, .args = args, .output = output };
    const work: namespace.Work = .{ .context = &child, .call = child_call };
    return namespace.run(host, facts, work, null, diag) catch return error.Failed;
}

fn child_call(context: *anyopaque, squash_owner: bool) u8 {
    assert(@intFromPtr(context) != 0);
    _ = squash_owner; // Nothing here records an owner.
    const child: *Child = @ptrCast(@alignCast(context));
    var diag: Diag = undefined;
    diag.reset();
    return run(child.host, child.ws, child.args, child.output, &diag) catch {
        var buffer: [constants.output_bytes_max]u8 = undefined;
        const text = render.render(&diag, child.output.mode, child.output.color, &buffer);
        child.host.write_all(.stderr, text) catch return constants.exit_environment;
        return diag.exit_code();
    };
}

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
        .explicit = .{ .keys = undefined, .count = 0 },
        .tree = undefined,
        .result = null,
    };
    ws.report.clear();
    if (!job.store.locate(host)) {
        store_diagnose.no_data_directory(diag);
        return error.Failed;
    }
    const present = open.check(&job.store, .existing, diag) catch return error.Failed;
    if (!present) return broken(&job, .signature, .no_record, "", 0);
    try read_keys(&job);
    gate.load(host, &ws.policies, diag) catch return error.Failed;
    try store_diagnose.hold(diag, &job.store, .shared, "verify", "verifying");
    defer lock.release(&job.store);
    try resolve(&job);
    try link_signature(&job);
    try link_signer(&job);
    try link_tree(&job);
    const signed = try link_provenance(&job);
    if (signed) {
        try link_inputs(&job);
        try link_build_file(&job);
    }
    try put_report(&job);
    return 0;
}

/// A broken link: the report so far, then the diagnostic.
fn broken(
    job: *Job,
    link: Link,
    cause: diagnose.VerifyCause,
    detail: []const u8,
    errno: u16,
) Error {
    return broken_at(job, link, cause, detail, "", errno);
}

/// Link 2: `policy` lists the policy files present, or is empty when there are none.
fn broken_with_policy(job: *Job, signers: []const u8, policy: []const u8) Error {
    return broken_at(job, .signer, .no_trusted_signer, signers, policy, 0);
}

fn broken_at(
    job: *Job,
    link: Link,
    cause: diagnose.VerifyCause,
    detail: []const u8,
    policy: []const u8,
    errno: u16,
) Error {
    assert(job.args.operand.len > 0);
    assert(errno < 4096);
    job.ws.report.set(link, .failed);
    put_report(job) catch {}; // The diagnostic is the failure; a lost report adds nothing.
    diagnose.verify_broken(job.diag, &.{
        .operand = job.args.operand,
        .link = link,
        .cause = cause,
        .detail = detail,
        .policy = policy,
        .errno = errno,
    });
    return error.Failed;
}

// ---- What is named ----

fn resolve(job: *Job) Error!void {
    const operand = job.args.operand;
    if (std.mem.indexOfScalar(u8, operand, '@') != null) return resolve_image(job);
    const digest = Digest.parse(operand) orelse {
        store_diagnose.bad_digest(job.diag, operand);
        return error.Failed;
    };
    var errno: u16 = 0;
    const ws = job.ws;
    result.load(&job.store, digest, &ws.result, &ws.result_bytes, &errno) catch |err| {
        switch (err) {
            error.NotFound => return resolve_tree(job, digest),
            error.Damaged, error.Newer => {
                build_diagnose.result_unusable(job.diag, digest, err == error.Newer);
                return error.Failed;
            },
            error.Unreadable => return unreadable(job, "reading the build result", errno),
        }
    };
    job.tree = ws.result.tree;
    job.result = digest;
}

fn resolve_tree(job: *Job, digest: Digest) Error!void {
    const found = trees.has(&job.store, digest) catch {
        return unreadable(job, "looking for the tree", job.store.fs.last_errno());
    };
    if (!found) return broken(job, .signature, .no_record, "", 0);
    job.tree = digest;
}

fn resolve_image(job: *Job) Error!void {
    const operand = job.args.operand;
    var reference: reference_mod.Reference = undefined;
    reference_mod.parse(operand, &reference) catch |err| {
        registry_diagnose.bad_reference(job.diag, operand, err);
        return error.Failed;
    };
    const manifest = reference.digest orelse return broken(job, .signature, .no_record, "", 0);
    var errno: u16 = 0;
    images.load(&job.store, manifest, &job.ws.image, &errno) catch |err| switch (err) {
        error.NotFound => return broken(job, .signature, .no_record, "", 0),
        error.Unreadable => return unreadable(job, "reading the image record", errno),
        else => {
            const what = "reading the image record";
            store_diagnose.cannot_read(job.diag, &job.store, what, error.FileTooLarge, errno);
            return error.Failed;
        },
    };
    job.tree = job.ws.image.tree;
}

fn unreadable(job: *const Job, step: []const u8, errno: u16) Error {
    store_diagnose.cannot_read(job.diag, &job.store, step, error.IoFailed, errno);
    return error.Failed;
}

// ---- The keys named on the command line ----

fn read_keys(job: *Job) Error!void {
    assert(job.explicit.count == 0);
    if (job.args.public) |text| {
        const public = key.parse_public_text(text) orelse {
            const failure: key_store.Failure = .{ .problem = .malformed };
            diagnose.unusable(job.diag, "--public", "", failure);
            return error.Failed;
        };
        job.explicit.keys[job.explicit.count] = public;
        job.explicit.count += 1;
    }
    const name = job.args.key orelse return;
    if (!key.name_valid(name)) {
        diagnose.bad_name(job.diag, name);
        return error.Failed;
    }
    var paths: key_store.Paths = undefined;
    var failure: key_store.Failure = .{ .problem = .no_home };
    if (!key_store.locate(job.host, &paths)) {
        diagnose.unusable(job.diag, name, "", failure);
        return error.Failed;
    }
    const file = key_store.read_pub(job.host.filesystem(), &paths, name, &failure) catch {
        diagnose.unusable(job.diag, name, paths.dir.text(), failure);
        return error.Failed;
    };
    job.explicit.keys[job.explicit.count] = file.public;
    job.explicit.count += 1;
}

/// Whether `public` is trusted: listed by every policy file there is, so that verify agrees with
/// what `zbx run` would accept; only with no policy file at all do `--key` and `--public` name
/// the key to trust (docs/decisions/2026-11-09-verify-policy-decides.md).
fn trusted(job: *const Job, public: *const [constants.key_public_bytes]u8) bool {
    assert(job.explicit.count <= job.explicit.keys.len);
    const policies = &job.ws.policies;
    if (policies.count == 0) {
        for (job.explicit.keys[0..job.explicit.count]) |named| {
            if (std.mem.eql(u8, &named, public)) return true;
        }
        return false;
    }
    for (policies.files[0..policies.count]) |*loaded| {
        if (loaded.policy.trusted(public) == null) return false;
    }
    return true;
}

// ---- Link 1: the signatures ----

fn link_signature(job: *Job) Error!void {
    const ws = job.ws;
    var errno: u16 = 0;
    record_mod.load(&job.store, &ws.record_work, job.tree, &ws.record, &errno) catch |err| {
        var path: PathBuf = undefined;
        const text = record_mod.record_path(&job.store, &path, job.tree);
        switch (err) {
            error.NotFound => return broken(job, .signature, .no_record, "", 0),
            error.Damaged => diagnose.record_unusable(job.diag, text, .damaged),
            error.Newer => diagnose.record_unusable(job.diag, text, .newer),
            error.Unreadable => {
                const what = "reading the signatures";
                store_diagnose.cannot_read(job.diag, &job.store, what, error.IoFailed, errno);
            },
        }
        return error.Failed;
    };
    const report = &ws.report;
    report.lines = ws.record.count;
    assert(report.lines >= 1);
    var index: u32 = 0;
    while (index < ws.record.count) : (index += 1) {
        const envelope = dsse.parse(&ws.dsse, ws.record.line(index)) catch continue;
        add_signer(report, envelope.public);
    }
    assert(report.signer_count <= ws.record.count);
    report.set(.signature, .ok);
}

fn add_signer(report: *Report, public: [constants.key_public_bytes]u8) void {
    assert(report.signer_count < report.signers.len);
    for (report.signers[0..report.signer_count]) |known| {
        if (std.mem.eql(u8, &known, &public)) return;
    }
    report.signers[report.signer_count] = public;
    report.signer_count += 1;
}

// ---- Link 2: a trusted signer ----

fn link_signer(job: *Job) Error!void {
    const report = &job.ws.report;
    assert(report.signer_count >= 1);
    for (report.signers[0..report.signer_count]) |public| {
        if (!trusted(job, &public)) continue;
        report.trusted = public;
        report.has_trusted = true;
        report.set(.signer, .ok);
        return;
    }
    var text: [constants.arg_echo_bytes_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&text);
    for (report.signers[0..report.signer_count], 0..) |public, at| {
        const id = key.key_id(public);
        const separator: []const u8 = if (at == 0) "" else ", ";
        // A full buffer only shortens the list of ids in the message.
        writer.print("{s}{s}", .{ separator, id[0..16] }) catch break;
    }
    var names: [constants.arg_echo_bytes_max]u8 = undefined;
    var policy_writer = std.Io.Writer.fixed(&names);
    const policies = &job.ws.policies;
    for (policies.files[0..policies.count], 0..) |*loaded, at| {
        const separator: []const u8 = if (at == 0) "" else ", ";
        policy_writer.print("{s}{s}", .{ separator, loaded.path.text() }) catch break;
    }
    return broken_with_policy(job, writer.buffered(), policy_writer.buffered());
}

// ---- Link 3: the tree ----

fn link_tree(job: *Job) Error!void {
    assert(job.ws.report.has_trusted);
    assert(job.ws.report.status[1] == .ok);
    const fault = tree_check.check(&job.store, &job.ws.tree, job.tree) orelse {
        job.ws.report.set(.tree, .ok);
        return;
    };
    const cause: diagnose.VerifyCause = switch (fault.why) {
        .object_missing => .tree_missing,
        .object_damaged => .tree_damaged,
        .too_large => .tree_too_large,
        else => .tree_unreadable,
    };
    return broken(job, .tree, cause, "", fault.errno);
}

// ---- Link 4: the signed provenance ----

/// Finds the first trusted line that is provenance of this tree (and result). False when there is
/// none and none is required: the later links have nothing to walk.
fn link_provenance(job: *Job) Error!bool {
    const ws = job.ws;
    var index: u32 = 0;
    var other: ?Digest = null; // The result the last trusted provenance of this tree is about.
    while (index < ws.record.count) : (index += 1) {
        const envelope = dsse.parse(&ws.dsse, ws.record.line(index)) catch continue;
        if (!trusted(job, &envelope.public)) continue;
        const head = statement.parse(envelope.payload) catch continue;
        if (head.kind != .provenance) continue;
        provenance.parse(envelope.payload, &ws.signed, &ws.again) catch continue;
        const about = std.mem.eql(u8, &ws.signed.tree, &job.tree.bytes) and
            (job.result == null or std.mem.eql(u8, &ws.signed.result, &job.result.?.bytes));
        if (!about) {
            other = .{ .bytes = ws.signed.result };
            continue;
        }
        try compare_stored(job, envelope.payload);
        ws.report.set(.provenance, .ok);
        return true;
    }
    if (job.args.require_provenance) {
        const named = other orelse return broken(job, .provenance, .no_provenance, "", 0);
        const text = named.text();
        return broken(job, .provenance, .provenance_other, &text, 0);
    }
    ws.report.set(.provenance, .skipped);
    ws.report.set(.inputs, .skipped);
    ws.report.set(.build_file, .skipped);
    return false;
}

/// Whether the store's provenance record of the result is the signed bytes. Reported only.
fn compare_stored(job: *Job, signed: []const u8) Error!void {
    const ws = job.ws;
    const wanted: Digest = .{ .bytes = ws.signed.result };
    var errno: u16 = 0;
    const bytes = provenance_store.load(&job.store, &ws.stored, wanted, &errno) catch |err| {
        switch (err) {
            error.NotFound => ws.report.stored = .absent,
            error.Damaged => ws.report.stored = .differs,
            error.Unreadable => {
                return unreadable(job, "reading the provenance record", errno);
            },
        }
        return;
    };
    ws.report.stored = if (std.mem.eql(u8, bytes, signed)) .same else .differs;
}

// ---- Link 5: the inputs ----

fn link_inputs(job: *Job) Error!void {
    const ws = job.ws;
    const count = collect_inputs(ws);
    assert(count <= inputs_max);
    for (ws.inputs[0..count]) |input| {
        const found = trees.has(&job.store, input.tree) catch {
            return unreadable(job, "looking for an input", job.store.fs.last_errno());
        };
        if (!found) {
            try absent_input(job, &input);
            continue;
        }
        if (tree_check.check(&job.store, &ws.tree, input.tree)) |fault| {
            var label: [constants.arg_echo_bytes_max]u8 = undefined;
            const cause: diagnose.VerifyCause = if (fault.why == .unreadable)
                .tree_unreadable
            else
                .input_damaged;
            return broken(job, .inputs, cause, describe(ws, &input, &label), fault.errno);
        }
        ws.report.checked += 1;
    }
    ws.report.set(.inputs, if (ws.report.not_in_store > 0) .absent else .ok);
}

/// The distinct trees the signed provenance names, into `ws.inputs`.
fn collect_inputs(ws: *Workspace) u32 {
    var count: u32 = 0;
    const signed = &ws.signed;
    for (signed.bases_slice(), 0..) |base, at| {
        count = add_input(ws, count, base.tree, .base, @intCast(at));
    }
    for (signed.steps_slice(), 0..) |*step, at| {
        count = add_input(ws, count, step.input, .step_input, @intCast(at));
        for (step.needs_slice()) |need| {
            count = add_input(ws, count, need.output, .need_output, @intCast(at));
        }
        count = add_input(ws, count, step.output, .step_output, @intCast(at));
    }
    assert(count <= inputs_max);
    return count;
}

fn add_input(ws: *Workspace, count: u32, tree: Bytes, origin: Origin, index: u32) u32 {
    assert(count < inputs_max);
    for (ws.inputs[0..count]) |known| {
        if (std.mem.eql(u8, &known.tree.bytes, &tree)) return count;
    }
    ws.inputs[count] = .{ .tree = .{ .bytes = tree }, .origin = origin, .index = index };
    return count + 1;
}

/// What the input is, for the message.
fn describe(ws: *const Workspace, input: *const Input, buffer: []u8) []const u8 {
    assert(buffer.len > 0);
    const signed = &ws.signed;
    const text = switch (input.origin) {
        .base => std.fmt.bufPrint(buffer, "the base {s}", .{
            signed.bases[input.index].text(),
        }),
        .step_input => std.fmt.bufPrint(buffer, "the input tree of step {s}", .{
            signed.steps[input.index].text(),
        }),
        .step_output => std.fmt.bufPrint(buffer, "the output tree of step {s}", .{
            signed.steps[input.index].text(),
        }),
        .need_output => std.fmt.bufPrint(buffer, "a needed output of step {s}", .{
            signed.steps[input.index].text(),
        }),
    };
    return text catch buffer[0..0]; // A name too long for the echo is cut to nothing.
}

/// W0903, or E0908 under `--strict`.
fn absent_input(job: *Job, input: *const Input) Error!void {
    const ws = job.ws;
    var label: [constants.arg_echo_bytes_max]u8 = undefined;
    const what = describe(ws, input, &label);
    if (job.args.strict) return broken(job, .inputs, .input_absent, what, 0);
    ws.report.not_in_store += 1;
    var diag: Diag = undefined;
    diag.reset();
    diagnose.verify_absent_input(&diag, job.args.operand, what);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const text = render.render(&diag, job.output.mode, job.output.color, &buffer);
    job.host.write_all(.stderr, text) catch |err| {
        errors.output_failed(job.diag, .stderr, err, job.host.last_errno());
        return error.Failed;
    };
}

// ---- Link 6: the build file ----

fn link_build_file(job: *Job) Error!void {
    const ws = job.ws;
    assert(ws.report.status[3] == .ok);
    var cwd: [constants.store_path_bytes_max]u8 = undefined;
    const base = job.host.working_directory(&cwd) catch "";
    var path: PathBuf = undefined;
    var have_path = false; // `path` is set only when the project's directory was read and fits.
    const named = ws.signed.build_file_text();
    ws.report.build_file = if (base.len == 0) .skipped else blk: {
        const parts: []const []const u8 = if (named.len > 0 and named[0] == '/')
            &.{named}
        else
            &.{ base, "/", named };
        path.set(parts) catch break :blk .skipped;
        have_path = true;
        break :blk file_status(job, path.text(), ws.signed.build_file_digest);
    };
    if (ws.report.build_file == .failed) {
        return broken(job, .build_file, .build_file_changed, "the build file", 0);
    }
    ws.report.lock = if (have_path) check_lock(job, path.text()) else .skipped;
    if (ws.report.lock == .failed) {
        return broken(job, .build_file, .build_file_changed, "zbx.lock", 0);
    }
    const both_absent = ws.report.build_file == .skipped and ws.report.lock != .ok;
    ws.report.set(.build_file, if (both_absent) .skipped else .ok);
}

/// The lock's status; it lies beside the build file.
fn check_lock(job: *const Job, build_path: []const u8) Status {
    const wanted = job.ws.signed.lock orelse return .skipped;
    const slash = std.mem.lastIndexOfScalar(u8, build_path, '/') orelse return .skipped;
    var path: PathBuf = undefined;
    path.set(&.{ build_path[0 .. slash + 1], provenance.lock_name }) catch return .skipped;
    return file_status(job, path.text(), wanted);
}

/// Whether the file at `path` hashes to `wanted`: ok, failed, or skipped when it is not there.
fn file_status(job: *const Job, path: [:0]const u8, wanted: Bytes) Status {
    assert(path.len > 0);
    assert(path[0] == '/');
    const fs = job.store.fs;
    const bytes = fs.read_whole(path, &job.ws.file) catch |err| {
        return if (err == error.FileTooLarge) .failed else .skipped;
    };
    const found = Digest.of(bytes);
    return if (std.mem.eql(u8, &found.bytes, &wanted)) .ok else .failed;
}

// ---- Output ----

fn status_word(status: Status) []const u8 {
    return switch (status) {
        .unreached => "not reached",
        .ok => "ok",
        .skipped => "skipped",
        .absent => "ok",
        .failed => "FAILED",
    };
}

fn put(job: *const Job, text: []const u8) Error!void {
    assert(text.len <= constants.output_bytes_max);
    job.host.write_all(.stdout, text) catch |err| {
        errors.output_failed(job.diag, .stdout, err, job.host.last_errno());
        return error.Failed;
    };
}

fn stored_word(stored: Stored) []const u8 {
    return switch (stored) {
        .not_asked => "none",
        .same => "same",
        .differs => "differs",
        .absent => "absent",
    };
}

fn put_report(job: *const Job) Error!void {
    var buffer: [constants.output_bytes_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    // Cannot fail: a few short lines, an operand and ids fit the buffer.
    if (job.output.json) {
        write_json(job, &writer) catch unreachable; // Same bound.
    } else {
        write_text(job, &writer) catch unreachable; // Same bound.
    }
    try put(job, writer.buffered());
}

const link_names = [links_count][]const u8{
    "signatures", "signer", "tree", "provenance", "inputs", "build_file",
};

fn write_text(job: *const Job, writer: *std.Io.Writer) std.Io.Writer.Error!void {
    const report = &job.ws.report;
    const tree = job.tree.text();
    try writer.print("verify {s}\ntree: {s}\n", .{ job.args.operand, &tree });
    for (report.status, 0..) |status, at| {
        try writer.print("{d} {s}: {s}", .{ at + 1, link_names[at], status_word(status) });
        try write_detail(report, at, writer);
        try writer.writeAll("\n");
    }
}

fn write_detail(report: *const Report, at: usize, writer: *std.Io.Writer) !void {
    if (report.status[at] != .ok and report.status[at] != .absent) return;
    switch (at) {
        0 => try writer.print(" ({d} signatures)", .{report.lines}),
        1 => {
            const id = key.key_id(report.trusted);
            try writer.print(" (key {s})", .{&id});
        },
        3 => try writer.print(" (stored record: {s})", .{stored_word(report.stored)}),
        4 => {
            try writer.print(" ({d} trees checked", .{report.checked});
            try writer.print(", {d} not in the store)", .{report.not_in_store});
        },
        5 => try writer.print(" (build file: {s}, zbx.lock: {s})", .{
            status_word(report.build_file), status_word(report.lock),
        }),
        else => {},
    }
}

fn write_json(job: *const Job, writer: *std.Io.Writer) !void {
    const report = &job.ws.report;
    const tree = job.tree.text();
    var ok = true;
    for (report.status) |status| ok = ok and status != .failed and status != .unreached;
    try writer.writeAll("{\"schema\":\"zbx.verify/1\",\"subject\":");
    try json.write_json_string(writer, job.args.operand);
    try writer.print(",\"tree\":\"{s}\",\"ok\":{},\"links\":[", .{ &tree, ok });
    for (report.status, 0..) |status, at| {
        const separator: []const u8 = if (at == 0) "" else ",";
        try writer.print("{s}{{\"n\":{d},\"name\":\"{s}\",\"status\":\"{s}\"}}", .{
            separator, at + 1, link_names[at], json_status(status),
        });
    }
    try writer.writeAll("],\"signers\":[");
    for (report.signers[0..report.signer_count], 0..) |public, at| {
        const id = key.key_id(public);
        try writer.print("{s}\"{s}\"", .{ if (at == 0) "" else ",", &id });
    }
    try writer.print("],\"provenance_record\":\"{s}\",", .{stored_word(report.stored)});
    try writer.print("\"inputs\":{{\"checked\":{d},\"not_in_store\":{d}}},", .{
        report.checked, report.not_in_store,
    });
    try writer.print("\"build_file\":\"{s}\",\"lock\":\"{s}\"}}\n", .{
        json_status(report.build_file), json_status(report.lock),
    });
}

fn json_status(status: Status) []const u8 {
    return switch (status) {
        .unreached => "not_reached",
        .ok => "ok",
        .skipped => "skipped",
        .absent => "partial",
        .failed => "failed",
    };
}
