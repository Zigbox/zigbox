//! The import of a step's inputs, in the store's namespace (`store/namespace.zig`).
//!
//! The input tree records every file as owner 0:0, as the image's files are, and writing an
//! object with that owner is a `chown` that only the namespace's root may do. So the import runs
//! in the single-threaded child that every other write of the store runs in, and the digest, or
//! the diagnostic, comes back on a pipe.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const doctor = @import("../doctor.zig");
const host_mod = @import("../host.zig");
const Diag = @import("../diag/diag.zig").Diag;
const fs_mod = @import("../store/fs.zig");
const layout = @import("../store/layout.zig");
const namespace = @import("../store/namespace.zig");
const store_diagnose = @import("../store/diagnose.zig");
const digest_mod = @import("../store/digest.zig");
const load_mod = @import("load.zig");
const input_tree = @import("input_tree.zig");
const roots = @import("../store/roots.zig");
const step_mod = @import("step.zig");
const inputs_mod = @import("inputs.zig");
const diagnose = @import("diagnose.zig");

const Host = host_mod.Host;
const Digest = digest_mod.Digest;
const Store = layout.Store;

pub const Error = error{Failed};

/// What the caller gives: the build's host, store and loaded file, and the memory the import
/// works in.
pub const Request = struct {
    host: Host,
    facts: *doctor.Facts,
    store: *Store,
    loaded: *const load_mod.Workspace,
    step: u8,
    /// A copy entry of the step (an index into its entries): import its `.src`, not `.inputs`.
    entry: ?u32 = null,
    ws: *input_tree.Workspace,
    problem: *inputs_mod.Problem,
};

const Job = struct {
    request: *const Request,
    report: host_mod.Pipe,
};

/// Imports the inputs of step `request.step` and returns the tree's digest.
pub fn import(request: *const Request, diag: *Diag) Error!Digest {
    assert(diag.code == null);
    assert(request.step < request.loaded.file.steps_count);
    const host = request.host;
    var job: Job = .{
        .request = request,
        .report = host.pipe() catch |err| {
            store_diagnose.worker_ended(diag, .{ .step = .{
                .name = "pipe",
                .err = err,
                .errno = host.last_errno(),
            } });
            return error.Failed;
        },
    };
    defer host.close(job.report.read);
    const work: namespace.Work = .{
        .context = &job,
        .call = job_call,
        .store = request.store,
    };
    const code = namespace.run(host, request.facts, work, null, diag) catch {
        host.close(job.report.write);
        return error.Failed;
    };
    host.close(job.report.write);
    var bytes: [constants.diag_carry_bytes_max]u8 = undefined;
    var length: usize = 0;
    while (length < bytes.len) {
        const count = host.read_some(job.report.read, bytes[length..]) catch break;
        if (count == 0) break;
        length += count;
    }
    if (code == constants.exit_ok and length == constants.store_digest_bytes) {
        return .{ .bytes = bytes[0..constants.store_digest_bytes].* };
    }
    if (length > 0 and code != constants.exit_ok and diag.decode(bytes[0..length])) {
        return error.Failed;
    }
    diag.reset();
    store_diagnose.worker_ended(diag, .{ .step = .{
        .name = "import",
        .err = error.IoFailed,
        .errno = 0,
    } });
    return error.Failed;
}

/// The child: imports, and writes the digest, or the encoded diagnostic, to the pipe.
fn job_call(context: *anyopaque, squash_owner: bool) u8 {
    _ = squash_owner; // The tree is imported with owners 0:0 either way.
    const job: *Job = @ptrCast(@alignCast(context));
    const request = job.request;
    var diag: Diag = undefined;
    diag.reset();
    if (imported(request, &diag)) |digest| {
        request.host.write_handle_all(job.report.write, &digest.bytes) catch {};
        return constants.exit_ok;
    }
    if (diag.code == null) {
        diag.raise(.B0001);
        diag.cause("the import of a step's inputs failed with no diagnostic", .{});
    }
    var bytes: [constants.diag_carry_bytes_max]u8 = undefined;
    request.host.write_handle_all(job.report.write, diag.encode(&bytes)) catch {};
    return diag.exit_code();
}

fn imported(request: *const Request, diag: *Diag) ?Digest {
    const loaded = request.loaded;
    const fs = request.host.filesystem();
    const project = fs.open_directory(loaded.project.text()) catch |err| {
        const operation = "opening the project directory";
        const errno = fs.last_errno();
        store_diagnose.write_failed(diag, request.store, operation, err, errno);
        return null;
    };
    defer fs.close(project);
    var import_request: input_tree.Request = .{
        .store = request.store,
        .project = project,
        .file = &loaded.file,
        .step = request.step,
    };
    if (request.entry) |at| {
        const file = &loaded.file;
        const step = &file.steps[request.step];
        const entry = file.copy_entries(step)[at];
        import_request.inputs = file.texts(entry.src);
        import_request.exclude = .{ file.exclude, step.exclude, entry.exclude };
    }
    const imported_digest = input_tree.import(import_request, request.ws, request.problem, diag);
    const digest = imported_digest catch |err| {
        if (err == error.Refused) {
            diagnose.input_problem(diag, loaded.project.text(), &loaded.file, request.problem);
        }
        return null;
    };
    // The tree is read again after this child has gone (a copy's selection, a command step's
    // worker): a root keeps a concurrent `store gc` from removing it in between.
    const name = request.loaded.file.text(request.loaded.file.steps[request.step].name);
    if (!root_tree(request.store, digest, name, diag)) return null;
    return digest;
}

/// Roots a tree a step reads later as a build's output is rooted (`step.output_root_prefix`
/// plus the step's name), so the build's `unroot` drops it once it is used. A root that was
/// already there (the user's, or an earlier build's) is left as it was. False with `diag` raised
/// on a write error.
pub fn root_tree(store: *Store, digest: Digest, name: []const u8, diag: *Diag) bool {
    assert(diag.code == null);
    assert(name.len <= constants.build_step_name_bytes_max);
    var root: roots.Root = undefined;
    var errno: u16 = 0;
    if (roots.load(store, digest, &root, &errno)) |_| {
        return true; // A record is already there; keep it as it is.
    } else |err| {
        // Only "not there" leads to a new record; any other answer leaves the tree as it is.
        if (err != error.NotFound) return true;
    }
    const label_max = step_mod.output_root_prefix.len + constants.build_step_name_bytes_max;
    var label: [label_max]u8 = undefined;
    const labelled = std.fmt.bufPrint(&label, step_mod.output_root_prefix ++ "{s}", .{
        name,
    }) catch unreachable; // The buffer holds the prefix and the longest step name.
    root.digest = digest;
    root.kind = .import;
    root.time = store.host.time_now();
    root.files = 0;
    root.bytes = 0;
    root.set_source(labelled);
    root.parent = null;
    var failure: fs_mod.Failure = undefined;
    roots.save(store, &root, &failure) catch {
        const operation = "writing the root record of a step's tree";
        store_diagnose.write_failed(diag, store, operation, failure.err, failure.errno);
        return false;
    };
    return true;
}
