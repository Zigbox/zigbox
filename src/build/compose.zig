//! `zbx build`, the thin composition of slice 2: for each step of the build file in graph order,
//! the lock gives the base image, the image record its tree, platform and environment, the
//! inputs are imported (`input_tree.zig`), the key is computed (`key.zig`), and the cache
//! (`cache.zig`) either has the output (a hit starts no container) or `step.run_step` makes it
//! and the cache records it. One line per step says which: `<step>  hit|built  <output digest>`.
//!
//! This is not the scheduler (slice 3): steps run one at a time, a failure stops the build, a
//! base that the lock names but the store lacks is refused with the pull that fixes it (the
//! pull by locked digest is slice 3's), and there is no image output yet (slice 4).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const doctor = @import("../doctor.zig");
const errors = @import("../diag/errors.zig");
const lock_file = @import("../lock_file.zig");
const image_diagnose = @import("../image_diagnose.zig");
const Diag = @import("../diag/diag.zig").Diag;
const layout = @import("../store/layout.zig");
const images = @import("../store/images.zig");
const lock = @import("../store/lock.zig");
const store_diagnose = @import("../store/diagnose.zig");
const digest_mod = @import("../store/digest.zig");
const load_mod = @import("load.zig");
const file_mod = @import("file.zig");
const key_mod = @import("key.zig");
const cache = @import("cache.zig");
const step_mod = @import("step.zig");
const input_tree = @import("input_tree.zig");
const inputs_mod = @import("inputs.zig");
const diagnose = @import("diagnose.zig");

const Host = host_mod.Host;
const Digest = digest_mod.Digest;
const Store = layout.Store;

pub const Error = error{ Failed, OutputFailed };

/// The caller's memory for a build: large, so static or heap storage.
pub const Workspace = struct {
    locking: lock_file.Workspace,
    image: images.Image,
    input: input_tree.Workspace,
    input_problem: inputs_mod.Problem,
    step: step_mod.Workspace,
    cache: cache.Workspace,
    result: step_mod.Result,
    outputs: [constants.build_steps_max]Digest,
    base_env: [constants.env_vars_count_max][]const u8,
    env: [constants.build_step_env_max][]const u8,
    argv: [constants.build_step_argv_max][]const u8,
    needs: [constants.build_step_needs_max]key_mod.Need,
    key: key_mod.Key,
    row: [row_bytes]u8,
};

const row_bytes = constants.build_step_name_bytes_max + 16 + constants.store_digest_text_bytes;

/// Builds every step of the loaded build file, in graph order, writing one row per step.
pub fn run_steps(
    host: Host,
    facts: *doctor.Facts,
    loaded: *const load_mod.Workspace,
    ws: *Workspace,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    assert(loaded.graph.count == loaded.file.steps_count);
    var failure: lock_file.Failure = undefined;
    lock_file.open_project(host, host.filesystem(), &ws.locking, &failure) catch {
        image_diagnose.lock_failure(diag, lock_file.file_name, failure);
        return error.Failed;
    };
    var store: Store = undefined;
    if (!store.locate(host)) {
        store_diagnose.no_data_directory(diag);
        return error.Failed;
    }
    var group_storage: [step_mod.log_group_bytes]u8 = undefined;
    const group = step_mod.log_group(&group_storage, loaded.path.text());
    var context: Context = .{
        .host = host,
        .facts = facts,
        .loaded = loaded,
        .ws = ws,
        .diag = diag,
        .store = &store,
        .group = group,
    };
    try context.sweep();
    for (loaded.graph.order_slice()) |index| try context.build_step(index);
}

const Context = struct {
    host: Host,
    facts: *doctor.Facts,
    loaded: *const load_mod.Workspace,
    ws: *Workspace,
    diag: *Diag,
    store: *Store,
    group: []const u8,

    fn request(context: *const Context, spec: *const key_mod.Spec) step_mod.Request {
        return .{
            .host = context.host,
            .facts = context.facts,
            .spec = spec,
            .file = context.loaded.shown(),
            .group = context.group,
        };
    }

    /// Clears what a killed build left in `build/work`, before this one starts steps.
    fn sweep(context: *Context) Error!void {
        const spec: key_mod.Spec = .{
            .platform = "linux/amd64",
            .base_tree = Digest.of("sweep"),
            .base_env = &.{},
            .input_tree = Digest.of("sweep"),
            .needs = &.{},
            .argv = &.{},
            .env = &.{},
            .network = false,
            .name = "sweep",
        };
        const sweep_request = context.request(&spec);
        step_mod.sweep(&sweep_request, &context.ws.step, context.diag) catch return error.Failed;
    }

    fn build_step(context: *Context, index: u8) Error!void {
        const loaded = context.loaded;
        const ws = context.ws;
        const file = &loaded.file;
        assert(index < file.steps_count);
        const step = &file.steps[index];
        const name = file.text(step.name);
        var spec: key_mod.Spec = undefined;
        spec.name = name;
        spec.network = step.network;
        try context.resolve_base(file.text(step.base), &spec);
        spec.input_tree = try context.import_inputs(index);
        fill_lists(file, step, ws, &spec);
        spec.needs = fill_needs(loaded, index, ws);
        key_mod.compute(&spec, &ws.key) catch {
            diagnose.step_env_refused(context.diag, name, loaded.shown(), step.env.count, "");
            return error.Failed;
        };
        var failure: cache.Failure = undefined;
        const found = cache.lookup(context.store, &ws.cache, &ws.key, &failure) catch {
            return context.cache_failed(&failure);
        };
        switch (found) {
            .hit => |output| {
                ws.outputs[index] = output;
                return context.row(name, "hit", output);
            },
            .miss => {},
        }
        const run_request = context.request(&spec);
        step_mod.run_step(&run_request, &ws.step, &ws.result, context.diag) catch {
            return error.Failed;
        };
        const output = try context.record(ws.result.output);
        ws.outputs[index] = output;
        try context.row(name, "built", output);
    }

    /// The base's image, from the lock: its platform, tree and environment.
    fn resolve_base(context: *Context, reference: []const u8, spec: *key_mod.Spec) Error!void {
        const ws = context.ws;
        const name = spec.name;
        const at = ws.locking.lock.find(reference) orelse {
            diagnose.base_not_locked(context.diag, name, reference, false);
            return error.Failed;
        };
        const entry = &ws.locking.lock.entries[at];
        var errno: u16 = 0;
        images.load(context.store, entry.manifest, &ws.image, &errno) catch |err| {
            if (err == error.NotFound) {
                diagnose.base_not_locked(context.diag, name, reference, true);
            } else {
                const operation = "reading the base image's record";
                store_diagnose.write_failed(context.diag, context.store, operation, error.IoFailed, errno);
            }
            return error.Failed;
        };
        spec.platform = entry.platform_text();
        spec.base_tree = ws.image.tree;
        const count = ws.image.settings.count(.env);
        assert(count <= ws.base_env.len);
        for (0..count) |word| ws.base_env[word] = ws.image.settings.word(.env, @intCast(word));
        spec.base_env = ws.base_env[0..count];
    }

    fn import_inputs(context: *Context, index: u8) Error!Digest {
        const loaded = context.loaded;
        const fs = context.host.filesystem();
        const project = fs.open_directory(loaded.project.text()) catch |err| {
            const operation = "opening the project directory";
            store_diagnose.write_failed(context.diag, context.store, operation, err, fs.last_errno());
            return error.Failed;
        };
        defer fs.close(project);
        const import: input_tree.Request = .{
            .store = context.store,
            .project = project,
            .file = &loaded.file,
            .step = index,
        };
        const ws = context.ws;
        return input_tree.import(import, &ws.input, &ws.input_problem, context.diag) catch |err| {
            if (err == error.Refused) {
                diagnose.input_problem(
                    context.diag,
                    loaded.project.text(),
                    &loaded.file,
                    &ws.input_problem,
                );
            }
            return error.Failed;
        };
    }

    /// Writes the entry under the shared lock, and returns the tree it names.
    fn record(context: *Context, output: Digest) Error!Digest {
        const store = context.store;
        try store_diagnose.hold(context.diag, store, .shared, "build", "recording a build step");
        defer lock.release(store);
        var failure: cache.Failure = undefined;
        return cache.record(store, &context.ws.cache, &context.ws.key, output, &failure) catch {
            return context.cache_failed(&failure);
        };
    }

    fn cache_failed(context: *Context, failure: *const cache.Failure) Error {
        const operation = "reading the build cache";
        switch (failure.*) {
            .io => |io| {
                store_diagnose.write_failed(context.diag, context.store, io.step, io.err, io.errno);
            },
            .tree => store_diagnose.write_failed(
                context.diag,
                context.store,
                operation,
                error.IoFailed,
                0,
            ),
        }
        return error.Failed;
    }

    fn row(context: *Context, name: []const u8, what: []const u8, output: Digest) Error!void {
        const text = output.text();
        const line = std.fmt.bufPrint(&context.ws.row, "{s}  {s}  {s}\n", .{ name, what, &text }) catch
            unreachable; // `row_bytes` holds a name, a word and a digest.
        context.host.write_all(.stdout, line) catch |err| {
            errors.output_failed(context.diag, .stdout, err, context.host.last_errno());
            return error.OutputFailed;
        };
    }
};

fn fill_lists(
    file: *const file_mod.BuildFile,
    step: *const file_mod.Step,
    ws: *Workspace,
    spec: *key_mod.Spec,
) void {
    for (step.run.slice(), 0..) |word, at| ws.argv[at] = file.text(word);
    for (step.env.slice(), 0..) |word, at| ws.env[at] = file.text(word);
    spec.argv = ws.argv[0..step.run.count];
    spec.env = ws.env[0..step.env.count];
}

fn fill_needs(loaded: *const load_mod.Workspace, index: u8, ws: *Workspace) []const key_mod.Need {
    const file = &loaded.file;
    const wanted = loaded.graph.needs_slice(file, index);
    for (wanted, 0..) |need, at| {
        ws.needs[at] = .{ .name = file.text(file.steps[need].name), .output = ws.outputs[need] };
    }
    return ws.needs[0..wanted.len];
}

comptime {
    assert(row_bytes > constants.store_digest_text_bytes);
}
