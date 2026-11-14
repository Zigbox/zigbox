//! The policy gate in front of a start, shared by `zbx run` and the library's `zigbox.start`
//! (docs/briefs/library-trust-gate.md). Both load the same policy files (`gate.load`: the node's
//! own, `/etc/zbx/policy.zon`, then the user's), judge the run's tree with `gate.judge_all`, and
//! turn the tamper check on as soon as any policy file exists. So a node whose policy refuses an
//! image from the command line refuses it from Zigcube's agent too, with the same code. The
//! library's `zigbox.exec_start` runs the gate `zbx exec` runs (`exec_gate.check`) the same way.
//!
//! The library has no way to switch the gate off: a check its caller can skip is no independent
//! judge. With no policy file that asks for anything it reads nothing beyond the policy lookup
//! and starts exactly as an ungated start would. The ungated `run.start` and `exec.start` stay
//! internal, and so does a build step's start (`build.step.run_step`): `zbx run`, `zbx exec` and
//! `zbx build` each gate before them, with the subject only they know (a build's base is bound
//! to the manifest its lock names).
//!
//! The subject is what the caller's `Spec` says, as the store backs it: its tree (a prefix or an
//! image name is resolved first, and the start runs the tree that was judged), and
//! `Spec.binding`, kept only when the store's own record of that manifest or result names the
//! same tree. A binding the store does not back is dropped, so the tree is judged as `zbx run`
//! judges the bare tree; a name the caller leaves unbound is bound to the manifest it resolved
//! through, as `zbx run` binds it. What the gate judged is what the run record keeps, for the
//! gate at `zbx exec`.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;
const host_mod = @import("../host.zig");
const digest_mod = @import("../store/digest.zig");
const images = @import("../store/images.zig");
const layout = @import("../store/layout.zig");
const verify = @import("../store/verify.zig");
const image_mod = @import("../runtime/image.zig");
const run = @import("../runtime/run.zig");
const spec_mod = @import("../runtime/spec.zig");
const exec_gate = @import("exec_gate.zig");
const gate = @import("gate.zig");
const record_mod = @import("record.zig");
const result = @import("../build/result.zig");
const exec = @import("../runtime/exec.zig");
const statement = @import("statement.zig");
const tamper = @import("tamper.zig");

const Digest = digest_mod.Digest;
const Host = host_mod.Host;

pub const Error = error{Refused};

/// The gate's state for one start: where its memory is, and the tamper check it asks for. The
/// pointers are the caller's (`zbx`'s `Storage`, or the library's `Workspace`).
pub const Gate = struct {
    memory: *gate.Memory,
    record: *record_mod.Record,
    work: *record_mod.Work,
    tamper: *tamper.Workspace,
    /// Idle while the gate runs: `zbx` lends its `sign` workspace's buffers.
    lent: tamper.Lent,
    tamper_on: bool = false,
    tamper_always: bool = false,
    /// A check of the caller's own, run after the tamper check (the library's
    /// `StartOptions.tree_check`); `zbx` has none.
    then: ?image_mod.Check = null,

    /// Reads every policy file. Any file at all asks for the tamper check, whatever it requires
    /// (the strictest `verify` of them wins); with none there is no check.
    pub fn load(self: *Gate, host: Host, diag: *Diag) Error!void {
        assert(diag.code == null);
        self.tamper_on = false;
        self.tamper_always = false;
        try gate.load(host, self.memory, diag);
        self.tamper_on = self.memory.count > 0;
        for (self.memory.files[0..self.memory.count]) |*loaded| {
            if (loaded.policy.verify == .always) self.tamper_always = true;
        }
        if (self.tamper_always) assert(self.tamper_on);
    }

    /// Judges `subject` against what `load` read. A refusal has set `diag` and started nothing.
    pub fn judge(self: *Gate, host: Host, subject: gate.Subject, diag: *Diag) Error!void {
        assert(diag.code == null);
        assert(self.memory.count <= constants.policy_files_max);
        try gate.judge_all(host, self.memory, self.record, self.work, subject, diag);
    }

    /// The check the store's child makes of the tree before it starts, or none.
    pub fn tree_check(self: *Gate) ?image_mod.Check {
        assert(self.memory.count <= constants.policy_files_max);
        if (!self.tamper_on) return self.then;
        assert(self.memory.count > 0);
        return .{ .context = self, .call = tamper_call };
    }
};

fn tamper_call(context: *anyopaque, store: *layout.Store, tree: Digest, diag: *Diag) bool {
    const self: *Gate = @ptrCast(@alignCast(context));
    assert(self.tamper_on);
    assert(self.memory.count > 0);
    assert(diag.code == null);
    tamper.check(store, self.tamper, self.lent, tree, self.tamper_always, diag) catch {
        return false;
    };
    const then = self.then orelse return true;
    return then.call(then.context, store, tree, diag);
}

/// The library start's memory, about 17 MiB: the caller's, in static or heap storage. It must
/// not move while a start is going on (the tamper check points into it), and it serves one start
/// or exec at a time: two threads that start at once each bring their own.
pub const Workspace = struct {
    gate: gate.Memory,
    record: record_mod.Record,
    work: record_mod.Work,
    tamper: tamper.Workspace,
    scratch: verify.Scratch,
    tree_buffer: [constants.store_tree_bytes_max]u8,
    stack: [constants.image_import_stack_max]Digest,
    /// The image record a manifest binding is checked against and derives its result from.
    image: images.Image,
    /// The result record a result binding is checked against, and the bytes it is read into.
    result_record: result.Record,
    result_bytes: [constants.build_result_bytes_max + 1]u8,
    /// The full digest of the tree judged, which the start then runs.
    tree_text: [constants.store_digest_text_bytes]u8,
    /// What the refusal names: the tree's digest, or the result's.
    subject_text: [constants.store_digest_text_bytes]u8,
    state: Gate,
};

/// `run.start` behind the gate: the start of the `zigbox` library. A refusal returns
/// `StartFailed` with `diag` holding the code `zbx run` gives (E0903 to E0907, or the store's
/// own), before anything is made: no run record, scope or log. `handle` is set up as for any
/// start that fails before the container exists.
pub fn start(
    host: Host,
    container: *const spec_mod.Spec,
    options: run.StartOptions,
    handle: *run.Handle,
    workspace: *Workspace,
    diag: *Diag,
) run.Error!void {
    assert(diag.code == null);
    if (container.image != null) assert(options.image_workspace != null);
    run.init_handle(host, container, options, handle);
    var judged = container.*;
    const gated = try admit(host, &judged, options, workspace, diag);
    return run.start(host, &judged, gated, handle, diag);
}

/// The gate alone: loads the policy files, judges `container` when one asks anything, and
/// returns the options the start runs with (the tamper check added when any file exists).
/// `container.image` is set to the full digest of the tree judged.
pub fn admit(
    host: Host,
    container: *spec_mod.Spec,
    options: run.StartOptions,
    workspace: *Workspace,
    diag: *Diag,
) run.Error!run.StartOptions {
    assert(diag.code == null);
    const state = &workspace.state;
    state.* = .{
        .memory = &workspace.gate,
        .record = &workspace.record,
        .work = &workspace.work,
        .tamper = &workspace.tamper,
        .lent = .{
            .scratch = &workspace.scratch,
            .tree_buffer = &workspace.tree_buffer,
            .stack = &workspace.stack,
        },
        .then = options.tree_check,
    };
    state.load(host, diag) catch return error.StartFailed;
    if (gate.any_checks(&workspace.gate)) {
        const subject = try subject_of(host, workspace, container, options, diag);
        state.judge(host, subject, diag) catch return error.StartFailed;
    }
    var gated = options;
    gated.tree_check = state.tree_check();
    if (options.tree_check == null) {
        if (!state.tamper_on) assert(gated.tree_check == null);
    }
    assert(diag.code == null);
    return gated;
}

/// What the policy judges of `container`. A tree given by a prefix or an image name is resolved
/// here and `container.image` set to its full digest, so the start runs the tree judged; the
/// binding is the one the store backs (`backed`), and `container.binding` is set to it, so the
/// run record keeps what was judged. A directory, or a tree with no store to find it in, has no
/// tree: every check refuses it.
fn subject_of(
    host: Host,
    workspace: *Workspace,
    container: *spec_mod.Spec,
    options: run.StartOptions,
    diag: *Diag,
) run.Error!gate.Subject {
    assert(diag.code == null);
    const none: gate.Subject = .{ .tree = null, .binding = .none, .text = "" };
    const image = container.image orelse return none;
    var store: layout.Store = undefined;
    const located = store.locate(host);
    const resolved: image_mod.Resolved = if (Digest.parse(image)) |tree|
        .{ .tree = tree, .manifest = null }
    else found: {
        if (!located) return none; // The start says what is missing.
        const found = image_mod.resolve_image(&store, options.image_workspace.?, image, diag);
        break :found found catch return error.StartFailed;
    };
    const binding: statement.Binding = if (located)
        backed(&store, workspace, container.binding, resolved)
    else
        .none;
    container.binding = spec_binding_of(binding);
    workspace.tree_text = resolved.tree.text();
    container.image = &workspace.tree_text;
    workspace.subject_text = switch (binding) {
        .result => |bytes| (Digest{ .bytes = bytes }).text(),
        else => workspace.tree_text,
    };
    assert(Digest.parse(container.image.?) != null);
    return .{
        .tree = resolved.tree,
        .binding = binding,
        .derived = exec_gate.derived_of(host, binding, &workspace.image),
        .text = &workspace.subject_text,
    };
}

/// The binding the store backs for `resolved.tree`: the caller's, when the store's record of
/// that manifest or result names the same tree (`zbx run` binds only what it found there);
/// otherwise the manifest a name resolved through; otherwise none. So a binding never makes a
/// statement count that `zbx run` of the same tree, result or name would not count.
fn backed(
    store: *layout.Store,
    workspace: *Workspace,
    given: spec_mod.Binding,
    resolved: image_mod.Resolved,
) statement.Binding {
    assert(@intFromPtr(store) != 0);
    assert(@intFromPtr(workspace) != 0);
    var errno: u16 = 0;
    switch (given) {
        .none => {},
        .manifest => |bytes| {
            const image = &workspace.image;
            if (images.load(store, .{ .bytes = bytes }, image, &errno)) |_| {
                if (image.tree.eql(resolved.tree)) return .{ .manifest = bytes };
            } else |_| {}
        },
        .result => |bytes| {
            const found = &workspace.result_record;
            const buffer = &workspace.result_bytes;
            if (result.load(store, .{ .bytes = bytes }, found, buffer, &errno)) |_| {
                if (found.tree.eql(resolved.tree)) return .{ .result = bytes };
            } else |_| {}
        },
    }
    const manifest = resolved.manifest orelse return .none;
    return .{ .manifest = manifest.bytes };
}

/// The binding as the run record keeps it (the runtime does not know the trust module).
fn spec_binding_of(binding: statement.Binding) spec_mod.Binding {
    const out: spec_mod.Binding = switch (binding) {
        .none => .none,
        .result => |bytes| .{ .result = bytes },
        .manifest => |bytes| .{ .manifest = bytes },
    };
    assert(std.mem.eql(u8, @tagName(out), @tagName(binding)));
    return out;
}

/// `exec.start` behind the gate `zbx exec` runs: the library's `zigbox.exec_start`. The
/// container's tree and binding come from its run record, and every policy file is met before
/// the command starts. A refusal returns `StartFailed` with `diag` holding the code `zbx exec`
/// gives (E0903 to E0905), before anything is started; `handle` is set up as for any exec that
/// fails before its command runs. The record is read only when a policy asks for something.
pub fn exec_start(
    host: Host,
    command: *const exec.Spec,
    options: exec.Options,
    handle: *exec.Handle,
    workspace: *Workspace,
    diag: *Diag,
) exec.Error!void {
    assert(diag.code == null);
    assert(command.command.len > 0);
    exec.init_handle(host, command, options, handle);
    const record = &workspace.record;
    const work = &workspace.work;
    const image = &workspace.image;
    exec_gate.check(host, &workspace.gate, record, work, image, command.name, diag) catch {
        assert(diag.code != null);
        return error.StartFailed;
    };
    assert(diag.code == null);
    return exec.start(host, command, options, handle, diag);
}
