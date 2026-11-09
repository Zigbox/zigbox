//! The run gate (docs/briefs/M8-trust.md, "Where the checks run"): before a container starts,
//! every policy file that exists is read and the run's tree is judged against it. With no
//! policy file, or only files that ask for nothing, the gate reads nothing else and costs one
//! failed `open` per file.
//!
//! Policy files: `/etc/zbx/policy.zon`, then `<config>/zbx/policy.zon` (`XDG_CONFIG_HOME`, else
//! `~/.config`). Each applies on its own: a run must pass every file, and the first that
//! refuses is the one reported. A file that exists and cannot be used is E0904, never "no
//! rules": a policy that is not read must not be taken for one that is absent. Nothing names
//! another policy file, so a flag or a variable cannot switch the check off.
//!
//! The gate only decides. It starts nothing and writes nothing, so a refusal leaves no run
//! record, scope or log.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const Diag = @import("../diag/diag.zig").Diag;
const digest_mod = @import("../store/digest.zig");
const fs_mod = @import("../store/fs.zig");
const layout = @import("../store/layout.zig");
const open = @import("../store/open.zig");
const store_diagnose = @import("../store/diagnose.zig");
const diagnose = @import("diagnose.zig");
const policy_mod = @import("policy.zig");
const record_mod = @import("record.zig");
const statement = @import("statement.zig");
const verdict = @import("verdict.zig");

const Digest = digest_mod.Digest;
const Host = host_mod.Host;
const PathBuf = fs_mod.PathBuf;
const Store = layout.Store;

pub const Error = error{Refused};

/// What is to run, as far as a policy is concerned.
pub const Subject = struct {
    /// The tree the container starts from; null for a directory, which has none.
    tree: ?Digest,
    binding: statement.Binding,
    /// The digest the user would give `zbx sign`, for the message. Empty for a directory.
    text: []const u8,
    /// The build step whose base this is, for the message; empty for a run.
    step: []const u8 = "",
};

/// One policy file that was found, with where.
pub const Loaded = struct {
    policy: policy_mod.Policy,
    path: PathBuf,
};

/// The gate's own memory, about 20 KiB; the record and the envelope work are the caller's.
pub const Memory = struct {
    files: [constants.policy_files_max]Loaded,
    count: u32,
    text: [constants.policy_bytes_max + 1]u8,
};

/// The user's policy path from the environment. False when there is no home to look in.
pub fn user_path(host: Host, out: *PathBuf) bool {
    const suffix = constants.policy_user_suffix;
    const limit: u32 = constants.store_path_bytes_max - suffix.len;
    var base: []const u8 = "";
    var middle: []const u8 = "";
    if (host.environment("XDG_CONFIG_HOME", limit)) |config| {
        if (config.len > 0 and config[0] == '/') base = config;
    }
    if (base.len == 0) {
        const home = host.environment("HOME", limit - "/.config".len) orelse return false;
        if (home.len == 0 or home[0] != '/') return false;
        base = home;
        middle = "/.config";
    }
    out.set(&.{ std.mem.trimEnd(u8, base, "/"), middle, suffix }) catch return false;
    return true;
}

/// Reads the policy files that exist into `memory`. A file that exists and is not a policy is
/// E0904.
pub fn load(host: Host, memory: *Memory, diag: *Diag) Error!void {
    assert(diag.code == null);
    memory.count = 0;
    var system: PathBuf = undefined;
    system.set(&.{constants.policy_system_path}) catch unreachable; // A short constant.
    try load_one(host, memory, &system, diag);
    var user: PathBuf = undefined;
    if (user_path(host, &user)) try load_one(host, memory, &user, diag);
    assert(memory.count <= constants.policy_files_max);
}

fn load_one(host: Host, memory: *Memory, path: *const PathBuf, diag: *Diag) Error!void {
    assert(memory.count < constants.policy_files_max);
    const fs = host.filesystem();
    const bytes = fs.read_whole(path.text(), &memory.text) catch |err| {
        if (err == error.NotFound) return;
        const fault: diagnose.PolicyFault = if (err == error.FileTooLarge)
            .{ .problem = .{
                .kind = .too_large,
                .line = 0,
                .column = 0,
                .detail = undefined,
                .detail_length = 0,
            } }
        else
            .{ .unreadable = fs.last_errno() };
        diagnose.policy_unusable(diag, path.text(), fault);
        return error.Refused;
    };
    const slot = &memory.files[memory.count];
    if (policy_mod.parse(bytes, &slot.policy)) |problem| {
        diagnose.policy_unusable(diag, path.text(), .{ .problem = problem });
        return error.Refused;
    }
    slot.path = path.*;
    memory.count += 1;
}

/// True when some loaded file asks for anything of a run.
pub fn any_checks(memory: *const Memory) bool {
    for (memory.files[0..memory.count]) |*loaded| {
        if (loaded.policy.checks()) return true;
    }
    return false;
}

/// Judges `subject` against every loaded policy file. `record` and `work` are the caller's
/// memory. On a refusal `diag` holds E0905 (or E0903 or the store's own failure).
pub fn judge_all(
    host: Host,
    memory: *const Memory,
    record: *record_mod.Record,
    work: *record_mod.Work,
    subject: Subject,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    if (!any_checks(memory)) return;
    var report: verdict.Report = undefined;
    report.clear();
    record.clear();
    if (subject.tree) |tree| try read_record(host, work, tree, record, diag);
    for (memory.files[0..memory.count]) |*loaded| {
        if (!loaded.policy.checks()) continue;
        const have: verdict.Subject = .{
            .tree = if (subject.tree) |tree| tree.bytes else @splat(0),
            .binding = subject.binding,
        };
        const met = subject.tree != null and
            verdict.judge(&work.envelope, &loaded.policy, record, have, &report);
        if (met) continue;
        diagnose.unsigned(diag, &.{
            .digest = subject.text,
            .policy_path = loaded.path.text(),
            .report = &report,
            .policy = &loaded.policy,
            .no_tree = subject.tree == null,
            .step = subject.step,
        });
        return error.Refused;
    }
}

/// The record of `tree` into `record`, empty when there is none (or no store yet).
pub fn read_record(
    host: Host,
    work: *record_mod.Work,
    tree: Digest,
    record: *record_mod.Record,
    diag: *Diag,
) Error!void {
    var store: Store = undefined;
    if (!store.locate(host)) return;
    const present = open.check(&store, .existing, diag) catch return error.Refused;
    if (!present) return;
    var errno: u16 = 0;
    record_mod.load(&store, work, tree, record, &errno) catch |err| switch (err) {
        error.NotFound => return,
        error.Unreadable => {
            const what = "reading the signatures";
            store_diagnose.cannot_read(diag, &store, what, error.IoFailed, errno);
            return error.Refused;
        },
        error.Damaged, error.Newer => {
            var path: PathBuf = undefined;
            const where = record_mod.record_path(&store, &path, tree);
            const problem: diagnose.RecordProblem = if (err == error.Newer) .newer else .damaged;
            diagnose.record_unusable(diag, where, problem);
            return error.Refused;
        },
    };
    assert(record.count >= 1);
}
