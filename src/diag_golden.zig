//! Golden tests for diagnostics (DIAGNOSTICS.md, "Testing"): for every registered code, one case
//! triggers the condition through the real CLI against the simulated host and compares the
//! default, verbose and JSON output with the checked-in files in src/testdata/diag/. A doctor
//! code (E01xx) is triggered by a named fixture, and its golden is that code's block among the
//! blocks the doctor writes.
//!
//! Changing a message means updating the golden file in the same commit. The files for a code
//! NAME are NAME.txt, NAME.verbose.txt and NAME.json.txt.
//!
//! A second test runs the same cases (and every doctor fixture) and fails if any output shows a
//! stack trace or a raw Zig error name. The goldens are also what the demo checks against.

const std = @import("std");
const assert = std.debug.assert;
const cli = @import("cli.zig");
const constants = @import("constants.zig");
const codes = @import("diag/codes.zig");
const panic = @import("diag/panic.zig");
const render = @import("diag/render.zig");
const test_util = @import("test_util.zig");
const fixtures = @import("doctor_fixtures.zig");
const run = @import("runtime/run.zig");
const Diag = @import("diag/diag.zig").Diag;
const plan_mod = @import("runtime/plan.zig");
const sim_run = @import("runtime/sim_run.zig");
const HostSim = @import("host_sim.zig").HostSim;
const SimFs = @import("store/fs_sim.zig").SimFs;
const tree = @import("store/tree.zig");
const support = @import("store/test_support.zig");
const Digest = @import("store/digest.zig").Digest;
const net_sim = @import("registry/net_sim.zig");
const test_registry = @import("registry/test_registry.zig");

const testing = std.testing;

const Case = struct {
    code: codes.Code,
    /// The arguments after the program name, without the global options.
    args: []const [:0]const u8,
    /// Fail every write to stdout, as `> /dev/full` does.
    stdout_full: bool = false,
    /// The name of a doctor fixture (doctor_fixtures.zig) to run against; null for no files.
    fixture: ?[]const u8 = null,
    /// Sets the simulator up after it is initialised (a container host and a failure to inject).
    prepare: ?*const fn (sim: *HostSim) void = null,
    /// The command writes its result to stdout (a path), so stdout is not empty.
    prints: bool = false,
    /// The code is a warning: the run goes on, so the exit code is the command's, not the blame's.
    warning: bool = false,
    /// The exit code the case must end with.
    exit: u8,
};

/// The index of the first step of `kind` in a plan for a host that maps a full range of ids.
fn step_of(kind: plan_mod.Kind) u32 {
    return sim_run.step_index(kind, true);
}

/// A host where one step of the hardening, or of the read-only setup, is refused.
fn prepare_step_refused(sim: *HostSim, index: u32, errno: u16) void {
    sim_run.init(sim, 1);
    sim.faults.fail_step = index;
    sim.faults.fail_step_errno = errno;
}

fn prepare_capabilities_refused(sim: *HostSim) void {
    prepare_step_refused(sim, step_of(.restrict_capabilities), 1);
}

fn prepare_seccomp_refused(sim: *HostSim) void {
    prepare_step_refused(sim, step_of(.install_seccomp), 22);
}

fn prepare_no_tmp(sim: *HostSim) void {
    prepare_step_refused(sim, sim_run.step_index_read_only(.make_tmp_dir), 13);
}

fn prepare_container(sim: *HostSim) void {
    sim_run.init(sim, 1);
}

fn prepare_helper_refuses(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim.world.helper_fails_with = 1;
}

fn prepare_single(sim: *HostSim) void {
    sim_run.init_single(sim, 1);
}

fn prepare_disk_full(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim.world.disk_full = true;
}

/// A runs directory over the limit, with a record that is damaged and one from a newer zbx.
fn prepare_records_unreadable(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim.world.add_node(sim_run.runs_path, .dir);
    const future = ".{\n    .version = 9,\n    .name = \"future\",\n    .started = 5,\n}\n";
    assert(sim.world.write_file(sim_run.runs_path ++ "/damaged.zon", "garbage") == null);
    assert(sim.world.write_file(sim_run.runs_path ++ "/future.zon", future) == null);
    for (0..constants.runs_max - 1) |number| {
        var path: [64]u8 = undefined;
        const format = sim_run.runs_path ++ "/old-{d:0>2}.zon";
        const where = std.fmt.bufPrint(&path, format, .{number}) catch unreachable; // Short.
        var body: [96]u8 = undefined;
        const text = ".{{\n    .name = \"old-{d:0>2}\",\n    .started = {d},\n}}\n";
        const args = .{ number, 1000 + number };
        // Cannot fail: the body is a few dozen bytes.
        const record = std.fmt.bufPrint(&body, text, args) catch unreachable;
        assert(sim.world.write_file(where, record) == null);
    }
}

/// One container, started and left running, for the commands that look at containers.
var golden_handle: run.Handle = undefined;
/// The container above is running and its scope's keeper still holds its pipe, which is the
/// state of a running container; the case that looked at it ends it before the check for leaks.
var golden_started = false;

fn prepare_running(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim.world.command_runs_ms = 3_600_000;
    var diag: Diag = undefined;
    diag.reset();
    const container: run.Spec = .{
        .rootfs = sim_run.rootfs_path,
        .name = "web-1",
        .command = &.{"/bin/sh"},
    };
    run.start(sim.interface(), &container, .{ .detached = true }, &golden_handle, &diag) catch {
        unreachable; // The simulated host starts a container.
    };
    golden_started = true;
}

fn prepare_unsignalable(sim: *HostSim) void {
    prepare_running(sim);
    sim.world.kill_errno = 1; // EPERM.
}

fn prepare_immortal(sim: *HostSim) void {
    prepare_running(sim);
    sim.world.immortal = true;
}

fn prepare_no_fork(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim.world.fork_errno = 11; // EAGAIN.
}

/// The user's bus is perfect for the probe (the first connection) and meets `model` after it, so
/// the run gets as far as the scope step before the fault.
fn prepare_scope_fault(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim.world.bus.model.quiet_connections = 1;
    sim.world.bus.model.perfect_from = 2;
}

fn prepare_no_bus(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim.world.bus.model.present = false;
}

fn prepare_bus_not_there(sim: *HostSim) void {
    prepare_scope_fault(sim);
    sim.world.bus.model.present = false;
}

fn prepare_bus_rejects(sim: *HostSim) void {
    prepare_scope_fault(sim);
    sim.world.bus.model.auth = .reject;
}

fn prepare_bus_garbage(sim: *HostSim) void {
    prepare_scope_fault(sim);
    sim.world.bus.model.misbehave = .{ .at_call = 3, .how = .garbage_reply };
}

fn prepare_systemd_refuses(sim: *HostSim) void {
    prepare_scope_fault(sim);
    sim.world.bus.model.start_error = "org.freedesktop.DBus.Error.AccessDenied";
}

/// The container ends and its scope stays: the manager refuses to stop it.
fn prepare_scope_lingers(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim.world.bus.model.quiet_connections = 2; // The probe and the scope step; not the cleanup.
    sim.world.bus.model.scope_removal = .never;
    sim.world.bus.model.stop_error = "org.freedesktop.DBus.Error.AccessDenied";
}

fn prepare_name_taken(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim.world.bus.model.unit_taken = true;
}

/// An old systemd that cannot set the memory limit itself, and a cgroup that will not take it.
fn prepare_cgroup_refuses(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim.world.bus.model.version = "230.1";
    const base = "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service";
    sim.world.add_node(base ++ "/zbx-web-1.scope/memory.max", .dir);
}

fn prepare_proc_refused(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim.faults.fail_step = step_of(.mount_proc);
    sim.faults.fail_step_errno = 1; // EPERM
}

/// Ubuntu 24.04 as installed: AppArmor restricts user namespaces, so clone3 is refused.
const run_restricted = fixtures.build(.{
    .name = "run_restricted",
    .apparmor_restrict = "1\n",
    .probes = .{ .userns = .denied, .overlay = .setup_denied },
    .extra_files = &sim_run.extra_files,
});

fn prepare_namespaces_refused(sim: *HostSim) void {
    sim.init(1, run_restricted.files);
    run_restricted.apply(sim);
    sim.world.seed_container_host(sim_run.rootfs_path);
    sim.world.add_node(sim_run.home_path, .dir);
    sim.environment_variables = &sim_run.env_home;
    sim.faults.fail_step = step_of(.spawn);
    sim.faults.fail_step_errno = 13; // EACCES
}

/// The store's file system for the store cases: a user with a home, and a source tree to import.
var golden_files: SimFs = undefined;

const gc_module = @import("store/gc.zig");
var golden_import: @import("store/import.zig").Workspace = undefined;
var golden_store: @import("store/layout.zig").Store = undefined;
/// The digest of the sample tree `prepare_store_with_tree` imported.
var golden_digest: Digest = undefined;

/// A user's store that holds the sample tree, imported; the host can run containers.
fn prepare_store_with_tree(sim: *HostSim) void {
    sim_run.init(sim, 1);
    golden_files.init(1);
    sim.store_fs = &golden_files;
    support.make_user_store(&golden_files, ".{\n    .format = 1,\n}\n");
    support.make_source(&golden_files, 0);
    // A second file with the bytes and attributes of one in the tree: one object, two names.
    golden_files.put_file("/src/bin/ls2", 0o755, "#!shell\n");
    golden_store.at(sim.interface(), support.user_store);
    var result: @import("store/import.zig").Result = undefined;
    var diag: Diag = undefined;
    diag.reset();
    const options: @import("store/import.zig").Options = .{ .squash_owner = false, .warn = null };
    @import(
        "store/import.zig",
    ).import(&golden_store, &golden_import, "/src", options, &result, &diag) catch
        unreachable; // The sample tree imports.
    golden_digest = result.digest;
}

const golden_state = "/home/alice/.local/state/zbx/containers";

/// The container's merged directory and a shell in the container model, as the overlay would
/// show the tree.
fn prepare_overlay_dirs(sim: *HostSim) void {
    sim.world.add_node(golden_state ++ "/web-1/merged", .dir);
    inline for ([_][]const u8{ "/bin", "/proc", "/dev", "/usr/bin" }) |suffix| {
        sim.world.add_node(golden_state ++ "/web-1/merged" ++ suffix, .dir);
    }
    sim.world.add_node(golden_state ++ "/web-1/merged/bin/sh", .file);
}

fn prepare_link_limit(sim: *HostSim) void {
    prepare_store_with_tree(sim);
    golden_files.faults.link_max = 2; // The object and one name: the second shell is one too many.
}

/// A finished container "web-1" that ran the sample tree, with the upper layer a commit reads
/// (one new file in it, and whatever `extra` puts there).
const Extra = *const fn (files: *SimFs, upper: []const u8) void;

fn prepare_committable(sim: *HostSim, extra: ?Extra) void {
    prepare_store_with_tree(sim);
    const upper = golden_state ++ "/web-1/upper";
    const parents = [_][]const u8{
        "/home/alice/.local/state",
        "/home/alice/.local/state/zbx",
        golden_state,
        golden_state ++ "/web-1",
        upper,
    };
    for (parents) |parent| {
        if (golden_files.kind_of(parent) == null) golden_files.put_dir(parent, 0o755);
    }
    golden_files.put_file(upper ++ "/new", 0o644, "added\n");
    if (extra) |change| change(&golden_files, upper);
    const text = golden_digest.text();
    var view = sim_run.sample_view("web-1", 1000);
    view.tree = &text;
    view.upper = upper;
    sim_run.put_record(sim, &view);
}

fn prepare_commit_redirect(sim: *HostSim) void {
    prepare_committable(sim, put_redirect);
}

fn put_redirect(files: *SimFs, upper: []const u8) void {
    assert(std.mem.endsWith(u8, upper, "/upper"));
    files.put_dir(golden_state ++ "/web-1/upper/renamed", 0o755);
    files.put_xattr(golden_state ++ "/web-1/upper/renamed", "user.overlay.redirect", "/etc");
}

fn prepare_commit_directory(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim_run.put_record(sim, &sim_run.sample_view("web-1", 1000));
}

/// The path of the stored object a file of the sample tree became.
fn stored_object(source_path: []const u8, buffer: []u8) []const u8 {
    const object = @import("store/object.zig");
    const stat = golden_files.stat_of(source_path).?;
    const attrs: object.Attrs = .{
        .mode = stat.mode,
        .uid = stat.uid,
        .gid = stat.gid,
        .xattrs = golden_files.xattrs_of(source_path) orelse &@import("store/xattrs.zig").empty,
    };
    const id = object.object_id(Digest.of(golden_files.content_of(source_path).?), attrs);
    const hex = id.hex();
    return std.fmt.bufPrint(
        buffer,
        support.user_store ++ "/objects/{s}/{s}",
        .{ hex[0..2], hex[2..] },
    ) catch
        unreachable; // Short.
}

/// A store whose object for /etc/passwd has a changed byte.
fn prepare_damaged_object(sim: *HostSim) void {
    prepare_store_with_tree(sim);
    var buffer: [200]u8 = undefined;
    golden_files.flip_byte(stored_object("/src/etc/passwd", &buffer), 2);
}

/// A trash `aaaaaaaaaaaa` holding the sample tree's root tree object, which the store has again;
/// `promised` is what its metadata says it holds.
fn put_trash(promised: u64, with_tree: bool) void {
    const base = support.user_store ++ "/trash/aaaaaaaaaaaa";
    golden_files.put_dir(base, 0o755);
    var meta: [gc_module.meta_bytes_max]u8 = undefined;
    const text = gc_module.render_meta(&.{
        .time = 1_760_000_000,
        .expires = 1_760_000_000 + constants.store_trash_seconds,
        .objects = 0,
        .lists = 0,
        .trees = promised,
        .farms = 0,
        .bytes = 100,
        .complete = true,
    }, &meta);
    golden_files.put_file(base ++ "/meta.zon", 0o644, text);
    if (!with_tree) return;
    const hex = golden_digest.hex();
    var path: [200]u8 = undefined;
    var source: [200]u8 = undefined;
    golden_files.put_dir(base ++ "/trees", 0o755);
    golden_files.put_dir(
        std.fmt.bufPrint(&path, base ++ "/trees/{s}", .{hex[0..2]}) catch unreachable, // Short.
        0o755,
    ); // Short.
    const content = golden_files.content_of(treefile(&source)).?;
    const target = std.fmt.bufPrint(
        &path,
        base ++ "/trees/{s}/{s}",
        .{ hex[0..2], hex[2..] },
    ) catch unreachable; // Short.
    golden_files.put_file(target, 0o644, content);
}

fn treefile(buffer: []u8) []const u8 {
    const hex = golden_digest.hex();
    return std.fmt.bufPrint(
        buffer,
        support.user_store ++ "/trees/{s}/{s}",
        .{ hex[0..2], hex[2..] },
    ) catch
        unreachable; // Short.
}

fn prepare_restore_conflict(sim: *HostSim) void {
    prepare_store_with_tree(sim);
    put_trash(1, true);
}

fn prepare_trash_incomplete(sim: *HostSim) void {
    prepare_store_with_tree(sim);
    put_trash(3, false);
}

fn prepare_root_unusable(sim: *HostSim) void {
    prepare_store_with_tree(sim);
    golden_files.put_file(
        support.user_store ++ "/roots/" ++ test_util.repeat('e', 64),
        0o644,
        "not a record\n",
    );
}

var golden_lock: ?@import("store/fs.zig").Fd = null;

/// Another process is applying a gc: it holds the store lock exclusively.
fn prepare_store_locked(sim: *HostSim) void {
    prepare_store_with_tree(sim);
    const path = support.user_store ++ "/lock";
    // The descriptor stays open for the whole case, as the other process would keep it.
    golden_lock = golden_files.interface().lock(path, true, "4242 gc") catch {
        unreachable; // The store directory is there and nothing else holds the lock.
    };
}

fn prepare_overlay_refused(sim: *HostSim) void {
    prepare_store_with_tree(sim);
    prepare_overlay_dirs(sim);
    sim.world.overlay_refused = true;
}

/// Records over the limit, one of them a run whose container directory cannot be removed.
fn prepare_layers_stay(sim: *HostSim) void {
    prepare_records_unreadable(sim);
    golden_files.init(1);
    sim.store_fs = &golden_files;
    const parents = [_][]const u8{
        "/home",
        "/home/alice",
        "/home/alice/.local",
        "/home/alice/.local/state",
        "/home/alice/.local/state/zbx",
        "/home/alice/.local/state/zbx/containers",
        golden_state ++ "/damaged",
    };
    for (parents) |parent| golden_files.put_dir(parent, 0o755);
    golden_files.put_file(golden_state ++ "/damaged/left", 0o644, "x");
    golden_files.faults.fail_mutation = 0;
    golden_files.faults.fail_errno = 13;
}

fn prepare_store_host(sim: *HostSim) void {
    sim_run.init(sim, 1);
    golden_files.init(1);
    golden_files.put_dir("/home", 0o755);
    golden_files.put_dir("/home/alice", 0o755);
    sim.store_fs = &golden_files;
}

fn prepare_store_source(sim: *HostSim) void {
    prepare_store_host(sim);
    support.make_source(&golden_files, 0);
}

fn prepare_store_made(sim: *HostSim) void {
    prepare_store_host(sim);
    support.make_user_store(&golden_files, ".{\n    .format = 1,\n}\n");
}

fn prepare_ambiguous(sim: *HostSim) void {
    prepare_store_made(sim);
    const shard = support.user_store ++ "/trees/aa";
    golden_files.put_dir(shard, 0o755);
    // Two trees whose digests start with twelve a's: 62 digits in the name, ten of them a's.
    const tail = "0123456789abcdef0123456789abcdef0123456789abcdef012";
    inline for (.{ "1", "2" }) |last| {
        golden_files.put_file(shard ++ "/aaaaaaaaaa" ++ tail ++ last, 0o644, "");
    }
}

fn prepare_format_newer(sim: *HostSim) void {
    prepare_store_host(sim);
    support.make_user_store(&golden_files, ".{\n    .format = 9,\n}\n");
}

fn prepare_deep(sim: *HostSim) void {
    prepare_store_host(sim);
    support.make_chain(&golden_files, constants.store_depth_max + 1);
}

fn prepare_store_full(sim: *HostSim) void {
    prepare_store_source(sim);
    golden_files.faults.bytes_max = 85;
}

fn prepare_store_read_only(sim: *HostSim) void {
    prepare_store_source(sim);
    golden_files.faults.fail_mutation = 0;
    golden_files.faults.fail_errno = 30; // EROFS
}

fn prepare_store_growing(sim: *HostSim) void {
    prepare_store_source(sim);
    golden_files.faults.grow_on_open = true;
}

fn prepare_store_helper_refuses(sim: *HostSim) void {
    prepare_store_source(sim);
    sim.world.helper_fails_with = 1;
}

/// A tree that exists but that no root keeps.
fn prepare_tree_without_root(sim: *HostSim) void {
    prepare_store_made(sim);
    var buffer: [64]u8 = undefined;
    var writer = tree.Writer.init(&buffer);
    _ = support.put_tree_object(&golden_files, writer.finish());
}

/// A root tree whose subtree is not in the store.
fn prepare_missing_subtree(sim: *HostSim) void {
    prepare_store_made(sim);
    var buffer: [256]u8 = undefined;
    var writer = tree.Writer.init(&buffer);
    writer.begin(
        "lib",
        .dir,
        0o755,
        0,
        0,
        &@import("store/xattrs.zig").empty,
    ) catch unreachable; // Fits.
    writer.end_dir(Digest.of("missing")) catch unreachable; // Fits.
    _ = support.put_tree_object(&golden_files, writer.finish());
}

fn prepare_roots_unreadable(sim: *HostSim) void {
    prepare_store_made(sim);
    golden_files.set_unreadable(support.user_store ++ "/roots");
}

fn prepare_store_devices(sim: *HostSim) void {
    prepare_store_source(sim);
    golden_files.put("/src/null", .char_device, 0o666, .{ 0, 0 }, "");
}

fn prepare_store_attribute(sim: *HostSim) void {
    prepare_store_source(sim);
    golden_files.put_xattr("/src/etc/passwd", "trusted.thing", "1");
}

fn prepare_store_unmapped(sim: *HostSim) void {
    prepare_store_source(sim);
    // The overflow id: what the kernel shows for an owner the namespace has no mapping for.
    golden_files.set_owner_of("/src/etc/passwd", constants.store_overflow_id, 0);
}

const many_arguments: [constants.args_count_max + 1][:0]const u8 = @splat("a");

/// One case per code that the command line can trigger. B0001 is a panic and has its own test.
const cases = base_cases ++ bundle_cases ++ registry_cases;

const base_cases = [_]Case{
    .{ .code = .E0001, .args = &.{"frobnicate"}, .exit = 1 },
    .{ .code = .E0002, .args = &.{}, .exit = 1 },
    .{ .code = .E0003, .args = &.{ "help", "me" }, .exit = 1 },
    .{ .code = .E0004, .args = &.{"--frobnicate"}, .exit = 1 },
    .{ .code = .E0005, .args = &.{ "--output", "xml", "doctor" }, .exit = 1 },
    .{ .code = .E0006, .args = &.{"explain"}, .exit = 1 },
    .{ .code = .E0007, .args = &.{ "explain", "E9999" }, .exit = 1 },
    .{ .code = .E0008, .args = &many_arguments, .exit = 1 },
    .{ .code = .E0009, .args = &.{"help"}, .stdout_full = true, .exit = 2 },
    .{ .code = .E0101, .args = &.{"doctor"}, .fixture = "ubuntu_2404_restricted", .exit = 2 },
    .{ .code = .E0102, .args = &.{"doctor"}, .fixture = "old_kernel", .exit = 2 },
    .{ .code = .E0103, .args = &.{"doctor"}, .fixture = "cgroup_missing_controllers", .exit = 2 },
    .{ .code = .E0104, .args = &.{"doctor"}, .fixture = "overlay_denied", .exit = 2 },
    .{ .code = .E0105, .args = &.{"doctor"}, .fixture = "subid_missing_entry", .exit = 2 },
    .{ .code = .E0106, .args = &.{"doctor"}, .fixture = "seccomp_absent", .exit = 2 },
    .{
        .code = .E0201,
        .args = &.{ "run", "--rootfs", "./alpine", "--", "/bin/sh" },
        .prepare = prepare_container,
        .exit = 125,
    },
    .{
        .code = .E0202,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/nothere" },
        .prepare = prepare_container,
        .exit = 127,
    },
    .{
        .code = .E0203,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/sh" },
        .prepare = prepare_namespaces_refused,
        .exit = 125,
    },
    .{
        .code = .E0204,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/sh" },
        .prepare = prepare_helper_refuses,
        .exit = 125,
    },
    .{
        .code = .E0205,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/sh" },
        .prepare = prepare_proc_refused,
        .exit = 125,
    },
    .{
        .code = .E0207,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/sh" },
        .prepare = prepare_capabilities_refused,
        .exit = 125,
    },
    .{
        .code = .E0208,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/sh" },
        .prepare = prepare_seccomp_refused,
        .exit = 125,
    },
    .{
        .code = .E0209,
        .args = &.{
            "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--read-only", "--", "/bin/sh",
        },
        .prepare = prepare_no_tmp,
        .exit = 125,
    },
    .{ .code = .E0401, .args = &.{ "stop", "web-1", "--grace", "soon" }, .exit = 1 },
    .{
        .code = .E0402,
        .args = &.{ "stop", "web-1" },
        .prepare = prepare_container,
        .exit = 1,
    },
    .{
        .code = .E0403,
        .args = &.{ "stop", "web-1" },
        .prepare = prepare_unsignalable,
        .exit = 2,
    },
    .{
        .code = .E0404,
        .args = &.{ "stop", "web-1", "--grace", "100" },
        .prepare = prepare_immortal,
        .exit = 2,
    },
    .{
        .code = .E0405,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "-d", "--", "/bin/sh" },
        .prepare = prepare_no_fork,
        .exit = 125,
    },
    .{ .code = .E0406, .args = &.{ "schema", "explain" }, .exit = 1 },
    .{
        .code = .E0410,
        .args = &.{ "store", "du", "aaaaaaaaaaaa" },
        .prepare = prepare_store_made,
        .exit = 1,
    },
    .{
        .code = .E0411,
        .args = &.{ "store", "du", "aaaaaaaaaaaa" },
        .prepare = prepare_ambiguous,
        .exit = 1,
    },
    .{ .code = .E0412, .args = &.{ "store", "du", "12345" }, .exit = 1 },
    .{ .code = .E0413, .args = &.{ "store", "ls" }, .prepare = prepare_format_newer, .exit = 2 },
    .{
        .code = .E0414,
        .args = &.{ "store", "import", "/nowhere" },
        .prepare = prepare_store_host,
        .exit = 1,
    },
    .{
        .code = .E0415,
        .args = &.{ "store", "import", "/deep" },
        .prepare = prepare_deep,
        .exit = 1,
    },
    .{
        .code = .E0416,
        .args = &.{ "store", "import", "/src" },
        .prepare = prepare_store_full,
        .exit = 2,
    },
    .{
        .code = .E0417,
        .args = &.{ "store", "import", "/src" },
        .prepare = prepare_store_read_only,
        .exit = 2,
    },
    .{
        .code = .E0418,
        .args = &.{ "store", "import", "/src" },
        .prepare = prepare_store_growing,
        .exit = 1,
    },
    .{
        .code = .E0419,
        .args = &.{ "store", "import", "/src" },
        .prepare = prepare_store_helper_refuses,
        .exit = 2,
    },
    .{
        .code = .E0420,
        .args = &.{ "store", "rm", "b3:745006977617" },
        .prepare = prepare_tree_without_root,
        .exit = 1,
    },
    .{ .code = .E0421, .args = &.{ "store", "ls" }, .prepare = prepare_no_state, .exit = 2 },
    .{
        .code = .E0422,
        .args = &.{ "store", "du", "b3:dc22adc080b1" },
        .prepare = prepare_missing_subtree,
        .exit = 2,
    },
    .{
        .code = .E0423,
        .args = &.{ "store", "ls" },
        .prepare = prepare_roots_unreadable,
        .exit = 2,
    },
    .{
        .code = .W0410,
        .args = &.{ "store", "import", "/src" },
        .prepare = prepare_store_devices,
        .prints = true,
        .warning = true,
        .exit = 0,
    },
    .{
        .code = .W0411,
        .args = &.{ "store", "import", "/src" },
        .prepare = prepare_store_attribute,
        .prints = true,
        .warning = true,
        .exit = 0,
    },
    .{
        .code = .W0412,
        .args = &.{ "store", "import", "/src" },
        .prepare = prepare_store_unmapped,
        .prints = true,
        .warning = true,
        .exit = 0,
    },
    .{
        .code = .E0424,
        .args = &.{ "run", "4ccf5b88ec09", "--name", "web-1", "--", "/bin/sh" },
        .prepare = prepare_link_limit,
        .exit = 125,
    },
    .{
        .code = .E0425,
        .args = &.{ "run", "4ccf5b88ec09", "--name", "web-1", "--", "/bin/sh" },
        .prepare = prepare_overlay_refused,
        .exit = 125,
    },
    .{
        .code = .E0426,
        .args = &.{ "commit", "web-1" },
        .prepare = prepare_commit_directory,
        .exit = 1,
    },
    .{
        .code = .E0427,
        .args = &.{ "commit", "web-1" },
        .prepare = prepare_running,
        .exit = 1,
    },
    .{
        .code = .E0428,
        .args = &.{ "commit", "web-1" },
        .prepare = prepare_commit_redirect,
        .exit = 2,
    },
    .{
        .code = .E0429,
        .args = &.{ "store", "verify" },
        .prepare = prepare_damaged_object,
        .prints = true,
        .exit = 2,
    },
    .{
        .code = .E0430,
        .args = &.{ "store", "verify" },
        .prepare = prepare_damaged_object,
        .prints = true,
        .exit = 2,
    },
    .{
        .code = .E0431,
        .args = &.{
            "store",
            "gc",
            "--confirm",
            "b3:0000000000000000000000000000000000000000000000000000000000000000",
        },
        .prepare = prepare_store_with_tree,
        .exit = 1,
    },
    .{
        .code = .E0432,
        .args = &.{ "store", "restore", "aaaaaaaaaaaa" },
        .prepare = prepare_restore_conflict,
        .exit = 1,
    },
    .{
        .code = .E0433,
        .args = &.{ "store", "restore", "bbbbbbbbbbbb" },
        .prepare = prepare_store_with_tree,
        .exit = 1,
    },
    .{
        .code = .E0434,
        .args = &.{ "store", "restore", "aaaaaaaaaaaa" },
        .prepare = prepare_trash_incomplete,
        .exit = 2,
    },
    .{
        .code = .E0435,
        .args = &.{ "store", "gc" },
        .prepare = prepare_root_unusable,
        .exit = 2,
    },
    .{
        .code = .E0436,
        .args = &.{ "store", "import", "/src" },
        .prepare = prepare_store_locked,
        .exit = 1,
    },
    .{
        .code = .W0413,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/sh" },
        .prepare = prepare_layers_stay,
        .warning = true,
        .exit = 0,
    },
    .{
        .code = .E0206,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "Web_1", "--", "/bin/sh" },
        .prepare = prepare_container,
        .exit = 125,
    },
    .{
        .code = .E0301,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/sh" },
        .prepare = prepare_bus_not_there,
        .exit = 125,
    },
    .{
        .code = .E0302,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/sh" },
        .prepare = prepare_bus_rejects,
        .exit = 125,
    },
    .{
        .code = .E0303,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/sh" },
        .prepare = prepare_bus_garbage,
        .exit = 125,
    },
    .{
        .code = .E0304,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/sh" },
        .prepare = prepare_systemd_refuses,
        .exit = 125,
    },
    .{
        .code = .E0305,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/sh" },
        .prepare = prepare_name_taken,
        .exit = 125,
    },
    .{
        .code = .E0306,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--memory", "0m", "--", "/bin/sh" },
        .prepare = prepare_container,
        .exit = 125,
    },
    .{
        .code = .E0307,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--pids", "64", "--", "/bin/sh" },
        .prepare = prepare_no_bus,
        .exit = 125,
    },
    .{
        .code = .E0308,
        .args = &.{
            "run",      "--rootfs", "/srv/alpine", "--name",  "web-1",
            "--memory", "64m",      "--",          "/bin/sh",
        },
        .prepare = prepare_cgroup_refuses,
        .exit = 125,
    },
    .{
        .code = .W0301,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/sh" },
        .prepare = prepare_no_bus,
        .warning = true,
        .exit = 0,
    },
    .{
        .code = .W0302,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/sh" },
        .prepare = prepare_scope_lingers,
        .warning = true,
        .exit = 0,
    },
    .{
        .code = .W0201,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/sh" },
        .prepare = prepare_single,
        .warning = true,
        .exit = 0,
    },
    .{
        .code = .W0202,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/sh" },
        .prepare = prepare_disk_full,
        .warning = true,
        .exit = 0,
    },
    .{
        .code = .W0203,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/sh" },
        .prepare = prepare_records_unreadable,
        .warning = true,
        .exit = 0,
    },
};

fn prepare_no_state(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim.environment_variables = &.{};
}

fn prepare_with_record(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim.world.now = 1_792_873_384;
    sim_run.put_record(sim, &sim_run.sample_view("web-1", 1_792_873_000));
}

fn prepare_bundle_disk_full(sim: *HostSim) void {
    prepare_with_record(sim);
    sim.world.disk_full = true;
}

const bundle_cases = [_]Case{
    .{ .code = .E0701, .args = &.{ "bundle", "--last" }, .prepare = prepare_no_state, .exit = 2 },
    .{
        .code = .E0702,
        .args = &.{ "bundle", "--last" },
        .prepare = prepare_bundle_disk_full,
        .exit = 2,
    },
    .{ .code = .E0703, .args = &.{ "bundle", "nothere" }, .prepare = prepare_container, .exit = 1 },
    .{ .code = .E0704, .args = &.{ "bundle", "--last" }, .prepare = prepare_container, .exit = 1 },
    .{
        .code = .W0701,
        .args = &.{ "bundle", "--last", "--no-redact" },
        .prepare = prepare_with_record,
        .prints = true,
        .warning = true,
        .exit = 0,
    },
};

// ---- The registry's codes ------------------------------------------------------------------

/// One test registry and the wire to it, for the cases below (the cases run one at a time).
var golden_registry: test_registry.TestRegistry = undefined;
var golden_wire: net_sim.SimNet = undefined;

fn prepare_registry(sim: *HostSim) void {
    golden_registry.init();
    golden_wire.init(1, golden_registry.responder());
    sim.wire = &golden_wire;
}

fn prepare_wire_fault(sim: *HostSim, err: @import("registry/net.zig").Error) void {
    prepare_registry(sim);
    golden_wire.faults.fail_request = 0;
    golden_wire.faults.fail_error = err;
}

fn prepare_unknown_host(sim: *HostSim) void {
    prepare_wire_fault(sim, error.UnknownHost);
}

fn prepare_connect_failed(sim: *HostSim) void {
    prepare_wire_fault(sim, error.ConnectFailed);
}

fn prepare_untrusted(sim: *HostSim) void {
    prepare_wire_fault(sim, error.TlsUntrusted);
}

fn prepare_cut(sim: *HostSim) void {
    prepare_registry(sim);
}

const pull = [_][:0]const u8{ "pull", "--resolve-only" };

const bad_mirror_environment = [_]@import("host_sim.zig").EnvironmentVariable{
    .{ .name = "ZBX_REGISTRY_MIRRORS", .value = "mirror.gcr.io, bad host" },
};

fn prepare_bad_mirror(sim: *HostSim) void {
    prepare_registry(sim);
    sim.environment_variables = &bad_mirror_environment;
}

fn pull_case(
    comptime code: codes.Code,
    comptime reference: [:0]const u8,
    comptime prepare: ?*const fn (sim: *HostSim) void,
    comptime exit: u8,
) Case {
    return .{
        .code = code,
        .args = &(pull ++ [_][:0]const u8{reference}),
        .prepare = prepare,
        .exit = exit,
    };
}

const registry_cases = [_]Case{
    pull_case(.E0501, "Alpine:3.20", null, 1),
    pull_case(.E0502, test_registry.TestRegistry.reference(.open), prepare_unknown_host, 2),
    pull_case(.E0503, test_registry.TestRegistry.reference(.open), prepare_connect_failed, 2),
    pull_case(.E0504, test_registry.TestRegistry.reference(.open), prepare_untrusted, 2),
    pull_case(.E0505, test_registry.TestRegistry.reference(.broken), prepare_registry, 3),
    pull_case(.E0506, test_registry.TestRegistry.reference(.limited), prepare_registry, 3),
    pull_case(.E0507, test_registry.TestRegistry.reference(.denied), prepare_registry, 3),
    pull_case(.E0508, test_registry.TestRegistry.reference(.missing), prepare_registry, 1),
    pull_case(.E0509, test_registry.TestRegistry.reference(.nomatch), prepare_registry, 1),
    pull_case(.E0510, test_registry.TestRegistry.reference(.media), prepare_registry, 3),
    pull_case(.E0511, test_registry.TestRegistry.reference(.badsum), prepare_registry, 3),
    pull_case(.E0512, test_registry.TestRegistry.reference(.huge), prepare_registry, 3),
    pull_case(.E0513, test_registry.TestRegistry.reference(.cut), prepare_cut, 3),
    pull_case(.E0514, test_registry.TestRegistry.reference(.open), prepare_bad_mirror, 1),
};

const Style = enum { default, verbose, json };

/// Runs `case` with the global options for `style` placed before its arguments.
fn run_style(sim: *HostSim, case: *const Case, style: Style) !u8 {
    var items: [constants.args_count_max + 8][:0]const u8 = undefined;
    var count: u32 = 0;
    items[0] = "zbx";
    count += 1;
    const flags: []const [:0]const u8 = switch (style) {
        .default => &.{},
        .verbose => &.{"-v"},
        .json => &.{ "--output", "json" },
    };
    for (flags) |flag| {
        items[count] = flag;
        count += 1;
    }
    for (case.args) |argument| {
        items[count] = argument;
        count += 1;
    }
    sim.init(1, &.{});
    if (case.fixture) |name| {
        const fixture = fixtures.find(name).?;
        sim.init(1, fixture.files);
        fixture.apply(sim);
    }
    if (case.prepare) |prepare| prepare(sim);
    if (case.stdout_full) {
        sim.faults.write_error_per_mille = 1000;
        sim.faults.write_fault_stream = .stdout;
    }
    var iterator: SliceIterator = .{ .items = items[0..count] };
    const code = cli.run_from_iterator(sim.interface(), &iterator);
    if (golden_started) {
        golden_handle.session.release_keeper();
        golden_started = false;
    }
    if (golden_lock) |fd| {
        golden_files.interface().close(fd);
        golden_lock = null;
    }
    try testing.expectEqual(@as(u32, 0), sim.open_count());
    return code;
}

const SliceIterator = struct {
    items: []const [:0]const u8,
    index: u32 = 0,

    pub fn next(iterator: *SliceIterator) ?[:0]const u8 {
        if (iterator.index == iterator.items.len) return null;
        defer iterator.index += 1;
        return iterator.items[iterator.index];
    }
};

/// The part of the doctor's stderr that is the diagnostic of `code`: its block in text, its
/// line in JSON. Blocks are separated by a blank line and JSON objects by a newline.
fn block_of(stderr: []const u8, code: codes.Code, style: Style) []const u8 {
    const full = codes.full_name(code);
    var header_storage: [32]u8 = undefined;
    const header = switch (style) {
        .json => std.fmt.bufPrint(&header_storage, "{{\"code\":\"{s}\"", .{full}),
        else => std.fmt.bufPrint(&header_storage, "error[{s}]", .{full}),
    } catch unreachable; // A code is nine bytes.
    var start: usize = 0;
    while (start < stderr.len) {
        const end = std.mem.indexOfScalarPos(u8, stderr, start, '\n').? + 1;
        if (std.mem.startsWith(u8, stderr[start..], header)) {
            if (style == .json) return stderr[start..end];
            const blank = std.mem.indexOfPos(u8, stderr, start, "\n\n");
            return stderr[start..if (blank) |at| at + 1 else stderr.len];
        }
        start = end;
    }
    unreachable; // The case's fixture is chosen to raise this code.
}

test "golden: every code in default, verbose and JSON output" {
    // Goal: the text of each diagnostic is part of the product. Method: trigger each code
    // through run_from_iterator (the E01xx ones by a doctor fixture) and compare stderr, or the
    // code's block of it, byte for byte; the exit code is the blame's, and the code in the
    // header is the case's. A command line code leaves stdout empty; a doctor code leaves the
    // report there, with the code on its FAIL line.
    var sim: HostSim = undefined;
    inline for (cases) |case| {
        const name = @tagName(case.code);
        const expected = [_][]const u8{
            @embedFile("testdata/diag/" ++ name ++ ".txt"),
            @embedFile("testdata/diag/" ++ name ++ ".verbose.txt"),
            @embedFile("testdata/diag/" ++ name ++ ".json.txt"),
        };
        for (std.enums.values(Style), expected) |style, golden| {
            const code = try run_style(&sim, &case, style);
            const shown = if (case.fixture == null) sim.stderr() else block_of(
                sim.stderr(),
                case.code,
                style,
            );
            testing.expectEqualStrings(golden, shown) catch |err| {
                std.debug.print("GOLDEN {s} {s}\n", .{ name, @tagName(style) });
                return err;
            };
            try testing.expectEqual(case.exit, code);
            const is_run = case.args.len > 0 and std.mem.eql(u8, case.args[0], "run");
            if (!case.warning and !is_run) {
                try testing.expectEqual(codes.exit_code(codes.entry(case.code).blame), code);
            }
            if (!case.warning and is_run) try testing.expect(code >= 125);
            const full = codes.full_name(case.code);
            if (case.prints) {
                try testing.expect(sim.stdout().len > 0);
            } else if (case.fixture == null) {
                try testing.expectEqual(@as(usize, 0), sim.stdout().len);
            } else {
                var tag: [16]u8 = undefined;
                const line_end = try std.fmt.bufPrint(&tag, "  [{s}]\n", .{full});
                try testing.expect(std.mem.indexOf(u8, sim.stdout(), line_end) != null);
            }
            try testing.expect(std.mem.indexOf(u8, sim.stderr(), full) != null);
            if (style == .json) {
                // One JSON object per line: a warning, then the run's end, are two lines.
                var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, golden, "\n"), '\n');
                while (lines.next()) |line| try testing.expect(try test_util.json_is_valid(line));
            }
        }
    }
}

test "golden: a panic, in default, verbose and JSON output" {
    // Goal: B0001 as the panic handler writes it. Method: call respond (the handler minus the
    // raw write and the exit) with a fixed message in each mode. The default text hides the
    // message; verbose and JSON show it; none shows a trace.
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const message = "index out of bounds: index 5, len 3";
    const names = [_][]const u8{
        @embedFile("testdata/diag/B0001.txt"),
        @embedFile("testdata/diag/B0001.verbose.txt"),
        @embedFile("testdata/diag/B0001.json.txt"),
    };
    for ([_]render.Mode{ .text, .verbose, .json }, names) |mode, golden| {
        var state: panic.State = .{};
        panic.configure(&state, mode, .standard);
        const output = panic.respond(&state, message, &buffer).?;
        try testing.expectEqualStrings(golden, output);
        try testing.expect(!render.contains_raw_error(output));
        try testing.expectEqual(@as(u8, 70), panic.exit_code(&state));
        // A panic on a `zbx run` line is 125, so it cannot be mistaken for a container's 70.
        var run_state: panic.State = .{};
        panic.configure(&run_state, mode, .container_run);
        try testing.expectEqual(@as(u8, 125), panic.exit_code(&run_state));
    }
}

test "no raw errors: no diagnostic or doctor report shows a trace or a Zig error name" {
    // Goal: DIAGNOSTICS.md, "No stack traces for users". Method: every case in every style,
    // and the doctor against every fixture; neither stdout nor stderr may match the detector.
    var sim: HostSim = undefined;
    for (&cases) |*case| {
        for (std.enums.values(Style)) |style| {
            _ = try run_style(&sim, case, style);
            try testing.expect(!render.contains_raw_error(sim.stderr()));
            try testing.expect(!render.contains_raw_error(sim.stdout()));
        }
    }
    const doctor_args = [_][]const [:0]const u8{
        &.{ "zbx", "doctor" },
        &.{ "zbx", "-v", "doctor" },
        &.{ "zbx", "--output", "json", "doctor" },
    };
    for (fixtures.all) |fixture| {
        for (doctor_args) |args| {
            sim.init(7, fixture.files);
            fixture.apply(&sim);
            var iterator: SliceIterator = .{ .items = args };
            _ = cli.run_from_iterator(sim.interface(), &iterator);
            try testing.expect(!render.contains_raw_error(sim.stderr()));
            try testing.expect(!render.contains_raw_error(sim.stdout()));
        }
    }
    // The host with no files at all is a doctor case of its own (not a fixture).
    for (doctor_args) |args| {
        sim.init(7, &.{});
        var iterator: SliceIterator = .{ .items = args };
        _ = cli.run_from_iterator(sim.interface(), &iterator);
        try testing.expect(!render.contains_raw_error(sim.stderr()));
        try testing.expect(!render.contains_raw_error(sim.stdout()));
    }
}

test "every registered code has a case or is the panic" {
    // Goal: the registry cannot gain a code without a golden test. B0001 is covered by the
    // panic test above; every E01xx code is triggered by a doctor fixture.
    for (codes.registry) |item| {
        if (item.code == .B0001) continue;
        const covered = for (cases) |case| {
            if (case.code == item.code) break true;
        } else false;
        try testing.expect(covered);
    }
}
