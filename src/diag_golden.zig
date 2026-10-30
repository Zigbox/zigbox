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
const vm_golden = @import("mac/vm_golden.zig");
const fixtures = @import("doctor_fixtures.zig");
const run = @import("runtime/run.zig");
const doctor = @import("doctor.zig");
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
    /// A doctor warning: the text report never prints its block (a warning changes nothing for
    /// the user of the text), so the golden is the diagnostic that the check holds, rendered in
    /// each mode, and `--output json` shows it in the `zbx.doctor/1` document.
    from_report: bool = false,
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

fn prepare_no_pasta(sim: *HostSim) void {
    sim_run.start(sim, 1, sim_run.files_without_pasta);
}

fn prepare_old_pasta(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim.world.pasta_version_line = "pasta 2023_12_30.f091893\n";
}

fn prepare_pasta_fails(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim.world.pasta_behaviour = .fails;
}

fn prepare_port_taken(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim.world.ports_taken[0] = 8080;
    sim.world.ports_taken_count = 1;
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

/// The macOS VM's host: no user bus, a delegated cgroup directory, and a limit file that cannot
/// be written.
fn prepare_cgroupfs_refuses(sim: *HostSim) void {
    sim_run.init_cgroupfs(sim, 1);
    sim.world.add_node(sim_run.cgroup_root ++ "/zbx-web-1.scope/memory.max", .dir);
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

const net_user_args = [_][:0]const u8{
    "run", "--net", "user", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/sh",
};

fn publish_args(comptime forward: [:0]const u8) [9][:0]const u8 {
    return .{
        "run", "--publish", forward, "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/sh",
    };
}

/// One case per code that the command line can trigger. B0001 is a panic and has its own test.
const cases = base_cases ++ bundle_cases ++ registry_cases ++ image_cases ++ state_cases ++
    mount_cases ++ writable_cases ++ logs_cases;

const logfile = @import("runtime/logfile.zig");
const records = @import("runtime/records.zig");

/// The disk the logs of the golden cases are kept on.
var golden_logs: SimFs = undefined;

fn logs_disk(sim: *HostSim) void {
    golden_logs.init(1);
    golden_logs.put_dir("/home", 0o755);
    golden_logs.put_dir("/home/alice", 0o755);
    sim.log_fs = &golden_logs;
}

/// A finished container called web-1 with a record and no log.
fn prepare_no_log(sim: *HostSim) void {
    prepare_with_record(sim);
    logs_disk(sim);
}

/// A log from a newer zbx, and a file that is not a log.
fn prepare_log_newer(sim: *HostSim) void {
    prepare_no_log(sim);
    var header: [constants.log_header_bytes]u8 = undefined;
    logfile.encode_header(0, &header);
    header[0] = 2;
    const parts = [_][]const u8{
        "/home/alice/.local",
        "/home/alice/.local/state",
        "/home/alice/.local/state/zbx",
        sim_run.logs_path,
    };
    for (parts) |part| golden_logs.put_dir(part, 0o755);
    golden_logs.put_file(sim_run.logs_path ++ "/web-1.log", 0o600, &header);
}

/// A log that dropped its oldest output: two files, the older one first in the stream.
fn prepare_log_dropped(sim: *HostSim) void {
    prepare_no_log(sim);
    var runs: records.Dir = undefined;
    assert(records.locate(sim.interface(), &runs));
    const dir = logfile.dir_of(&runs).?;
    var writer: logfile.Writer = undefined;
    const options: logfile.WriterOptions = .{ .segment_bytes_max = 16 + 2 * 20, .record_bytes_max = 8 };
    writer.open(golden_logs.interface(), &dir, "web-1", options) catch unreachable; // Fresh disk.
    for (0..6) |number| {
        var text: [8]u8 = undefined;
        _ = std.fmt.bufPrint(&text, "line {d}\n", .{number}) catch unreachable; // Eight bytes.
        writer.append(.stdout, 1_792_873_000, &text) catch unreachable; // Room for it.
    }
    writer.close();
}

/// A run whose log disk fails every call.
fn prepare_log_disk_down(sim: *HostSim) void {
    sim_run.init(sim, 1);
    logs_disk(sim);
    golden_logs.crashed = true;
}

const logs_cases = [_]Case{
    .{ .code = .E0217, .args = &.{ "logs", "web-1" }, .prepare = prepare_no_log, .exit = 1 },
    .{ .code = .E0218, .args = &.{ "logs", "web-1" }, .prepare = prepare_log_newer, .exit = 2 },
    .{ .code = .E0219, .args = &.{ "logs", "web-1", "--tail", "many" }, .exit = 1 },
    .{
        .code = .W0204,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/sh" },
        .prepare = prepare_log_disk_down,
        .warning = true,
        .exit = 0,
    },
    .{
        .code = .W0205,
        .args = &.{ "logs", "web-1" },
        .prepare = prepare_log_dropped,
        .warning = true,
        .prints = true,
        .exit = 0,
    },
};

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
    .{
        .code = .E0600,
        .args = &.{ "run", "--publish", "8080", "--rootfs", "/srv/alpine", "--", "/bin/sh" },
        .exit = 125,
    },
    .{
        .code = .E0601,
        .args = &net_user_args,
        .prepare = prepare_no_pasta,
        .exit = 125,
    },
    .{
        .code = .E0602,
        .args = &net_user_args,
        .prepare = prepare_old_pasta,
        .exit = 125,
    },
    .{
        .code = .E0603,
        .args = &net_user_args,
        .prepare = prepare_pasta_fails,
        .exit = 125,
    },
    .{
        .code = .E0604,
        .args = &publish_args("8080:80"),
        .prepare = prepare_port_taken,
        .exit = 125,
    },
    .{
        .code = .E0605,
        .args = &publish_args("80:80"),
        .prepare = prepare_container,
        .exit = 125,
    },
    .{
        .code = .E0010,
        .args = &.{ "run", "-e", "1bad=marker-value-1", "--rootfs", "/srv/alpine", "--", "sh" },
        .exit = 125,
    },
    .{
        .code = .E0011,
        .args = &.{ "run", "-e", "UNSET_VARIABLE", "--rootfs", "/srv/alpine", "--", "sh" },
        .prepare = prepare_container,
        .exit = 125,
    },
    .{
        .code = .W0101,
        .args = &.{"doctor"},
        .fixture = "restricted_but_working",
        .exit = 0,
        .from_report = true,
    },
    .{
        .code = .W0102,
        .args = &.{"doctor"},
        .fixture = "pasta_missing",
        .exit = 0,
        .from_report = true,
    },
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
    .{ .code = .E0406, .args = &.{ "schema", "help" }, .exit = 1 },
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
        .code = .E0309,
        .args = &.{
            "run",      "--rootfs", "/srv/alpine", "--name",  "web-1",
            "--memory", "64m",      "--",          "/bin/sh",
        },
        .prepare = prepare_cgroupfs_refuses,
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

// ---- State volumes (M6) --------------------------------------------------------------------

const state_root = sim_run.state_root;
const pg_target = "pgdata:/var/lib/postgresql/data";
/// When the golden state's trash entry was made: two minutes before the simulated clock.
const trash_removed: u64 = 1_760_000_000 - 120;

fn prepare_state_world(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim_run.prepare_state(sim, &golden_files, &.{"pgdata"});
}

fn prepare_state_volume(sim: *HostSim) void {
    prepare_state_world(sim);
    golden_files.put_dir(state_root, 0o755);
    golden_files.put_dir(state_root ++ "/pgdata", 0o755);
    golden_files.put_dir(state_root ++ "/pgdata/data", 0o700);
}

fn prepare_state_held(sim: *HostSim) void {
    prepare_state_volume(sim);
    // The descriptor stays open for the whole case, as the other run would keep it.
    const path = state_root ++ "/pgdata/lock";
    golden_lock = golden_files.interface().lock(path, true, "4242 pg") catch {
        unreachable; // The volume's directory is there and nothing else holds the lock.
    };
}

fn prepare_state_trash(sim: *HostSim) void {
    prepare_state_world(sim);
    golden_files.put_dir(state_root, 0o755);
    golden_files.put_dir(state_root ++ "/.trash", 0o755);
    golden_files.put_dir(state_root ++ "/.trash/pgdata@1759999880", 0o755);
}

fn prepare_state_restore_over(sim: *HostSim) void {
    prepare_state_trash(sim);
    golden_files.put_dir(state_root ++ "/pgdata", 0o755);
}

fn prepare_state_expired(sim: *HostSim) void {
    prepare_state_trash(sim);
    sim.world.now = trash_removed + 8 * 24 * 60 * 60;
}

fn prepare_state_no_home(sim: *HostSim) void {
    prepare_state_world(sim);
    sim.environment_variables = &.{};
}

fn prepare_state_record_newer(sim: *HostSim) void {
    prepare_state_volume(sim);
    golden_files.put_file(state_root ++ "/pgdata/state.zon", 0o644, ".{\n    .version = 9,\n}\n");
}

/// The container's model has no directory for the volume, so the child's first state step
/// (making `data`) fails.
fn prepare_state_unmountable(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim_run.prepare_state(sim, &golden_files, &.{});
}

fn prepare_state_unreadable(sim: *HostSim) void {
    prepare_state_volume(sim);
    golden_files.put_dir(state_root ++ "/pgdata/data/base", 0o700);
    golden_files.set_unreadable(state_root ++ "/pgdata/data/base");
}

const state_run = [_][:0]const u8{ "run", "--rootfs", "/srv/alpine", "--name", "web-1" };

const state_cases = [_]Case{
    .{
        .code = .E0705,
        .args = &(state_run ++ [_][:0]const u8{ "--state", "PgData:/data", "--", "/bin/sh" }),
        .prepare = prepare_state_world,
        .exit = 125,
    },
    .{
        .code = .E0706,
        .args = &(state_run ++ [_][:0]const u8{ "--state", pg_target, "--", "/bin/sh" }),
        .prepare = prepare_state_held,
        .exit = 125,
    },
    .{
        .code = .E0707,
        .args = &.{ "state", "rm", "pgdata" },
        .prepare = prepare_state_world,
        .exit = 1,
    },
    .{
        .code = .E0708,
        .args = &.{ "state", "restore", "pgdata" },
        .prepare = prepare_state_restore_over,
        .exit = 1,
    },
    .{
        .code = .E0709,
        .args = &.{ "state", "restore", "pgdata" },
        .prepare = prepare_state_world,
        .exit = 1,
    },
    .{
        .code = .E0710,
        .args = &.{ "state", "restore", "pgdata" },
        .prepare = prepare_state_expired,
        .exit = 1,
    },
    .{ .code = .E0711, .args = &.{ "state", "ls" }, .prepare = prepare_state_no_home, .exit = 2 },
    .{
        .code = .E0712,
        .args = &(state_run ++ [_][:0]const u8{ "--state", pg_target, "--", "/bin/sh" }),
        .prepare = prepare_state_record_newer,
        .exit = 125,
    },
    .{
        .code = .E0713,
        .args = &(state_run ++ [_][:0]const u8{ "--state", pg_target, "--", "/bin/sh" }),
        .prepare = prepare_state_unmountable,
        .exit = 125,
    },
    .{
        .code = .W0702,
        .args = &.{ "state", "ls" },
        .prepare = prepare_state_unreadable,
        .prints = true,
        .warning = true,
        .exit = 0,
    },
};

// ---- The other mounts and the export (M6 slice 3) ---------------------------------------

fn prepare_export_terminal(sim: *HostSim) void {
    prepare_state_volume(sim);
    sim.terminal = true;
    sim.no_color_value = true;
}

fn prepare_export_fifo(sim: *HostSim) void {
    prepare_state_volume(sim);
    golden_files.put_file(state_root ++ "/pgdata/data/PG_VERSION", 0o600, "16\n");
    golden_files.put(state_root ++ "/pgdata/data/pipe", .fifo, 0o600, .{ 0, 0 }, "");
}

/// A project directory with a site in it, a link in it that points out, and a directory beside
/// it, for the cases of `--mount`.
fn prepare_mount_files(sim: *HostSim) void {
    sim_run.init(sim, 1);
    golden_files.init(1);
    sim.store_fs = &golden_files;
    for ([_][]const u8{
        "/home",
        "/home/alice",
        image_project,
        image_project ++ "/site",
        "/home/alice/other",
        "/etc",
    }) |directory| golden_files.put_dir(directory, 0o755);
    golden_files.put_symlink(image_project ++ "/escape", "/etc");
    _ = sim.world.processes[0].cwd.set(image_project);
}

fn prepare_mount_world(sim: *HostSim) void {
    prepare_mount_files(sim);
    sim.world.add_node(image_project ++ "/site", .dir); // The container's view of the host.
}

/// The service image (it runs as app:staff) and a site in the project to mount.
fn prepare_service_mount(sim: *HostSim) void {
    prepare_image_world(sim);
    setup_command(sim, &.{ "pull", test_registry.TestRegistry.reference(.service) });
    golden_files.put_dir(image_project ++ "/site", 0o755);
    sim.world.add_node(image_project ++ "/site", .dir);
}

const service_reference = test_registry.TestRegistry.reference(.service);
const mount_run = [_][:0]const u8{ "run", "--rootfs", "/srv/alpine", "--name", "web-1" };

const writable_cases = [_]Case{
    .{
        .code = .E0014,
        .args = &(mount_run ++ [_][:0]const u8{ "--mount", "site", "--", "/bin/sh" }),
        .prepare = prepare_mount_world,
        .exit = 125,
    },
    .{
        .code = .E0015,
        .args = &(mount_run ++ [_][:0]const u8{ "--user", "a:b:c", "--", "/bin/sh" }),
        .prepare = prepare_mount_world,
        .exit = 125,
    },
    .{
        .code = .E0212,
        .args = &(mount_run ++ [_][:0]const u8{ "--mount", "escape:/srv", "--", "/bin/sh" }),
        .prepare = prepare_mount_world,
        .exit = 125,
    },
    .{
        .code = .E0213,
        .args = &.{ "run", "--name", "web-1", "--mount", "site:/srv", service_reference },
        .prepare = prepare_service_mount,
        .exit = 125,
    },
    .{
        .code = .E0214,
        .args = &(mount_run ++ [_][:0]const u8{ "--mount", "missing:/srv", "--", "/bin/sh" }),
        .prepare = prepare_mount_world,
        .exit = 125,
    },
    .{
        .code = .E0215,
        .args = &(mount_run ++ [_][:0]const u8{ "--mount", "site:/srv", "--", "/bin/sh" }),
        .prepare = prepare_mount_files, // No node in the container's model: the bind fails.
        .exit = 125,
    },
    .{
        .code = .E0216,
        .args = &.{ "run", "--name", "web-1", "--user", "ghost", service_reference },
        .prepare = prepare_service_mount,
        .exit = 125,
    },
};

const mount_cases = [_]Case{
    .{
        .code = .E0012,
        .args = &(state_run ++ [_][:0]const u8{ "--tmpfs", "data", "--", "/bin/sh" }),
        .prepare = prepare_state_world,
        .exit = 125,
    },
    .{
        .code = .E0013,
        .args = &(state_run ++ [_][:0]const u8{
            "--tmpfs", "/scratch", "--tmpfs", "/scratch/in", "--", "/bin/sh",
        }),
        .prepare = prepare_state_world,
        .exit = 125,
    },
    .{
        .code = .E0210,
        .args = &(state_run ++ [_][:0]const u8{ "--bind", "/srv/missing:/data", "--", "/bin/sh" }),
        .prepare = prepare_state_world,
        .exit = 125,
    },
    .{
        .code = .E0211,
        .args = &(state_run ++ [_][:0]const u8{ "--bind", "/srv/file:/data", "--", "/bin/sh" }),
        .prepare = prepare_state_world,
        .exit = 125,
    },
    .{
        .code = .E0714,
        .args = &.{ "state", "export", "pgdata" },
        .prepare = prepare_export_terminal,
        .exit = 1,
    },
    .{
        .code = .E0715,
        .args = &.{ "state", "export", "pgdata", "-o", "/nowhere/pgdata.tar.gz" },
        .prepare = prepare_state_volume,
        .exit = 2,
    },
    .{
        .code = .E0716,
        .args = &.{ "state", "export", "pgdata" },
        .prepare = prepare_state_unreadable,
        .exit = 2,
    },
    .{
        .code = .W0703,
        .args = &.{ "state", "export", "pgdata" },
        .prepare = prepare_export_fifo,
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

fn prepare_pull(sim: *HostSim) void {
    sim_run.init(sim, 1);
    prepare_registry(sim);
    golden_files.init(1);
    golden_files.put_dir("/home", 0o755);
    golden_files.put_dir("/home/alice", 0o755);
    sim.store_fs = &golden_files;
}

fn whole_pull_case(
    comptime code: codes.Code,
    comptime reference: [:0]const u8,
    comptime warning: bool,
) Case {
    return .{
        .code = code,
        .args = &[_][:0]const u8{ "pull", reference },
        .prepare = prepare_pull,
        .prints = warning,
        .warning = warning,
        .exit = if (warning) 0 else 3,
    };
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
    whole_pull_case(.E0515, test_registry.TestRegistry.reference(.unsafe), false),
    whole_pull_case(.E0516, test_registry.TestRegistry.reference(.damaged), false),
    whole_pull_case(.W0501, test_registry.TestRegistry.reference(.special), true),
    whole_pull_case(.W0502, test_registry.TestRegistry.reference(.open), true),
};

// ---- Images, locks and running by name ---------------------------------------------------------

const image_project = "/home/alice/project";
const image_lock = image_project ++ "/zbx.lock";
const open_reference = test_registry.TestRegistry.reference(.open);

/// The host of a pull, a project directory to work in, and the roots of the containers a run
/// of these cases starts (the child's mounts are modelled, so the nodes must exist).
fn prepare_image_world(sim: *HostSim) void {
    prepare_pull(sim);
    golden_files.put_dir(image_project, 0o755);
    _ = sim.world.processes[0].cwd.set(image_project);
    sim.world.add_node("/sys", .dir);
    var path: [200]u8 = undefined;
    var inner: [220]u8 = undefined;
    const base = "/home/alice/.local/state/zbx/containers/web-1/merged";
    @memcpy(path[0..base.len], base);
    sim.world.add_node(path[0..base.len], .dir);
    for ([_][]const u8{ "/bin", "/proc", "/dev", "/usr/bin" }) |suffix| {
        const text = join(&inner, base, suffix);
        sim.world.add_node(text, .dir);
    }
    for ([_][]const u8{ "/bin/sh", "/bin/hello", "/bin/svc" }) |program| {
        const text = join(&inner, base, program);
        sim.world.add_node(text, .file);
    }
}

/// Runs a command line of the setup, and forgets what it printed.
fn setup_command(sim: *HostSim, words: []const [:0]const u8) void {
    var items: [8][:0]const u8 = undefined;
    items[0] = "zbx";
    for (words, 1..) |word, index| items[index] = word;
    var iterator: SliceIterator = .{ .items = items[0 .. words.len + 1] };
    const code = cli.run_from_iterator(sim.interface(), &iterator);
    assert(code == 0); // The setup of a case must work.
    sim.stdout_len = 0;
    sim.stderr_len = 0;
}

fn join(buffer: *[220]u8, base: []const u8, suffix: []const u8) []const u8 {
    return std.fmt.bufPrint(buffer, "{s}{s}", .{ base, suffix }) catch unreachable; // Short.
}

fn overwrite_golden(path: []const u8, text: []const u8) void {
    var copy: [256]u8 = undefined; // The path may be the model's own storage.
    @memcpy(copy[0..path.len], path);
    const own = copy[0..path.len];
    if (golden_files.kind_of(own) != null) golden_files.remove_path(own);
    golden_files.put_file(own, 0o644, text);
}

fn prepare_pulled(sim: *HostSim) void {
    prepare_image_world(sim);
    setup_command(sim, &.{ "pull", open_reference });
}

fn prepare_bad_lock(sim: *HostSim) void {
    prepare_image_world(sim);
    overwrite_golden(image_lock, ".{\n    .version = 1,\n    nonsense\n}\n");
}

/// The lock with `from` replaced by `to`.
fn change_lock(from: []const u8, to: []const u8) void {
    const original = golden_files.content_of(image_lock).?;
    var edited: [constants.lock_file_bytes_max]u8 = undefined;
    const size = std.mem.replacementSize(u8, original, from, to);
    assert(size <= edited.len);
    _ = std.mem.replace(u8, original, from, to, &edited);
    overwrite_golden(image_lock, edited[0..size]);
}

fn prepare_lock_wrong_tree(sim: *HostSim) void {
    prepare_pulled(sim);
    const tree_text = golden_registry_tree();
    change_lock(tree_text, "b3:" ++ test_util.repeat('0', 64));
}

fn prepare_lock_wrong_manifest(sim: *HostSim) void {
    prepare_pulled(sim);
    change_lock(&golden_registry.fixture.oci.amd64.digest, "sha256:" ++ test_util.repeat('1', 64));
}

/// The tree digest the lock records, read back from it.
fn golden_registry_tree() []const u8 {
    const text = golden_files.content_of(image_lock).?;
    const at = std.mem.indexOf(u8, text, "b3:").?;
    return text[at..][0..67];
}

fn prepare_other_locked(sim: *HostSim) void {
    prepare_image_world(sim);
    setup_command(sim, &.{ "pull", test_registry.TestRegistry.reference(.docker) });
}

fn prepare_ghost(sim: *HostSim) void {
    prepare_image_world(sim);
    setup_command(sim, &.{ "pull", test_registry.TestRegistry.reference(.ghost) });
}

fn prepare_service_single(sim: *HostSim) void {
    prepare_image_world(sim);
    setup_command(sim, &.{ "pull", test_registry.TestRegistry.reference(.service) });
    const environment = sim.environment_variables;
    sim_run.init_single(sim, 2);
    sim.wire = &golden_wire;
    sim.store_fs = &golden_files;
    sim.environment_variables = environment;
    _ = sim.world.processes[0].cwd.set(image_project);
    sim.world.add_node("/sys", .dir);
    const base = "/home/alice/.local/state/zbx/containers/web-1/merged";
    var inner: [220]u8 = undefined;
    sim.world.add_node(base, .dir);
    for ([_][]const u8{ "/bin", "/proc", "/dev", "/usr/bin" }) |suffix| {
        const text = join(&inner, base, suffix);
        sim.world.add_node(text, .dir);
    }
    sim.world.add_node(base ++ "/bin/svc", .file);
}

fn prepare_no_command(sim: *HostSim) void {
    prepare_pulled(sim);
    var index: u32 = 0;
    while (golden_files.alive_path(index)) |path| : (index += 1) {
        if (std.mem.indexOf(u8, path, "/store/images/") == null) continue;
        const record = golden_files.content_of(path) orelse continue;
        var kept: [4096]u8 = undefined;
        var writer = std.Io.Writer.fixed(&kept);
        var lines = std.mem.splitScalar(u8, record, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " ");
            const drop = std.mem.startsWith(u8, trimmed, ".entrypoint") or
                std.mem.startsWith(u8, trimmed, ".cmd");
            if (!drop) writer.print("{s}\n", .{line}) catch unreachable; // Sized.
        }
        overwrite_golden(path, std.mem.trimEnd(u8, writer.buffered(), "\n"));
    }
}

fn prepare_lock_unwritable(sim: *HostSim) void {
    prepare_image_world(sim);
    _ = sim.world.processes[0].cwd.set("/home/alice/gone"); // A directory that is not there.
}

const run_open = [_][:0]const u8{ "run", "--name", "web-1", open_reference };

const image_cases = [_]Case{
    whole_pull_case(.E0517, test_registry.TestRegistry.reference(.badconfig), false),
    .{
        .code = .E0518,
        .args = &.{ "pull", open_reference },
        .prepare = prepare_bad_lock,
        .exit = 1,
    },
    .{ .code = .E0519, .args = &run_open, .prepare = prepare_lock_wrong_tree, .exit = 125 },
    .{ .code = .E0520, .args = &run_open, .prepare = prepare_lock_wrong_manifest, .exit = 125 },
    .{
        .code = .E0521,
        .args = &.{ "run", "--name", "web-1", test_registry.TestRegistry.reference(.ghost) },
        .prepare = prepare_ghost,
        .exit = 125,
    },
    .{ .code = .E0522, .args = &run_open, .prepare = prepare_other_locked, .exit = 125 },
    .{
        .code = .E0523,
        .args = &.{ "run", "--name", "web-1", test_registry.TestRegistry.reference(.service) },
        .prepare = prepare_service_single,
        .exit = 125,
    },
    .{ .code = .E0524, .args = &run_open, .prepare = prepare_no_command, .exit = 125 },
    .{
        .code = .E0525,
        .args = &.{ "pull", open_reference },
        .prepare = prepare_lock_unwritable,
        .exit = 2,
    },
    .{ .code = .E0526, .args = &.{ "lock", "show" }, .prepare = prepare_image_world, .exit = 1 },
    .{
        .code = .W0503,
        .args = &run_open,
        .prepare = prepare_image_world,
        .warning = true,
        .exit = 0,
    },
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
        golden_handle.session.release_output();
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

var golden_facts: doctor.Facts = undefined;

/// The diagnostic of the warning `case` names, as the doctor's check holds it, rendered in
/// the mode `style` stands for.
fn warning_block(sim: *HostSim, case: *const Case, style: Style, buffer: []u8) []const u8 {
    const fixture = fixtures.find(case.fixture.?).?;
    sim.init(1, fixture.files);
    fixture.apply(sim);
    var report: doctor.Report = undefined;
    doctor.inspect(sim.interface(), &golden_facts, &report);
    const mode: render.Mode = switch (style) {
        .default => .text,
        .verbose => .verbose,
        .json => .json,
    };
    for (&report.checks) |*check| {
        if (check.status != .warn) continue;
        if (check.diag.code.? == case.code) return render.render(&check.diag, mode, false, buffer);
    }
    unreachable; // The case's fixture is chosen to warn with this code.
}

test "golden: every code in default, verbose and JSON output" {
    // Goal: the text of each diagnostic is part of the product. Method: trigger each code
    // through run_from_iterator (the E01xx ones by a doctor fixture) and compare stderr, or the
    // code's block of it, byte for byte; the exit code is the blame's, and the code in the
    // header is the case's. A command line code leaves stdout empty; a doctor code leaves the
    // report there, with the code on its FAIL line.
    @setEvalBranchQuota(100_000);
    var sim: HostSim = undefined;
    inline for (cases) |case| {
        const name = @tagName(case.code);
        const expected = [_][]const u8{
            @embedFile("testdata/diag/" ++ name ++ ".txt"),
            @embedFile("testdata/diag/" ++ name ++ ".verbose.txt"),
            @embedFile("testdata/diag/" ++ name ++ ".json.txt"),
        };
        for (std.enums.values(Style), expected) |style, golden| {
            if (case.from_report) {
                var storage: [constants.output_bytes_max]u8 = undefined;
                const block = warning_block(&sim, &case, style, &storage);
                testing.expectEqualStrings(golden, block) catch |err| {
                    std.debug.print("GOLDEN {s} {s}\n", .{ name, @tagName(style) });
                    return err;
                };
                continue;
            }
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
                // Text: the code ends the FAIL line. JSON: the check carries it, in the document.
                var tag: [40]u8 = undefined;
                const mark = if (style == .json)
                    try std.fmt.bufPrint(&tag, "\"code\":\"{s}\",\"diagnostic\"", .{full})
                else
                    try std.fmt.bufPrint(&tag, "  [{s}]\n", .{full});
                try testing.expect(std.mem.indexOf(u8, sim.stdout(), mark) != null);
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
        } else vm_golden.covers(item.code);
        try testing.expect(covered);
    }
}
