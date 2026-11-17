//! The `zigbox` module: the container runtime as a library, for Zigcube's agent (and anything
//! else that wants to run a container without going through the `zbx` command line). Its types
//! follow the `Runtime` contract of Zigcube's HANDOFF.md one to one:
//!
//!   - `Spec`: what to run. In M1 the root is a directory (`rootfs`) where the contract will hold
//!     an image digest; the command, the name, the labels and the environment (`env`) are the
//!     contract's. `limits` (memory bytes, pids, CPU thousandths) is enforced by the container's
//!     cgroup scope.
//!   - `start(host, spec, options, handle, gate, diag)`: starts it; on return the command is
//!     running. `StartOptions.detached` marks the run as one whose supervisor outlives the
//!     caller. Before anything is made, the run passes the node's trust policy exactly as
//!     `zbx run` does (`trust/start_gate.zig`): the same policy files (`/etc/zbx/policy.zon`,
//!     then the user's), the same verdict and tamper check, the same refusal codes (E0903 to
//!     E0907). There is no way to skip it. With no policy file it reads nothing more and changes
//!     nothing; `gate` (a `GateWorkspace`, about 17 MiB) is the caller's memory for it, one start
//!     at a time per workspace. `exec_start` runs the gate `zbx exec` runs the same way. No
//!     export starts a container or a command ungated: a build step's start is internal.
//!   - `wait(handle)`: how it ended, as an `ExitReason`. `StartOptions.timeout_ms` ends a run
//!     that lasts too long (SIGTERM, then SIGKILL after `grace_ms`); `timed_out(handle)` says so.
//!   - `signal(handle, number)`: sends it a signal, with the forwarding rule of PID 1.
//!   - `inspect(handle)`: a `Status`, `stopped` carrying the `ExitReason`.
//!   - `lifecycle.stop(ref, grace_ms, kill_wait_ms)`: SIGTERM, then SIGKILL; `list`, `adopt` (a
//!     `Ref` to a container by name, from the record and the kernel, in any process), and
//!     `Watcher.poll` for the changes. See `runtime/lifecycle.zig` for how "alive" is decided
//!     and what the poll bound is.
//!
//! Storage is the caller's. The library keeps no module-level state (the real host's errno is per
//! thread; the panic handler's settings are the `zbx` program's): a `Handle` (about 480 KiB, with
//! the plan and the doctor's `Facts`) is passed by pointer and must not move while a run is going
//! on; a `bundle.Workspace` is the same for a bundle. Two callers on two threads each bring their
//! own and share nothing (`runtime/lifecycle_tests.zig` runs two at once). Keep a `Handle` in
//! static storage or on the heap, not on a small thread's stack.
//!
//! A failure is a `Diag` (code, causes, fixes), the same structure `zbx` and `zcube why` render.
//! Nothing here prints. Warnings go to the `Warn` in `StartOptions` as they happen.
//!
//! Where the contract as written cannot be met as is, docs/demos/m2.md says so (the shape of
//! `Spec`, the poll-based event stream, `list` returning `Entry`).

const std = @import("std");

const run = @import("runtime/run.zig");
const exec_file = @import("runtime/exec.zig");
const start_gate = @import("trust/start_gate.zig");

pub const Spec = run.Spec;
pub const Label = run.Label;
pub const Limits = run.Limits;
pub const Handle = run.Handle;
pub const Status = run.Status;
pub const ExitReason = run.ExitReason;
pub const StartOptions = run.StartOptions;
pub const Warn = run.Warn;
pub const Error = run.Error;
/// The memory `start`'s trust gate works in: the caller's, in static or heap storage.
pub const GateWorkspace = start_gate.Workspace;

/// `--require-host` (M2b): the host settings a run may require (`Spec.host_requirements`),
/// read through the host and checked purely, so a caller can report them as a node's facts.
const host_settings = @import("runtime/host_settings.zig");
const host_settings_check = @import("runtime/host_settings_check.zig");
pub const HostSetting = host_settings.HostSetting;
pub const HostValueSet = host_settings.HostValueSet;
pub const HostRequirement = host_settings.HostRequirement;
pub const HostSettings = host_settings.HostSettings;
pub const parse_host_requirement = host_settings.parse_requirement;
pub const host_settings_read = host_settings_check.host_settings_read;
pub const host_requirements_check = host_settings_check.host_requirements_check;

/// `run.start` behind the trust gate. The ungated start is not part of the library.
pub const start = start_gate.start;

comptime {
    // The gated starts are the library's, so a merge that points either name back at the ungated
    // one fails to compile here rather than shipping quietly (the two signatures differ).
    std.debug.assert(@TypeOf(start) == @TypeOf(start_gate.start));
    std.debug.assert(@TypeOf(exec_start) == @TypeOf(start_gate.exec_start));
    std.debug.assert(@TypeOf(start) != @TypeOf(run.start));
    std.debug.assert(@TypeOf(exec_start) != @TypeOf(exec_file.start));
}
pub const wait = run.wait;
pub const signal = run.signal;
pub const inspect = run.inspect;
pub const failed_start = run.failed_start;
pub const timed_out = run.timed_out;

/// What a caller that did not start the container uses: list, adopt, stop, watch.
pub const lifecycle = @import("runtime/lifecycle.zig");
pub const Ref = lifecycle.Ref;
pub const Entry = lifecycle.Entry;
pub const Watcher = lifecycle.Watcher;
pub const list = lifecycle.list;
pub const adopt = lifecycle.adopt;
pub const stop = lifecycle.stop;
pub const ref_of = lifecycle.ref_of;

/// The kernel interface a run goes through: the real one for a program, the simulator for tests.
pub const host = @import("host.zig");
pub const host_real = @import("host_real.zig");
pub const host_sim = @import("host_sim.zig");

/// Diagnostics: the collector, the registry of codes, and the renderer.
pub const diag = @import("diag/diag.zig");
pub const codes = @import("diag/codes.zig");
pub const render = @import("diag/render.zig");
/// A second product's diagnostics: a finished diagnostic as plain data with JSON in and out, the
/// strings that belong to one product, and the explanation of a code given as data. Zigcube's
/// agent renders its own `ZC-` codes and Zigbox's `ZBX-` ones with the same renderer through
/// these (`render.render_diagnostic`, `explain.render_entry`).
pub const diagnostic = @import("diag/diagnostic.zig");
pub const product = @import("diag/product.zig");
pub const explain = @import("diag/explain.zig");

/// Run records: the state a run leaves in the state directory.
pub const records = @import("runtime/records.zig");

/// The log of a container: everything it wrote to standard output and error, kept up to 5 MiB
/// beside its run record (`runtime/logfile.zig` has the format). A caller that did not start the
/// container reads it with `open_log` and a `LogReader` of its own (about 33 KiB, no allocation):
/// `LogReader.next` returns records (stream, time, bytes) until `end`, and
/// `LogReader.dropped_bytes` says how much older output the cap dropped. `StartOptions.keep_log`
/// turns the log off for a run; a run that cannot write it warns once and goes on.
pub const logs = @import("runtime/logfile.zig");
pub const LogReader = logs.Reader;
pub const open_log = logs.open_log;

/// `exec` (M6b): a command in a running container, by its name, with what the container has and
/// nothing more (its namespaces, cgroup, capabilities, `no_new_privs` and seccomp filter). The
/// caller's `ExecHandle` (at most 640 KiB, asserted at compile time; keep it in static storage
/// or on the heap) holds the plan and the state; `exec_start` returns once the command runs,
/// `exec_wait` reaps it. With
/// `ExecSpec.terminal` the command gets a pseudo-terminal sized as the caller's; without, its
/// streams are the caller's. The thread that starts it must be the process's only thread at
/// that moment and must be the one that waits. `ExecExit.code` is the command's exit code.
/// `exec_start(host, spec, options, handle, gate, diag)` first meets the node's trust policy as
/// `zbx exec` does (`trust/start_gate.zig`): a refusal is `StartFailed` with E0903 to E0905 and
/// nothing started. `gate` is a `GateWorkspace`, one start or exec at a time.
///
/// `exec` names the types and the calls on a started command, and not `runtime/exec.zig`
/// itself: that file's `start` runs the command with no gate (release review A for 0.5.2).
pub const exec = struct {
    pub const Spec = exec_file.Spec;
    pub const Options = exec_file.Options;
    pub const Handle = exec_file.Handle;
    pub const Exit = exec_file.Exit;
    pub const Error = exec_file.Error;
    pub const Label = exec_file.Label;
    pub const Phase = exec_file.Phase;
    pub const wait = exec_file.wait;
    pub const signal = exec_file.signal;
};
pub const ExecSpec = exec.Spec;
pub const ExecOptions = exec.Options;
pub const ExecHandle = exec.Handle;
pub const ExecExit = exec.Exit;
pub const exec_start = start_gate.exec_start;
pub const exec_wait = exec.wait;
pub const exec_signal = exec.signal;
/// A new, unconnected IPv4 TCP socket made inside a running container's network namespace
/// (`docs/decisions/2026-11-14-zigcube-c4-requests.md`): `container_socket(host, name, .tcp4,
/// &diag)` returns a close-on-exec descriptor the caller owns, or `error.SocketFailed` with the
/// diagnostic in `diag`. Callable from any thread, many times, by a process that did not start
/// the container; it needs the same state directory and uid as `exec_start`. Threads: each
/// thread passes a `Host` of its own (one `HostReal` per thread); a `Host` is not shared. The
/// container must have been started with `--net none` (the default): `--net host` and
/// `--net user` (pasta) are refused with E0610.
pub const container_socket_module = @import("runtime/container_socket.zig");
pub const container_socket = container_socket_module.open;
pub const ContainerSocketKind = container_socket_module.Kind;
pub const ContainerSocketError = container_socket_module.Error;
/// The recent execs of a container, as `zbx bundle` shows them.
pub const exec_history = @import("runtime/exec_history.zig");

/// The store: content-addressed file trees (docs/briefs/M3-store.md). Its module doc has the
/// layout; `Store` and `import.Workspace` are the caller's storage, and the work runs in a
/// single-threaded child inside the user's namespace (`store.namespace`).
pub const store = @import("store/store.zig");

/// Lazy start's chunk resolver (docs/briefs/S2-lazy-start.md): `lazy.Source` is what a peer
/// source implements, `lazy.Resolver` what the FUSE server reads through.
pub const lazy = @import("lazy/lazy.zig");

/// The doctor's `Facts`, which `store.namespace.outside_owners` fills. It is large: keep one in
/// static storage or on the heap, not on a small thread's stack.
pub const Facts = @import("doctor.zig").Facts;

/// Pull (M6b): fetch an image into the store and record it, as `zbx pull` does, from a library
/// call (`pull.pull`). The caller passes the request (reference, platform, mirrors), its own
/// `pull.Workspace` (about 15 MiB: static storage or the heap), the store's `import.Workspace`
/// and the doctor's `Facts`, an optional progress callback and a `Result` to fill. It reads no
/// environment variable of its own, touches no `zbx.lock` and prints nothing; a failure is a
/// coded `Diag`. `pull.zig` has the rest.
pub const pull = @import("pull.zig");

/// AWS credentials (M6c): `aws_credentials_resolve(host, env, region, now_s, workspace,
/// credentials, trace)` finds the credentials a call in `region` runs with: the environment the
/// caller passes as an `AwsEnv` view (never the process's own), web identity, then the instance
/// metadata service (version 2 only). It knows nothing of pulls: ECR pull and push both call it.
/// The caller owns the `AwsWorkspace` (about 75 KiB) and the `AwsCredentials`, wipes both when
/// done, and reads the `AwsTrace` to say why nothing was found. Nothing is cached or written.
/// Where the brief's `diag` is a `Trace` here: the diagnostics are registered with the ECR client.
pub const aws_credentials = @import("aws/credentials.zig");
pub const aws_credentials_resolve = aws_credentials.resolve;
pub const AwsEnv = aws_credentials.Env;
pub const AwsCredentials = aws_credentials.Credentials;
pub const AwsWorkspace = aws_credentials.Workspace;
pub const AwsTrace = aws_credentials.Trace;

/// Google credentials (M6d): `google_credentials_resolve(host, env, now_s, sources, workspace,
/// token, trace)` finds an access token from the sources the caller's `sources` names: workload
/// identity federation through the `external_account` file a `GoogleEnv` view names (never the
/// process's own environment), then the GCE metadata server. It knows nothing of pulls. The
/// caller owns the `GoogleWorkspace` (about 124 KiB) and the `GoogleToken`, wipes both when done,
/// and reads the `GoogleTrace` to say why nothing was found. Nothing is cached or written.
pub const google_credentials = @import("google/credentials.zig");
pub const google_credentials_resolve = google_credentials.resolve;
pub const GoogleEnv = google_credentials.Env;
pub const GoogleSources = google_credentials.Sources;
pub const GoogleToken = google_credentials.Token;
pub const GoogleWorkspace = google_credentials.Workspace;
pub const GoogleTrace = google_credentials.Trace;

/// Push (M8, lane U): the packing a registry upload and an OCI layout share. `push.pack` makes
/// the one deterministic gzip layer of a tree, its config and manifest (the caller's
/// `push.Workspace`, about 8 MiB: static storage or the heap) and leaves them in the store's blob
/// cache; `push.export_layout` writes them as an OCI image layout. The same tree and settings
/// give the same digests, in any store and at any buffer size. Nothing here reads the
/// environment, touches the network or prints; a refusal is a `Stopped` error whose `Failure`
/// says which step and why (`push/diagnose.zig` turns one into a coded `Diag`). `push.send` puts
/// a packed image in a registry without credentials, over the caller's `net.Net` (its own
/// `push.UploadWorkspace`, about 12 KiB): each blob is found there, mounted from another
/// repository of the registry, or uploaded in pieces, and only then is the manifest put under
/// the tag and its digest checked. A repeat sends no blob bytes. A refusal is a coded `Diag`
/// (E0555 for a blob, E0556 for the manifest).
pub const push = struct {
    pub const pack = @import("push/pack.zig");
    pub const export_mod = @import("push/export.zig");
    pub const source = @import("push/source.zig");
    pub const Workspace = pack.Workspace;
    pub const Input = pack.Input;
    /// Writer 1 in 0.5.2, the default of `Input.writer_version`: lazy start (S2) is dormant in
    /// this release, so a library pack writes 0.5.1's bytes unless its caller asks for writer 2.
    pub const release_writer_version = pack.release_writer_version;
    pub const Packed = pack.Packed;
    pub const Exported = export_mod.Exported;
    pub const export_layout = export_mod.export_layout;
    pub const upload = @import("push/upload.zig");
    pub const UploadWorkspace = upload.Workspace;
    pub const Destination = upload.Destination;
    pub const UploadOptions = upload.Options;
    pub const UploadReport = upload.Report;
    pub const send = upload.push;
    pub const ecr = @import("push/ecr.zig");
};

/// The package writer (M8): `.deb` and `.rpm` packages and the apt and dnf trees around them,
/// reproducibly, for a second product's own packages (Zigcube's C3), and the check that reads a
/// tree back (`zig build packages-check`). Pure: the caller passes its bytes (`File.bytes`) and an
/// allocator, and owns every returned slice; nothing touches a host, a clock or the build system.
/// It signs nothing: an rpm takes a detached header signature the caller made (`rpm.Options`),
/// and the trees are unsigned until the caller signs `Release` and each `repomd.xml`. The caller
/// names its own repository (`apt.Identity`) and build host (`rpm.Options.build_host`).
///
/// Only the names below are the contract (docs/decisions/2026-11-13-zigcube-zb1-zb2.md); the
/// test at the bottom of this file fails if one is added, renamed or removed. `zig build packages`
/// writes zbx's own packages with the same files, which are also the `zigbox_package` module.
/// A compilation that links the runtime uses `zigbox.package` and never imports
/// `zigbox_package` too: Zig refuses a file in two modules, with
/// `error: file exists in modules 'zigbox' and 'zigbox_package'`.
pub const package = struct {
    const model = @import("package/model.zig");
    const deb_file = @import("package/deb.zig");
    const rpm_file = @import("package/rpm.zig");
    const apt_file = @import("package/apt.zig");
    const dnf_file = @import("package/dnf.zig");
    const check_file = @import("package_check.zig");

    pub const Package = model.Package;
    pub const File = model.File;
    pub const Architecture = model.Architecture;
    pub const Built = model.Built;
    pub const TreeFile = model.TreeFile;
    pub const Error = model.Error;
    pub const validate = model.validate;
    pub const describe = model.describe;

    pub const deb = struct {
        pub const write = deb_file.write;
        pub const file_name = deb_file.file_name;
    };

    pub const rpm = struct {
        pub const Options = rpm_file.Options;
        pub const write = rpm_file.write;
        pub const file_name = rpm_file.file_name;
        pub const header_bytes = rpm_file.header_bytes;
    };

    pub const apt = struct {
        pub const Identity = apt_file.Identity;
        pub const write = apt_file.write;
    };

    pub const dnf = struct {
        pub const write = dnf_file.write;
    };

    /// `zig build packages-check` over a tree the caller assembled: `apt/` and
    /// `rpm/<architecture>/` for both architectures, as `zig build packages` lays them out.
    /// Its errors are `CheckFailed` and `OutOfMemory` only, and its options have no test key.
    pub const check_tree = check_file.check_tree;
    pub const CheckOptions = check_file.TreeOptions;
    pub const CheckError = check_file.TreeError;
    pub const CheckSource = check_file.Source;
    pub const TreeSource = check_file.TreeSource;
};

/// The pure trust surface (M8): policy, verdict, DSSE, statements, keys' public text and the
/// signature record's type, with caller-supplied storage and no host or store. It compiles for
/// `wasm32-freestanding` (`zig build trust-wasm`). `trust_export.zig` has the rest.
pub const trust = @import("trust_export.zig");

/// State volumes (M6): their names, layout, records and locks (`state/state.zig`).
pub const state = @import("state/state.zig");

/// The build (M7): the build file's parser, the step graph and its order, the cache key, a
/// step's names and its sweeps, and the scheduler, for a caller that is not the command line.
/// The caller reads the file with `build.file.parse`, orders it with `build.graph.order`, works
/// out a step's key with `build.key.compute` and drives the steps with `build.schedule.run`,
/// with an executor of its own. A step's start (`run_step`) is not exported: it runs its base
/// with no trust gate, because `zbx build` judges each base, bound to the manifest its lock
/// names, before the step (docs/decisions/2026-11-13-library-trust-gate.md). Nothing here
/// reads the environment or prints. A failure is a coded `Diag`. `docs/demos/m7.md` has the
/// limits.
pub const build = struct {
    pub const file = @import("build/file.zig");
    pub const graph = @import("build/graph.zig");
    pub const glob = @import("build/glob.zig");
    pub const key = @import("build/key.zig");
    pub const step = struct {
        const step_file = @import("build/step.zig");
        pub const Error = step_file.Error;
        pub const Request = step_file.Request;
        pub const Result = step_file.Result;
        pub const Workspace = step_file.Workspace;
        pub const hostname = step_file.hostname;
        pub const umask = step_file.umask;
        pub const name_prefix = step_file.name_prefix;
        pub const log_group_bytes = step_file.log_group_bytes;
        pub const log_group = step_file.log_group;
        pub const cache_dir_name = step_file.cache_dir_name;
        pub const output_root_prefix = step_file.output_root_prefix;
        pub const sweep = step_file.sweep;
        pub const clear_caches = step_file.clear_caches;
    };
    pub const schedule = @import("build/schedule.zig");
};

/// The Dockerfile translator (M9): `dockerfile.translate(ws, options)` turns a Dockerfile, its
/// `.dockerignore` and the build arguments into the bytes of a `zbx.build.zon`, and fills
/// `ws.report` and the references it reached. Pure: the caller's `Resolver` says what a base
/// image's env and workdir are, and nothing is read, pulled or written here. A refusal is
/// `error.Refused` with `ws.refusal` (a code, a line, what and a fix); an image the resolver
/// cannot find is `error.Unresolved`. `dockerfile.report` renders the report (text and
/// `zbx.import/1`). The workspace is large: give it static or heap memory.
pub const dockerfile = @import("dockerfile/translate.zig");

test "the module's surface is what the contract names" {
    // Goal: a rename or a removal in the runtime that Zigcube relies on fails here, loudly.
    _ = Spec;
    _ = Handle;
    _ = Status;
    _ = ExitReason;
    _ = start;
    _ = GateWorkspace;
    _ = wait;
    _ = signal;
    _ = inspect;
    _ = stop;
    _ = list;
    _ = adopt;
    _ = Watcher;
    _ = open_log;
    _ = LogReader;
    _ = exec_start;
    _ = exec_wait;
    _ = container_socket;
    _ = pull.pull;
    _ = pull.Workspace;
    _ = aws_credentials_resolve;
    _ = google_credentials_resolve;
    _ = push.pack.pack;
    _ = push.export_layout;
    _ = push.send;
    _ = push.UploadWorkspace;
    _ = exec_signal;
    _ = ExecHandle;
    _ = trust.verdict.judge;
    _ = trust.policy.parse;
    _ = trust.dsse.parse;
    _ = trust.statement.parse;
    _ = lazy.Source;
    _ = lazy.Range;
    _ = lazy.Resolver;
    try std.testing.expect(std.meta.fieldNames(ExecExit).len == 3);
    try std.testing.expect(std.meta.fieldNames(Status).len == 3);
}

test "no export reachable from the module starts a process but the gated two" {
    // Goal: the promise in the module doc, "no export starts a container or a command ungated",
    // holds for every name a caller can reach, not only the top level (`zigbox.exec.start` once
    // reached `runtime/exec.zig`'s ungated start, release review A for 0.5.2). Method: walk every
    // public declaration of the module and of each namespace it reaches, with an explicit queue,
    // and compare each function with the starts that skip the gate and the commands built on
    // them. The gated `start` and `exec_start` must be found, so the walk is known to look.
    const step_file = @import("build/step.zig");
    const ungated = .{
        run.start,
        exec_file.start,
        step_file.run_step,
        @import("build/compose.zig").run_steps,
        @import("build_commands.zig").run,
        @import("exec_commands.zig").run_exec,
        @import("cli.zig").run,
        @import("cli.zig").run_from_iterator,
    };
    const found = comptime reachable_starts(ungated);
    try std.testing.expectEqual(@as(u32, 0), found.ungated);
    try std.testing.expect(found.gated_start);
    try std.testing.expect(found.gated_exec);
}

const Starts = struct { ungated: u32, gated_start: bool, gated_exec: bool };

fn reachable_starts(comptime ungated: anytype) Starts {
    @setEvalBranchQuota(10_000_000);
    const namespaces_max = 4096;
    var queue: [namespaces_max]type = undefined;
    queue[0] = @This();
    var count: u32 = 1;
    var found: Starts = .{ .ungated = 0, .gated_start = false, .gated_exec = false };
    var at: u32 = 0;
    while (at < count) : (at += 1) {
        const namespace = queue[at];
        for (std.meta.declarations(namespace)) |name| {
            // The type first: a `pub var` has no value at compile time, and is no namespace or
            // function either.
            const Value = @TypeOf(@field(namespace, name));
            if (Value == type) {
                const value = @field(namespace, name);
                if (!is_namespace(value)) continue;
                const seen = for (queue[0..count]) |known| {
                    if (known == value) break true;
                } else false;
                if (seen) continue;
                std.debug.assert(count < namespaces_max);
                queue[count] = value;
                count += 1;
            } else if (@typeInfo(Value) == .@"fn") {
                const value = @field(namespace, name);
                if (same_fn(value, start_gate.start)) found.gated_start = true;
                if (same_fn(value, start_gate.exec_start)) found.gated_exec = true;
                inline for (ungated) |forbidden| {
                    if (same_fn(value, forbidden)) {
                        @compileLog("an ungated start is exported", namespace, name);
                        found.ungated += 1;
                    }
                }
            }
        }
    }
    std.debug.assert(count > 1);
    return found;
}

fn is_namespace(comptime value: type) bool {
    return switch (@typeInfo(value)) {
        .@"struct", .@"union", .@"enum", .@"opaque" => true,
        else => false,
    };
}

fn same_fn(comptime value: anytype, comptime other: anytype) bool {
    if (@TypeOf(value) != @TypeOf(other)) return false;
    return value == other;
}

/// Fails unless `namespace` declares exactly `names`, in any order: a public name added to the
/// package writer's surface without a decision is as much a change of contract as one removed.
fn expect_exactly(comptime namespace: type, comptime names: []const []const u8) !void {
    const declared = comptime std.meta.declarations(namespace);
    try std.testing.expectEqual(names.len, declared.len);
    for (names) |name| {
        const found = for (declared) |declared_name| {
            if (std.mem.eql(u8, name, declared_name)) break true;
        } else false;
        if (!found) std.debug.print("not declared: {s}\n", .{name});
        try std.testing.expect(found);
    }
}

test "the package writer's surface is exactly what the decision names" {
    // Goal: ZB-1's contract (docs/decisions/2026-11-13-zigcube-zb1-zb2.md) changes only on
    // purpose. Method: each namespace's public declarations are compared, name by name and by
    // count, with the documented list; each function is referenced so its signature compiles.
    try expect_exactly(package, &.{
        "Package",    "File",         "Architecture", "Built",       "TreeFile",   "Error",
        "validate",   "describe",     "deb",          "rpm",         "apt",        "dnf",
        "check_tree", "CheckOptions", "CheckError",   "CheckSource", "TreeSource",
    });
    try expect_exactly(package.deb, &.{ "write", "file_name" });
    try expect_exactly(package.rpm, &.{ "Options", "write", "file_name", "header_bytes" });
    try expect_exactly(package.apt, &.{ "Identity", "write" });
    try expect_exactly(package.dnf, &.{"write"});
    _ = package.validate;
    _ = package.describe;
    _ = package.deb.write;
    _ = package.deb.file_name;
    _ = package.rpm.write;
    _ = package.rpm.file_name;
    _ = package.rpm.header_bytes;
    _ = package.apt.write;
    _ = package.dnf.write;
    _ = package.check_tree;
    _ = package.TreeSource.source;
    // The check exposes nothing of the OpenPGP module: no test key, no signing error.
    try std.testing.expectEqual(1, std.meta.fieldNames(package.CheckOptions).len);
    try std.testing.expect(@hasField(package.CheckOptions, "signatures_required"));
    const check_errors = @typeInfo(package.CheckError).error_set.error_names.?;
    try std.testing.expectEqual(2, check_errors.len);
    for (check_errors) |found| {
        const known = std.mem.eql(u8, found, "CheckFailed") or
            std.mem.eql(u8, found, "OutOfMemory");
        try std.testing.expect(known);
    }
}

test "the module's surface for a second product's diagnostics" {
    // Goal: what Zigcube's agent calls (docs/DECISIONS.md, "Zigcube's diagnostic codes plug into
    // Zigbox's diagnostics") fails here, loudly, if it is renamed or removed. Method: a
    // `ZBX-` diagnostic goes through the whole path a node-to-agent hop takes.
    var collector: diag.Diag = undefined;
    collector.reset();
    collector.raise(.E0001);
    collector.cause("a cause", .{});
    var finished: diagnostic.Diagnostic = undefined;
    diagnostic.from_diag(&finished, &collector);
    var json: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&json);
    try diagnostic.write_json(&writer, &finished);
    var parsed: diagnostic.Diagnostic = undefined;
    try diagnostic.parse_json(&parsed, writer.buffered());
    try std.testing.expect(parsed.equal(&finished));

    var out: [16 * 1024]u8 = undefined;
    const products = [_]product.Product{product.Product.zbx};
    const text = render.render_diagnostic(&parsed, &products, .text, false, &out);
    try std.testing.expect(std.mem.indexOf(u8, text, "zbx explain E0001") != null);
    try std.testing.expect(product.Product.find(&products, "ZC-E0201") == null);
    const entry: explain.ExplainEntry = .{
        .full_name = "ZBX-E0001",
        .severity = .@"error",
        .blame = .user,
        .summary = "s",
        .explanation = "e",
        .exit_text = "1",
    };
    try std.testing.expect(explain.render_entry(entry, &out).len > 0);
}

test "the pure trust surface imports only std and its own pure files" {
    // Goal: `trust` stays callable from `wasm32-freestanding` (`zig build trust-wasm`). Method:
    // the compile check cannot see an import of a host file that nothing calls, so read every
    // import of each exported file and allow only `std`, `constants.zig`, the lexer and the
    // exported trust files. A new import fails here by name until someone lists it on purpose.
    const sources = [_][]const u8{
        @embedFile("trust/policy.zig"),
        @embedFile("trust/verdict.zig"),
        @embedFile("trust/dsse.zig"),
        @embedFile("trust/statement.zig"),
        @embedFile("trust/key.zig"),
        @embedFile("trust/json.zig"),
        @embedFile("trust/signature_record.zig"),
        @embedFile("build/lexer.zig"),
        @embedFile("trust_export.zig"),
    };
    const allowed = [_][]const u8{
        "std",                "constants.zig",              "../constants.zig",
        "../build/lexer.zig", "policy.zig",                 "verdict.zig",
        "dsse.zig",           "statement.zig",              "key.zig",
        "json.zig",           "signature_record.zig",       "trust/policy.zig",
        "trust/verdict.zig",  "trust/dsse.zig",             "trust/statement.zig",
        "trust/key.zig",      "trust/signature_record.zig",
    };
    for (sources) |source| {
        var lines = std.mem.splitScalar(u8, source, '\n');
        while (lines.next()) |line| {
            if (std.mem.startsWith(u8, std.mem.trimStart(u8, line, " "), "//")) continue;
            const open = "@import(\"";
            var rest = line;
            while (std.mem.indexOf(u8, rest, open)) |at| {
                rest = rest[at + open.len ..];
                const end = std.mem.indexOfScalar(u8, rest, '"').?;
                var found = false;
                for (allowed) |name| found = found or std.mem.eql(u8, rest[0..end], name);
                if (!found) std.debug.print("trust imports {s}\n", .{rest[0..end]});
                try std.testing.expect(found);
            }
        }
    }
}

test "the lazy surface Zigcube's agent plugs its swarm into" {
    // Goal: S2's interface for a peer source (docs/briefs/S2-lazy-start.md, section 5) changes
    // only by decision. Method: `zigbox.lazy` declares exactly these names, a `Source` has
    // exactly these fields with these types, and a start takes a list of them.
    try expect_exactly(lazy, &.{
        "Digest",    "Wanted",    "ObjectIndex", "FetchError", "Request",
        "PeerToken", "Fetched",   "Source",      "Range",      "Location",
        "Object",    "Catalog",   "ReadError",   "Event",      "Outcome",
        "Log",       "FreeBytes", "Report",      "Resolver",   "Options",
    });
    const Source = lazy.Source;
    const fields = std.meta.fieldNames(Source);
    try std.testing.expectEqual(@as(usize, 4), fields.len);
    try std.testing.expect(@FieldType(Source, "context") == *anyopaque);
    try std.testing.expect(@FieldType(Source, "name") == []const u8);
    const Fetch = *const fn (*anyopaque, *const lazy.Request, []u8) lazy.FetchError!lazy.Fetched;
    try std.testing.expect(@FieldType(Source, "fetch") == Fetch);
    const Lied = *const fn (*anyopaque, *const lazy.Request, lazy.PeerToken) void;
    try std.testing.expect(@FieldType(Source, "lied") == Lied);
    try std.testing.expect(@FieldType(StartOptions, "lazy_sources") == []const lazy.Source);
    const none: StartOptions = .{};
    try std.testing.expectEqual(@as(usize, 0), none.lazy_sources.len);
}
