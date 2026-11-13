//! The `zigbox` module: the container runtime as a library, for Zigcube's agent (and anything
//! else that wants to run a container without going through the `zbx` command line). Its types
//! follow the `Runtime` contract of Zigcube's HANDOFF.md one to one:
//!
//!   - `Spec`: what to run. In M1 the root is a directory (`rootfs`) where the contract will hold
//!     an image digest; the command, the name, the labels and the environment (`env`) are the
//!     contract's. `limits` (memory bytes, pids, CPU thousandths) is enforced by the container's
//!     cgroup scope.
//!   - `start(host, spec, options, handle, diag)`: starts it; on return the command is running.
//!     `StartOptions.detached` marks the run as one whose supervisor outlives the caller.
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

pub const Spec = run.Spec;
pub const Label = run.Label;
pub const Limits = run.Limits;
pub const Handle = run.Handle;
pub const Status = run.Status;
pub const ExitReason = run.ExitReason;
pub const StartOptions = run.StartOptions;
pub const Warn = run.Warn;
pub const Error = run.Error;

pub const start = run.start;
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
/// caller's `ExecHandle` (about 600 KiB; keep it in static storage or on the heap) holds the
/// plan and the state; `exec_start` returns once the command runs, `exec_wait` reaps it. With
/// `ExecSpec.terminal` the command gets a pseudo-terminal sized as the caller's; without, its
/// streams are the caller's. The thread that starts it must be the process's only thread at
/// that moment and must be the one that waits. `ExecExit.code` is the command's exit code.
pub const exec = @import("runtime/exec.zig");
pub const ExecSpec = exec.Spec;
pub const ExecOptions = exec.Options;
pub const ExecHandle = exec.Handle;
pub const ExecExit = exec.Exit;
pub const exec_start = exec.start;
pub const exec_wait = exec.wait;
pub const exec_signal = exec.signal;
/// The recent execs of a container, as `zbx bundle` shows them.
pub const exec_history = @import("runtime/exec_history.zig");

/// The store: content-addressed file trees (docs/briefs/M3-store.md). Its module doc has the
/// layout; `Store` and `import.Workspace` are the caller's storage, and the work runs in a
/// single-threaded child inside the user's namespace (`store.namespace`).
pub const store = @import("store/store.zig");

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
/// reproducibly, for a second product's own packages (Zigcube's C3). Pure: the caller passes its
/// bytes (`File.bytes`) and an allocator, and owns every returned slice; nothing touches a host,
/// a clock or the build system. It signs nothing: an rpm takes a detached header signature the
/// caller made (`rpm.Options`), and the trees are unsigned until the caller signs `Release` and
/// each `repomd.xml`. `zig build packages` writes zbx's own packages with the same files. The
/// same files are the `zigbox_package` module; a compilation imports one module or the other.
pub const package = struct {
    pub const model = @import("package/model.zig");
    pub const deb = @import("package/deb.zig");
    pub const rpm = @import("package/rpm.zig");
    pub const apt = @import("package/apt.zig");
    pub const dnf = @import("package/dnf.zig");
    pub const Package = model.Package;
    pub const File = model.File;
    pub const Architecture = model.Architecture;
    pub const Built = model.Built;
    pub const TreeFile = model.TreeFile;
    pub const Error = model.Error;
    pub const validate = model.validate;
    pub const describe = model.describe;
};

/// The pure trust surface (M8): policy, verdict, DSSE, statements, keys' public text and the
/// signature record's type, with caller-supplied storage and no host or store. It compiles for
/// `wasm32-freestanding` (`zig build trust-wasm`). `trust_export.zig` has the rest.
pub const trust = @import("trust_export.zig");

/// State volumes (M6): their names, layout, records and locks (`state/state.zig`).
pub const state = @import("state/state.zig");

/// The build (M7): the build file's parser, the step graph and its order, the cache key, one
/// step's run, and the scheduler, for a caller that is not the command line. The caller reads
/// the file with `build.file.parse`, orders it with `build.graph.order`, works out a step's key
/// with `build.key.compute`, runs a step with `build.step.run_step` (its own `Workspace`, `Diag`
/// and store) and drives the steps with `build.schedule.run`. Nothing here reads the environment,
/// and nothing prints unless the request sets `stream`: then each line of the step's output goes
/// to stderr behind `<step> | `. A failure is a coded `Diag`. `docs/demos/m7.md` has the limits.
pub const build = struct {
    pub const file = @import("build/file.zig");
    pub const graph = @import("build/graph.zig");
    pub const glob = @import("build/glob.zig");
    pub const key = @import("build/key.zig");
    pub const step = @import("build/step.zig");
    pub const schedule = @import("build/schedule.zig");
};

test "the module's surface is what the contract names" {
    // Goal: a rename or a removal in the runtime that Zigcube relies on fails here, loudly.
    _ = Spec;
    _ = Handle;
    _ = Status;
    _ = ExitReason;
    _ = start;
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
    _ = pull.pull;
    _ = pull.Workspace;
    _ = aws_credentials_resolve;
    _ = push.pack.pack;
    _ = push.export_layout;
    _ = push.send;
    _ = push.UploadWorkspace;
    _ = package.deb.write;
    _ = package.rpm.write;
    _ = package.apt.write;
    _ = package.dnf.write;
    _ = exec_signal;
    _ = ExecHandle;
    _ = trust.verdict.judge;
    _ = trust.policy.parse;
    _ = trust.dsse.parse;
    _ = trust.statement.parse;
    try std.testing.expect(std.meta.fieldNames(ExecExit).len == 3);
    try std.testing.expect(std.meta.fieldNames(Status).len == 3);
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
