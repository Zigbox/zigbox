//! The M6d demo, run in a real Ubuntu 24.04 VM (the M0 harness: same image, same provisioning),
//! against the owner's Google project through GitHub's workload identity federation:
//!   1. With no Google credentials, the pull is refused with E0560, naming the sources and fix.
//!   2. With `GOOGLE_APPLICATION_CREDENTIALS` naming an external_account file whose subject token
//!      is a file: the Artifact Registry pull succeeds, `zbx run` prints `hello`, `zbx.lock`
//!      holds the digest; the JSON pull, a bundle and the logs are written for step 5.
//!   3. The same credentials pull from gcr.io.
//!   4. A repository the identity may not read is E0568, naming it and the permission.
//!   5. No secret is in any byte zbx wrote: the guest helper searches the demo user's home, its
//!      runtime directory, /tmp, /var/tmp (with the whole journal) for each OIDC token served and
//!      for the shapes of the tokens no one outside zbx sees (`ya29.`, and the realm's Basic).
//! Besides: the helper checks on live Google that the federated and access tokens have the shape
//! step 5 searches for, and pulls through the library with a token it resolved (the agent path).
//!
//! The GitHub OIDC token is fetched here, on the runner, just before the steps that need it (it
//! lives about five minutes), served once on the harness's own HTTP server, written by the guest
//! into a 0700 directory, and blanked and zeroed here. The guest console is copied into the job
//! log, so zbx's output reaches it only through the helper's mask (m6d_fixture/mask.zig).
//! Without the repository variables the demo is not run, and says so (docs/demos/m6d.md).

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;
const checks = @import("checks_m6d.zig");
const checks_m4 = @import("checks_m4.zig");
const scan = @import("m6d_fixture/scan.zig");
const harness = @import("harness.zig");
const image = @import("image.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");

const Session = session_mod.Session;
const H = harness;

const zbx = "/home/demo/zbx";
const helper = "/home/demo/m6d-helper";
const wrapper = "/home/demo/w";
const secrets_dir = "/home/demo/m6d-secrets";
const wif = "/home/demo/wif.json";
const wif_direct = "/home/demo/wif-direct.json";
const oidc_route = "/m6d/oidc";
const helper_route = "/m6d/helper";
const credentials = "GOOGLE_APPLICATION_CREDENTIALS=" ++ wif ++ " ";
/// What step 5 searches: the demo user's home, its runtime directory, /tmp and /var/tmp.
const scan_roots = [_][]const u8{ "/home/demo", "/run/user/1000", "/tmp", "/var/tmp" };
const run_name = "m6d-hello";
/// The OIDC tokens the guest may be given: the helper reads at most this many as needles.
const oidc_fetches_max = scan.needles_max - scan.shapes.len;
const oidc_body_bytes_max = 3 * scan.needle_bytes_max;

/// Runs a program in the project directory with its streams saved, then prints them only
/// through the helper's mask; exits as the program did (125 when the mask could not show them).
const wrapper_script =
    \\#!/bin/sh
    \\set -u
    \\n=$1; shift
    \\cd /home/demo/project || exit 125
    \\"$@" > /home/demo/m6d-out/$n.out 2> /home/demo/m6d-out/$n.err
    \\s=$?
    \\/home/demo/m6d-helper mask /home/demo/m6d-secrets /home/demo/m6d-out/$n.out || exit 125
    \\/home/demo/m6d-helper mask /home/demo/m6d-secrets /home/demo/m6d-out/$n.err >&2 || exit 125
    \\exit $s
    \\
;

const Oidc = struct {
    request_url: []const u8,
    request_token: []const u8,
    provider: []const u8,
    fetched_ms: u64 = 0,
    count: u32 = 0,
    token: [scan.needle_bytes_max]u8 = undefined,
    body: [oidc_body_bytes_max]u8 = undefined,
};

var oidc: Oidc = undefined;

pub fn main(init: std.process.Init) !u8 {
    harness.demo_name = "demo-m6d";
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const options = H.parse_options(init) catch |err| {
        try out.print("demo-m6d: bad arguments ({s})\n", .{@errorName(err)});
        return 2;
    };
    const config = (read_config(init, out) catch return 1) orelse return 3;
    const started = session_mod.now_ms();
    demo(init, out, options, config) catch |err| {
        if (err == error.NoKvm) return 1;
        try out.print("\ndemo-m6d: FAILED ({s})\n", .{@errorName(err)});
        return 1;
    };
    try out.print("\ndemo-m6d: PASSED in {d} s\n", .{(session_mod.now_ms() - started) / 1000});
    return 0;
}

const ConfigFailure = error{ Malformed, Unmasked };

/// The repository variables and the runner's token request, checked. Null, after one line
/// saying the demo was not run and why, when one is missing; an error, after one line saying the
/// demo failed, when one is malformed.
fn read_config(init: std.process.Init, out: *Io.Writer) ConfigFailure!?checks.Config {
    var values: [6]?[]const u8 = undefined;
    const names = checks.variable_names ++ checks.runner_names;
    for (names, 0..) |name, index| values[index] = init.environ_map.get(name);
    if (checks.first_missing(values)) |name| {
        out.print("demo-m6d: NOT RUN ({s} is not set; setup: docs/demos/m6d.md)\n", .{name}) catch
            {};
        return null;
    }
    const config: checks.Config = .{
        .provider = values[0].?,
        .service_account = values[1] orelse "",
        .gar_registry = values[2].?,
        .gcr_registry = values[3].?,
    };
    checks.check_config(config) catch |err| {
        // Set but wrong is a broken setup, not a missing one: a failure.
        out.print("demo-m6d: FAILED (the repository variables are malformed: {s}; " ++
            "see docs/demos/m6d.md)\n", .{@errorName(err)}) catch {};
        return error.Malformed;
    };
    oidc = .{
        .request_url = values[4].?,
        .request_token = values[5].?,
        .provider = config.provider,
    };
    assert(oidc.request_token.len > 0);
    mask_in_job_log(init, out, oidc.request_token) catch |err| {
        out.print("demo-m6d: FAILED (the runner's token request could not be masked: {s})\n", .{
            @errorName(err),
        }) catch {};
        return error.Unmasked;
    };
    return config;
}

fn demo(
    init: std.process.Init,
    out: *Io.Writer,
    options: H.Options,
    config: checks.Config,
) !void {
    const io = init.io;
    const accel = harness.choose_accel(options.accel, H.kvm_usable(io)) catch |err| switch (err) {
        error.NoKvm => {
            try out.print("demo-m6d: /dev/kvm is not usable here; add -Daccel=tcg\n", .{});
            return error.NoKvm;
        },
        error.BadAccel => return error.BadAccel,
    };
    const binary = try H.check_binaries(init, out, options);
    const arena = init.arena.allocator();
    const base = try image.ensure(init, options.cache_dir, out);
    const overlay_format = "{s}/overlay-demo-m6d.qcow2";
    const overlay = try std.fmt.allocPrint(arena, overlay_format, .{options.cache_dir});
    if (!options.reuse_overlay) try image.make_overlay(init, base, overlay);
    defer if (!options.keep_overlay) Io.Dir.cwd().deleteFile(io, overlay) catch {};

    var session: Session = undefined;
    const extra = [_]@import("zigbox_vm").Route{
        .{ .path = helper_route, .body = @embedFile("m6d_helper") },
        .{ .path = oidc_route, .body = "" },
    };
    try session_mod.start(&session, init, out, overlay, accel, .{
        .binary = binary,
        .extra = &extra,
    });
    defer session.deinit();
    var timer = H.Timer.start();
    try H.provision(&session, out, &timer, options.reuse_overlay);
    try H.install_binary(&session, out, &timer);
    try prepare(&session, out, config);
    const refs = try References.init(arena, config);
    var context: Context = .{ .init = init, .session = &session, .out = out, .refs = refs };
    try step_no_credentials(&context);
    const cli = try step_artifact_registry(&context);
    try step_gcr(&context);
    try step_denied(&context);
    try step_shapes(&context, config.service_account.len > 0);
    try step_agent(&context, cli);
    try step_scan(&context);
    try session.shutdown();
}

const References = struct {
    gar_host: []const u8,
    gar: []const u8,
    gcr: []const u8,
    denied: []const u8,
    /// How E0568 names the denied repository: `<project>/zbx-denied/hello`.
    denied_repository: []const u8,

    fn init(arena: std.mem.Allocator, config: checks.Config) !References {
        const slash = std.mem.indexOfScalar(u8, config.gar_registry, '/').?;
        const project = checks.project_of(config.gar_registry);
        assert(slash > 0);
        assert(project.len > 0);
        return .{
            .gar_host = config.gar_registry[0..slash],
            .gar = try std.mem.concat(arena, u8, &.{
                config.gar_registry, "/zbx-demo/hello:latest",
            }),
            .gcr = try std.mem.concat(arena, u8, &.{ config.gcr_registry, "/hello:latest" }),
            .denied = try std.mem.concat(arena, u8, &.{
                config.gar_registry, "/zbx-denied/hello:latest",
            }),
            .denied_repository = try std.mem.concat(arena, u8, &.{ project, "/zbx-denied/hello" }),
        };
    }
};

const Context = struct {
    init: std.process.Init,
    session: *Session,
    out: *Io.Writer,
    refs: References,
};

fn fail_step(out: *Io.Writer, step: []const u8, err: anyerror) anyerror {
    try out.print("demo-m6d: {s} FAILED ({s})\n", .{ step, @errorName(err) });
    return err;
}

/// The directories, the helper, the wrapper and the external_account files (no secret is in
/// any of them: each names the token file the OIDC token is written to later).
fn prepare(session: *Session, out: *Io.Writer, config: checks.Config) !void {
    try out.print("\ndemo-m6d: the project, the helper and the workload identity files\n", .{});
    const directories = "install -d -o demo -g demo -m 0755 /home/demo/project " ++
        "/home/demo/m6d-out && install -d -o demo -g demo -m 0700 " ++ secrets_dir;
    const made = try session.run(directories, limits.command_timeout_kvm_s);
    try H.show(out, "make the project, output and secrets directories", made);
    if (made.status != 0) return error.SetupFailed;
    const copied = try session.copy_in(.{
        .route = helper_route,
        .guest_path = helper,
        .owner = "demo:demo",
        .mode = "755",
    });
    try H.show(out, "install the helper", copied);
    if (copied.status != 0) return error.SetupFailed;
    try H.put_file(session, wrapper, wrapper_script);
    const impersonate = config.service_account.len > 0;
    var buffer: [1024]u8 = undefined;
    const token_path = secrets_dir ++ "/oidc";
    const file = try checks.render_external_account(&buffer, config, token_path, impersonate);
    try H.put_file(session, wif, file);
    const direct = try checks.render_external_account(&buffer, config, token_path, false);
    try H.put_file(session, wif_direct, direct);
    const shown = try session.run("cat " ++ wif ++ " " ++ wif_direct, limits.command_timeout_kvm_s);
    try H.show(out, "the external_account files (no secret: the token is a file)", shown);
    if (shown.status != 0) return error.SetupFailed;
}

/// Fetches the runner's OIDC token for the provider's default audience, without a redirect,
/// into `oidc.token`. The request token goes only in the header, never on an argument list.
fn fetch_oidc(init: std.process.Init) ![]const u8 {
    var url_buffer: [2048]u8 = undefined;
    const url = try checks.oidc_request_url(&url_buffer, oidc.request_url, oidc.provider);
    var header: [scan.needle_bytes_max]u8 = undefined;
    defer std.crypto.secureZero(u8, &header);
    defer std.crypto.secureZero(u8, &oidc.body);
    const authorization = try std.fmt.bufPrint(&header, "bearer {s}", .{oidc.request_token});
    var client: std.http.Client = .{ .allocator = init.gpa, .io = init.io };
    defer client.deinit();
    try client.initDefaultProxies(init.arena.allocator(), init.environ_map);
    var writer: Io.Writer = .fixed(&oidc.body);
    const result = client.fetch(.{
        .location = .{ .url = url },
        .redirect_behavior = .not_allowed,
        .headers = .{ .authorization = .{ .override = authorization }, .accept_encoding = .omit },
        .response_writer = &writer,
    }) catch return error.OidcFetchFailed;
    if (result.status != .ok) return error.OidcRefused;
    const token = try checks.parse_oidc_response(writer.buffered());
    assert(token.len <= oidc.token.len);
    @memcpy(oidc.token[0..token.len], token);
    return oidc.token[0..token.len];
}

/// Asks the GitHub runner to redact `secret` from the job log (`::add-mask::`), before anything
/// can print it: the guest console and the harness's own lines are copied into that log. The
/// line goes to this process's stdout, which the runner reads and does not echo, and is flushed
/// at once; never on an argument list. Outside GitHub Actions (a developer's terminal) nothing
/// is written, since there the line itself would show the secret.
fn mask_in_job_log(init: std.process.Init, out: *Io.Writer, secret: []const u8) !void {
    assert(secret.len > 0);
    // A line break would end the command early and print the rest of the secret.
    if (std.mem.indexOfAny(u8, secret, "\r\n") != null) return error.SecretNotMaskable;
    const actions = init.environ_map.get("GITHUB_ACTIONS") orelse return;
    if (!std.mem.eql(u8, actions, "true")) return;
    try out.flush();
    try out.print("::add-mask::{s}\n", .{secret});
    try out.flush();
}

/// Gives the guest a fresh OIDC token, unless the last is still fresh: served for one fetch into
/// `oidc-<n>` (0600), copied over `oidc` (the file the external_account files name), then the
/// route is blanked and the token zeroed here.
fn refresh_oidc(context: *Context) !void {
    const now = session_mod.now_ms();
    if (oidc.count > 0 and checks.oidc_fresh(oidc.fetched_ms, now)) return;
    if (oidc.count == oidc_fetches_max) return error.OidcFetchesExhausted;
    const session = context.session;
    const token = try fetch_oidc(context.init);
    defer std.crypto.secureZero(u8, &oidc.token);
    try mask_in_job_log(context.init, context.out, token);
    session.server.set_route(oidc_route, token);
    defer session.server.set_route(oidc_route, "");
    const command = try std.fmt.allocPrint(
        session.scratch_allocator(),
        "runuser -u demo -- sh -c 'umask 077 && cd {s} && " ++
            "curl -fsS -o oidc-{d} http://10.0.2.2:{d}{s} && cp oidc-{d} oidc.next && " ++
            "mv oidc.next oidc && stat -c \"%a %U %s bytes\" oidc'",
        .{ secrets_dir, oidc.count, session.server.port, oidc_route, oidc.count },
    );
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(context.out, "give the guest a GitHub OIDC token (a file; never shown)", result);
    if (result.status != 0) return error.OidcNotDelivered;
    oidc.fetched_ms = now;
    oidc.count += 1;
    assert(oidc.count <= oidc_fetches_max);
}

/// The command that runs `program` as `demo` through the wrapper, its output saved as `name`.
fn saved_command(
    buffer: []u8,
    name: []const u8,
    environment: []const u8,
    program: []const u8,
) ![]const u8 {
    assert(name.len > 0);
    assert(program.len > 0);
    const command = try std.fmt.bufPrint(buffer, "{s}{s}{s} {s} {s}", .{
        H.as_demo, environment, wrapper, name, program,
    });
    if (command.len > limits.command_bytes_max - 128) return error.CommandTooLong;
    return command;
}

fn run_saved(
    context: *Context,
    name: []const u8,
    environment: []const u8,
    program: []const u8,
) !H.SplitResult {
    var buffer: [limits.command_bytes_max]u8 = undefined;
    const command = try saved_command(&buffer, name, environment, program);
    const result = try H.run_split(context.session, command);
    try H.show_split(context.out, program, result);
    return result;
}

fn format(context: *Context, comptime text: []const u8, args: anytype) ![]const u8 {
    return std.fmt.allocPrint(context.init.arena.allocator(), text, args);
}

fn step_no_credentials(context: *Context) !void {
    try context.out.print("\ndemo-m6d: STEP 1: no Google credentials: E0560\n", .{});
    const program = try format(context, zbx ++ " pull {s}", .{context.refs.gar});
    const result = try run_saved(context, "1-pull", "", program);
    checks.check_no_credentials(result.streams, result.status, context.refs.gar_host) catch |err|
        return fail_step(context.out, "STEP 1", err);
}

fn step_artifact_registry(context: *Context) !checks_m4.PullDoc {
    const out = context.out;
    const reference = context.refs.gar;
    try out.print("\ndemo-m6d: STEP 2: workload identity: pull, run, zbx.lock\n", .{});
    try refresh_oidc(context);
    const pulled = try run_saved(context, "2-pull", credentials, try format(
        context,
        zbx ++ " pull {s}",
        .{reference},
    ));
    const printed = checks.check_pull(pulled.streams, pulled.status) catch |err|
        return fail_step(out, "STEP 2 (pull)", err);
    const digest = try context.init.arena.allocator().dupe(u8, printed);
    const json = try run_saved(context, "2-json", credentials, try format(
        context,
        zbx ++ " --output json pull {s}",
        .{reference},
    ));
    const arena = context.init.arena.allocator();
    const doc = checks_m4.check_pull_json(arena, json.streams, json.status, reference) catch |err|
        return fail_step(out, "STEP 2 (--output json)", err);
    if (!std.mem.eql(u8, doc.manifest_digest, digest)) {
        return fail_step(out, "STEP 2 (--output json)", error.DigestWrong);
    }
    const ran = try run_saved(context, "2-run", credentials, try format(
        context,
        zbx ++ " run --name " ++ run_name ++ " {s}",
        .{reference},
    ));
    checks.check_hello(ran.streams, ran.status) catch |err|
        return fail_step(out, "STEP 2 (run)", err);
    const lock = try run_saved(context, "2-lock", "", "cat zbx.lock");
    if (lock.status != 0) return fail_step(out, "STEP 2 (zbx.lock)", error.ExitCodeWrong);
    checks.check_lock(lock.streams.stdout, reference, digest) catch |err|
        return fail_step(out, "STEP 2 (zbx.lock)", err);
    try write_records(context);
    return doc;
}

/// What step 5 searches besides the pulls: a bundle of the run, unredacted (so a secret in the
/// record would be in it), and the run's logs.
fn write_records(context: *Context) !void {
    const bundle = try run_saved(context, "2-bundle", "", zbx ++ " bundle --no-redact " ++
        run_name);
    if (bundle.status != 0) return fail_step(context.out, "STEP 2 (bundle)", error.ExitCodeWrong);
    // Shown, not checked: a foreground run's logs may be empty; step 5 searches what is there.
    _ = try run_saved(context, "2-logs", "", zbx ++ " logs " ++ run_name);
}

fn step_gcr(context: *Context) !void {
    try context.out.print("\ndemo-m6d: STEP 3: the same credentials pull from gcr.io\n", .{});
    try refresh_oidc(context);
    const program = try format(context, zbx ++ " pull {s}", .{context.refs.gcr});
    const result = try run_saved(context, "3-pull", credentials, program);
    _ = checks.check_pull(result.streams, result.status) catch |err|
        return fail_step(context.out, "STEP 3", err);
}

fn step_denied(context: *Context) !void {
    try context.out.print("\ndemo-m6d: STEP 4: a repository the identity may not read\n", .{});
    try refresh_oidc(context);
    const program = try format(context, zbx ++ " pull {s}", .{context.refs.denied});
    const result = try run_saved(context, "4-pull", credentials, program);
    const repository = context.refs.denied_repository;
    checks.check_denied(result.streams, result.status, repository) catch |err|
        return fail_step(context.out, "STEP 4", err);
}

fn step_shapes(context: *Context, impersonate: bool) !void {
    try context.out.print("\ndemo-m6d: the tokens zbx makes have the shape step 5 searches\n", .{});
    try refresh_oidc(context);
    const program = if (impersonate)
        helper ++ " shapes federated " ++ wif_direct ++ " access " ++ wif
    else
        helper ++ " shapes federated " ++ wif;
    const result = try run_saved(context, "shapes", "", program);
    checks.check_shapes(result.streams, result.status, impersonate) catch |err|
        return fail_step(context.out, "the shape check", err);
}

fn step_agent(context: *Context, cli: checks_m4.PullDoc) !void {
    try context.out.print("\ndemo-m6d: the agent: the library pulls with its own token\n", .{});
    try refresh_oidc(context);
    const reference = context.refs.gar;
    const program = try format(context, helper ++ " agent {s}", .{reference});
    const result = try run_saved(context, "agent", credentials, program);
    const arena = context.init.arena.allocator();
    checks.check_agent(arena, result.streams, result.status, reference, cli) catch |err|
        return fail_step(context.out, "the agent", err);
}

fn step_scan(context: *Context) !void {
    try context.out.print("\ndemo-m6d: STEP 5: no secret in any byte zbx wrote\n", .{});
    const session = context.session;
    const journal = "journalctl --no-pager > /var/tmp/m6d-journal.txt && " ++
        "du -sh /home/demo /run/user/1000 /tmp /var/tmp";
    const dumped = try session.run(journal, limits.command_timeout_kvm_s);
    try H.show(context.out, "write the whole journal where the search reads it", dumped);
    if (dumped.status != 0) return fail_step(context.out, "STEP 5", error.JournalNotWritten);
    const command = helper ++ " scan " ++ secrets_dir ++ " " ++ zbx ++ "," ++ helper ++
        " " ++ scan_roots[0] ++ " " ++ scan_roots[1] ++ " " ++ scan_roots[2] ++ " " ++
        scan_roots[3];
    const result = try H.run_split(session, command);
    try H.show_split(context.out, command, result);
    const needles_min: u32 = oidc.count + @as(u32, scan.shapes.len);
    // The demo user's home holds zbx's store and records, /var/tmp the journal just written;
    // the runtime directory and /tmp may be empty, but must be searched.
    const nonempty = [_][]const u8{ scan_roots[0], scan_roots[3] };
    const roots: []const []const u8 = &scan_roots;
    checks.check_scan(result.streams, result.status, needles_min, roots, &nonempty) catch |err|
        return fail_step(context.out, "STEP 5", err);
}

test "the wrapper fits a put_file, and the longest command fits the console" {
    // Goal: the variables' bound (`value_bytes_max`) keeps every command under the console's
    // limit with room for run_split's redirection. Method: build the longest command with
    // references made from values at the bound.
    try std.testing.expect(wrapper_script.len <= @import("zigbox_vm").limits.put_file_bytes_max);
    const value: [checks.value_bytes_max]u8 = @splat('a');
    var reference: [checks.value_bytes_max + 64]u8 = undefined;
    const longest = try std.fmt.bufPrint(&reference, "{s}/zbx-denied/hello:latest", .{&value});
    var program_buffer: [512]u8 = undefined;
    const program = try std.fmt.bufPrint(&program_buffer, zbx ++ " --output json pull {s}", .{
        longest,
    });
    var buffer: [limits.command_bytes_max]u8 = undefined;
    const command = try saved_command(&buffer, "2-json", credentials, program);
    try std.testing.expect(std.mem.startsWith(u8, command, H.as_demo));
    try std.testing.expect(std.mem.indexOf(u8, command, wrapper ++ " 2-json ") != null);
}

test {
    _ = @import("checks_m6d.zig");
}
