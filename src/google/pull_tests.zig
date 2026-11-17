//! M6d slice 2: `zbx pull` and `zbx run` of an Artifact Registry or gcr.io reference, end to end
//! through the command line, against the simulated Google (`google_sim.zig`). The demo's five
//! steps, each refusal the client turns into a code, where every credential went, and that no
//! secret is left in an output, on disk or in the pull's memory.

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const cli = @import("../cli.zig");
const codes = @import("../diag/codes.zig");
const constants = @import("../constants.zig");
const credentials_mod = @import("credentials.zig");
const doctor = @import("../doctor.zig");
const fs_sim = @import("../store/fs_sim.zig");
const google_sim = @import("google_sim.zig");
const host_sim = @import("../host_sim.zig");
const import = @import("../store/import.zig");
const net_sim = @import("../registry/net_sim.zig");
const parse = @import("parse.zig");
const parse_tests = @import("parse_tests.zig");
const pull = @import("../pull.zig");
const sim_run = @import("../runtime/sim_run.zig");
const lazy_start = @import("../lazy_start.zig");
const images_mod = @import("../store/images.zig");
const store_open = @import("../store/open.zig");
const Diag = @import("../diag/diag.zig").Diag;
const Store = @import("../store/layout.zig").Store;
const Warn = @import("../store/namespace.zig").Warn;

const EnvironmentVariable = host_sim.EnvironmentVariable;

const credentials_path = "/home/ci/gcp.json";
const subject_path = "/run/zbx/oidc-token";
const key_path = "/home/ci/sa-key.json";
const user_path = "/home/ci/adc.json";
const project = "/home/alice/project";
const lock_path = project ++ "/zbx.lock";
const repository = "fixture/cdn";
const reference = google_sim.registry_host ++ "/" ++ repository ++ ":latest";
const gcr_reference = "gcr.io/" ++ repository ++ ":latest";

const disk_files = sim_run.files ++ [_]host_sim.File{
    .{ .path = credentials_path, .content = parse_tests.file_account },
    .{ .path = subject_path, .content = google_sim.subject_token ++ "\n" },
    .{ .path = key_path, .content = "{\"type\":\"service_account\",\"private_key\":\"-----\"}" },
    .{ .path = user_path, .content = "{\"type\":\"authorized_user\",\"refresh_token\":\"x\"}" },
};

const wif_env = sim_run.env_home ++ [_]EnvironmentVariable{
    .{ .name = "GOOGLE_APPLICATION_CREDENTIALS", .value = credentials_path },
};
const missing_file_env = sim_run.env_home ++ [_]EnvironmentVariable{
    .{ .name = "GOOGLE_APPLICATION_CREDENTIALS", .value = "/nowhere/gcp.json" },
};
const key_env = sim_run.env_home ++ [_]EnvironmentVariable{
    .{ .name = "GOOGLE_APPLICATION_CREDENTIALS", .value = key_path },
};
const user_env = sim_run.env_home ++ [_]EnvironmentVariable{
    .{ .name = "GOOGLE_APPLICATION_CREDENTIALS", .value = user_path },
};
const mirror_env = wif_env ++ [_]EnvironmentVariable{
    .{ .name = "ZBX_REGISTRY_MIRRORS", .value = "mirror.example" },
};

var command_storage: ?*cli.Storage = null;
var gc_tables: ?[]align(8) u8 = null;
var store_disk: ?*fs_sim.SimFs = null;

const World = struct {
    sim: host_sim.HostSim,
    google: google_sim.GoogleSim,
    wire: net_sim.SimNet,
    /// What the wire keeps of an upload: STS's form and IAM's body. 64 KiB, as a request larger
    /// than the buffer is dropped.
    received: [64 * 1024]u8,

    fn create() !*World {
        return std.heap.page_allocator.create(World);
    }

    fn destroy(world: *World) void {
        std.heap.page_allocator.destroy(world);
    }

    fn setup(world: *World, seed: u64, env: []const EnvironmentVariable) void {
        world.setup_at(seed, env, google_sim.registry_host);
    }

    fn setup_at(
        world: *World,
        seed: u64,
        env: []const EnvironmentVariable,
        comptime registry: []const u8,
    ) void {
        sim_run.start(&world.sim, seed, &disk_files);
        world.google.init_at(registry);
        world.google.now_s = world.sim.world.now;
        // Off GCE unless a test says otherwise: step 1 of the demo.
        world.google.metadata = .absent;
        world.wire.init(seed, world.google.responder());
        world.wire.received = &world.received;
        world.sim.wire = &world.wire;
        world.sim.environment_variables = env;
        const disk = store_disk orelse made: {
            store_disk = std.heap.page_allocator.create(fs_sim.SimFs) catch unreachable; // Tests.
            break :made store_disk.?;
        };
        disk.init(seed);
        disk.put_dir("/home", 0o755);
        disk.put_dir("/home/alice", 0o755);
        disk.put_dir(project, 0o755);
        world.sim.store_fs = disk;
        _ = world.sim.world.processes[0].cwd.set(project);
    }

    fn run(world: *World, args: []const [:0]const u8) u8 {
        world.sim.stdout_len = 0;
        world.sim.stderr_len = 0;
        var iterator: sim_run.SliceIterator = .{ .items = args };
        return cli.run_with(world.sim.interface(), &iterator, storage_of());
    }

    fn pull_of(world: *World, text: [:0]const u8) u8 {
        return world.run(&.{ "zbx", "-v", "pull", text });
    }

    fn prepare_run(world: *World, name: []const u8) void {
        world.sim.world.add_node("/sys", .dir);
        var path: [200]u8 = undefined;
        var inner: [220]u8 = undefined;
        const format = "/home/alice/.local/state/zbx/containers/{s}/merged";
        const merged = std.fmt.bufPrint(&path, format, .{name}) catch unreachable; // Short.
        world.sim.world.add_node(merged, .dir);
        for ([_][]const u8{ "/bin", "/proc", "/dev", "/usr/bin" }) |suffix| {
            const target = std.fmt.bufPrint(&inner, "{s}{s}", .{ merged, suffix });
            world.sim.world.add_node(target catch unreachable, .dir); // Short.
        }
        for ([_][]const u8{ "/bin/sh", "/bin/hello", "/bin/other", "/bin/svc" }) |program| {
            const target = std.fmt.bufPrint(&inner, "{s}{s}", .{ merged, program });
            world.sim.world.add_node(target catch unreachable, .file); // Short.
        }
    }

    fn expect_lock_digest(world: *const World, text: []const u8) !void {
        const lock = store_disk.?.content_of(lock_path) orelse "";
        try testing.expect(std.mem.indexOf(u8, lock, text) != null);
        const digest = &world.google.fixture.oci.amd64.digest;
        try testing.expect(std.mem.indexOf(u8, lock, digest) != null);
    }

    fn stderr_has(world: *const World, text: []const u8) bool {
        return std.mem.indexOf(u8, world.sim.stderr(), text) != null;
    }

    /// Every secret the model issued, and the realm's Basic value, and Google's messages.
    fn secrets(world: *const World, basic: *[128]u8, metadata_basic: *[128]u8) [9][]const u8 {
        return .{
            google_sim.subject_token,       google_sim.federated_token,
            google_sim.access_token,        google_sim.metadata_token,
            google_sim.message_marker,      google_sim.runner_authorization,
            world.google.basic_text(basic), metadata_basic_text(metadata_basic),
            "registry-token",
        };
    }

    /// Nothing secret is in an output or on the store's disk.
    fn expect_clean(world: *const World) !void {
        var basic: [128]u8 = undefined;
        var metadata_basic: [128]u8 = undefined;
        for (world.secrets(&basic, &metadata_basic)) |secret| {
            try testing.expect(std.mem.indexOf(u8, world.sim.stdout(), secret) == null);
            try testing.expect(std.mem.indexOf(u8, world.sim.stderr(), secret) == null);
            var index: u32 = 0;
            while (store_disk.?.alive_path(index)) |path| : (index += 1) {
                const content = store_disk.?.content_of(path) orelse continue;
                try testing.expect(std.mem.indexOf(u8, content, secret) == null);
            }
        }
    }

    /// Every buffer that held a secret is zero when the command has ended, and no secret is left
    /// anywhere in the pull's memory.
    fn expect_wiped(world: *const World) !void {
        const workspace = &command_storage.?.pull;
        const google = &workspace.google;
        try expect_zero(&google.token.bytes);
        try expect_zero(&google.workspace.credentials_file);
        try expect_zero(&google.workspace.subject_token);
        try expect_zero(&google.workspace.request_body);
        try expect_zero(&google.workspace.response);
        try expect_zero(&google.workspace.federated_token);
        try expect_zero(&workspace.library.client.basic);
        try expect_zero(&workspace.library.client.token);
        try expect_zero(&workspace.library.client.token_body);
        var basic: [128]u8 = undefined;
        var metadata_basic: [128]u8 = undefined;
        for (world.secrets(&basic, &metadata_basic)) |secret| {
            if (std.mem.eql(u8, secret, google_sim.message_marker)) continue;
            try testing.expect(std.mem.indexOf(u8, std.mem.asBytes(workspace), secret) == null);
        }
    }

    /// The model saw no credential where it must not go, no request to a host it does not know,
    /// every request that carried a credential was marked secret and went to Google's services
    /// or to the registry's own host, and every request with a body went to STS or IAM.
    fn expect_where_sent(world: *const World) !void {
        try testing.expectEqual(@as(u32, 0), world.google.leaked);
        try testing.expectEqual(@as(u32, 0), world.google.stray);
        var index: u32 = 0;
        while (world.wire.logged(index)) |entry| : (index += 1) {
            if (entry.sent > 0) {
                // A body is a credential in a pull (STS's form holds the subject token, IAM's
                // names the account): it goes only to those two, marked secret.
                try testing.expect(entry.secret);
                const service = std.mem.eql(u8, entry.host_text(), parse.sts_host) or
                    std.mem.eql(u8, entry.host_text(), parse.iam_host);
                try testing.expect(service);
            }
            if (!entry.credential_sent()) continue;
            const host = entry.host_text();
            // The registry's own bearer token is held as any registry's is; every other
            // credential (the realm's Basic, the services' tokens) travels marked secret.
            const registry_bearer = std.mem.eql(u8, host, world.google.registry_name) and
                entry.basic_len == 0 and entry.authorization_len == 0;
            if (!registry_bearer) try testing.expect(entry.secret);
            const allowed = std.mem.eql(u8, host, world.google.registry_name) or
                std.mem.eql(u8, host, parse.iam_host) or
                std.mem.eql(u8, host, google_sim.subject_host);
            try testing.expect(allowed);
        }
    }
};

/// The command storage the tests share, made on first use.
fn storage_of() *cli.Storage {
    const storage = command_storage orelse made: {
        const allocator = std.heap.page_allocator;
        command_storage = allocator.create(cli.Storage) catch unreachable; // Tests.
        gc_tables = allocator.alignedAlloc(u8, .@"8", 8 << 20) catch unreachable; // Tests.
        break :made command_storage.?;
    };
    storage.gc_tables = gc_tables.?;
    return storage;
}

fn expect_zero(bytes: []const u8) !void {
    for (bytes) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

/// The realm's Basic value for the metadata server's token.
fn metadata_basic_text(out: *[128]u8) []const u8 {
    const plain = constants.google_realm_user ++ ":" ++ google_sim.metadata_token;
    return std.base64.standard.Encoder.encode(out, plain);
}

test "the demo's first step: no Google credentials is E0560, naming both sources" {
    // Goal: off GCE with no GOOGLE_APPLICATION_CREDENTIALS, the anonymous pull is refused at the
    // realm, the metadata server is asked once (nothing answers) and the refusal names workload
    // identity and the metadata server, with the fix.
    const world = try World.create();
    defer world.destroy();
    world.setup(1, &sim_run.env_home);
    try testing.expectEqual(@as(u8, 2), world.pull_of(reference));
    try testing.expect(world.stderr_has("error[ZBX-E0560]"));
    try testing.expect(world.stderr_has("no Google credentials were found"));
    try testing.expect(world.stderr_has("GOOGLE_APPLICATION_CREDENTIALS"));
    try testing.expectEqual(@as(u32, 1), world.google.metadata_calls);
    try testing.expectEqual(@as(u32, 1), world.google.realm_calls);
    try testing.expectEqual(@as(u32, 0), world.google.sts_calls);
    try world.expect_where_sent();
    try world.expect_clean();
    try world.expect_wiped();
}

test "the demo's second step: workload identity pulls, and the lock holds the digest" {
    // Goal: the subject token goes to STS only, the federated token to IAM only, the access token
    // to the same-host realm only as Basic; the metadata server is never asked once the variable
    // is set. The blobs redirect to a relative path on the registry host, as Artifact Registry's.
    const world = try World.create();
    defer world.destroy();
    world.setup(2, &wif_env);
    try testing.expectEqual(@as(u8, 0), world.pull_of(reference));
    try testing.expectEqual(@as(u32, 1), world.google.sts_calls);
    try testing.expectEqual(@as(u32, 1), world.google.iam_calls);
    try testing.expectEqual(@as(u32, 0), world.google.metadata_calls);
    try testing.expectEqual(@as(u32, 1), world.google.realm_calls);
    try testing.expectEqual(@as(u32, 1), world.google.realm_ok);
    try testing.expectEqual(@as(u32, 0), world.google.storage_served);
    try world.expect_lock_digest(reference);
    try world.expect_where_sent();
    try world.expect_clean();
    try world.expect_wiped();
}

test "the demo's second step through zbx run, which has its own way to the pull" {
    const world = try World.create();
    defer world.destroy();
    world.setup(3, &wif_env);
    world.prepare_run("web-1");
    const code = world.run(&.{ "zbx", "run", "--name", "web-1", reference });
    if (code != 0) std.debug.print("RUN: {s}\n", .{world.sim.stderr()});
    try testing.expectEqual(@as(u8, 0), code);
    try testing.expectEqual(@as(u32, 1), world.google.sts_calls);
    try testing.expectEqual(@as(u32, 1), world.google.realm_ok);
    try testing.expect(world.sim.world.processes[1].exec_argv_len > 0);
    try world.expect_lock_digest(reference);
    try world.expect_where_sent();
    try world.expect_clean();
    try world.expect_wiped();
}

test "the demo's third step: gcr.io with the same credentials" {
    const world = try World.create();
    defer world.destroy();
    world.setup_at(4, &wif_env, "gcr.io");
    try testing.expectEqual(@as(u8, 0), world.pull_of(gcr_reference));
    try testing.expectEqual(@as(u32, 1), world.google.realm_ok);
    try world.expect_lock_digest(gcr_reference);
    try world.expect_where_sent();
    try world.expect_clean();
}

test "the demo's fourth step, and every answer a missing repository may get" {
    // Goal: the realm refusing, or granting and the manifest refusing, each names the repository
    // and the permission (or that it does not exist); a token the realm refuses is E0567. The
    // owner has not checked which of the missing-repository answers Google gives, so all three.
    const Case = struct { fault: google_sim.RegistryFault, code: []const u8, exit: u8 };
    const cases = [_]Case{
        .{ .fault = .denied, .code = "error[ZBX-E0568]", .exit = 1 },
        .{ .fault = .missing_repo, .code = "error[ZBX-E0568]", .exit = 1 },
        .{ .fault = .denied_at_manifest, .code = "error[ZBX-E0568]", .exit = 1 },
        .{ .fault = .missing_at_manifest, .code = "error[ZBX-E0569]", .exit = 1 },
        .{ .fault = .bad_token, .code = "error[ZBX-E0567]", .exit = 3 },
    };
    const world = try World.create();
    defer world.destroy();
    for (cases, 0..) |case, index| {
        world.setup(10 + index, &wif_env);
        world.google.registry_fault = case.fault;
        try testing.expectEqual(case.exit, world.pull_of(reference));
        try testing.expect(world.stderr_has(case.code));
        if (case.fault != .bad_token) try testing.expect(world.stderr_has(repository));
        if (case.fault != .bad_token and case.fault != .missing_at_manifest) {
            try testing.expect(world.stderr_has("artifactregistry.repositories.downloadArtifacts"));
        }
        try world.expect_where_sent();
        try world.expect_clean();
        try world.expect_wiped();
    }
}

test "the demo's fifth step: no secret in the JSON, the lock, the store or a bundle" {
    const stage_max = constants.bundle_stage_bytes_max;
    const plain = try std.heap.page_allocator.alloc(u8, stage_max * 2);
    defer std.heap.page_allocator.free(plain);
    const world = try World.create();
    defer world.destroy();
    world.setup(20, &wif_env);
    world.prepare_run("web-1");
    const json_pull = [_][:0]const u8{ "zbx", "--output", "json", "-v", "pull", reference };
    try testing.expectEqual(@as(u8, 0), world.run(&json_pull));
    try world.expect_clean();
    const run_web = [_][:0]const u8{ "zbx", "run", "--name", "web-1", reference };
    try testing.expectEqual(@as(u8, 0), world.run(&run_web));
    try testing.expectEqual(@as(u8, 0), world.run(&.{ "zbx", "bundle", "web-1" }));
    const tar = try bundle_tar(world, plain);
    try testing.expect(std.mem.indexOf(u8, tar, "web-1") != null);
    var basic: [128]u8 = undefined;
    var metadata_basic: [128]u8 = undefined;
    for (world.secrets(&basic, &metadata_basic)) |secret| {
        try testing.expect(std.mem.indexOf(u8, tar, secret) == null);
    }
    try world.expect_clean();
    try world.expect_wiped();
}

fn bundle_tar(world: *const World, plain: []u8) ![]const u8 {
    const path = std.mem.trimEnd(u8, world.sim.stdout(), "\n");
    const stored = world.sim.world.read_written(path) orelse return error.NotWritten;
    var input: std.Io.Reader = .fixed(stored);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress: std.compress.flate.Decompress = .init(&input, .gzip, &window);
    var output = std.Io.Writer.fixed(plain);
    _ = try decompress.reader.streamRemaining(&output);
    return output.buffered();
}

test "on GCE, the metadata server's token is asked once, after the anonymous refusal" {
    // Goal: anonymous first; the realm's 403 brings one metadata call and one retry with Basic.
    const world = try World.create();
    defer world.destroy();
    world.setup(30, &sim_run.env_home);
    world.google.metadata = .ok;
    world.google.accepted_token = google_sim.metadata_token;
    try testing.expectEqual(@as(u8, 0), world.pull_of(reference));
    try testing.expectEqual(@as(u32, 1), world.google.metadata_calls);
    try testing.expectEqual(@as(u32, 2), world.google.realm_calls);
    try testing.expectEqual(@as(u32, 1), world.google.realm_ok);
    try testing.expectEqual(@as(u32, 0), world.google.sts_calls);
    try world.expect_where_sent();
    try world.expect_clean();
    try world.expect_wiped();
}

test "the metadata server's failures after a refusal are E0560 or E0572" {
    const Case = struct { mode: google_sim.MetadataMode, code: []const u8 };
    const cases = [_]Case{
        .{ .mode = .no_service_account, .code = "error[ZBX-E0560]" },
        .{ .mode = .ec2, .code = "error[ZBX-E0560]" },
        .{ .mode = .malformed, .code = "error[ZBX-E0572]" },
        .{ .mode = .unavailable, .code = "error[ZBX-E0572]" },
    };
    const world = try World.create();
    defer world.destroy();
    for (cases, 0..) |case, index| {
        world.setup(40 + index, &sim_run.env_home);
        world.google.metadata = case.mode;
        try testing.expect(world.pull_of(reference) != 0);
        try testing.expect(world.stderr_has(case.code));
        try testing.expect(!world.stderr_has(google_sim.message_marker));
        try world.expect_where_sent();
        try world.expect_wiped();
    }
}

test "each workload identity failure has its code, and nothing else is tried" {
    const Case = struct {
        sts: google_sim.StsMode = .ok,
        iam: google_sim.IamMode = .ok,
        code: []const u8,
    };
    const cases = [_]Case{
        .{ .sts = .invalid_grant, .code = "error[ZBX-E0565]" },
        .{ .sts = .invalid_target, .code = "error[ZBX-E0565]" },
        .{ .sts = .unavailable, .code = "error[ZBX-E0572]" },
        .{ .sts = .malformed, .code = "error[ZBX-E0572]" },
        .{ .iam = .denied, .code = "error[ZBX-E0566]" },
        .{ .iam = .malformed, .code = "error[ZBX-E0572]" },
    };
    const world = try World.create();
    defer world.destroy();
    for (cases, 0..) |case, index| {
        world.setup(50 + index, &wif_env);
        world.google.sts = case.sts;
        world.google.iam = case.iam;
        try testing.expect(world.pull_of(reference) != 0);
        try testing.expect(world.stderr_has(case.code));
        try testing.expect(!world.stderr_has(google_sim.message_marker));
        try testing.expectEqual(@as(u32, 0), world.google.realm_calls);
        try testing.expectEqual(@as(u32, 0), world.google.metadata_calls);
        try world.expect_where_sent();
        try world.expect_clean();
        try world.expect_wiped();
    }
}

fn setup_on(world: *World, gcr: bool, seed: u64, env: []const EnvironmentVariable) void {
    if (gcr) world.setup_at(seed, env, "gcr.io") else world.setup(seed, env);
}

test "a credentials file zbx cannot use does not stop a public pull, as in 0.5.2" {
    // Goal: an unreadable, key or authorized_user file asks no service up front. A public image
    // pulls anonymously; a private one is refused with the file's code after the realm's no, and
    // no source stands in for the file.
    const Case = struct { env: []const EnvironmentVariable, code: []const u8 };
    const cases = [_]Case{
        .{ .env = &missing_file_env, .code = "error[ZBX-E0561]" },
        .{ .env = &key_env, .code = "error[ZBX-E0562]" },
        .{ .env = &user_env, .code = "error[ZBX-E0563]" },
    };
    const world = try World.create();
    defer world.destroy();
    for (cases, 0..) |case, index| {
        for ([_][:0]const u8{ reference, gcr_reference }) |text| {
            const gcr = text.ptr == gcr_reference.ptr;
            const seed: u64 = 60 + index * 4 + @as(u64, @intFromBool(gcr)) * 2;
            setup_on(world, gcr, seed, case.env);
            world.google.public = true;
            world.google.metadata = .ok;
            try testing.expectEqual(@as(u8, 0), world.pull_of(text));
            try testing.expect(!world.stderr_has("error["));
            try testing.expectEqual(@as(u32, 1), world.google.realm_calls);
            try testing.expectEqual(@as(u32, 0), world.google.sts_calls);
            try testing.expectEqual(@as(u32, 0), world.google.metadata_calls);
            try world.expect_where_sent();
            try world.expect_wiped();

            setup_on(world, gcr, seed + 1, case.env);
            world.google.metadata = .ok;
            try testing.expect(world.pull_of(text) != 0);
            try testing.expect(world.stderr_has(case.code));
            try testing.expectEqual(@as(u32, 1), world.google.realm_calls);
            try testing.expectEqual(@as(u32, 0), world.google.sts_calls);
            try testing.expectEqual(@as(u32, 0), world.google.metadata_calls);
            try world.expect_where_sent();
            try world.expect_wiped();
        }
    }
}

test "a redirect to storage.googleapis.com gets no credential" {
    // Goal: the storage host fails any request with Authorization; the pull works, storage served
    // the layers, and nothing leaked.
    const world = try World.create();
    defer world.destroy();
    world.setup(70, &wif_env);
    world.google.blob_redirect = .storage;
    try testing.expectEqual(@as(u8, 0), world.pull_of(reference));
    try testing.expect(world.google.storage_served > 0);
    try world.expect_where_sent();
    try world.expect_clean();
}

test "a downloads path that redirects on to storage: the realm's Bearer stops at the registry" {
    // Goal: the chain blobs -> same-host downloads path -> storage.googleapis.com; the same-host
    // hop gets the realm's Bearer (the registry's own origin), storage gets nothing.
    const world = try World.create();
    defer world.destroy();
    world.setup(72, &wif_env);
    world.google.blob_redirect = .same_host_then_storage;
    try testing.expectEqual(@as(u8, 0), world.pull_of(reference));
    try testing.expect(world.google.downloads_bearer > 0);
    try testing.expect(world.google.storage_served > 0);
    try world.expect_where_sent();
    try world.expect_clean();
}

test "a realm on another host or in plain HTTP gets no credential, and no source is asked" {
    // Goal: the realm's Basic goes only to the registry's own host over HTTPS. Workload identity
    // (held from the start) and the metadata fallback (asked after a refusal) are each refused
    // as a bad realm, before the Basic value is sent anywhere or a token is fetched for it.
    const Case = struct { at: google_sim.RealmAt, fallback: bool, elsewhere_calls: u32 };
    const cases = [_]Case{
        .{ .at = .elsewhere, .fallback = false, .elsewhere_calls = 0 },
        .{ .at = .elsewhere, .fallback = true, .elsewhere_calls = 1 },
        .{ .at = .plain, .fallback = false, .elsewhere_calls = 0 },
        .{ .at = .plain, .fallback = true, .elsewhere_calls = 0 },
    };
    const world = try World.create();
    defer world.destroy();
    for (cases, 0..) |case, index| {
        world.setup(74 + index, if (case.fallback) &sim_run.env_home else &wif_env);
        world.google.realm_at = case.at;
        if (case.fallback) {
            world.google.metadata = .ok;
            world.google.accepted_token = google_sim.metadata_token;
        }
        try testing.expect(world.pull_of(reference) != 0);
        try testing.expect(world.stderr_has("error[ZBX-E0507]"));
        try testing.expectEqual(@as(u32, 0), world.google.metadata_calls);
        try testing.expectEqual(@as(u32, 0), world.google.realm_calls);
        try testing.expectEqual(case.elsewhere_calls, world.google.elsewhere_calls);
        var logged: u32 = 0;
        while (world.wire.logged(logged)) |entry| : (logged += 1) {
            try testing.expectEqual(@as(u32, 0), entry.basic_len);
        }
        try world.expect_where_sent();
        try world.expect_clean();
        try world.expect_wiped();
    }
}

/// A lazy start's room (about 160 MiB), static so it is in bss, as `main.zig` keeps it.
var lazy_workspace: lazy_start.Workspace = undefined;
var lazy_image: images_mod.Image = undefined;

fn ignore_warning(context: *anyopaque, diag: *const Diag) void {
    _ = context;
    assert(diag.code != null);
}

test "a lazy start keeps no Google token, and no fallback, once its resolve has ended" {
    // Goal: `zbx run --lazy` (S2's, dormant in a release build but callable here) wipes the
    // Google token `request_of` found and drops the fallback, whose storage that is, when the
    // resolve ends: with workload identity, and with the metadata server after a refusal.
    // Method: `lazy_start.start` as `zbx run --lazy` calls it; the fixture's image has two layers,
    // so the start ends `whole` right after the resolve.
    const world = try World.create();
    defer world.destroy();
    for ([_]bool{ false, true }, 0..) |fallback, index| {
        world.setup(80 + index, if (fallback) &sim_run.env_home else &wif_env);
        if (fallback) {
            world.google.metadata = .ok;
            world.google.accepted_token = google_sim.metadata_token;
        }
        const host = world.sim.interface();
        var store: Store = undefined;
        try testing.expect(store.locate(host));
        var diag: Diag = undefined;
        diag.reset();
        _ = try store_open.check(&store, .create, &diag);
        const pull_workspace = &storage_of().pull;
        const warn: Warn = .{ .context = world, .call = ignore_warning };
        const ws = &lazy_workspace;
        const image = &lazy_image;
        const outcome =
            try lazy_start.start(host, pull_workspace, ws, &store, reference, warn, image, &diag);
        try testing.expectEqual(lazy_start.Outcome.whole, outcome);
        try testing.expectEqual(@as(u32, 1), world.google.realm_ok);
        try testing.expectEqual(@intFromBool(fallback), world.google.metadata_calls);
        try testing.expect(lazy_workspace.client.realm_fallback == null);
        try expect_zero(&pull_workspace.google.token.bytes);
        lazy_start.wipe(pull_workspace, &lazy_workspace);
        try world.expect_where_sent();
        try world.expect_wiped();
    }
}

test "mirrors are for Docker Hub only: an Artifact Registry or gcr.io pull asks none" {
    const world = try World.create();
    defer world.destroy();
    inline for (.{ google_sim.registry_host, "gcr.io" }, 0..) |host, index| {
        world.setup_at(80 + index, &mirror_env, host);
        const text = host ++ "/" ++ repository ++ ":latest";
        try testing.expectEqual(@as(u8, 0), world.pull_of(text));
        var entry_index: u32 = 0;
        while (world.wire.logged(entry_index)) |entry| : (entry_index += 1) {
            try testing.expect(!std.mem.eql(u8, entry.host_text(), "mirror.example"));
        }
        try world.expect_where_sent();
    }
}

test "a Google host zbx sends no credentials to is E0570 when refused, and asks no source" {
    // Goal: k8s.gcr.io is Google's but not a host zbx authenticates to: with workload identity set
    // up, nothing is resolved, and the realm's refusal says the host is not supported.
    const world = try World.create();
    defer world.destroy();
    world.setup_at(90, &wif_env, "k8s.gcr.io");
    try testing.expectEqual(@as(u8, 1), world.pull_of("k8s.gcr.io/" ++ repository ++ ":latest"));
    try testing.expect(world.stderr_has("error[ZBX-E0570]"));
    try testing.expectEqual(@as(u32, 0), world.google.sts_calls);
    try testing.expectEqual(@as(u32, 0), world.google.metadata_calls);
    try world.expect_where_sent();
}

/// What a library caller owns.
const Library = struct {
    workspace: pull.Workspace,
    import_workspace: import.Workspace,
    facts: doctor.Facts,
    result: pull.Result,
    diag: Diag,
    token: credentials_mod.Token,

    fn pull_once(library: *Library, host: anytype, request: *const pull.Request) !void {
        const progress: pull.Progress = .{ .context = library, .call = ignore_event };
        try pull.pull(
            host,
            &library.facts,
            request,
            progress,
            &library.workspace,
            &library.import_workspace,
            &library.result,
            &library.diag,
        );
    }
};

fn ignore_event(context: *anyopaque, event: pull.Event) void {
    _ = context;
    _ = event;
}

test "the library: a caller's token pulls, an expired one is refused before it is sent" {
    // Goal: the library entry as Zigcube calls it: a token pulls; one past its expiry is E0567
    // with nothing sent, as is an empty one; no token and no fallback is E0560 after the
    // anonymous refusal.
    const library = try std.heap.page_allocator.create(Library);
    defer std.heap.page_allocator.destroy(library);
    const world = try World.create();
    defer world.destroy();
    world.setup(100, &sim_run.env_home);
    const host = world.sim.interface();
    library.token = .{};
    @memcpy(library.token.bytes[0..google_sim.access_token.len], google_sim.access_token);
    library.token.len = google_sim.access_token.len;
    library.token.expiration_s = host.time_now() + 3600;
    var request: pull.Request = .{
        .reference = reference,
        .platform = .{},
        .mirrors = "",
        .google = &library.token,
    };
    library.diag.reset();
    try library.pull_once(host, &request);
    try testing.expectEqual(@as(u32, 1), world.google.realm_ok);
    try world.expect_where_sent();
    library.token.expiration_s = host.time_now() - 1;
    const requests = world.wire.requests;
    library.diag.reset();
    try testing.expectError(error.Failed, library.pull_once(host, &request));
    try testing.expectEqual(@as(?codes.Code, .E0567), library.diag.code);
    try testing.expectEqual(requests, world.wire.requests);
    // An empty token is the caller's mistake: refused the same way, not a panic.
    const length = library.token.len;
    library.token.len = 0;
    library.diag.reset();
    try testing.expectError(error.Failed, library.pull_once(host, &request));
    try testing.expectEqual(@as(?codes.Code, .E0567), library.diag.code);
    try testing.expectEqual(requests, world.wire.requests);
    library.token.len = length;
    request.google = null;
    library.diag.reset();
    try testing.expectError(error.Failed, library.pull_once(host, &request));
    try testing.expectEqual(@as(?codes.Code, .E0560), library.diag.code);
    library.token.wipe();
    var basic: [128]u8 = undefined;
    const encoded = world.google.basic_text(&basic);
    const memory = std.mem.asBytes(library);
    try testing.expect(std.mem.indexOf(u8, memory, google_sim.access_token) == null);
    try testing.expect(std.mem.indexOf(u8, memory, encoded) == null);
}
