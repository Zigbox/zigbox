//! Tests of a pull from Amazon ECR through the command line (M6c, slice 2), against the simulated
//! host and the simulated ECR (`ecr_sim.zig`): the five steps of the demo (no credentials, a web
//! identity, static keys, a repository the role may not read, and no secret anywhere), the
//! redirect to S3 that must never carry the token, the mirrors that ECR never reaches, and every
//! coded refusal the ECR path can give.

const std = @import("std");
const testing = std.testing;
const aws_sim = @import("aws_sim.zig");
const cli = @import("../cli.zig");
const client_mod = @import("../registry/client.zig");
const ecr_sim = @import("ecr_sim.zig");
const fs_sim = @import("../store/fs_sim.zig");
const host_sim = @import("../host_sim.zig");
const net_sim = @import("../registry/net_sim.zig");
const sim_run = @import("../runtime/sim_run.zig");

const EnvironmentVariable = host_sim.EnvironmentVariable;

const token_path = "/var/run/secrets/eks/token";
const role_arn = "arn:aws:iam::123456789012:role/zbx-pull";
const project = "/home/alice/project";
const lock_path = project ++ "/zbx.lock";

const disk_files = sim_run.files ++ [_]host_sim.File{
    .{ .path = token_path, .content = aws_sim.web_token ++ "\n" },
};

const keys_env = sim_run.env_home ++ [_]EnvironmentVariable{
    .{ .name = "AWS_ACCESS_KEY_ID", .value = aws_sim.issued_key_id },
    .{ .name = "AWS_SECRET_ACCESS_KEY", .value = aws_sim.issued_secret },
    .{ .name = "AWS_SESSION_TOKEN", .value = aws_sim.issued_token },
};
const web_env = sim_run.env_home ++ [_]EnvironmentVariable{
    .{ .name = "AWS_ROLE_ARN", .value = role_arn },
    .{ .name = "AWS_WEB_IDENTITY_TOKEN_FILE", .value = token_path },
};
const missing_file_env = sim_run.env_home ++ [_]EnvironmentVariable{
    .{ .name = "AWS_ROLE_ARN", .value = role_arn },
    .{ .name = "AWS_WEB_IDENTITY_TOKEN_FILE", .value = "/nowhere/token" },
};
const mirror_env = keys_env ++ [_]EnvironmentVariable{
    .{ .name = "ZBX_REGISTRY_MIRRORS", .value = "mirror.example" },
};

/// The store's disk is large: it is made once, on the heap, and made again by every `setup`.
var store_disk: ?*fs_sim.SimFs = null;

const World = struct {
    sim: host_sim.HostSim,
    ecr: ecr_sim.EcrSim,
    wire: net_sim.SimNet,
    /// What the wire keeps of an upload: the ECR API's `{}` and STS's form.
    received: [1024]u8,

    fn setup(world: *World, seed: u64, env: []const EnvironmentVariable) void {
        sim_run.start(&world.sim, seed, &disk_files);
        world.ecr.init();
        world.ecr.aws.now_s = world.sim.world.now;
        world.wire.init(seed, world.ecr.responder());
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
        return cli.run_from_iterator(world.sim.interface(), &iterator);
    }

    fn pull(world: *World, reference: [:0]const u8) u8 {
        return world.run(&.{ "zbx", "-v", "pull", reference });
    }

    fn stderr_has(world: *const World, text: []const u8) bool {
        return std.mem.indexOf(u8, world.sim.stderr(), text) != null;
    }

    /// Nothing secret is in an output or on the store's disk: not a key, a token, the ECR
    /// password or what AWS's messages said.
    fn expect_clean(world: *const World) !void {
        var basic: [64]u8 = undefined;
        const encoded = ecr_sim.EcrSim.basic_text(&basic);
        const secrets = [_][]const u8{
            aws_sim.ecr_password,  aws_sim.issued_secret,  aws_sim.issued_token,
            aws_sim.issued_key_id, aws_sim.message_marker, aws_sim.web_token,
            aws_sim.imds_token,    encoded,
        };
        for (secrets) |secret| {
            try testing.expect(std.mem.indexOf(u8, world.sim.stdout(), secret) == null);
            try testing.expect(std.mem.indexOf(u8, world.sim.stderr(), secret) == null);
            var index: u32 = 0;
            while (store_disk.?.alive_path(index)) |path| : (index += 1) {
                const content = store_disk.?.content_of(path) orelse continue;
                try testing.expect(std.mem.indexOf(u8, content, secret) == null);
            }
        }
    }

    /// No request to S3 or to anything but ECR and AWS carried a credential, and every one that
    /// carried one was marked secret for the network to wipe.
    fn expect_basic_to_origin_only(world: *const World) !void {
        try testing.expectEqual(@as(u32, 0), world.ecr.leaked());
        var index: u32 = 0;
        while (world.wire.logged(index)) |entry| : (index += 1) {
            if (!entry.credential_sent()) continue;
            try testing.expect(entry.secret);
            const host = entry.host_text();
            const allowed = std.mem.eql(u8, host, ecr_sim.ecr_host) or
                std.mem.startsWith(u8, host, "api.ecr.");
            try testing.expect(allowed);
        }
    }
};

test "static keys pull an ECR image, and the token never crosses the redirect to S3" {
    // Goal: the demo's third step. Method: keys in the environment; the cdn repository redirects
    // its blobs to S3, which refuses any credential; the pull works, S3 served the layers, and the
    // lock, the store, stdout and stderr hold no secret.
    var world: World = undefined;
    world.setup(1, &keys_env);
    try testing.expectEqual(@as(u8, 0), world.pull(ecr_sim.reference));
    try testing.expect(world.ecr.s3_served > 0);
    try testing.expectEqual(@as(u32, 0), world.ecr.s3_leaked);
    try testing.expectEqual(@as(u32, 1), world.ecr.aws.ecr_ok);
    try testing.expectEqual(@as(u32, 0), world.ecr.aws.sts_calls);
    try testing.expect(world.ecr.registry_authenticated > 0);
    try testing.expect(store_disk.?.content_of(lock_path) != null);
    try world.expect_basic_to_origin_only();
    try world.expect_clean();
}

test "a web identity pulls the same image, with one STS call and the answer's keys" {
    // Goal: the demo's second step. Method: role ARN and token file set; STS is asked once, the
    // ECR API once, the pull works.
    var world: World = undefined;
    world.setup(2, &web_env);
    try testing.expectEqual(@as(u8, 0), world.pull(ecr_sim.reference));
    try testing.expectEqual(@as(u32, 1), world.ecr.aws.sts_calls);
    try testing.expectEqual(@as(u32, 1), world.ecr.aws.ecr_ok);
    try testing.expectEqual(@as(u32, 0), world.ecr.aws.imds_calls);
    try world.expect_basic_to_origin_only();
    try world.expect_clean();
}

test "an unreadable web identity token file is E0533, and nothing else is tried" {
    // Goal: a web identity that was set up is the answer: no fall through to the instance role.
    var world: World = undefined;
    world.setup(3, &missing_file_env);
    try testing.expectEqual(@as(u8, 2), world.pull(ecr_sim.reference));
    try testing.expect(world.stderr_has("error[ZBX-E0533]"));
    try testing.expectEqual(@as(u32, 0), world.ecr.aws.imds_calls);
    try testing.expectEqual(@as(u32, 0), world.ecr.registry_calls);
    try world.expect_clean();
}

test "no credentials is E0527 with what each source did, and no registry call" {
    // Goal: the demo's first step. Method: no AWS variable and an instance with no role; the
    // refusal names the three sources and the registry is never asked.
    var world: World = undefined;
    world.setup(4, &sim_run.env_home);
    world.ecr.aws.imds = .no_role;
    try testing.expectEqual(@as(u8, 2), world.pull(ecr_sim.reference));
    try testing.expect(world.stderr_has("error[ZBX-E0527]"));
    try testing.expect(world.stderr_has("no role attached"));
    try testing.expect(world.stderr_has("attach an IAM role"));
    try testing.expectEqual(@as(u32, 0), world.ecr.registry_calls);
    try world.expect_clean();
}

test "the metadata service's refusal is worded from the status, 403 or 404" {
    // Goal: a 403 on the token call says a proxy or version 1, and says 403; a 404 does not.
    var world: World = undefined;
    world.setup(5, &sim_run.env_home);
    world.ecr.aws.imds = .token_forbidden;
    try testing.expectEqual(@as(u8, 2), world.pull(ecr_sim.reference));
    try testing.expect(world.stderr_has("(403), a proxy or version 1 only"));
    world.setup(6, &sim_run.env_home);
    world.ecr.aws.imds = .v1_only;
    try testing.expectEqual(@as(u8, 2), world.pull(ecr_sim.reference));
    try testing.expect(world.stderr_has("version 1 only"));
    try testing.expect(!world.stderr_has("(403)"));
    try testing.expectEqual(@as(u32, 0), world.ecr.aws.imds_v1_served);
}

test "each AWS refusal has its own code and shows only AWS's code name" {
    // Goal: E0528 for keys AWS does not know, E0529 for a clock too far off, E0530 for an identity
    // that may not get a token; AWS's message (the marker) is in none of them.
    var world: World = undefined;
    world.setup(7, &keys_env);
    world.ecr.aws.accepted_key_id = "ASIAOTHEROTHEROTHER1";
    try testing.expectEqual(@as(u8, 2), world.pull(ecr_sim.reference));
    try testing.expect(world.stderr_has("error[ZBX-E0528]"));
    try testing.expect(world.stderr_has("UnrecognizedClientException"));
    try world.expect_clean();
    world.setup(8, &keys_env);
    world.ecr.aws.now_s += 4000;
    try testing.expectEqual(@as(u8, 2), world.pull(ecr_sim.reference));
    try testing.expect(world.stderr_has("error[ZBX-E0529]"));
    try world.expect_clean();
    world.setup(9, &keys_env);
    world.ecr.aws.api_denied = true;
    try testing.expectEqual(@as(u8, 1), world.pull(ecr_sim.reference));
    try testing.expect(world.stderr_has("error[ZBX-E0530]"));
    try testing.expect(world.stderr_has("ecr:GetAuthorizationToken"));
    try world.expect_clean();
}

test "a repository the role may not read, or that is missing, or a token ECR rejects" {
    // Goal: the demo's fourth step (zbx-denied) and its neighbours: E0531 for 403 DENIED, E0532
    // for 404 NAME_UNKNOWN, E0535 for a 401 on the Basic token. No secret in any of them, and the
    // token still went to the registry's origin only.
    const faults = [_]struct { fault: ecr_sim.Fault, code: []const u8, exit: u8 }{
        .{ .fault = .denied, .code = "error[ZBX-E0531]", .exit = 1 },
        .{ .fault = .missing_repo, .code = "error[ZBX-E0532]", .exit = 1 },
        .{ .fault = .bad_token, .code = "error[ZBX-E0535]", .exit = 3 },
    };
    var world: World = undefined;
    for (faults, 0..) |entry, index| {
        world.setup(10 + index, &keys_env);
        world.ecr.fault = entry.fault;
        try testing.expectEqual(entry.exit, world.pull(ecr_sim.reference));
        try testing.expect(world.stderr_has(entry.code));
        try world.expect_basic_to_origin_only();
        try world.expect_clean();
    }
}

test "mirrors are for Docker Hub only: an ECR pull asks none" {
    // Goal: the token must never reach a mirror. Method: a mirror is named; the pull works and no
    // request goes to it or to any host but ECR, S3 and AWS.
    var world: World = undefined;
    world.setup(20, &mirror_env);
    try testing.expectEqual(@as(u8, 0), world.pull(ecr_sim.reference));
    try testing.expectEqual(@as(u32, 0), world.ecr.stray);
    var index: u32 = 0;
    while (world.wire.logged(index)) |entry| : (index += 1) {
        try testing.expect(!std.mem.eql(u8, entry.host_text(), "mirror.example"));
    }
    try world.expect_basic_to_origin_only();
    try testing.expect(std.mem.indexOf(u8, store_disk.?.content_of(lock_path).?, "mirror") == null);
    try world.expect_clean();
}

test "an ECR host of a kind zbx does not sign for is E0534, with no network and no lookup" {
    // Goal: FIPS and other partitions are refused before anything is sent or read.
    var world: World = undefined;
    world.setup(21, &keys_env);
    const fips = "123456789012.dkr.ecr-fips.us-east-1.amazonaws.com/fixture/cdn:3.20";
    try testing.expectEqual(@as(u8, 1), world.pull(fips));
    try testing.expect(world.stderr_has("error[ZBX-E0534]"));
    try testing.expectEqual(@as(u32, 0), world.wire.requests);
}

test "a host that is not ECR reads no AWS setting and calls no AWS service" {
    // Goal: credentials are looked up only for an ECR reference.
    var world: World = undefined;
    world.setup(22, &keys_env);
    _ = world.pull("registry.example/fixture/open:3.20");
    try testing.expectEqual(@as(u32, 0), world.ecr.aws.ecr_calls);
    try testing.expectEqual(@as(u32, 0), world.ecr.aws.sts_calls);
    try testing.expectEqual(@as(u32, 0), world.ecr.aws.imds_calls);
    try world.expect_clean();
}

test "wiping a client workspace zeroes the token and the answer it held" {
    // Goal: the secret buffers of a pull are zero when it ends, on any path.
    const workspace = try std.heap.page_allocator.create(client_mod.Workspace);
    defer std.heap.page_allocator.destroy(workspace);
    @memset(&workspace.basic, 'x');
    @memset(&workspace.token_body, 'y');
    client_mod.Workspace.wipe(workspace);
    for (workspace.basic) |byte| try testing.expectEqual(@as(u8, 0), byte);
    for (workspace.token_body) |byte| try testing.expectEqual(@as(u8, 0), byte);
}
