//! Tests of a push to Amazon ECR (M8 slice 13) against recorded answers: the simulated AWS
//! (`aws_sim.zig`: the ECR API that issues the token) in front of the upload test registry, which
//! stands in the ECR host and takes only the Basic token AWS issued. There is no AWS account in
//! CI. What is pinned: the token is sent to the registry's origin and nowhere else (a Location on
//! another origin gets none), every refusal ECR can give is its own coded diagnostic, a repository
//! that does not exist is not created, and no secret is left in any output or buffer.

const std = @import("std");
const assert = std.debug.assert;
const aws_sim = @import("../aws/aws_sim.zig");
const codes = @import("../diag/codes.zig");
const credentials_mod = @import("../aws/credentials.zig");
const net = @import("../registry/net.zig");
const net_sim = @import("../registry/net_sim.zig");
const push_ecr = @import("ecr.zig");
const push_registry = @import("../registry/push_registry.zig");
const render = @import("../diag/render.zig");
const tests = @import("upload_tests.zig");
const upload = @import("upload.zig");
const constants = @import("../constants.zig");

const testing = std.testing;
const Rig = tests.Rig;

const ecr_host = "123456789012.dkr.ecr.us-east-1.amazonaws.com";

/// What a test owns besides the rig: the AWS model, the ECR token buffers, and the faults the ECR
/// registry can be given.
const World = struct {
    rig: *Rig,
    aws: aws_sim.AwsSim,
    token: push_ecr.Workspace,
    /// The registry answers `403 DENIED` to a request that opens an upload.
    deny_uploads: bool,

    fn create(seed: u64) !*World {
        const world = try std.heap.page_allocator.create(World);
        world.rig = try Rig.create(seed);
        world.aws = .{};
        world.deny_uploads = false;
        world.token.reset();
        const rig = world.rig;
        std.crypto.secureZero(u8, &rig.ws.basic); // the rig's workspace starts undefined
        rig.wire.init(seed, .{ .context = world, .answer = answer });
        rig.registry.init(&rig.wire);
        rig.registry.host = ecr_host;
        rig.registry.fixture.init("https://" ++ ecr_host, "https://" ++ push_registry.other_host);
        rig.registry.require_as("AWS", .basic, aws_sim.ecr_password);
        rig.host.wire = &rig.wire;
        world.aws.now_s = rig.host.interface().time_now();
        return world;
    }

    fn destroy(world: *World) void {
        world.rig.destroy();
        std.heap.page_allocator.destroy(world);
    }

    /// Static keys the model accepts, as the command line's resolver would give them.
    fn keys() credentials_mod.Credentials {
        var credentials: credentials_mod.Credentials = std.mem.zeroes(credentials_mod.Credentials);
        const id = aws_sim.issued_key_id;
        const secret = aws_sim.issued_secret;
        const session = aws_sim.issued_token;
        @memcpy(credentials.access_key_id[0..id.len], id);
        credentials.access_key_id_len = id.len;
        @memcpy(credentials.secret_access_key[0..secret.len], secret);
        credentials.secret_access_key_len = secret.len;
        @memcpy(credentials.session_token[0..session.len], session);
        credentials.session_token_len = session.len;
        credentials.source = .environment;
        return credentials;
    }

    fn authorize(world: *World, aws: ?*const credentials_mod.Credentials) !void {
        world.rig.diag.reset();
        try push_ecr.authorize(
            world.rig.host.interface(),
            aws,
            ecr_host,
            "push/ok",
            &world.token,
            &world.rig.diag,
        );
    }

    /// Pushes `repository` to the ECR host with the token `authorize` gave.
    fn push(world: *World, repository: []const u8) upload.Error!void {
        const rig = world.rig;
        rig.diag.reset();
        const destination: upload.Destination = .{
            .origin = .{ .scheme = .https, .host = ecr_host, .port = 443 },
            .repository = repository,
            .tag = "v1",
        };
        return upload.push(
            &rig.store,
            &rig.ws,
            rig.wire.interface(),
            destination,
            &rig.made,
            .{ .chunk_bytes = 64, .ecr_token = world.token.text() },
            &rig.report,
            &rig.diag,
        );
    }

    fn rendered(world: *const World, buffer: []u8) []const u8 {
        return render.render(&world.rig.diag, .verbose, false, buffer);
    }

    /// The secrets of the run: the ECR password and its Basic form, the keys and the session.
    fn secrets() [5][]const u8 {
        return .{
            aws_sim.ecr_password,
            "QVdTOmVjci1wYXNzd29yZC0wMTIzNDU2Nzg5",
            aws_sim.issued_secret,
            aws_sim.issued_token,
            aws_sim.message_marker,
        };
    }

    /// Nothing secret is in the diagnostic, the upload's workspace, the store or the rig's disk,
    /// and the upload's own copy of the token is zero.
    fn expect_clean(world: *const World) !void {
        var buffer: [constants.output_bytes_max]u8 = undefined;
        const text = if (world.rig.diag.code != null) world.rendered(&buffer) else "";
        for (secrets()) |secret| {
            try testing.expect(std.mem.indexOf(u8, text, secret) == null);
            const held = [_][]const u8{
                std.mem.asBytes(&world.rig.diag),
                std.mem.asBytes(&world.rig.ws),
                std.mem.asBytes(&world.rig.files),
            };
            for (held) |bytes| try testing.expect(std.mem.indexOf(u8, bytes, secret) == null);
        }
        for (world.rig.ws.basic) |byte| try testing.expectEqual(@as(u8, 0), byte);
    }

    /// No request to a host but the registry's (and the AWS ones, signed) carried a credential.
    fn expect_credential_stayed(world: *const World) !void {
        try testing.expectEqual(@as(u32, 0), world.rig.registry.leaked);
        var index: u32 = 0;
        while (world.rig.wire.logged(index)) |entry| : (index += 1) {
            const host = entry.host_text();
            if (entry.basic_len == 0 and entry.bearer_len == 0) continue;
            try testing.expectEqualStrings(ecr_host, host);
        }
    }

    fn expect_code(world: *const World, code: codes.Code) !void {
        try testing.expect(world.rig.diag.code != null);
        try testing.expectEqual(code, world.rig.diag.code.?);
    }
};

fn answer(
    context: *anyopaque,
    request: *const net.Request,
    received: []const u8,
    served: *net_sim.Served,
) void {
    const world: *World = @ptrCast(@alignCast(context));
    const is_aws = std.mem.startsWith(u8, request.host, "api.ecr.") or
        std.mem.startsWith(u8, request.host, "sts.") or
        std.mem.eql(u8, request.host, "169.254.169.254");
    if (is_aws) {
        const inner = world.aws.responder();
        return inner.answer(inner.context, request, received, served);
    }
    if (world.deny_uploads and request.method == .post and request.basic.len > 0) {
        served.* = .{
            .status = 403,
            .body = "{\"errors\":[{\"code\":\"DENIED\",\"message\":\"not allowed\"}]}",
        };
        return;
    }
    const inner = world.rig.registry.responder();
    inner.answer(inner.context, request, received, served);
}

test "a push to ECR sends the token to the registry's origin and puts the image" {
    // Goal: the demo's happy path. Method: static keys buy the token from the model's ECR API;
    // the registry takes only that Basic; both blobs and the manifest go up, and no credential
    // went to any host but the registry's.
    const world = try World.create(1);
    defer world.destroy();
    var keys = World.keys();
    defer keys.wipe();
    try world.authorize(&keys);
    try testing.expect(world.token.text().len > 0);
    try world.push("push/ok");
    try testing.expectEqual(upload.Outcome.uploaded, world.rig.report.layer.outcome);
    try testing.expect(world.rig.holds("push/ok", world.rig.made.layer));
    try testing.expect(world.rig.report.manifest.eql(world.rig.made.manifest));
    try testing.expectEqual(@as(u32, 1), world.aws.ecr_ok);
    try world.expect_credential_stayed();
    try world.expect_clean();
    world.token.wipe();
}

test "a Location on another origin is followed with no token" {
    // Goal: the origin-only rule, the S3 case. Method: the registry names another origin for
    // every upload session; the push completes and that origin never saw the token.
    const world = try World.create(2);
    defer world.destroy();
    var keys = World.keys();
    defer keys.wipe();
    try world.authorize(&keys);
    try world.push("push/farlocation");
    try testing.expect(world.rig.holds("push/farlocation", world.rig.made.layer));
    var elsewhere = false;
    var index: u32 = 0;
    while (world.rig.wire.logged(index)) |entry| : (index += 1) {
        if (std.mem.eql(u8, entry.host_text(), push_registry.other_host)) elsewhere = true;
    }
    try testing.expect(elsewhere);
    try world.expect_credential_stayed();
    try world.expect_clean();
    world.token.wipe();
}

test "a push to ECR given no AWS credentials is E0552 with its own cause" {
    // Goal: the caller that gave nothing is told so, in words about AWS, and nothing is sent.
    const world = try World.create(3);
    defer world.destroy();
    try testing.expectError(error.Failed, world.authorize(null));
    try world.expect_code(.E0552);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const text = world.rendered(&buffer);
    try testing.expect(std.mem.indexOf(u8, text, "Amazon ECR") != null);
    try testing.expect(std.mem.indexOf(u8, text, "AWS credentials") != null);
    try testing.expectEqual(@as(u32, 0), world.aws.ecr_calls);
    try testing.expectEqual(@as(usize, 0), world.token.text().len);
}

test "a token the registry does not accept is E0553 and is not tried twice" {
    // Goal: an expired or foreign token. Method: the registry wants another password; the
    // refusal names the token, not a user and password, and the token is sent once.
    const world = try World.create(4);
    defer world.destroy();
    var keys = World.keys();
    defer keys.wipe();
    try world.authorize(&keys);
    world.rig.registry.require_as("AWS", .basic, "another-password-entirely");
    try testing.expectError(error.Failed, world.push("push/ok"));
    try world.expect_code(.E0553);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const text = world.rendered(&buffer);
    try testing.expect(std.mem.indexOf(u8, text, "authorization token AWS issued") != null);
    try world.expect_credential_stayed();
    try world.expect_clean();
    world.token.wipe();
}

test "an identity that may not push is E0553 naming the IAM actions" {
    // Goal: ECR's 403 DENIED on an upload. The fix names the five actions the push needs.
    const world = try World.create(5);
    defer world.destroy();
    var keys = World.keys();
    defer keys.wipe();
    try world.authorize(&keys);
    world.deny_uploads = true;
    try testing.expectError(error.Failed, world.push("push/ok"));
    try world.expect_code(.E0553);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const text = world.rendered(&buffer);
    try testing.expect(std.mem.indexOf(u8, text, "ecr:InitiateLayerUpload") != null);
    try testing.expect(std.mem.indexOf(u8, text, "ecr:PutImage") != null);
    try world.expect_clean();
    world.token.wipe();
}

test "a repository ECR does not hold is E0556, and nothing creates it" {
    // Goal: ECR does not create a repository on push. Method: push to a repository the registry
    // does not know (404 NAME_UNKNOWN); the diagnostic says so and gives the command that makes it.
    const world = try World.create(6);
    defer world.destroy();
    var keys = World.keys();
    defer keys.wipe();
    try world.authorize(&keys);
    try testing.expectError(error.Failed, world.push("nosuch/repo"));
    try world.expect_code(.E0556);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const text = world.rendered(&buffer);
    try testing.expect(std.mem.indexOf(u8, text, "does not create one") != null);
    try testing.expect(std.mem.indexOf(u8, text, "aws ecr create-repository") != null);
    try testing.expect(std.mem.indexOf(u8, text, "--region us-east-1") != null);
    try testing.expect(!world.rig.holds("nosuch/repo", world.rig.made.layer));
    try world.expect_clean();
    world.token.wipe();
}

test "AWS refusing the token call is its own diagnostic, with no secret in it" {
    // Goal: the identity may not get a token (E0530); the message AWS sent is not printed.
    const world = try World.create(7);
    defer world.destroy();
    world.aws.api_denied = true;
    var keys = World.keys();
    defer keys.wipe();
    try testing.expectError(error.Failed, world.authorize(&keys));
    try world.expect_code(.E0530);
    try world.expect_clean();
    try testing.expectEqual(@as(usize, 0), world.token.text().len);
    for (world.token.token) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "an ECR host zbx does not sign for is refused before any request" {
    // Goal: a FIPS host is E0534, and a host that is not ECR asks AWS for nothing.
    const world = try World.create(8);
    defer world.destroy();
    var keys = World.keys();
    defer keys.wipe();
    world.rig.diag.reset();
    const fips = "123456789012.dkr.ecr-fips.us-east-1.amazonaws.com";
    try testing.expectError(error.Failed, push_ecr.authorize(
        world.rig.host.interface(),
        &keys,
        fips,
        "push/ok",
        &world.token,
        &world.rig.diag,
    ));
    try world.expect_code(.E0534);
    world.rig.diag.reset();
    try push_ecr.authorize(
        world.rig.host.interface(),
        &keys,
        "registry.test",
        "push/ok",
        &world.token,
        &world.rig.diag,
    );
    try testing.expectEqual(@as(usize, 0), world.token.text().len);
    try testing.expectEqual(@as(u32, 0), world.aws.ecr_calls);
}

test "a token handed to a push for a host that is not ECR is never sent" {
    // Goal: an AWS token goes to ECR hosts only, whatever the caller passed.
    const rig = try Rig.create(9);
    defer rig.destroy();
    try rig.push("push/ok", .{ .ecr_token = "QVdTOmVjci1wYXNzd29yZC0wMTIzNDU2Nzg5" });
    var index: u32 = 0;
    while (rig.wire.logged(index)) |entry| : (index += 1) {
        try testing.expectEqual(@as(u32, 0), entry.basic_len);
    }
}
