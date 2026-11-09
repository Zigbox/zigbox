//! Tests of `zigbox.aws_credentials_resolve`, the library call, from a caller other than the
//! command line: a long-running agent that holds a different environment per workload, none in
//! its own process, its own clock and its own memory, against the simulated host and AWS. The
//! resolver's own tests are in `aws/credentials_tests.zig`.

const std = @import("std");
const testing = std.testing;
const zigbox = @import("zigbox.zig");
const aws_sim = @import("aws/aws_sim.zig");
const host_sim = @import("host_sim.zig");
const net_sim = @import("registry/net_sim.zig");

const token_path = "/run/workload/token";

const Caller = struct {
    host: host_sim.HostSim,
    wire: net_sim.SimNet,
    aws: aws_sim.AwsSim,
    workspace: zigbox.AwsWorkspace,
    credentials: zigbox.AwsCredentials,
    trace: zigbox.AwsTrace,
    received: [1024]u8,

    fn resolve(
        caller: *Caller,
        pairs: []const zigbox.AwsEnv.Pair,
        region: []const u8,
        now: u64,
    ) !void {
        try zigbox.aws_credentials_resolve(
            caller.host.interface(),
            .{ .pairs = pairs },
            region,
            now,
            &caller.workspace,
            &caller.credentials,
            &caller.trace,
        );
    }
};

test "a second caller resolves from its own environment, region and clock" {
    // Goal: the library call needs no process environment and no pull; two callers with their own
    // memory and views get their own answers. Method: the host's process holds other AWS
    // variables than either caller passes; one caller passes static keys, the other a web
    // identity, in different regions and at different times.
    const files = [_]host_sim.File{.{ .path = token_path, .content = aws_sim.web_token }};
    const process_env = [_]host_sim.EnvironmentVariable{
        .{ .name = "AWS_ACCESS_KEY_ID", .value = "AKIAPROCESSPROCESS1" },
        .{ .name = "AWS_SECRET_ACCESS_KEY", .value = "processsecretprocesssecret" },
    };
    var callers: [2]*Caller = undefined;
    for (&callers, 1..) |*slot, seed| {
        const caller = try std.heap.page_allocator.create(Caller);
        caller.host.init(seed, &files);
        caller.host.environment_variables = &process_env;
        caller.aws = .{};
        caller.aws.now_s = caller.host.world.now;
        caller.wire.init(seed, caller.aws.responder());
        caller.wire.received = &caller.received;
        caller.host.wire = &caller.wire;
        slot.* = caller;
    }
    defer for (callers) |caller| std.heap.page_allocator.destroy(caller);
    const keys = [_]zigbox.AwsEnv.Pair{
        .{ .name = "AWS_ACCESS_KEY_ID", .value = "AKIACALLERONEAAAA1" },
        .{ .name = "AWS_SECRET_ACCESS_KEY", .value = aws_sim.issued_secret },
    };
    try callers[0].resolve(&keys, "eu-west-1", callers[0].host.world.now);
    const first_key = callers[0].credentials.key();
    try testing.expectEqualStrings("AKIACALLERONEAAAA1", first_key.access_key_id);
    try testing.expectEqual(@as(u32, 0), callers[0].wire.requests);
    const web = [_]zigbox.AwsEnv.Pair{
        .{ .name = "AWS_ROLE_ARN", .value = "arn:aws:iam::123456789012:role/other" },
        .{ .name = "AWS_WEB_IDENTITY_TOKEN_FILE", .value = token_path },
    };
    callers[1].aws.region = "ap-southeast-2";
    try callers[1].resolve(&web, "ap-southeast-2", callers[1].host.world.now);
    const web_identity = zigbox.aws_credentials.Source.web_identity;
    try testing.expectEqual(web_identity, callers[1].credentials.source);
    const logged = callers[1].wire.logged(0).?;
    try testing.expectEqualStrings("sts.ap-southeast-2.amazonaws.com", logged.host_text());
    // The first caller's keys are untouched by the second's resolve.
    const again = callers[0].credentials.key();
    try testing.expectEqualStrings("AKIACALLERONEAAAA1", again.access_key_id);
    // The clock is the caller's: a clock far in the future finds the answer out of date.
    const far = callers[1].host.world.now + 10 * 3600;
    try testing.expectError(error.NoCredentials, callers[1].resolve(&web, "ap-southeast-2", far));
    try testing.expectEqual(zigbox.aws_credentials.State.expired, callers[1].trace.web_identity);
}
