//! Tests of `zigbox.google_credentials_resolve`, the library call, from a caller other than the
//! command line: an agent that holds a different environment per workload and none in its own
//! process, with its own clock and memory, against the simulated host and Google. The resolver's
//! own tests are in `google/credentials_tests.zig`.

const std = @import("std");
const testing = std.testing;
const zigbox = @import("zigbox.zig");
const google_sim = @import("google/google_sim.zig");
const parse_tests = @import("google/parse_tests.zig");
const host_sim = @import("host_sim.zig");
const net_sim = @import("registry/net_sim.zig");

const Caller = struct {
    host: host_sim.HostSim,
    wire: net_sim.SimNet,
    google: google_sim.GoogleSim,
    workspace: zigbox.GoogleWorkspace,
    token: zigbox.GoogleToken,
    trace: zigbox.GoogleTrace,
    received: [1024]u8,

    fn create(seed: u64, files: []const host_sim.File) !*Caller {
        const caller = try std.heap.page_allocator.create(Caller);
        caller.host.init(seed, files);
        caller.google.init();
        caller.google.now_s = caller.host.world.now;
        caller.wire.init(seed, caller.google.responder());
        caller.wire.received = &caller.received;
        caller.host.wire = &caller.wire;
        caller.token = .{};
        return caller;
    }

    fn resolve(
        caller: *Caller,
        pairs: []const zigbox.GoogleEnv.Pair,
        now: u64,
        sources: zigbox.GoogleSources,
    ) !void {
        try zigbox.google_credentials_resolve(
            caller.host.interface(),
            .{ .pairs = pairs },
            now,
            sources,
            &caller.workspace,
            &caller.token,
            &caller.trace,
        );
    }
};

test "a caller resolves from its own environment and clock, not the process's" {
    // Goal: the library call reads no process environment: the process names a file that does
    // not exist, the caller names one that does, and the caller's answer wins. The clock is the
    // caller's: a clock far ahead finds the same answer out of date.
    const files = [_]host_sim.File{
        .{ .path = "/workload/gcp.json", .content = parse_tests.file_account },
        .{ .path = "/run/zbx/oidc-token", .content = google_sim.subject_token },
    };
    const process_env = [_]host_sim.EnvironmentVariable{
        .{ .name = "GOOGLE_APPLICATION_CREDENTIALS", .value = "/nowhere.json" },
    };
    const caller = try Caller.create(3, &files);
    defer std.heap.page_allocator.destroy(caller);
    caller.host.environment_variables = &process_env;
    const pairs = [_]zigbox.GoogleEnv.Pair{
        .{ .name = "GOOGLE_APPLICATION_CREDENTIALS", .value = "/workload/gcp.json" },
    };
    const wif: zigbox.GoogleSources = .{ .workload_identity = true };
    try caller.resolve(&pairs, caller.host.world.now, wif);
    try testing.expectEqualStrings(google_sim.access_token, caller.token.text());
    // An empty view finds nothing, whatever the process holds.
    try testing.expectError(error.NoCredentials, caller.resolve(&.{}, caller.host.world.now, wif));
    try testing.expectEqual(@as(u32, 0), caller.token.len);
    // The model's clock stays put; the caller's moves on, past the token's life.
    const far = caller.host.world.now + 10 * 3600;
    try testing.expectError(error.NoCredentials, caller.resolve(&pairs, far, wif));
    const state = caller.trace.workload_identity;
    try testing.expectEqual(zigbox.google_credentials.State.expired, state);
}
