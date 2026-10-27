//! The test registry (`src/testing/vm/registry_fixture.zig`) behind the simulator's network:
//! the fixture answers, `net_sim.zig` is the wire. Tests of the pull code build one of these, hand
//! its `responder` to a `SimNet`, and need no internet.

const std = @import("std");
const assert = std.debug.assert;
const fixture_mod = @import("../testing/vm/registry_fixture.zig");
const net = @import("net.zig");
const net_sim = @import("net_sim.zig");

pub const Fixture = fixture_mod.Fixture;
pub const Scenario = fixture_mod.Scenario;
pub const token_text = fixture_mod.token_text;

/// The registry's own host in the simulator, and the other host a redirect may point at.
pub const registry_host = "registry.test";
pub const other_host = "other.test";

pub const TestRegistry = struct {
    fixture: Fixture,

    pub fn init(registry: *TestRegistry) void {
        registry.fixture.init("https://" ++ registry_host, "https://" ++ other_host);
        assert(registry.fixture.oci.index.len > 0);
    }

    pub fn responder(registry: *TestRegistry) net_sim.Responder {
        return .{ .context = registry, .answer = answer };
    }

    /// The reference text of a scenario's repository: `registry.test/fixture/<scenario>:3.20`.
    pub fn reference(comptime scenario: Scenario) [:0]const u8 {
        return registry_host ++ "/fixture/" ++ @tagName(scenario) ++ ":3.20";
    }
};

fn answer(context: *anyopaque, request: *const net.Request, served: *net_sim.Served) void {
    const registry: *TestRegistry = @ptrCast(@alignCast(context));
    var out: fixture_mod.Answer = .{};
    registry.fixture.answer(.{
        .host = request.host,
        .target = request.target,
        .bearer = request.bearer,
    }, &out);
    served.* = .{
        .status = out.status,
        .content_length = out.content_length,
        .www_authenticate = out.www_authenticate,
        .retry_after = out.retry_after,
        .content_type = out.content_type,
        .content_digest = out.content_digest,
        .location = out.location,
        .body = out.body,
        .deliver = out.deliver,
    };
}
