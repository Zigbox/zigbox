//! The upload test registry (`src/testing/vm/push_fixture.zig`) behind the simulator's network:
//! the fixture answers, `net_sim.zig` is the wire. Tests of the push code build one of these and
//! hand its `responder` to a `SimNet`.

const std = @import("std");
const assert = std.debug.assert;
const fixture_mod = @import("../testing/vm/push_fixture.zig");
const net = @import("net.zig");
const net_sim = @import("net_sim.zig");

pub const PushFixture = fixture_mod.PushFixture;
pub const Fault = fixture_mod.Fault;

/// The registry's own host in the simulator, and the other host a Location may point at.
pub const registry_host = "registry.test";
pub const other_host = "other.test";

pub const PushRegistry = struct {
    fixture: PushFixture,
    /// Where the simulator drains an upload body to.
    drained: [fixture_mod.blob_bytes_max]u8,

    /// Starts the registry and gives `sim` the room to drain uploads into.
    pub fn init(registry: *PushRegistry, sim: *net_sim.SimNet) void {
        registry.fixture.init("https://" ++ registry_host, "https://" ++ other_host);
        sim.received = &registry.drained;
        assert(sim.received.len == fixture_mod.blob_bytes_max);
    }

    pub fn responder(registry: *PushRegistry) net_sim.Responder {
        return .{ .context = registry, .answer = answer };
    }

    /// The destination text of a fault's repository: `registry.test/push/<fault>:v1`.
    pub fn destination(comptime fault: Fault) [:0]const u8 {
        return registry_host ++ "/push/" ++ @tagName(fault) ++ ":v1";
    }
};

fn method_of(method: net.Method) fixture_mod.Method {
    return switch (method) {
        .get => .get,
        .head => .head,
        .post => .post,
        .patch => .patch,
        .put => .put,
    };
}

fn answer(
    context: *anyopaque,
    request: *const net.Request,
    received: []const u8,
    served: *net_sim.Served,
) void {
    const registry: *PushRegistry = @ptrCast(@alignCast(context));
    var out: fixture_mod.Answer = .{};
    registry.fixture.answer(.{
        .method = method_of(request.method),
        .target = request.target,
        .content_range = request.content_range,
        .body = received,
    }, &out);
    served.* = .{
        .status = out.status,
        .content_length = out.content_length,
        .www_authenticate = out.www_authenticate,
        .retry_after = out.retry_after,
        .content_type = out.content_type,
        .content_digest = out.content_digest,
        .location = out.location,
        .content_range = out.content_range,
        .range = out.range,
        .body = out.body,
        .deliver = out.deliver,
    };
}
