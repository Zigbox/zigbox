//! The link-local metadata request both clouds make: AWS's instance metadata service and Google's
//! metadata server answer on the same address, `169.254.169.254`, over plain HTTP. It is asked by
//! address, never by a name (`metadata.google.internal`), so DNS cannot send it elsewhere, and
//! never through a proxy whatever `HTTPS_PROXY` or `NO_PROXY` say: a proxy cannot reach it and
//! must not see a credential. Its timeouts are short, so a machine that is not in that cloud
//! finds out fast; each provider passes its own.
//!
//! This is the only plain-HTTP request that carries a credential (in its answer). Nothing else
//! may use it: `request` fixes the scheme, the address and the port.

const std = @import("std");
const assert = std.debug.assert;
const host_mod = @import("../host.zig");
const net = @import("../registry/net.zig");

/// The link-local address of the metadata service on AWS and on Google Cloud.
pub const address = "169.254.169.254";

/// A GET of `target` on the metadata address, its answer bounded by `response`, marked secret
/// (the answer is a credential), never through a proxy. The caller sets a method, a body or
/// extra headers on the result when the call needs them.
pub fn request(
    target: []const u8,
    response: []u8,
    idle_timeout_ms: u32,
    total_timeout_ms: u32,
) net.Request {
    assert(target.len > 0);
    assert(target[0] == '/');
    assert(idle_timeout_ms < total_timeout_ms);
    return .{
        .scheme = .http,
        .host = address,
        .port = 80,
        .target = target,
        .accept = "",
        .bearer = "",
        .body_bytes_max = response.len,
        .idle_timeout_ms = idle_timeout_ms,
        .total_timeout_ms = total_timeout_ms,
        .proxy = .never,
        .secret = true,
    };
}

/// One call to the metadata address. The status, or null if the call failed (nothing answered,
/// or not in time). `head` holds the answer's headers for a caller that checks one.
pub fn call(
    host: host_mod.Host,
    req: *const net.Request,
    head: *net.Head,
    sink: *net.BufferSink,
) ?u16 {
    assert(req.proxy == .never);
    assert(req.scheme == .http);
    assert(std.mem.eql(u8, req.host, address));
    head.* = .{};
    sink.len = 0;
    host.network().call(req, head, sink.sink()) catch return null;
    return head.status;
}
