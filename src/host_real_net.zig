//! placeholder
const std = @import("std");
const host_real = @import("host_real.zig");
const net = @import("registry/net.zig");
pub fn interface(context: *host_real.HostReal) net.Net {
    const vtable: net.VTable = .{ .get = get, .last_errno = last_errno };
    return .{ .context = context, .vtable = &vtable };
}
fn get(context: *anyopaque, request: *const net.Request, head: *net.Head, sink: net.Sink) net.Error!void {
    _ = context;
    _ = request;
    _ = head;
    _ = sink;
    return error.Unsupported;
}
fn last_errno(context: *anyopaque) u16 {
    _ = context;
    return 0;
}
