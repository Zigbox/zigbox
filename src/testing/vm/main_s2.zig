const std = @import("std");
pub fn main(init: std.process.Init) !u8 {
    _ = init;
    return 0;
}
test {
    _ = @import("fixture_s2.zig");
    _ = @import("http_s2.zig");
    _ = @import("index_s2.zig");
    _ = @import("registry_disk_s2.zig");
    _ = @import("tool_s2.zig");
}
