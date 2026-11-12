//! Tests of the CDI spec parser and resolver (M10 slice 2). The second caller of `Resolver`
//! (a caller that is not the CLI: what Zigcube's agent does) is "resolves without a host".

const std = @import("std");
const testing = std.testing;
const constants = @import("../constants.zig");
const cdi = @import("cdi.zig");

const fake_spec =
    \\{"cdiVersion":"0.6.0","kind":"vendor.example/gpu",
    \\ "devices":[
    \\  {"name":"0","containerEdits":{"deviceNodes":[{"path":"/dev/fake0"}]}},
    \\  {"name":"1","containerEdits":{"deviceNodes":[{"path":"/dev/fake1","type":"c"}]}}],
    \\ "containerEdits":{
    \\  "env":["FAKE_VISIBLE=all"],
    \\  "mounts":[{"hostPath":"/usr/lib/fake.so","containerPath":"/usr/lib/fake.so",
    \\             "options":["ro","nosuid","nodev","bind"]}],
    \\  "hooks":[{"hookName":"createContainer","path":"/usr/bin/nvidia-cdi-hook",
    \\            "args":["nvidia-cdi-hook","update-ldcache","--folder","/usr/lib"]}]}}
;

fn make() !*cdi.Parsed {
    return try testing.allocator.create(cdi.Parsed);
}

fn resolved() !*cdi.Resolved {
    return try testing.allocator.create(cdi.Resolved);
}

test "parse: a vendor spec is read whole" {
    const parsed = try make();
    defer testing.allocator.destroy(parsed);
    try testing.expectEqual(@as(?cdi.Problem, null), cdi.parse(parsed, fake_spec));
    try testing.expectEqualStrings("vendor.example/gpu", parsed.slice(parsed.kind));
    try testing.expectEqual(@as(u32, 2), parsed.devices_count);
    try testing.expectEqual(@as(u32, 1), parsed.common.mounts_count);
    try testing.expectEqual(@as(u32, 1), parsed.common.dirs_count);
    try testing.expectEqual(cdi.Unsupported.none, parsed.common.unsupported);
}

fn refused(input: []const u8) !cdi.Problem {
    const parsed = try make();
    defer testing.allocator.destroy(parsed);
    return cdi.parse(parsed, input) orelse error.TestUnexpectedResult;
}

test "parse: refusals are named" {
    try testing.expectEqual(cdi.Problem.not_json, try refused("not json"));
    try testing.expectEqual(cdi.Problem.not_json, try refused(""));
    try testing.expectEqual(cdi.Problem.wrong_type, try refused("[]"));
    try testing.expectEqual(cdi.Problem.version, try refused(
        \\{"cdiVersion":"1.0.0","kind":"a.b/c","devices":[{"name":"x"}]}
    ));
    try testing.expectEqual(cdi.Problem.kind, try refused(
        \\{"cdiVersion":"0.5.0","kind":"nokind","devices":[{"name":"x"}]}
    ));
    try testing.expectEqual(cdi.Problem.missing, try refused(
        \\{"cdiVersion":"0.5.0","kind":"a.b/c"}
    ));
    try testing.expectEqual(cdi.Problem.device_repeated, try refused(
        \\{"cdiVersion":"0.5.0","kind":"a.b/c","devices":[{"name":"x"},{"name":"x"}]}
    ));
    try testing.expectEqual(cdi.Problem.path, try refused(
        \\{"cdiVersion":"0.5.0","kind":"a.b/c","devices":[{"name":"x","containerEdits":
        \\{"deviceNodes":[{"path":"/etc/passwd"}]}}]}
    ));
    try testing.expectEqual(cdi.Problem.env, try refused(
        \\{"cdiVersion":"0.5.0","kind":"a.b/c","devices":[{"name":"x","containerEdits":
        \\{"env":["1BAD=x"]}}]}
    ));
}

test "parse: depth and trailing text are refused" {
    const open: [40]u8 = @splat('[');
    const close: [40]u8 = @splat(']');
    const parsed = try make();
    defer testing.allocator.destroy(parsed);
    const nested = "{\"cdiVersion\":\"0.5.0\",\"x\":" ++ open ++ close ++ "}";
    try testing.expect(cdi.parse(parsed, nested) != null);
    try testing.expect(cdi.parse(parsed, fake_spec ++ " x") != null);
}

test "parse: the size bound, at and one past" {
    const parsed = try make();
    defer testing.allocator.destroy(parsed);
    const big = try testing.allocator.alloc(u8, constants.cdi_spec_bytes_max + 1);
    defer testing.allocator.free(big);
    @memset(big, ' ');
    try testing.expectEqual(@as(?cdi.Problem, cdi.Problem.too_big), cdi.parse(parsed, big));
    const at = cdi.parse(parsed, big[0..constants.cdi_spec_bytes_max]);
    try testing.expect(at != null and at.? != cdi.Problem.too_big);
}

test "parse: unsupported edits are kept, not refused" {
    const parsed = try make();
    defer testing.allocator.destroy(parsed);
    const spec =
        \\{"cdiVersion":"0.5.0","kind":"a.b/c","devices":[
        \\ {"name":"hooked","containerEdits":{"hooks":[{"hookName":"prestart","path":"/bin/x"}]}},
        \\ {"name":"rdt","containerEdits":{"intelRdt":{"closID":"a"}}},
        \\ {"name":"gids","containerEdits":{"additionalGids":[5]}},
        \\ {"name":"odd","containerEdits":{"cgroupsPath":"x"}},
        \\ {"name":"plain"}]}
    ;
    try testing.expectEqual(@as(?cdi.Problem, null), cdi.parse(parsed, spec));
    const want = [_]cdi.Unsupported{ .hook, .intel_rdt, .additional_gids, .other, .none };
    for (want, 0..) |edit, at| try testing.expectEqual(edit, parsed.devices[at].edits.unsupported);
    try testing.expectEqualStrings("cgroupsPath", parsed.slice(parsed.devices[3].edits.unsupported_name));
}

test "names: kinds, device names, paths and variables" {
    try testing.expect(cdi.kind_valid("nvidia.com/gpu"));
    try testing.expect(!cdi.kind_valid("nvidia.com"));
    try testing.expect(!cdi.kind_valid("/gpu"));
    try testing.expect(!cdi.kind_valid("a./b"));
    try testing.expect(cdi.device_name_valid("GPU-0a1b:2"));
    try testing.expect(!cdi.device_name_valid(""));
    try testing.expect(!cdi.device_name_valid("-x"));
    const long: [constants.cdi_device_name_bytes_max + 1]u8 = @splat('x');
    try testing.expect(cdi.device_name_valid(long[0..constants.cdi_device_name_bytes_max]));
    try testing.expect(!cdi.device_name_valid(&long));
    try testing.expect(cdi.path_valid("/usr/lib/x.so"));
    try testing.expect(!cdi.path_valid("usr"));
    try testing.expect(!cdi.path_valid("/a/../b"));
    try testing.expect(!cdi.path_valid("/a//b"));
    try testing.expect(!cdi.path_valid("/a/"));
    try testing.expect(cdi.env_valid("A_1=x y"));
    try testing.expect(!cdi.env_valid("A=\"x"));
    try testing.expect(!cdi.env_valid("=x"));
    const q = cdi.split_qualified("vendor.example/gpu=all").?;
    try testing.expectEqualStrings("vendor.example/gpu", q.kind);
    try testing.expectEqualStrings("all", q.name);
    try testing.expect(cdi.split_qualified("/dev/dri/card0") == null);
}

/// The second caller: no CLI, no host, only file contents and a name.
fn resolve_one(asked: []const []const u8, out: *cdi.Resolved) !?cdi.Refusal {
    const parsed = try make();
    defer testing.allocator.destroy(parsed);
    var resolver: cdi.Resolver = undefined;
    resolver.init(asked, parsed, out);
    if (resolver.add_file("fake.json", fake_spec)) |refusal| return refusal;
    return resolver.finish();
}

test "resolve: a device brings its node, the common mounts, env and cache directories" {
    const out = try resolved();
    defer testing.allocator.destroy(out);
    const refusal = try resolve_one(&.{"vendor.example/gpu=1"}, out);
    try testing.expectEqual(@as(?cdi.Refusal, null), refusal);
    try testing.expectEqual(@as(u32, 1), out.nodes_count);
    try testing.expectEqualStrings("/dev/fake1", out.text(out.nodes[0]));
    try testing.expectEqualStrings("/usr/lib/fake.so", out.text(out.mounts[0].container));
    try testing.expectEqualStrings("FAKE_VISIBLE=all", out.text(out.env[0]));
    try testing.expectEqualStrings("/usr/lib", out.text(out.dirs[0]));
}

test "resolve: all is every device, and two devices do not repeat the common edits" {
    const out = try resolved();
    defer testing.allocator.destroy(out);
    const refusal = try resolve_one(&.{"vendor.example/gpu=all"}, out);
    try testing.expectEqual(@as(?cdi.Refusal, null), refusal);
    try testing.expectEqual(@as(u32, 2), out.nodes_count);
    try testing.expectEqual(@as(u32, 1), out.mounts_count);
    try testing.expectEqual(@as(u32, 1), out.env_count);
    const again = try resolve_one(&.{ "vendor.example/gpu=0", "vendor.example/gpu=0" }, out);
    try testing.expectEqual(@as(?cdi.Refusal, null), again);
    try testing.expectEqual(@as(u32, 1), out.nodes_count);
}

test "resolve: an unknown name is refused and the known names are listed" {
    const parsed = try make();
    defer testing.allocator.destroy(parsed);
    const out = try resolved();
    defer testing.allocator.destroy(out);
    var resolver: cdi.Resolver = undefined;
    resolver.init(&.{"vendor.example/gpu=7"}, parsed, out);
    try testing.expectEqual(@as(?cdi.Refusal, null), resolver.add_file("fake.json", fake_spec));
    const refusal = resolver.finish().?;
    try testing.expectEqual(@as(u32, 0), refusal.unknown);
    try testing.expectEqual(@as(u32, 2), resolver.known_count);
    try testing.expectEqualStrings("vendor.example/gpu=0", resolver.known_name(0));
}

test "resolve: a YAML file is a problem, not a refusal, when another file has the device" {
    const parsed = try make();
    defer testing.allocator.destroy(parsed);
    const out = try resolved();
    defer testing.allocator.destroy(out);
    var resolver: cdi.Resolver = undefined;
    resolver.init(&.{"vendor.example/gpu=0"}, parsed, out);
    try testing.expectEqual(@as(?cdi.Refusal, null), resolver.add_file("a.yaml", "cdiVersion: 0.5"));
    try testing.expectEqual(@as(u32, 1), resolver.problems_count);
    try testing.expectEqual(cdi.Problem.yaml, resolver.problem_slice()[0].problem);
    try testing.expectEqual(@as(?cdi.Refusal, null), resolver.add_file("b.json", fake_spec));
    try testing.expectEqual(@as(?cdi.Refusal, null), resolver.finish());
}

test "resolve: an unsupported edit is refused only for a device that has it" {
    const spec =
        \\{"cdiVersion":"0.5.0","kind":"a.b/c","devices":[
        \\ {"name":"ok","containerEdits":{"deviceNodes":[{"path":"/dev/ok"}]}},
        \\ {"name":"bad","containerEdits":{"additionalGids":[7]}}]}
    ;
    const parsed = try make();
    defer testing.allocator.destroy(parsed);
    const out = try resolved();
    defer testing.allocator.destroy(out);
    var resolver: cdi.Resolver = undefined;
    resolver.init(&.{"a.b/c=ok"}, parsed, out);
    try testing.expectEqual(@as(?cdi.Refusal, null), resolver.add_file("s.json", spec));
    try testing.expectEqual(@as(?cdi.Refusal, null), resolver.finish());
    resolver.init(&.{"a.b/c=bad"}, parsed, out);
    const refusal = resolver.add_file("s.json", spec).?;
    try testing.expectEqual(cdi.Unsupported.additional_gids, refusal.unsupported.edit);
}

test "resolve: a mount conflict and the per-run node bound" {
    const parsed = try make();
    defer testing.allocator.destroy(parsed);
    const out = try resolved();
    defer testing.allocator.destroy(out);
    const conflict =
        \\{"cdiVersion":"0.5.0","kind":"a.b/c","devices":[
        \\ {"name":"x","containerEdits":{"mounts":[
        \\   {"hostPath":"/a/x","containerPath":"/lib/x"},
        \\   {"hostPath":"/b/x","containerPath":"/lib/x"}]}}]}
    ;
    var resolver: cdi.Resolver = undefined;
    resolver.init(&.{"a.b/c=x"}, parsed, out);
    const refusal = resolver.add_file("s.json", conflict).?;
    try testing.expectEqual(cdi.Unsupported.mount_conflict, refusal.unsupported.edit);
}

const Edit = enum { nodes, mounts, env, dirs };

/// A one-device spec with `count` edits of one kind, each different.
fn edit_spec(buffer: []u8, comptime edit: Edit, count: u32) []const u8 {
    var length: usize = 0;
    const head = "{\"cdiVersion\":\"0.5.0\",\"kind\":\"a.b/c\",\"devices\":[{\"name\":\"x\"," ++
        "\"containerEdits\":{";
    @memcpy(buffer[0..head.len], head);
    length += head.len;
    const key = switch (edit) {
        .nodes => "\"deviceNodes\":[",
        .mounts => "\"mounts\":[",
        .env => "\"env\":[",
        .dirs => "\"hooks\":[{\"hookName\":\"createContainer\",\"path\":" ++
            "\"/usr/bin/nvidia-cdi-hook\",\"args\":[\"nvidia-cdi-hook\",\"update-ldcache\"",
    };
    @memcpy(buffer[length..][0..key.len], key);
    length += key.len;
    for (0..count) |index| {
        const comma: []const u8 = if (index > 0 and edit != .dirs) "," else "";
        const piece = switch (edit) {
            .nodes => "{s}{{\"path\":\"/dev/n{d}\"}}",
            .mounts => "{s}{{\"hostPath\":\"/h/m{d}\",\"containerPath\":\"/c/m{d}\"}}",
            .env => "{s}\"V{d}=x\"",
            .dirs => ",\"--folder\",\"/usr/lib/d{d}\"{s}",
        };
        const written = switch (edit) {
            .mounts => std.fmt.bufPrint(buffer[length..], piece, .{ comma, index, index }),
            .dirs => std.fmt.bufPrint(buffer[length..], piece, .{ index, "" }),
            else => std.fmt.bufPrint(buffer[length..], piece, .{ comma, index }),
        } catch unreachable; // The buffer holds the largest spec.
        length += written.len;
    }
    const tail = if (edit == .dirs) "]}]}}]}" else "]}}]}";
    @memcpy(buffer[length..][0..tail.len], tail);
    return buffer[0 .. length + tail.len];
}

fn resolve_edits(comptime edit: Edit, count: u32) !?cdi.Refusal {
    const parsed = try make();
    defer testing.allocator.destroy(parsed);
    const out = try resolved();
    defer testing.allocator.destroy(out);
    const buffer = try testing.allocator.alloc(u8, 32 * 1024);
    defer testing.allocator.free(buffer);
    var resolver: cdi.Resolver = undefined;
    resolver.init(&.{"a.b/c=x"}, parsed, out);
    const refusal = resolver.add_file("s.json", edit_spec(buffer, edit, count));
    try testing.expectEqual(@as(u32, 0), resolver.problems_count);
    return refusal orelse resolver.finish();
}

test "resolve: the per-run bounds, at and one past" {
    // Goal: what one run applies is bounded, and the first edit over is `too_big`, not a crash.
    const cases = [_]struct { comptime edit: Edit, max: u32 }{
        .{ .edit = .nodes, .max = constants.cdi_run_nodes_max },
        .{ .edit = .mounts, .max = constants.cdi_run_mounts_max },
        .{ .edit = .env, .max = constants.cdi_run_env_max },
        .{ .edit = .dirs, .max = constants.cdi_run_dirs_max },
    };
    inline for (cases) |case| {
        try testing.expectEqual(@as(?cdi.Refusal, null), try resolve_edits(case.edit, case.max));
        const over = (try resolve_edits(case.edit, case.max + 1)).?;
        try testing.expectEqual(@as(u32, 0), over.too_big);
    }
}
