//! The JSON schemas of the commands' output (`zbx schema <command>`), versioned: the number in
//! each `$id` and `version` is the schema's, and a change that could break a reader makes a new
//! one. They describe what `--output json` writes: the result on stdout for the commands that
//! have one (`ps`, `stop`, `run -d`, `bundle`), and the lines on stderr: a diagnostic per
//! failure or warning, and for a foreground `run` that started, a last `container_exit` line.
//!
//! Every one is one JSON object. The tests check that each is valid JSON and that the output of
//! the commands they describe has the keys they require.

const std = @import("std");
const assert = std.debug.assert;

/// The diagnostic object, as `zbx explain`, the renderer and DIAGNOSTICS.md describe it.
const diagnostic_definition =
    \\"diagnostic":{"type":"object","required":["code","severity","blame","summary","causes",
    \\"docs"],
    \\"properties":{"code":{"type":"string","pattern":"^ZBX-[EWB][0-9]{4}$"},
    \\"severity":{"enum":["error","warning","bug"]},"blame":{"enum":["user","environment",
    \\"external","bug"]},
    \\"summary":{"type":"string"},"causes":{"type":"array","items":{"type":"string"}},
    \\"while":{"type":"array","items":{"type":"string"}},"context":{"type":"object"},
    \\"fixes":{"type":"array","items":{"type":"object"}},"docs":{"type":"string"}}}
;

const run_schema =
    \\{"$schema":"https://json-schema.org/draft/2020-12/schema",
    \\"$id":"https://zigbox.github.io/zigbox/schema/run/1","version":1,
    \\"title":"zbx run --output json",
    \\"description":"stderr: diagnostics, then container_exit. With -d, stdout: detached.",
    \\"oneOf":[{"$ref":"#/$defs/diagnostic"},{"$ref":"#/$defs/container_exit"},
    \\{"$ref":"#/$defs/detached"}],
    \\"$defs":{
++ diagnostic_definition ++
    \\,"container_exit":{"type":"object","required":["container_exit"],
    \\"properties":{"container_exit":{"type":"object",
    \\"required":["reason","code"],"properties":{"reason":{"enum":["exited","signal","oom",
    \\"pid_limit"]},
    \\"code":{"type":"integer","minimum":0,"maximum":255},"signal":{"type":"integer"},
    \\"limit_bytes":{"type":["integer","null"]},"limit":{"type":["integer","null"]},
    \\"timed_out":{"type":"boolean"}}}}},
    \\"detached":{"type":"object","required":["schema","container"],
    \\"properties":{"schema":{"const":"zbx.run/1"},
    \\"container":{"type":"object","required":["name","pid","detached"],
    \\"properties":{"name":{"type":"string"},
    \\"pid":{"type":"integer"},"scope":{"type":["string","null"]},"detached":{"const":true}}}}}}}
;

const ps_schema =
    \\{"$schema":"https://json-schema.org/draft/2020-12/schema",
    \\"$id":"https://zigbox.github.io/zigbox/schema/ps/1","version":1,
    \\"title":"zbx ps --output json",
    \\"description":"stdout: containers, newest first; without --all only running and lost.",
    \\"type":"object","required":["schema","containers"],
    \\"properties":{"schema":{"const":"zbx.ps/1"},
    \\"containers":{"type":"array","items":{"type":"object",
    \\"required":["name","state","pid","started","timed_out","command","labels","limits"],
    \\"properties":{
    \\"name":{"type":"string"},"state":{"enum":["running","stopped","lost"]},
    \\"pid":{"type":"integer"},
    \\"supervisor":{"type":"integer"},"scope":{"type":["string","null"]},
    \\"detached":{"type":"boolean"},
    \\"timed_out":{"type":"boolean","description":"stopped because --timeout was up"},
    \\"started":{"type":"integer",
    \\"description":"seconds since the epoch; 0 for a scope without a record"},
    \\"ended":{"type":["integer","null"]},
    \\"reason":{"enum":["exited","signal","oom","pid_limit","none"]},
    \\"exit_code":{"type":["integer","null"]},
    \\"command":{"type":"array","items":{"type":"string"}},
    \\"labels":{"type":"array","items":{"type":"object","required":["key","value"],
    \\"properties":{"key":{"type":"string"},"value":{"type":"string"}}}},
    \\"limits":{"type":"object","properties":{"memory_bytes":{"type":["integer","null"]},
    \\"pids":{"type":["integer","null"]},"cpu_millis":{"type":["integer","null"]}}}}}}}}
;

const stop_schema =
    \\{"$schema":"https://json-schema.org/draft/2020-12/schema",
    \\"$id":"https://zigbox.github.io/zigbox/schema/stop/1","version":1,
    \\"title":"zbx stop --output json",
    \\"description":"stdout: how the container stopped. A failure is a diagnostic on stderr.",
    \\"type":"object","required":["schema","name","result"],
    \\"properties":{"schema":{"const":"zbx.stop/1"},
    \\"name":{"type":"string"},"result":{"enum":["graceful","killed","already_stopped"]},
    \\"reason":{"enum":["exited","signal","oom","pid_limit","none"]},
    \\"exit_code":{"type":["integer","null"]}}}
;

const bundle_schema =
    \\{"$schema":"https://json-schema.org/draft/2020-12/schema",
    \\"$id":"https://zigbox.github.io/zigbox/schema/bundle/1","version":1,
    \\"title":"zbx bundle --output json",
    \\"description":"stdout: the path of the bundle written. A failure is a diagnostic on stderr.",
    \\"type":"object","required":["bundle"],"properties":{"bundle":{"type":"string"}}}
;

const doctor_schema =
    \\{"$schema":"https://json-schema.org/draft/2020-12/schema",
    \\"$id":"https://zigbox.github.io/zigbox/schema/doctor/1","version":1,
    \\"title":"zbx doctor --output json",
    \\"description":"stderr: a diagnostic per failing check, in order. Exit 0, or 2 on failure.",
    \\"$ref":"#/$defs/diagnostic","$defs":{
++ diagnostic_definition ++ "}}";

const Entry = struct { command: []const u8, text: []const u8 };

const table = [_]Entry{
    .{ .command = "run", .text = run_schema },
    .{ .command = "bundle", .text = bundle_schema },
    .{ .command = "ps", .text = ps_schema },
    .{ .command = "stop", .text = stop_schema },
    .{ .command = "doctor", .text = doctor_schema },
};

/// The schema of a command's output, or null if it has none.
pub fn of(command: []const u8) ?[]const u8 {
    assert(command.len <= 4096);
    assert(table.len == 5);
    for (table) |entry| {
        if (std.mem.eql(u8, entry.command, command)) return entry.text;
    }
    return null;
}

/// The longest schema, for the buffer that prints it.
pub const bytes_max: usize = blk: {
    var longest: usize = 0;
    for (table) |entry| longest = @max(longest, entry.text.len + 1);
    break :blk longest;
};

const testing = std.testing;
const test_util = @import("test_util.zig");

test "every schema is valid JSON, names its command and its version" {
    // Goal: the registry is complete and each document parses. Method: the five commands of the
    // brief; an unknown command has none.
    for (table) |entry| {
        try testing.expect(try test_util.json_is_valid(entry.text));
        var id: [64]u8 = undefined;
        const want = try std.fmt.bufPrint(&id, "/schema/{s}/1\"", .{entry.command});
        try testing.expect(std.mem.indexOf(u8, entry.text, want) != null);
        try testing.expect(std.mem.indexOf(u8, entry.text, "\"version\":1") != null);
    }
    try testing.expect(of("explain") == null);
    try testing.expect(of("") == null);
    try testing.expectEqual(@as(usize, 5), table.len);
}
