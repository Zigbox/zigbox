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

const store_import_schema =
    \\{"$schema":"https://json-schema.org/draft/2020-12/schema",
    \\"$id":"https://zigbox.github.io/zigbox/schema/store-import/1","version":1,
    \\"title":"zbx store import --output json",
    \\"description":"stdout: what was imported. Warnings and failures are diagnostics on stderr.",
    \\"type":"object","required":["schema","digest","source","files","directories","symlinks",
    \\"skipped","unmapped_owners","unmapped_groups","bytes","new_objects","reused_objects",
    \\"new_bytes","new_trees","reused_trees",
    \\"ids"],
    \\"properties":{"schema":{"const":"zbx.store.import/1"},
    \\"digest":{"type":"string","pattern":"^b3:[0-9a-f]{64}$"},"source":{"type":"string"},
    \\"files":{"type":"integer"},"directories":{"type":"integer"},"symlinks":{"type":"integer"},
    \\"skipped":{"type":"integer","description":"devices, FIFOs and sockets left out"},
    \\"xattrs_skipped":{"type":"integer"},
    \\"unmapped_owners":{"type":"integer","description":"entries with an unmappable owner"},
    \\"unmapped_groups":{"type":"integer","description":"the same for groups"},
    \\"bytes":{"type":"integer",
    \\"description":"the sum of the lengths of the files"},
    \\"new_objects":{"type":"integer"},"reused_objects":{"type":"integer"},
    \\"new_bytes":{"type":"integer","description":"bytes of the objects that were new"},
    \\"new_trees":{"type":"integer"},"reused_trees":{"type":"integer"},
    \\"ids":{"enum":["full","single"],"description":"how ids were mapped while importing"}}}
;

const store_ls_schema =
    \\{"$schema":"https://json-schema.org/draft/2020-12/schema",
    \\"$id":"https://zigbox.github.io/zigbox/schema/store-ls/1","version":1,
    \\"title":"zbx store ls --output json",
    \\"description":"stdout: the roots, newest first.",
    \\"type":"object","required":["schema","roots"],
    \\"properties":{"schema":{"const":"zbx.store.ls/1"},
    \\"roots":{"type":"array","items":{"type":"object",
    \\"required":["digest","kind","time","files","bytes","source","parent"],
    \\"properties":{"digest":{"type":"string","pattern":"^b3:[0-9a-f]{64}$"},
    \\"kind":{"enum":["import","commit","container"]},
    \\"time":{"type":"integer","description":"seconds since the epoch"},
    \\"files":{"type":"integer"},"bytes":{"type":"integer"},
    \\"source":{"type":"string"},"parent":{"type":["string","null"]}}}}}}
;

const store_du_schema =
    \\{"$schema":"https://json-schema.org/draft/2020-12/schema",
    \\"$id":"https://zigbox.github.io/zigbox/schema/store-du/1","version":1,
    \\"title":"zbx store du --output json",
    \\"description":"stdout: the store's totals, or with a digest one tree's sizes.",
    \\"type":"object","required":["schema"],
    \\"properties":{"schema":{"const":"zbx.store.du/1"},
    \\"store":{"type":"object","required":["bytes","objects","trees"],
    \\"properties":{"bytes":{"type":"integer"},"objects":{"type":"integer"},
    \\"trees":{"type":"integer"}}},
    \\"tree":{"type":"object","required":["digest","files","logical_bytes","objects",
    \\"stored_bytes","shared_bytes"],
    \\"properties":{"digest":{"type":"string","pattern":"^b3:[0-9a-f]{64}$"},
    \\"files":{"type":"integer"},"logical_bytes":{"type":"integer"},
    \\"objects":{"type":"integer","description":"distinct objects"},
    \\"stored_bytes":{"type":"integer","description":"bytes of the distinct objects"},
    \\"shared_bytes":{"type":"integer","description":"of those, bytes other roots also use"}}}},
    \\"oneOf":[{"required":["store"]},{"required":["tree"]}]}
;

const store_rm_schema =
    \\{"$schema":"https://json-schema.org/draft/2020-12/schema",
    \\"$id":"https://zigbox.github.io/zigbox/schema/store-rm/1","version":1,
    \\"title":"zbx store rm --output json",
    \\"description":"stdout: the root that was dropped. A failure is a diagnostic on stderr.",
    \\"type":"object","required":["schema","digest","removed"],
    \\"properties":{"schema":{"const":"zbx.store.rm/1"},
    \\"digest":{"type":"string","pattern":"^b3:[0-9a-f]{64}$"},"removed":{"const":true}}}
;

const commit_schema =
    \\{"$schema":"https://json-schema.org/draft/2020-12/schema",
    \\"$id":"https://zigbox.github.io/zigbox/schema/commit/1","version":1,
    \\"title":"zbx commit --output json",
    \\"description":"stdout: the tree a container's changes made. A failure is a diagnostic",
    \\"type":"object","required":["schema","digest","parent","container","unchanged","files",
    \\"bytes","new_objects","new_bytes","new_trees","deleted"],
    \\"properties":{"schema":{"const":"zbx.commit/1"},
    \\"digest":{"type":"string","pattern":"^b3:[0-9a-f]{64}$"},
    \\"parent":{"type":"string","pattern":"^b3:[0-9a-f]{64}$",
    \\"description":"the tree the container started from"},
    \\"container":{"type":"string"},
    \\"unchanged":{"type":"boolean",
    \\"description":"true if digest equals parent: nothing changed, no root written"},
    \\"files":{"type":"integer","description":"files in the whole new tree"},
    \\"bytes":{"type":"integer","description":"their total length"},
    \\"new_objects":{"type":"integer"},"new_bytes":{"type":"integer"},
    \\"new_trees":{"type":"integer"},
    \\"deleted":{"type":"integer","description":"names the container deleted from the parent"}}}
;

const store_diff_schema =
    \\{"$schema":"https://json-schema.org/draft/2020-12/schema",
    \\"$id":"https://zigbox.github.io/zigbox/schema/store-diff/1","version":1,
    \\"title":"zbx store diff --output json",
    \\"description":"stdout: the paths that differ, in path order, a directory first",
    \\"type":"object","required":["schema","from","to","changes","summary"],
    \\"properties":{"schema":{"const":"zbx.store.diff/1"},
    \\"from":{"type":"string","pattern":"^b3:[0-9a-f]{64}$"},
    \\"to":{"type":"string","pattern":"^b3:[0-9a-f]{64}$"},
    \\"changes":{"type":"array","items":{"type":"object","required":["change","kind","path"],
    \\"properties":{"change":{"enum":["added","removed","changed"]},
    \\"kind":{"enum":["file","dir","symlink"],
    \\"description":"in the second tree, or the first for a removed path"},
    \\"path":{"type":"string",
    \\"description":"from the root, with a leading slash; / is the root directory itself"},
    \\"attributes":{"type":"array","description":"only for changed: what differs",
    \\"items":{"enum":["content","mode","owner","xattrs","target","type"]}}}}},
    \\"summary":{"type":"object","required":["added","removed","changed"],
    \\"properties":{"added":{"type":"integer"},"removed":{"type":"integer"},
    \\"changed":{"type":"integer"}}}}}
;

const store_verify_schema =
    \\{"$schema":"https://json-schema.org/draft/2020-12/schema",
    \\"$id":"https://zigbox.github.io/zigbox/schema/store-verify/1","version":1,
    \\"title":"zbx store verify --output json",
    \\"description":"stdout: what was checked and what is damaged (exit 2 if anything is)",
    \\"type":"object","required":["schema","ok","objects","object_bytes","chunk_lists",
    \\"orphan_lists","trees","roots","damaged","paths_truncated","things"],
    \\"properties":{"schema":{"const":"zbx.store.verify/1"},"ok":{"type":"boolean"},
    \\"objects":{"type":"integer"},"object_bytes":{"type":"integer"},
    \\"chunk_lists":{"type":"integer"},
    \\"orphan_lists":{"type":"integer","description":"chunk lists with no object: not damage"},
    \\"trees":{"type":"integer"},"roots":{"type":"integer"},
    \\"damaged":{"type":"integer","description":"all damaged things, listed or not"},
    \\"paths_truncated":{"type":"boolean","description":"the walk for paths ran out of room"},
    \\"things":{"type":"array","items":{"type":"object",
    \\"required":["id","class","kind","reason","errno","reached","paths"],
    \\"properties":{"id":{"type":"string","pattern":"^b3:[0-9a-f]{64}$"},
    \\"class":{"enum":["object","tree","root"]},
    \\"kind":{"enum":["content","chunk_list","unreadable","not_a_file","tree_damaged",
    \\"tree_missing","object_missing","root_unusable"]},
    \\"reason":{"type":"string"},"errno":{"type":"integer"},
    \\"reached":{"type":"integer","description":"paths in root trees that reach it"},
    \\"paths":{"type":"array","description":"up to 16 of them, sorted",
    \\"items":{"type":"object","required":["root","path"],
    \\"properties":{"root":{"type":"string","pattern":"^b3:[0-9a-f]{64}$"},
    \\"path":{"type":"string","description":"from the root, with a leading slash"}}}}}}}}}
;

const store_gc_schema =
    \\{"$schema":"https://json-schema.org/draft/2020-12/schema",
    \\"$id":"https://zigbox.github.io/zigbox/schema/store-gc/1","version":1,
    \\"title":"zbx store gc --output json",
    \\"description":"stdout: the plan (applied false), or what a confirmed plan moved (true)",
    \\"type":"object","required":["schema","applied","plan","objects","lists","trees","farms",
    \\"tmp","bytes"],
    \\"properties":{"schema":{"const":"zbx.store.gc/1"},"applied":{"type":"boolean"},
    \\"plan":{"type":"string","pattern":"^b3:[0-9a-f]{64}$",
    \\"description":"the hash to confirm with"},
    \\"generation":{"type":"integer","description":"plans only: the store's generation counter"},
    \\"gc":{"type":"string","description":"applied only: the id of the trash"},
    \\"expires":{"type":"integer","description":"applied only: when the trash is emptied"},
    \\"expired":{"type":"integer","description":"applied only: old trash emptied now"},
    \\"objects":{"type":"integer"},"lists":{"type":"integer","description":"chunk lists"},
    \\"trees":{"type":"integer"},"farms":{"type":"integer","description":"materialized dirs"},
    \\"tmp":{"type":"integer","description":"leftovers of dead processes in tmp/"},
    \\"bytes":{"type":"integer"}}}
;

const store_trash_schema =
    \\{"$schema":"https://json-schema.org/draft/2020-12/schema",
    \\"$id":"https://zigbox.github.io/zigbox/schema/store-trash/1","version":1,
    \\"title":"zbx store gc --trash --output json",
    \\"description":"stdout: the trash that is left, oldest first",
    \\"type":"object","required":["schema","trash"],
    \\"properties":{"schema":{"const":"zbx.store.trash/1"},
    \\"trash":{"type":"array","items":{"type":"object","required":["gc","readable"],
    \\"properties":{"gc":{"type":"string"},"readable":{"type":"boolean"},
    \\"time":{"type":"integer"},"expires":{"type":"integer"},
    \\"objects":{"type":"integer"},"lists":{"type":"integer"},"trees":{"type":"integer"},
    \\"farms":{"type":"integer"},"bytes":{"type":"integer"},
    \\"complete":{"type":"boolean","description":"false if a gc or restore was interrupted"}}}}}}
;

const store_restore_schema =
    \\{"$schema":"https://json-schema.org/draft/2020-12/schema",
    \\"$id":"https://zigbox.github.io/zigbox/schema/store-restore/1","version":1,
    \\"title":"zbx store restore --output json",
    \\"description":"stdout: what was moved back from the trash",
    \\"type":"object","required":["schema","gc","objects","lists","trees","farms"],
    \\"properties":{"schema":{"const":"zbx.store.restore/1"},"gc":{"type":"string"},
    \\"objects":{"type":"integer"},"lists":{"type":"integer"},"trees":{"type":"integer"},
    \\"farms":{"type":"integer"}}}
;

const pull_resolve_schema =
    \\{"$schema":"https://json-schema.org/draft/2020-12/schema",
    \\"$id":"https://zigbox.github.io/zigbox/schema/pull-resolve/1","version":1,
    \\"title":"zbx pull --resolve-only --output json",
    \\"description":"stdout: what a reference names for this platform. A failure is on stderr.",
    \\"type":"object","required":["schema","reference","registry","repository","index_digest",
    \\"manifest_digest","manifest_size","platform","config_digest","config_size","layers"],
    \\"properties":{"schema":{"const":"zbx.pull.resolve/1"},
    \\"reference":{"type":"string","description":"the canonical form of the reference"},
    \\"registry":{"type":"string"},"repository":{"type":"string"},
    \\"index_digest":{"type":["string","null"],"pattern":"^sha256:[0-9a-f]{64}$",
    \\"description":"the index or manifest list the reference named; null for a single manifest"},
    \\"manifest_digest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$",
    \\"description":"the manifest of this platform: what zbx.lock records"},
    \\"manifest_size":{"type":"integer"},
    \\"platform":{"enum":["linux/amd64","linux/arm64"]},
    \\"config_digest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
    \\"config_size":{"type":"integer"},
    \\"layers":{"type":"array","items":{"type":"object","required":["digest","size","kind"],
    \\"properties":{"digest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
    \\"size":{"type":"integer"},"kind":{"enum":["tar","tar_gzip","tar_zstd"]}}}}}}
;

const Entry = struct { command: []const u8, text: []const u8 };

const table = [_]Entry{
    .{ .command = "run", .text = run_schema },
    .{ .command = "bundle", .text = bundle_schema },
    .{ .command = "ps", .text = ps_schema },
    .{ .command = "stop", .text = stop_schema },
    .{ .command = "doctor", .text = doctor_schema },
    .{ .command = "store-import", .text = store_import_schema },
    .{ .command = "store-ls", .text = store_ls_schema },
    .{ .command = "store-du", .text = store_du_schema },
    .{ .command = "store-rm", .text = store_rm_schema },
    .{ .command = "commit", .text = commit_schema },
    .{ .command = "store-diff", .text = store_diff_schema },
    .{ .command = "store-verify", .text = store_verify_schema },
    .{ .command = "store-gc", .text = store_gc_schema },
    .{ .command = "store-trash", .text = store_trash_schema },
    .{ .command = "store-restore", .text = store_restore_schema },
    .{ .command = "pull-resolve", .text = pull_resolve_schema },
};

/// The schema of a command's output, or null if it has none.
pub fn of(command: []const u8) ?[]const u8 {
    assert(command.len <= 4096);
    assert(table.len == 16);
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
    // Goal: the registry is complete and each document parses. Method: the five commands of M2
    // and the four store commands; an unknown command has none.
    for (table) |entry| {
        try testing.expect(try test_util.json_is_valid(entry.text));
        var id: [64]u8 = undefined;
        const want = try std.fmt.bufPrint(&id, "/schema/{s}/1\"", .{entry.command});
        try testing.expect(std.mem.indexOf(u8, entry.text, want) != null);
        try testing.expect(std.mem.indexOf(u8, entry.text, "\"version\":1") != null);
    }
    try testing.expect(of("explain") == null);
    try testing.expect(of("") == null);
    try testing.expectEqual(@as(usize, 16), table.len);
}
