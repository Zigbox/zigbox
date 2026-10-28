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

/// The members of the diagnostic object, as `zbx explain`, the renderer and DIAGNOSTICS.md
/// describe it. Inline text (no `$ref`), shared by every schema that holds a diagnostic.
const diagnostic_properties =
    \\"code":{"type":"string","pattern":"^ZBX-[EWB][0-9]{4}$"},
    \\"severity":{"enum":["error","warning","bug"]},"blame":{"enum":["user","environment",
    \\"external","internal","bug"]},
    \\"summary":{"type":"string"},"causes":{"type":"array","items":{"type":"string"}},
    \\"while":{"type":"array","items":{"type":"string"}},"context":{"type":"object"},
    \\"fixes":{"type":"array","items":{"type":"object","properties":{
    \\"sentence":{"type":"string"},"command":{"type":["string","null"]},
    \\"needs_root":{"type":"boolean","description":"M6: only when true; the command needs root"},
    \\"template":{"type":"boolean",
    \\"description":"M6: only when true; an example to adapt, not to run as written"}}}},
    \\"docs":{"type":"string"},"saved":{"type":"string"},"omitted":{"type":"object"}
;

const diagnostic_required =
    \\"required":["code","severity","blame","summary","causes","docs"]
;

/// The diagnostic as one object schema, for a member that holds one (a doctor check's).
const diagnostic_object =
    \\{"type":"object",
++ diagnostic_required ++
    \\,"properties":{
++ diagnostic_properties ++ "}}";

/// The old `$defs` entry, kept so that a reader of the path `$defs.diagnostic` still finds it.
const diagnostic_definition = "\"diagnostic\":" ++ diagnostic_object;

/// What `container_exit` holds (the value of the member of that name).
const container_exit_object =
    \\{"type":"object","required":["reason","code"],
    \\"properties":{"reason":{"enum":["exited","signal","oom","pid_limit"]},
    \\"code":{"type":"integer","minimum":0,"maximum":255},"signal":{"type":"integer"},
    \\"limit_bytes":{"type":["integer","null"]},"limit":{"type":["integer","null"]},
    \\"network":{"enum":["none","host","user"]},
    \\"hint":{"enum":["network_none"],
    \\"description":"M6: the failure may be the network: default network, no --net, exit != 0"},
    \\"published":{"type":"array","description":"--publish: TCP host ports forwarded (M5)",
    \\"items":{"type":"object","required":["host","container"],
    \\"properties":{"host":{"type":"integer","minimum":1,"maximum":65535},
    \\"container":{"type":"integer","minimum":1,"maximum":65535}}}},
    \\"timed_out":{"type":"boolean"}}}
;

const ran_object =
    \\{"type":"object","description":"what the run ran","required":["kind"],
    \\"properties":{"kind":{"enum":["image","tree","rootfs"]},
    \\"reference":{"type":"string","description":"image: the name as typed"},
    \\"manifest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","description":"image"},
    \\"tree":{"type":"string","pattern":"^b3:[0-9a-f]{64}$","description":"image and tree"},
    \\"path":{"type":"string","description":"rootfs: the directory as typed"}}}
;

/// The `container` of a detached run's document. `network`, `published` and `env` are M6's.
const detached_container_object =
    \\{"type":"object","required":["name","pid","detached"],
    \\"properties":{"name":{"type":"string"},
    \\"pid":{"type":"integer"},"scope":{"type":["string","null"]},"detached":{"const":true},
    \\"network":{"enum":["none","host","user"],"description":"M6: what the container can reach"},
    \\"published":{"type":"array","description":"M6: --publish, as in container_exit",
    \\"items":{"type":"object","required":["host","container"],
    \\"properties":{"host":{"type":"integer","minimum":1,"maximum":65535},
    \\"container":{"type":"integer","minimum":1,"maximum":65535}}}},
    \\"env":{"type":"array","items":{"type":"string"},
    \\"description":"M6: names of the variables set with -e; a value is never shown"}}}
;

/// `zbx schema run`: ONE object schema with no `$ref`, which an agent can follow without a
/// resolver. The members of the three documents a run can print (a diagnostic, the
/// `container_exit` line, the detached document) are all listed under `properties`, and `oneOf`
/// says which members tell the kinds apart. `$defs` is the older form of the same text, kept
/// so that no reader of it breaks. Nothing in this text refers to anything else.
const run_schema =
    \\{"$schema":"https://json-schema.org/draft/2020-12/schema",
    \\"$id":"https://zigbox.github.io/zigbox/schema/run/1","version":1,
    \\"title":"zbx run --output json",
    \\"description":"stderr: diagnostics, then container_exit. With -d, stdout: detached.",
    \\"$comment":"One object schema, no $ref: oneOf names the members that tell them apart.",
    \\"type":"object",
    \\"properties":{
++ diagnostic_properties ++
    \\,"container_exit":
++ container_exit_object ++
    \\,"schema":{"const":"zbx.run/1"},"container":
++ detached_container_object ++
    \\,"ran":
++ ran_object ++
    \\},
    \\"oneOf":[{
++ diagnostic_required ++
    \\},{"required":["container_exit"]},{"required":["schema","container"]}],
    \\"$defs":{
++ diagnostic_definition ++
    \\,"container_exit":{"type":"object","required":["container_exit"],
    \\"properties":{"container_exit":
++ container_exit_object ++
    \\,"ran":
++ ran_object ++
    \\}},
    \\"ran":
++ ran_object ++
    \\,"detached":{"type":"object","required":["schema","container"],
    \\"properties":{"schema":{"const":"zbx.run/1"},"container":
++ detached_container_object ++
    \\,"ran":
++ ran_object ++
    \\}}}}
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
    \\"pids":{"type":["integer","null"]},"cpu_millis":{"type":["integer","null"]}}},
    \\"network":{"enum":["none","host","user",null],
    \\"description":"M6: what the container can reach; null for a record of an older zbx"},
    \\"published":{"type":"array","description":"M6: --publish, as in zbx run",
    \\"items":{"type":"object","required":["host","container"],
    \\"properties":{"host":{"type":"integer","minimum":1,"maximum":65535},
    \\"container":{"type":"integer","minimum":1,"maximum":65535}}}},
    \\"env":{"type":"array","items":{"type":"string"},
    \\"description":"M6: names of the variables set with -e; a value is never kept"}}}}}}
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

/// `zbx schema doctor`: stdout is the `zbx.doctor/1` report; stderr carries the diagnostic of
/// each failing check, as before (M6 added the report; the diagnostics did not change). One
/// object schema without `$ref`, like `run`'s.
const doctor_schema =
    \\{"$schema":"https://json-schema.org/draft/2020-12/schema",
    \\"$id":"https://zigbox.github.io/zigbox/schema/doctor/1","version":1,
    \\"title":"zbx doctor --output json",
    \\"description":"stdout: the report. stderr: a diagnostic per failing check. Exit 0, or 2.",
    \\"$comment":"One object schema, no $ref: oneOf names the members that tell them apart.",
    \\"type":"object",
    \\"properties":{
++ diagnostic_properties ++
    \\,"schema":{"const":"zbx.doctor/1"},"ok":{"type":"boolean",
    \\"description":"no check failed; a warning does not change it"},
    \\"checks":{"type":"array","description":"every check, in the order of the text report",
    \\"items":{"type":"object","required":["id","status","detail"],
    \\"properties":{"id":{"enum":["kernel","userns","cgroup","overlay","subid","seccomp","net"]},
    \\"status":{"enum":["ok","warn","fail"]},"detail":{"type":"string",
    \\"description":"the line of the text report"},
    \\"code":{"type":"string","pattern":"^ZBX-[EW][0-9]{4}$",
    \\"description":"only for warn and fail: the code of the diagnostic"},
    \\"diagnostic":
++ diagnostic_object ++
    \\}}}},
    \\"oneOf":[{"required":["schema","ok","checks"]},{
++ diagnostic_required ++
    \\}],
    \\"$defs":{
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
    \\"description":"stdout: the roots, newest first, and the pulled images.",
    \\"type":"object","required":["schema","roots","images"],
    \\"properties":{"schema":{"const":"zbx.store.ls/1"},
    \\"roots":{"type":"array","items":{"type":"object",
    \\"required":["digest","kind","time","files","bytes","source","parent"],
    \\"properties":{"digest":{"type":"string","pattern":"^b3:[0-9a-f]{64}$"},
    \\"kind":{"enum":["import","commit","container"]},
    \\"time":{"type":"integer","description":"seconds since the epoch"},
    \\"files":{"type":"integer"},"bytes":{"type":"integer"},
    \\"source":{"type":"string"},"parent":{"type":["string","null"]}}}},
    \\"images":{"type":"array","description":"pulled images, with every tag they were pulled as",
    \\"items":{"type":"object","required":["reference","tags","manifest","platform","tree","time"],
    \\"properties":{"reference":{"type":["string","null"],
    \\"description":"the newest of tags; null if there are none"},
    \\"tags":{"type":"array","items":{"type":"string"},
    \\"description":"every reference it was pulled as, oldest first; none if only by digest"},
    \\"manifest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
    \\"platform":{"type":"string"},
    \\"tree":{"type":"string","pattern":"^b3:[0-9a-f]{64}$"},
    \\"time":{"type":"integer"}}}}}}
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
    \\"shared_bytes":{"type":"integer","description":"of those, bytes other roots also use"}}},
    \\"images":{"type":"array","description":"du --by-image: one entry for each pulled image",
    \\"items":{"type":"object","required":["reference","tags","manifest","platform","tree",
    \\"files","logical_bytes","compressed_bytes","stored_bytes","shared_bytes"],
    \\"properties":{"reference":{"type":["string","null"],
    \\"description":"the newest of tags; null if there are none"},
    \\"tags":{"type":"array","items":{"type":"string"},
    \\"description":"the references the image was pulled as, oldest first"},
    \\"manifest":{"type":"string"},
    \\"platform":{"type":"string"},"tree":{"type":"string","pattern":"^b3:[0-9a-f]{64}$"},
    \\"files":{"type":"integer"},"logical_bytes":{"type":"integer"},
    \\"compressed_bytes":{"type":"integer","description":"the layers as downloaded"},
    \\"stored_bytes":{"type":"integer","description":"bytes of the distinct objects"},
    \\"shared_bytes":{"type":"integer","description":"of those, bytes other roots also use"}}}}},
    \\"oneOf":[{"required":["store"]},{"required":["tree"]},{"required":["images"]}]}
;

const store_rm_schema =
    \\{"$schema":"https://json-schema.org/draft/2020-12/schema",
    \\"$id":"https://zigbox.github.io/zigbox/schema/store-rm/1","version":1,
    \\"title":"zbx store rm --output json",
    \\"description":"stdout: the root that was dropped. A failure is a diagnostic on stderr.",
    \\"type":"object","required":["schema","digest","removed"],
    \\"properties":{"schema":{"const":"zbx.store.rm/1"},
    \\"digest":{"type":"string","pattern":"^b3:[0-9a-f]{64}$"},"removed":{"const":true},
    \\"images":{"type":"integer","description":"image records of the tree that went with it"}}}
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
    \\"blobs":{"type":"integer","description":"downloaded blobs no image names"},
    \\"partials":{"type":"integer","description":"cut downloads untouched for 24 hours"},
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
    \\"farms":{"type":"integer"},"blobs":{"type":"integer"},"partials":{"type":"integer"},
    \\"bytes":{"type":"integer"},
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
    \\"farms":{"type":"integer"},"blobs":{"type":"integer"},"partials":{"type":"integer"}}}
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

const pull_schema =
    \\{"$schema":"https://json-schema.org/draft/2020-12/schema",
    \\"$id":"https://zigbox.github.io/zigbox/schema/pull/1","version":1,
    \\"title":"zbx pull --output json",
    \\"description":"stdout: the image pulled and the tree it became. A failure is on stderr.",
    \\"type":"object","required":["schema","reference","registry","repository","manifest_digest",
    \\"platform","tree","config","layers","files","directories","symlinks","bytes",
    \\"special_skipped","xattrs_skipped","image","lock"],
    \\"properties":{"schema":{"const":"zbx.pull/1"},
    \\"reference":{"type":"string","description":"as the user wrote it"},
    \\"registry":{"type":"string"},"repository":{"type":"string"},
    \\"manifest_digest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
    \\"platform":{"enum":["linux/amd64","linux/arm64"]},
    \\"tree":{"type":"string","pattern":"^b3:[0-9a-f]{64}$",
    \\"description":"the store's identity of the image: the digest of its flattened tree"},
    \\"config":{"type":"object","required":["digest","cache"],
    \\"properties":{"digest":{"type":"string"},"cache":{"enum":["cached","downloaded","resumed"]}}},
    \\"layers":{"type":"array","items":{"type":"object","required":["digest","size","cache"],
    \\"properties":{"digest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
    \\"size":{"type":"integer"},"cache":{"enum":["cached","downloaded","resumed"]}}}},
    \\"files":{"type":"integer"},"directories":{"type":"integer"},"symlinks":{"type":"integer"},
    \\"bytes":{"type":"integer"},"special_skipped":{"type":"integer"},
    \\"xattrs_skipped":{"type":"integer"},
    \\"image":{"type":"object","description":"what the image runs by default",
    \\"required":["entrypoint","cmd","env","workdir","user"],
    \\"properties":{"entrypoint":{"type":"array","items":{"type":"string"}},
    \\"cmd":{"type":"array","items":{"type":"string"}},
    \\"env":{"type":"array","items":{"type":"string"}},
    \\"workdir":{"type":"string"},"user":{"type":"string"}}},
    \\"lock":{"type":["object","null"],
    \\"description":"zbx.lock after the pull; null for a digest reference, which needs none",
    \\"required":["path","created"],
    \\"properties":{"path":{"type":"string"},
    \\"created":{"type":"boolean","description":"this pull made the file"}}}}}
;

const explain_schema =
    \\{"$schema":"https://json-schema.org/draft/2020-12/schema",
    \\"$id":"https://zigbox.github.io/zigbox/schema/explain/1","version":1,
    \\"title":"zbx explain <code> --output json",
    \\"description":"stdout: one registered code. An unknown code is a diagnostic on stderr.",
    \\"type":"object","required":["schema","code","severity","blame","summary","explanation",
    \\"docs"],
    \\"properties":{"schema":{"const":"zbx.explain/1"},
    \\"code":{"type":"string","pattern":"^ZBX-[EWB][0-9]{4}$"},
    \\"severity":{"enum":["error","warning","note","bug"]},
    \\"blame":{"enum":["user","environment","external","internal"]},
    \\"summary":{"type":"string"},
    \\"explanation":{"type":"string","description":"the long text, hard-wrapped, with newlines"},
    \\"docs":{"type":"string","description":"the page of the code on the project site"}}}
;

const lock_show_schema =
    \\{"$schema":"https://json-schema.org/draft/2020-12/schema",
    \\"$id":"https://zigbox.github.io/zigbox/schema/lock-show/1","version":1,
    \\"title":"zbx lock show --output json",
    \\"description":"stdout: the project's zbx.lock. A failure is a diagnostic on stderr.",
    \\"type":"object","required":["schema","path","images"],
    \\"properties":{"schema":{"const":"zbx.lock/1"},
    \\"path":{"type":"string","description":"the lock file, found as run finds it"},
    \\"images":{"type":"array","description":"the entries, sorted by reference",
    \\"items":{"type":"object","required":["reference","manifest","platform","tree"],
    \\"properties":{"reference":{"type":"string","description":"as it was written"},
    \\"manifest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
    \\"platform":{"enum":["linux/amd64","linux/arm64"]},
    \\"tree":{"type":"string","pattern":"^b3:[0-9a-f]{64}$"}}}}}}
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
    .{ .command = "pull", .text = pull_schema },
    .{ .command = "explain", .text = explain_schema },
    .{ .command = "lock-show", .text = lock_show_schema },
};

/// The schema of a command's output, or null if it has none.
pub fn of(command: []const u8) ?[]const u8 {
    assert(command.len <= 4096);
    assert(table.len == 19);
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
    try testing.expect(of("lock") == null);
    try testing.expect(of("") == null);
    try testing.expectEqual(@as(usize, 19), table.len);
}

test "run and doctor are one object schema without a $ref, as an agent can follow it" {
    // Goal: M5's agent test, finding 6. Method: the text has no `$ref`; the top level is an
    // object schema whose `oneOf` alternatives are lists of required members (the form the
    // agent's checker follows); every member they require is listed under `properties`; and the
    // members M6 added to the documents are there, with the flags of a fix.
    for ([_][]const u8{ "run", "doctor" }) |command| {
        const text = of(command).?;
        try testing.expect(std.mem.indexOf(u8, text, "\"$ref\"") == null);
        var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, text, .{});
        defer parsed.deinit();
        const root = parsed.value.object;
        try testing.expectEqualStrings("object", root.get("type").?.string);
        const properties = root.get("properties").?.object;
        for (root.get("oneOf").?.array.items) |alternative| {
            try testing.expectEqual(@as(u32, 1), alternative.object.count());
            for (alternative.object.get("required").?.array.items) |name| {
                try testing.expect(properties.get(name.string) != null);
            }
        }
        const fixes = properties.get("fixes").?.object.get("items").?.object;
        const flags = fixes.get("properties").?.object;
        try testing.expect(flags.get("needs_root") != null);
        try testing.expect(flags.get("template") != null);
    }
    const run_text = of("run").?;
    for ([_][]const u8{ "\"hint\"", "network_none", "\"env\"", "\"detached\"" }) |part| {
        try testing.expect(std.mem.indexOf(u8, run_text, part) != null);
    }
    const doctor_text = of("doctor").?;
    for ([_][]const u8{ "zbx.doctor/1", "\"checks\"", "\"diagnostic\"", "ZBX-[EW]" }) |part| {
        try testing.expect(std.mem.indexOf(u8, doctor_text, part) != null);
    }
    const ps_text = of("ps").?;
    for ([_][]const u8{ "\"network\"", "\"published\"", "\"env\"" }) |part| {
        try testing.expect(std.mem.indexOf(u8, ps_text, part) != null);
    }
}
