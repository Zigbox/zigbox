//! The agent test of M4 (docs/SPEC.md, "Production readiness"): a scripted agent drives the demo
//! in the guest using only `--output json`, `zbx schema <command>`, `zbx explain --output json`
//! and `zbx lock show --output json`. It never scrapes text and never reads `zbx.lock` as text:
//! every decision is made on a member of a JSON document that `zbx schema` says it may rely on,
//! and every document is checked against that schema first. What the agent has to guess is a
//! finding (docs/demos/m4.md, "The agent test"), not something to work around here.
//!
//! The agent's five steps are the spec's, in its own project directory with its own `zbx.lock`
//! (the store, and so the blobs, are the demo's own):
//!   1. `pull alpine:3.20`: the document has the manifest digest, the tree and the lock's path.
//!   2. `run alpine:3.20`: how it ended is the `container_exit` line, not the program's output,
//!      and the line's `ran` names the image, its manifest and its tree.
//!   3. `pull` of both python images; `store du --by-image` and its ratio.
//!   4. `run python:3.12-slim` prints the number.
//!   5. The lock's tree is read with `lock show` and made wrong (the digest is an opaque string to
//!      replace at the path `lock show` gave): `run` is refused with a diagnostic whose context
//!      holds both trees; the agent reads the entry with `explain --output json`, runs the first
//!      fix's command, and `lock show` has the first tree again.
//! Every assertion is a function of json.zig or m4.zig with unit tests.

const std = @import("std");
const Io = std.Io;
const json = @import("agent_json.zig");
const m4 = @import("checks_m4.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");

const Session = session_mod.Session;
const H = harness;
const za = common.za;
const fail_step = common.fail_step;
const expect_exit = common.expect_exit;
const run_shown = common.run_shown;

const step = "AGENT";
const wrapper_path = "/home/demo/za";

/// The schemas the agent fetches, by the name `zbx schema` takes, and the document each names.
const Wanted = struct { command: []const u8, id: []const u8 };
const wanted_schemas = [_]Wanted{
    .{ .command = "pull", .id = "zbx.pull/1" },
    .{ .command = "store-du", .id = "zbx.store.du/1" },
    .{ .command = "store-ls", .id = "zbx.store.ls/1" },
    .{ .command = "store-verify", .id = "zbx.store.verify/1" },
    .{ .command = "explain", .id = "zbx.explain/1" },
    .{ .command = "lock-show", .id = "zbx.lock/1" },
};

const Schemas = struct {
    pull: []const u8,
    du: []const u8,
    ls: []const u8,
    verify: []const u8,
    explain: []const u8,
    lock: []const u8,
};

pub fn run_agent(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m4: AGENT: the demo again, by JSON only\n", .{});
    const schemas = try fetch_schemas(session, out);
    const alpine = try agent_pull(session, out, schemas.pull, "alpine:3.20");
    try agent_run_alpine(session, out, alpine);
    const old = try agent_pull(session, out, schemas.pull, "python:3.12-slim");
    const new = try agent_pull(session, out, schemas.pull, "python:3.13-slim");
    if (std.mem.eql(u8, old.tree, new.tree)) {
        return fail_step(out, step, "expected two images to be two trees", error.IdentityWrong);
    }
    try agent_dedup(session, out, schemas);
    try agent_run_python(session, out);
    try agent_refusal(session, out, schemas, alpine);
    try timer.lap(out, "agent");
}

/// `zbx schema <command>` for each document the agent reads: valid JSON that names the document.
fn fetch_schemas(session: *Session, out: *Io.Writer) !Schemas {
    const arena = session.scratch_allocator();
    var texts: [wanted_schemas.len][]const u8 = undefined;
    for (wanted_schemas, 0..) |wanted, index| {
        const command = try common.format(session, "{s} schema {s}", .{ za, wanted.command });
        const result = try expect_exit(session, out, step, command, 0);
        json.schema_names(arena, result.streams.stdout, wanted.id) catch |err| {
            return fail_step(out, step, "expected a schema that names its document", err);
        };
        texts[index] = try arena.dupe(u8, result.streams.stdout);
    }
    return .{
        .pull = texts[0],
        .du = texts[1],
        .ls = texts[2],
        .verify = texts[3],
        .explain = texts[4],
        .lock = texts[5],
    };
}

/// Fails the step unless `document` follows `schema`.
fn conforms(
    session: *Session,
    out: *Io.Writer,
    schema: []const u8,
    document: []const u8,
    what: []const u8,
) !void {
    const reason = json.violation(session.scratch_allocator(), schema, document) catch |err| {
        return fail_step(out, step, what, err);
    };
    if (reason) |text| {
        try out.print("demo-m4: {s}: the document breaks its schema: {s}\n", .{ what, text });
        return fail_step(out, step, what, error.SchemaViolated);
    }
}

fn agent_pull(
    session: *Session,
    out: *Io.Writer,
    schema: []const u8,
    reference: []const u8,
) !m4.PullDoc {
    const command = try common.format(session, "{s} --output json pull {s}", .{ za, reference });
    const result = try expect_exit(session, out, step, command, 0);
    try conforms(session, out, schema, result.streams.stdout, "pull");
    const arena = session.scratch_allocator();
    const doc = m4.check_pull_json(arena, result.streams, result.status, reference) catch |err| {
        return fail_step(out, step, "expected the pull as the documented JSON", err);
    };
    if (doc.lock == null) return fail_step(out, step, "expected a lock path", error.FieldWrong);
    return doc;
}

fn agent_run_alpine(session: *Session, out: *Io.Writer, alpine: m4.PullDoc) !void {
    const command = za ++ " --output json run alpine:3.20 -- cat /etc/os-release";
    const result = try expect_exit(session, out, step, command, 0);
    const arena = session.scratch_allocator();
    json.check_exited(arena, result.streams, result.status, 0) catch |err| {
        return fail_step(out, step, "expected container_exit exited 0", err);
    };
    const reference = "alpine:3.20";
    const stderr = result.streams.stderr;
    const manifest = alpine.manifest_digest;
    json.check_ran_image(arena, stderr, reference, manifest, alpine.tree) catch |err| {
        return fail_step(out, step, "expected the run to say which image, manifest and tree", err);
    };
    m4.check_output_has(result.streams, result.status, "ID=alpine") catch |err| {
        return fail_step(out, step, "expected the program's own output", err);
    };
}

fn agent_dedup(session: *Session, out: *Io.Writer, schemas: Schemas) !void {
    const arena = session.scratch_allocator();
    const du = try expect_exit(session, out, step, za ++ " --output json store du --by-image", 0);
    try conforms(session, out, schemas.du, du.streams.stdout, "store du --by-image");
    const old = "python:3.12-slim";
    const checked = m4.check_dedup(arena, du.streams, du.status, old, "python:3.13-slim");
    const facts = checked catch |err| {
        return fail_step(out, step, "expected the second image to cost a share of its size", err);
    };
    try out.print("demo-m4: AGENT: python:3.13-slim costs {d} bytes of its {d} compressed\n", .{
        facts.unique_bytes, facts.compressed_bytes,
    });
}

fn agent_run_python(session: *Session, out: *Io.Writer) !void {
    const command = za ++ " --output json run python:3.12-slim -- python -c 'print(2**100)'";
    const result = try expect_exit(session, out, step, command, 0);
    json.check_exited(session.scratch_allocator(), result.streams, result.status, 0) catch |err| {
        return fail_step(out, step, "expected container_exit exited 0", err);
    };
    const number = "1267650600228229401496703205376";
    m4.check_output_is(result.streams, result.status, number) catch |err| {
        return fail_step(out, step, "expected 2**100", err);
    };
}

/// The wrong tree: the first digits of the real one replaced. Returns the text in the arena.
fn wrong_tree(session: *Session, tree: []const u8) ![]const u8 {
    const wrong = "b3:00000000";
    return common.format(session, "{s}{s}", .{ wrong, tree[wrong.len..] });
}

/// `lock show --output json`: the document follows its schema, and has the entry of `alpine:3.20`.
fn agent_lock_show(session: *Session, out: *Io.Writer, schemas: Schemas) !json.LockShown {
    const shown = try expect_exit(session, out, step, za ++ " --output json lock show", 0);
    try conforms(session, out, schemas.lock, shown.streams.stdout, "lock show");
    const arena = session.scratch_allocator();
    return json.check_lock_show(arena, shown.streams, shown.status, "alpine:3.20") catch |err| {
        return fail_step(out, step, "expected lock show to have the entry of alpine:3.20", err);
    };
}

/// The lock names what the pull reported: the same file, manifest, platform and tree.
fn agent_lock_agrees(out: *Io.Writer, locked: json.LockShown, alpine: m4.PullDoc) !void {
    const entry = locked.entry;
    const path = alpine.lock.?.path;
    if (!std.mem.eql(u8, locked.path, path)) {
        return fail_step(out, step, "expected lock show to name the pull's lock", error.LockWrong);
    }
    if (!std.mem.eql(u8, entry.manifest, alpine.manifest_digest) or
        !std.mem.eql(u8, entry.tree, alpine.tree) or
        !std.mem.eql(u8, entry.platform, alpine.platform))
    {
        return fail_step(out, step, "expected lock show to agree with the pull", error.LockWrong);
    }
}

/// Step 5: the lock read with `lock show`, the refusal read from its members, the entry read
/// with `explain --output json`, the fix run, and the lock read again.
fn agent_refusal(
    session: *Session,
    out: *Io.Writer,
    schemas: Schemas,
    alpine: m4.PullDoc,
) !void {
    const arena = session.scratch_allocator();
    const locked = try agent_lock_show(session, out, schemas);
    try agent_lock_agrees(out, locked, alpine);
    const wrong = try wrong_tree(session, locked.entry.tree);
    const edit = try common.format(
        session,
        "runuser -u demo -- sed -i 's/{s}/{s}/' {s}",
        .{ locked.entry.tree, wrong, locked.path },
    );
    const edited = try session.run(edit, limits.command_timeout_kvm_s);
    if (edited.status != 0) return fail_step(out, step, "editing the lock", error.LockNotEdited);
    const refused = try run_shown(session, out, za ++ " --output json run alpine:3.20 -- true");
    const code = "ZBX-E0519";
    const streams = refused.streams;
    const checked = json.check_refusal(arena, streams, refused.status, code, wrong, alpine.tree);
    const found = checked catch |err| {
        return fail_step(out, step, "expected E0519 with both trees in its context", err);
    };
    const explain = try common.format(
        session,
        "{s} --output json explain {s}",
        .{ za, found.code[4..] },
    );
    const explained = try expect_exit(session, out, step, explain, 0);
    try conforms(session, out, schemas.explain, explained.streams.stdout, "explain");
    json.check_explain(arena, explained.streams, explained.status, found) catch |err| {
        return fail_step(out, step, "expected explain to carry the diagnostic's members", err);
    };
    var buffer: [limits.command_bytes_max]u8 = undefined;
    const fix = json.fix_command(&buffer, wrapper_path, found.fixes[0].command.?) catch |err| {
        return fail_step(out, step, "expected a fix command to run", err);
    };
    const as_demo = try common.format(session, "{s}{s}", .{ H.as_demo, fix });
    const fixed = try expect_exit(session, out, step, as_demo, 0);
    try conforms(session, out, schemas.pull, fixed.streams.stdout, "the fix's pull");
    const tag = "alpine:3.20";
    const repaired = m4.check_pull_json(arena, fixed.streams, fixed.status, tag) catch |err| {
        return fail_step(out, step, "expected the fix to pull the image as JSON", err);
    };
    if (!std.mem.eql(u8, repaired.tree, alpine.tree)) {
        return fail_step(out, step, "expected the fix to give the same tree", error.IdentityWrong);
    }
    const restored = try agent_lock_show(session, out, schemas);
    try agent_lock_agrees(out, restored, alpine);
    try agent_after_fix(session, out, schemas);
}

fn agent_after_fix(session: *Session, out: *Io.Writer, schemas: Schemas) !void {
    const arena = session.scratch_allocator();
    const quiet = za ++ " --output json run alpine:3.20 -- true";
    const again = try expect_exit(session, out, step, quiet, 0);
    json.check_exited(arena, again.streams, again.status, 0) catch |err| {
        return fail_step(out, step, "expected the run to work after the fix", err);
    };
    const verify = try expect_exit(session, out, step, za ++ " --output json store verify", 0);
    try conforms(session, out, schemas.verify, verify.streams.stdout, "store verify");
    m4.check_verify_ok(arena, verify.streams, verify.status, 1) catch |err| {
        return fail_step(out, step, "expected a store with no damage", err);
    };
    const listed = try expect_exit(session, out, step, za ++ " --output json store ls", 0);
    try conforms(session, out, schemas.ls, listed.streams.stdout, "store ls");
}
