//! `zbx policy check [OPERAND]` (docs/briefs/M8-trust.md, "The policy file"): prints the verdict
//! `zbx run` would reach, with every policy file read, each rule it sets, each signature of the
//! subject's tree and why it counts or not. It runs nothing and writes nothing.
//!
//! It asks the same question as the run gate: `gate.load` reads the files, `gate.read_record`
//! reads the tree's signatures and `verdict.judge` judges each file, so the policy part of the
//! preview cannot drift from the gate. It does not run the tamper check (`trust/tamper.zig`):
//! a run that would start can still be refused with E0907 for a damaged file, and the output
//! says so. Without an operand it only describes the files. The exit code is 0
//! when the run would start (or no operand was given) and 1 when a policy would refuse it; an
//! unreadable policy file is E0904, as for a run.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const Diag = @import("../diag/diag.zig").Diag;
const errors = @import("../diag/errors.zig");
const json = @import("../bundle.zig");
const diagnose = @import("diagnose.zig");
const fs_mod = @import("../store/fs.zig");
const gate = @import("gate.zig");
const key = @import("key.zig");
const policy_mod = @import("policy.zig");
const record_mod = @import("record.zig");
const verdict = @import("verdict.zig");

const Host = host_mod.Host;

pub const Error = error{Failed};

pub const Output = struct {
    json: bool,
};

/// What one file said of the subject.
const Judged = enum {
    /// The file asks nothing of a run.
    asks_nothing,
    met,
    /// No trusted signature covers the subject: `run` says ZBX-E0905.
    refused,
    /// A trusted signature covers it, but `require_provenance` finds no signed provenance:
    /// `run` says ZBX-E0906.
    refused_provenance,
};

/// Reads the policy files and judges `subject` (null: only describe the files) against each.
/// `memory`, `record` and `work` are the caller's, the same as the gate's.
pub fn run(
    host: Host,
    memory: *gate.Memory,
    record: *record_mod.Record,
    work: *record_mod.Work,
    subject: ?gate.Subject,
    output: Output,
    diag: *Diag,
) Error!u8 {
    assert(diag.code == null);
    gate.load(host, memory, diag) catch return error.Failed;
    record.clear();
    if (subject) |found| {
        const wanted = found.tree != null and gate.any_checks(memory);
        if (wanted) gate.read_record(host, work, found.tree.?, record, diag) catch {
            return error.Failed;
        };
    }
    var allowed = true;
    // What the first refusing file said: the gate stops at the first, so the code is its.
    var first_refusal: Judged = .met;
    var out: Printer = .{ .host = host, .output = output, .diag = diag };
    try out.begin(subject, memory);
    for (memory.files[0..memory.count], 0..) |*loaded, index| {
        var report: verdict.Report = undefined;
        report.clear();
        const judged = judge_one(loaded, record, work, subject, &report);
        if (judged == .refused or judged == .refused_provenance) {
            if (allowed) first_refusal = judged;
            allowed = false;
        }
        try out.file(loaded, judged, &report, index > 0);
    }
    try out.end(memory, subject, first_refusal);
    return if (allowed) constants.exit_ok else 1;
}

fn judge_one(
    loaded: *const gate.Loaded,
    record: *const record_mod.Record,
    work: *record_mod.Work,
    subject: ?gate.Subject,
    report: *verdict.Report,
) Judged {
    const asked = subject orelse return .asks_nothing;
    if (!loaded.policy.checks()) return .asks_nothing;
    const tree = asked.tree orelse return .refused;
    const have: verdict.Subject = .{
        .tree = tree.bytes,
        .binding = asked.binding,
        .derived = asked.derived,
    };
    // The gate's own rule: a signature is not enough when the policy asks for provenance too.
    if (!verdict.judge(&work.envelope, &loaded.policy, record, have, report)) return .refused;
    if (!verdict.provenance_met(&loaded.policy, report)) return .refused_provenance;
    return .met;
}

const Printer = struct {
    host: Host,
    output: Output,
    diag: *Diag,

    fn put(printer: *const Printer, text: []const u8) Error!void {
        assert(text.len <= constants.output_bytes_max);
        printer.host.write_all(.stdout, text) catch |err| {
            errors.output_failed(printer.diag, .stdout, err, printer.host.last_errno());
            return error.Failed;
        };
    }

    fn begin(
        printer: *const Printer,
        subject: ?gate.Subject,
        memory: *const gate.Memory,
    ) Error!void {
        _ = memory;
        if (!printer.output.json) return;
        var buffer: [constants.output_bytes_max]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        writer.writeAll("{\"schema\":\"zbx.policy/1\",\"subject\":") catch unreachable; // Fits.
        if (subject) |found| {
            write_subject_json(&writer, &found);
        } else {
            writer.writeAll("null") catch unreachable; // Fits.
        }
        writer.writeAll(",\"files\":[") catch unreachable; // Fits.
        try printer.put(writer.buffered());
    }

    fn file(
        printer: *const Printer,
        loaded: *const gate.Loaded,
        judged: Judged,
        report: *const verdict.Report,
        later: bool,
    ) Error!void {
        var buffer: [constants.output_bytes_max]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        if (printer.output.json) {
            if (later) writer.writeAll(",") catch unreachable; // Fits.
            write_file_json(&writer, loaded, judged, report);
        } else {
            write_file_text(&writer, loaded, judged, report);
        }
        try printer.put(writer.buffered());
    }

    fn end(
        printer: *const Printer,
        memory: *const gate.Memory,
        subject: ?gate.Subject,
        refusal: Judged,
    ) Error!void {
        assert(refusal != .asks_nothing);
        const allowed = refusal == .met;
        var buffer: [constants.output_bytes_max]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        if (printer.output.json) {
            writer.print("],\"allowed\":{}}}\n", .{allowed}) catch unreachable; // Fits.
        } else {
            write_end_text(&writer, memory, printer.host, subject, refusal);
        }
        try printer.put(writer.buffered());
    }
};

fn binding_word(binding: @import("statement.zig").Binding) []const u8 {
    return switch (binding) {
        .none => "none",
        .result => "result",
        .manifest => "manifest",
    };
}

fn write_subject_json(writer: *std.Io.Writer, subject: *const gate.Subject) void {
    writer.writeAll("{\"operand\":") catch unreachable; // Fits.
    json.write_json_string(writer, subject.text) catch unreachable; // Fits.
    if (subject.tree) |tree| {
        const text = tree.text();
        writer.print(",\"tree\":\"{s}\"", .{&text}) catch unreachable; // Fits.
    } else {
        writer.writeAll(",\"tree\":null") catch unreachable; // Fits.
    }
    const word = binding_word(subject.binding);
    writer.print(",\"binding\":\"{s}\"}}", .{word}) catch unreachable; // Fits.
}

fn reason_word(reason: verdict.Reason) []const u8 {
    return @tagName(reason);
}

fn write_file_json(
    writer: *std.Io.Writer,
    loaded: *const gate.Loaded,
    judged: Judged,
    report: *const verdict.Report,
) void {
    const policy = &loaded.policy;
    writer.writeAll("{\"path\":") catch unreachable; // Fits.
    json.write_json_string(writer, loaded.path.text()) catch unreachable; // Fits.
    writer.print(",\"require_signature\":{},\"require_provenance\":{},\"verify\":\"{s}\"", .{
        policy.require_signature, policy.require_provenance, @tagName(policy.verify),
    }) catch unreachable; // Fits.
    writer.writeAll(",\"keys\":[") catch unreachable; // Fits.
    for (policy.keys[0..policy.key_count], 0..) |*listed, index| {
        if (index > 0) writer.writeAll(",") catch unreachable; // Fits.
        const public = key.public_text(listed.public);
        writer.writeAll("{\"name\":") catch unreachable; // Fits.
        json.write_json_string(writer, listed.name_text()) catch unreachable; // Fits.
        writer.print(",\"public\":\"{s}\"}}", .{&public}) catch unreachable; // Fits.
    }
    writer.writeAll("],\"met\":") catch unreachable; // Fits.
    switch (judged) {
        .asks_nothing => writer.writeAll("null") catch unreachable, // Fits.
        .met => writer.writeAll("true") catch unreachable, // Fits.
        .refused, .refused_provenance => writer.writeAll("false") catch unreachable, // Fits.
    }
    // Why not, when not: the code `run` would give, and the rule behind it.
    switch (judged) {
        .refused => writer.writeAll(",\"code\":\"ZBX-E0905\",\"refusal\":\"unsigned\"") catch
            unreachable, // Fits.
        .refused_provenance => writer.writeAll(
            ",\"code\":\"ZBX-E0906\",\"refusal\":\"provenance\"",
        ) catch unreachable, // Fits.
        .asks_nothing, .met => writer.writeAll(",\"code\":null,\"refusal\":null") catch
            unreachable, // Fits.
    }
    writer.writeAll(",\"signatures\":[") catch unreachable; // Fits.
    for (report.lines[0..report.count], 0..) |line, index| {
        if (index > 0) writer.writeAll(",") catch unreachable; // Fits.
        const public = key.public_text(line.public);
        const listed = policy.trusted(&line.public);
        writer.print("{{\"public\":\"{s}\",\"key\":", .{&public}) catch unreachable; // Fits.
        if (listed) |found| {
            json.write_json_string(writer, found.name_text()) catch unreachable; // Fits.
        } else {
            writer.writeAll("null") catch unreachable; // Fits.
        }
        const why = reason_word(line.reason);
        writer.print(",\"reason\":\"{s}\"}}", .{why}) catch unreachable; // Fits.
    }
    writer.writeAll("]}") catch unreachable; // Fits.
}

fn write_file_text(
    writer: *std.Io.Writer,
    loaded: *const gate.Loaded,
    judged: Judged,
    report: *const verdict.Report,
) void {
    const policy = &loaded.policy;
    writer.print("policy {s}\n", .{loaded.path.text()}) catch unreachable; // Fits.
    writer.print("  require_signature: {s}\n  require_provenance: {s}\n  verify: {s}\n", .{
        yes_no(policy.require_signature),
        yes_no(policy.require_provenance),
        @tagName(policy.verify),
    }) catch unreachable; // Fits.
    for (policy.keys[0..policy.key_count]) |*listed| {
        const public = key.public_text(listed.public);
        writer.print("  key {s}: {s}\n", .{ listed.name_text(), &public }) catch
            unreachable; // Fits.
    }
    for (report.lines[0..report.count]) |line| {
        const public = key.public_text(line.public);
        const prefix_bytes = key.public_prefix.len + 16;
        const listed = policy.trusted(&line.public);
        const name: []const u8 = if (listed) |found| found.name_text() else public[0..prefix_bytes];
        writer.print("  signed by {s}: {s}\n", .{ name, diagnose.reason_text(line.reason) }) catch
            unreachable; // Fits.
    }
    const word = switch (judged) {
        .asks_nothing => "asks nothing of a run",
        .met => "met",
        .refused => "not met: no trusted signature covers it (ZBX-E0905)",
        .refused_provenance => "not met: signed, but no trusted signed provenance covers it " ++
            "(ZBX-E0906)",
    };
    writer.print("  verdict: {s}\n", .{word}) catch unreachable; // Fits.
}

fn write_end_text(
    writer: *std.Io.Writer,
    memory: *const gate.Memory,
    host: Host,
    subject: ?gate.Subject,
    refusal: Judged,
) void {
    const allowed = refusal == .met;
    if (memory.count == 0) {
        var user: fs_mod.PathBuf = undefined;
        const looked = if (gate.user_path(host, &user)) user.text() else "(no home)";
        writer.print("no policy file ({s}, {s}): nothing is checked\n", .{
            constants.policy_system_path, looked,
        }) catch unreachable; // Fits.
    }
    const asked = subject orelse return;
    const verb = if (allowed) "would start" else if (refusal == .refused_provenance)
        "would be refused (ZBX-E0906)"
    else
        "would be refused (ZBX-E0905)";
    const what = if (asked.text.len > 0) asked.text else "a directory";
    writer.print("run of {s}: {s}\n", .{ what, verb }) catch unreachable; // Fits.
    if (allowed and memory.count > 0) {
        writer.writeAll("file integrity is not checked here: the run still refuses " ++
            "damaged files (ZBX-E0907)\n") catch unreachable; // Fits.
    }
}

fn yes_no(value: bool) []const u8 {
    return if (value) "yes" else "no";
}

comptime {
    // One file's block is at most: 16 keys, 8 signatures, and a few lines of settings.
    const file_bytes = constants.policy_keys_max * (constants.key_name_bytes_max +
        constants.key_public_text_bytes + 32) +
        constants.signatures_per_tree_max * (constants.key_public_text_bytes + 96) + 512;
    assert(file_bytes < constants.output_bytes_max);
}
