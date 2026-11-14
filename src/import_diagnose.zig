//! The diagnostics of `zbx import` (docs/briefs/M9-dockerfile-import.md, "Diagnostics"): the
//! translator's refusals (`dockerfile/refusal.zig`) as diagnostics, the command line's own
//! refusals, and the two warnings that close a report.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const text_util = @import("text.zig");
const refusal_mod = @import("dockerfile/refusal.zig");
const errors = @import("diag/errors.zig");
const fs_mod = @import("store/fs.zig");
const Diag = @import("diag/diag.zig").Diag;
const codes = @import("diag/codes.zig");

const Echo = [constants.arg_echo_bytes_max]u8;

fn code_of(code: refusal_mod.Code) codes.Code {
    return switch (code) {
        .E0810 => .E0810,
        .E0811 => .E0811,
        .E0812 => .E0812,
        .E0813 => .E0813,
        .E0814 => .E0814,
        .E0815 => .E0815,
        .E0816 => .E0816,
    };
}

/// A refusal of the translator: what was refused, at which line of `dockerfile`, and what to
/// write instead. The sentences are sanitised into buffers as large as the refusal's own, so
/// nothing is cut here; the diagnostic's field bound is the only cut.
pub fn refused(diag: *Diag, refusal: *const refusal_mod.Refusal, dockerfile: []const u8) void {
    assert(diag.code == null);
    assert(dockerfile.len > 0);
    var name_echo: Echo = undefined;
    var what_echo: [refusal_mod.what_bytes_max]u8 = undefined;
    const name = text_util.sanitise(&name_echo, dockerfile);
    const what = text_util.sanitise(&what_echo, refusal.what_text());
    assert(what.len == refusal.what_len);
    diag.raise(code_of(refusal.code));
    diag.while_("importing {s}", .{name});
    // Most sentences open with their own location, `Dockerfile:<line> ...`: that is printed
    // once, with the file's name as the user gave it.
    const located = "Dockerfile:";
    if (std.mem.startsWith(u8, what, located)) {
        diag.cause("{s}:{s}", .{ name, what[located.len..] });
    } else if (refusal.line > 0) {
        diag.cause("{s}:{d}: {s}", .{ name, refusal.line, what });
    } else {
        diag.cause("{s}: {s}", .{ name, what });
    }
    if (refusal.line > 0) diag.context("line", "{d}", .{refusal.line});
    var fix_echo: [refusal_mod.fix_bytes_max]u8 = undefined;
    const fix = text_util.sanitise(&fix_echo, refusal.fix_text());
    assert(fix.len == refusal.fix_len);
    diag.fix(.{ .sentence = fix });
    assert(diag.code != null);
}

/// Why the Dockerfile could not be read (`E0810`).
pub const ReadFailure = enum { missing, not_file, too_large, unreadable, bad_path };

/// `E0810`: the Dockerfile (or its `.dockerignore`) cannot be read.
pub fn read_failed(diag: *Diag, path: []const u8, failure: ReadFailure) void {
    assert(diag.code == null);
    if (path.len == 0) assert(failure == .bad_path);
    var echo: Echo = undefined;
    const shown = text_util.sanitise(&echo, path);
    diag.raise(.E0810);
    diag.while_("reading the Dockerfile", .{});
    if (path.len == 0) {
        diag.cause("the Dockerfile's name is empty", .{});
        diag.fix(.{ .sentence = "name the Dockerfile:", .command = "zbx import Dockerfile" });
        return;
    }
    const why = switch (failure) {
        .missing => "is not there",
        .not_file => "is not a regular file",
        .too_large => "is larger than an import reads",
        .unreadable => "cannot be read",
        .bad_path => "is not a path zbx can follow",
    };
    if (failure == .too_large) {
        diag.cause("'{s}' {s} ({d} bytes)", .{ shown, why, constants.import_dockerfile_bytes_max });
    } else diag.cause("'{s}' {s}", .{ shown, why });
    diag.context("path", "{s}", .{shown});
    diag.fix(.{
        .sentence = "name the Dockerfile, or run zbx import in its directory:",
        .command = "zbx import docker/app.Dockerfile --context .",
        .template = true,
    });
    assert(diag.code.? == .E0810);
}

/// `E0816`: the output already exists, and `--force` was not given.
pub fn output_exists(diag: *Diag, path: []const u8) void {
    assert(diag.code == null);
    assert(path.len > 0);
    var echo: Echo = undefined;
    const shown = text_util.sanitise(&echo, path);
    diag.raise(.E0816);
    diag.while_("writing the build file", .{});
    diag.cause("'{s}' exists, and an import never replaces a file unasked", .{shown});
    diag.context("path", "{s}", .{shown});
    diag.fix(.{
        .sentence = "replace it with --force, or write elsewhere with -o:",
        .command = "zbx import -o imported.build.zon",
        .template = true,
    });
    assert(diag.code.? == .E0816);
}

/// `E0816`: the output could not be written; nothing was left in its place.
pub fn output_failed(diag: *Diag, path: []const u8, failure: *const fs_mod.Failure) void {
    assert(diag.code == null);
    assert(path.len > 0);
    var echo: Echo = undefined;
    const shown = text_util.sanitise(&echo, path);
    diag.raise(.E0816);
    diag.while_("writing the build file", .{});
    errors.cause_host_error(diag, "writing the build file", failure.err, failure.errno);
    diag.context("path", "{s}", .{shown});
    diag.fix(.{ .sentence = "make the directory writable, or write elsewhere with -o" });
    assert(diag.code.? == .E0816);
}

pub const flagged_label = "steps not hermetic: ";
pub const dropped_label = "not carried over: ";

/// `W0810`: the import has steps with the network or a cache. `names` is the steps, each with
/// why, joined by `, `; `count` how many.
pub fn not_hermetic(diag: *Diag, names: []const u8, count: u32) void {
    assert(diag.code == null);
    assert(count > 0);
    assert(names.len > 0);
    diag.raise(.W0810);
    diag.while_("importing the Dockerfile", .{});
    diag.cause("their output can depend on the network or a cache, not only on the inputs", .{});
    diag.cause(flagged_label ++ "{s}", .{names});
    diag.context("steps", "{d}", .{count});
    diag.fix(.{
        .sentence = "pin what each step fetches; zbx import --hermetic refuses such steps",
    });
    assert(diag.code.? == .W0810);
}

/// `W0811`: parts of the Dockerfile became labels or were ignored. `what` is the parts, joined
/// by `, `; `count` how many.
pub fn dropped(diag: *Diag, what: []const u8, count: u32) void {
    assert(diag.code == null);
    assert(count > 0);
    assert(what.len > 0);
    diag.raise(.W0811);
    diag.while_("importing the Dockerfile", .{});
    diag.cause(dropped_label ++ "{s}", .{what});
    diag.context("count", "{d}", .{count});
    diag.fix(.{
        .sentence = "nothing to do unless one matters; the report says what became of each",
    });
    assert(diag.code.? == .W0811);
}
