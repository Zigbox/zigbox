//! Renders a `Diagnostic` (or a `Diag`, through it) for people and for scripts (DIAGNOSTICS.md,
//! "Anatomy" and "Output modes"). Pure: a diagnostic goes in, bytes come out, into a caller's
//! buffer. This is the only place that decides how a diagnostic looks, and it is called only
//! from the CLI boundary.
//!
//!   text     summary, the newest cause, the fixes, and a `more` line
//!   verbose  plus the `while` lines, the whole cause chain and the context pairs
//!   json     one object on one line with every field, for `--output json`
//!
//! A `bug` has its own anatomy: it says the fault is ours and where to report it, and shows
//! the internal message only in verbose and json.
//!
//! Colour is an option and never changes the words: stripping the escape sequences from a
//! coloured rendering gives the plain one byte for byte (a test checks that).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const codes = @import("codes.zig");
const diag_mod = @import("diag.zig");
const diagnostic_mod = @import("diagnostic.zig");
const product_mod = @import("product.zig");

const Diag = diag_mod.Diag;
const Diagnostic = diagnostic_mod.Diagnostic;
const Product = product_mod.Product;

pub const Mode = enum { text, verbose, json };

pub const report_url = Product.zbx.report_url;

const color_bold = "\x1b[1m";
const color_reset = "\x1b[0m";

/// Renders `diag` into `buffer` and returns the used prefix. `buffer` must be
/// `constants.output_bytes_max` bytes: the comptime check in constants.zig proves a maximal
/// diagnostic fits it, so a write cannot fail. A `Diag` is Zigbox's, so it renders as a
/// `Diagnostic` of the one product `Product.zbx`.
pub fn render(diag: *const Diag, mode: Mode, color: bool, buffer: []u8) []const u8 {
    assert(buffer.len >= constants.output_bytes_max);
    assert(diag.code != null);
    var diagnostic: Diagnostic = undefined;
    diagnostic_mod.from_diag(&diagnostic, diag);
    return render_diagnostic(&diagnostic, &.{Product.zbx}, mode, color, buffer);
}

/// Renders `diagnostic` into `buffer` and returns the used prefix; same buffer rule as `render`.
/// The product whose strings it uses (the command in `more`, the report address of a bug, the
/// docs page) is the one `Product.find` picks from `products` by the code's own prefix, not the
/// program's: `zcube why` showing a "ZBX-" diagnostic says `zbx explain`. A code that no product
/// owns gets neither a `more` nor a `docs` line (nor a report address), and nothing else changes.
/// JSON mode writes the diagnostic as it is, docs included.
pub fn render_diagnostic(
    diagnostic: *const Diagnostic,
    products: []const Product,
    mode: Mode,
    color: bool,
    buffer: []u8,
) []const u8 {
    assert(buffer.len >= constants.output_bytes_max);
    assert(diagnostic.code.len > 0);
    var writer = std.Io.Writer.fixed(buffer);
    const product = Product.find(products, diagnostic.code.slice());
    switch (mode) {
        // Cannot fail: the buffer holds a maximal diagnostic (the proof in constants.zig).
        .json => diagnostic_mod.write_json(&writer, diagnostic) catch unreachable,
        .text, .verbose => write_text(&writer, diagnostic, product, mode == .verbose, color),
    }
    const output = writer.buffered();
    assert(output.len > 0);
    assert(output[output.len - 1] == '\n');
    return output;
}

// The writer is a fixed buffer that `render` proves holds a maximal diagnostic (the bound is a
// comptime assertion in constants.zig), so a write to it cannot fail. These three helpers are the
// only places that say so.

fn emit(writer: *std.Io.Writer, bytes: []const u8) void {
    assert(writer.buffer.len >= constants.output_bytes_max);
    assert(bytes.len <= constants.output_bytes_max);
    writer.writeAll(bytes) catch unreachable; // Cannot fail: the buffer holds a maximal diagnostic.
}

fn emit_format(writer: *std.Io.Writer, comptime format: []const u8, args: anytype) void {
    assert(writer.buffer.len >= constants.output_bytes_max);
    assert(format.len > 0);
    writer.print(format, args) catch unreachable; // Cannot fail: same bound as `emit`.
}

fn emit_spaces(writer: *std.Io.Writer, count: usize) void {
    assert(count <= constants.diag_field_bytes_max + 3); // Fix padding is the widest.
    assert(writer.buffer.len >= constants.output_bytes_max);
    writer.splatByteAll(' ', count) catch unreachable; // Cannot fail: same bound as `emit`.
}

// ---- Text ----------------------------------------------------------------------------------

fn header_color(severity: codes.Severity) []const u8 {
    const color: []const u8 = switch (severity) {
        .@"error", .bug => "\x1b[1;31m",
        .warning => "\x1b[1;33m",
        .note => "\x1b[1;36m",
    };
    assert(color[0] == 0x1b);
    assert(color[color.len - 1] == 'm');
    return color;
}

fn write_text(
    writer: *std.Io.Writer,
    diagnostic: *const Diagnostic,
    product: ?*const Product,
    verbose: bool,
    color: bool,
) void {
    assert(diagnostic.summary.len > 0);
    if (color) emit(writer, header_color(diagnostic.severity));
    const head = .{
        @tagName(diagnostic.severity), diagnostic.code.slice(), diagnostic.summary.slice(),
    };
    emit_format(writer, "{s}[{s}]: {s}", head);
    if (color) emit(writer, color_reset);
    emit(writer, "\n");

    if (diagnostic.severity == .bug) {
        write_bug_body(writer, diagnostic, product, verbose, color);
    } else {
        write_error_body(writer, diagnostic, verbose, color);
    }
    if (product) |owner| write_more(writer, diagnostic, owner, verbose, color);
}

fn write_error_body(
    writer: *std.Io.Writer,
    diagnostic: *const Diagnostic,
    verbose: bool,
    color: bool,
) void {
    assert(diagnostic.code.len > 0);
    assert(diagnostic.severity != .bug); // A bug has its own body.
    if (verbose) {
        // Outermost first: the list holds them innermost first.
        write_omitted(writer, "while", diagnostic.whiles.omitted, color);
        var index = diagnostic.whiles.count;
        while (index > 0) : (index -= 1) {
            write_wrapped(writer, "while", diagnostic.whiles.items[index - 1].slice(), color);
        }
        write_omitted(writer, "cause", diagnostic.causes.omitted, color);
        for (diagnostic.causes.slice()) |text| write_wrapped(writer, "cause", text.slice(), color);
        for (diagnostic.pairs.slice()) |*pair| {
            write_wrapped(writer, pair.key_slice(), pair.value.slice(), color);
        }
        write_omitted(writer, "extra", diagnostic.pairs.omitted, color);
    } else if (diagnostic.last_cause()) |text| {
        write_wrapped(writer, "cause", text, color);
    }
    write_fixes(writer, diagnostic, verbose, color);
}

/// A bug says whose fault it is and where to report it. Without a product (a code nobody here
/// owns) it cannot name the program or the address, and says only that the fault is not the
/// user's.
fn write_bug_body(
    writer: *std.Io.Writer,
    diagnostic: *const Diagnostic,
    product: ?*const Product,
    verbose: bool,
    color: bool,
) void {
    assert(diagnostic.code.len > 0);
    assert(diagnostic.severity == .bug);
    if (product) |owner| {
        emit_format(writer, "  this is a bug in {s}, not something you did\n", .{owner.command});
    } else {
        emit(writer, "  this is a bug, not something you did\n");
    }
    if (diagnostic.saved.len > 0) {
        var line: [constants.state_path_bytes_max + 160]u8 = undefined;
        const parts = .{diagnostic.saved.slice()};
        // Cannot fail: the saved path is at most state_path_bytes_max + 128 and the label 20.
        const text = std.fmt.bufPrint(&line, "diagnostic bundle: {s}", parts) catch unreachable;
        write_wrapped(writer, "saved", text, color);
    }
    if (verbose) {
        for (diagnostic.whiles.slice()) |text| write_wrapped(writer, "while", text.slice(), color);
        for (diagnostic.causes.slice()) |text| write_wrapped(writer, "cause", text.slice(), color);
    }
    if (product) |owner| write_wrapped(writer, "report", owner.report_url, color);
}

fn write_more(
    writer: *std.Io.Writer,
    diagnostic: *const Diagnostic,
    product: *const Product,
    verbose: bool,
    color: bool,
) void {
    assert(diagnostic.summary.len > 0);
    const rerun = if (diagnostic.severity == .bug)
        " \u{b7} rerun with --verbose for the message"
    else
        " \u{b7} rerun with --verbose for the full cause chain";
    var command: [constants.product_explain_bytes_max]u8 = undefined;
    var line: [128]u8 = undefined;
    const explain = product.explain_command(&command, diagnostic.code.slice());
    const text = std.fmt.bufPrint(&line, "{s}{s}", .{ explain, if (verbose) "" else rerun }) catch
        unreachable; // Fits 128 bytes.
    write_wrapped(writer, "more", text, color);
    // Its own line: the URL does not fit beside the `more` text within 80 columns.
    var url: [constants.docs_url_bytes_max]u8 = undefined;
    write_wrapped(writer, "docs", product.docs_url(&url, diagnostic.code.slice()), color);
}

fn write_label(writer: *std.Io.Writer, label: []const u8, color: bool) void {
    // An empty label is the continuation of a list (the second fix).
    assert(std.mem.indexOfScalar(u8, label, ' ') == null);
    assert(label.len <= constants.diag_label_columns - 3);
    // Two spaces, the label padded to six, one space: the text starts in column nine.
    emit(writer, "  ");
    if (color) emit(writer, color_bold);
    emit(writer, label);
    if (color) emit(writer, color_reset);
    const pad = constants.diag_label_columns - 2 - label.len;
    emit_spaces(writer, pad);
}

/// Writes `  label  text`, breaking the text at spaces so lines stay within the wrap width and
/// continuation lines align under the first. A word longer than a line is never split.
fn write_wrapped(writer: *std.Io.Writer, label: []const u8, text: []const u8, color: bool) void {
    assert(text.len > 0);
    assert(label.len <= constants.diag_label_columns);
    write_label(writer, label, color);
    var column: u32 = constants.diag_label_columns;
    var words = std.mem.tokenizeScalar(u8, text, ' ');
    var first = true;
    // Cannot fail, below: see `write_text`.
    while (words.next()) |word| {
        const length: u32 = @intCast(word.len);
        if (!first) {
            if (column + 1 + length > constants.diag_wrap_columns) {
                emit(writer, "\n");
                emit_spaces(writer, constants.diag_label_columns);
                column = constants.diag_label_columns;
            } else {
                emit(writer, " ");
                column += 1;
            }
        }
        emit(writer, word);
        column += length;
        first = false;
    }
    // Text of only spaces has no words; say so rather than leave a label with nothing.
    if (first) emit(writer, "(blank)");
    emit(writer, "\n");
}

fn write_omitted(writer: *std.Io.Writer, label: []const u8, omitted: u32, color: bool) void {
    assert(label.len > 0);
    if (omitted == 0) return;
    assert(omitted <= std.math.maxInt(u16)); // Counts are small; the note below is short.
    var line: [64]u8 = undefined;
    // Cannot fail: a count and a short phrase fit.
    const text = std.fmt.bufPrint(&line, "({d} more not shown)", .{omitted}) catch unreachable;
    write_wrapped(writer, label, text, color);
}

fn write_fixes(
    writer: *std.Io.Writer,
    diagnostic: *const Diagnostic,
    verbose: bool,
    color: bool,
) void {
    const fixes = diagnostic.fixes.slice();
    assert(fixes.len <= constants.diag_fixes_count_max);
    if (fixes.len == 0) return;
    // Commands line up in one column, after the longest sentence that has a command.
    var sentence_columns: usize = 0;
    for (fixes) |item| {
        if (item.command.len > 0) sentence_columns = @max(sentence_columns, item.sentence.len);
    }
    for (fixes, 0..) |*item, index| {
        write_label(writer, if (index == 0) "fix" else "", color);
        emit(writer, item.sentence.slice());
        if (item.command.len > 0) {
            emit_spaces(writer, sentence_columns - item.sentence.len + 3);
            emit(writer, item.command.slice());
        }
        emit(writer, "\n");
    }
    if (verbose) write_omitted(writer, "fix", diagnostic.fixes.omitted, color);
}

/// Removes ANSI colour sequences (`ESC [ ... m`), for tests that compare coloured and plain.
pub fn strip_colour(output: []u8, input: []const u8) []const u8 {
    assert(output.len >= input.len);
    var length: usize = 0;
    var index: usize = 0;
    while (index < input.len) {
        if (input[index] == 0x1b) {
            const end = std.mem.indexOfScalarPos(u8, input, index, 'm') orelse input.len - 1;
            index = end + 1;
            continue;
        }
        output[length] = input[index];
        length += 1;
        index += 1;
    }
    assert(length <= input.len);
    return output[0..length];
}

/// True if user-facing output shows what it must never show (DIAGNOSTICS.md, "No stack traces
/// for users"): a raw Zig error name (`error.` and an identifier), a source location, an
/// address, or a trace header. Used by the tests and the CLI fuzzer; text that merely echoes
/// the user's own argument is the caller's to exclude.
pub fn contains_raw_error(output: []const u8) bool {
    assert(output.len <= constants.output_bytes_max);
    assert(output.len < std.math.maxInt(u32));
    const markers = [_][]const u8{
        ".zig", "0x", "stack trace", "Stack trace", "panic:", "thread ",
    };
    for (markers) |marker| {
        if (std.mem.indexOf(u8, output, marker) != null) return true;
    }
    var from: usize = 0;
    while (std.mem.indexOfPos(u8, output, from, "error.")) |at| : (from = at + 1) {
        if (at + 6 < output.len) {
            if (std.ascii.isAlphabetic(output[at + 6])) return true;
        }
    }
    return false;
}

const testing = std.testing;
const test_util = @import("../test_util.zig");

test "contains_raw_error finds raw error names and traces and nothing else" {
    // Goal: the detector is not vacuous. Each marker is found; ordinary diagnostic text is not.
    try testing.expect(contains_raw_error("cause  error.AccessDenied"));
    try testing.expect(contains_raw_error("at src/main.zig:12"));
    try testing.expect(contains_raw_error("Stack trace:\n"));
    try testing.expect(contains_raw_error("frame 0x7ffd1234"));
    try testing.expect(contains_raw_error("thread 1 panic: x"));
    try testing.expect(!contains_raw_error("error[ZBX-E0001]: unknown command\n"));
    try testing.expect(!contains_raw_error("an error. Then a sentence"));
    try testing.expect(!contains_raw_error("the error."));
}

fn sample(diag: *Diag) void {
    diag.reset();
    diag.raise(.E0001);
    diag.while_("starting container \"web-1\"", .{});
    diag.while_("setting up namespaces", .{});
    diag.cause("clone3 returned EACCES", .{});
    diag.cause("AppArmor restricts unprivileged user namespaces", .{});
    diag.context("path", "{s}", .{"C:\\x"});
    diag.fix(.{ .sentence = "allow zbx only:", .command = "sudo zbx doctor --fix apparmor" });
    diag.fix(.{ .sentence = "or system-wide:", .command = "sudo sysctl a.b=0" });
    diag.fix(.{ .sentence = "or read the docs" });
}

test "text rendering: the anatomy of the standard, default and verbose" {
    // Goal: the exact shape of both text modes for one rich diagnostic: label column, innermost
    // cause only by default, while lines outermost first, commands aligned, the more line.
    var diag: Diag = undefined;
    sample(&diag);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    try testing.expectEqualStrings(
        "error[ZBX-E0001]: unknown command\n" ++
            "  cause  AppArmor restricts unprivileged user namespaces\n" ++
            "  fix    allow zbx only:   sudo zbx doctor --fix apparmor\n" ++
            "         or system-wide:   sudo sysctl a.b=0\n" ++
            "         or read the docs\n" ++
            "  more   zbx explain E0001 \u{b7} rerun with --verbose for the full cause chain\n" ++
            "  docs   https://zigbox.github.io/zigbox/errors/E0001.html\n",
        render(&diag, .text, false, &buffer),
    );
    try testing.expectEqualStrings(
        "error[ZBX-E0001]: unknown command\n" ++
            "  while  setting up namespaces\n" ++
            "  while  starting container \"web-1\"\n" ++
            "  cause  clone3 returned EACCES\n" ++
            "  cause  AppArmor restricts unprivileged user namespaces\n" ++
            "  path   C:\\x\n" ++
            "  fix    allow zbx only:   sudo zbx doctor --fix apparmor\n" ++
            "         or system-wide:   sudo sysctl a.b=0\n" ++
            "         or read the docs\n" ++
            "  more   zbx explain E0001\n" ++
            "  docs   https://zigbox.github.io/zigbox/errors/E0001.html\n",
        render(&diag, .verbose, false, &buffer),
    );
}

test "text rendering wraps prose at the column bound and never splits a word" {
    // Goal: long causes continue under the first line; a word longer than the line stays whole.
    var diag: Diag = undefined;
    diag.reset();
    diag.raise(.E0001);
    const word = test_util.repeat('w', 90);
    diag.cause("alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi " ++
        "omicron pi rho {s} sigma", .{word});
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const output = render(&diag, .text, false, &buffer);
    var lines = std.mem.splitScalar(u8, output, '\n');
    var saw_word = false;
    while (lines.next()) |line| {
        if (std.mem.indexOf(u8, line, word) != null) saw_word = true;
        if (std.mem.indexOf(u8, line, word) == null) {
            try testing.expect(line.len <= constants.diag_wrap_columns + 2); // The middle dot.
        }
    }
    try testing.expect(saw_word);
    // Continuation lines align under the first line's text, in column nine.
    try testing.expect(std.mem.indexOf(u8, output, "\n         ") != null);
}

test "bug rendering: ours, with the report address; the message only when asked" {
    var diag: Diag = undefined;
    diag.reset();
    diag.raise(.B0001);
    diag.cause("reached unreachable code", .{});
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const plain = render(&diag, .text, false, &buffer);
    const ours = "this is a bug in zbx, not something you did";
    try testing.expect(std.mem.indexOf(u8, plain, ours) != null);
    try testing.expect(std.mem.indexOf(u8, plain, report_url) != null);
    try testing.expect(std.mem.indexOf(u8, plain, "unreachable") == null);
    try testing.expect(std.mem.indexOf(u8, plain, "saved") == null);
    const verbose = render(&diag, .verbose, false, &buffer);
    try testing.expect(std.mem.indexOf(u8, verbose, "cause  reached unreachable code") != null);
}

test "colour adds escapes around the header and labels and nothing else" {
    var diag: Diag = undefined;
    sample(&diag);
    var plain_buffer: [constants.output_bytes_max]u8 = undefined;
    var colour_buffer: [constants.output_bytes_max]u8 = undefined;
    var stripped: [constants.output_bytes_max]u8 = undefined;
    for ([_]Mode{ .text, .verbose }) |mode| {
        const plain = render(&diag, mode, false, &plain_buffer);
        const coloured = render(&diag, mode, true, &colour_buffer);
        try testing.expect(std.mem.indexOfScalar(u8, plain, 0x1b) == null);
        try testing.expect(std.mem.startsWith(u8, coloured, "\x1b[1;31merror[ZBX-E0001]"));
        try testing.expectEqualStrings(plain, strip_colour(&stripped, coloured));
    }
}

test "json rendering: one line, every field, escapes, null for a fix without a command" {
    // Goal: the machine-readable shape. Method: compare the exact line, then validate it with
    // the standard JSON scanner so a quoting mistake cannot hide in a golden file.
    var diag: Diag = undefined;
    sample(&diag);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const output = render(&diag, .json, false, &buffer);
    try testing.expectEqualStrings(
        "{\"code\":\"ZBX-E0001\",\"severity\":\"error\",\"blame\":\"user\"," ++
            "\"summary\":\"unknown command\"," ++
            "\"causes\":[\"clone3 returned EACCES\"," ++
            "\"AppArmor restricts unprivileged user namespaces\"]," ++
            "\"while\":[\"starting container \\\"web-1\\\"\",\"setting up namespaces\"]," ++
            "\"context\":{\"path\":\"C:\\\\x\"}," ++
            "\"fixes\":[{\"sentence\":\"allow zbx only:\"," ++
            "\"command\":\"sudo zbx doctor --fix apparmor\",\"needs_root\":true}," ++
            "{\"sentence\":\"or system-wide:\",\"command\":\"sudo sysctl a.b=0\"," ++
            "\"needs_root\":true}," ++
            "{\"sentence\":\"or read the docs\",\"command\":null}]," ++
            "\"docs\":\"https://zigbox.github.io/zigbox/errors/E0001.html\"," ++
            "\"omitted\":{\"causes\":0,\"while\":0,\"context\":0,\"fixes\":0}}\n",
        output,
    );
    try testing.expect(try test_util.json_is_valid(output[0 .. output.len - 1]));
}
