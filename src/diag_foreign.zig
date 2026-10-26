//! Tests for a second product's diagnostics (docs/DECISIONS.md, "Zigcube's diagnostic codes plug
//! into Zigbox's diagnostics"): a made-up product, "ZC-", rendered by the same renderer as
//! Zigbox's own. The made-up `Product` is defined here and nowhere else: Zigbox never ships
//! another product's strings. The snapshots are in src/testdata/diag_foreign/, named
//! NAME.txt, NAME.verbose.txt and NAME.json.txt like the goldens of src/diag_golden.zig.
//!
//! Changing how a foreign diagnostic looks means updating the snapshot in the same commit.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const codes = @import("diag/codes.zig");
const diag_mod = @import("diag/diag.zig");
const diagnostic_mod = @import("diag/diagnostic.zig");
const product_mod = @import("diag/product.zig");
const render = @import("diag/render.zig");

const Diag = diag_mod.Diag;
const Diagnostic = diagnostic_mod.Diagnostic;
const Product = product_mod.Product;

const testing = std.testing;

const zcube: Product = .{
    .prefix = "ZC-",
    .command = "zcube",
    .bundle_hint = "zcube bundle --last",
    .report_url = "https://example.invalid/zigcube/issues/new",
    .docs_url_base = "https://example.invalid/zigcube/errors/",
};

/// What a product's `from_diag` does: its collector's content under its own code. The content is
/// built with Zigbox's collector, which is all this repository has, then the code, severity,
/// blame and summary are the foreign registry's.
fn foreign(out: *Diagnostic, code: []const u8, severity: codes.Severity, summary: []const u8) void {
    var collector: Diag = undefined;
    collector.reset();
    collector.raise(.E0001);
    collector.while_("placing web-1 on node n2", .{});
    collector.while_("asking the agent to start it", .{});
    collector.cause("the agent answered 503", .{});
    collector.cause("the node has no free memory for a 512 MiB limit", .{});
    collector.context("node", "{s}", .{"n2"});
    collector.fix(.{
        .sentence = "free memory on the node, or lower the limit:",
        .command = "zcube run --memory 256M web",
    });
    collector.fix(.{ .sentence = "or place it on another node" });
    diagnostic_mod.from_diag(out, &collector);
    out.code = .{};
    out.code.print("{s}", .{code});
    out.severity = severity;
    out.blame = .environment;
    out.summary = .{};
    out.summary.print("{s}", .{summary});
    out.docs = .{};
    if (Product.find(&.{zcube}, code)) |owner| out.set_docs(owner);
    if (severity == .bug) out.saved.print("{s}", .{"/var/lib/zcube/bundles/2026-10-26"});
}

fn check_snapshot(
    comptime name: []const u8,
    diagnostic: *const Diagnostic,
    products: []const Product,
) !void {
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const text = render.render_diagnostic(diagnostic, products, .text, false, &buffer);
    try testing.expectEqualStrings(@embedFile("testdata/diag_foreign/" ++ name ++ ".txt"), text);
    const verbose = render.render_diagnostic(diagnostic, products, .verbose, false, &buffer);
    const verbose_file = @embedFile("testdata/diag_foreign/" ++ name ++ ".verbose.txt");
    try testing.expectEqualStrings(verbose_file, verbose);
    const json = render.render_diagnostic(diagnostic, products, .json, false, &buffer);
    const json_file = @embedFile("testdata/diag_foreign/" ++ name ++ ".json.txt");
    try testing.expectEqualStrings(json_file, json);
}

test "a foreign product's diagnostic renders with its own command and addresses" {
    // Goal: the acceptance test of the second registry. A "ZC-" diagnostic shown with the
    // product that owns it says `zcube explain`, points at its docs, and keeps the anatomy:
    // default, verbose and JSON are the snapshots.
    var diagnostic: Diagnostic = undefined;
    foreign(&diagnostic, "ZC-E0201", .@"error", "no node can place the container");
    try check_snapshot("ZC-E0201", &diagnostic, &.{ Product.zbx, zcube });

    foreign(&diagnostic, "ZC-B0001", .bug, "an internal check failed");
    try check_snapshot("ZC-B0001", &diagnostic, &.{ Product.zbx, zcube });
}

test "a code no known product owns renders without more and docs, and without crashing" {
    // Goal: a diagnostic from a newer version, or from a product this program does not know, is
    // still shown in full: only the lines that need the owner's strings are left out. Method:
    // an error and a bug with the prefix "QX-", in every mode, with and without any products.
    var diagnostic: Diagnostic = undefined;
    foreign(&diagnostic, "QX-E0042", .@"error", "a failure from elsewhere");
    try check_snapshot("QX-E0042", &diagnostic, &.{ Product.zbx, zcube });

    var buffer: [constants.output_bytes_max]u8 = undefined;
    const lists = [_][]const Product{ &.{}, &.{Product.zbx}, &.{zcube} };
    const severities = [_]codes.Severity{ .@"error", .warning, .note, .bug };
    for (lists) |products| {
        for (severities) |severity| {
            foreign(&diagnostic, "QX-E0042", severity, "a failure from elsewhere");
            for ([_]render.Mode{ .text, .verbose, .json }) |mode| {
                const output = render.render_diagnostic(&diagnostic, products, mode, true, &buffer);
                if (mode != .json) {
                    try testing.expect(std.mem.indexOf(u8, output, "more ") == null);
                    try testing.expect(std.mem.indexOf(u8, output, "docs ") == null);
                    try testing.expect(std.mem.indexOf(u8, output, "report") == null);
                }
                try testing.expect(std.mem.indexOf(u8, output, "QX-E0042") != null);
            }
        }
    }
}

test "a Zigbox diagnostic shown by another product still says zbx" {
    // Goal: the point of choosing the product by the code's prefix. For every registered code and
    // every mode, rendering it with the foreign product listed first, and Zigbox's second, is
    // byte for byte what `zbx` itself prints for the collector.
    var collector: Diag = undefined;
    var diagnostic: Diagnostic = undefined;
    var expected: [constants.output_bytes_max]u8 = undefined;
    var actual: [constants.output_bytes_max]u8 = undefined;
    for (codes.registry) |item| {
        collector.reset();
        collector.raise(item.code);
        collector.cause("a cause with \"quotes\"", .{});
        collector.fix(.{ .sentence = "a fix:", .command = "zbx doctor" });
        if (item.severity == .bug) collector.save_bundle("/state/zbx/bundles/x");
        diagnostic_mod.from_diag(&diagnostic, &collector);
        for ([_]render.Mode{ .text, .verbose, .json }) |mode| {
            const before = render.render(&collector, mode, false, &expected);
            const products = [_]Product{ zcube, Product.zbx };
            const after = render.render_diagnostic(&diagnostic, &products, mode, false, &actual);
            try testing.expectEqualStrings(before, after);
        }
    }
}

test "the foreign diagnostic survives the wire and renders the same" {
    // Goal: JSON out and in loses nothing a renderer shows, for a product Zigbox does not know.
    var diagnostic: Diagnostic = undefined;
    foreign(&diagnostic, "ZC-E0201", .@"error", "no node can place the container");
    var json: [constants.output_bytes_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&json);
    try diagnostic_mod.write_json(&writer, &diagnostic);
    var parsed: Diagnostic = undefined;
    try diagnostic_mod.parse_json(&parsed, writer.buffered());
    try testing.expect(diagnostic.equal(&parsed));

    var first: [constants.output_bytes_max]u8 = undefined;
    var second: [constants.output_bytes_max]u8 = undefined;
    const products = [_]Product{ Product.zbx, zcube };
    for ([_]render.Mode{ .text, .verbose, .json }) |mode| {
        const left = render.render_diagnostic(&diagnostic, &products, mode, false, &first);
        const right = render.render_diagnostic(&parsed, &products, mode, false, &second);
        try testing.expectEqualStrings(left, right);
    }
}
