//! `Product`: the strings of a diagnostic that belong to one product (DIAGNOSTICS.md, "Same
//! model everywhere"). A second product (Zigcube, prefix "ZC-") keeps its own collector and its
//! own registry of codes and declares its own `Product` value; the renderer picks the product by
//! the prefix of the code it is rendering, so a "ZBX-" diagnostic shown by `zcube` still points
//! at `zbx explain`, a command that exists, and not at one `zcube` does not have.
//!
//! This file defines the type and `Product.zbx` only. It never holds another product's strings,
//! so a change to them needs no Zigbox release.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

pub const Product = struct {
    /// Capital letters and a dash, at most `product_prefix_bytes_max`: "ZBX-".
    prefix: []const u8,
    /// The command that explains a code: the `more` line is "<command> explain E0101".
    command: []const u8,
    /// How to collect a bundle, for example "zbx bundle --last". Not placed by the renderer; it
    /// is for the product's own fixes, so the hint stays next to the other strings.
    bundle_hint: []const u8,
    /// Where a bug is reported.
    report_url: []const u8,
    /// Ends in "/"; a code's page is the base plus "<tag>.html".
    docs_url_base: []const u8,

    pub const zbx: Product = .{
        .prefix = "ZBX-",
        .command = "zbx",
        .bundle_hint = "zbx bundle --last",
        .report_url = "https://github.com/Zigbox/zigbox/issues/new",
        .docs_url_base = constants.docs_url_base,
    };

    /// Asserts that the strings are within the bounds the renderer's buffers are proved for.
    /// A `Product` is written by the program that declares it, so a bad one is a programmer
    /// error and not an operating error.
    pub fn validate(product: *const Product) void {
        assert(product.prefix.len >= 2);
        assert(product.prefix.len <= constants.product_prefix_bytes_max);
        assert(product.prefix[product.prefix.len - 1] == '-');
        for (product.prefix[0 .. product.prefix.len - 1]) |byte| assert(std.ascii.isUpper(byte));
        assert(product.command.len > 0);
        assert(product.command.len <= constants.product_command_bytes_max);
        assert(std.mem.indexOfScalar(u8, product.command, ' ') == null);
        assert(product.bundle_hint.len <= constants.product_bundle_hint_bytes_max);
        assert(product.report_url.len > 0);
        assert(product.report_url.len <= constants.product_report_url_bytes_max);
        assert(std.mem.startsWith(u8, product.docs_url_base, "https://"));
        assert(std.mem.endsWith(u8, product.docs_url_base, "/"));
        assert(product.docs_url_base.len <= constants.product_docs_base_bytes_max);
    }

    /// The product whose prefix starts `code_text`, or null: a code from a newer version, or
    /// from a product the caller does not know. A prefix ends in a dash and holds no other, so
    /// at most one product can match.
    pub fn find(products: []const Product, code_text: []const u8) ?*const Product {
        assert(products.len <= constants.products_count_max);
        assert(code_text.len <= constants.diag_code_bytes);
        for (products) |*product| {
            product.validate();
            if (std.mem.startsWith(u8, code_text, product.prefix)) return product;
        }
        return null;
    }

    /// The code without the product's prefix, as typed to its `explain`: "E0501".
    pub fn tag_of(product: *const Product, code_text: []const u8) []const u8 {
        assert(std.mem.startsWith(u8, code_text, product.prefix));
        const tag = code_text[product.prefix.len..];
        assert(tag.len > 0);
        return tag;
    }

    /// "zbx explain E0501".
    pub fn explain_command(
        product: *const Product,
        buffer: *[constants.product_explain_bytes_max]u8,
        code_text: []const u8,
    ) []const u8 {
        const tag = product.tag_of(code_text);
        // Cannot fail: `constants.zig` proves the longest command, the word and a tag fit.
        const text = std.fmt.bufPrint(buffer, "{s} explain {s}", .{ product.command, tag }) catch
            unreachable;
        assert(std.mem.startsWith(u8, text, product.command));
        return text;
    }

    /// "https://zigbox.github.io/zigbox/errors/E0501.html": the code's generated page.
    pub fn docs_url(
        product: *const Product,
        buffer: *[constants.docs_url_bytes_max]u8,
        code_text: []const u8,
    ) []const u8 {
        const tag = product.tag_of(code_text);
        const parts = .{ product.docs_url_base, tag };
        // Cannot fail: `constants.zig` proves the longest base and a tag with ".html" fit.
        const text = std.fmt.bufPrint(buffer, "{s}{s}.html", parts) catch unreachable;
        assert(std.mem.startsWith(u8, text, "https://"));
        assert(std.mem.endsWith(u8, text, ".html"));
        return text;
    }
};

const testing = std.testing;

test "Product.zbx carries the strings the renderer used before products existed" {
    // Goal: moving the strings here changed none of them.
    Product.zbx.validate();
    try testing.expectEqualStrings("ZBX-", Product.zbx.prefix);
    const report = "https://github.com/Zigbox/zigbox/issues/new";
    try testing.expectEqualStrings(report, Product.zbx.report_url);
    var command: [constants.product_explain_bytes_max]u8 = undefined;
    try testing.expectEqualStrings(
        "zbx explain E0501",
        Product.zbx.explain_command(&command, "ZBX-E0501"),
    );
    var url: [constants.docs_url_bytes_max]u8 = undefined;
    try testing.expectEqualStrings(
        "https://zigbox.github.io/zigbox/errors/E0501.html",
        Product.zbx.docs_url(&url, "ZBX-E0501"),
    );
}

test "find picks the product by the prefix of the code and nothing else" {
    // Goal: the lookup of the standard. A code of a product in the list finds that product
    // whatever its position; an unknown prefix, a prefix that is only part of another, and an
    // empty list find none.
    const other: Product = .{
        .prefix = "ZC-",
        .command = "zcube",
        .bundle_hint = "zcube bundle --last",
        .report_url = "https://example.invalid/issues/new",
        .docs_url_base = "https://example.invalid/errors/",
    };
    const products = [_]Product{ Product.zbx, other };
    try testing.expectEqual(&products[0], Product.find(&products, "ZBX-E0001").?);
    try testing.expectEqual(&products[1], Product.find(&products, "ZC-E0201").?);
    try testing.expect(Product.find(&products, "ZX-E0201") == null);
    try testing.expect(Product.find(&products, "ZB-E0201") == null);
    try testing.expect(Product.find(&products, "ZCX-E0201") == null);
    try testing.expect(Product.find(&products, "E0201") == null);
    try testing.expect(Product.find(&.{}, "ZBX-E0001") == null);
    try testing.expect(Product.find(products[1..], "ZBX-E0001") == null);
}
