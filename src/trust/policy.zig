//! The policy file (docs/briefs/M8-trust.md, "The policy file"): a restricted ZON file that says
//! which keys the owner trusts and which rules a run must pass.
//!
//!   .{
//!       .version = 1,
//!       .keys = .{ .{ .name = "release", .public = "zbx-ed25519:<64 hex>" } },
//!       .require_signature = true,
//!       .verify = "cached",
//!   }
//!
//! Only `.version` is required. Fields come in any order, each at most once; a string has no
//! escapes. M7's lexer finds the tokens, and this parser reads the schema from them and refuses
//! the first defect with its line and column. A file holds at most `policy_keys_max` keys and
//! `policy_bytes_max` bytes. `.require_provenance = true` asks for a signed SLSA provenance
//! statement for the tree being run (verdict.zig).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const lexer_mod = @import("../build/lexer.zig");
const key = @import("key.zig");

const Lexer = lexer_mod.Lexer;
const Token = lexer_mod.Token;

pub const version_supported: u32 = 1;

pub const Verify = enum { cached, always };

pub const Key = struct {
    name: [constants.key_name_bytes_max]u8,
    name_length: u32,
    public: [constants.key_public_bytes]u8,

    pub fn name_text(self: *const Key) []const u8 {
        return self.name[0..self.name_length];
    }
};

pub const Policy = struct {
    keys: [constants.policy_keys_max]Key,
    key_count: u32,
    require_signature: bool,
    require_provenance: bool,
    verify: Verify,

    pub fn clear(policy: *Policy) void {
        policy.key_count = 0;
        policy.require_signature = false;
        policy.require_provenance = false;
        policy.verify = .cached;
    }

    /// The listed key whose public key is `public`, if the policy trusts it.
    pub fn trusted(
        policy: *const Policy,
        public: *const [constants.key_public_bytes]u8,
    ) ?*const Key {
        assert(policy.key_count <= constants.policy_keys_max);
        for (policy.keys[0..policy.key_count]) |*listed| {
            if (std.mem.eql(u8, &listed.public, public)) return listed;
        }
        return null;
    }

    /// True when the policy asks for anything at all of a run.
    pub fn checks(policy: *const Policy) bool {
        return policy.require_signature or policy.require_provenance;
    }
};

pub const Kind = enum {
    syntax,
    unknown_field,
    duplicate_field,
    missing_version,
    bad_version,
    newer_version,
    bad_string,
    bad_name,
    bad_public,
    key_twice,
    too_many_keys,
    bad_verify,
    too_large,
};

/// The first defect: what, and where (line and column count from 1; 0 for the whole file).
pub const Problem = struct {
    kind: Kind,
    line: u32,
    column: u32,
    /// The field or key name involved, truncated; empty when none.
    detail: [constants.key_name_bytes_max]u8,
    detail_length: u32,

    pub fn detail_text(self: *const Problem) []const u8 {
        return self.detail[0..self.detail_length];
    }
};

const Seen = struct {
    version: bool = false,
    keys: bool = false,
    require_signature: bool = false,
    require_provenance: bool = false,
    verify: bool = false,
};

const Field = enum { version, keys, require_signature, require_provenance, verify };

const field_names = [_]struct { name: []const u8, field: Field }{
    .{ .name = "version", .field = .version },
    .{ .name = "keys", .field = .keys },
    .{ .name = "require_signature", .field = .require_signature },
    .{ .name = "require_provenance", .field = .require_provenance },
    .{ .name = "verify", .field = .verify },
};

const Parser = struct {
    lexer: Lexer,
    token: Token,
    problem: Problem,

    fn advance(parser: *Parser) void {
        parser.token = parser.lexer.next();
    }

    fn text(parser: *const Parser) []const u8 {
        return parser.lexer.text[parser.token.start..parser.token.end];
    }

    fn fail(parser: *Parser, kind: Kind, detail: []const u8) error{Refused} {
        const length = @min(detail.len, constants.key_name_bytes_max);
        parser.problem = .{
            .kind = kind,
            .line = parser.token.line,
            .column = parser.token.column,
            .detail = undefined,
            .detail_length = @intCast(length),
        };
        @memcpy(parser.problem.detail[0..length], detail[0..length]);
        return error.Refused;
    }

    fn expect(parser: *Parser, tag: lexer_mod.Tag) error{Refused}!void {
        if (parser.token.tag != tag) return parser.fail(.syntax, "");
        parser.advance();
    }

    /// A string's contents: no escapes, so the bytes between the quotes are the value.
    fn string(parser: *Parser) error{Refused}![]const u8 {
        if (parser.token.tag != .string) return parser.fail(.syntax, "");
        const raw = parser.text();
        const inner = raw[1 .. raw.len - 1];
        if (std.mem.indexOfScalar(u8, inner, '\\') != null) return parser.fail(.bad_string, "");
        for (inner) |byte| {
            if (byte < 0x20 or byte == 0x7f) return parser.fail(.bad_string, "");
        }
        parser.advance();
        return inner;
    }

    fn boolean(parser: *Parser) error{Refused}!bool {
        const value = switch (parser.token.tag) {
            .true_word => true,
            .false_word => false,
            else => return parser.fail(.syntax, ""),
        };
        parser.advance();
        return value;
    }
};

/// Reads `bytes` into `out`; on a defect returns the first one.
pub fn parse(bytes: []const u8, out: *Policy) ?Problem {
    assert(constants.policy_bytes_max <= constants.build_render_bytes_max);
    out.clear();
    if (bytes.len > constants.policy_bytes_max) return whole_file(.too_large);
    var parser: Parser = .{
        .lexer = Lexer.init(bytes),
        .token = undefined,
        .problem = undefined,
    };
    parser.advance();
    read_root(&parser, out) catch return parser.problem;
    assert(out.key_count <= constants.policy_keys_max);
    return null;
}

fn whole_file(kind: Kind) Problem {
    return .{ .kind = kind, .line = 0, .column = 0, .detail = undefined, .detail_length = 0 };
}

fn read_root(parser: *Parser, out: *Policy) error{Refused}!void {
    var seen: Seen = .{};
    try parser.expect(.open);
    // Each pass reads one member, and a file has at most `field_names.len` of them.
    while (parser.token.tag != .close) {
        if (parser.token.tag != .field) return parser.fail(.syntax, "");
        const field = field_of(parser.text()[1..]) orelse
            return parser.fail(.unknown_field, parser.text()[1..]);
        try read_member(parser, out, &seen, field);
        if (parser.token.tag == .comma) {
            parser.advance();
        } else if (parser.token.tag != .close) {
            return parser.fail(.syntax, "");
        }
    }
    parser.advance(); // The `}`.
    if (parser.token.tag != .end) return parser.fail(.syntax, "");
    if (!seen.version) return parser.fail(.missing_version, "");
}

fn field_of(name: []const u8) ?Field {
    for (field_names) |entry| {
        if (std.mem.eql(u8, entry.name, name)) return entry.field;
    }
    return null;
}

fn read_member(parser: *Parser, out: *Policy, seen: *Seen, field: Field) error{Refused}!void {
    const flag: *bool = switch (field) {
        .version => &seen.version,
        .keys => &seen.keys,
        .require_signature => &seen.require_signature,
        .require_provenance => &seen.require_provenance,
        .verify => &seen.verify,
    };
    if (flag.*) return parser.fail(.duplicate_field, parser.text()[1..]);
    flag.* = true;
    parser.advance();
    try parser.expect(.equals);
    switch (field) {
        .version => try read_version(parser),
        .keys => try read_keys(parser, out),
        .require_signature => out.require_signature = try parser.boolean(),
        .require_provenance => {
            out.require_provenance = try parser.boolean();
        },
        .verify => try read_verify(parser, out),
    }
}

fn read_version(parser: *Parser) error{Refused}!void {
    if (parser.token.tag != .integer) return parser.fail(.syntax, "");
    const value = std.fmt.parseInt(u32, parser.text(), 10) catch
        return parser.fail(.bad_version, "");
    if (value > version_supported) return parser.fail(.newer_version, "");
    if (value != version_supported) return parser.fail(.bad_version, "");
    parser.advance();
}

fn read_verify(parser: *Parser, out: *Policy) error{Refused}!void {
    const at = parser.token;
    const value = try parser.string();
    if (std.mem.eql(u8, value, "cached")) {
        out.verify = .cached;
    } else if (std.mem.eql(u8, value, "always")) {
        out.verify = .always;
    } else {
        parser.token = at;
        return parser.fail(.bad_verify, value);
    }
}

fn read_keys(parser: *Parser, out: *Policy) error{Refused}!void {
    try parser.expect(.open);
    // Each pass reads one key, and a policy has at most `policy_keys_max` of them.
    while (parser.token.tag != .close) {
        if (out.key_count == constants.policy_keys_max) return parser.fail(.too_many_keys, "");
        try read_key(parser, out);
        if (parser.token.tag == .comma) {
            parser.advance();
        } else if (parser.token.tag != .close) {
            return parser.fail(.syntax, "");
        }
    }
    parser.advance();
}

fn read_key(parser: *Parser, out: *Policy) error{Refused}!void {
    const start = parser.token;
    try parser.expect(.open);
    var entry: Key = undefined;
    var have_name = false;
    var have_public = false;
    // Two members, in either order, so the loop ends within three passes.
    while (parser.token.tag != .close) {
        if (parser.token.tag != .field) return parser.fail(.syntax, "");
        const name = parser.text()[1..];
        const is_name = std.mem.eql(u8, name, "name");
        const is_public = std.mem.eql(u8, name, "public");
        if (!is_name and !is_public) return parser.fail(.unknown_field, name);
        if ((is_name and have_name) or (is_public and have_public)) {
            return parser.fail(.duplicate_field, name);
        }
        parser.advance();
        try parser.expect(.equals);
        if (is_name) {
            try read_key_name(parser, &entry);
            have_name = true;
        } else {
            try read_key_public(parser, &entry);
            have_public = true;
        }
        if (parser.token.tag == .comma) {
            parser.advance();
        } else if (parser.token.tag != .close) {
            return parser.fail(.syntax, "");
        }
    }
    if (!have_name or !have_public) {
        parser.token = start;
        return parser.fail(.syntax, "");
    }
    for (out.keys[0..out.key_count]) |*listed| {
        if (std.mem.eql(u8, &listed.public, &entry.public) or
            std.mem.eql(u8, listed.name_text(), entry.name_text()))
        {
            return parser.fail(.key_twice, entry.name_text());
        }
    }
    parser.advance();
    out.keys[out.key_count] = entry;
    out.key_count += 1;
}

fn read_key_name(parser: *Parser, entry: *Key) error{Refused}!void {
    const at = parser.token;
    const value = try parser.string();
    if (!key.name_valid(value)) {
        parser.token = at;
        return parser.fail(.bad_name, value);
    }
    entry.name_length = @intCast(value.len);
    @memcpy(entry.name[0..value.len], value);
}

fn read_key_public(parser: *Parser, entry: *Key) error{Refused}!void {
    const at = parser.token;
    const value = try parser.string();
    const parsed = if (value.len == constants.key_public_text_bytes)
        key.parse_public_text(value)
    else
        null;
    entry.public = parsed orelse {
        parser.token = at;
        return parser.fail(.bad_public, "");
    };
}
