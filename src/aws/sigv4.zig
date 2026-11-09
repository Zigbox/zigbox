//! AWS Signature Version 4, the way zbx signs a request to an AWS API (ECR's
//! `GetAuthorizationToken`, and later ECR push's calls): HMAC-SHA256 from `std.crypto`, no
//! allocation, nothing global. The signer is pure: it takes the request's parts, the time and the
//! key, and writes the `Authorization` value. It sends nothing and keeps nothing.
//!
//! What is signed is explicit in the types. A `Scope` is the region and the service the signature
//! is good for (`us-east-1`, `ecr`): a signature made for one is useless at another, which is the
//! point of keeping them in the call and never in a default. The signer adds the headers a
//! signature must cover whatever the caller sends (`x-amz-date`, and `x-amz-security-token` when
//! the key is temporary); the caller sends the same two, from `Signed`.
//!
//! Known limits, all refused with an error and never guessed at: the target must already be
//! normalised (no `.` or `..` segment, no empty segment but the root), and a request header may
//! not be repeated. Both hold for every call zbx makes.
//!
//! The canonical request and the string to sign are secrets in one case: when the session token is
//! signed, it is in the canonical request. The workspace is zeroed before `sign` returns, as are
//! the derived keys.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const net = @import("../registry/net.zig");

const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// The algorithm name every SigV4 signature starts with.
pub const algorithm = "AWS4-HMAC-SHA256";

/// Where a signature is good: the region and the service it was made for.
pub const Scope = struct {
    region: []const u8,
    service: []const u8,
};

/// The key a request is signed with. `session_token` is empty for a long-lived key.
pub const Key = struct {
    access_key_id: []const u8,
    secret_access_key: []const u8,
    session_token: []const u8,
};

pub const Header = net.Header;

pub const Input = struct {
    method: net.Method,
    /// Path and query, starting with '/'. The query's names and values are percent-encoded or
    /// plain; the signer decodes and encodes them again in AWS's canonical form.
    target: []const u8,
    /// Every header the request will carry that the signature covers, `host` among them. Not
    /// `x-amz-date` and not `x-amz-security-token`: the signer adds those.
    headers: []const Header,
    body: []const u8,
    scope: Scope,
    key: Key,
    /// The time of the request, in seconds since the epoch (from the host's clock).
    now_s: u64,
};

pub const Error = error{
    /// The target is not `/path?query` in normal form, or has more query parameters than
    /// `query_params_max`.
    BadTarget,
    /// A header the signer cannot take: a repeated name, one it adds itself, or too many.
    BadHeader,
    /// The canonical request or the `Authorization` value does not fit its bound.
    TooLarge,
};

const query_params_max = constants.aws_query_params_max;

/// What `sign` needs room for. Zeroed by `sign` before it returns.
pub const Workspace = struct {
    canonical: [constants.aws_canonical_bytes_max]u8,
    /// The encoded query parameters, before they are sorted into the canonical request.
    query: [constants.registry_url_bytes_max]u8,
};

/// What the caller sends: `amz_date` as `X-Amz-Date`, `authorization` as the `Authorization`
/// header. The signature is not a secret, but it is zeroed with the rest by `wipe`.
pub const Signed = struct {
    amz_date: [16]u8,
    authorization: [constants.aws_authorization_bytes_max]u8,
    authorization_len: u32,

    pub fn authorization_text(signed: *const Signed) []const u8 {
        assert(signed.authorization_len <= signed.authorization.len);
        return signed.authorization[0..signed.authorization_len];
    }

    pub fn wipe(signed: *Signed) void {
        std.crypto.secureZero(u8, &signed.authorization);
        signed.authorization_len = 0;
    }
};

/// `20150830T123600Z`: seconds since the epoch in SigV4's basic ISO 8601 form.
pub fn amz_date_of(now_s: u64) [16]u8 {
    assert(now_s < 1 << 40);
    const epoch_seconds: std.time.epoch.EpochSeconds = .{ .secs = now_s };
    const year_day = epoch_seconds.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch_seconds.getDaySeconds();
    var text: [16]u8 = undefined;
    const written = std.fmt.bufPrint(&text, "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
    }) catch unreachable; // Four digits of year (below 2^40 s is year 36812: five) fit 16 bytes.
    assert(written.len == 16);
    assert(text[8] == 'T');
    return text;
}

/// The signing key for a day, region and service (`kSigning` of the AWS documentation).
pub fn signing_key(
    secret_access_key: []const u8,
    date: *const [8]u8,
    scope: Scope,
) [Hmac.mac_length]u8 {
    assert(secret_access_key.len > 0);
    assert(secret_access_key.len <= constants.aws_secret_key_bytes_max);
    var seed: [4 + constants.aws_secret_key_bytes_max]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    @memcpy(seed[0..4], "AWS4");
    @memcpy(seed[4..][0..secret_access_key.len], secret_access_key);
    var date_key: [Hmac.mac_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &date_key);
    Hmac.create(&date_key, date, seed[0 .. 4 + secret_access_key.len]);
    var region_key: [Hmac.mac_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &region_key);
    Hmac.create(&region_key, scope.region, &date_key);
    var service_key: [Hmac.mac_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &service_key);
    Hmac.create(&service_key, scope.service, &region_key);
    var result: [Hmac.mac_length]u8 = undefined;
    Hmac.create(&result, "aws4_request", &service_key);
    return result;
}

/// Appends to a bounded buffer; an overflow is remembered, never half-applied.
pub const Writer = struct {
    buffer: []u8,
    len: u32 = 0,
    overflow: bool = false,

    pub fn put(writer: *Writer, bytes: []const u8) void {
        assert(writer.len <= writer.buffer.len);
        if (writer.overflow) return;
        if (bytes.len > writer.buffer.len - writer.len) {
            writer.overflow = true;
            return;
        }
        @memcpy(writer.buffer[writer.len..][0..bytes.len], bytes);
        writer.len += @intCast(bytes.len);
    }

    pub fn byte(writer: *Writer, value: u8) void {
        writer.put(&.{value});
    }

    pub fn text(writer: *const Writer) []const u8 {
        assert(!writer.overflow);
        return writer.buffer[0..writer.len];
    }
};

fn is_unreserved(value: u8) bool {
    if (std.ascii.isAlphanumeric(value)) return true;
    return value == '-' or value == '_' or value == '.' or value == '~';
}

fn hex_value(digit: u8) ?u8 {
    return switch (digit) {
        '0'...'9' => digit - '0',
        'A'...'F' => digit - 'A' + 10,
        'a'...'f' => digit - 'a' + 10,
        else => null,
    };
}

/// Writes `text` the way SigV4 wants: every byte but the unreserved ones as `%XX` in capitals,
/// and a `+` is a plus (not a space). With `decode`, a valid `%XX` is decoded first (a query,
/// which is encoded once); without it a `%` is encoded again (a path, which is encoded twice
/// for every service but S3, so the canonical path is the sent path encoded once more).
/// `keep_slash` leaves `/` alone (a path).
pub fn put_encoded(writer: *Writer, text: []const u8, decode: bool, keep_slash: bool) void {
    var at: usize = 0;
    while (at < text.len) : (at += 1) {
        var value = text[at];
        const escaped = decode and value == '%' and at + 2 < text.len and
            hex_value(text[at + 1]) != null and hex_value(text[at + 2]) != null;
        if (escaped) {
            value = hex_value(text[at + 1]).? * 16 + hex_value(text[at + 2]).?;
            at += 2;
        }
        if (is_unreserved(value) or (keep_slash and value == '/')) {
            writer.byte(value);
        } else {
            const digits = "0123456789ABCDEF";
            writer.put(&.{ '%', digits[value >> 4], digits[value & 15] });
        }
    }
}

/// One query parameter, encoded, as spans of the workspace's query buffer.
const Param = struct {
    name_start: u32,
    name_end: u32,
    value_end: u32,
};

fn param_less(query: []const u8, left: Param, right: Param) bool {
    const left_name = query[left.name_start..left.name_end];
    const right_name = query[right.name_start..right.name_end];
    const order = std.mem.order(u8, left_name, right_name);
    if (order != .eq) return order == .lt;
    const left_value = query[left.name_end..left.value_end];
    const right_value = query[right.name_end..right.value_end];
    return std.mem.order(u8, left_value, right_value) == .lt;
}

/// The canonical query string of `query` (the text after `?`), sorted by name, then value.
fn put_query(writer: *Writer, scratch: []u8, query: []const u8) Error!void {
    var spans: [query_params_max]Param = undefined;
    var count: u32 = 0;
    var encoded: Writer = .{ .buffer = scratch };
    var rest = query;
    while (rest.len > 0) {
        const end = std.mem.indexOfScalar(u8, rest, '&') orelse rest.len;
        const pair = rest[0..end];
        rest = if (end < rest.len) rest[end + 1 ..] else rest[rest.len..];
        if (pair.len == 0) continue;
        if (count == query_params_max) return error.BadTarget;
        const equals = std.mem.indexOfScalar(u8, pair, '=') orelse pair.len;
        const start: u32 = @intCast(encoded.len);
        put_encoded(&encoded, pair[0..equals], true, false);
        const name_end: u32 = @intCast(encoded.len);
        if (equals < pair.len) put_encoded(&encoded, pair[equals + 1 ..], true, false);
        if (encoded.overflow) return error.TooLarge;
        spans[count] = .{
            .name_start = start,
            .name_end = name_end,
            .value_end = @intCast(encoded.len),
        };
        count += 1;
    }
    const kept = encoded.text();
    std.mem.sort(Param, spans[0..count], kept, param_less);
    for (spans[0..count], 0..) |span, index| {
        if (index > 0) writer.byte('&');
        writer.put(kept[span.name_start..span.name_end]);
        writer.byte('=');
        writer.put(kept[span.name_end..span.value_end]);
    }
}

/// The path of a target in canonical form, or `BadTarget` if it is not normal: it must start
/// with '/', and have no `.` or `..` segment and no empty segment (a trailing slash is allowed).
fn put_path(writer: *Writer, path: []const u8) Error!void {
    assert(path.len > 0);
    if (path[0] != '/') return error.BadTarget;
    var segments = std.mem.splitScalar(u8, path[1..], '/');
    while (segments.next()) |segment| {
        const last = segments.peek() == null;
        if (segment.len == 0 and !last) return error.BadTarget;
        if (std.mem.eql(u8, segment, ".")) return error.BadTarget;
        if (std.mem.eql(u8, segment, "..")) return error.BadTarget;
    }
    put_encoded(writer, path, false, true);
}

/// A header name in lower case, ordered the way the canonical request orders names.
fn name_less(_: void, left: Header, right: Header) bool {
    const length = @min(left.name.len, right.name.len);
    for (left.name[0..length], right.name[0..length]) |a, b| {
        const low_a = std.ascii.toLower(a);
        const low_b = std.ascii.toLower(b);
        if (low_a != low_b) return low_a < low_b;
    }
    return left.name.len < right.name.len;
}

/// A header value with its outer blanks cut and every run of blanks inside made one space.
fn put_value(writer: *Writer, value: []const u8) void {
    const trimmed = std.mem.trim(u8, value, " \t");
    var in_blank = false;
    for (trimmed) |byte| {
        const blank = byte == ' ' or byte == '\t';
        if (blank and in_blank) continue;
        in_blank = blank;
        writer.byte(if (blank) ' ' else byte);
    }
}

fn put_name_lower(writer: *Writer, name: []const u8) void {
    for (name) |byte| writer.byte(std.ascii.toLower(byte));
}

const date_name = "x-amz-date";
const token_name = "x-amz-security-token";

/// The headers the signature covers, sorted: the caller's, then the two the signer adds.
const Covered = struct {
    items: [constants.aws_signed_headers_max]Header,
    count: u32,
};

fn cover_headers(input: *const Input, amz_date: []const u8, covered: *Covered) Error!void {
    assert(amz_date.len == 16);
    covered.count = 0;
    const extra: u32 = if (input.key.session_token.len > 0) 2 else 1;
    if (input.headers.len + extra > constants.aws_signed_headers_max) return error.BadHeader;
    for (input.headers) |header| {
        // `Header.valid` refuses the names the network writes itself, `host` and the content
        // type among them, and a signature must cover exactly those, so it is not used here.
        if (!valid_signed_header(header)) return error.BadHeader;
        if (std.ascii.eqlIgnoreCase(header.name, date_name)) return error.BadHeader;
        if (std.ascii.eqlIgnoreCase(header.name, token_name)) return error.BadHeader;
        covered.items[covered.count] = header;
        covered.count += 1;
    }
    covered.items[covered.count] = .{ .name = date_name, .value = amz_date };
    covered.count += 1;
    if (input.key.session_token.len > 0) {
        covered.items[covered.count] = .{ .name = token_name, .value = input.key.session_token };
        covered.count += 1;
    }
    const sorted = covered.items[0..covered.count];
    std.mem.sort(Header, sorted, {}, name_less);
    for (sorted[1..], 0..) |header, index| {
        if (std.ascii.eqlIgnoreCase(header.name, sorted[index].name)) return error.BadHeader;
    }
}

/// A header the signer may cover: its name is a token and its value has no control byte.
fn valid_signed_header(header: Header) bool {
    if (header.name.len == 0) return false;
    if (header.value.len > constants.net_header_value_bytes_max) return false;
    for (header.name) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '-') return false;
    }
    for (header.value) |byte| {
        if (byte < 0x20 and byte != '\t') return false;
        if (byte == 0x7f) return false;
    }
    return true;
}

/// The canonical request, in `workspace.canonical`, and where its signed-headers line is.
pub const Canonical = struct {
    text: []const u8,
    /// The `a;b;c` list, a slice of `text`.
    signed_headers: []const u8,
};

/// Builds the canonical request of `input` at time `amz_date` (see `amz_date_of`). Public so the
/// known-answer tests can compare it with the published text.
pub fn canonical_request(
    input: *const Input,
    amz_date: []const u8,
    workspace: *Workspace,
) Error!Canonical {
    assert(input.target.len > 0);
    var covered: Covered = undefined;
    try cover_headers(input, amz_date, &covered);
    var writer: Writer = .{ .buffer = &workspace.canonical };
    writer.put(input.method.text());
    writer.byte('\n');
    const question = std.mem.indexOfScalar(u8, input.target, '?');
    const path = if (question) |at| input.target[0..at] else input.target;
    try put_path(&writer, path);
    writer.byte('\n');
    if (question) |at| try put_query(&writer, &workspace.query, input.target[at + 1 ..]);
    writer.byte('\n');
    for (covered.items[0..covered.count]) |header| {
        put_name_lower(&writer, header.name);
        writer.byte(':');
        put_value(&writer, header.value);
        writer.byte('\n');
    }
    writer.byte('\n');
    const list_start = writer.len;
    for (covered.items[0..covered.count], 0..) |header, index| {
        if (index > 0) writer.byte(';');
        put_name_lower(&writer, header.name);
    }
    const list_end = writer.len;
    writer.byte('\n');
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(input.body, &digest, .{});
    writer.put(&std.fmt.bytesToHex(digest, .lower));
    if (writer.overflow) return error.TooLarge;
    const text = writer.text();
    return .{ .text = text, .signed_headers = text[list_start..list_end] };
}

/// `AWS4-HMAC-SHA256\n<date>\n<scope>\n<hex of the canonical request's hash>`.
pub fn string_to_sign(
    amz_date: []const u8,
    scope: Scope,
    canonical: []const u8,
    out: []u8,
) Error![]const u8 {
    assert(amz_date.len == 16);
    var writer: Writer = .{ .buffer = out };
    writer.put(algorithm ++ "\n");
    writer.put(amz_date);
    writer.byte('\n');
    put_scope(&writer, amz_date[0..8], scope);
    writer.byte('\n');
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(canonical, &digest, .{});
    writer.put(&std.fmt.bytesToHex(digest, .lower));
    if (writer.overflow) return error.TooLarge;
    return writer.text();
}

fn put_scope(writer: *Writer, date: []const u8, scope: Scope) void {
    assert(date.len == 8);
    writer.put(date);
    writer.byte('/');
    writer.put(scope.region);
    writer.byte('/');
    writer.put(scope.service);
    writer.put("/aws4_request");
}

/// The longest string to sign: the algorithm, a date, the scope and 64 hex digits.
const string_to_sign_bytes_max =
    128 + constants.aws_region_bytes_max + constants.aws_service_bytes_max;

/// Signs `input`. Zeroes `workspace` and every derived key before it returns, on every path.
pub fn sign(input: *const Input, workspace: *Workspace, signed: *Signed) Error!void {
    assert(input.key.access_key_id.len > 0);
    assert(input.key.access_key_id.len <= constants.aws_key_id_bytes_max);
    assert(input.key.session_token.len <= constants.aws_session_token_bytes_max);
    assert(input.scope.region.len > 0);
    assert(input.scope.region.len <= constants.aws_region_bytes_max);
    assert(input.scope.service.len > 0);
    assert(input.scope.service.len <= constants.aws_service_bytes_max);
    defer std.crypto.secureZero(u8, &workspace.canonical);
    defer std.crypto.secureZero(u8, &workspace.query);
    signed.amz_date = amz_date_of(input.now_s);
    const canonical = try canonical_request(input, &signed.amz_date, workspace);
    var sts_storage: [string_to_sign_bytes_max]u8 = undefined;
    defer std.crypto.secureZero(u8, &sts_storage);
    const to_sign = try string_to_sign(
        &signed.amz_date,
        input.scope,
        canonical.text,
        &sts_storage,
    );
    var key = signing_key(input.key.secret_access_key, signed.amz_date[0..8], input.scope);
    defer std.crypto.secureZero(u8, &key);
    var mac: [Hmac.mac_length]u8 = undefined;
    Hmac.create(&mac, to_sign, &key);
    var writer: Writer = .{ .buffer = &signed.authorization };
    writer.put(algorithm ++ " Credential=");
    writer.put(input.key.access_key_id);
    writer.byte('/');
    put_scope(&writer, signed.amz_date[0..8], input.scope);
    writer.put(", SignedHeaders=");
    writer.put(canonical.signed_headers);
    writer.put(", Signature=");
    writer.put(&std.fmt.bytesToHex(mac, .lower));
    if (writer.overflow) return error.TooLarge;
    signed.authorization_len = writer.len;
    assert(std.mem.startsWith(u8, signed.authorization_text(), algorithm));
    assert(std.mem.endsWith(u8, signed.authorization_text(), &std.fmt.bytesToHex(mac, .lower)));
}
