//! The fuzzer for what comes back from Google and what names it: `zig build fuzz --
//! parse_google`. Each iteration builds an input (random bytes, a valid sample with a few edits,
//! or two samples run together) and feeds it to the credentials-file reader, the subject-token
//! readers, STS's and the metadata server's token answer, IAM Credentials' answer, the error-code
//! reader (the realm's error body among its shapes), the JSON member reader and the host
//! classifier.
//!
//! Properties, for any input: no parser crashes; what a parser accepts is a slice of its input
//! and passes the validators the requests rely on (so nothing with a control byte, a quote or an
//! oversized field reaches a header or a form); an accepted credentials file names an HTTPS URL
//! source, at most its bound of headers, and an impersonation URL only with the account it names;
//! an error code is a short name of letters, digits and `_`; a host gets credentials only when it
//! is exactly one of the supported shapes.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const parse = @import("google/parse.zig");
const parse_tests = @import("google/parse_tests.zig");
const hosts = @import("google/hosts.zig");
const json = @import("cloud/json.zig");
const net = @import("registry/net.zig");

const input_bytes_max = 4096;

const key_file = "{\"type\":\"service_account\",\"private_key\":\"FAKE\"}";
const user_file = "{\"type\":\"authorized_user\",\"refresh_token\":\"FAKE\"}";

const samples = [_][]const u8{
    parse_tests.file_account,
    parse_tests.url_account,
    parse_tests.sts_answer,
    parse_tests.iam_answer,
    parse_tests.metadata_answer,
    key_file,
    user_file,
    "{\"error\":\"invalid_grant\",\"error_description\":\"x\"}",
    "{\"error\":{\"code\":403,\"message\":\"x\",\"status\":\"PERMISSION_DENIED\"}}",
    "{\"errors\":[{\"code\":\"DENIED\",\"message\":\"x\"}]}",
    "{\"count\":1,\"value\":\"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ6YngifQ.c2ln\"}",
    "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ6YngifQ.c2ln\n",
    "2026-11-16T13:00:00Z",
    "us-docker.pkg.dev",
    "europe-west4-docker.pkg.dev",
    "gcr.io",
    "asia.gcr.io",
    "mirror.gcr.io",
    "k8s.gcr.io",
};

const interesting = "\"{}[]:,\\\x00\xff\x80\n 0123456789-._/AZaz=u";

fn mutate(random: std.Random, buffer: *[input_bytes_max]u8, length_in: usize) usize {
    var length = length_in;
    for (0..random.intRangeAtMost(u8, 1, 4)) |_| {
        if (length == 0) break;
        const at = random.uintLessThan(usize, length);
        switch (random.uintLessThan(u8, 3)) {
            0 => buffer[at] = interesting[random.uintLessThan(usize, interesting.len)],
            1 => length = at,
            else => {
                std.mem.copyForwards(u8, buffer[at .. length - 1], buffer[at + 1 .. length]);
                length -= 1;
            },
        }
    }
    return length;
}

fn build(random: std.Random, buffer: *[input_bytes_max]u8) usize {
    comptime var longest = 0;
    inline for (samples) |sample| longest = @max(longest, sample.len);
    comptime assert(2 * longest <= input_bytes_max);
    switch (random.uintLessThan(u8, 3)) {
        0 => {
            const length = random.uintAtMost(usize, 512);
            random.bytes(buffer[0..length]);
            return length;
        },
        1 => {
            const sample = samples[random.uintLessThan(usize, samples.len)];
            @memcpy(buffer[0..sample.len], sample);
            return mutate(random, buffer, sample.len);
        },
        else => {
            const first = samples[random.uintLessThan(usize, samples.len)];
            const second = samples[random.uintLessThan(usize, samples.len)];
            @memcpy(buffer[0..first.len], first);
            @memcpy(buffer[first.len..][0..second.len], second);
            return first.len + second.len;
        },
    }
}

fn inside(outer: []const u8, inner: []const u8) bool {
    if (inner.len == 0) return true;
    const start = @intFromPtr(inner.ptr);
    const base = @intFromPtr(outer.ptr);
    return start >= base and start + inner.len <= base + outer.len;
}

fn check_account(input: []const u8, account: *const parse.ExternalAccount) void {
    // Checked here without the parser's own helpers: an accepted file names its type, and does
    // not open as a key file or gcloud's credentials.
    assert(std.mem.indexOf(u8, input, "\"external_account\"") != null);
    check_opening(input);
    assert(inside(input, account.audience));
    assert(inside(input, account.subject_token_type));
    assert(inside(input, account.location));
    assert(inside(input, account.json_field));
    assert(inside(input, account.impersonation_url));
    assert(account.audience.len > 0);
    assert(account.location.len > 0);
    assert(account.headers_count <= constants.google_source_headers_max);
    if (account.source == .url) {
        const url = net.parse_url(account.location) catch unreachable; // Accepted, so it parses.
        assert(url.scheme == .https);
    } else {
        assert(account.headers_count == 0);
    }
    for (account.source_headers()) |header| {
        assert(inside(input, header.name));
        assert(inside(input, header.value));
    }
    if (account.impersonation_url.len == 0) {
        assert(account.service_account.len == 0);
    } else {
        const named = parse.impersonated_account(account.impersonation_url).?;
        assert(std.mem.eql(u8, named, account.service_account));
        assert(parse.email_valid(account.service_account));
        check_impersonation(account.impersonation_url, account.service_account);
    }
}

/// The impersonation URL and its email, checked without the parser's helpers: the fixed prefix,
/// the email, the fixed suffix, and one `@` with text on both sides.
fn check_impersonation(url: []const u8, email: []const u8) void {
    const prefix = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/";
    const suffix = ":generateAccessToken";
    assert(url.len == prefix.len + email.len + suffix.len);
    assert(std.mem.eql(u8, url[0..prefix.len], prefix));
    assert(std.mem.eql(u8, url[prefix.len..][0..email.len], email));
    assert(std.mem.eql(u8, url[prefix.len + email.len ..], suffix));
    const at = std.mem.indexOfScalar(u8, email, '@').?;
    assert(at > 0);
    assert(at + 1 < email.len);
    assert(std.mem.indexOfScalarPos(u8, email, at + 1, '@') == null);
}

/// A file that opens with a key file's or gcloud's type is refused with that reason, or as
/// malformed when an edit later on broke the JSON; never as anything else, never accepted.
fn check_refusal(input: []const u8, refused: parse.Refused) void {
    assert(refused.type_name.len <= constants.google_type_name_bytes_max);
    const key_head = "{\"type\":\"service_account\",";
    const user_head = "{\"type\":\"authorized_user\",";
    if (std.mem.startsWith(u8, input, key_head)) {
        const named = refused.reason == .service_account_key or refused.reason == .malformed;
        assert(named);
    }
    if (std.mem.startsWith(u8, input, user_head)) {
        const named = refused.reason == .authorized_user or refused.reason == .malformed;
        assert(named);
    }
}

fn check_opening(input: []const u8) void {
    assert(!std.mem.startsWith(u8, input, "{\"type\":\"service_account\","));
    assert(!std.mem.startsWith(u8, input, "{\"type\":\"authorized_user\","));
}

fn check_token(input: []const u8, token: parse.AccessToken) void {
    assert(inside(input, token.token));
    assert(parse.access_token_valid(token.token));
    assert(token.token.len <= constants.google_access_token_bytes_max);
    if (token.relative) {
        assert(token.expires > 0);
        assert(token.expires <= constants.google_token_lifetime_max_s);
    }
}

fn check_host(input: []const u8) void {
    const class = hosts.classify(input);
    switch (class) {
        .artifact_registry => {
            assert(std.mem.endsWith(u8, input, "-docker.pkg.dev"));
            assert(hosts.valid_region(input[0 .. input.len - "-docker.pkg.dev".len]));
        },
        .gcr => {
            var known = false;
            for (hosts.gcr_hosts) |gcr_host| known = known or std.mem.eql(u8, gcr_host, input);
            assert(known);
        },
        .mirror => assert(std.mem.eql(u8, input, hosts.mirror_host)),
        .other_google, .not_google => assert(!class.credentialed()),
    }
}

fn check_members(input: []const u8) void {
    var members = json.Members.init(input) catch return;
    var count: u32 = 0;
    while (members.next() catch return) |found| {
        assert(inside(input, found.name));
        assert(inside(input, found.value.text));
        count += 1;
        assert(count <= input.len);
    }
}

pub fn fuzz_parse_google(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    var buffer: [input_bytes_max]u8 = undefined;
    const input = buffer[0..build(random, &buffer)];
    switch (parse.parse_credentials(input)) {
        .account => |account| check_account(input, &account),
        .refused => |refused| check_refusal(input, refused),
    }
    if (parse.subject_text(input)) |token| {
        assert(inside(input, token));
        assert(parse.subject_token_valid(token));
    } else |_| {}
    if (parse.subject_json(input, "value")) |token| {
        assert(inside(input, token));
        assert(parse.subject_token_valid(token));
    } else |_| {}
    if (parse.parse_token_answer(input)) |token| check_token(input, token) else |_| {}
    if (parse.parse_impersonation(input)) |token| check_token(input, token) else |_| {}
    if (parse.error_code(input)) |code| {
        assert(code.len > 0);
        assert(code.len <= constants.google_error_code_bytes_max);
        for (code) |byte| {
            const allowed = std.ascii.isAlphanumeric(byte) or byte == '_';
            assert(allowed);
        }
    }
    check_members(input);
    check_host(input);
}
