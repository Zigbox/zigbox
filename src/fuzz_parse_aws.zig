//! The fuzzer for what comes back from AWS and what names it: `zig build fuzz -- parse_aws`.
//! Each iteration builds an input (random bytes, a valid sample with a few edits, or two samples
//! run together) and feeds it to the token service's XML, the metadata service's JSON, the role
//! list, ECR's token answer, the error-code reader, the timestamp reader and the host classifier.
//!
//! Properties, for any input: no parser crashes; what a parser accepts is a slice of its input
//! and passes the validators the signer relies on (so nothing with a control byte, a quote or an
//! oversized field reaches a header); an error code is a short name of letters and digits; a
//! host is classified as a private registry only when it rebuilds from its own parts.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const parse = @import("aws/parse.zig");
const ecr = @import("aws/ecr.zig");

const input_bytes_max = 2048;

const samples = [_][]const u8{
    "<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials>" ++
        "<AccessKeyId>ASIAEXAMPLEEXAMPLE12</AccessKeyId><SecretAccessKey>wJalrXUtnFEMI/K7MDENG" ++
        "</SecretAccessKey><SessionToken>AQoDYXdzEJr//token</SessionToken>" ++
        "<Expiration>2026-11-09T12:00:00Z</Expiration></Credentials>" ++
        "</AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>",
    "{\"Code\":\"Success\",\"AccessKeyId\":\"ASIAEXAMPLEEXAMPLE12\",\"SecretAccessKey\":" ++
        "\"wJalrXUtnFEMI/K7MDENG\",\"Token\":\"AQoDYXdz\",\"Expiration\":\"2026-11-09T12:00:00Z\"}",
    "zbx-pull-role\n",
    "{\"authorizationData\":[{\"authorizationToken\":\"QVdTOnBhc3N3b3Jk\"," ++
        "\"expiresAt\":1.7E9,\"proxyEndpoint\":\"https://1.dkr.ecr.us-east-1.amazonaws.com\"}]}",
    "{\"__type\":\"ExpiredTokenException\",\"message\":\"The security token is expired\"}",
    "<ErrorResponse><Error><Code>InvalidIdentityToken</Code><Message>x</Message></Error>" ++
        "</ErrorResponse>",
    "2026-11-09T12:00:00Z",
    "123456789012.dkr.ecr.us-east-1.amazonaws.com",
    "123456789012.dkr.ecr-fips.us-east-1.amazonaws.com",
    "123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn",
    "public.ecr.aws",
};

const interesting = "<>/\"{}[]:,\\\x00\xff\x80\n 0123456789-.AZaz=";

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
    switch (random.uintLessThan(u8, 3)) {
        0 => {
            const length = random.uintAtMost(usize, buffer.len);
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

fn check_credentials(input: []const u8, got: parse.Credentials) void {
    assert(inside(input, got.access_key_id));
    assert(inside(input, got.secret_access_key));
    assert(inside(input, got.session_token));
    assert(parse.key_id_valid(got.access_key_id));
    assert(parse.secret_valid(got.secret_access_key));
    if (got.session_token.len > 0) assert(parse.token_valid(got.session_token));
}

fn check_error_code(code: []const u8) void {
    assert(code.len > 0);
    assert(code.len <= constants.aws_error_code_bytes_max);
    for (code) |byte| assert(std.ascii.isAlphanumeric(byte));
}

fn check_host(input: []const u8) void {
    const host = ecr.classify(input);
    const private = switch (host) {
        .private => |value| value,
        else => return,
    };
    assert(ecr.valid_region(private.region));
    for (private.account) |digit| assert(std.ascii.isDigit(digit));
    var rebuilt: [constants.aws_ecr_host_bytes_max]u8 = undefined;
    const text = std.fmt.bufPrint(
        &rebuilt,
        "{s}.dkr.ecr.{s}.amazonaws.com",
        .{ &private.account, private.region },
    ) catch unreachable; // The host was classified, so it fits.
    assert(std.mem.eql(u8, text, input));
}

pub fn fuzz_parse_aws(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    var buffer: [input_bytes_max]u8 = undefined;
    const input = buffer[0..build(random, &buffer)];
    if (parse.parse_sts(input)) |got| check_credentials(input, got) else |_| {}
    if (parse.parse_imds(input)) |got| check_credentials(input, got) else |_| {}
    if (parse.parse_imds_role(input)) |role| assert(inside(input, role)) else |_| {}
    if (parse.parse_ecr_token(input)) |token| {
        assert(inside(input, token.basic));
        assert(token.basic.len > 0);
        assert(token.basic.len <= constants.aws_ecr_token_bytes_max);
    } else |_| {}
    if (parse.error_code(input)) |code| check_error_code(code);
    _ = parse.parse_timestamp(input);
    _ = parse.imds_token_valid(input);
    check_host(input);
}
