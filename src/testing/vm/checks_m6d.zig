//! The M6d demo's assertions (docs/briefs/M6d-gar.md, slice 3) and the pure pieces of its setup,
//! each with a unit test fed wrong text: the repository variables' shapes, the OIDC token request
//! and its answer, the external_account file, the masking of anything token-shaped before the
//! harness prints guest output, and each step's check. main_m6d.zig runs the commands.

const std = @import("std");
const assert = std.debug.assert;
const checks = @import("checks.zig");
const checks_m4 = @import("checks_m4.zig");
const checks_m3 = @import("checks_m3.zig");
const scan = @import("m6d_fixture/scan.zig");
const mask = @import("m6d_fixture/mask.zig");
const shape = @import("m6d_fixture/shape.zig");

pub const Streams = checks.Streams;

pub const Error = error{
    ExitCodeWrong,
    /// A line the step must print is missing, or one it must not print is there.
    OutputWrong,
    /// A refusal is not the code it must be, or names too little.
    RefusalWrong,
    DigestWrong,
    JsonWrong,
    /// Step 5 found a secret, or scanned nothing.
    SecretFound,
};

pub const ConfigError = error{
    ProviderWrong,
    ServiceAccountWrong,
    RegistryWrong,
    TooLong,
};

/// The repository variables the demo reads (docs/demos/m6d.md has the owner's setup).
pub const variable_names = [_][]const u8{
    "ZBX_GAR_PROVIDER",
    "ZBX_GAR_SERVICE_ACCOUNT",
    "ZBX_GAR_REGISTRY",
    "ZBX_GCR_REGISTRY",
};

/// What the runner gives a job with `id-token: write`.
pub const runner_names = [_][]const u8{
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
};

/// The longest value any of the variables may have; they are typed into guest commands.
pub const value_bytes_max = 200;
/// A GitHub OIDC token is used this long after it was fetched, then fetched again; it lives
/// about five minutes.
pub const oidc_fresh_ms: u64 = 3 * 60 * 1000;

pub const Config = struct {
    /// projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>
    provider: []const u8,
    /// An email, or empty for direct access by the federated principal.
    service_account: []const u8,
    /// <region>-docker.pkg.dev/<project>
    gar_registry: []const u8,
    /// gcr.io/<project> (or us., eu., asia.gcr.io)
    gcr_registry: []const u8,
};

/// The first variable (of `variable_names` then `runner_names`) a run needs and does not have.
/// The service account may be empty. `values` is in that order.
pub fn first_missing(values: [6]?[]const u8) ?[]const u8 {
    assert(variable_names.len + runner_names.len == values.len);
    for (values, 0..) |value, index| {
        if (index == 1) continue; // The service account is optional.
        const empty = if (value) |text| text.len == 0 else true;
        if (!empty) continue;
        if (index < variable_names.len) return variable_names[index];
        return runner_names[index - variable_names.len];
    }
    return null;
}

fn is_id_byte(byte: u8) bool {
    return (byte >= 'a' and byte <= 'z') or (byte >= '0' and byte <= '9') or byte == '-';
}

fn is_id(text: []const u8) bool {
    if (text.len == 0) return false;
    if (text.len > 63) return false;
    for (text) |byte| {
        if (!is_id_byte(byte)) return false;
    }
    return true;
}

fn is_number(text: []const u8) bool {
    if (text.len == 0) return false;
    for (text) |byte| {
        if (byte < '0' or byte > '9') return false;
    }
    return true;
}

/// Checks each value's shape and alphabet, so that each can be typed into a guest command and a
/// JSON string as it is.
pub fn check_config(config: Config) ConfigError!void {
    const all = [_][]const u8{
        config.provider, config.service_account, config.gar_registry, config.gcr_registry,
    };
    for (all) |value| if (value.len > value_bytes_max) return error.TooLong;
    var parts = std.mem.splitScalar(u8, config.provider, '/');
    const words = [_][]const u8{ "projects", "", "locations", "global" } ++
        [_][]const u8{ "workloadIdentityPools", "", "providers", "" };
    for (words, 0..) |word, index| {
        const part = parts.next() orelse return error.ProviderWrong;
        if (index == 1) {
            if (!is_number(part)) return error.ProviderWrong;
        } else if (word.len == 0) {
            if (!is_id(part)) return error.ProviderWrong;
        } else if (!std.mem.eql(u8, part, word)) return error.ProviderWrong;
    }
    if (parts.next() != null) return error.ProviderWrong;
    try check_service_account(config.service_account);
    try check_registry(config.gar_registry, "-docker.pkg.dev");
    try check_registry(config.gcr_registry, "gcr.io");
}

fn check_service_account(email: []const u8) ConfigError!void {
    if (email.len == 0) return;
    const suffix = ".iam.gserviceaccount.com";
    const at = std.mem.indexOfScalar(u8, email, '@') orelse return error.ServiceAccountWrong;
    if (!std.mem.endsWith(u8, email, suffix)) return error.ServiceAccountWrong;
    // The suffix has no `@`, so the first `@` is before it.
    assert(at < email.len - suffix.len);
    if (!is_id(email[0..at])) return error.ServiceAccountWrong;
    if (!is_id(email[at + 1 .. email.len - suffix.len])) return error.ServiceAccountWrong;
}

/// `<host>/<project>`, the host ending in `host_suffix` (`us-docker.pkg.dev`, `gcr.io`,
/// `eu.gcr.io`), each label of it an id.
fn check_registry(registry: []const u8, host_suffix: []const u8) ConfigError!void {
    assert(host_suffix.len > 0);
    const slash = std.mem.indexOfScalar(u8, registry, '/') orelse return error.RegistryWrong;
    const host = registry[0..slash];
    if (!std.mem.endsWith(u8, host, host_suffix)) return error.RegistryWrong;
    var labels = std.mem.splitScalar(u8, host, '.');
    while (labels.next()) |label| if (!is_id(label)) return error.RegistryWrong;
    if (!is_id(registry[slash + 1 ..])) return error.RegistryWrong;
    assert(slash > 0);
}

/// The project path in a registry value: `my-project` in `us-docker.pkg.dev/my-project`.
pub fn project_of(registry: []const u8) []const u8 {
    const slash = std.mem.indexOfScalar(u8, registry, '/').?; // check_config passed.
    assert(slash + 1 < registry.len);
    return registry[slash + 1 ..];
}

fn percent_encode(writer: *std.Io.Writer, text: []const u8) std.Io.Writer.Error!void {
    for (text) |byte| {
        const plain = is_id_byte(byte) or (byte >= 'A' and byte <= 'Z') or
            byte == '.' or byte == '_' or byte == '~';
        if (plain) {
            try writer.writeByte(byte);
        } else {
            try writer.print("%{X:0>2}", .{byte});
        }
    }
}

/// The runner's token URL with the audience the provider allows by default,
/// `https://iam.googleapis.com/<provider>` (as google-github-actions/auth asks for it).
pub fn oidc_request_url(buffer: []u8, request_url: []const u8, provider: []const u8) ![]u8 {
    assert(request_url.len > 0);
    assert(provider.len > 0);
    var writer: std.Io.Writer = .fixed(buffer);
    try writer.writeAll(request_url);
    const separator: u8 = if (std.mem.indexOfScalar(u8, request_url, '?') == null) '?' else '&';
    try writer.print("{c}audience=", .{separator});
    try percent_encode(&writer, "https://iam.googleapis.com/");
    try percent_encode(&writer, provider);
    return writer.buffered();
}

const is_jwt_byte = mask.is_jwt_byte;

/// The JWT in the runner's answer, `{"count":..,"value":"<jwt>"}`: three base64url parts.
pub fn parse_oidc_response(body: []const u8) Error![]const u8 {
    const key = "\"value\"";
    const at = std.mem.indexOf(u8, body, key) orelse return error.JsonWrong;
    var rest = std.mem.trimStart(u8, body[at + key.len ..], " \t\r\n");
    if (rest.len == 0 or rest[0] != ':') return error.JsonWrong;
    rest = std.mem.trimStart(u8, rest[1..], " \t\r\n");
    if (rest.len == 0 or rest[0] != '"') return error.JsonWrong;
    const end = std.mem.indexOfScalarPos(u8, rest, 1, '"') orelse return error.JsonWrong;
    const token = rest[1..end];
    if (token.len < scan.needle_bytes_min) return error.JsonWrong;
    if (token.len > scan.needle_bytes_max) return error.JsonWrong;
    for (token) |byte| if (!is_jwt_byte(byte)) return error.JsonWrong;
    if (std.mem.count(u8, token, ".") != 2) return error.JsonWrong;
    assert(token.len <= body.len);
    return token;
}

/// Whether a token fetched at `fetched_ms` may still be used at `now_ms`.
pub fn oidc_fresh(fetched_ms: u64, now_ms: u64) bool {
    assert(oidc_fresh_ms > 0);
    if (now_ms < fetched_ms) return false;
    return now_ms - fetched_ms < oidc_fresh_ms;
}

/// The external_account file zbx reads (`GOOGLE_APPLICATION_CREDENTIALS`): the subject token from
/// `token_path`, exchanged at STS for `//iam.googleapis.com/<provider>`, and impersonating
/// `service_account` unless it is empty. No secret is in it.
pub fn render_external_account(
    buffer: []u8,
    config: Config,
    token_path: []const u8,
    impersonate: bool,
) ![]u8 {
    assert(token_path.len > 0);
    assert(token_path[0] == '/');
    var writer: std.Io.Writer = .fixed(buffer);
    try writer.print(
        "{{\"type\":\"external_account\",\"audience\":\"//iam.googleapis.com/{s}\"," ++
            "\"subject_token_type\":\"urn:ietf:params:oauth:token-type:jwt\"," ++
            "\"token_url\":\"https://sts.googleapis.com/v1/token\"," ++
            "\"credential_source\":{{\"file\":\"{s}\"}}",
        .{ config.provider, token_path },
    );
    if (impersonate) {
        assert(config.service_account.len > 0);
        try writer.print(
            ",\"service_account_impersonation_url\":\"https://iamcredentials.googleapis.com/" ++
                "v1/projects/-/serviceAccounts/{s}:generateAccessToken\"",
            .{config.service_account},
        );
    }
    try writer.writeAll("}\n");
    return writer.buffered();
}

/// Masks every token shape and named secret (m6d_fixture/mask.zig): the guest helper prints
/// zbx's output through it, so the console, which the job log copies, never carries a token.
pub const mask_secrets = mask.mask_secrets;

// ---- The steps -------------------------------------------------------------------------------

fn has(text: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, text, needle) != null;
}

/// A refusal with `code`: exit `exit_code`, nothing on stdout, the coded first line.
fn expect_refusal(streams: Streams, status: u8, exit_code: u8, code: []const u8) Error!void {
    assert(code.len > 0);
    if (status != exit_code) return error.ExitCodeWrong;
    if (std.mem.trim(u8, streams.stdout, " \r\n").len != 0) return error.RefusalWrong;
    if (!std.mem.startsWith(u8, streams.stderr, "error[ZBX-")) return error.RefusalWrong;
    if (!has(streams.stderr[0..@min(streams.stderr.len, 24)], code)) return error.RefusalWrong;
    if (has(streams.stderr, "errno")) return error.RefusalWrong;
}

/// Step 1: no credentials. E0560 (exit 2), naming both sources and the fix.
pub fn check_no_credentials(streams: Streams, status: u8, registry_host: []const u8) Error!void {
    assert(registry_host.len > 0);
    try expect_refusal(streams, status, 2, "E0560");
    const wanted = [_][]const u8{
        "no Google credentials were found",
        registry_host,
        "GOOGLE_APPLICATION_CREDENTIALS",
        "Google Compute Engine",
    };
    for (wanted) |text| if (!has(streams.stderr, text)) return error.RefusalWrong;
}

/// Steps 2 and 3: the pull prints the manifest digest alone and exits 0.
pub const check_pull = checks_m4.check_pull;

/// Step 2: `zbx run` of the image prints `hello`.
pub fn check_hello(streams: Streams, status: u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!std.mem.eql(u8, std.mem.trim(u8, streams.stdout, " \r\n"), "hello")) {
        return error.OutputWrong;
    }
}

/// `zbx.lock` names the reference and the digest the pull printed.
pub fn check_lock(lock: []const u8, reference: []const u8, digest: []const u8) Error!void {
    assert(checks_m4.is_manifest_digest(digest));
    assert(reference.len > 0);
    if (!has(lock, reference)) return error.DigestWrong;
    if (!has(lock, digest)) return error.DigestWrong;
}

/// Step 4: the repository the identity may not read: E0568 (exit 1), naming the repository and
/// the permission.
pub fn check_denied(streams: Streams, status: u8, repository: []const u8) Error!void {
    assert(repository.len > 0);
    try expect_refusal(streams, status, 1, "E0568");
    if (!has(streams.stderr, repository)) return error.RefusalWrong;
    const permission = "artifactregistry.repositories.downloadArtifacts";
    if (!has(streams.stderr, permission)) return error.RefusalWrong;
}

/// What the agent (the library path) prints: one JSON document, nothing else.
pub const AgentDoc = struct {
    schema: []const u8,
    reference: []const u8,
    manifest_digest: []const u8,
    tree: []const u8,
    token_source: []const u8,
};

/// The agent pulled `reference` with a token it resolved itself (workload identity), to the
/// same manifest and tree the command line's pull named.
pub fn check_agent(
    arena: std.mem.Allocator,
    streams: Streams,
    status: u8,
    reference: []const u8,
    cli: checks_m4.PullDoc,
) Error!void {
    assert(reference.len > 0);
    assert(checks_m3.is_digest(cli.tree)); // check_pull checked it.
    if (status != 0) return error.ExitCodeWrong;
    const doc = checks_m4.parse_json(AgentDoc, arena, streams.stdout) catch return error.JsonWrong;
    if (!std.mem.eql(u8, doc.schema, "zbx-demo.m6d-agent/1")) return error.JsonWrong;
    if (!std.mem.eql(u8, doc.reference, reference)) return error.JsonWrong;
    if (!std.mem.eql(u8, doc.token_source, "workload_identity")) return error.JsonWrong;
    if (!std.mem.eql(u8, doc.manifest_digest, cli.manifest_digest)) return error.DigestWrong;
    if (!std.mem.eql(u8, doc.tree, cli.tree)) return error.DigestWrong;
}

/// Whether `text` carries anything token-shaped: a searched shape, a JWT's start, or the mask's
/// mark (the harness reads the helper only through the mask).
fn has_token_shape(text: []const u8) bool {
    for (scan.shapes) |prefix| if (has(text, prefix)) return true;
    if (has(text, "eyJ")) return true;
    return has(text, mask.mask_text);
}

/// One line of the helper's shape check: `shapes: <label> token: google_access, <n> bytes`, with
/// bytes after the `ya29.` prefix.
fn check_shape_line(line: []const u8, label: []const u8) Error!void {
    assert(label.len > 0);
    assert(label.len <= 32);
    var buffer: [shape.line_bytes_max]u8 = undefined;
    const head = std.fmt.bufPrint(&buffer, "shapes: {s} token: {t}, ", .{
        label, shape.Class.google_access,
    }) catch unreachable; // 8 + 32 + 9 + 13 + 2 bytes at most, under line_bytes_max.
    if (!std.mem.startsWith(u8, line, head)) return error.OutputWrong;
    const rest = line[head.len..];
    const tail = " bytes";
    if (!std.mem.endsWith(u8, rest, tail)) return error.OutputWrong;
    const count = std.fmt.parseInt(u32, rest[0 .. rest.len - tail.len], 10) catch
        return error.OutputWrong;
    if (count <= scan.shapes[0].len) return error.OutputWrong;
}

/// The helper's shape check: the federated token (and, when impersonating, the access token) has
/// the class step 5 searches by shape. One line per token, its class and length, and nothing
/// token-shaped: no prefix, no byte of a token.
pub fn check_shapes(streams: Streams, status: u8, impersonate: bool) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (streams.stderr.len != 0) return error.OutputWrong;
    if (has_token_shape(streams.stdout)) return error.SecretFound;
    var lines = std.mem.splitScalar(u8, std.mem.trim(u8, streams.stdout, " \r\n"), '\n');
    try check_shape_line(std.mem.trimEnd(u8, lines.first(), "\r"), "federated");
    if (impersonate) {
        const access = lines.next() orelse return error.OutputWrong;
        try check_shape_line(std.mem.trimEnd(u8, access, "\r"), "access");
    }
    if (lines.next() != null) return error.OutputWrong;
}

/// The count on the helper's `<prefix><number>...` line, or null without one.
fn count_after(line: []const u8, prefix: []const u8) ?u64 {
    assert(prefix.len > 0);
    if (!std.mem.startsWith(u8, line, prefix)) return null;
    const rest = line[prefix.len..];
    const end = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
    return std.fmt.parseInt(u64, rest[0..end], 10) catch null;
}

/// The files the helper searched under `root`: its `root <root> files <n>` line, or null.
fn root_files(stdout: []const u8, root: []const u8) ?u64 {
    assert(root.len > 0);
    var buffer: [256]u8 = undefined;
    const prefix = std.fmt.bufPrint(&buffer, "root {s} files ", .{root}) catch return null;
    var lines = std.mem.splitScalar(u8, stdout, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r");
        if (count_after(line, prefix)) |files| return files;
    }
    return null;
}

/// Step 5: the helper searched for `needles_min` or more needles, under every one of `roots`
/// (each reported, none skipped), at least one file under each of `nonempty`, and found none.
pub fn check_scan(
    streams: Streams,
    status: u8,
    needles_min: u32,
    roots: []const []const u8,
    nonempty: []const []const u8,
) Error!void {
    assert(roots.len > 0);
    if (status != 0) return error.SecretFound;
    if (has(streams.stdout, "HIT ")) return error.SecretFound;
    var lines = std.mem.splitScalar(u8, streams.stdout, '\n');
    var clean = false;
    var needles: u64 = 0;
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r");
        if (std.mem.eql(u8, line, "scan: clean")) clean = true;
        if (count_after(line, "needles ")) |count| needles = count;
    }
    if (!clean) return error.SecretFound;
    if (needles < needles_min) return error.SecretFound;
    for (roots) |root| {
        if (root_files(streams.stdout, root) == null) return error.SecretFound;
    }
    for (nonempty) |root| {
        const files = root_files(streams.stdout, root) orelse return error.SecretFound;
        if (files == 0) return error.SecretFound;
    }
}

test {
    _ = @import("checks_m6d_tests.zig");
}
