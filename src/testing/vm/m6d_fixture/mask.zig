//! Masking for demo-m6d: the guest helper prints zbx's saved output only through `mask_secrets`,
//! because the harness copies the whole guest console into the job log. Every run shaped like a
//! token (a Google access or federated token, the registry realm's Basic value, a JWT) and every
//! named secret (the OIDC tokens the harness served) becomes `[masked]`. Pure; the harness's unit
//! tests feed it text (checks_m6d_tests.zig).

const std = @import("std");
const assert = std.debug.assert;
const scan = @import("scan.zig");

pub const mask_text = "[masked]";
/// The shortest run masked: a shape, or a named secret, is at least this long, so the output is
/// at most `mask_text.len / mask_run_min` times the input.
const mask_run_min = scan.needle_bytes_min;
/// The shortest JWT masked by its shape: three base64url parts and two dots.
const jwt_bytes_min = 40;

pub fn is_jwt_byte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '_' or byte == '.';
}

fn is_token_byte(byte: u8) bool {
    return is_jwt_byte(byte) or byte == '+' or byte == '/' or byte == '=';
}

/// The room `mask_secrets` needs for `text_len` bytes of input.
pub fn out_bytes(text_len: usize) usize {
    comptime assert(mask_text.len < 2 * mask_run_min);
    return 2 * text_len;
}

/// The length of a token-shaped run at `text[at..]`: one starting with a searched shape, or a
/// JWT (`eyJ`, two dots, at least `jwt_bytes_min` bytes); 0 for none.
fn token_run(text: []const u8, at: usize) usize {
    assert(at < text.len);
    const rest = text[at..];
    var end: usize = 0;
    while (end < rest.len and is_token_byte(rest[end])) end += 1;
    const run = rest[0..end];
    for (scan.shapes) |shape| if (std.mem.startsWith(u8, run, shape)) return end;
    if (std.mem.startsWith(u8, run, "eyJ")) {
        if (end >= jwt_bytes_min and std.mem.count(u8, run, ".") == 2) return end;
    }
    return 0;
}

/// The length of the named secret at `text[at..]`, wherever it starts; 0 for none.
fn secret_run(text: []const u8, at: usize, secrets: []const []const u8) usize {
    assert(at < text.len);
    for (secrets) |secret| {
        assert(secret.len >= mask_run_min);
        if (std.mem.startsWith(u8, text[at..], secret)) return secret.len;
    }
    return 0;
}

/// Copies `text` to `out` with every named secret, and every token-shaped run that starts a word,
/// replaced by `[masked]`. `out` holds at least `out_bytes(text.len)`.
pub fn mask_secrets(text: []const u8, secrets: []const []const u8, out: []u8) []const u8 {
    assert(out.len >= out_bytes(text.len));
    var length: usize = 0;
    var at: usize = 0;
    while (at < text.len) {
        // A shape only at the start of a word: a token never follows a letter or a digit.
        const starts_word = at == 0 or !std.ascii.isAlphanumeric(text[at - 1]);
        var run = secret_run(text, at, secrets);
        if (run == 0 and starts_word) run = token_run(text, at);
        if (run > 0) {
            assert(run >= mask_run_min);
            @memcpy(out[length..][0..mask_text.len], mask_text);
            length += mask_text.len;
            at += run;
        } else {
            out[length] = text[at];
            length += 1;
            at += 1;
        }
    }
    assert(length <= out_bytes(text.len));
    return out[0..length];
}
