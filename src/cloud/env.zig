//! The environment a credential resolver reads, as its caller sees it: name and value pairs,
//! handed in so a caller that holds different settings per workload (or none in its own process)
//! is not bound to the process's. Each provider fixes the names it reads (`CredentialEnv`); only
//! those are ever looked at. AWS's `Env` and Google's `Env` are both this shape (M6d).

const std = @import("std");
const assert = std.debug.assert;
const host_mod = @import("../host.zig");

/// One variable. Every provider's `Env.Pair` is this type.
pub const EnvPair = struct { name: []const u8, value: []const u8 };

/// The environment view for a provider that reads the variables `list`.
pub fn CredentialEnv(comptime list: []const []const u8) type {
    comptime assert(list.len > 0);
    return struct {
        pairs: []const EnvPair,

        const Env = @This();
        pub const Pair = EnvPair;

        /// The names the provider's resolver reads.
        pub const names: [list.len][]const u8 = list[0..list.len].*;

        /// The value of `name`, whole whatever its length, or null if not set. An empty value
        /// counts as not set, as the AWS SDKs and Google's client libraries read it
        /// (docs/decisions/2026-11-10-aws-empty-env-is-unset.md).
        pub fn get(env: Env, name: []const u8) ?[]const u8 {
            assert(name.len > 0);
            for (env.pairs) |pair| {
                if (!std.mem.eql(u8, pair.name, name)) continue;
                if (pair.value.len == 0) return null;
                return pair.value;
            }
            return null;
        }

        /// The caller's view of this process, for the CLI: each name in `names` that the host
        /// has, in `storage`, whole whatever its length (the host hands out a slice of its own
        /// memory, so reading a long value copies nothing). A value over its bound reaches the
        /// resolver as it is and is refused there, not cut or dropped.
        pub fn from_host(host: host_mod.Host, storage: *[names.len]Env.Pair) Env {
            var count: u32 = 0;
            inline for (names) |name| {
                if (host.environment(name, std.math.maxInt(u32))) |value| {
                    storage[count] = .{ .name = name, .value = value };
                    count += 1;
                }
            }
            assert(count <= names.len);
            return .{ .pairs = storage[0..count] };
        }
    };
}
