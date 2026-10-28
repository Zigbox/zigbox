//! `Diag`: the per-operation collector behind every user-facing failure (DIAGNOSTICS.md,
//! "Implementation in Zig"). Zig error sets carry no payload, so a function that can fail across
//! a module boundary returns a plain error and takes a `*Diag`: the error says THAT it failed,
//! the `Diag` says WHY.
//!
//!   - The layer that knows what kind of failure it is calls `raise(code)`, exactly once.
//!   - Inner layers add `cause(...)`s, in the order they are discovered. The first is usually
//!     the symptom (a syscall failed), the last is the real cause ("AppArmor restricts ..."), and
//!     the last is the one default output shows.
//!   - Outer layers add `while_(...)` ("starting container web-1") and `context(...)` pairs as
//!     the error propagates, so `while_` entries arrive innermost first; they are shown
//!     outermost first.
//!   - `fix(...)` adds a concrete next step, with a runnable command where there is one.
//!
//! Nothing here formats text for the user: `render.zig` does that, only at the CLI boundary.
//!
//! The collector is fixed-size and never allocates. Every bound is in `constants.zig`. Past a
//! bound nothing crashes: text is cut and ends in "...", and items that do not fit are counted
//! and shown as an omitted note. Which item survives is deliberate: the newest cause and the
//! newest `while_` replace the last slot (the real cause must never be lost), while context and
//! fixes keep the oldest (the first fix is the most specific).
//!
//! Every byte stored is printable ASCII: anything else (including bytes of an untrusted file or
//! argument) becomes '?' on the way in, so no layer above can emit a terminal escape.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const codes = @import("codes.zig");
const text_util = @import("../text.zig");

pub const Text = text_util.Bounded(constants.diag_field_bytes_max);
pub const Command = text_util.Bounded(constants.diag_command_bytes_max);

pub const Pair = struct {
    /// Lower-case ASCII letters, at most `diag_key_bytes_max`.
    key: [constants.diag_key_bytes_max]u8,
    key_len: u8,
    value: Text,

    pub fn key_slice(pair: *const Pair) []const u8 {
        assert(pair.key_len > 0);
        assert(pair.key_len <= constants.diag_key_bytes_max);
        return pair.key[0..pair.key_len];
    }
};

pub const Fix = struct {
    sentence: Text,
    /// Empty when the fix is not a command.
    command: Command,
    /// The command needs administrator rights (JSON `needs_root`). `Diag.fix` also sets it for
    /// any command that starts with `sudo`, so the flag cannot disagree with the text.
    needs_root: bool,
    /// The command is an example to adapt, not to run as written (JSON `template`).
    template: bool,
};

pub const FixOptions = struct {
    sentence: []const u8,
    command: []const u8 = "",
    needs_root: bool = false,
    template: bool = false,
};

/// True if a command runs `sudo` at its start or after a pipe or `&&`.
pub fn command_uses_sudo(command: []const u8) bool {
    assert(command.len <= constants.diag_command_bytes_max * 4);
    if (std.mem.startsWith(u8, command, "sudo ")) return true;
    if (std.mem.indexOf(u8, command, "| sudo ") != null) return true;
    return std.mem.indexOf(u8, command, "&& sudo ") != null;
}

/// Which end of a full list survives a new item.
const Keep = enum { oldest, newest };

fn List(comptime Item: type, comptime capacity: u32, comptime keep: Keep) type {
    comptime assert(capacity > 0);
    return struct {
        const Self = @This();
        items: [capacity]Item = undefined,
        count: u32 = 0,
        /// Items that did not fit (or that replaced the last slot). Shown as an omitted note.
        omitted: u32 = 0,

        fn reset(list: *Self) void {
            list.count = 0;
            list.omitted = 0;
            assert(list.slice().len == 0);
        }

        /// The slot to fill, or null if the list is full and keeps its oldest items. The
        /// caller initialises the slot completely.
        fn next(list: *Self) ?*Item {
            assert(list.count <= capacity);
            if (list.count == capacity) {
                assert(list.omitted < std.math.maxInt(u32));
                list.omitted += 1;
                if (keep == .oldest) return null;
                return &list.items[capacity - 1];
            }
            list.count += 1;
            assert(list.count <= capacity);
            return &list.items[list.count - 1];
        }

        pub fn slice(list: *const Self) []const Item {
            assert(list.count <= capacity);
            if (list.omitted > 0) assert(list.count == capacity);
            return list.items[0..list.count];
        }
    };
}

/// The list types of a collector, named so that `Diagnostic` (a finished, plain copy) has the
/// same ones.
pub const Causes = List(Text, constants.diag_causes_count_max, .newest);
pub const Whiles = List(Text, constants.diag_whiles_count_max, .newest);
pub const Pairs = List(Pair, constants.diag_context_count_max, .oldest);
pub const Fixes = List(Fix, constants.diag_fixes_count_max, .oldest);
pub const Saved = text_util.Bounded(constants.state_path_bytes_max + 128);

/// Words the renderer uses as labels of its own, so a context key may not be one.
pub const reserved_keys = [_][]const u8{ "while", "cause", "fix", "more", "report" };

pub const Diag = struct {
    code: ?codes.Code,
    causes: Causes,
    whiles: Whiles,
    pairs: Pairs,
    fixes: Fixes,
    /// The path of the bundle written for this bug, empty for none. Only a bug has one.
    saved: Saved,
    /// Set only on ZBX-E0202, when the cause is a command that was not found: a container run
    /// then exits 127 where a command that cannot be run exits 126.
    command_missing: bool,

    /// Initialises in place: the struct is several kilobytes.
    pub fn reset(diag: *Diag) void {
        diag.code = null;
        diag.causes.reset();
        diag.whiles.reset();
        diag.pairs.reset();
        diag.fixes.reset();
        diag.saved = .{};
        diag.command_missing = false;
        assert(diag.saved.len == 0);
        assert(diag.causes.count == 0);
        assert(diag.code == null);
    }

    /// Says that the E0202 being built is a command that was not found.
    pub fn mark_command_missing(diag: *Diag) void {
        assert(diag.code != null);
        assert(diag.code.? == .E0202);
        diag.command_missing = true;
    }

    /// Records where the bundle for this bug was written.
    pub fn save_bundle(diag: *Diag, path: []const u8) void {
        assert(diag.code != null);
        assert(path.len > 0);
        diag.saved = .{};
        diag.saved.print("{s}", .{path});
        assert(diag.saved.len > 0);
    }

    /// Classifies the failure. Once per diagnostic: two classifications would mean two layers
    /// each believe they own the failure, and the user would see only one of them.
    pub fn raise(diag: *Diag, code: codes.Code) void {
        assert(diag.code == null);
        diag.code = code;
        assert(diag.code.? == code);
    }

    pub fn cause(diag: *Diag, comptime format: []const u8, args: anytype) void {
        const slot = diag.causes.next().?; // `.newest` lists always have a slot.
        slot.* = .{};
        put(slot, format, args);
        assert(slot.len > 0);
        assert(slot.len <= constants.diag_field_bytes_max);
        assert(diag.causes.count > 0);
    }

    pub fn while_(diag: *Diag, comptime format: []const u8, args: anytype) void {
        const slot = diag.whiles.next().?; // `.newest` lists always have a slot.
        slot.* = .{};
        put(slot, format, args);
        assert(slot.len > 0);
        assert(slot.len <= constants.diag_field_bytes_max);
        assert(diag.whiles.count > 0);
    }

    /// Adds a labelled fact, for example `diag.context("path", "{s}", .{path})`. The key is a
    /// comptime string so that a bad one does not compile.
    pub fn context(
        diag: *Diag,
        comptime key: []const u8,
        comptime format: []const u8,
        args: anytype,
    ) void {
        comptime check_key(key);
        const slot = diag.pairs.next() orelse return;
        slot.key = @splat(0);
        @memcpy(slot.key[0..key.len], key);
        slot.key_len = key.len;
        slot.value = .{};
        put(&slot.value, format, args);
        assert(slot.value.len > 0);
        assert(slot.key_len == key.len);
        assert(diag.pairs.count > 0);
    }

    pub fn fix(diag: *Diag, options: FixOptions) void {
        assert(options.sentence.len > 0);
        assert(options.command.len <= constants.diag_command_bytes_max * 4); // Cut by `put`.
        const slot = diag.fixes.next() orelse return;
        slot.sentence = .{};
        slot.command = .{};
        put(&slot.sentence, "{s}", .{options.sentence});
        if (options.command.len > 0) put(&slot.command, "{s}", .{options.command});
        slot.needs_root = options.needs_root or command_uses_sudo(options.command);
        slot.template = options.template;
        assert(slot.sentence.len > 0);
        // A flag on a prose-only fix would describe a command that is not there.
        if (slot.command.len == 0) assert(!slot.needs_root);
        if (slot.command.len == 0) assert(!slot.template);
    }

    /// A fix whose command is built from run-time text, for example the name of the command that
    /// was misused. The sentence is fixed prose; the command is formatted and sanitised.
    pub fn fix_with(
        diag: *Diag,
        sentence: []const u8,
        comptime command_format: []const u8,
        command_args: anytype,
    ) void {
        assert(sentence.len > 0);
        const slot = diag.fixes.next() orelse return;
        slot.sentence = .{};
        slot.command = .{};
        put(&slot.sentence, "{s}", .{sentence});
        put(&slot.command, command_format, command_args);
        slot.needs_root = command_uses_sudo(slot.command.slice());
        slot.template = false;
        assert(slot.command.len > 0);
    }

    /// Marks the fix just added as an example to adapt (a `fix_with` command holds a placeholder).
    pub fn mark_last_fix_template(diag: *Diag) void {
        if (diag.fixes.count == 0) return;
        if (diag.fixes.omitted > 0) return; // The fix just added was dropped.
        const slot = &diag.fixes.items[diag.fixes.count - 1];
        if (slot.command.len == 0) return;
        slot.template = true;
    }

    /// The registry entry for the classified code. Asserts that `raise` was called.
    pub fn entry(diag: *const Diag) *const codes.Entry {
        assert(diag.code != null);
        const found = codes.entry(diag.code.?);
        assert(found.summary.len > 0);
        return found;
    }

    /// The process exit code for this failure in the standard scope: the code's blame decides.
    pub fn exit_code(diag: *const Diag) u8 {
        assert(diag.code != null);
        return diag.exit_code_in(.standard);
    }

    /// The process exit code for this failure in `scope`, from the code (and, for E0202, whether
    /// the command was missing) and nothing else: `codes.exit_code_in` is the one mapping.
    pub fn exit_code_in(diag: *const Diag, scope: codes.ExitScope) u8 {
        assert(diag.code != null);
        const exit = codes.exit_code_in(scope, diag.code.?, diag.command_missing);
        assert(exit != constants.exit_ok);
        return exit;
    }

    /// The diagnostic as plain lines, for a pipe: the code, then one line per item, fields
    /// separated by a tab (text is printable ASCII, so neither tab nor newline is in it). The
    /// store's worker (a child in a user namespace) sends its failure this way, and the caller
    /// gets the same diagnostic back with `decode`.
    pub fn encode(diag: *const Diag, out: *[constants.diag_carry_bytes_max]u8) []const u8 {
        assert(diag.code != null);
        var writer = std.Io.Writer.fixed(out);
        // Cannot fail: the buffer holds the most a diagnostic can be (checked below).
        writer.print("{s}\n", .{codes.full_name(diag.code.?)}) catch unreachable;
        for (diag.whiles.slice()) |item| {
            writer.print("w\t{s}\n", .{item.slice()}) catch unreachable; // Same bound.
        }
        for (diag.causes.slice()) |item| {
            writer.print("c\t{s}\n", .{item.slice()}) catch unreachable; // Same bound.
        }
        for (diag.pairs.slice()) |item| {
            writer.print("k\t{s}\t{s}\n", .{ item.key_slice(), item.value.slice() }) catch
                unreachable;
        }
        for (diag.fixes.slice()) |item| {
            writer.print("f\t{s}\t{s}", .{ item.sentence.slice(), item.command.slice() }) catch
                unreachable;
            // The flags follow the command after a third tab, only when one is set.
            if (item.needs_root or item.template) {
                const flags: []const u8 = if (item.needs_root and item.template)
                    "rt"
                else if (item.needs_root) "r" else "t";
                writer.print("\t{s}", .{flags}) catch unreachable; // Same bound.
            }
            writer.writeByte('\n') catch unreachable; // Same bound.
        }
        return writer.buffered();
    }

    /// Reads what `encode` wrote into a fresh collector. False if the bytes are not that.
    pub fn decode(diag: *Diag, bytes: []const u8) bool {
        assert(diag.code == null);
        var lines = std.mem.splitScalar(u8, bytes, '\n');
        const first = lines.next() orelse return false;
        diag.code = codes.parse(first) orelse return false;
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            if (line.len < 3 or line[1] != '\t') return false;
            const rest = line[2..];
            switch (line[0]) {
                'w' => diag.while_("{s}", .{rest}),
                'c' => diag.cause("{s}", .{rest}),
                'k' => {
                    const tab = std.mem.indexOfScalar(u8, rest, '\t') orelse return false;
                    if (tab == 0 or tab > constants.diag_key_bytes_max) return false;
                    const slot = diag.pairs.next() orelse continue;
                    slot.key = @splat(0);
                    @memcpy(slot.key[0..tab], rest[0..tab]);
                    slot.key_len = @intCast(tab);
                    slot.value = .{};
                    put(&slot.value, "{s}", .{rest[tab + 1 ..]});
                },
                'f' => {
                    const tab = std.mem.indexOfScalar(u8, rest, '\t') orelse return false;
                    if (tab == 0) return false;
                    var command = rest[tab + 1 ..];
                    var flags: []const u8 = "";
                    if (std.mem.indexOfScalar(u8, command, '\t')) |second| {
                        flags = command[second + 1 ..];
                        command = command[0..second];
                    }
                    const known = std.mem.eql(u8, flags, "") or std.mem.eql(u8, flags, "r") or
                        std.mem.eql(u8, flags, "t") or std.mem.eql(u8, flags, "rt");
                    if (!known) return false;
                    diag.fix(.{
                        .sentence = rest[0..tab],
                        .command = command,
                        .needs_root = std.mem.indexOfScalar(u8, flags, 'r') != null,
                        .template = std.mem.indexOfScalar(u8, flags, 't') != null,
                    });
                },
                else => return false,
            }
        }
        return diag.causes.count > 0;
    }

    /// The newest cause: the one default output shows. Null if none was added.
    pub fn last_cause(diag: *const Diag) ?[]const u8 {
        assert(diag.causes.count <= constants.diag_causes_count_max);
        if (diag.causes.count == 0) return null;
        const text = diag.causes.items[diag.causes.count - 1].slice();
        assert(text.len > 0);
        return text;
    }
};

fn check_key(comptime key: []const u8) void {
    comptime {
        assert(key.len > 0);
        assert(key.len <= constants.diag_key_bytes_max);
        for (key) |byte| assert(std.ascii.isLower(byte));
        for (reserved_keys) |word| assert(!std.mem.eql(u8, key, word));
    }
}

/// Appends formatted text to a field and makes the new bytes safe to show. A field that
/// overflows ends in "..." (Bounded does that); the sanitising pass runs on what was added.
fn put(field: anytype, comptime format: []const u8, args: anytype) void {
    const start = field.len;
    field.print(format, args);
    assert(field.len >= start);
    for (field.bytes[start..field.len]) |*byte| {
        if (!text_util.is_printable(byte.*)) byte.* = '?';
    }
    // A field is never empty, so no renderer has to cope with a labelled nothing.
    if (field.len == 0) field.print("(empty)", .{});
    assert(field.len > 0);
}

const testing = std.testing;
const repeat = @import("../test_util.zig").repeat;

test "a diagnostic collects causes, whiles, context and fixes in order" {
    // Goal: the data model of the standard. Causes keep insertion order (symptom first, real
    // cause last), the exit code follows the blame, and the last cause is what default shows.
    var diag: Diag = undefined;
    diag.reset();
    try testing.expect(diag.code == null);
    try testing.expect(diag.last_cause() == null);
    diag.raise(.E0001);
    diag.cause("symptom {d}", .{1});
    diag.cause("real cause", .{});
    diag.while_("doing {s}", .{"a thing"});
    diag.context("path", "{s}", .{"/x"});
    diag.fix(.{ .sentence = "do this:", .command = "zbx help" });
    diag.fix(.{ .sentence = "or just think" });

    try testing.expectEqual(@as(u8, constants.exit_user), diag.exit_code());
    try testing.expectEqualStrings("real cause", diag.last_cause().?);
    try testing.expectEqualStrings("symptom 1", diag.causes.slice()[0].slice());
    try testing.expectEqualStrings("doing a thing", diag.whiles.slice()[0].slice());
    try testing.expectEqualStrings("path", diag.pairs.slice()[0].key_slice());
    try testing.expectEqualStrings("zbx help", diag.fixes.slice()[0].command.slice());
    try testing.expectEqual(@as(usize, 0), diag.fixes.slice()[1].command.slice().len);
}

test "text is sanitised on the way in and cut with a marker at the bound" {
    // Goal: the negative space. Control bytes and non-ASCII never reach a renderer; a field one
    // byte over its bound ends in "..." and one at the bound does not.
    var diag: Diag = undefined;
    diag.reset();
    diag.raise(.E0001);
    diag.cause("a{s}b", .{"\x1b[31m\xff\x00"});
    try testing.expectEqualStrings("a?[31m??b", diag.last_cause().?);

    const exact = repeat('x', constants.diag_field_bytes_max);
    diag.cause("{s}", .{exact});
    try testing.expectEqualStrings(exact, diag.last_cause().?);
    diag.cause("{s}y", .{exact});
    const cut = diag.last_cause().?;
    try testing.expectEqual(@as(usize, constants.diag_field_bytes_max), cut.len);
    try testing.expect(std.mem.endsWith(u8, cut, "..."));
}

test "lists keep the newest cause and the oldest fix when full" {
    // Goal: the overflow policy. Past the bound the real (newest) cause still shows, the count
    // of what did not fit is exact, and nothing is written outside the arrays.
    var diag: Diag = undefined;
    diag.reset();
    diag.raise(.E0001);
    const extra = 3;
    for (0..constants.diag_causes_count_max + extra) |index| {
        diag.cause("cause {d}", .{index});
    }
    try testing.expectEqual(@as(u32, constants.diag_causes_count_max), diag.causes.count);
    try testing.expectEqual(@as(u32, extra), diag.causes.omitted);
    try testing.expectEqualStrings("cause 8", diag.last_cause().?);
    try testing.expectEqualStrings("cause 0", diag.causes.slice()[0].slice());

    for (0..constants.diag_fixes_count_max + extra) |index| {
        diag.fix(.{ .sentence = "fix", .command = if (index == 0) "first" else "later" });
    }
    try testing.expectEqual(@as(u32, constants.diag_fixes_count_max), diag.fixes.count);
    try testing.expectEqual(@as(u32, extra), diag.fixes.omitted);
    try testing.expectEqualStrings("first", diag.fixes.slice()[0].command.slice());

    for (0..constants.diag_context_count_max + 1) |_| diag.context("k", "v", .{});
    try testing.expectEqual(@as(u32, 1), diag.pairs.omitted);
}

test "reset clears everything, including the code" {
    var diag: Diag = undefined;
    diag.reset();
    diag.raise(.B0001);
    diag.cause("x", .{});
    diag.reset();
    try testing.expect(diag.code == null);
    try testing.expectEqual(@as(u32, 0), diag.causes.count);
    diag.raise(.E0002); // Allowed again: reset starts a new diagnostic.
    try testing.expectEqual(@as(u8, constants.exit_user), diag.exit_code());
}

test "a diagnostic crosses a pipe as lines and comes back the same" {
    // Goal: the store's worker can report a failure whole. Method: a diagnostic with every kind
    // of item, encoded and decoded, rendered the same; and bytes that are not one are refused.
    var diag: Diag = undefined;
    diag.reset();
    diag.raise(.E0416);
    diag.while_("writing the store", .{});
    diag.cause("write failed: no space left on the device (ENOSPC)", .{});
    diag.cause("2 objects were written", .{});
    diag.context("path", "{s}", .{"/home/alice/.local/share/zbx/store"});
    diag.fix(.{ .sentence = "free space:", .command = "df -h '/home/alice'" });
    diag.fix(.{ .sentence = "then run it again" });
    var buffer: [constants.diag_carry_bytes_max]u8 = undefined;
    const bytes = diag.encode(&buffer);
    var back: Diag = undefined;
    back.reset();
    try testing.expect(back.decode(bytes));
    try testing.expectEqual(diag.code, back.code);
    try testing.expectEqualStrings(diag.last_cause().?, back.last_cause().?);
    try testing.expectEqual(diag.causes.count, back.causes.count);
    try testing.expectEqual(diag.fixes.count, back.fixes.count);
    try testing.expectEqualStrings("df -h '/home/alice'", back.fixes.items[0].command.slice());
    try testing.expectEqualStrings("path", back.pairs.items[0].key_slice());
    var other: Diag = undefined;
    other.reset();
    try testing.expect(!other.decode("not a diagnostic\n"));
    other.reset();
    try testing.expect(!other.decode("ZBX-E0416\nx\tbad\n"));
}
