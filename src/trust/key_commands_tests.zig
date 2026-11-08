//! Tests of `zbx key new|list|show` against the simulated host: what each writes and prints, the
//! ways a passphrase can arrive or fail to, and that nothing is read from standard input unless
//! it is a terminal. The diagnostics' own text is in the golden tests.

const std = @import("std");
const cli = @import("../cli.zig");
const codes = @import("../diag/codes.zig");
const Diag = @import("../diag/diag.zig").Diag;
const host_sim = @import("../host_sim.zig");
const key = @import("key.zig");
const constants = @import("../constants.zig");
const key_commands = @import("key_commands.zig");
const sim_run = @import("../runtime/sim_run.zig");
const fs_sim = @import("../store/fs_sim.zig");

const testing = std.testing;

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;

const directory = "/home/alice/.config/zbx/keys";
/// Cheap enough for a debug build; the product's cost is in the constants and the demo.
const cheap: key_commands.Cost = .{ .t = 1, .m_kib = 8, .p = 1 };

fn start() void {
    sim_run.init(&sim, 1);
    files.init(1);
    sim.store_fs = &files;
    files.put_dir("/home", 0o755);
    files.put_dir("/home/alice", 0o755);
}

/// Runs `zbx <args>` (the product's cost) and returns the exit code.
fn command(args: []const [:0]const u8) u8 {
    var items: [12][:0]const u8 = undefined;
    items[0] = "zbx";
    @memcpy(items[1 .. 1 + args.len], args);
    sim.stdout_len = 0;
    sim.stderr_len = 0;
    return sim_run.run_cli(&sim, items[0 .. 1 + args.len]);
}

/// Runs the key command directly at the cheap cost; the code of the diagnostic, if it refused.
fn direct(args: key_commands.Args, json: bool) ?codes.Code {
    var diag: Diag = undefined;
    diag.reset();
    sim.stdout_len = 0;
    sim.stderr_len = 0;
    const code = key_commands.run(sim.interface(), args, .{ .json = json }, cheap, &diag) catch
        return diag.code.?;
    std.debug.assert(code == 0);
    return null;
}

fn has(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}

/// (Re)writes the passphrase file.
fn put_pass(mode: u16, content: []const u8) void {
    if (files.kind_of("/home/alice/pass") != null) files.remove_path("/home/alice/pass");
    files.put_file("/home/alice/pass", mode, content);
}

fn long_line(comptime count: usize) *const [count]u8 {
    const bytes: [count]u8 = @splat('x');
    return &bytes;
}

fn long_name(comptime count: usize) [:0]const u8 {
    const bytes: [count:0]u8 = @splat('a');
    return &bytes;
}

fn new_args(name: []const u8) key_commands.Args {
    return .{ .action = .new, .name = name };
}

test "key new --no-passphrase writes a none key, and show says so" {
    // Goal: the unencrypted form and the read side. Method: make one through the command line;
    // the file is the `none` form, the modes are 0600 and 0700, show names the public text.
    start();
    const make = [_][:0]const u8{ "key", "new", "ci", "--no-passphrase" };
    try testing.expectEqual(@as(u8, 0), command(&make));
    const body = files.content_of(directory ++ "/ci.key").?;
    try testing.expect(has(body, ".secret"));
    try testing.expect(!has(body, "argon2id"));
    try testing.expectEqual(@as(u16, 0o600), files.stat_of(directory ++ "/ci.key").?.mode & 0o777);
    try testing.expectEqual(@as(u16, 0o700), files.stat_of(directory).?.mode & 0o777);
    const record = try key.parse(body);
    const public = key.public_text(record.public);
    try testing.expect(has(sim.stdout(), &public));
    try testing.expect(has(sim.stdout(), "none"));
    const show = [_][:0]const u8{ "key", "show", "ci" };
    try testing.expectEqual(@as(u8, 0), command(&show));
    try testing.expect(has(sim.stdout(), &public));
    try testing.expect(has(sim.stdout(), "encryption: none"));
    const id = key.key_id(record.public);
    try testing.expect(has(sim.stdout(), &id));
}

test "a sealed key opens with its passphrase and with nothing else" {
    // Goal: the passphrase file path end to end. Method: a file with a line and a newline; the
    // key file is the argon2id form, holds neither the passphrase nor the seed; show and list
    // say passphrase and need none; open works with the passphrase, fails without or with a wrong.
    start();
    put_pass(0o600, "correct horse\nsecond line\n");
    var args = new_args("release");
    args.passphrase_file = "/home/alice/pass";
    try testing.expect(direct(args, false) == null);
    const body = files.content_of(directory ++ "/release.key").?;
    try testing.expect(has(body, "argon2id-xchacha20poly1305"));
    try testing.expect(!has(body, "correct horse"));
    try testing.expect(!has(sim.stdout(), "correct horse"));
    try testing.expect(!has(sim.stderr(), "correct horse"));
    const record = try key.parse(body);
    const seed = try key.open(testing.allocator, &record, "correct horse");
    try testing.expectEqual(record.public, key.public_of_seed(seed));
    try testing.expectError(error.WrongPassphrase, key.open(testing.allocator, &record, null));
    try testing.expectError(
        error.WrongPassphrase,
        key.open(testing.allocator, &record, "correct horse\n"),
    );
    try testing.expectError(error.WrongPassphrase, key.open(testing.allocator, &record, "other"));
    const list = [_][:0]const u8{ "key", "list" };
    try testing.expectEqual(@as(u8, 0), command(&list));
    try testing.expect(has(sim.stdout(), "passphrase"));
    try testing.expect(!has(sim.stdout(), &std.fmt.bytesToHex(seed, .lower)));
    try testing.expect(sim.world.input_handle == null);
}

test "no passphrase and no terminal refuses without reading standard input" {
    // Goal: E0911 and the rule that stdin is never read unless it is a terminal. Method: input
    // waiting on stdin, which is not a terminal, and no file.
    start();
    sim.world.input = "stolen\nstolen\n";
    try testing.expectEqual(codes.Code.E0911, direct(new_args("ci"), false).?);
    try testing.expect(sim.world.input_handle == null);
    try testing.expect(files.kind_of(directory ++ "/ci.key") == null);
    try testing.expect(files.kind_of(directory ++ "/ci.pub") == null);
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
}

test "a passphrase file is refused when others can read it, empty, or too long" {
    // Goal: the file rules. Method: each bad file, then the longest first line that is allowed.
    start();
    var args = new_args("ci");
    args.passphrase_file = "/home/alice/pass";
    put_pass(0o644, "secret\n");
    try testing.expectEqual(codes.Code.E0911, direct(args, false).?);
    put_pass(0o640, "secret\n");
    try testing.expectEqual(codes.Code.E0911, direct(args, false).?);
    put_pass(0o600, "\nsecret\n");
    try testing.expectEqual(codes.Code.E0911, direct(args, false).?);
    put_pass(0o600, "");
    try testing.expectEqual(codes.Code.E0911, direct(args, false).?);
    const long = long_line(1025).* ++ "\n";
    put_pass(0o600, long);
    try testing.expectEqual(codes.Code.E0911, direct(args, false).?);
    try testing.expect(files.kind_of(directory ++ "/ci.key") == null);
    put_pass(0o600, long_line(1024) ++ "\nmore");
    try testing.expect(direct(args, false) == null);
    put_pass(0o600, "no newline at the end");
    args.name = "other";
    try testing.expect(direct(args, false) == null);
    args.name = "gone";
    args.passphrase_file = "/home/alice/missing";
    try testing.expectEqual(codes.Code.E0911, direct(args, false).?);
}

test "on a terminal the passphrase is asked twice, and echo is restored on every exit" {
    // Goal: the interactive path. Method: a terminal that answers, one that mismatches, one
    // that sends Ctrl-C; the input is never left in raw mode.
    start();
    sim.terminal = true;
    sim.world.input_terminal = true;
    sim.world.input = "pw\npw\n";
    try testing.expect(direct(new_args("one"), false) == null);
    try testing.expect(!sim.world.input_is_raw);
    try testing.expect(!has(sim.stdout(), "pw\n"));
    try testing.expect(has(files.content_of(directory ++ "/one.key").?, "argon2id"));
    sim.world.input_handle = null;
    sim.world.input = "pw\nnope\n";
    try testing.expectEqual(codes.Code.E0911, direct(new_args("two"), false).?);
    try testing.expect(!sim.world.input_is_raw);
    try testing.expect(files.kind_of(directory ++ "/two.key") == null);
    sim.world.input_handle = null;
    sim.world.input = "pw\x03";
    try testing.expectEqual(codes.Code.E0911, direct(new_args("three"), false).?);
    try testing.expect(!sim.world.input_is_raw);
    sim.world.input_handle = null;
    sim.world.input = "\n\n";
    try testing.expectEqual(codes.Code.E0911, direct(new_args("four"), false).?);
    try testing.expect(!sim.world.input_is_raw);
}

test "a name that exists is refused and the old key is untouched; a bad name is E0005" {
    // Goal: zbx never overwrites a key. Method: make one, make it again, compare the bytes.
    start();
    const make = [_][:0]const u8{ "key", "new", "ci", "--no-passphrase" };
    try testing.expectEqual(@as(u8, 0), command(&make));
    const before = try testing.allocator.dupe(u8, files.content_of(directory ++ "/ci.key").?);
    defer testing.allocator.free(before);
    try testing.expectEqual(@as(u8, 1), command(&make));
    try testing.expect(has(sim.stderr(), "ZBX-E0902"));
    try testing.expectEqualStrings(before, files.content_of(directory ++ "/ci.key").?);
    const bad = [_][:0]const u8{ "key", "new", "Bad_Name", "--no-passphrase" };
    try testing.expectEqual(@as(u8, 1), command(&bad));
    try testing.expect(has(sim.stderr(), "ZBX-E0005"));
    const long = [_][:0]const u8{ "key", "new", long_name(33), "--no-passphrase" };
    try testing.expectEqual(@as(u8, 1), command(&long));
    const longest = [_][:0]const u8{ "key", "new", long_name(32), "--no-passphrase" };
    try testing.expectEqual(@as(u8, 0), command(&longest));
}

test "a loose keys directory is refused, and show needs only the public file" {
    // Goal: E0901 for a loose directory, and that show never opens the secret. Method: loosen the
    // secret (show still works, it reads the .pub only) and the directory (new is refused).
    // The refusal of a loose secret itself is tested on read_secret, in key_store_tests.zig.
    start();
    const make = [_][:0]const u8{ "key", "new", "ci", "--no-passphrase" };
    try testing.expectEqual(@as(u8, 0), command(&make));
    files.set_mode_of(directory ++ "/ci.key", 0o644);
    const show = [_][:0]const u8{ "key", "show", "ci" };
    try testing.expectEqual(@as(u8, 0), command(&show));
    const other = [_][:0]const u8{ "key", "new", "ci2", "--no-passphrase" };
    files.set_mode_of(directory, 0o755);
    try testing.expectEqual(@as(u8, 1), command(&other));
    try testing.expect(has(sim.stderr(), "ZBX-E0901"));
    try testing.expect(files.kind_of(directory ++ "/ci2.key") == null);
}

test "list is in name order, and the JSON is the zbx.key/1 document without a secret" {
    // Goal: the machine form. Method: three keys made out of order; parse the JSON.
    start();
    for ([_][:0]const u8{ "b", "a", "c" }) |name| {
        const make = [_][:0]const u8{ "key", "new", name, "--no-passphrase" };
        try testing.expectEqual(@as(u8, 0), command(&make));
    }
    const list = [_][:0]const u8{ "--output", "json", "key", "list" };
    try testing.expectEqual(@as(u8, 0), command(&list));
    const Value = std.json.Value;
    const parsed = try std.json.parseFromSlice(Value, testing.allocator, sim.stdout(), .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try testing.expectEqualStrings("zbx.key/1", root.get("schema").?.string);
    try testing.expectEqualStrings("list", root.get("action").?.string);
    try testing.expect(!root.get("truncated").?.bool);
    const keys = root.get("keys").?.array.items;
    try testing.expectEqual(@as(usize, 3), keys.len);
    try testing.expectEqualStrings("a", keys[0].object.get("name").?.string);
    try testing.expectEqualStrings("c", keys[2].object.get("name").?.string);
    for (keys) |item| {
        try testing.expectEqual(@as(usize, 4), item.object.count());
        try testing.expectEqualStrings("none", item.object.get("encryption").?.string);
        try testing.expect(!has(sim.stdout(), "secret"));
    }
    const text = [_][:0]const u8{ "key", "list" };
    try testing.expectEqual(@as(u8, 0), command(&text));
    try testing.expect(std.mem.startsWith(u8, sim.stdout(), "a  "));
}

test "list of no keys says how to make one; show of a missing key is E0901" {
    // Goal: the empty cases. Method: a home with no keys directory.
    start();
    const list = [_][:0]const u8{ "key", "list" };
    try testing.expectEqual(@as(u8, 0), command(&list));
    try testing.expect(has(sim.stdout(), "zbx key new <name>"));
    const show = [_][:0]const u8{ "key", "show", "ci" };
    try testing.expectEqual(@as(u8, 1), command(&show));
    try testing.expect(has(sim.stderr(), "ZBX-E0901"));
}

test "the key options: inline value, missing value, wrong command, both ways, twice" {
    // Goal: the argument rules. Method: each is E0003, E0004-like refusal or accepted.
    start();
    const wrong = [_][:0]const u8{ "key", "list", "--no-passphrase" };
    try testing.expectEqual(@as(u8, 1), command(&wrong));
    const missing = [_][:0]const u8{ "key", "new", "ci", "--passphrase-file" };
    try testing.expectEqual(@as(u8, 1), command(&missing));
    const both = [_][:0]const u8{ "key", "new", "ci", "--no-passphrase", "--passphrase-file=x" };
    try testing.expectEqual(@as(u8, 1), command(&both));
    try testing.expect(has(sim.stderr(), "cannot be combined"));
    const twice = [_][:0]const u8{ "key", "new", "ci", "--no-passphrase", "--no-passphrase" };
    try testing.expectEqual(@as(u8, 1), command(&twice));
    try testing.expect(has(sim.stderr(), "given twice"));
    put_pass(0o600, "pw\n");
    const file = "--passphrase-file=/home/alice/pass";
    const inline_value = [_][:0]const u8{ "key", "new", "ci", file };
    try testing.expectEqual(@as(u8, 0), command(&inline_value));
    try testing.expect(has(files.content_of(directory ++ "/ci.key").?, "argon2id"));
}

test "a passphrase file that is a link or is missing says so, not just that it failed" {
    // Goal: the causes the review asked to tell apart. Method: a link to a good file, then no
    // file; each is E0911 with its own words, and no key is made.
    start();
    put_pass(0o600, "secret\n");
    files.put_symlink("/home/alice/link", "/home/alice/pass");
    const linked = [_][:0]const u8{ "key", "new", "a", "--passphrase-file", "/home/alice/link" };
    try testing.expectEqual(@as(u8, 1), command(&linked));
    try testing.expect(has(sim.stderr(), "is a symbolic link; name the file it points to"));
    const missing = [_][:0]const u8{ "key", "new", "a", "--passphrase-file", "/home/alice/none" };
    try testing.expectEqual(@as(u8, 1), command(&missing));
    try testing.expect(has(sim.stderr(), "there is no file /home/alice/none"));
    try testing.expect(files.kind_of(directory ++ "/a.key") == null);
}

test "a passphrase typed too long, or ended with Ctrl-Z or Ctrl-\\, is refused in plain words" {
    // Goal: no empty file name in the message, and no control byte in a passphrase. Method: 1025
    // typed bytes; then a Ctrl-Z and a Ctrl-\\ after some letters.
    start();
    sim.terminal = true;
    sim.world.input_terminal = true;
    sim.world.input = long_line(1025) ++ "\n";
    const make = [_][:0]const u8{ "key", "new", "a" };
    try testing.expectEqual(@as(u8, 1), command(&make));
    try testing.expect(has(sim.stderr(), "the passphrase is longer than 1024 bytes"));
    try testing.expect(!has(sim.stderr(), "line of  "));
    for ([_][]const u8{ "pw\x1a", "pw\x1c" }) |input| {
        sim.world.input_handle = null;
        sim.world.input = input;
        try testing.expectEqual(@as(u8, 1), command(&make));
        try testing.expect(has(sim.stderr(), "the passphrase was not entered; nothing was done"));
        try testing.expect(!sim.world.input_is_raw);
    }
    try testing.expect(files.kind_of(directory ++ "/a.key") == null);
}

test "a keys directory that is a symbolic link is named as one" {
    // Goal: the cause is not "can be read by other users" (chmod cannot fix a link). Method: a
    // link to a private directory in place of the keys directory.
    start();
    files.put_dir("/home/alice/.config", 0o755);
    files.put_dir("/home/alice/.config/zbx", 0o700);
    files.put_dir("/home/alice/private", 0o700);
    files.put_symlink(directory, "/home/alice/private");
    const make = [_][:0]const u8{ "key", "new", "a", "--no-passphrase" };
    try testing.expectEqual(@as(u8, 1), command(&make));
    try testing.expect(has(sim.stderr(), "ZBX-E0901"));
    try testing.expect(has(sim.stderr(), "symbolic link or not a directory"));
    try testing.expect(!has(sim.stderr(), "can be read by other users"));
}

test "a .key without its .pub: recent is kept, old is a leftover, a .pub alone has its own cause" {
    // Goal: the loser of a live `key new` race is not told to delete the winner's secret.
    // Method: the .key is aged by the host's clock; within the window no rm is offered, past it
    // the leftover is named with its removal, and a lone .pub says the secret is gone.
    start();
    const first = [_][:0]const u8{ "key", "new", "ci", "--no-passphrase" };
    try testing.expectEqual(@as(u8, 0), command(&first));
    files.remove_path(directory ++ "/ci.pub");
    files.set_mtime_of(directory ++ "/ci.key", 1000);
    sim.world.now = 1000 + constants.key_leftover_age_seconds - 1;
    try testing.expectEqual(@as(u8, 1), command(&first));
    try testing.expect(has(sim.stderr(), "ZBX-E0902"));
    try testing.expect(has(sim.stderr(), "ci.key has no ci.pub"));
    try testing.expect(!has(sim.stderr(), "rm "));
    sim.world.now = 1000 + constants.key_leftover_age_seconds;
    try testing.expectEqual(@as(u8, 1), command(&first));
    try testing.expect(has(sim.stderr(), "interrupted 'zbx key new' left it"));
    try testing.expect(has(sim.stderr(), "rm " ++ directory ++ "/ci.key"));
    files.remove_path(directory ++ "/ci.key");
    files.put_file(directory ++ "/ci.pub", 0o644, "x");
    try testing.expectEqual(@as(u8, 1), command(&first));
    try testing.expect(has(sim.stderr(), "is gone"));
    try testing.expect(has(sim.stderr(), "rm " ++ directory ++ "/ci.pub"));
}

test "key new removes old temporaries of its own pattern and nothing else" {
    // Goal: a killed run's temporary (a plaintext seed with --no-passphrase) does not stay for
    // good, and a live run's, other files and other names are never swept. Method: old and
    // recent temporaries, a look-alike, a directory; one key new; check each.
    start();
    const mk = [_][:0]const u8{ "key", "new", "ci", "--no-passphrase" };
    try testing.expectEqual(@as(u8, 0), command(&mk));
    const old_key = directory ++ "/.dead.key.0123456789abcdef.tmp";
    const old_pub = directory ++ "/.dead.pub.0123456789abcdef.tmp";
    const recent = directory ++ "/.live.key.fedcba9876543210.tmp";
    const lookalike = directory ++ "/.dead.key.0123456789abcdeg.tmp";
    const notes = directory ++ "/.notes.tmp";
    for ([_][]const u8{ old_key, old_pub, recent, lookalike, notes }) |path| {
        files.put_file(path, 0o600, "seed");
        files.set_mtime_of(path, 100);
    }
    sim.world.now = 100 + constants.key_leftover_age_seconds;
    files.set_mtime_of(recent, sim.world.now - 1);
    const other = [_][:0]const u8{ "key", "new", "ci2", "--no-passphrase" };
    try testing.expectEqual(@as(u8, 0), command(&other));
    try testing.expect(files.kind_of(old_key) == null);
    try testing.expect(files.kind_of(old_pub) == null);
    try testing.expect(files.kind_of(recent) != null);
    try testing.expect(files.kind_of(lookalike) != null);
    try testing.expect(files.kind_of(notes) != null);
    try testing.expect(files.kind_of(directory ++ "/ci2.key") != null);
}

test "key new sweeps at most key_sweep_max temporaries per run" {
    // Goal: the sweep bound, at the bound and one past it. Method: one more old temporary than
    // the bound; the first key new removes exactly the bound, the second removes the rest.
    start();
    const make = [_][:0]const u8{ "key", "new", "ci", "--no-passphrase" }; // Makes the directory.
    try testing.expectEqual(@as(u8, 0), command(&make));
    const total = constants.key_sweep_max + 1;
    var paths: [total][64]u8 = undefined;
    for (&paths, 0..) |*buffer, index| {
        @memset(buffer, 0);
        const path = std.fmt.bufPrint(buffer, directory ++ "/.dead.key.{x:0>16}.tmp", .{index}) catch
            return error.TestUnexpectedResult;
        files.put_file(path, 0o600, "seed");
        files.set_mtime_of(path, 100);
    }
    sim.world.now = 100 + constants.key_leftover_age_seconds;
    const first = [_][:0]const u8{ "key", "new", "one", "--no-passphrase" };
    try testing.expectEqual(@as(u8, 0), command(&first));
    try testing.expectEqual(@as(u32, 1), remaining(&paths));
    const second = [_][:0]const u8{ "key", "new", "two", "--no-passphrase" };
    try testing.expectEqual(@as(u8, 0), command(&second));
    try testing.expectEqual(@as(u32, 0), remaining(&paths));
}

/// How many of `paths` (NUL-terminated text in each buffer) are still there.
fn remaining(paths: []const [64]u8) u32 {
    var count: u32 = 0;
    for (paths) |buffer| {
        const length = std.mem.indexOfScalar(u8, &buffer, 0) orelse return 0;
        if (files.kind_of(buffer[0..length]) != null) count += 1;
    }
    return count;
}
