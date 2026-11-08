//! The `zbx key` commands (M8): `new`, `list` and `show` (docs/briefs/M8-trust.md).
//!
//! `new` makes an Ed25519 key, seals its seed under a passphrase (or, with `--no-passphrase`,
//! keeps it in the clear, mode 0600) and writes `<name>.key` and `<name>.pub`. `list` and `show`
//! read only the `.pub` files: they need no passphrase, and no secret is ever in memory for
//! them. Output is text, or one JSON object (`zbx.key/1`) with `--output json`.
//!
//! No secret reaches a diagnostic, a log or the output: the seed, the derived key and the
//! passphrase live in buffers that are zeroed with `secureZero` before the function ends.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const Diag = @import("../diag/diag.zig").Diag;
const errors = @import("../diag/errors.zig");
const json = @import("../bundle.zig");
const diagnose = @import("diagnose.zig");
const key = @import("key.zig");
const passphrase_mod = @import("passphrase.zig");
const store = @import("key_store.zig");

const Host = host_mod.Host;

pub const Error = error{Failed};

pub const Action = enum { new, list, show };

pub const Args = struct {
    action: Action,
    /// `new` and `show`.
    name: ?[]const u8,
    /// `new`: keep the secret in the clear.
    no_passphrase: bool = false,
    /// `new`: the file whose first line is the passphrase.
    passphrase_file: ?[]const u8 = null,
};

pub const Output = struct {
    json: bool,
};

/// What argon2id costs. The defaults are the product's; only a test lowers them.
pub const Cost = struct {
    t: u32 = constants.key_kdf_t,
    m_kib: u32 = constants.key_kdf_m_kib,
    p: u32 = constants.key_kdf_p,
};

/// One key as the commands show it.
const Entry = struct {
    name: [constants.key_name_bytes_max]u8,
    name_len: u8,
    id: key.IdText,
    public: key.PublicText,
    encryption: key.Encryption,

    fn name_slice(entry: *const Entry) []const u8 {
        assert(entry.name_len > 0);
        return entry.name[0..entry.name_len];
    }
};

const Job = struct {
    host: Host,
    args: Args,
    output: Output,
    cost: Cost,
    paths: store.Paths,
    failure: store.Failure,
};

pub fn run(host: Host, args: Args, output: Output, cost: Cost, diag: *Diag) Error!u8 {
    assert(diag.code == null);
    assert((args.action == .list) == (args.name == null));
    if (args.name) |name| {
        if (!key.name_valid(name)) {
            diagnose.bad_name(diag, name);
            return error.Failed;
        }
    }
    var job: Job = .{
        .host = host,
        .args = args,
        .output = output,
        .cost = cost,
        .paths = undefined,
        .failure = .{ .problem = .no_home },
    };
    if (!store.locate(host, &job.paths)) {
        diagnose.unusable(diag, args.name orelse "", "", job.failure);
        return error.Failed;
    }
    switch (args.action) {
        .new => try run_new(&job, diag),
        .list => try run_list(&job, diag),
        .show => try run_show(&job, diag),
    }
    return 0;
}

/// Raises E0901 for the failure the store left in `job`, naming the file it is about.
fn unusable(job: *const Job, extension: []const u8, diag: *Diag) Error {
    const name = job.args.name orelse "";
    var path: fs_path = undefined;
    const text: []const u8 = blk: {
        if (name.len == 0 or job.failure.problem == .dir_too_open or
            job.failure.problem == .dir_not_real) break :blk job.paths.dir.text();
        store.file_path(&job.paths, name, extension, &path) catch
            break :blk job.paths.dir.text();
        break :blk path.text();
    };
    diagnose.unusable(diag, name, text, job.failure);
    return error.Failed;
}

const fs_path = @import("../store/fs.zig").PathBuf;

fn run_new(job: *Job, diag: *Diag) Error!void {
    const name = job.args.name.?;
    const fs = job.host.filesystem();
    store.ensure_dir(fs, &job.paths, &job.failure) catch return unusable(job, ".key", diag);
    const now = job.host.time_now();
    _ = store.sweep_temporaries(fs, &job.paths, now);
    if (store.name_taken(fs, &job.paths, name)) return taken(job, diag);
    var phrase: passphrase_mod.Passphrase = undefined;
    phrase.length = 0;
    defer phrase.wipe();
    if (!job.args.no_passphrase) try ask(job, name, &phrase, diag);
    var seed: [constants.key_seed_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    var salt: [constants.key_salt_bytes]u8 = undefined;
    var nonce: [constants.key_nonce_bytes]u8 = undefined;
    var unique: store.Unique = undefined;
    for ([_][]u8{ &seed, &salt, &nonce, &unique }) |bytes| {
        job.host.random_bytes(bytes) catch return random_failed(job, name, diag);
    }
    const public = key.public_of_seed(seed);
    var record: key.Record = .{ .public = public, .body = .{ .none = seed } };
    defer std.crypto.secureZero(u8, std.mem.asBytes(&record));
    if (!job.args.no_passphrase) try seal(job, &record, &phrase, seed, salt, nonce, diag);
    store.create(fs, &job.paths, name, &record, &unique, &job.failure) catch |err| {
        assert(err == error.Failed);
        return create_failed(job, diag);
    };
    var entry = entry_of(name, .{ .public = public, .encryption = record.body });
    try put_entries(job, "new", (&entry)[0..1], false, diag);
}

fn create_failed(job: *const Job, diag: *Diag) Error {
    if (job.failure.problem == .exists) return taken(job, diag);
    return unusable(job, ".key", diag);
}

/// E0902 for a name that has a file, saying so when it is half a key and whether a live run
/// can still be finishing it.
fn taken(job: *const Job, diag: *Diag) Error {
    const name = job.args.name.?;
    const fs = job.host.filesystem();
    const state = store.name_state(fs, &job.paths, name, job.host.time_now());
    const how: diagnose.Taken = switch (state) {
        // Both files, or (the other run just finished, or a file just went) a state that
        // is whole by now: say plainly the name is taken.
        .whole, .free => .whole,
        .secret_only_recent => .secret_recent,
        .secret_only_stale => .secret_stale,
        .public_only => .public_only,
    };
    diagnose.name_exists(diag, name, job.paths.dir.text(), how);
    return error.Failed;
}

fn random_failed(job: *const Job, name: []const u8, diag: *Diag) Error {
    assert(name.len > 0);
    diagnose.unusable(diag, name, "the system's random source", .{
        .problem = .unreadable,
        .errno = job.host.last_errno(),
    });
    return error.Failed;
}

/// The passphrase for a new key, or the E0911 that says why there is none.
fn ask(job: *Job, name: []const u8, phrase: *passphrase_mod.Passphrase, diag: *Diag) Error!void {
    var problem: diagnose.PassphraseProblem = undefined;
    const file = job.args.passphrase_file;
    passphrase_mod.acquire(job.host, file, name, true, phrase, &problem) catch {
        diagnose.passphrase(diag, name, file orelse "", problem);
        return error.Failed;
    };
    assert(phrase.length > 0);
}

fn seal(
    job: *const Job,
    record: *key.Record,
    phrase: *const passphrase_mod.Passphrase,
    seed: [constants.key_seed_bytes]u8,
    salt: [constants.key_salt_bytes]u8,
    nonce: [constants.key_nonce_bytes]u8,
    diag: *Diag,
) Error!void {
    const kdf: key.Kdf = .{
        .t = job.cost.t,
        .m_kib = job.cost.m_kib,
        .p = job.cost.p,
        .salt = salt,
    };
    // The memory argon2id needs is the OS's, taken for the length of one call and given back:
    // the one allocation of the whole program, and a bounded one (parse refuses above it).
    const allocator = std.heap.page_allocator;
    const sealed = key.seal(allocator, phrase.text(), seed, record.public, kdf, nonce) catch {
        diagnose.unusable(diag, job.args.name.?, "memory for the key's passphrase hash", .{
            .problem = .unreadable,
            .errno = 12, // ENOMEM
        });
        return error.Failed;
    };
    record.body = .{ .passphrase = sealed };
}

fn entry_of(name: []const u8, file: key.PubFile) Entry {
    assert(name.len > 0);
    assert(name.len <= constants.key_name_bytes_max);
    var entry: Entry = .{
        .name = undefined,
        .name_len = @intCast(name.len),
        .id = key.key_id(file.public),
        .public = key.public_text(file.public),
        .encryption = file.encryption,
    };
    @memcpy(entry.name[0..name.len], name);
    return entry;
}

fn run_show(job: *Job, diag: *Diag) Error!void {
    const name = job.args.name.?;
    const file = store.read_pub(job.host.filesystem(), &job.paths, name, &job.failure) catch
        return unusable(job, ".pub", diag);
    var entry = entry_of(name, file);
    try put_entries(job, "show", (&entry)[0..1], false, diag);
}

fn run_list(job: *Job, diag: *Diag) Error!void {
    var listing: store.Listing = undefined;
    const fs = job.host.filesystem();
    store.list(fs, &job.paths, &listing, &job.failure) catch return unusable(job, ".pub", diag);
    var entries: [constants.keys_listed_max]Entry = undefined;
    for (0..listing.count) |index| {
        const name = listing.name(@intCast(index));
        const file = store.read_pub(fs, &job.paths, name, &job.failure) catch {
            job.args.name = name; // The one the failure is about.
            return unusable(job, ".pub", diag);
        };
        entries[index] = entry_of(name, file);
    }
    try put_entries(job, "list", entries[0..listing.count], listing.truncated, diag);
}

// ---- Output ----

fn put(job: *const Job, text: []const u8, diag: *Diag) Error!void {
    assert(text.len <= constants.output_bytes_max);
    if (text.len == 0) return;
    job.host.write_all(.stdout, text) catch |err| {
        errors.output_failed(diag, .stdout, err, job.host.last_errno());
        return error.Failed;
    };
}

fn put_entries(
    job: *const Job,
    action: []const u8,
    entries: []const Entry,
    truncated: bool,
    diag: *Diag,
) Error!void {
    assert(entries.len <= constants.keys_listed_max);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    if (job.output.json) {
        var writer = std.Io.Writer.fixed(&buffer);
        // Cannot fail: the fixed words and one bounded entry fit the buffer.
        writer.print("{{\"schema\":\"zbx.key/1\",\"action\":\"{s}\",\"keys\":[", .{action}) catch
            unreachable; // Same bound.
        try put(job, writer.buffered(), diag);
        for (entries, 0..) |*entry, index| {
            try put(job, entry_json(entry, index > 0, &buffer), diag);
        }
        const tail = if (truncated) "],\"truncated\":true}\n" else "],\"truncated\":false}\n";
        try put(job, tail, diag);
        return;
    }
    if (entries.len == 0) {
        return put(job, "no keys; make one with: zbx key new <name>\n", diag);
    }
    const show = std.mem.eql(u8, action, "show") or std.mem.eql(u8, action, "new");
    for (entries) |*entry| try put(job, entry_text(entry, show, &buffer), diag);
    if (truncated) try put(job, "more keys than are shown\n", diag);
}

fn entry_text(entry: *const Entry, labelled: bool, buffer: []u8) []const u8 {
    assert(buffer.len >= 512);
    const word = key.encryption_word(entry.encryption);
    // Cannot fail: a name, two fixed-length texts and a word fit 512 bytes.
    if (labelled) {
        return std.fmt.bufPrint(
            buffer,
            "key: {s}\nid: {s}\npublic: {s}\nencryption: {s}\n",
            .{ entry.name_slice(), &entry.id, &entry.public, word },
        ) catch unreachable; // Same bound.
    }
    return std.fmt.bufPrint(buffer, "{s}  {s}  {s}  {s}\n", .{
        entry.name_slice(), word, &entry.id, &entry.public,
    }) catch unreachable; // Same bound.
}

fn entry_json(entry: *const Entry, comma: bool, buffer: []u8) []const u8 {
    assert(buffer.len >= 512);
    var writer = std.Io.Writer.fixed(buffer);
    // Cannot fail, any of these: one entry's bounded fields fit the buffer.
    if (comma) writer.writeAll(",") catch unreachable; // Same bound.
    writer.writeAll("{\"name\":") catch unreachable; // Same bound.
    json.write_json_string(&writer, entry.name_slice()) catch unreachable; // Same bound.
    writer.print(",\"id\":\"{s}\",\"public\":\"{s}\",\"encryption\":\"{s}\"}}", .{
        &entry.id, &entry.public, key.encryption_word(entry.encryption),
    }) catch unreachable; // Same bound.
    return writer.buffered();
}
