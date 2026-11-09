//! The provenance record of one build result (docs/briefs/M8-trust.md, "Provenance"): an
//! in-toto Statement v1 with an SLSA v1 provenance predicate, written by `zbx build` and kept
//! unsigned at `trust/provenance/<result hex>`. `zbx sign` wraps its exact bytes in a DSSE
//! envelope. The field map and the digest encodings are in docs/demos/m8.md.
//!
//! This module is pure: a `Record` is everything the statement says, `render` writes it in the
//! canonical JSON form (`json.zig`: schema order, no whitespace, integers only), and `parse`
//! reads only what `render` writes: it reads the members in the writer's order, then renders
//! what it read and refuses any payload that is not those very bytes.
//!
//! A record is a function of the build's inputs and its two times, and of nothing else: the
//! same project built again, all hits or not, gives the same bytes but for `startedOn` and
//! `finishedOn`.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const json = @import("json.zig");
const dsse = @import("dsse.zig");
const statement = @import("statement.zig");

pub const Digest = statement.Digest;

pub const ParseError = error{Malformed};

pub const lock_name = "zbx.lock";
pub const build_file_digest_key = "blake3";
pub const lock_digest_key = "blake3";
pub const builder_name = "zbx";
pub const tree_annotation = "zbxTree";
/// A build file's path that is not UTF-8 cannot be written in JSON; this says so instead.
pub const path_not_text = "(path is not UTF-8)";

/// One step a step needs: the name it is mounted under and its output tree.
pub const Need = struct {
    name: [constants.build_step_name_bytes_max]u8,
    name_length: u8,
    output: Digest,

    pub fn text(need: *const Need) []const u8 {
        return need.name[0..need.name_length];
    }
};

/// One build step, as it was keyed.
pub const Step = struct {
    name: [constants.build_step_name_bytes_max]u8,
    name_length: u8,
    /// The step's cache key (the digest of its preimage).
    key: Digest,
    /// Index into `Record.bases`.
    base: u32,
    input: Digest,
    needs: [constants.build_step_needs_max]Need,
    needs_count: u32,
    output: Digest,
    network: bool,

    pub fn text(step: *const Step) []const u8 {
        return step.name[0..step.name_length];
    }

    pub fn needs_slice(step: *const Step) []const Need {
        return step.needs[0..step.needs_count];
    }
};

/// A base image the build resolved: the reference as the file wrote it, the manifest the lock
/// names, and the tree the store holds for it.
pub const Base = struct {
    reference: [constants.reference_bytes_max]u8,
    reference_length: u32,
    manifest: Digest,
    tree: Digest,

    pub fn text(base: *const Base) []const u8 {
        return base.reference[0..base.reference_length];
    }
};

pub const Record = struct {
    /// The image tree, then the result record that commits to it: the two subjects.
    tree: Digest,
    result: Digest,
    build_file: [constants.path_bytes_max]u8,
    build_file_length: u32,
    build_file_digest: Digest,
    /// The BLAKE3 of `zbx.lock`; null for a build with no base, which needs none.
    lock: ?Digest,
    steps: [constants.provenance_steps_max]Step,
    steps_count: u32,
    image_key: Digest,
    /// Index into `bases`; null for an image built from nothing.
    image_base: ?u32,
    bases: [constants.provenance_bases_max]Base,
    bases_count: u32,
    version: [constants.provenance_version_bytes_max]u8,
    version_length: u32,
    /// `linux/amd64` or `linux/arm64`: the platform of the zbx that built.
    platform: [16]u8,
    platform_length: u32,
    /// The BLAKE3 of the zbx executable (zero where it could not be read).
    zbx: Digest,
    started: u64,
    finished: u64,

    pub fn clear(record: *Record) void {
        record.steps_count = 0;
        record.bases_count = 0;
        record.build_file_length = 0;
        record.version_length = 0;
        record.platform_length = 0;
        record.lock = null;
        record.image_base = null;
        record.started = 0;
        record.finished = 0;
    }

    pub fn build_file_text(record: *const Record) []const u8 {
        return record.build_file[0..record.build_file_length];
    }

    pub fn version_text(record: *const Record) []const u8 {
        return record.version[0..record.version_length];
    }

    pub fn platform_text(record: *const Record) []const u8 {
        return record.platform[0..record.platform_length];
    }

    pub fn steps_slice(record: *const Record) []const Step {
        return record.steps[0..record.steps_count];
    }

    pub fn bases_slice(record: *const Record) []const Base {
        return record.bases[0..record.bases_count];
    }

    /// Names the build file; a path that is not UTF-8, or that is too long, is replaced.
    pub fn set_build_file(record: *Record, path: []const u8) void {
        const usable = path.len <= record.build_file.len and std.unicode.utf8ValidateSlice(path);
        const shown = if (usable) path else path_not_text;
        @memcpy(record.build_file[0..shown.len], shown);
        record.build_file_length = @intCast(shown.len);
        assert(record.build_file_length <= record.build_file.len);
        if (path.len > 0) assert(record.build_file_length > 0);
    }

    pub fn set_version(record: *Record, version: []const u8, platform: []const u8) void {
        const kept = version[0..@min(version.len, record.version.len)];
        @memcpy(record.version[0..kept.len], kept);
        record.version_length = @intCast(kept.len);
        assert(platform.len <= record.platform.len);
        @memcpy(record.platform[0..platform.len], platform);
        record.platform_length = @intCast(platform.len);
    }

    /// The index of the base with this reference and manifest, added when it is new.
    pub fn add_base(record: *Record, reference: []const u8, manifest: Digest, tree: Digest) u32 {
        assert(reference.len <= constants.reference_bytes_max);
        for (record.bases_slice(), 0..) |*base, index| {
            if (std.mem.eql(u8, base.text(), reference) and
                std.mem.eql(u8, &base.manifest, &manifest)) return @intCast(index);
        }
        assert(record.bases_count < constants.provenance_bases_max);
        const base = &record.bases[record.bases_count];
        @memcpy(base.reference[0..reference.len], reference);
        base.reference_length = @intCast(reference.len);
        base.manifest = manifest;
        base.tree = tree;
        record.bases_count += 1;
        return record.bases_count - 1;
    }

    /// A step with no needs yet; fill `needs` and `needs_count` of the returned slot.
    pub fn add_step(record: *Record, name: []const u8) *Step {
        assert(name.len > 0);
        assert(name.len <= constants.build_step_name_bytes_max);
        assert(record.steps_count < constants.provenance_steps_max);
        const step = &record.steps[record.steps_count];
        record.steps_count += 1;
        @memcpy(step.name[0..name.len], name);
        step.name_length = @intCast(name.len);
        step.needs_count = 0;
        return step;
    }

    pub fn add_need(step: *Step, name: []const u8, output: Digest) void {
        assert(name.len > 0);
        assert(name.len <= constants.build_step_name_bytes_max);
        assert(step.needs_count < constants.build_step_needs_max);
        const need = &step.needs[step.needs_count];
        @memcpy(need.name[0..name.len], name);
        need.name_length = @intCast(name.len);
        need.output = output;
        step.needs_count += 1;
    }
};

comptime {
    assert(constants.provenance_bytes_max <= constants.statement_bytes_max);
    assert(constants.provenance_build_type.len > constants.type_uri_base.len);
    assert(constants.provenance_steps_max <= 255); // A step's index is one byte in the build.
}

// ---- Render ----

/// The payload bytes of `record`, into `out` (at least `statement_bytes_max`). A record the
/// bounds allow always fits (`provenance_bytes_max`), so this cannot fail.
pub fn render(out: []u8, record: *const Record) []const u8 {
    assert(out.len >= constants.statement_bytes_max);
    assert(record.steps_count <= constants.provenance_steps_max);
    var writer = json.Writer.init(out[0..constants.statement_bytes_max]);
    write_statement(&writer, record) catch unreachable; // Sized by `provenance_bytes_max`.
    const text = writer.finish();
    assert(text.len <= constants.statement_bytes_max);
    return text;
}

fn write_statement(writer: *json.Writer, record: *const Record) json.WriteError!void {
    try writer.begin_object();
    try writer.member_string("_type", statement.statement_type);
    try writer.member_array("subject");
    try write_subject(writer, statement.tree_name, statement.tree_digest_key, &record.tree);
    try write_subject(writer, statement.result_name, statement.result_digest_key, &record.result);
    try writer.end_array();
    try writer.member_string("predicateType", constants.provenance_predicate_type);
    try writer.member_object("predicate");
    try write_definition(writer, record);
    try write_run_details(writer, record);
    try writer.end_object();
    try writer.end_object();
}

fn write_subject(
    writer: *json.Writer,
    name: []const u8,
    digest_key: []const u8,
    digest: *const Digest,
) json.WriteError!void {
    try writer.begin_object();
    try writer.member_string("name", name);
    try write_digest(writer, digest_key, digest);
    try writer.end_object();
}

/// `"digest":{"<key>":"<hex>"}`.
fn write_digest(
    writer: *json.Writer,
    digest_key: []const u8,
    digest: *const Digest,
) json.WriteError!void {
    try writer.member_object("digest");
    try write_hex(writer, digest_key, digest);
    try writer.end_object();
}

fn write_hex(writer: *json.Writer, name: []const u8, digest: *const Digest) json.WriteError!void {
    const hex = std.fmt.bytesToHex(digest.*, .lower);
    try writer.member_string(name, &hex);
}

fn write_definition(writer: *json.Writer, record: *const Record) json.WriteError!void {
    try writer.member_object("buildDefinition");
    try writer.member_string("buildType", constants.provenance_build_type);
    try writer.member_object("externalParameters");
    try writer.member_object("buildFile");
    try writer.member_string("name", record.build_file_text());
    try write_digest(writer, build_file_digest_key, &record.build_file_digest);
    try writer.end_object();
    try writer.end_object();
    try writer.member_object("internalParameters");
    try writer.member_array("steps");
    for (record.steps_slice()) |*step| try write_step(writer, step);
    try writer.end_array();
    try writer.member_object("image");
    try write_hex(writer, "key", &record.image_key);
    if (record.image_base) |base| try writer.member_unsigned("base", base);
    try writer.end_object();
    try writer.end_object();
    try writer.member_array("resolvedDependencies");
    if (record.lock) |*lock| {
        try writer.begin_object();
        try writer.member_string("name", lock_name);
        try write_digest(writer, lock_digest_key, lock);
        try writer.end_object();
    }
    for (record.bases_slice()) |*base| try write_base(writer, base);
    try writer.end_array();
    try writer.end_object();
}

fn write_step(writer: *json.Writer, step: *const Step) json.WriteError!void {
    try writer.begin_object();
    try writer.member_string("name", step.text());
    try write_hex(writer, "key", &step.key);
    try writer.member_unsigned("base", step.base);
    try write_hex(writer, "input", &step.input);
    try writer.member_object("needs");
    for (step.needs_slice()) |*need| try write_hex(writer, need.text(), &need.output);
    try writer.end_object();
    try write_hex(writer, "output", &step.output);
    try writer.member_boolean("network", step.network);
    try writer.end_object();
}

fn write_base(writer: *json.Writer, base: *const Base) json.WriteError!void {
    try writer.begin_object();
    try writer.member_string("name", base.text());
    try write_digest(writer, statement.manifest_digest_key, &base.manifest);
    try writer.member_object("annotations");
    try write_hex(writer, tree_annotation, &base.tree);
    try writer.end_object();
    try writer.end_object();
}

fn write_run_details(writer: *json.Writer, record: *const Record) json.WriteError!void {
    try writer.member_object("runDetails");
    try writer.member_object("builder");
    try writer.member_string("id", constants.provenance_builder_id);
    try writer.member_object("version");
    try writer.member_string("zbx", record.version_text());
    try writer.member_string("platform", record.platform_text());
    try writer.end_object();
    try writer.member_array("builderDependencies");
    try writer.begin_object();
    try writer.member_string("name", builder_name);
    try write_digest(writer, "blake3", &record.zbx);
    try writer.end_object();
    try writer.end_array();
    try writer.end_object();
    try writer.member_object("metadata");
    const started = statement.format_time(record.started);
    const finished = statement.format_time(record.finished);
    try writer.member_string("startedOn", &started);
    try writer.member_string("finishedOn", &finished);
    try writer.end_object();
    try writer.end_object();
}

// ---- Parse ----

/// Reads `payload` into `out`. `again` is scratch of at least `statement_bytes_max` bytes, in
/// which the record is rendered again to compare with the payload. Accepts only a payload that
/// `render` writes for some record.
pub fn parse(payload: []const u8, out: *Record, again: []u8) ParseError!void {
    assert(again.len >= constants.statement_bytes_max);
    if (payload.len > constants.statement_bytes_max) return error.Malformed;
    out.clear();
    const head = statement.parse(payload) catch return error.Malformed;
    if (head.kind != .provenance) return error.Malformed;
    out.tree = head.tree;
    out.result = head.binding.result;
    var scratch: [constants.path_bytes_max + 1]u8 = undefined;
    var reader = json.Reader.init(payload);
    try skip_to_predicate(&reader, &scratch);
    try parse_definition(&reader, &scratch, out);
    try parse_run_details(&reader, &scratch, out);
    try expect(&reader, &scratch, .object_end);
    try expect(&reader, &scratch, .object_end);
    try expect(&reader, &scratch, .end);
    try check_references(out);
    const rendered = render(again, out);
    if (!std.mem.eql(u8, rendered, payload)) return error.Malformed;
}

/// Past the header, which `statement.parse` has read: the first `predicate` member. Anything
/// the header held that was not the writer's header fails the comparison at the end.
fn skip_to_predicate(reader: *json.Reader, scratch: []u8) ParseError!void {
    assert(scratch.len > 1);
    var tokens: u32 = 0;
    while (tokens < 64) : (tokens += 1) {
        const token = reader.next(scratch) catch return error.Malformed;
        switch (token) {
            .key => |name| if (std.mem.eql(u8, name, "predicate")) {
                return expect(reader, scratch, .object_begin);
            },
            .end => return error.Malformed,
            else => {},
        }
    }
    return error.Malformed;
}

fn expect(reader: *json.Reader, scratch: []u8, want: std.meta.Tag(json.Token)) ParseError!void {
    dsse.expect(reader, scratch, want) catch return error.Malformed;
}

fn expect_key(reader: *json.Reader, scratch: []u8, name: []const u8) ParseError!void {
    dsse.expect_key(reader, scratch, name) catch return error.Malformed;
}

fn read_string(reader: *json.Reader, scratch: []u8) ParseError![]const u8 {
    return dsse.read_string(reader, scratch) catch return error.Malformed;
}

fn read_hex(reader: *json.Reader, scratch: []u8) ParseError!Digest {
    return statement.read_digest(reader, scratch) catch return error.Malformed;
}

fn read_unsigned(reader: *json.Reader, scratch: []u8) ParseError!u64 {
    const token = reader.next(scratch) catch return error.Malformed;
    switch (token) {
        .unsigned => |value| return value,
        else => return error.Malformed,
    }
}

/// `"digest":{"<key>":"<hex>"}`.
fn read_digest_object(
    reader: *json.Reader,
    scratch: []u8,
    digest_key: []const u8,
) ParseError!Digest {
    try expect_key(reader, scratch, "digest");
    try expect(reader, scratch, .object_begin);
    try expect_key(reader, scratch, digest_key);
    const digest = try read_hex(reader, scratch);
    try expect(reader, scratch, .object_end);
    return digest;
}

fn copy_name(into: []u8, text: []const u8) ParseError!u8 {
    if (text.len == 0 or text.len > into.len) return error.Malformed;
    @memcpy(into[0..text.len], text);
    return @intCast(text.len);
}

fn parse_definition(reader: *json.Reader, scratch: []u8, out: *Record) ParseError!void {
    try expect_key(reader, scratch, "buildDefinition");
    try expect(reader, scratch, .object_begin);
    try expect_key(reader, scratch, "buildType");
    const build_type = try read_string(reader, scratch);
    if (!std.mem.eql(u8, build_type, constants.provenance_build_type)) return error.Malformed;
    try expect_key(reader, scratch, "externalParameters");
    try expect(reader, scratch, .object_begin);
    try expect_key(reader, scratch, "buildFile");
    try expect(reader, scratch, .object_begin);
    try expect_key(reader, scratch, "name");
    const path = try read_string(reader, scratch);
    if (path.len == 0 or path.len > out.build_file.len) return error.Malformed;
    @memcpy(out.build_file[0..path.len], path);
    out.build_file_length = @intCast(path.len);
    out.build_file_digest = try read_digest_object(reader, scratch, build_file_digest_key);
    try expect(reader, scratch, .object_end);
    try expect(reader, scratch, .object_end);
    try expect_key(reader, scratch, "internalParameters");
    try expect(reader, scratch, .object_begin);
    try parse_steps(reader, scratch, out);
    try parse_image(reader, scratch, out);
    try expect(reader, scratch, .object_end);
    try parse_dependencies(reader, scratch, out);
    try expect(reader, scratch, .object_end);
}

fn parse_steps(reader: *json.Reader, scratch: []u8, out: *Record) ParseError!void {
    try expect_key(reader, scratch, "steps");
    try expect(reader, scratch, .array_begin);
    while (true) {
        const token = reader.next(scratch) catch return error.Malformed;
        switch (token) {
            .array_end => return,
            .object_begin => {},
            else => return error.Malformed,
        }
        if (out.steps_count == constants.provenance_steps_max) return error.Malformed;
        try parse_step(reader, scratch, &out.steps[out.steps_count]);
        out.steps_count += 1;
    }
}

fn parse_step(reader: *json.Reader, scratch: []u8, step: *Step) ParseError!void {
    try expect_key(reader, scratch, "name");
    step.name_length = try copy_name(&step.name, try read_string(reader, scratch));
    try expect_key(reader, scratch, "key");
    step.key = try read_hex(reader, scratch);
    try expect_key(reader, scratch, "base");
    const base = try read_unsigned(reader, scratch);
    if (base >= constants.provenance_bases_max) return error.Malformed;
    step.base = @intCast(base);
    try expect_key(reader, scratch, "input");
    step.input = try read_hex(reader, scratch);
    try expect_key(reader, scratch, "needs");
    try parse_needs(reader, scratch, step);
    try expect_key(reader, scratch, "output");
    step.output = try read_hex(reader, scratch);
    try expect_key(reader, scratch, "network");
    const token = reader.next(scratch) catch return error.Malformed;
    step.network = switch (token) {
        .boolean => |value| value,
        else => return error.Malformed,
    };
    try expect(reader, scratch, .object_end);
}

fn parse_needs(reader: *json.Reader, scratch: []u8, step: *Step) ParseError!void {
    try expect(reader, scratch, .object_begin);
    step.needs_count = 0;
    while (true) {
        const token = reader.next(scratch) catch return error.Malformed;
        const name = switch (token) {
            .object_end => return,
            .key => |found| found,
            else => return error.Malformed,
        };
        if (step.needs_count == constants.build_step_needs_max) return error.Malformed;
        const need = &step.needs[step.needs_count];
        need.name_length = try copy_name(&need.name, name);
        need.output = try read_hex(reader, scratch);
        step.needs_count += 1;
    }
}

fn parse_image(reader: *json.Reader, scratch: []u8, out: *Record) ParseError!void {
    try expect_key(reader, scratch, "image");
    try expect(reader, scratch, .object_begin);
    try expect_key(reader, scratch, "key");
    out.image_key = try read_hex(reader, scratch);
    out.image_base = null;
    const token = reader.next(scratch) catch return error.Malformed;
    switch (token) {
        .object_end => return,
        .key => |name| if (!std.mem.eql(u8, name, "base")) return error.Malformed,
        else => return error.Malformed,
    }
    const base = try read_unsigned(reader, scratch);
    if (base >= constants.provenance_bases_max) return error.Malformed;
    out.image_base = @intCast(base);
    try expect(reader, scratch, .object_end);
}

fn parse_dependencies(reader: *json.Reader, scratch: []u8, out: *Record) ParseError!void {
    try expect_key(reader, scratch, "resolvedDependencies");
    try expect(reader, scratch, .array_begin);
    out.lock = null;
    var index: u32 = 0;
    while (true) : (index += 1) {
        const token = reader.next(scratch) catch return error.Malformed;
        switch (token) {
            .array_end => return,
            .object_begin => {},
            else => return error.Malformed,
        }
        try expect_key(reader, scratch, "name");
        const name = try read_string(reader, scratch);
        if (name.len == 0 or name.len > constants.reference_bytes_max) return error.Malformed;
        // The name is in `scratch`, which the next token overwrites: keep it where it goes.
        if (out.bases_count == constants.provenance_bases_max) return error.Malformed;
        const base = &out.bases[out.bases_count];
        @memcpy(base.reference[0..name.len], name);
        base.reference_length = @intCast(name.len);
        const is_lock_name = std.mem.eql(u8, name, lock_name);
        try expect_key(reader, scratch, "digest");
        try expect(reader, scratch, .object_begin);
        const keyed = reader.next(scratch) catch return error.Malformed;
        const digest_key = switch (keyed) {
            .key => |found| found,
            else => return error.Malformed,
        };
        if (std.mem.eql(u8, digest_key, lock_digest_key)) {
            // The lock is the first entry and has its own name; it is not a base.
            if (index != 0 or !is_lock_name) return error.Malformed;
            out.lock = try read_hex(reader, scratch);
            try expect(reader, scratch, .object_end);
            try expect(reader, scratch, .object_end);
            continue;
        }
        if (!std.mem.eql(u8, digest_key, statement.manifest_digest_key)) return error.Malformed;
        base.manifest = try read_hex(reader, scratch);
        try expect(reader, scratch, .object_end);
        try expect_key(reader, scratch, "annotations");
        try expect(reader, scratch, .object_begin);
        try expect_key(reader, scratch, tree_annotation);
        base.tree = try read_hex(reader, scratch);
        try expect(reader, scratch, .object_end);
        try expect(reader, scratch, .object_end);
        out.bases_count += 1;
    }
}

fn parse_run_details(reader: *json.Reader, scratch: []u8, out: *Record) ParseError!void {
    try expect_key(reader, scratch, "runDetails");
    try expect(reader, scratch, .object_begin);
    try expect_key(reader, scratch, "builder");
    try expect(reader, scratch, .object_begin);
    try expect_key(reader, scratch, "id");
    if (!std.mem.eql(u8, try read_string(reader, scratch), constants.provenance_builder_id)) {
        return error.Malformed;
    }
    try expect_key(reader, scratch, "version");
    try expect(reader, scratch, .object_begin);
    try expect_key(reader, scratch, "zbx");
    const version = try read_string(reader, scratch);
    if (version.len > out.version.len) return error.Malformed;
    @memcpy(out.version[0..version.len], version);
    out.version_length = @intCast(version.len);
    try expect_key(reader, scratch, "platform");
    const platform = try read_string(reader, scratch);
    if (platform.len > out.platform.len) return error.Malformed;
    @memcpy(out.platform[0..platform.len], platform);
    out.platform_length = @intCast(platform.len);
    try expect(reader, scratch, .object_end);
    try parse_builder_dependency(reader, scratch, out);
    try expect(reader, scratch, .object_end);
    try parse_metadata(reader, scratch, out);
    try expect(reader, scratch, .object_end);
}

fn parse_builder_dependency(reader: *json.Reader, scratch: []u8, out: *Record) ParseError!void {
    try expect_key(reader, scratch, "builderDependencies");
    try expect(reader, scratch, .array_begin);
    try expect(reader, scratch, .object_begin);
    try expect_key(reader, scratch, "name");
    if (!std.mem.eql(u8, try read_string(reader, scratch), builder_name)) return error.Malformed;
    out.zbx = try read_digest_object(reader, scratch, "blake3");
    try expect(reader, scratch, .object_end);
    try expect(reader, scratch, .array_end);
}

fn parse_metadata(reader: *json.Reader, scratch: []u8, out: *Record) ParseError!void {
    try expect_key(reader, scratch, "metadata");
    try expect(reader, scratch, .object_begin);
    try expect_key(reader, scratch, "startedOn");
    out.started = statement.parse_time(try read_string(reader, scratch)) orelse
        return error.Malformed;
    try expect_key(reader, scratch, "finishedOn");
    out.finished = statement.parse_time(try read_string(reader, scratch)) orelse
        return error.Malformed;
    try expect(reader, scratch, .object_end);
}

/// Every index a step or the image holds names a base the record lists.
fn check_references(record: *const Record) ParseError!void {
    assert(record.bases_count <= constants.provenance_bases_max);
    for (record.steps_slice()) |*step| {
        if (step.base >= record.bases_count) return error.Malformed;
    }
    if (record.image_base) |base| {
        if (base >= record.bases_count) return error.Malformed;
    }
}
