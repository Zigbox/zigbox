//! The `dockerfile` fuzzer: `zig build fuzz -- dockerfile`. The translator (`dockerfile/`) reads
//! a Dockerfile written by anyone, so each iteration builds a Dockerfile from instruction
//! fragments (the shapes real files have, and the ones the translator refuses), mutates it with
//! byte flips, dropped and added bytes, and translates it through a resolver that does not find
//! `missing/` images.
//!
//! Properties, every iteration:
//!   1. The translator never crashes: it returns bytes, `Refused` or `Unresolved`.
//!   2. A refusal has a registered code, a line inside the file (or 0), a sentence for what and
//!      one for the fix.
//!   3. `Unresolved` happens only when the file names a `missing/` image.
//!   4. Accepted bytes are a build file: they parse with the builder's own reader, and written
//!      back in the canonical form read as the same file.
//!   5. The same input gives the same bytes again (nothing is kept between translations).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const codes = @import("diag/codes.zig");
const file_mod = @import("build/file.zig");
const render = @import("build/render.zig");
const translate = @import("dockerfile/translate.zig");

const text_bytes_max = 4096;
const fragments = [_][]const u8{
    "FROM alpine:3.20\n",
    "FROM alpine:3.20 AS base\n",
    "FROM base AS app\n",
    "FROM scratch\n",
    "FROM missing/image:1\n",
    "FROM --platform=linux/arm64 alpine\n",
    "ARG VERSION=1\n",
    "ARG NAME\n",
    "ENV APP=/srv HOME=/root\n",
    "ENV A b c\n",
    "WORKDIR /srv\n",
    "WORKDIR ../x//y/.\n",
    "USER 1000:1000\n",
    "LABEL a=b \"c d\"=e\n",
    "EXPOSE 80/tcp 443\n",
    "VOLUME /data\n",
    "STOPSIGNAL SIGTERM\n",
    "SHELL [\"/bin/bash\", \"-c\"]\n",
    "COPY . /srv\n",
    "COPY --from=base /a /b\n",
    "COPY --chown=1:1 a b /c/\n",
    "COPY --from=$VERSION /a /b\n",
    "COPY --from=${NAME:-base} /a .\n",
    "COPY file .\n",
    "COPY a b /dest\n",
    "RUN --mount=type=bind,from=$NAME,target=/m ls /m\n",
    "RUN --mount=type=bind,from=base,target=/m ls /m\n",
    "RUN cat <<EOF > /etc/x\nhi\nEOF\n",
    "\xef\xbb\xbf",
    "ADD https://example.com/x /x\n",
    "RUN echo $VERSION > /v\n",
    "RUN apk add curl && make\n",
    "RUN --mount=type=cache,target=/c go build\n",
    "RUN --mount=type=secret,id=s true\n",
    "RUN --network=none true\n",
    "RUN <<EOF\necho hi\nEOF\n",
    "RUN [\"/bin/true\"]\n",
    "CMD [\"/bin/sh\"]\n",
    "CMD echo ${VERSION:-x}\n",
    "ENTRYPOINT [\"/e\"]\n",
    "HEALTHCHECK CMD true\n",
    "ONBUILD RUN true\n",
    "# comment\n",
    "\n",
    "RUN a \\\n  b \\\n# note\n  c\n",
    "BOGUS x\n",
};

const noise = "\\\"'$${}()[]<>=:-+#\n\t \x00\xff";

fn build_text(random: std.Random, buffer: []u8) []const u8 {
    assert(buffer.len == text_bytes_max);
    var length: usize = 0;
    const count = random.intRangeAtMost(u32, 1, 14);
    for (0..count) |_| {
        const piece = fragments[random.uintLessThan(usize, fragments.len)];
        if (length + piece.len > buffer.len) break;
        @memcpy(buffer[length..][0..piece.len], piece);
        length += piece.len;
    }
    return mutate(random, buffer, length);
}

fn mutate(random: std.Random, buffer: []u8, length_in: usize) []const u8 {
    var length = length_in;
    const mutations = random.uintLessThan(u32, 4);
    for (0..mutations) |_| {
        if (length == 0) break;
        const at = random.uintLessThan(usize, length);
        switch (random.uintLessThan(u8, 3)) {
            0 => buffer[at] = noise[random.uintLessThan(usize, noise.len)],
            1 => {
                std.mem.copyForwards(u8, buffer[at..], buffer[at + 1 .. length]);
                length -= 1;
            },
            else => if (length < buffer.len) {
                std.mem.copyBackwards(u8, buffer[at + 1 .. length + 1], buffer[at..length]);
                buffer[at] = noise[random.uintLessThan(usize, noise.len)];
                length += 1;
            },
        }
    }
    return buffer[0..length];
}

const Table = struct {
    fn resolve(context: *anyopaque, reference: []const u8) error{Unresolved}!translate.ImageFacts {
        _ = context;
        assert(reference.len > 0);
        if (std.mem.startsWith(u8, reference, "missing/")) return error.Unresolved;
        return .{ .env = &.{"PATH=/usr/bin:/bin"}, .workdir = "" };
    }
};

fn options_of(
    text: []const u8,
    args: []const translate.BuildArg,
    target: ?[]const u8,
    context: *u8,
) translate.Options {
    assert(text.len <= text_bytes_max);
    return .{
        .dockerfile = text,
        .dockerfile_name = "Dockerfile",
        .dockerignore = "a\n!b\n",
        .build_args = args,
        .target = target,
        .platform = .{ .os = "linux", .architecture = "amd64", .variant = "" },
        .network = .detect,
        .hermetic = false,
        .resolver = .{ .context = context, .resolve = Table.resolve },
    };
}

fn check_refusal(refusal: *const translate.refusal.Refusal, text: []const u8) void {
    const registered = std.meta.stringToEnum(codes.Code, @tagName(refusal.code));
    assert(registered != null);
    const lines_count: u32 = @intCast(std.mem.count(u8, text, "\n") + 1);
    assert(refusal.line <= lines_count);
    assert(refusal.what_text().len > 0);
    assert(refusal.fix_text().len > 0);
}

fn check_accepted(bytes: []const u8) void {
    assert(bytes.len > 0);
    const heap = std.heap.page_allocator;
    const files = heap.alloc(file_mod.BuildFile, 2) catch @panic("fuzz: out of memory");
    defer heap.free(files);
    var problem: file_mod.Problem = undefined;
    assert(file_mod.parse(bytes, &files[0], &problem) == .parsed);
    var buffer: [constants.build_render_bytes_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    render.render(&files[0], &writer) catch @panic("fuzz: render overflow");
    assert(file_mod.parse(writer.buffered(), &files[1], &problem) == .parsed);
    assert(render.equal(&files[0], &files[1]));
}

pub fn fuzz_dockerfile(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    var buffer: [text_bytes_max]u8 = undefined;
    const text = build_text(random, &buffer);
    const heap = std.heap.page_allocator;
    const ws = heap.create(translate.Workspace) catch @panic("fuzz: out of memory");
    defer heap.destroy(ws);
    const args: [1]translate.BuildArg = .{.{ .name = "VERSION", .value = "2" }};
    const with_args = random.boolean();
    const target: ?[]const u8 = if (random.boolean()) "base" else null;
    var context: u8 = 0;
    const options = options_of(text, if (with_args) &args else &.{}, target, &context);
    const result = translate.translate(ws, &options);
    if (result) |bytes| {
        check_accepted(bytes);
        var again: [constants.build_render_bytes_max]u8 = undefined;
        @memcpy(again[0..bytes.len], bytes);
        // Same input, same result: the first translation succeeded.
        const second = translate.translate(ws, &options) catch unreachable;
        assert(std.mem.eql(u8, again[0..bytes.len], second));
    } else |err| switch (err) {
        error.Refused => check_refusal(&ws.refusal, text),
        error.Unresolved => assert(std.mem.indexOf(u8, text, "missing/") != null),
    }
}
