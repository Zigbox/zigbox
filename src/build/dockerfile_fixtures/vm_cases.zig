//! The fixtures that `demo-m9`'s ACCEPT part translates through the binary, in the guest, with
//! the demo project's `zbx.lock` (alpine:3.20 and golang:1.23-alpine). The harness module cannot
//! embed files outside `src/testing/vm/`, so build.zig hands it this file as the anonymous import
//! `m9_fixtures`, and this file embeds its neighbours.
//!
//! Only the fixtures whose translation needs no image beyond that lock run here: the rest name
//! node, python, debian, nginx, golang:1.22, quay.io or mcr.microsoft.com bases, gigabytes of
//! pulls or registries zbx does not pull from (docs/demos/m9.md, "Cuts"). Every fixture, these
//! included, is checked against its golden by `zig build test` through the library
//! (src/dockerfile/translate_tests.zig); the binary adds the reading, the lock and the writing.

pub const Case = struct {
    /// The golden's name, without `.golden` or `.refused`; the directory the guest uses.
    name: []const u8,
    dockerfile: []const u8,
    /// Empty when the fixture has none.
    dockerignore: []const u8 = "",
    /// What `zbx import` is given after the command, as the guest's shell reads it.
    arguments: []const u8 = "",
    /// The golden translation, or the golden refusal (`<code> Dockerfile:<line>`, the what, the
    /// fix), as src/dockerfile/translate_tests.zig writes them.
    golden: []const u8,
    refused: bool,
};

pub const cases = [_]Case{
    .{
        .name = "arg_paths_user",
        .dockerfile = @embedFile("arg_paths_user.Dockerfile"),
        .golden = @embedFile("arg_paths_user.golden"),
        .refused = false,
    },
    .{
        .name = "dockerignore",
        .dockerfile = @embedFile("dockerignore.Dockerfile"),
        .dockerignore = @embedFile("dockerignore.dockerignore"),
        .golden = @embedFile("dockerignore.golden"),
        .refused = false,
    },
    .{
        .name = "shell_logic",
        .dockerfile = @embedFile("shell_logic.Dockerfile"),
        .golden = @embedFile("shell_logic.golden"),
        .refused = false,
    },
    .{
        .name = "user_forms",
        .dockerfile = @embedFile("user_forms.Dockerfile"),
        .golden = @embedFile("user_forms.golden"),
        .refused = false,
    },
    .{
        .name = "target_skips",
        .dockerfile = @embedFile("target_skips.Dockerfile"),
        .arguments = "--target app",
        .golden = @embedFile("target_skips.golden"),
        .refused = false,
    },
    .{
        .name = "target_skips.last",
        .dockerfile = @embedFile("target_skips.Dockerfile"),
        .golden = @embedFile("target_skips.last.refused"),
        .refused = true,
    },
    .{
        .name = "stage_collision",
        .dockerfile = @embedFile("stage_collision.Dockerfile"),
        .golden = @embedFile("stage_collision.refused"),
        .refused = true,
    },
    .{
        .name = "label_key",
        .dockerfile = @embedFile("label_key.Dockerfile"),
        .golden = @embedFile("label_key.refused"),
        .refused = true,
    },
    .{
        .name = "add_url",
        .dockerfile = @embedFile("add_url.Dockerfile"),
        .golden = @embedFile("add_url.refused"),
        .refused = true,
    },
    .{
        .name = "add_git",
        .dockerfile = @embedFile("add_git.Dockerfile"),
        .golden = @embedFile("add_git.refused"),
        .refused = true,
    },
    .{
        .name = "arg_from_no_default",
        .dockerfile = @embedFile("arg_from_no_default.Dockerfile"),
        .golden = @embedFile("arg_from_no_default.refused"),
        .refused = true,
    },
};
