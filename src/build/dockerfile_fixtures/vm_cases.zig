//! The fixtures that `demo-m9`'s ACCEPT part translates through the binary, in the guest, with
//! the demo project's `zbx.lock` (alpine:3.20 and golang:1.23-alpine). The harness module cannot
//! embed files outside `src/testing/vm/`, so build.zig hands it this file as the anonymous import
//! `m9_vm_cases`, and this file embeds its neighbours.
//!
//! `zbx import` resolves every base before it translates, so a fixture whose base the lock does
//! not pin pulls it, refused or not. Here are 22 of the 33 goldens: those on the lock's bases, and
//! those on debian:bookworm-slim and nginx:1.27 (add_url, add_git and label_key pull them;
//! heredoc_run, shell_instruction and labels then reuse them). The 11 left out pull bases of
//! hundreds of megabytes to a gigabyte each, golang:1.22 (mounts and mounts.hermetic,
//! workdir_dot, copy_from_stage_glob, copy_from_image_platform), golang:1.22-alpine
//! (arg_from_no_default.build_arg), node (onbuild) and python (secret_mount), or pull from
//! registries other than Docker Hub, which the demo reaches only through its mirror: quay.io
//! (arg_from, arg_from.build_arg) and mcr.microsoft.com (escape_backtick) (docs/demos/m9.md,
//! "Cuts"). Every golden is checked by `zig build test` through the library
//! (src/dockerfile/translate_tests.zig); the binary adds the reading, the lock, the pulls and
//! the writing.

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
    .{
        .name = "bind_hermetic",
        .dockerfile = @embedFile("bind_hermetic.Dockerfile"),
        .arguments = "--hermetic",
        .golden = @embedFile("bind_hermetic.golden"),
        .refused = false,
    },
    .{
        .name = "from_variable",
        .dockerfile = @embedFile("from_variable.Dockerfile"),
        .golden = @embedFile("from_variable.golden"),
        .refused = false,
    },
    .{
        .name = "heredoc_redirect",
        .dockerfile = @embedFile("heredoc_redirect.Dockerfile"),
        .golden = @embedFile("heredoc_redirect.golden"),
        .refused = false,
    },
    .{
        .name = "network_forms",
        .dockerfile = @embedFile("network_forms.Dockerfile"),
        .golden = @embedFile("network_forms.golden"),
        .refused = false,
    },
    .{
        .name = "bind_no_steps",
        .dockerfile = @embedFile("bind_no_steps.Dockerfile"),
        .golden = @embedFile("bind_no_steps.refused"),
        .refused = true,
    },
    .{
        .name = "copy_several",
        .dockerfile = @embedFile("copy_several.Dockerfile"),
        .golden = @embedFile("copy_several.refused"),
        .refused = true,
    },
    .{
        .name = "from_mount_stage_arg",
        .dockerfile = @embedFile("from_mount_stage_arg.Dockerfile"),
        .golden = @embedFile("from_mount_stage_arg.refused"),
        .refused = true,
    },
    .{
        .name = "from_stage_arg",
        .dockerfile = @embedFile("from_stage_arg.Dockerfile"),
        .golden = @embedFile("from_stage_arg.refused"),
        .refused = true,
    },
    .{
        .name = "heredoc_run",
        .dockerfile = @embedFile("heredoc_run.Dockerfile"),
        .golden = @embedFile("heredoc_run.golden"),
        .refused = false,
    },
    .{
        .name = "shell_instruction",
        .dockerfile = @embedFile("shell_instruction.Dockerfile"),
        .golden = @embedFile("shell_instruction.golden"),
        .refused = false,
    },
    .{
        .name = "labels",
        .dockerfile = @embedFile("labels.Dockerfile"),
        .golden = @embedFile("labels.golden"),
        .refused = false,
    },
};
