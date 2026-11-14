//! Tests of .github/ci-changes.sh, which decides what ci.yml runs. Each row names changed paths
//! and the outputs that must come out true; the script runs under bash, on those paths on its
//! stdin, as CI runs it, and every output line it writes is checked: true exactly for the named
//! outputs, false for the rest. Run from the repository root, as `zig build test` does.

const std = @import("std");
const testing = std.testing;

const script = ".github/ci-changes.sh";
const max_paths = 8;

/// Every output the script writes: `code`, the thirteen demos and the packages demo.
const all_outputs = [_][]const u8{
    "code",    "demo_m0",  "demo_m1",          "demo_m2", "demo_m3", "demo_m4",
    "demo_m5", "demo_m6",  "demo_m6b",         "demo_m7", "demo_m8", "demo_m8b",
    "demo_m9", "demo_m10", "demo_m8_packages",
};

const Row = struct {
    paths: []const []const u8,
    /// The outputs that must be true. Every other output must be false.
    true_outputs: []const []const u8,
};

const rows = [_]Row{
    // The packages demo: the package sources select it and no VM demo.
    .{
        .paths = &.{"src/package/rpm.zig"},
        .true_outputs = &.{ "code", "demo_m8_packages" },
    },
    .{
        .paths = &.{"src/package.zig"},
        .true_outputs = &.{ "code", "demo_m8_packages" },
    },
    .{
        .paths = &.{"packaging/rpm/spec.in"},
        .true_outputs = &.{ "code", "demo_m8_packages" },
    },
    .{
        .paths = &.{"src/testing/vm/checks_m8_packages.zig"},
        .true_outputs = &.{ "code", "demo_m8_packages" },
    },
    .{
        .paths = &.{"src/testing/vm/main_m8_packages.zig"},
        .true_outputs = &.{ "code", "demo_m8_packages" },
    },
    // The release workflow, its own actions and its signing script run after a push to main and
    // in their own test jobs: no demo.
    .{
        .paths = &.{ ".github/workflows/release.yml", ".github/release-sign.sh" },
        .true_outputs = &.{"code"},
    },
    .{
        .paths = &.{
            ".github/actions/setup-gh/action.yml",
            ".github/actions/find-draft/action.yml",
            ".github/actions/tap-formula/action.yml",
            ".github/actions/mac-check-zip/action.yml",
        },
        .true_outputs = &.{"code"},
    },
    .{
        .paths = &.{".github/release-sign-test.sh"},
        .true_outputs = &.{"code"},
    },
    // The other workflows are CI itself: every demo and the packages demo.
    .{
        .paths = &.{".github/workflows/ci.yml"},
        .true_outputs = &.{
            "code",    "demo_m0",  "demo_m1",          "demo_m2", "demo_m3", "demo_m4",
            "demo_m5", "demo_m6",  "demo_m6b",         "demo_m7", "demo_m8", "demo_m8b",
            "demo_m9", "demo_m10", "demo_m8_packages",
        },
    },
    // The runtime every demo runs on selects every VM demo, not the packages demo.
    .{
        .paths = &.{"src/cli.zig"},
        .true_outputs = &.{
            "code",    "demo_m0",  "demo_m1",  "demo_m2", "demo_m3", "demo_m4",
            "demo_m5", "demo_m6",  "demo_m6b", "demo_m7", "demo_m8", "demo_m8b",
            "demo_m9", "demo_m10",
        },
    },
    // The M8b demo: its harness files select demo_m8b alone.
    .{
        .paths = &.{"src/testing/vm/checks_m8b.zig"},
        .true_outputs = &.{ "code", "demo_m8b" },
    },
    // The M10 demo: its harness files select demo_m10 alone.
    .{
        .paths = &.{ "src/testing/vm/checks_m10.zig", "src/testing/vm/m10_fixture/probe.zig" },
        .true_outputs = &.{ "code", "demo_m10" },
    },
    // The M8 demo: its harness files and its source area select demo_m8 and not the packages.
    .{
        .paths = &.{"src/testing/vm/checks_m8.zig"},
        .true_outputs = &.{ "code", "demo_m8" },
    },
    .{
        .paths = &.{"src/testing/vm/upgrade_m8.zig"},
        .true_outputs = &.{ "code", "demo_m8" },
    },
    .{
        .paths = &.{"src/trust/x.zig"},
        .true_outputs = &.{ "code", "demo_m8" },
    },
    // A docs-only change runs no demo: the script's docs rule wins over the demo doc's rule.
    .{
        .paths = &.{"docs/demos/m8.md"},
        .true_outputs = &.{},
    },
    .{
        .paths = &.{ "docs/demos/m8.md", "src/trust/x.zig" },
        .true_outputs = &.{ "code", "demo_m8" },
    },
    .{
        .paths = &.{"README.md"},
        .true_outputs = &.{},
    },
    // The build and CI are every demo and the packages demo.
    .{
        .paths = &.{"build.zig"},
        .true_outputs = &all_outputs,
    },
    // The M9 demo: its harness files, the translator and its fixtures select demo_m9; the builder
    // selects M7's and M9's demos.
    .{
        .paths = &.{ "src/testing/vm/checks_m9.zig", "src/testing/vm/m9_project/Dockerfile" },
        .true_outputs = &.{ "code", "demo_m9" },
    },
    .{
        .paths = &.{"src/dockerfile/translate.zig"},
        .true_outputs = &.{ "code", "demo_m9" },
    },
    .{
        .paths = &.{"src/build/dockerfile_fixtures/mounts.golden"},
        .true_outputs = &.{ "code", "demo_m9" },
    },
    .{
        .paths = &.{"src/import_commands.zig"},
        .true_outputs = &.{ "code", "demo_m9" },
    },
    .{
        .paths = &.{"src/build/graph.zig"},
        .true_outputs = &.{ "code", "demo_m7", "demo_m9" },
    },
    .{
        .paths = &.{ "docs/demos/m9.md", "src/dockerfile/translate.zig" },
        .true_outputs = &.{ "code", "demo_m9" },
    },
};

test "ci-changes: each row selects exactly its outputs" {
    for (rows) |row| {
        const stdout = try run_script(testing.allocator, row.paths);
        defer testing.allocator.free(stdout);
        try check_row(row, stdout);
    }
}

/// Runs the script with `paths`, one per line, on its stdin, and returns its standard output.
/// `std.process.run` takes no stdin, so the paths reach the script through a shell pipe. The
/// environment is cleared but for PATH, as on a pull request with no label: a GITHUB_OUTPUT or
/// HEAD_REF of the CI running this test cannot leak in. The caller frees the result.
fn run_script(gpa: std.mem.Allocator, paths: []const []const u8) ![]u8 {
    std.debug.assert(paths.len <= max_paths);
    var argv: [max_paths + 4][]const u8 = undefined;
    argv[0] = "sh";
    argv[1] = "-c";
    argv[2] = "printf '%s\\n' \"$@\" | env -i PATH=\"$PATH\" EVENT=pull_request bash " ++ script;
    argv[3] = "sh";
    @memcpy(argv[4 .. 4 + paths.len], paths);
    const result = try std.process.run(gpa, testing.io, .{
        .argv = argv[0 .. 4 + paths.len],
    });
    defer gpa.free(result.stderr);
    switch (result.term) {
        .exited => |code| if (code == 0) return result.stdout,
        else => {},
    }
    std.debug.print("{s}", .{result.stderr});
    gpa.free(result.stdout);
    return error.ScriptFailed;
}

/// Checks every output line of one run: its value is true exactly when the row names it, and
/// every named output appears.
fn check_row(row: Row, stdout: []const u8) !void {
    var lines: usize = 0;
    var trues: usize = 0;
    var it = std.mem.tokenizeScalar(u8, stdout, '\n');
    while (it.next()) |line| {
        lines += 1;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse
            return fail(row, stdout, "an output line without '='");
        const name = line[0..eq];
        const value = line[eq + 1 ..];
        const named = contains(row.true_outputs, name);
        if (named) trues += 1;
        const want: []const u8 = if (named) "true" else "false";
        if (!std.mem.eql(u8, value, want)) {
            return fail(row, stdout, "an output has the wrong value");
        }
    }
    if (lines != all_outputs.len) return fail(row, stdout, "the wrong number of output lines");
    if (trues != row.true_outputs.len) return fail(row, stdout, "a named output was not written");
}

fn contains(names: []const []const u8, name: []const u8) bool {
    for (names) |n| {
        if (std.mem.eql(u8, n, name)) return true;
    }
    return false;
}

fn fail(row: Row, stdout: []const u8, what: []const u8) error{WrongOutputs} {
    std.debug.print("ci-changes: {s} for the paths:\n", .{what});
    for (row.paths) |path| std.debug.print("  {s}\n", .{path});
    std.debug.print("script output:\n{s}", .{stdout});
    return error.WrongOutputs;
}
