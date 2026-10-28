//! Hand-written command line parser and dispatcher. Pure with respect to the kernel: all
//! output goes through the `Host`, so snapshot tests can capture it from the simulator.
//!
//! Contract (docs/briefs/M0-diagnostics.md): commands `doctor`, `explain <code>`, `help`,
//! `--version`; global options `-v`/`--verbose` and `--output text|json`, which may come before
//! or after the command. Every refusal is a diagnostic (`E00xx`, blame user), rendered here, at
//! the boundary, and nowhere below. The exit code comes from the diagnostic and the command
//! (`codes.exit_code_in`: blame for most commands, 125 to 127 for `run`), once, in `fail`.

const std = @import("std");
const assert = std.debug.assert;
const build_options = @import("build_options");
const constants = @import("constants.zig");
const host_mod = @import("host.zig");
const doctor = @import("doctor.zig");
const text_util = @import("text.zig");
const codes = @import("diag/codes.zig");
const errors = @import("diag/errors.zig");
const explain = @import("diag/explain.zig");
const lock_commands = @import("lock_commands.zig");
const panic = @import("diag/panic.zig");
const render = @import("diag/render.zig");
const diagnose = @import("runtime/diagnose.zig");
const image_mod = @import("runtime/image.zig");
const runtime = @import("runtime/run.zig");
const runtime_spec = @import("runtime/spec.zig");
const Diag = @import("diag/diag.zig").Diag;
const bundle = @import("bundle.zig");
const commands = @import("commands.zig");
const store_commands = @import("store_commands.zig");
const digest_prefix = @import("store/digest.zig");
const run_image = @import("run_image.zig");
const gc = @import("store/gc.zig");
const pull_commands = @import("pull_commands.zig");
const lifecycle = @import("runtime/lifecycle.zig");
const Sha256 = @import("registry/digest.zig").Sha256;

const Host = host_mod.Host;

const help_text =
    \\zbx - rootless container runtime
    \\
    \\usage: zbx [options] <command>
    \\
    \\commands:
    \\  run             run a command in a container whose root is a tree or a directory (see below)
    \\  bundle          collect a redacted diagnostic bundle for a run (see below)
    \\  doctor          check that this host can run zbx (a diagnostic per failing check)
    \\  ps              list the containers (--all: the ones that ended too)
    \\  stop <name>     stop a container: SIGTERM, then SIGKILL after --grace
    \\  commit <name>   turn what a stopped container changed into a new tree and print its digest
    \\  store <cmd>     the content-addressed store: import, ls, du, rm, diff, verify, gc, restore
    \\  lock show       print the project's zbx.lock: each image, its manifest and tree
    \\  pull <ref>      pull an image from a registry into the store (see below)
    \\  schema <cmd>    print the JSON schema of a command's output
    \\  explain <code>  explain a diagnostic code offline, for example E0001 (--output json: a
    \\                  document, see zbx schema explain)
    \\  help            show this text
    \\  --version       print the version
    \\
    \\run:
    \\  zbx run <image> [--name <name>] [-- <command> [args...]]
    \\  zbx run <digest> [--name <name>] -- <command> [args...]
    \\  zbx run --rootfs <dir> [--name <name>] -- <command> [args...]
    \\  <image>         a pulled image by name (alpine:3.20, name@sha256:...): it runs what the
    \\                  image says (entrypoint, command, environment, directory, user); words
    \\                  after -- replace its command. A tag is looked up in zbx.lock, which is
    \\                  made if the project has none, and refused if it and the store disagree
    \\  <digest>        a tree of the store (or a unique prefix of 12 or more hex digits), run on
    \\                  an overlay: its writes go to the container's own layer, never the store
    \\  --rootfs <dir>  or a directory to use as the container's root, read and written in place
    \\  --name <name>   the container's name and hostname (default: zbx- and six hex digits)
    \\  --memory <size> memory limit, binary units: 128m, 1g (needs the systemd user manager)
    \\  --pids <n>      limit on processes and threads, as in 64
    \\  --cpus <n>      limit on CPU time, in CPUs: 0.5 is half of one
    \\  --read-only     mount the root read-only, with a tmpfs at /tmp and /run
    \\  --net <mode>    none (the default: a network of its own, only lo), host (share the host's)
    \\                  or user (the network through pasta, as the user: apt install passt)
    \\  --publish <h:c> forward TCP port h of this machine to port c of the container (repeatable;
    \\                  implies --net user)
    \\  -d, --detach    start the container and return; zbx ps and zbx stop find it again
    \\  --timeout <ms>  stop the container when it has run this long (SIGTERM, then SIGKILL)
    \\  --grace <ms>    time between SIGTERM and SIGKILL (default 10000)
    \\  --              ends the options; everything after it is the command, as typed
    \\
    \\stop:
    \\  zbx stop <name> [--grace <ms>] [--timeout <ms>]
    \\  --timeout <ms>  give up (exit 2) if the container is still there after this long
    \\
    \\store:
    \\  zbx store import <dir>   read a directory into the store and print its digest
    \\  zbx store ls             list the roots (the trees the store keeps) and the images
    \\  zbx store du [<digest>]  the store's size, or what one tree costs
    \\  zbx store du --by-image  what each pulled image costs, and how much it shares
    \\  zbx store rm <digest>    drop a root and its image records (the data stays until gc)
    \\  zbx store diff <a> <b>   list the paths that differ between two trees
    \\  zbx store verify         rehash everything; name each damaged file and the paths it breaks
    \\  zbx store gc             plan a collection of what no root reaches (changes nothing)
    \\  zbx store gc --confirm <hash>   do that plan: move it to the trash, kept for 7 days
    \\  zbx store gc --trash     list the trash
    \\  zbx store restore <id>   put a gc's trash back
    \\  a digest is b3: and 64 hex digits, or any unique prefix of 12 or more hex digits
    \\
    \\pull:
    \\  zbx pull [--resolve-only] <reference>
    \\  <reference>     [registry/][namespace/]name[:tag][@sha256:<hex>], for example alpine:3.20
    \\                  or ghcr.io/owner/image:v1 (Docker Hub when no registry is named)
    \\  --resolve-only  print the digest of the image manifest for this machine's platform,
    \\                  as the registry names it (anonymous; HTTPS_PROXY and NO_PROXY are used)
    \\  without it, the layers are downloaded into the store (a cut download resumes), unpacked
    \\  into one tree and recorded, and zbx.lock (the nearest one up from here, else here) gets
    \\  the entry; the manifest digest is printed, or with --output json the object of
    \\  "zbx schema pull", which has the tree's digest
    \\  ZBX_REGISTRY_MIRRORS=host[,host]   mirrors of Docker Hub to ask first (mirror.gcr.io)
    \\
    \\bundle:
    \\  zbx bundle (--last | <name>) [--no-redact]
    \\  --last          the most recent run; <name> is the run called that
    \\  --no-redact     keep secrets in the bundle (prints a warning; review before sharing)
    \\  writes <state>/zbx/bundles/<UTC time>-<name>.tar.gz and prints its path
    \\
    \\options (before the "--" of run, or after any other command):
    \\  -v, --verbose   show the full cause chain and context of a failure
    \\  --output json   write each failure to stderr as one JSON object per line
    \\
    \\exit codes: 0 ok, 1 usage error, 2 this host cannot run zbx, 3 an external service, 70 a bug
    \\run exits with the command's own exit code, or 128 plus the signal that killed it, and
    \\keeps its own failures out of that range: 125 zbx failed before the command started,
    \\126 the command could not be run, 127 the command was not found
    \\
;

const version_text = "zbx " ++ build_options.version ++ "\n";

comptime {
    // Fixed messages must fit the one buffer every message is rendered into.
    assert(help_text.len < constants.output_bytes_max);
    assert(version_text.len < constants.output_bytes_max);
    assert(help_text[help_text.len - 1] == '\n');
    assert(version_text[version_text.len - 1] == '\n');
}

pub const Command = enum {
    bundle,
    commit,
    doctor,
    explain,
    help,
    lock,
    ps,
    pull,
    run,
    schema,
    stop,
    store,
    version,
};

pub const OutputFormat = enum { text, json };

/// The global options. Defaults are what a run with no options gets.
pub const Options = struct {
    verbose: bool = false,
    output: OutputFormat = .text,
    /// The command line is a `run`: its failures use the container-run exit codes.
    runs_container: bool = false,

    pub fn exit_scope(options: Options) codes.ExitScope {
        const scope: codes.ExitScope = if (options.runs_container) .container_run else .standard;
        assert((scope == .container_run) == options.runs_container);
        return scope;
    }

    /// json always carries everything; verbose only changes the text rendering.
    pub fn mode(options: Options) render.Mode {
        const result: render.Mode = if (options.output == .json)
            .json
        else if (options.verbose)
            .verbose
        else
            .text;
        assert((result == .json) == (options.output == .json));
        if (result == .verbose) assert(options.verbose);
        return result;
    }
};

/// What `run` was given: the options that came before `--`, and the command after it.
pub const RunArgs = struct {
    rootfs: ?[]const u8,
    name: ?[]const u8,
    command: []const []const u8,
    /// The text of the limit flags, read by `limits_of` when the container starts.
    memory: ?[]const u8 = null,
    pids: ?[]const u8 = null,
    cpus: ?[]const u8 = null,
    /// `--timeout` and `--grace` of `run` and `stop`, in milliseconds as typed.
    timeout: ?[]const u8 = null,
    grace: ?[]const u8 = null,
    /// `-d`: the run is detached; `--all` (of `ps`): stopped containers too.
    detach: bool = false,
    all: bool = false,
    /// `--read-only`: the rootfs is mounted read-only, with a tmpfs at /tmp and /run.
    read_only: bool = false,
    /// `--net` as typed. No `--net` is `none` (unless `--publish` was given, which implies
    /// `user`), and a run with neither says so when it fails.
    net: ?[]const u8 = null,
    /// The `--publish` values, parsed as each was read (a bad one is refused there, E0600).
    publish: [constants.publish_count_max]runtime_spec.Publish = undefined,
    publish_count: u32 = 0,

    pub fn publish_slice(run_args: *const RunArgs) []const runtime_spec.Publish {
        assert(run_args.publish_count <= constants.publish_count_max);
        return run_args.publish[0..run_args.publish_count];
    }
};

/// The options of `run` that take a value, before the `--`.
const RunOption = enum {
    rootfs,
    name,
    memory,
    pids,
    cpus,
    timeout,
    grace,
    net,
    publish,

    fn flag(option: RunOption) []const u8 {
        assert(@backingInt(option) <= 8);
        assert(@tagName(option).len > 0);
        return switch (option) {
            .rootfs => "--rootfs",
            .name => "--name",
            .memory => "--memory",
            .pids => "--pids",
            .cpus => "--cpus",
            .timeout => "--timeout",
            .grace => "--grace",
            .net => "--net",
            .publish => "--publish",
        };
    }
};

/// What `bundle` was given besides its optional operand, the run's name.
pub const BundleArgs = struct {
    last: bool = false,
    no_redact: bool = false,
};

/// What `store` was given: the subcommand and its one operand.
pub const StoreArgs = struct {
    action: store_commands.Action,
    operand: ?[]const u8,
    /// `store diff`: the second digest.
    second: ?[]const u8 = null,
    /// `store gc --confirm <hash>`, and `store gc --trash`.
    confirm: ?[]const u8 = null,
    trash: bool = false,
    /// `store du --by-image`.
    by_image: bool = false,
};

/// What `pull` was given besides its reference.
pub const PullArgs = struct {
    resolve_only: bool = false,
};

pub const Invocation = struct {
    command: Command,
    /// The one operand of `explain`; null for commands that take none.
    operand: ?[]const u8,
    options: Options,
    /// Set only when `command` is `run`.
    run: RunArgs,
    /// Set only when `command` is `bundle`.
    bundle: BundleArgs,
    /// Set only when `command` is `store`.
    store: StoreArgs,
    /// Set only when `command` is `pull`.
    pull: PullArgs,
};

pub const ParseError = error{
    MissingCommand,
    UnknownCommand,
    UnexpectedArgument,
    UnknownOption,
    BadOptionValue,
    MissingArgument,
};

pub const CollectError = error{
    TooManyArguments,
    ArgumentTooLong,
};

pub const RunError = error{
    UnknownCode,
    OutputFailed,
    /// The container could not be started; the reason is in the diagnostic.
    StartFailed,
    /// A pull the run began failed, and its child has written the diagnostic.
    PullFailed,
    /// The bundle could not be written; the reason is in the diagnostic.
    BundleFailed,
    /// `ps`, `stop` or `schema` failed; the reason is in the diagnostic.
    CommandFailed,
};

/// What one argument is, decided by its shape alone. Shared by `scan_options` and `parse` so
/// that they cannot disagree about where an option's value is.
const Token = union(enum) {
    verbose,
    /// `--output`, whose value is the next argument.
    output_next,
    /// `--output=<value>`.
    output_inline: []const u8,
    /// `--rootfs`, `--name`, `--memory`, `--pids`, `--cpus`: options of `run`, whose value is the
    /// next argument.
    run_option_next: RunOption,
    /// The same with the value after an `=`.
    run_option_inline: struct { option: RunOption, value: []const u8 },
    /// `--read-only` and `-d`: options of `run` without a value; `--all` is `ps`'s.
    read_only,
    detach,
    all,
    /// `--confirm`, whose value is the next argument, and `--confirm=<value>`: `store gc`'s.
    confirm_next,
    confirm_inline: []const u8,
    /// `--by-image`: `store du`'s.
    by_image,
    /// `--trash`: `store gc`'s.
    trash,
    /// `--last` and `--no-redact`: options of `bundle`.
    last,
    no_redact,
    /// `--resolve-only`: `pull`'s.
    resolve_only,
    /// `--`: after `run`, everything that follows is the command.
    separator,
    unknown_option,
    operand,
};

/// `--rootfs`, `--rootfs=x` and the other value options of `run`, or null.
fn run_option_of(argument: []const u8) ?Token {
    assert(argument.len <= constants.arg_bytes_max);
    assert(std.enums.values(RunOption).len == 9);
    inline for (comptime std.enums.values(RunOption)) |option| {
        const flag = comptime option.flag();
        if (std.mem.eql(u8, argument, flag)) return .{ .run_option_next = option };
        if (std.mem.startsWith(u8, argument, flag ++ "=")) {
            const value = argument[flag.len + 1 ..];
            return .{ .run_option_inline = .{ .option = option, .value = value } };
        }
    }
    return null;
}

fn classify(argument: []const u8) Token {
    assert(argument.len <= constants.arg_bytes_max);
    assert(std.mem.indexOfScalar(u8, argument, 0) == null); // Arguments are C strings.
    if (std.mem.eql(u8, argument, "-v")) return .verbose;
    if (std.mem.eql(u8, argument, "--verbose")) return .verbose;
    if (std.mem.eql(u8, argument, "--output")) return .output_next;
    const inline_prefix = "--output=";
    if (std.mem.startsWith(u8, argument, inline_prefix)) {
        return .{ .output_inline = argument[inline_prefix.len..] };
    }
    if (run_option_of(argument)) |token| return token;
    if (std.mem.eql(u8, argument, "--")) return .separator;
    if (std.mem.eql(u8, argument, "--read-only")) return .read_only;
    if (std.mem.eql(u8, argument, "-d")) return .detach;
    if (std.mem.eql(u8, argument, "--detach")) return .detach;
    if (std.mem.eql(u8, argument, "--all")) return .all;
    if (std.mem.eql(u8, argument, "--confirm")) return .confirm_next;
    if (std.mem.startsWith(u8, argument, "--confirm=")) {
        return .{ .confirm_inline = argument["--confirm=".len..] };
    }
    if (std.mem.eql(u8, argument, "--trash")) return .trash;
    if (std.mem.eql(u8, argument, "--by-image")) return .by_image;
    if (std.mem.eql(u8, argument, "--resolve-only")) return .resolve_only;
    if (std.mem.eql(u8, argument, "--last")) return .last;
    if (std.mem.eql(u8, argument, "--no-redact")) return .no_redact;
    // "--help" and "--version" are commands that look like options; a lone "-" and the empty
    // string are operands, so they reach the "unknown command" error with their text.
    if (command_named(argument) != null) return .operand;
    if (argument.len > 1) {
        if (argument[0] == '-') return .unknown_option;
    }
    return .operand;
}

fn output_format_named(value: []const u8) ?OutputFormat {
    assert(value.len <= constants.arg_bytes_max);
    assert(std.mem.indexOfScalar(u8, value, 0) == null);
    if (std.mem.eql(u8, value, "text")) return .text;
    if (std.mem.eql(u8, value, "json")) return .json;
    return null;
}

/// Exact match only: near misses such as `Help` or `version` are unknown commands.
fn command_named(name: []const u8) ?Command {
    assert(name.len <= constants.arg_bytes_max); // collect() refuses longer arguments.
    var found: ?Command = null;
    if (std.mem.eql(u8, name, "bundle")) found = .bundle;
    if (std.mem.eql(u8, name, "commit")) found = .commit;
    if (std.mem.eql(u8, name, "doctor")) found = .doctor;
    if (std.mem.eql(u8, name, "explain")) found = .explain;
    if (std.mem.eql(u8, name, "help")) found = .help;
    if (std.mem.eql(u8, name, "lock")) found = .lock;
    if (std.mem.eql(u8, name, "ps")) found = .ps;
    if (std.mem.eql(u8, name, "pull")) found = .pull;
    if (std.mem.eql(u8, name, "run")) found = .run;
    if (std.mem.eql(u8, name, "schema")) found = .schema;
    if (std.mem.eql(u8, name, "stop")) found = .stop;
    if (std.mem.eql(u8, name, "store")) found = .store;
    if (std.mem.eql(u8, name, "--help")) found = .help;
    if (std.mem.eql(u8, name, "--version")) found = .version;
    if (found != null) assert(name.len > 0); // The empty string is never a command.
    return found;
}

fn operands_count(command: Command) u32 {
    assert(@tagName(command).len > 0);
    const count: u32 = switch (command) {
        .bundle, .doctor, .help, .ps, .run, .version => 0,
        .explain, .schema, .stop, .commit, .pull, .lock => 1,
        .store => 2,
    };
    assert(count <= 2);
    return count;
}

/// Reads the global options leniently, ignoring anything wrong with them. It runs before the
/// strict `parse` so that a failure of any kind is already rendered in the requested mode: a
/// script that asked for JSON gets JSON even when it also mistyped the command. After
/// `run ... --` everything is the command's, so `-v` there is not ours.
pub fn scan_options(args: []const []const u8) Options {
    assert(args.len <= constants.args_count_max);
    var options: Options = .{};
    var first: ?Command = null;
    var seen_operand = false;
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const is_run = first != null and first.? == .run;
        switch (classify(args[index])) {
            .verbose => options.verbose = true,
            .output_inline => |value| {
                if (output_format_named(value)) |format| options.output = format;
            },
            .output_next => {
                if (index + 1 < args.len) {
                    if (output_format_named(args[index + 1])) |format| options.output = format;
                    index += 1;
                }
            },
            .run_option_next => {
                if (is_run and index + 1 < args.len) index += 1;
            },
            .separator => {
                if (is_run) break;
            },
            .confirm_next => {
                if (index + 1 < args.len) index += 1;
            },
            .confirm_inline, .trash, .resolve_only, .by_image => {},
            .run_option_inline, .unknown_option, .last, .no_redact => {},
            .read_only, .detach, .all => {},
            .operand => {
                if (!seen_operand) first = command_named(args[index]);
                seen_operand = true;
            },
        }
    }
    assert(index <= args.len + 1);
    options.runs_container = first != null and first.? == .run;
    return options;
}

/// Maps the arguments after the program name to an invocation. Pure; on failure the diagnostic
/// is in `diag` and the caller renders it.
pub fn parse(
    args: []const []const u8,
    invocation: *Invocation,
    diag: *Diag,
) ParseError!void {
    assert(args.len <= constants.args_count_max);
    assert(diag.code == null);
    var operands: [constants.args_count_max][]const u8 = undefined;
    var count: u32 = 0;
    var run_args: RunArgs = .{ .rootfs = null, .name = null, .command = &.{} };
    var bundle_args: BundleArgs = .{};
    var pull_args: PullArgs = .{};
    var gc_args: GcArgs = .{};
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const argument = args[index];
        const is_run = count > 0 and command_named(operands[0]) == .run;
        const is_bundle = count > 0 and command_named(operands[0]) == .bundle;
        switch (classify(argument)) {
            .verbose => {},
            .output_inline => |value| try check_output_value(diag, value),
            .output_next => {
                if (index + 1 == args.len) return bad_output_value(diag, null);
                index += 1;
                try check_output_value(diag, args[index]);
            },
            .run_option_next, .run_option_inline => {
                const is_stop = count > 0 and command_named(operands[0]) == .stop;
                if (!is_run and !is_stop) return unknown_option(diag, argument);
                try take_run_option(diag, &run_args, args, &index, is_run);
            },
            .all => try take_all_option(diag, &run_args, operands[0..count], argument),
            .separator => {
                if (!is_run) return unknown_option(diag, argument);
                run_args.command = args[index + 1 ..];
                break;
            },
            .detach, .read_only => {
                if (!is_run) return unknown_option(diag, argument);
                run_args.detach = run_args.detach or classify(argument) == .detach;
                run_args.read_only = run_args.read_only or classify(argument) == .read_only;
            },
            .confirm_next, .confirm_inline, .trash => {
                try take_gc_option(diag, &gc_args, operands[0..count], args, &index);
            },
            .last, .no_redact => {
                if (!is_bundle) return unknown_option(diag, argument);
                bundle_args.last = bundle_args.last or classify(argument) == .last;
                bundle_args.no_redact = bundle_args.no_redact or classify(argument) == .no_redact;
            },
            .resolve_only => try take_pull_option(diag, &pull_args, operands[0..count], argument),
            .by_image => try take_by_image(diag, &gc_args, operands[0..count], argument),
            .unknown_option => return unknown_option(diag, argument),
            .operand => {
                operands[count] = argument;
                count += 1;
            },
        }
    }
    assert(count <= args.len);
    invocation.options = scan_options(args);
    invocation.run = run_args;
    invocation.bundle = bundle_args;
    invocation.pull = pull_args;
    try resolve(args, operands[0..count], invocation, diag);
    try check_options(&gc_args, invocation, diag);
}

/// `--all`, which only `ps` takes.
fn take_all_option(
    diag: *Diag,
    run_args: *RunArgs,
    operands: []const []const u8,
    argument: []const u8,
) ParseError!void {
    assert(classify(argument) == .all);
    if (operands.len == 0) return unknown_option(diag, argument);
    if (command_named(operands[0]) != .ps) return unknown_option(diag, argument);
    run_args.all = true;
}

/// `--resolve-only`, which only `pull` takes.
fn take_pull_option(
    diag: *Diag,
    pull_args: *PullArgs,
    operands: []const []const u8,
    argument: []const u8,
) ParseError!void {
    assert(classify(argument) == .resolve_only);
    if (operands.len == 0) return unknown_option(diag, argument);
    if (command_named(operands[0]) != .pull) return unknown_option(diag, argument);
    pull_args.resolve_only = true;
}

/// The checks that need the command resolved: what `store gc`, `run` and `bundle` were given.
fn check_options(gc_args: *const GcArgs, invocation: *Invocation, diag: *Diag) ParseError!void {
    assert(diag.code == null);
    if (invocation.command == .store and invocation.store.action == .gc) {
        try check_gc_args(diag, gc_args, invocation);
    }
    if (gc_args.by_image) {
        // `du --by-image` lists every image; a tree to measure is another question.
        if (invocation.store.operand) |operand| return unexpected_argument(diag, .store, operand);
        invocation.store.by_image = true;
    }
    if (invocation.command == .run) try check_run_args(diag, &invocation.run, invocation.operand);
    if (invocation.command == .bundle) try check_bundle_args(diag, invocation);
}

/// What `store gc` was given besides its words.
const GcArgs = struct { confirm: ?[]const u8 = null, trash: bool = false, by_image: bool = false };

fn is_gc(operands: []const []const u8) bool {
    return operands.len >= 2 and command_named(operands[0]) == .store and
        std.mem.eql(u8, operands[1], "gc");
}

/// `--by-image`, which only `store du` takes.
fn take_by_image(
    diag: *Diag,
    gc_args: *GcArgs,
    operands: []const []const u8,
    argument: []const u8,
) ParseError!void {
    assert(classify(argument) == .by_image);
    const is_du = operands.len >= 2 and command_named(operands[0]) == .store and
        std.mem.eql(u8, operands[1], "du");
    if (!is_du) return unknown_option(diag, argument);
    gc_args.by_image = true;
}

/// `--confirm <hash>`, `--confirm=<hash>` and `--trash`, which only `store gc` takes.
fn take_gc_option(
    diag: *Diag,
    gc_args: *GcArgs,
    operands: []const []const u8,
    args: []const []const u8,
    index: *usize,
) ParseError!void {
    assert(index.* < args.len);
    assert(diag.code == null);
    const argument = args[index.*];
    if (!is_gc(operands)) return unknown_option(diag, argument);
    switch (classify(argument)) {
        .trash => gc_args.trash = true,
        .confirm_inline => |value| {
            if (gc_args.confirm != null) return unexpected_argument(diag, .store, argument);
            gc_args.confirm = value;
        },
        else => {
            if (gc_args.confirm != null) return unexpected_argument(diag, .store, argument);
            if (index.* + 1 == args.len) return missing_option_value(diag, "--confirm");
            index.* += 1;
            gc_args.confirm = args[index.*];
        },
    }
}

/// `gc` takes `--confirm <hash>` or `--trash`, not both.
fn check_gc_args(diag: *Diag, gc_args: *const GcArgs, invocation: *Invocation) ParseError!void {
    assert(diag.code == null);
    if (gc_args.confirm != null and gc_args.trash) {
        return unexpected_argument(diag, .store, "--trash");
    }
    invocation.store.confirm = gc_args.confirm;
    invocation.store.trash = gc_args.trash;
}

/// Reads one value option of `run` and its value (inline, or the next argument). A value that
/// is missing, or is the `--` that starts the command, is `ZBX-E0005`; giving the same option
/// twice is `ZBX-E0003`, since one of them would be silently ignored.
fn take_run_option(
    diag: *Diag,
    run_args: *RunArgs,
    args: []const []const u8,
    index: *usize,
    is_run: bool,
) ParseError!void {
    assert(index.* < args.len);
    assert(diag.code == null);
    const argument = args[index.*];
    const option: RunOption = switch (classify(argument)) {
        .run_option_next => |chosen| chosen,
        .run_option_inline => |chosen| chosen.option,
        else => unreachable, // The caller matched one of the two.
    };
    // `stop` takes the two times and nothing else of the options of `run`.
    if (!is_run and option != .timeout and option != .grace) return unknown_option(diag, argument);
    const value: []const u8 = switch (classify(argument)) {
        .run_option_inline => |chosen| chosen.value,
        else => blk: {
            const next = index.* + 1;
            if (next == args.len) return missing_option_value(diag, option.flag());
            const flag = option.flag();
            if (classify(args[next]) == .separator) return missing_option_value(diag, flag);
            index.* = next;
            break :blk args[next];
        },
    };
    if (option == .publish) return take_publish(diag, run_args, value);
    const slot = switch (option) {
        .rootfs => &run_args.rootfs,
        .name => &run_args.name,
        .memory => &run_args.memory,
        .pids => &run_args.pids,
        .cpus => &run_args.cpus,
        .timeout => &run_args.timeout,
        .grace => &run_args.grace,
        .net => &run_args.net,
        .publish => unreachable, // Repeatable: `take_publish` above.
    };
    if (slot.* != null) return unexpected_argument(diag, .run, argument);
    slot.* = value;
}

/// `run` needs a rootfs and a command: the two things a user is most likely to forget.
fn check_run_args(diag: *Diag, run_args: *const RunArgs, digest: ?[]const u8) ParseError!void {
    assert(diag.code == null);
    try check_network_args(diag, run_args);
    if (run_args.rootfs == null and digest == null) {
        return missing_argument(diag, .run, .rootfs);
    }
    if (run_args.rootfs != null and digest != null) return both_roots(diag, digest.?);
    // An image named by a tag has a command of its own, so the words after `--` are optional;
    // a rootfs and a tree digest have none.
    const has_default = digest != null and digest.?.len > 0 and !is_tree_operand(digest.?);
    if (run_args.command.len == 0 and !has_default) {
        return missing_argument(diag, .run, .command);
    }
    // `-- ""` names no program either.
    if (run_args.command.len > 0 and run_args.command[0].len == 0) {
        return missing_argument(diag, .run, .command);
    }
    assert((run_args.rootfs != null) != (digest != null));
    if (!has_default) assert(run_args.command.len > 0);
}

/// The network mode `--net` names; null for any other word.
const NetWord = enum { none, host, user };

fn net_word_named(value: []const u8) ?NetWord {
    assert(value.len <= constants.arg_bytes_max);
    assert(std.mem.indexOfScalar(u8, value, 0) == null); // Arguments are C strings.
    return std.meta.stringToEnum(NetWord, value);
}

/// `--net` takes none, host or user. `--publish` implies `user`: with an explicit `none` or
/// `host` it names a forward into a network the container does not get, which is refused.
fn check_network_args(diag: *Diag, run_args: *const RunArgs) ParseError!void {
    assert(diag.code == null);
    assert(run_args.publish_count <= constants.publish_count_max);
    const value = run_args.net orelse return;
    const word = net_word_named(value) orelse return bad_net_value(diag, value);
    if (run_args.publish_count == 0) return;
    if (word == .user) return;
    var storage: [runtime_spec.publish_text_bytes_max]u8 = undefined;
    const first = run_args.publish[0].text(&storage);
    diag.raise(.E0003);
    diag.while_("reading the command line", .{});
    if (word == .none) {
        diag.cause("--publish forwards a host port into the container's own network, " ++
            "and --net none gives it none", .{});
    } else {
        diag.cause("--publish forwards a host port into the container's own network, " ++
            "and --net host shares the host's instead", .{});
    }
    diag.context("cmd", "run", .{});
    diag.context("arg", "--net {s} --publish {s}", .{ value, first });
    diag.fix(.{
        .sentence = "drop --net: --publish implies --net user",
        .command = "zbx run --publish 8080:80 nginx",
    });
    return error.UnexpectedArgument;
}

/// One `--publish`: parsed now, so that the diagnostic quotes the value that is wrong.
fn take_publish(diag: *Diag, run_args: *RunArgs, value: []const u8) ParseError!void {
    assert(diag.code == null);
    assert(run_args.publish_count <= constants.publish_count_max);
    const parsed = switch (runtime_spec.parse_publish(value)) {
        .ok => |publish| publish,
        .problem => |problem| return bad_publish(diag, value, problem.sentence()),
    };
    if (run_args.publish_count == constants.publish_count_max) {
        return bad_publish(diag, value, "--publish is given more than 16 times");
    }
    for (run_args.publish_slice()) |earlier| {
        if (earlier.host == parsed.host) {
            return bad_publish(diag, value, "that host port is already published");
        }
    }
    run_args.publish[run_args.publish_count] = parsed;
    run_args.publish_count += 1;
    assert(runtime_spec.publish_problem(.user, run_args.publish_slice()) == null);
}

/// ZBX-E0600: a `--publish` value that is not a forward zbx can make.
fn bad_publish(diag: *Diag, value: []const u8, reason: []const u8) ParseError {
    assert(diag.code == null);
    assert(reason.len > 0);
    comptime assert(constants.publish_count_max == 16); // The sentence above says so.
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, value);
    diag.raise(.E0600);
    diag.while_("reading the command line", .{});
    diag.cause("--publish '{s}': {s}", .{ echo, reason });
    diag.context("arg", "{s}", .{echo});
    diag.fix(.{
        .sentence = "give a host port and the container's port, both 1 to 65535:",
        .command = "zbx run --publish 8080:80 nginx",
    });
    return error.BadOptionValue;
}

fn bad_net_value(diag: *Diag, value: []const u8) ParseError {
    assert(diag.code == null);
    assert(net_word_named(value) == null);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, value);
    diag.raise(.E0005);
    diag.while_("reading the command line", .{});
    diag.cause("--net takes none, host or user, not '{s}'", .{echo});
    diag.context("value", "{s}", .{echo});
    diag.fix(.{
        .sentence = "choose a mode:",
        .command = "zbx run --net user alpine -- wget -qO- https://example.com",
    });
    return error.BadOptionValue;
}

/// True if `operand` names a tree of the store (`b3:` and hex, or 12 hex digits or more); any
/// other operand of `run` is the name of an image.
fn is_tree_operand(operand: []const u8) bool {
    assert(operand.len <= constants.arg_bytes_max);
    return digest_prefix.Prefix.parse(operand) != null;
}

/// `bundle` needs exactly one of `--last` and a run's name.
fn check_bundle_args(diag: *Diag, invocation: *const Invocation) ParseError!void {
    assert(diag.code == null);
    assert(invocation.command == .bundle);
    if (invocation.bundle.last) {
        if (invocation.operand) |name| return unexpected_argument(diag, .bundle, name);
        return;
    }
    if (invocation.operand == null) return missing_argument(diag, .bundle, .target);
    assert(!invocation.bundle.last);
}

/// Turns the operands (everything that is not an option) into a command and its argument.
fn resolve(
    args: []const []const u8,
    operands: []const []const u8,
    invocation: *Invocation,
    diag: *Diag,
) ParseError!void {
    assert(operands.len <= constants.args_count_max);
    invocation.store = .{ .action = .ls, .operand = null }; // Only `store` and `commit` set it.
    if (operands.len == 0) return missing_command(diag, args.len);
    const command = command_named(operands[0]) orelse return unknown_command(diag, operands[0]);
    if (command == .store) return resolve_store(operands, invocation, diag);
    defer if (invocation.command == .commit) {
        invocation.store = .{ .action = .commit, .operand = invocation.operand };
    };
    // `bundle` takes at most one operand (a run's name) and checks the rest itself.
    // `run` takes at most one: the digest of the tree to run (or `--rootfs`, checked below).
    const wanted = if (command == .bundle or command == .run) 1 else operands_count(command);
    const given: u32 = @intCast(operands.len - 1);
    if (given > wanted) return unexpected_argument(diag, command, operands[1 + wanted]);
    if (given < wanted and command != .bundle and command != .run) {
        const what: Missing = switch (command) {
            .stop, .commit => .container,
            .schema => .topic,
            .lock => .action,
            .pull => .reference,
            else => .code,
        };
        return missing_argument(diag, command, what);
    }
    invocation.command = command;
    invocation.operand = if (given == 1) operands[1] else null;
    if (invocation.operand == null) assert(given == 0);
    if (command == .lock) {
        if (!std.mem.eql(u8, invocation.operand.?, "show")) {
            return lock_unknown(diag, invocation.operand.?);
        }
    }
}

/// `lock` was given a word that is not its subcommand.
fn lock_unknown(diag: *Diag, word: []const u8) ParseError {
    assert(diag.code == null);
    assert(!std.mem.eql(u8, word, "show"));
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, word);
    diag.raise(.E0001);
    diag.while_("reading the command line", .{});
    diag.cause("'{s}' is not a lock subcommand; the only one is show", .{echo});
    diag.context("arg", "{s}", .{echo});
    diag.fix(.{ .sentence = "print the project's lock:", .command = "zbx lock show" });
    return error.UnknownCommand;
}

/// `store` takes a subcommand, and for `import` and `rm` an operand; `du` takes one if it likes.
fn resolve_store(
    operands: []const []const u8,
    invocation: *Invocation,
    diag: *Diag,
) ParseError!void {
    assert(operands.len >= 1);
    assert(command_named(operands[0]) == .store);
    if (operands.len == 1) return store_usage(diag, .{ .missing = .action });
    const action = std.meta.stringToEnum(store_commands.Action, operands[1]) orelse {
        return store_usage(diag, .{ .unknown = operands[1] });
    };
    const given: usize = operands.len - 2;
    const wanted: usize = switch (action) {
        .ls, .verify, .gc => 0,
        .diff => 2,
        else => 1,
    };
    if (given > wanted) return store_usage(diag, .{ .extra = operands[2 + wanted] });
    if (given < wanted and action != .du) {
        const what: StoreMissing = switch (action) {
            .import => .directory,
            .diff => .two_digests,
            .restore => .gc_id,
            else => .digest,
        };
        return store_usage(diag, .{ .missing = what });
    }
    if (action == .commit) return store_usage(diag, .{ .unknown = operands[1] }); // A command.
    invocation.command = .store;
    invocation.operand = null;
    invocation.store = .{
        .action = action,
        .operand = if (given >= 1) operands[2] else null,
        .second = if (given == 2) operands[3] else null,
    };
    assert((invocation.store.operand != null) == (given >= 1));
}

const StoreMissing = enum { action, directory, digest, two_digests, gc_id };

const StoreUsage = union(enum) {
    missing: StoreMissing,
    unknown: []const u8,
    extra: []const u8,
};

fn store_usage(diag: *Diag, problem: StoreUsage) ParseError {
    assert(diag.code == null);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    diag.while_("reading the command line", .{});
    switch (problem) {
        .missing => |what| {
            diag.raise(.E0006);
            switch (what) {
                .action => diag.cause(
                    "'store' needs a subcommand: import, ls, du, rm, diff, verify, gc or restore",
                    .{},
                ),
                .directory => diag.cause("'store import' needs the directory to import", .{}),
                .digest => diag.cause("'store rm' needs the digest of the root to drop", .{}),
                .two_digests => diag.cause("'store diff' needs two digests to compare", .{}),
                .gc_id => diag.cause("'store restore' needs the id of the trash to restore", .{}),
            }
            diag.context("cmd", "store", .{});
            diag.fix(
                .{ .sentence = "see the roots and their digests:", .command = "zbx store ls" },
            );
            return error.MissingArgument;
        },
        .unknown => |word| {
            const echo = echo_of(&storage, word);
            diag.raise(.E0001);
            diag.cause(
                "'{s}' is not a store subcommand; they are import, ls, du, rm, diff, verify, gc " ++
                    "and restore",
                .{echo},
            );
            diag.context("arg", "{s}", .{echo});
            diag.fix(.{ .sentence = "see the commands:", .command = "zbx help" });
            return error.UnknownCommand;
        },
        .extra => |word| {
            const echo = echo_of(&storage, word);
            diag.raise(.E0003);
            diag.cause("'store' was given '{s}' after its operand, and takes no more", .{echo});
            diag.context("cmd", "store", .{});
            diag.context("arg", "{s}", .{echo});
            diag.fix(
                .{
                    .sentence = "give one operand at a time, for example:",
                    .command = "zbx store ls",
                },
            );
            return error.UnexpectedArgument;
        },
    }
}

// ---- The usage diagnostics ----------------------------------------------------------------

fn echo_of(storage: *[constants.arg_echo_bytes_max]u8, argument: []const u8) []const u8 {
    assert(argument.len <= constants.arg_bytes_max);
    const echo = text_util.sanitise(storage, argument);
    assert(echo.len <= constants.arg_echo_bytes_max);
    return echo;
}

fn missing_command(diag: *Diag, args_count: usize) ParseError {
    assert(diag.code == null);
    diag.raise(.E0002);
    diag.while_("reading the command line", .{});
    // The summary already says "no command"; the cause says what zbx actually saw.
    if (args_count == 0) {
        diag.cause("zbx was run with no arguments at all", .{});
    } else {
        diag.cause("only options were given, and the first word after them must be a command", .{});
    }
    diag.fix(.{ .sentence = "see the commands:", .command = "zbx help" });
    diag.fix(.{ .sentence = "check this host:", .command = "zbx doctor" });
    assert(diag.fixes.count == 2);
    return error.MissingCommand;
}

fn unknown_command(diag: *Diag, argument: []const u8) ParseError {
    assert(diag.code == null);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, argument);
    diag.raise(.E0001);
    diag.while_("reading the command line", .{});
    diag.cause("'{s}' is not a zbx command", .{echo});
    diag.context("arg", "{s}", .{echo});
    diag.fix(.{ .sentence = "see the commands:", .command = "zbx help" });
    assert(diag.code.? == .E0001);
    return error.UnknownCommand;
}

/// `run` was given a digest and a --rootfs: one root, not two.
fn both_roots(diag: *Diag, digest: []const u8) ParseError {
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, digest);
    assert(diag.code == null);
    diag.raise(.E0003);
    diag.while_("reading the command line", .{});
    diag.cause("'run' was given the tree '{s}' and --rootfs; it runs one root filesystem", .{echo});
    diag.context("cmd", "run", .{});
    diag.context("arg", "{s}", .{echo});
    diag.fix(
        .{ .sentence = "give one of them:", .command = "zbx run --rootfs ./alpine -- /bin/sh" },
    );
    return error.UnexpectedArgument;
}

fn unexpected_argument(diag: *Diag, command: Command, argument: []const u8) ParseError {
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, argument);
    assert(diag.code == null);
    const name = @tagName(command);
    diag.raise(.E0003);
    diag.while_("reading the command line", .{});
    if (command == .run) {
        diag.cause("'run' takes options, then '--' and the command, but '{s}' came first", .{echo});
    } else if (command == .bundle) {
        diag.cause("'bundle' takes --last or one run name, but '{s}' was also given", .{echo});
    } else if (operands_count(command) == 0) {
        diag.cause("'{s}' takes no arguments, but '{s}' was also given", .{ name, echo });
    } else {
        diag.cause("'{s}' takes one argument, but '{s}' was also given", .{ name, echo });
    }
    diag.context("cmd", "{s}", .{name});
    diag.context("arg", "{s}", .{echo});
    if (command == .run) {
        diag.fix(.{
            .sentence = "put the command after '--', and give each option once:",
            .command = "zbx run --rootfs ./alpine -- /bin/sh",
        });
    } else if (command == .bundle) {
        diag.fix(
            .{ .sentence = "name one run, or take the latest:", .command = "zbx bundle --last" },
        );
    } else if (operands_count(command) == 0) {
        diag.fix_with("run it on its own:", "zbx {s}", .{name});
    } else if (command == .stop) {
        diag.fix(.{ .sentence = "stop one container at a time:", .command = "zbx stop web-1" });
    } else if (command == .commit) {
        diag.fix(.{ .sentence = "commit one container at a time:", .command = "zbx commit web-1" });
    } else if (command == .schema) {
        diag.fix(.{ .sentence = "name one command:", .command = "zbx schema ps" });
    } else if (command == .lock) {
        diag.fix(.{ .sentence = "print the project's lock:", .command = "zbx lock show" });
    } else {
        diag.fix_with("pass one code:", "zbx {s} E0001", .{name});
    }
    assert(diag.code.? == .E0003);
    return error.UnexpectedArgument;
}

const Missing = enum { code, rootfs, command, target, container, topic, reference, action };

/// What `pull` lacks: its reference.
fn missing_pull(diag: *Diag, missing: Missing) void {
    assert(diag.code != null);
    assert(missing == .reference);
    diag.cause("'pull' needs the reference of the image to pull", .{});
    diag.fix(.{ .sentence = "name an image:", .command = "zbx pull alpine:3.20" });
}

/// What `lock` lacks: its subcommand.
fn missing_lock(diag: *Diag) void {
    assert(diag.code != null);
    diag.cause("'lock' needs a subcommand: show", .{});
    diag.fix(.{ .sentence = "print the project's lock:", .command = "zbx lock show" });
}

fn missing_argument(diag: *Diag, command: Command, missing: Missing) ParseError {
    // The commands with something to miss: `explain` its code, `run` its rootfs and command.
    if (command == .run) assert(missing != .code);
    if (command == .explain) assert(missing == .code);
    if (command == .bundle) assert(missing == .target);
    if (command == .stop or command == .commit) assert(missing == .container);
    if (command == .schema) assert(missing == .topic);
    if (command == .lock) assert(missing == .action);
    if (command == .pull) assert(@backingInt(missing) >= @backingInt(Missing.reference));

    assert(command != .doctor);
    assert(command != .ps);
    assert(command != .help);
    assert(command != .version);
    diag.raise(.E0006);
    diag.while_("reading the command line", .{});
    switch (missing) {
        .code => {
            diag.cause("'{s}' needs a diagnostic code", .{@tagName(command)});
            diag.fix(.{
                .sentence = "pass the code from a diagnostic:",
                .command = "zbx explain E0001",
            });
        },
        .rootfs => {
            diag.cause(
                "'run' needs the digest of a tree, or --rootfs <dir>, to use as the root",
                .{},
            );
            diag.fix(.{
                .sentence = "name a tree of the store (they are listed by zbx store ls):",
                .command = "zbx run b3:2f9c4a1d7e03 -- /bin/sh",
            });
            diag.fix(.{
                .sentence = "or a root filesystem directory:",
                .command = "zbx run --rootfs ./alpine -- /bin/sh",
            });
        },
        .target => {
            diag.cause("'bundle' needs --last or the name of a run", .{});
            diag.fix(
                .{ .sentence = "bundle the most recent run:", .command = "zbx bundle --last" },
            );
        },
        .container => {
            if (command == .commit) {
                diag.cause("'commit' needs the name of the container to commit", .{});
            } else {
                diag.cause("'stop' needs the name of the container to stop", .{});
            }
            diag.fix(.{ .sentence = "see the containers:", .command = "zbx ps --all" });
        },
        .topic => {
            diag.cause("'schema' needs the command whose output schema to print", .{});
            diag.fix(.{ .sentence = "name one:", .command = "zbx schema ps" });
        },
        .reference => missing_pull(diag, missing),
        .action => missing_lock(diag),
        .command => {
            diag.cause("'run' needs the command to run, after '--'", .{});
            diag.fix(.{
                .sentence = "put the command after '--':",
                .command = "zbx run --rootfs ./alpine -- /bin/sh",
            });
        },
    }
    diag.context("cmd", "{s}", .{@tagName(command)});
    assert(diag.code.? == .E0006);
    return error.MissingArgument;
}

/// `--rootfs` or `--name` with no value after it.
fn missing_option_value(diag: *Diag, option: []const u8) ParseError {
    assert(diag.code == null);
    assert(option.len > 2);
    diag.raise(.E0005);
    diag.while_("reading the command line", .{});
    diag.cause("{s} needs a value, and none follows it", .{option});
    diag.fix(.{
        .sentence = "give it a value:",
        .command = "zbx run --rootfs ./alpine --name web-1 -- /bin/sh",
    });
    assert(diag.code.? == .E0005);
    return error.BadOptionValue;
}

fn unknown_option(diag: *Diag, argument: []const u8) ParseError {
    assert(diag.code == null);
    assert(argument.len > 1);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, argument);
    diag.raise(.E0004);
    diag.while_("reading the command line", .{});
    diag.cause("'{s}' is not an option zbx knows", .{echo});
    diag.context("arg", "{s}", .{echo});
    diag.fix(.{ .sentence = "see the options:", .command = "zbx help" });
    assert(diag.code.? == .E0004);
    return error.UnknownOption;
}

fn check_output_value(diag: *Diag, value: []const u8) ParseError!void {
    assert(diag.code == null);
    assert(value.len <= constants.arg_bytes_max);
    if (output_format_named(value) == null) return bad_output_value(diag, value);
}

/// `value` is null when `--output` was the last argument.
fn bad_output_value(diag: *Diag, value: ?[]const u8) ParseError {
    assert(diag.code == null);
    if (value) |given| assert(output_format_named(given) == null);
    diag.raise(.E0005);
    diag.while_("reading the command line", .{});
    if (value) |given| {
        var storage: [constants.arg_echo_bytes_max]u8 = undefined;
        const echo = echo_of(&storage, given);
        diag.cause("--output takes text or json, not '{s}'", .{echo});
        diag.context("value", "{s}", .{echo});
    } else {
        diag.cause("--output needs a value, text or json, and none follows it", .{});
    }
    diag.fix(.{ .sentence = "choose text or json:", .command = "zbx --output json doctor" });
    assert(diag.code.? == .E0005);
    return error.BadOptionValue;
}

/// Copies the iterator's remaining arguments into fixed storage, refusing rather than
/// truncating when a limit is exceeded. A refusal is `ZBX-E0008` in `diag`. `collected` is how
/// many arguments were stored, also on failure, so the options among them can still be honoured
/// when the failure is rendered.
pub fn collect(
    storage: *[constants.args_count_max][]const u8,
    collected: *u32,
    iterator: anytype,
    diag: *Diag,
) CollectError![]const []const u8 {
    var count: u32 = 0;
    collected.* = 0;
    defer collected.* = count;
    while (iterator.next()) |argument| {
        if (count == constants.args_count_max) {
            diag.raise(.E0008);
            diag.while_("reading the command line", .{});
            diag.cause("more than {d} arguments were given", .{constants.args_count_max});
            diag.fix(.{ .sentence = "pass fewer arguments" });
            return error.TooManyArguments;
        }
        if (argument.len > constants.arg_bytes_max) {
            diag.raise(.E0008);
            diag.while_("reading the command line", .{});
            const size = .{ count + 1, constants.arg_bytes_max };
            diag.cause("argument {d} is longer than {d} bytes", size);
            diag.fix(.{ .sentence = "pass a shorter argument" });
            return error.ArgumentTooLong;
        }
        assert(argument.len <= constants.arg_bytes_max);
        storage[count] = argument;
        count += 1;
    }
    assert(count <= constants.args_count_max);
    if (count > 0) assert(storage[count - 1].len <= constants.arg_bytes_max);
    return storage[0..count];
}

// ---- Running -------------------------------------------------------------------------------

/// Entry point: skips the program name, collects, parses, runs. Returns the exit code.
/// Everything one command line needs that is too big for the stack: a run's handle (which holds
/// the plan and the doctor's facts) and the bundle's workspace. The caller owns it, so two
/// command lines in one process (a library user, a test) share nothing. `zbx` itself owns one in
/// `main.zig`.
pub const Storage = struct {
    handle: runtime.Handle,
    workspace: bundle.Workspace,
    /// The store commands' memory: names, entries and trees of the directories being read.
    store: store_commands.Workspace,
    /// A run of a tree from the store prepares it here (`runtime/image.zig`).
    image: image_mod.Workspace,
    /// A pull resolves a reference here (`pull_commands.zig`).
    pull: pull_commands.Workspace,
    /// `run` by an image's name: the lookup and the settings (`run_image.zig`).
    run_image: run_image.Workspace,
    /// Room for `zbx ps`.
    entries: [constants.runs_max + constants.scopes_listed_max]lifecycle.Entry,
    /// The room gc keeps its sets in (`gc.Workspace.tables`): the caller's, at least
    /// `gc.tables_bytes_min`. `zbx` gives it a static region of `store_gc_tables_bytes`.
    gc_tables: []align(8) u8,
};

/// One shared `Storage` for callers that run one command line at a time (the tests, the
/// fuzzers). Two at once is a bug in the caller, and the assertion says so; a caller that wants
/// concurrency owns a `Storage` and uses `run_with`.
var shared_storage: Storage = undefined;
var shared_tables: [8 * 1024 * 1024]u8 align(8) = @splat(0);
var shared_busy = std.atomic.Value(bool).init(false);

pub fn run_from_iterator(host: Host, iterator: anytype) u8 {
    assert(!shared_busy.swap(true, .acquire));
    defer assert(shared_busy.swap(false, .release));
    shared_storage.gc_tables = &shared_tables;
    return run_with(host, iterator, &shared_storage);
}

pub fn run(host: Host, args: []const []const u8) u8 {
    assert(!shared_busy.swap(true, .acquire));
    defer assert(shared_busy.swap(false, .release));
    shared_storage.gc_tables = &shared_tables;
    return run_slice(host, args, &shared_storage);
}

pub fn run_with(host: Host, iterator: anytype, storage: *Storage) u8 {
    _ = iterator.next(); // Program name; absent only in a malformed exec, which is harmless.
    var diag: Diag = undefined;
    diag.reset();
    var words: [constants.args_count_max][]const u8 = undefined;
    var collected: u32 = 0;
    const args = collect(&words, &collected, iterator, &diag) catch {
        assert(collected <= constants.args_count_max);
        // Whatever was collected before the limit was hit may hold --output or --verbose.
        const options = scan_options(words[0..collected]);
        panic.configure(&panic.state, options.mode(), options.exit_scope());
        return fail(host, &diag, options);
    };
    assert(args.len <= constants.args_count_max);
    return run_slice(host, args, storage);
}

pub fn run_slice(host: Host, args: []const []const u8, storage: *Storage) u8 {
    assert(args.len <= constants.args_count_max);
    var diag: Diag = undefined;
    diag.reset();
    const options = scan_options(args);
    panic.configure(&panic.state, options.mode(), options.exit_scope());
    var invocation: Invocation = undefined;
    parse(args, &invocation, &diag) catch return fail(host, &diag, options);
    assert(invocation.options.verbose == options.verbose);
    const code = dispatch(host, &invocation, storage, &diag) catch {
        return fail(host, &diag, options);
    };
    // A container's own exit code is passed through whole; zbx's own codes stay below 71.
    if (invocation.command != .run) assert(code <= constants.exit_internal);
    return code;
}

fn dispatch(host: Host, invocation: *const Invocation, storage: *Storage, diag: *Diag) RunError!u8 {
    assert(diag.code == null);
    const takes_operand = switch (invocation.command) {
        .explain, .bundle, .schema, .stop, .run, .commit, .pull, .lock => true,
        else => false,
    };
    if (invocation.command == .explain) assert(invocation.operand != null);
    if (!takes_operand) assert(invocation.operand == null);
    switch (invocation.command) {
        .bundle => return run_bundle(host, invocation, &storage.workspace, diag),
        .help => try print(host, help_text, diag),
        .version => try print(host, version_text, diag),
        .explain => try run_explain(
            host,
            invocation.operand.?,
            invocation.options.output == .json,
            diag,
        ),
        .lock => lock_commands.run_show(
            host,
            &storage.pull.unpack.locking,
            invocation.options.output == .json,
            diag,
        ) catch |err| return lock_error(err),
        .doctor => return run_doctor(host, invocation.options, &storage.handle.facts, diag),
        .run => return run_container(host, invocation, storage, diag),
        .ps => commands.run_ps(
            host,
            &storage.entries,
            invocation.options.output == .json,
            invocation.run.all,
            diag,
        ) catch |err| return command_error(err),
        .schema => commands.run_schema(host, invocation.operand.?, diag) catch |err| {
            return command_error(err);
        },
        .stop => return run_stop(host, invocation, diag),
        .pull => return run_pull(host, invocation, storage, diag),
        .commit => return run_store(host, invocation, storage, diag),
        .store => return run_store(host, invocation, storage, diag),
    }
    return constants.exit_ok;
}

fn lock_error(err: lock_commands.Error) RunError {
    assert(@errorName(err).len > 0);
    return switch (err) {
        error.Failed => error.CommandFailed,
        error.OutputFailed => error.OutputFailed,
    };
}

fn command_error(err: commands.Error) RunError {
    assert(@errorName(err).len > 0);
    assert(@intFromError(err) != 0);
    return switch (err) {
        error.Failed => error.CommandFailed,
        error.OutputFailed => error.OutputFailed,
    };
}

/// `zbx pull [--resolve-only] <reference>`: the registry's answer for this machine's platform,
/// and unless only that was asked for, the image in the store.
fn run_pull(
    host: Host,
    invocation: *const Invocation,
    storage: *Storage,
    diag: *Diag,
) RunError!u8 {
    assert(invocation.command == .pull);
    const args: pull_commands.Args = .{
        .reference = invocation.operand.?,
        .json = invocation.options.output == .json,
    };
    if (invocation.pull.resolve_only) {
        pull_commands.run_resolve(host, args, &storage.pull, diag) catch |err| switch (err) {
            error.Failed => return error.CommandFailed,
            error.OutputFailed => return error.OutputFailed,
        };
        return constants.exit_ok;
    }
    const mode = invocation.options.mode();
    const output: pull_commands.Output = .{
        .mode = mode,
        .color = mode != .json and host.color_enabled(.stderr),
        .json = args.json,
    };
    return pull_commands.run_pull(
        host,
        args,
        output,
        &storage.handle.facts,
        &storage.pull,
        &storage.store.import,
        diag,
    ) catch |err| switch (err) {
        error.Failed => return error.CommandFailed,
        error.OutputFailed => return error.OutputFailed,
    };
}

/// `zbx stop <name>`: the times are checked first (`ZBX-E0401`), then the container is stopped.
fn run_stop(host: Host, invocation: *const Invocation, diag: *Diag) RunError!u8 {
    assert(invocation.command == .stop);
    assert(diag.code == null);
    const times = try times_of(&invocation.run, diag);
    var options: commands.StopOptions = .{
        .name = invocation.operand.?,
        .json = invocation.options.output == .json,
    };
    if (invocation.run.grace != null) options.grace_ms = times.grace_ms;
    if (invocation.run.timeout != null) options.timeout_ms = times.timeout_ms;
    commands.run_stop(host, options, diag) catch |err| return command_error(err);
    return constants.exit_ok;
}

/// `zbx store ...`: the work runs in the store's child; its exit code is ours.
fn run_store(
    host: Host,
    invocation: *const Invocation,
    storage: *Storage,
    diag: *Diag,
) RunError!u8 {
    if (invocation.command != .store) assert(invocation.command == .commit);
    assert(diag.code == null);
    assert(storage.gc_tables.len >= gc.tables_bytes_min); // The caller gave gc its room.
    storage.store.gc.tables = storage.gc_tables;
    const mode = invocation.options.mode();
    const output: store_commands.Output = .{
        .mode = mode,
        .color = mode != .json and host.color_enabled(.stderr),
        .json = invocation.options.output == .json,
    };
    const args: store_commands.Args = .{
        .action = invocation.store.action,
        .operand = invocation.store.operand,
        .second = invocation.store.second,
        .confirm = invocation.store.confirm,
        .trash = invocation.store.trash,
        .by_image = invocation.store.by_image,
    };
    return store_commands.run(
        host,
        args,
        output,
        &storage.handle.facts,
        &storage.store,
        diag,
    ) catch {
        return error.CommandFailed;
    };
}

const Times = struct { timeout_ms: u32, grace_ms: u32 };

/// `--timeout` (0: none) and `--grace` as milliseconds, or `ZBX-E0401` for the first bad one.
fn times_of(given: *const RunArgs, diag: *Diag) RunError!Times {
    assert(diag.code == null);
    var times: Times = .{ .timeout_ms = 0, .grace_ms = constants.stop_grace_ms_default };
    if (given.timeout) |text| {
        times.timeout_ms = commands.parse_millis(text, 1) orelse {
            diagnose.time_invalid(diag, "--timeout", text);
            return error.CommandFailed;
        };
    }
    if (given.grace) |text| {
        times.grace_ms = commands.parse_millis(text, 0) orelse {
            diagnose.time_invalid(diag, "--grace", text);
            return error.CommandFailed;
        };
    }
    assert(times.grace_ms <= constants.wait_timeout_ms_max);
    assert(times.timeout_ms <= constants.wait_timeout_ms_max);
    return times;
}

/// Where a warning from the runtime is written: stderr, in the mode the user asked for.
const Reporter = struct {
    host: Host,
    options: Options,
};

fn report_warning(context: *anyopaque, diag: *const Diag) void {
    const reporter: *const Reporter = @ptrCast(@alignCast(context));
    assert(diag.code != null);
    const mode = reporter.options.mode();
    const color = mode != .json and reporter.host.color_enabled(.stderr);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const text = render.render(diag, mode, color, &buffer);
    // A warning that cannot be written is lost, and the run goes on: it is only a warning.
    reporter.host.write_all(.stderr, text) catch return;
}

comptime {
    // The run's handle is over 300 KiB (it holds a plan, a diagnostic and the doctor's facts), so
    // the caller provides it: `Storage`.
    assert(@sizeOf(runtime.Handle) <= constants.handle_bytes_max);
}

/// Runs a container in the foreground and returns its exit code: the command's own, or 128
/// plus the signal that killed it. A container that could not be started is a diagnostic; so is
/// one whose end could not be waited for.
/// An image named by a tag or a digest reference: finds it, pulls it if the project has no lock.
fn prepare_image(
    host: Host,
    invocation: *const Invocation,
    storage: *Storage,
    operand: []const u8,
    prepared: *run_image.Prepared,
    diag: *Diag,
) RunError!void {
    assert(operand.len > 0);
    const mode = invocation.options.mode();
    var reporter: Reporter = .{ .host = host, .options = invocation.options };
    const services: run_image.Services = .{
        .host = host,
        .facts = &storage.handle.facts,
        .pull = &storage.pull,
        .import_workspace = &storage.store.import,
        .output = .{
            .mode = mode,
            .color = mode != .json and host.color_enabled(.stderr),
            .json = false,
        },
        .warn = .{ .context = &reporter, .call = report_warning },
    };
    run_image.prepare(
        &services,
        &storage.run_image,
        operand,
        invocation.run.command,
        prepared,
        diag,
    ) catch |err| switch (err) {
        error.Failed => return error.StartFailed,
        error.PullFailed => return error.PullFailed,
    };
}

fn run_container(
    host: Host,
    invocation: *const Invocation,
    storage: *Storage,
    diag: *Diag,
) RunError!u8 {
    assert(diag.code == null);
    assert(invocation.command == .run);
    const given = invocation.run;
    const times = try times_of(&given, diag);
    var prepared: run_image.Prepared = .{
        .tree = invocation.operand orelse "",
        .command = given.command,
        .env = &.{},
        .workdir = "",
        .user = null,
    };
    if (invocation.operand) |operand| {
        if (operand.len > 0 and !is_tree_operand(operand)) {
            prepare_image(host, invocation, storage, operand, &prepared, diag) catch |err| {
                // A pull the run began has written its own diagnostic: only the exit code is left.
                if (err == error.PullFailed) return constants.exit_run_failed;
                return err;
            };
        }
    }
    const container: runtime_spec.Spec = .{
        .rootfs = given.rootfs orelse "", // check_run_args refused neither or both.
        .image = if (invocation.operand != null) prepared.tree else null,
        .name = given.name,
        .command = prepared.command,
        .limits = try limits_of(&given, diag),
        .read_only = given.read_only,
        .env = prepared.env,
        .workdir = prepared.workdir,
        .user = prepared.user,
        .network = network_of(&given),
        .publish = given.publish_slice(),
    };
    const ran = ran_of(invocation, &prepared);
    if (given.detach) return run_detached(host, invocation, &container, times, storage, &ran, diag);
    var reporter: Reporter = .{ .host = host, .options = invocation.options };
    const options: runtime.StartOptions = .{
        .warn = .{ .context = &reporter, .call = report_warning },
        .timeout_ms = times.timeout_ms,
        .grace_ms = times.grace_ms,
        .image_workspace = &storage.image,
    };
    const handle = &storage.handle;
    runtime.start(host, &container, options, handle, diag) catch {
        keep_bundle_of_bug(host, &storage.workspace, handle, diag);
        return error.StartFailed;
    };
    const reason = runtime.wait(handle);
    const code = reason.code() orelse {
        diag.* = handle.lost_diag; // The only reason a started run has no code.
        keep_bundle_of_bug(host, &storage.workspace, handle, diag);
        return error.StartFailed;
    };
    report_outcome(host, invocation.options, handle, &reason, &ran, given.net != null);
    return code;
}

/// What a run ran, for `--output json`: an image (the name as typed, its manifest and the tree
/// it became), a tree of the store, or a directory. The tree is not here: a prefix of one is
/// only resolved when the run starts, so it is taken from the run.
const Ran = struct {
    kind: enum { image, tree, rootfs },
    /// The name as typed (image), or the directory (rootfs); empty for a tree.
    text: []const u8,
    manifest: ?Sha256,
};

fn ran_of(invocation: *const Invocation, prepared: *const run_image.Prepared) Ran {
    assert(invocation.command == .run);
    const operand = invocation.operand orelse {
        const path = invocation.run.rootfs.?; // check_run_args refused neither or both.
        return .{ .kind = .rootfs, .text = path, .manifest = null };
    };
    assert(invocation.run.rootfs == null);
    if (is_tree_operand(operand)) return .{ .kind = .tree, .text = "", .manifest = null };
    assert(prepared.manifest != null);
    return .{ .kind = .image, .text = operand, .manifest = prepared.manifest };
}

/// Adds `"ran":{...}` to the JSON line in `writer`, which ends in "}\n": inside the line's one
/// object, after its last member. `tree` is the digest the run used; empty for a directory.
/// If the line has no room the line is left as it was.
fn append_ran(writer: *std.Io.Writer, ran: *const Ran, tree: []const u8) void {
    const line = writer.buffered();
    assert(line.len >= 3);
    assert(std.mem.endsWith(u8, line, "}\n"));
    const mark = writer.end;
    writer.end -= 2;
    if (write_ran(writer, ran, tree)) {
        writer.writeAll("}\n") catch unreachable; // Two bytes were freed above.
        return;
    }
    writer.end = mark;
    assert(std.mem.endsWith(u8, writer.buffered(), "}\n"));
}

fn write_ran(writer: *std.Io.Writer, ran: *const Ran, tree: []const u8) bool {
    if (ran.kind == .tree) assert(tree.len > 0);
    switch (ran.kind) {
        .image => {
            writer.writeAll(",\"ran\":{\"kind\":\"image\",\"reference\":") catch return false;
            bundle.write_json_string(writer, ran.text) catch return false;
            const manifest = ran.manifest.?;
            writer.print(",\"manifest\":\"{s}\",\"tree\":\"{s}\"}}", .{
                &manifest.text(), tree,
            }) catch return false;
        },
        .tree => writer.print(",\"ran\":{{\"kind\":\"tree\",\"tree\":\"{s}\"}}", .{tree}) catch
            return false,
        .rootfs => {
            writer.writeAll(",\"ran\":{\"kind\":\"rootfs\",\"path\":") catch return false;
            bundle.write_json_string(writer, ran.text) catch return false;
            writer.writeByte('}') catch return false;
        },
    }
    return true;
}

/// The network the flags asked for: none unless granted; `--publish` alone is `user`.
/// `check_network_args` has refused every other combination already.
fn network_of(given: *const RunArgs) runtime_spec.Network {
    const value = given.net orelse {
        return if (given.publish_count > 0) .user else .none;
    };
    const word = net_word_named(value).?;
    if (given.publish_count > 0) assert(word == .user);
    return switch (word) {
        .none => .none,
        .host => .host,
        .user => .user,
    };
}

/// The limits the flags asked for, or `ZBX-E0306` for the first that is not acceptable.
fn limits_of(given: *const RunArgs, diag: *Diag) RunError!runtime_spec.Limits {
    assert(diag.code == null);
    var limits: runtime_spec.Limits = .{};
    if (given.memory) |text| {
        limits.memory_bytes = runtime_spec.parse_memory(text) catch |problem| {
            diagnose.limit_invalid(diag, .memory, text, problem);
            return error.StartFailed;
        };
    }
    if (given.pids) |text| {
        limits.pids = runtime_spec.parse_pids(text) catch |problem| {
            diagnose.limit_invalid(diag, .pids, text, problem);
            return error.StartFailed;
        };
    }
    if (given.cpus) |text| {
        limits.cpu_millis = runtime_spec.parse_cpus(text) catch |problem| {
            diagnose.limit_invalid(diag, .cpus, text, problem);
            return error.StartFailed;
        };
    }
    assert(runtime_spec.limits_problem(limits) == null);
    return limits;
}

// ---- A detached run -----------------------------------------------------------------------

// A detached run is two processes. The supervisor is a fork of the caller: it starts the
// container, tells the caller over a pipe how that went, and stays to wait for it and finish its
// record. The caller reads the pipe, prints what the supervisor said as if it had started the
// container itself, and exits. The pipe carries frames: a tag byte, a two-byte length and that
// many bytes.

const frame_warning: u8 = 1;
const frame_started: u8 = 2;
const frame_failed: u8 = 3;

fn write_frame(
    host: Host,
    fd: host_mod.Handle,
    tag: u8,
    head: ?u8,
    body: []const u8,
) host_mod.Error!void {
    assert(body.len < constants.output_bytes_max);
    assert(tag >= frame_warning);
    assert(tag <= frame_failed);
    // Starting a scope puts SIGPIPE back; a caller that has gone must not kill the supervisor.
    host.ignore_broken_pipe(true);
    const length: u16 = @intCast(body.len + @intFromBool(head != null));
    const header = [3]u8{ tag, @truncate(length), @truncate(length >> 8) };
    try host.write_handle_all(fd, &header);
    if (head) |byte| try host.write_handle_all(fd, &[1]u8{byte});
    if (body.len > 0) try host.write_handle_all(fd, body);
}

/// A warning of the supervisor's start, rendered as the caller would have, goes down the pipe.
const FrameSink = struct {
    host: Host,
    fd: host_mod.Handle,
    options: Options,
};

fn frame_warning_call(context: *anyopaque, diag: *const Diag) void {
    const sink: *const FrameSink = @ptrCast(@alignCast(context));
    assert(diag.code != null);
    assert(sink.options.runs_container);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const text = render.render(diag, sink.options.mode(), false, &buffer);
    write_frame(sink.host, sink.fd, frame_warning, null, text) catch return;
}

fn run_detached(
    host: Host,
    invocation: *const Invocation,
    container: *const runtime_spec.Spec,
    times: Times,
    storage: *Storage,
    ran: *const Ran,
    diag: *Diag,
) RunError!u8 {
    assert(diag.code == null);
    assert(container.command.len > 0);
    assert(invocation.run.detach);
    assert(times.grace_ms <= constants.wait_timeout_ms_max);
    const pipe = host.pipe() catch |err| return supervisor_failed(host, diag, err);
    // A write to a caller that has gone is an error to ignore, not a signal that kills us.
    host.ignore_broken_pipe(true);
    const role = host.fork_supervisor() catch |err| {
        host.close(pipe.read);
        host.close(pipe.write);
        return supervisor_failed(host, diag, err);
    };
    switch (role) {
        .parent => {
            host.close(pipe.write);
            defer host.close(pipe.read);
            return relay(host, pipe.read, invocation.options, ran, diag);
        },
        .supervisor => {
            host.close(pipe.read);
            const code = supervise(host, invocation, container, times, storage, pipe.write);
            // exit_now closes the pipe: `supervise` may already have, and that number may be
            // another file by now.
            host.exit_now(code);
            return code;
        },
    }
}

fn supervisor_failed(host: Host, diag: *Diag, err: host_mod.Error) RunError {
    assert(diag.code == null);
    assert(@errorName(err).len > 0);
    const fault: diagnose.SupervisorFault = .{
        .fork = .{ .step = 0, .err = err, .errno = host.last_errno() },
    };
    diagnose.supervisor_failed(diag, fault);
    return error.CommandFailed;
}

/// The supervisor: starts the container, says how it went, waits for it. The caller of
/// `run -d` is waiting on `fd` for the first frame that is not a warning. Never writes to
/// the terminal (its streams are on /dev/null).
fn supervise(
    host: Host,
    invocation: *const Invocation,
    container: *const runtime_spec.Spec,
    times: Times,
    storage: *Storage,
    fd: host_mod.Handle,
) u8 {
    var sink: FrameSink = .{ .host = host, .fd = fd, .options = invocation.options };
    assert(times.grace_ms <= constants.wait_timeout_ms_max);
    assert(container.command.len > 0);
    const options: runtime.StartOptions = .{
        .warn = .{ .context = &sink, .call = frame_warning_call },
        .timeout_ms = times.timeout_ms,
        .grace_ms = times.grace_ms,
        .detached = true,
        .image_workspace = &storage.image,
    };
    var diag: Diag = undefined;
    diag.reset();
    const handle = &storage.handle;
    runtime.start(host, container, options, handle, &diag) catch {
        if (diag.code == null) {
            diag.raise(.B0001);
            diag.cause("a failure reached the supervisor with no diagnostic", .{});
        }
        var buffer: [constants.output_bytes_max]u8 = undefined;
        const text = render.render(&diag, invocation.options.mode(), false, &buffer);
        const code = diag.exit_code_in(.container_run);
        write_frame(host, fd, frame_failed, code, text) catch return code;
        return code;
    };
    const started_bytes_max = constants.container_name_bytes_max +
        constants.scope_name_bytes_max + 24 + constants.store_digest_text_bytes + 1;
    var body: [started_bytes_max]u8 = undefined;
    const scope = if (handle.plan.scoped) handle.plan.text(handle.plan.scope_name) else "-";
    // The tree the container runs on, whole (a prefix was resolved by the start), or "-".
    const tree = if (handle.has_image) handle.image.tree_text() else "-";
    const made = std.fmt.bufPrint(&body, "{s} {d} {s} {s}", .{
        handle.name_slice(),
        handle.pid,
        scope,
        tree,
    }) catch unreachable; // A name, a pid, a scope name and a tree fit the buffer.
    write_frame(host, fd, frame_started, null, made) catch {};
    host.close(fd); // The caller can go; the container's end is ours to see to.
    _ = runtime.wait(handle);
    return constants.exit_ok;
}

/// Reads exactly `into.len` bytes; false at the end of the pipe.
fn read_exact(host: Host, fd: host_mod.Handle, into: []u8) host_mod.Error!bool {
    assert(into.len > 0);
    assert(into.len <= constants.output_bytes_max);
    var have: usize = 0;
    while (have < into.len) {
        const count = try host.read_some(fd, into[have..]);
        if (count == 0) return false;
        have += count;
    }
    return true;
}

/// The caller of `run -d`: passes the supervisor's warnings on, then prints how the start went.
fn relay(
    host: Host,
    fd: host_mod.Handle,
    options: Options,
    ran: *const Ran,
    diag: *Diag,
) RunError!u8 {
    assert(diag.code == null);
    assert(options.runs_container);
    var body: [constants.output_bytes_max]u8 = undefined;
    while (true) {
        var header: [3]u8 = undefined;
        const got_header = read_exact(host, fd, &header) catch false;
        if (!got_header) break;
        const length = @as(usize, header[1]) | (@as(usize, header[2]) << 8);
        if (length > body.len) break;
        const got_body = length == 0 or (read_exact(host, fd, body[0..length]) catch false);
        if (!got_body) break;
        switch (header[0]) {
            frame_warning => host.write_all(.stderr, body[0..length]) catch {},
            frame_failed => {
                if (length < 1) break;
                host.write_all(.stderr, body[1..length]) catch {};
                return body[0];
            },
            frame_started => return print_started(host, options, body[0..length], ran, diag),
            else => break,
        }
    }
    diagnose.supervisor_failed(diag, .ended_early);
    return error.CommandFailed;
}

fn print_started(
    host: Host,
    options: Options,
    text: []const u8,
    ran: *const Ran,
    diag: *Diag,
) RunError!u8 {
    assert(diag.code == null);
    assert(text.len < constants.output_bytes_max);
    var fields = std.mem.splitScalar(u8, text, ' ');
    const name = fields.next() orelse "";
    const pid = fields.next() orelse "0";
    const scope = fields.next() orelse "-";
    const tree = fields.next() orelse "-";
    var buffer: [constants.path_bytes_max * 6 + 1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    // Cannot fail: the fields are bounded names and a number, in 512 bytes.
    if (options.output == .json) {
        const head = "{\"schema\":\"zbx.run/1\",\"container\":{\"name\":";
        writer.writeAll(head) catch unreachable; // Same bound.
        bundle.write_json_string(&writer, name) catch unreachable; // Same bound.
        writer.print(",\"pid\":{s},\"scope\":", .{pid}) catch unreachable; // Same.
        if (std.mem.eql(u8, scope, "-")) {
            writer.writeAll("null") catch unreachable; // Same.
        } else {
            bundle.write_json_string(&writer, scope) catch unreachable; // Same.
        }
        writer.writeAll(",\"detached\":true}}\n") catch unreachable; // Same.
        append_ran(&writer, ran, tree);
    } else {
        writer.print("{s}\n", .{name}) catch unreachable; // Same bound.
    }
    try print(host, writer.buffered(), diag);
    return constants.exit_ok;
}

/// A `bug` from a run that got as far as having a name gets a redacted bundle, and the bug
/// block says where it is. Any other diagnostic is left alone: a bundle is for bugs.
pub fn keep_bundle_of_bug(
    host: Host,
    workspace: *bundle.Workspace,
    handle: *const runtime.Handle,
    diag: *Diag,
) void {
    assert(diag.code != null);
    if (diag.entry().severity != .bug) return;
    if (handle.name_len == 0) return; // It failed before the run had a name or a record.
    bundle.attach_to_bug(host, workspace, handle.name_slice(), diag);
}

/// `zbx bundle`: writes the bundle and prints its path on stdout (a JSON object with --output
/// json). `--no-redact` first warns on stderr.
fn run_bundle(
    host: Host,
    invocation: *const Invocation,
    workspace: *bundle.Workspace,
    diag: *Diag,
) RunError!u8 {
    assert(diag.code == null);
    assert(invocation.command == .bundle);
    const no_redact = invocation.bundle.no_redact;
    if (no_redact) {
        var warning: Diag = undefined;
        warning.reset();
        bundle.unredacted_warning(&warning);
        var reporter: Reporter = .{ .host = host, .options = invocation.options };
        report_warning(&reporter, &warning);
    }
    var saved: bundle.Saved = undefined;
    const request: bundle.Request = .{ .name = invocation.operand, .redact = !no_redact };
    bundle.write(host, workspace, request, &saved, diag) catch return error.BundleFailed;
    var line: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&line);
    // Cannot fail: a path of at most 640 bytes escapes to at most six times that, plus a frame.
    if (invocation.options.output == .json) {
        writer.writeAll("{\"bundle\":") catch unreachable; // Sized above.
        bundle.write_json_string(&writer, saved.slice()) catch unreachable; // Same.
        writer.writeAll("}\n") catch unreachable; // Same.
    } else {
        writer.print("{s}\n", .{saved.slice()}) catch unreachable; // Same.
    }
    const text = writer.buffered();
    try print(host, text, diag);
    return constants.exit_ok;
}

/// Says on stderr how the container ended. Text mode names a signal that killed it (and, with
/// --verbose, the steps that were skipped); JSON mode ends with one `container_exit` line, so a
/// script can tell the container's exit code from zbx's own. A failed write is ignored: the
/// exit code is the container's and there is nowhere left to say more.
fn report_outcome(
    host: Host,
    options: Options,
    handle: *const runtime.Handle,
    reason: *const runtime.ExitReason,
    ran: *const Ran,
    network_given: bool,
) void {
    assert(handle.status == .stopped);
    assert(reason.code() != null);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    const timed_out = runtime.timed_out(handle);
    if (options.output == .json) {
        write_container_exit(&writer, reason);
        // The line ends "}}\n"; the network mode goes inside, and so does a stop for the time.
        writer.end -= 3;
        // Cannot fail: three bytes were freed and a short field fits a message.
        writer.print(",\"network\":\"{s}\"}}}}\n", .{handle.network.word()}) catch unreachable;
        writer.end -= 3;
        write_published(&writer, handle.publish_slice());
        if (timed_out) {
            writer.end -= 3;
            writer.writeAll(",\"timed_out\":true}}\n") catch unreachable; // Three bytes were freed.
        }
        append_ran(&writer, ran, if (handle.has_image) handle.image.tree_text() else "");
    } else {
        if (options.verbose) {
            for (handle.note_slice()) |*note| {
                // Cannot fail: a note is at most 160 bytes and the buffer holds a message.
                writer.print("zbx: note: {s}\n", .{note.slice()}) catch unreachable;
            }
        }
        if (options.verbose) write_ended_note(&writer, reason);
        write_signal_note(&writer, reason);
        if (timed_out) {
            const format = "zbx: stopped: timed out after {d} ms\n";
            // Cannot fail: a short line into a buffer that holds a message.
            writer.print(format, .{handle.wait_options.timeout_ms}) catch unreachable;
        }
        write_network_hint(&writer, handle.network, network_given, reason);
    }
    const text = writer.buffered();
    if (text.len > 0) host.write_all(.stderr, text) catch return;
}

/// `"published":[{"host":8080,"container":80}]` and the line's end, "}}\n": the forwards, in
/// the order given, empty for a run without any. Added in M5 beside `network`; additive.
fn write_published(writer: *std.Io.Writer, list: []const runtime_spec.Publish) void {
    assert(list.len <= constants.publish_count_max);
    // A forward is at most 34 bytes; sixteen of them and the member's name fit with room.
    comptime assert(constants.publish_count_max * 40 + 32 < constants.output_bytes_max / 4);
    writer.writeAll(",\"published\":[") catch unreachable; // Bounded above.
    for (list, 0..) |publish, index| {
        assert(publish.host > 0);
        const comma: []const u8 = if (index == 0) "" else ",";
        const format = "{s}{{\"host\":{d},\"container\":{d}}}";
        // Cannot fail: bounded above.
        writer.print(format, .{ comma, publish.host, publish.container }) catch unreachable;
    }
    writer.writeAll("]}}\n") catch unreachable; // Bounded above.
}

/// The one line a failed run without `--net` gets after the container's own output: the network
/// was none, and here is the flag. Only after the container's own exit with a code. A note,
/// not a diagnostic: the exit code is the container's.
/// Never for an explicit `--net none`.
fn write_network_hint(
    writer: *std.Io.Writer,
    network: runtime_spec.Network,
    network_given: bool,
    reason: *const runtime.ExitReason,
) void {
    assert(writer.buffer.len >= constants.output_bytes_max / 2);
    if (network_given) return;
    if (network != .none) return;
    // Only the container's own non-zero exit: a signal, a timeout or a limit has its own line.
    const code = switch (reason.*) {
        .exited => |value| value,
        else => return,
    };
    if (code == constants.exit_ok) return;
    // Cannot fail: a short line into a buffer that holds a message.
    writer.writeAll("zbx: network: none (grant with --net)\n") catch unreachable;
}

/// With --verbose, what the container's first process did when the report says something else
/// (the exit code is 137 for an OOM kill whatever it did), so nothing is hidden.
fn write_ended_note(writer: *std.Io.Writer, reason: *const runtime.ExitReason) void {
    assert(writer.end < writer.buffer.len);
    assert(writer.buffer.len >= constants.output_bytes_max / 2);
    const ended = switch (reason.*) {
        .oom => |hit| hit.ended,
        .pid_limit => |hit| hit.ended,
        else => return,
    };
    // Cannot fail: a short line into a buffer that holds a message.
    switch (ended) {
        .exited => |code| writer.print(
            "zbx: note: the container's first process exited with code {d}\n",
            .{code},
        ) catch unreachable, // Same bound as above.
        .signaled => |number| writer.print(
            "zbx: note: the container's first process was killed by signal {d}\n",
            .{number},
        ) catch unreachable, // Same bound as above.
    }
}

/// A size as the largest binary unit that divides it, "128 MiB".
fn bytes_words(buffer: []u8, bytes: u64) []const u8 {
    assert(buffer.len >= 32);
    assert(bytes > 0);
    const units = [_]struct { size: u64, name: []const u8 }{
        .{ .size = 1 << 40, .name = "TiB" },
        .{ .size = 1 << 30, .name = "GiB" },
        .{ .size = 1 << 20, .name = "MiB" },
        .{ .size = 1 << 10, .name = "KiB" },
    };
    for (units) |unit| {
        if (bytes >= unit.size and bytes % unit.size == 0) {
            // Cannot fail: twenty digits and a unit fit 32 bytes.
            return std.fmt.bufPrint(buffer, "{d} {s}", .{ bytes / unit.size, unit.name }) catch
                unreachable; // Same bound as above.
        }
    }
    return std.fmt.bufPrint(buffer, "{d} bytes", .{bytes}) catch unreachable; // Same.
}

fn write_signal_note(writer: *std.Io.Writer, reason: *const runtime.ExitReason) void {
    assert(writer.end < writer.buffer.len);
    assert(writer.buffer.len >= constants.output_bytes_max / 2);
    var words: [32]u8 = undefined;
    // Cannot fail: short lines into a buffer that holds a message.
    switch (reason.*) {
        .oom => |hit| {
            if (hit.limit_bytes) |limit| {
                writer.print("zbx: killed: out of memory (limit {s})\n", .{
                    bytes_words(&words, limit),
                }) catch unreachable; // Same bound as above.
            } else {
                writer.print("zbx: killed: out of memory\n", .{}) catch unreachable; // Same.
            }
            return;
        },
        .pid_limit => |hit| {
            if (hit.limit) |limit| {
                writer.print("zbx: stopped: process limit reached (limit {d})\n", .{limit}) catch
                    unreachable; // Same bound as above.
            } else {
                writer.writeAll("zbx: stopped: process limit reached\n") catch unreachable; // Same.
            }
            return;
        },
        else => {},
    }
    const number = switch (reason.*) {
        .signaled => |signal| signal,
        else => return,
    };
    const code: std.os.linux.SIG = @fromBackingInt(number);
    const name = std.enums.tagName(std.os.linux.SIG, code) orelse "?";
    // Cannot fail: a short line into a buffer that holds a message.
    writer.print("zbx: the container was killed by signal {d} (SIG{s})\n", .{ number, name }) catch
        unreachable; // Same bound as above.
}

fn write_optional(writer: *std.Io.Writer, value: anytype) void {
    assert(writer.end < writer.buffer.len);
    assert(writer.buffer.len >= constants.output_bytes_max / 2);
    // Cannot fail: a number or null in a buffer that holds a message.
    if (value) |number| {
        writer.print("{d}", .{number}) catch unreachable; // Same bound as above.
    } else {
        writer.writeAll("null") catch unreachable; // Same.
    }
}

fn write_container_exit(writer: *std.Io.Writer, reason: *const runtime.ExitReason) void {
    const code = reason.code().?; // Only called for a command that ran.
    assert(writer.buffer.len >= constants.output_bytes_max / 2);
    assert(writer.end < writer.buffer.len);
    // Cannot fail: a short line into a buffer that holds a message.
    switch (reason.*) {
        .signaled => |number| {
            const format = "{{\"container_exit\":{{\"reason\":\"signal\",\"signal\":{d}," ++
                "\"code\":{d}}}}}\n";
            writer.print(format, .{ number, code }) catch unreachable; // Same bound as above.
        },
        .oom => |hit| {
            writer.writeAll("{\"container_exit\":{\"reason\":\"oom\",\"limit_bytes\":") catch
                unreachable; // Same bound as above.
            write_optional(writer, hit.limit_bytes);
            writer.print(",\"code\":{d}}}}}\n", .{code}) catch unreachable; // Same.
        },
        .pid_limit => |hit| {
            writer.writeAll("{\"container_exit\":{\"reason\":\"pid_limit\",\"limit\":") catch
                unreachable; // Same bound as above.
            write_optional(writer, hit.limit);
            writer.print(",\"code\":{d}}}}}\n", .{code}) catch unreachable; // Same.
        },
        else => {
            const format = "{{\"container_exit\":{{\"reason\":\"exited\",\"code\":{d}}}}}\n";
            writer.print(format, .{code}) catch unreachable; // Same bound as above.
        },
    }
}

/// Runs the doctor: its report goes to stdout, then the diagnostic of each FAIL goes to stderr,
/// in check order, in the requested mode. Text blocks are separated by a blank line; JSON is
/// one object per line. The exit code is the blame of the failures' diagnostics (the
/// environment's) and, if stderr cannot be written, the same: there is nowhere to say so.
fn run_doctor(host: Host, options: Options, facts: *doctor.Facts, diag: *Diag) RunError!u8 {
    assert(diag.code == null);
    var report: doctor.Report = undefined;
    try doctor.run(host, facts, &report, diag);
    const mode = options.mode();
    const color = mode != .json and host.color_enabled(.stderr);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    var blocks: u32 = 0;
    for (&report.checks) |*check| {
        if (check.status != .fail) continue;
        const separator = blocks > 0 and mode != .json;
        if (separator) host.write_all(.stderr, "\n") catch return constants.exit_environment;
        const block = render.render(&check.diag, mode, color, &buffer);
        host.write_all(.stderr, block) catch return constants.exit_environment;
        blocks += 1;
    }
    const code = report.exit_code();
    // A failure has a block and an environment exit code; no failure has neither.
    assert((blocks > 0) == (code == constants.exit_environment));
    if (blocks == 0) assert(code == constants.exit_ok);
    return code;
}

fn run_explain(host: Host, operand: []const u8, json: bool, diag: *Diag) RunError!void {
    assert(operand.len <= constants.arg_bytes_max);
    assert(diag.code == null);
    const code = codes.parse(operand) orelse {
        var storage: [constants.arg_echo_bytes_max]u8 = undefined;
        const echo = echo_of(&storage, operand);
        diag.raise(.E0007);
        diag.while_("looking up a diagnostic code", .{});
        diag.cause("'{s}' is not a diagnostic code zbx has", .{echo});
        diag.context("arg", "{s}", .{echo});
        diag.fix(.{ .sentence = "codes look like this:", .command = "zbx explain E0001" });
        return error.UnknownCode;
    };
    var buffer: [constants.output_bytes_max]u8 = undefined;
    if (json) return print(host, explain.render_json(code, &buffer), diag);
    try print(host, explain.render(code, &buffer), diag);
}

/// Writes a message to stdout. A failed write is `ZBX-E0009` in `diag`.
fn print(host: Host, text: []const u8, diag: *Diag) RunError!void {
    assert(text.len > 0);
    assert(text.len <= constants.output_bytes_max);
    assert(diag.code == null);
    host.write_all(.stdout, text) catch |err| {
        errors.output_failed(diag, .stdout, err, host.last_errno());
        return error.OutputFailed;
    };
}

/// The one place a failure becomes output and an exit code: renders `diag` to stderr in the
/// requested mode and returns the exit code its blame decides. A diagnostic nobody classified
/// is a bug in zbx and is reported as one. If stderr itself cannot be written there is nowhere
/// to say so, and the exit code is the environment's.
pub fn fail(host: Host, diag: *Diag, options: Options) u8 {
    if (diag.code == null) {
        diag.raise(.B0001);
        diag.cause("a failure reached the command line with no diagnostic", .{});
    }
    assert(diag.code != null);
    const mode = options.mode();
    const color = mode != .json and host.color_enabled(.stderr);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const output = render.render(diag, mode, color, &buffer);
    const scope = options.exit_scope();
    host.write_all(.stderr, output) catch return codes.exit_code_unwritable(scope);
    const code = diag.exit_code_in(scope);
    assert(code != constants.exit_ok);
    if (options.runs_container) assert(code >= constants.exit_run_failed);
    return code;
}

// ---- Tests ---------------------------------------------------------------------------------

const testing = std.testing;
const HostSim = @import("host_sim.zig").HostSim;
const repeat = @import("test_util.zig").repeat;

const SliceIterator = struct {
    items: []const [:0]const u8,
    index: u32 = 0,

    fn next(iterator: *SliceIterator) ?[:0]const u8 {
        if (iterator.index == iterator.items.len) return null;
        defer iterator.index += 1;
        return iterator.items[iterator.index];
    }
};

/// Runs the CLI against a fresh simulator and returns it with the exit code.
fn run_case(sim: *HostSim, args: []const [:0]const u8) !u8 {
    sim.init(1, &.{});
    var iterator: SliceIterator = .{ .items = args };
    const code = run_from_iterator(sim.interface(), &iterator);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
    return code;
}

/// Parses `args` (without the program name) and returns the error and the diagnostic's code.
fn parse_case(args: []const []const u8, invocation: *Invocation) !?codes.Code {
    var diag: Diag = undefined;
    diag.reset();
    parse(args, invocation, &diag) catch return diag.code.?;
    try testing.expect(diag.code == null);
    return null;
}

test "snapshot: help text on stdout, exit 0" {
    // Goal: the user-visible help is exactly the checked-in text. Method: compare byte for byte
    // against src/testdata/help.stdout.txt; update that file deliberately when help changes.
    var sim: HostSim = undefined;
    try testing.expectEqual(@as(u8, 0), try run_case(&sim, &.{ "zbx", "help" }));
    try testing.expectEqualStrings(@embedFile("testdata/help.stdout.txt"), sim.stdout());
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    try testing.expectEqual(@as(u8, 0), try run_case(&sim, &.{ "zbx", "--help" }));
    try testing.expectEqualStrings(@embedFile("testdata/help.stdout.txt"), sim.stdout());
    // Options before and after the command do not change what help prints.
    const decorated = [_][:0]const u8{ "zbx", "-v", "help", "--output=json" };
    try testing.expectEqual(@as(u8, 0), try run_case(&sim, &decorated));
    try testing.expectEqualStrings(@embedFile("testdata/help.stdout.txt"), sim.stdout());
}

test "snapshot: --version prints the pinned version on stdout, exit 0" {
    // Goal: one line, "zbx <version>", where the version is build.zig.zon's.
    var sim: HostSim = undefined;
    try testing.expectEqual(@as(u8, 0), try run_case(&sim, &.{ "zbx", "--version" }));
    try testing.expectEqualStrings("zbx " ++ build_options.version ++ "\n", sim.stdout());
    try testing.expect(std.mem.startsWith(u8, sim.stdout(), "zbx 0."));
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
}

test "snapshot: explain prints the registry text on stdout, exit 0" {
    // Goal: `explain` accepts E0001 and ZBX-E0001 in any case and prints the same text; an
    // unknown code is E0007, a missing one E0006, and neither prints anything to stdout.
    var sim: HostSim = undefined;
    try testing.expectEqual(@as(u8, 0), try run_case(&sim, &.{ "zbx", "explain", "E0001" }));
    try testing.expectEqualStrings(@embedFile("testdata/explain_E0001.stdout.txt"), sim.stdout());
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    try testing.expectEqual(@as(u8, 0), try run_case(&sim, &.{ "zbx", "explain", "zbx-e0001" }));
    try testing.expectEqualStrings(@embedFile("testdata/explain_E0001.stdout.txt"), sim.stdout());
    try testing.expectEqual(@as(u8, 1), try run_case(&sim, &.{ "zbx", "explain", "E9999" }));
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "error[ZBX-E0007]: "));
    try testing.expectEqual(@as(u8, 1), try run_case(&sim, &.{ "zbx", "explain" }));
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "error[ZBX-E0006]: "));
}

test "snapshot: explain --output json is the zbx.explain/1 document; schemas for it and lock" {
    // Goal: the machine form of `explain` is exactly the checked-in document, wherever the option
    // stands; an unknown code is still a diagnostic and prints nothing on stdout; the schemas
    // `zbx schema` prints for it and for `lock show` are the checked-in text.
    var sim: HostSim = undefined;
    const want = @embedFile("testdata/explain_E0001.json.txt");
    const before = [_][:0]const u8{ "zbx", "--output", "json", "explain", "E0001" };
    try testing.expectEqual(@as(u8, 0), try run_case(&sim, &before));
    try testing.expectEqualStrings(want, sim.stdout());
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    const after = [_][:0]const u8{ "zbx", "explain", "zbx-e0001", "--output=json" };
    try testing.expectEqual(@as(u8, 0), try run_case(&sim, &after));
    try testing.expectEqualStrings(want, sim.stdout());
    try testing.expect(try @import("test_util.zig").json_is_valid(std.mem.trimEnd(u8, want, "\n")));
    const unknown = [_][:0]const u8{ "zbx", "--output", "json", "explain", "E9999" };
    try testing.expectEqual(@as(u8, 1), try run_case(&sim, &unknown));
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "{\"code\":\"ZBX-E0007\""));

    const goldens = [_]struct { topic: [:0]const u8, text: []const u8 }{
        .{ .topic = "explain", .text = @embedFile("testdata/schema_explain.stdout.txt") },
        .{ .topic = "lock-show", .text = @embedFile("testdata/schema_lock_show.stdout.txt") },
    };
    for (goldens) |golden| {
        const args = [_][:0]const u8{ "zbx", "schema", golden.topic };
        try testing.expectEqual(@as(u8, 0), try run_case(&sim, &args));
        try testing.expectEqualStrings(golden.text, sim.stdout());
    }
}

test "parse: lock takes the one subcommand show" {
    // Goal: `lock` alone is E0006, an unknown word E0001, an extra word E0003; `lock show` parses.
    var invocation: Invocation = undefined;
    try testing.expect(try parse_case(&.{ "lock", "show" }, &invocation) == null);
    try testing.expect(invocation.command == .lock);
    const json = [_][]const u8{ "--output", "json", "lock", "show" };
    try testing.expect(try parse_case(&json, &invocation) == null);
    try testing.expectEqual(codes.Code.E0006, (try parse_case(&.{"lock"}, &invocation)).?);
    try testing.expectEqual(codes.Code.E0001, (try parse_case(&.{ "lock", "ls" }, &invocation)).?);
    const extra = try parse_case(&.{ "lock", "show", "more" }, &invocation);
    try testing.expectEqual(codes.Code.E0003, extra.?);
}

test "parse: options come before or after the command and never change the command" {
    // Goal: the global flags are position-independent, and each combination parses to the same
    // command. Method: every placement of -v and --output json around `doctor`.
    const placements = [_][]const []const u8{
        &.{ "-v", "doctor" },
        &.{ "doctor", "-v" },
        &.{ "--verbose", "doctor", "--output", "json" },
        &.{ "--output", "json", "doctor" },
        &.{ "--output=json", "-v", "doctor" },
        &.{ "doctor", "--output=text" },
    };
    var invocation: Invocation = undefined;
    for (placements) |args| {
        try testing.expect(try parse_case(args, &invocation) == null);
        try testing.expectEqual(Command.doctor, invocation.command);
        try testing.expect(invocation.operand == null);
    }
    try testing.expect(try parse_case(&.{ "explain", "-v", "E0001" }, &invocation) == null);
    try testing.expectEqualStrings("E0001", invocation.operand.?);
    try testing.expect(invocation.options.verbose);
    try testing.expect(try parse_case(&.{ "doctor", "--output=json" }, &invocation) == null);
    try testing.expectEqual(OutputFormat.json, invocation.options.output);
    try testing.expectEqual(render.Mode.json, invocation.options.mode());
}

test "parse: every usage error has its code, at the exact boundary" {
    // Goal: each way a command line is wrong maps to exactly one code. Near misses of real
    // commands are unknown, not accepted: parsing is exact.
    var invocation: Invocation = undefined;
    const cases = [_]struct { args: []const []const u8, code: codes.Code }{
        .{ .args = &.{}, .code = .E0002 },
        .{ .args = &.{"-v"}, .code = .E0002 },
        .{ .args = &.{ "--output", "json" }, .code = .E0002 },
        .{ .args = &.{"frobnicate"}, .code = .E0001 },
        .{ .args = &.{"Help"}, .code = .E0001 },
        .{ .args = &.{"version"}, .code = .E0001 },
        .{ .args = &.{""}, .code = .E0001 },
        .{ .args = &.{"-"}, .code = .E0001 },
        .{ .args = &.{ "help", "me" }, .code = .E0003 },
        .{ .args = &.{ "doctor", "-v", "now" }, .code = .E0003 },
        .{ .args = &.{ "explain", "E0001", "E0002" }, .code = .E0003 },
        .{ .args = &.{"explain"}, .code = .E0006 },
        .{ .args = &.{ "explain", "-v" }, .code = .E0006 },
        .{ .args = &.{"--frobnicate"}, .code = .E0004 },
        .{ .args = &.{ "doctor", "-x" }, .code = .E0004 },
        .{ .args = &.{ "doctor", "--" }, .code = .E0004 },
        .{ .args = &.{ "doctor", "--output" }, .code = .E0005 },
        .{ .args = &.{ "doctor", "--output", "xml" }, .code = .E0005 },
        .{ .args = &.{ "doctor", "--output=" }, .code = .E0005 },
        .{ .args = &.{ "doctor", "--output", "-v" }, .code = .E0005 },
    };
    for (cases) |case| {
        const found = try parse_case(case.args, &invocation);
        try testing.expectEqual(@as(?codes.Code, case.code), found);
    }
}

test "snapshot: the usage errors exit 1 with one diagnostic on stderr and nothing on stdout" {
    // Goal: every usage error is a user-blamed diagnostic (exit 1, not the old 2), rendered on
    // stderr only. The full text of each is in the golden files (diag_golden.zig).
    var sim: HostSim = undefined;
    const bad = [_][]const [:0]const u8{
        &.{"zbx"},
        &.{ "zbx", "frobnicate" },
        &.{ "zbx", "help", "me" },
        &.{ "zbx", "--nope" },
        &.{ "zbx", "--output", "xml", "help" },
        &.{ "zbx", "explain" },
        &.{ "zbx", "explain", "Z" },
    };
    for (bad) |args| {
        try testing.expectEqual(@as(u8, 1), try run_case(&sim, args));
        try testing.expectEqual(@as(usize, 0), sim.stdout().len);
        try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "error[ZBX-E00"));
    }
}

test "snapshot: a usage error on a run command line exits 125, any other command line 1" {
    // Goal: `run` passes the container's exit code through, so its own refusals use 125 and the
    // codes 1, 2, 3 and 70 belong to the container alone. Method: the ways a run line is wrong
    // (unknown option, missing and repeated values, a bad --output, no command, no rootfs) each
    // give one error on stderr and 125; the same mistakes on other commands still give 1.
    var sim: HostSim = undefined;
    const bad_run = [_][]const [:0]const u8{
        &.{ "zbx", "run" },
        &.{ "zbx", "run", "--nope" },
        &.{ "zbx", "run", "--rootfs" },
        &.{ "zbx", "run", "--rootfs", "a", "--rootfs", "b", "--", "sh" },
        &.{ "zbx", "run", "--rootfs", "a" },
        &.{ "zbx", "run", "--rootfs", "a", "--" },
        &.{ "zbx", "--output", "xml", "run", "--rootfs", "a", "--", "sh" },
        &.{ "zbx", "run", "--output", "xml", "--rootfs", "a", "--", "sh" },
        &.{ "zbx", "--output=json", "run", "--last" },
    };
    for (bad_run) |args| {
        try testing.expectEqual(@as(u8, 125), try run_case(&sim, args));
        try testing.expectEqual(@as(usize, 0), sim.stdout().len);
        try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "ZBX-E00"));
    }
    const other = [_][]const [:0]const u8{
        &.{ "zbx", "bundle", "--nope" },
        &.{ "zbx", "doctor", "--rootfs", "a" },
        &.{ "zbx", "--output", "xml", "doctor" },
    };
    for (other) |args| try testing.expectEqual(@as(u8, 1), try run_case(&sim, args));
}

test "an echoed argument cannot inject terminal escapes or overflow the line" {
    // Goal: negative space. Control bytes and non-ASCII become '?', long text is truncated.
    var sim: HostSim = undefined;
    try testing.expectEqual(@as(u8, 1), try run_case(&sim, &.{ "zbx", "\x1b[31mred\n\xff" }));
    const echoed = "'?[31mred??' is not a zbx command";
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), echoed) != null);
    try testing.expect(std.mem.indexOfScalar(u8, sim.stderr(), 0x1b) == null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "error["));

    const long = repeat('x', constants.arg_bytes_max);
    try testing.expectEqual(@as(u8, 1), try run_case(&sim, &.{ "zbx", long }));
    const expected_echo = repeat('x', constants.arg_echo_bytes_max - 3) ++ "...";
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "'" ++ expected_echo ++ "'") != null);
}

test "argument limits are refused, at the exact boundary" {
    // Goal: args_count_max arguments are accepted by collect; one more is refused; an argument
    // of arg_bytes_max bytes is accepted and one byte more is refused. A refusal is E0008, and
    // an option among the arguments that were collected still applies to how it is shown.
    const at_limit: [constants.args_count_max][:0]const u8 = @splat("a");
    var storage: [constants.args_count_max][]const u8 = undefined;
    var collected: u32 = undefined;
    var diag: Diag = undefined;
    diag.reset();
    var iterator: SliceIterator = .{ .items = &at_limit };
    const accepted = try collect(&storage, &collected, &iterator, &diag);
    try testing.expectEqual(@as(usize, constants.args_count_max), accepted.len);
    try testing.expect(diag.code == null);

    const over_limit: [constants.args_count_max + 1][:0]const u8 = @splat("a");
    iterator = .{ .items = &over_limit };
    const refused = collect(&storage, &collected, &iterator, &diag);
    try testing.expectError(error.TooManyArguments, refused);
    try testing.expectEqual(codes.Code.E0008, diag.code.?);
    try testing.expectEqual(@as(u32, constants.args_count_max), collected);

    diag.reset();
    const longest: [:0]const u8 = repeat('y', constants.arg_bytes_max);
    iterator = .{ .items = &.{longest} };
    _ = try collect(&storage, &collected, &iterator, &diag);
    const too_long: [:0]const u8 = repeat('y', constants.arg_bytes_max + 1);
    iterator = .{ .items = &.{too_long} };
    const too_long_refused = collect(&storage, &collected, &iterator, &diag);
    try testing.expectError(error.ArgumentTooLong, too_long_refused);
    try testing.expectEqual(@as(u32, 0), collected);

    var sim: HostSim = undefined;
    try testing.expectEqual(@as(u8, 1), try run_case(&sim, &.{ "zbx", "--output=json", too_long }));
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "{\"code\":\"ZBX-E0008\""));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "\n"));
}

test "colour only on a terminal with NO_COLOR unset, and the words do not change" {
    // Goal: the colour rule of the standard. Method: the same failure on a plain stream, on a
    // terminal, and on a terminal with NO_COLOR; stripping the escapes from the coloured text
    // gives the plain text exactly. JSON is never coloured.
    var plain: HostSim = undefined;
    _ = try run_case(&plain, &.{ "zbx", "frobnicate" });
    try testing.expect(std.mem.indexOfScalar(u8, plain.stderr(), 0x1b) == null);

    var coloured: HostSim = undefined;
    coloured.init(1, &.{});
    coloured.terminal = true;
    var iterator: SliceIterator = .{ .items = &.{ "zbx", "frobnicate" } };
    _ = run_from_iterator(coloured.interface(), &iterator);
    try testing.expect(std.mem.indexOfScalar(u8, coloured.stderr(), 0x1b) != null);
    var stripped: [constants.output_bytes_max]u8 = undefined;
    const without_escapes = render.strip_colour(&stripped, coloured.stderr());
    try testing.expectEqualStrings(plain.stderr(), without_escapes);

    coloured.init(1, &.{});
    coloured.terminal = true;
    coloured.no_color_value = true;
    iterator = .{ .items = &.{ "zbx", "frobnicate" } };
    _ = run_from_iterator(coloured.interface(), &iterator);
    try testing.expectEqualStrings(plain.stderr(), coloured.stderr());

    coloured.init(1, &.{});
    coloured.terminal = true;
    iterator = .{ .items = &.{ "zbx", "--output", "json", "frobnicate" } };
    _ = run_from_iterator(coloured.interface(), &iterator);
    try testing.expect(std.mem.indexOfScalar(u8, coloured.stderr(), 0x1b) == null);
}

test "snapshot: doctor on a host with no readable files fails four checks, exit 2" {
    // Goal: faults and absences are FAIL with a reason, never ok. The simulator here has no
    // files at all, so every check that reads one must fail; the stdout report and the four
    // stderr blocks (in check order) are checked in. The exit code is the environment's (2),
    // not the user's.
    var sim: HostSim = undefined;
    try testing.expectEqual(@as(u8, 2), try run_case(&sim, &.{ "zbx", "doctor" }));
    try testing.expectEqualStrings(@embedFile("testdata/doctor/empty_host.txt"), sim.stdout());
    const blocks = @embedFile("testdata/doctor/empty_host.stderr.txt");
    try testing.expectEqualStrings(blocks, sim.stderr());
    try testing.expectEqual(@as(usize, 4), std.mem.count(u8, sim.stderr(), "error[ZBX-E01"));

    // The options apply to the blocks and not to the report on stdout.
    const stdout = try testing.allocator.dupe(u8, sim.stdout());
    defer testing.allocator.free(stdout);
    const as_json = [_][:0]const u8{ "zbx", "doctor", "--output", "json" };
    try testing.expectEqual(@as(u8, 2), try run_case(&sim, &as_json));
    try testing.expectEqualStrings(stdout, sim.stdout());
    try testing.expectEqual(@as(usize, 4), std.mem.count(u8, sim.stderr(), "\n"));
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "{\"code\":\"ZBX-E0101\""));
    try testing.expectEqual(@as(u8, 2), try run_case(&sim, &.{ "zbx", "-v", "doctor" }));
    try testing.expectEqualStrings(stdout, sim.stdout());
    const while_line = "  while  running the userns check of zbx doctor\n";
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), while_line) != null);
}

test "a failing stdout is E0009 on stderr and exit 2; a failing stderr is exit 2 alone" {
    // Goal: stdout closed or full must not panic and must not be silent. Method: fail only
    // stdout (as `zbx help > /dev/full` does): the diagnostic still reaches stderr. Then fail
    // everything: there is nowhere to say so, and the exit code still says "environment".
    var sim: HostSim = undefined;
    sim.init(1, &.{});
    sim.faults.write_error_per_mille = 1000;
    sim.faults.write_fault_stream = .stdout;
    var iterator: SliceIterator = .{ .items = &.{ "zbx", "help" } };
    try testing.expectEqual(@as(u8, 2), run_from_iterator(sim.interface(), &iterator));
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
    const header = "error[ZBX-E0009]: can't write output\n";
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), header));

    sim.init(1, &.{});
    sim.faults.write_error_per_mille = 1000;
    iterator = .{ .items = &.{ "zbx", "help" } };
    try testing.expectEqual(@as(u8, 2), run_from_iterator(sim.interface(), &iterator));
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    iterator = .{ .items = &.{ "zbx", "frobnicate" } };
    try testing.expectEqual(@as(u8, 2), run_from_iterator(sim.interface(), &iterator));
    // A run line with nowhere to say what went wrong still keeps out of the container's codes.
    iterator = .{ .items = &.{ "zbx", "run", "--nope" } };
    try testing.expectEqual(@as(u8, 125), run_from_iterator(sim.interface(), &iterator));
}

test "a failing write names the real errno: EBADF and ENOSPC from the simulator" {
    // Goal: principle 4 for output failures. Method: inject each errno on stdout writes only;
    // the E0009 cause must name exactly that errno (EBADF is how `zbx help >&-` fails; the host
    // collapses it to IoFailed, so the errno has to travel separately), exit 2 both times.
    const cases = [_]struct { errno: u16, cause: []const u8 }{
        .{ .errno = 9, .cause = "write(stdout) failed: bad file descriptor (EBADF)" },
        .{ .errno = 28, .cause = "write(stdout) failed: no space left on the device (ENOSPC)" },
        .{ .errno = 32, .cause = "write(stdout) failed: broken pipe (EPIPE)" },
    };
    for (cases) |case| {
        var sim: HostSim = undefined;
        sim.init(1, &.{});
        sim.faults.write_error_per_mille = 1000;
        sim.faults.write_fault_stream = .stdout;
        sim.faults.write_errno = case.errno;
        var iterator: SliceIterator = .{ .items = &.{ "zbx", "help" } };
        try testing.expectEqual(@as(u8, 2), run_from_iterator(sim.interface(), &iterator));
        try testing.expect(std.mem.startsWith(u8, sim.stderr(), "error[ZBX-E0009]"));
        try testing.expect(std.mem.indexOf(u8, sim.stderr(), case.cause) != null);
    }
}

test "output survives short writes" {
    // Goal: the help text arrives whole even when the kernel accepts one fragment at a time.
    var sim: HostSim = undefined;
    sim.init(5, &.{});
    sim.faults.short_write_per_mille = 1000;
    var iterator: SliceIterator = .{ .items = &.{ "zbx", "help" } };
    try testing.expectEqual(@as(u8, 0), run_from_iterator(sim.interface(), &iterator));
    try testing.expectEqualStrings(@embedFile("testdata/help.stdout.txt"), sim.stdout());
}

test "an unclassified failure is reported as a bug, never dropped" {
    // Goal: a layer that returned an error without raising a code is our bug, and the user
    // still gets exactly one diagnostic, with exit 70.
    var sim: HostSim = undefined;
    sim.init(1, &.{});
    var diag: Diag = undefined;
    diag.reset();
    try testing.expectEqual(@as(u8, 70), fail(sim.interface(), &diag, .{}));
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "bug[ZBX-B0001]: "));
}

test "parse: run takes its options, then the command after --, which is not ours to read" {
    // Goal: the shape of a run command line. Method: options in both spellings and orders,
    // global options before and among them, and a command whose words look like our options.
    var invocation: Invocation = undefined;
    const plain = [_][]const u8{ "run", "--rootfs", "alpine", "--", "/bin/sh" };
    try testing.expect(try parse_case(&plain, &invocation) == null);
    try testing.expectEqual(Command.run, invocation.command);
    try testing.expectEqualStrings("alpine", invocation.run.rootfs.?);
    try testing.expect(invocation.run.name == null);
    try testing.expectEqual(@as(usize, 1), invocation.run.command.len);

    const shaped = [_][]const u8{
        "-v",     "run", "--name=web-1", "--rootfs=./a", "--output", "json", "--",
        "ls",     "-v",  "--output",     "xml",          "--rootfs", "x",    "--",
        "--help",
    };
    try testing.expect(try parse_case(&shaped, &invocation) == null);
    try testing.expectEqualStrings("web-1", invocation.run.name.?);
    try testing.expectEqualStrings("./a", invocation.run.rootfs.?);
    try testing.expectEqual(@as(usize, 8), invocation.run.command.len);
    try testing.expectEqualStrings("ls", invocation.run.command[0]);
    try testing.expectEqualStrings("--", invocation.run.command[6]);
    try testing.expect(invocation.options.verbose);
    try testing.expectEqual(OutputFormat.json, invocation.options.output);

    // An option after the "--" is the command's: zbx's own --output and -v do not see it.
    const after = [_][]const u8{ "run", "--rootfs", "r", "--", "x", "--output", "json", "-v" };
    const options = scan_options(&after);
    try testing.expect(!options.verbose);
    try testing.expectEqual(OutputFormat.text, options.output);
    try testing.expectEqual(OutputFormat.json, scan_options(&.{ "--output=json", "run" }).output);
}

test "parse: every way a run command line is wrong has its code" {
    // Goal: the usage errors of `run` reuse the general codes: E0006 for what is missing, E0005
    // for an option without its value, E0003 for what should not be there, E0004 for an option
    // that is not run's. Method: the exact boundary of each rule.
    var invocation: Invocation = undefined;
    const cases = [_]struct { args: []const []const u8, code: ?codes.Code }{
        .{ .args = &.{ "run", "--rootfs", "r", "--", "x" }, .code = null },
        .{ .args = &.{ "run", "--", "x" }, .code = .E0006 },
        .{ .args = &.{"run"}, .code = .E0006 },
        .{ .args = &.{ "run", "--rootfs", "r" }, .code = .E0006 },
        .{ .args = &.{ "run", "--rootfs", "r", "--" }, .code = .E0006 },
        .{ .args = &.{ "run", "--rootfs", "r", "--", "" }, .code = .E0006 },
        .{ .args = &.{ "run", "--rootfs" }, .code = .E0005 },
        .{ .args = &.{ "run", "--rootfs", "--", "x" }, .code = .E0005 },
        .{ .args = &.{ "run", "--rootfs", "r", "--name" }, .code = .E0005 },
        .{ .args = &.{ "run", "--rootfs", "r", "--name", "--", "x" }, .code = .E0005 },
        .{ .args = &.{ "run", "extra", "--rootfs", "r", "--", "x" }, .code = .E0003 },
        .{ .args = &.{ "run", "--rootfs", "a", "--rootfs", "b", "--", "x" }, .code = .E0003 },
        .{ .args = &.{ "run", "--rootfs", "a", "--rootfs=b", "--", "x" }, .code = .E0003 },
        .{
            .args = &.{ "run", "--name", "a", "--name", "b", "--rootfs", "r", "--", "x" },
            .code = .E0003,
        },
        .{ .args = &.{ "doctor", "--rootfs", "r" }, .code = .E0004 },
        .{ .args = &.{ "--rootfs", "r", "run" }, .code = .E0004 },
        .{ .args = &.{ "--", "run" }, .code = .E0004 },
        .{ .args = &.{ "run", "--bogus", "--rootfs", "r", "--", "x" }, .code = .E0004 },
        .{ .args = &.{ "explain", "--name", "x" }, .code = .E0004 },
        .{ .args = &.{ "help", "--" }, .code = .E0004 },
    };
    for (cases) |case| {
        const found = try parse_case(case.args, &invocation);
        try testing.expectEqual(case.code, found);
    }
}

// ---- Tests of ps, stop, schema, run -d and the times ----------------------------------------

const sim_run = @import("runtime/sim_run.zig");

var test_storage: Storage = undefined;
var test_tables: [8 * 1024 * 1024]u8 align(8) = @splat(0);

fn command_line(sim: *HostSim, args: []const []const u8) u8 {
    test_storage.gc_tables = &test_tables;
    return run_slice(sim.interface(), args, &test_storage);
}

fn parse_json(bytes: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, testing.allocator, bytes, .{});
}

fn running_container(sim: *HostSim, name: []const u8) !void {
    sim_run.init(sim, 4);
    sim.world.command_runs_ms = 3_600_000;
    var diag: Diag = undefined;
    diag.reset();
    const container: runtime_spec.Spec = .{
        .rootfs = sim_run.rootfs_path,
        .name = name,
        .command = &.{ "/bin/sh", "-c", "sleep 1000" },
    };
    const options: runtime.StartOptions = .{ .detached = true };
    try runtime.start(sim.interface(), &container, options, &test_storage.handle, &diag);
}

test "parse: ps, stop, schema, -d and the times take what the brief says" {
    // Goal: the new commands and flags parse into the fields the dispatcher reads. Method: one
    // command line each, checking the field, and the lines that must be refused.
    var invocation: Invocation = undefined;
    try testing.expect(try parse_case(&.{ "ps", "--all" }, &invocation) == null);
    try testing.expect(invocation.run.all);
    try testing.expect(try parse_case(&.{"ps"}, &invocation) == null);
    try testing.expect(!invocation.run.all);
    const stop_line = [_][]const u8{ "stop", "web-1", "--grace", "250", "--timeout=900" };
    try testing.expect(try parse_case(&stop_line, &invocation) == null);
    try testing.expectEqualStrings("web-1", invocation.operand.?);
    try testing.expectEqualStrings("250", invocation.run.grace.?);
    try testing.expectEqualStrings("900", invocation.run.timeout.?);
    try testing.expect(try parse_case(&.{ "schema", "ps" }, &invocation) == null);
    const detached_line = [_][]const u8{ "run", "-d", "--rootfs", "r", "--", "x" };
    try testing.expect(try parse_case(&detached_line, &invocation) == null);
    try testing.expect(invocation.run.detach);
    const refused = [_]struct { args: []const []const u8, code: codes.Code }{
        .{ .args = &.{"stop"}, .code = .E0006 },
        .{ .args = &.{"schema"}, .code = .E0006 },
        .{ .args = &.{ "stop", "a", "b" }, .code = .E0003 },
        .{ .args = &.{ "ps", "extra" }, .code = .E0003 },
        .{ .args = &.{ "ps", "--grace", "5" }, .code = .E0004 },
        .{ .args = &.{ "stop", "web-1", "-d" }, .code = .E0004 },
        .{ .args = &.{ "stop", "web-1", "--grace" }, .code = .E0005 },
        .{ .args = &.{ "stop", "a", "--grace", "1", "--grace", "2" }, .code = .E0003 },
    };
    for (refused) |case| {
        const found = try parse_case(case.args, &invocation);
        try testing.expectEqual(@as(?codes.Code, case.code), found);
    }
}

test "schema prints the versioned schema of each command, and refuses the others" {
    // Goal: `zbx schema <command>` for run, bundle, ps, stop and doctor, and E0402 otherwise.
    var sim: HostSim = undefined;
    sim.init(1, &.{});
    for ([_][]const u8{ "run", "bundle", "ps", "stop", "doctor" }) |name| {
        sim.init(1, &.{});
        try testing.expectEqual(@as(u8, 0), command_line(&sim, &.{ "schema", name }));
        try testing.expect(std.mem.indexOf(u8, sim.stdout(), "/schema/") != null);
        try testing.expect(std.mem.endsWith(u8, sim.stdout(), "}\n"));
        try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    }
    sim.init(1, &.{});
    try testing.expectEqual(@as(u8, 1), command_line(&sim, &.{ "schema", "logs" }));
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0406") != null);
    sim.init(1, &.{});
    try testing.expectEqual(@as(u8, 1), command_line(&sim, &.{ "schema", "" }));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0406") != null);
}

test "ps lists a running container in text and in JSON that matches the schema's fields" {
    // Goal: the same view in both forms, from the record and the kernel's view of the pid.
    var sim: HostSim = undefined;
    try running_container(&sim, "web-1");
    try testing.expectEqual(@as(u8, 0), command_line(&sim, &.{"ps"}));
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "web-1") != null);
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "running") != null);
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "sleep 1000") != null);
    // JSON: one object, the containers inside it, every field of the schema's `required`.
    sim.stdout_len = 0;
    try testing.expectEqual(@as(u8, 0), command_line(&sim, &.{ "ps", "--output", "json" }));
    const parsed = try parse_json(sim.stdout());
    defer parsed.deinit();
    try testing.expectEqualStrings("zbx.ps/1", parsed.value.object.get("schema").?.string);
    const list = parsed.value.object.get("containers").?.array;
    try testing.expectEqual(@as(usize, 1), list.items.len);
    const one = list.items[0].object;
    const required = [_][]const u8{ "name", "state", "pid", "started", "timed_out" } ++
        [_][]const u8{ "command", "labels", "limits" };
    for (required) |key| {
        try testing.expect(one.get(key) != null);
    }
    try testing.expectEqualStrings("running", one.get("state").?.string);
    try testing.expect(!one.get("timed_out").?.bool);
    try testing.expectEqual(@as(usize, 3), one.get("command").?.array.items.len);
    _ = runtime.wait(&test_storage.handle);
}

test "stop ends a running container, says so in text and JSON, and is a no-op the second time" {
    var sim: HostSim = undefined;
    try running_container(&sim, "web-1");
    const grace = [_][]const u8{ "stop", "web-1", "--grace", "100", "--output", "json" };
    try testing.expectEqual(@as(u8, 0), command_line(&sim, &grace));
    const parsed = try parse_json(sim.stdout());
    defer parsed.deinit();
    try testing.expectEqualStrings("zbx.stop/1", parsed.value.object.get("schema").?.string);
    try testing.expectEqualStrings("web-1", parsed.value.object.get("name").?.string);
    try testing.expectEqualStrings("killed", parsed.value.object.get("result").?.string);
    _ = runtime.wait(&test_storage.handle);
    sim.stdout_len = 0;
    try testing.expectEqual(@as(u8, 0), command_line(&sim, &.{ "stop", "web-1" }));
    try testing.expectEqualStrings("web-1 was not running, exit code 137\n", sim.stdout());
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
}

test "stop and ps refuse what they cannot do with one line and a code" {
    // Goal: a bad time is E0401 before anything is looked at; an unknown name is E0402.
    var sim: HostSim = undefined;
    try running_container(&sim, "web-1");
    const soon = [_][]const u8{ "stop", "web-1", "--grace", "soon" };
    try testing.expectEqual(@as(u8, 1), command_line(&sim, &soon));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0401") != null);
    sim.stderr_len = 0;
    const zero = [_][]const u8{ "stop", "web-1", "--timeout", "0" };
    try testing.expectEqual(@as(u8, 1), command_line(&sim, &zero));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0401") != null);
    sim.stderr_len = 0;
    try testing.expectEqual(@as(u8, 1), command_line(&sim, &.{ "stop", "nope" }));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0402") != null);
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
    _ = runtime.wait(&test_storage.handle);
}

test "run --timeout stops the container when its time is up and says so" {
    var sim: HostSim = undefined;
    sim_run.init(&sim, 6);
    sim.world.command_runs_ms = 3_600_000;
    const sleeping = [_][]const u8{ "/bin/sh", "-c", "sleep 1000" };
    const head = [_][]const u8{ "run", "--rootfs", sim_run.rootfs_path, "--timeout", "2000", "--" };
    const args = head ++ sleeping;
    const code = command_line(&sim, &args);
    try testing.expectEqual(@as(u8, 143), code);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "timed out after 2000 ms") != null);
    sim_run.init(&sim, 6);
    sim.world.command_runs_ms = 3_600_000;
    sim.stderr_len = 0;
    const json = [_][]const u8{ "run", "--output", "json", "--rootfs", sim_run.rootfs_path } ++
        [_][]const u8{ "--timeout", "2000", "--" } ++ sleeping;
    try testing.expectEqual(@as(u8, 143), command_line(&sim, &json));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "\"timed_out\":true") != null);
}

const Frame = struct { tag: u8, head: ?u8, body: []const u8 };

const test_ran: Ran = .{ .kind = .rootfs, .text = "/srv/root", .manifest = null };

fn framed(sim: *HostSim, frames: []const Frame) !host_mod.Handle {
    const host = sim.interface();
    const pipe = try host.pipe();
    for (frames) |frame| try write_frame(host, pipe.write, frame.tag, frame.head, frame.body);
    host.close(pipe.write);
    return pipe.read;
}

test "run -d: the caller passes warnings on and prints the name once the start is reported" {
    var sim: HostSim = undefined;
    sim_run.init(&sim, 7);
    const read = try framed(&sim, &.{
        .{ .tag = frame_warning, .head = null, .body = "zbx: warning: something\n" },
        .{ .tag = frame_started, .head = null, .body = "web-1 502 zbx-web-1.scope" },
    });
    var diag: Diag = undefined;
    diag.reset();
    const options: Options = .{ .runs_container = true };
    const host = sim.interface();
    try testing.expectEqual(@as(u8, 0), try relay(host, read, options, &test_ran, &diag));
    sim.interface().close(read);
    try testing.expectEqualStrings("web-1\n", sim.stdout());
    try testing.expectEqualStrings("zbx: warning: something\n", sim.stderr());

    sim_run.init(&sim, 7);
    const bare: Frame = .{ .tag = frame_started, .head = null, .body = "web-1 502 -" };
    const again = try framed(&sim, &.{bare});
    const json: Options = .{ .runs_container = true, .output = .json };
    try testing.expectEqual(@as(u8, 0), try relay(sim.interface(), again, json, &test_ran, &diag));
    sim.interface().close(again);
    const expected = "{\"schema\":\"zbx.run/1\",\"container\":{\"name\":\"web-1\"," ++
        "\"pid\":502,\"scope\":null,\"detached\":true},\"ran\":{\"kind\":\"rootfs\"," ++
        "\"path\":\"/srv/root\"}}\n";
    try testing.expectEqualStrings(expected, sim.stdout());
}

test "run -d: a failed start passes the supervisor's diagnostic and code through" {
    var sim: HostSim = undefined;
    sim_run.init(&sim, 8);
    const refused: Frame = .{ .tag = frame_failed, .head = 126, .body = "zbx: refused\n" };
    const read = try framed(&sim, &.{refused});
    var diag: Diag = undefined;
    diag.reset();
    const options: Options = .{ .runs_container = true };
    const host = sim.interface();
    try testing.expectEqual(@as(u8, 126), try relay(host, read, options, &test_ran, &diag));
    sim.interface().close(read);
    try testing.expectEqualStrings("zbx: refused\n", sim.stderr());
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
}

test "run -d: a supervisor that ends without a report, or sends nonsense, is E0405" {
    // Goal: the caller never hangs and never prints a success it did not see.
    const cases = [_][]const u8{ "", "\x09\x00\x00", "\x02\xff\xff", "\x03\x00\x00" };
    for (cases) |bytes| {
        var sim: HostSim = undefined;
        sim_run.init(&sim, 9);
        const host = sim.interface();
        const pipe = try host.pipe();
        if (bytes.len > 0) try host.write_handle_all(pipe.write, bytes);
        host.close(pipe.write);
        var diag: Diag = undefined;
        diag.reset();
        const options: Options = .{ .runs_container = true };
        const failed = relay(host, pipe.read, options, &test_ran, &diag);
        try testing.expectError(error.CommandFailed, failed);
        host.close(pipe.read);
        try testing.expectEqual(codes.Code.E0405, diag.code.?);
        try testing.expectEqual(@as(usize, 0), sim.stdout().len);
    }
}

test "run -d as the supervisor starts the container, reports it and records it as detached" {
    // Goal: the supervisor's half end to end in the simulator: it forks into the supervisor
    // role, starts, waits for the container's end and leaves a finished record.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 10);
    sim.world.fork_role = .supervisor;
    sim.world.command_runs_ms = 5000;
    const args = [_][]const u8{ "run", "-d", "--name", "web-1", "--rootfs", sim_run.rootfs_path } ++
        [_][]const u8{ "--", "/bin/sh", "-c", "sleep 5" };
    try testing.expectEqual(@as(u8, 0), command_line(&sim, &args));
    try testing.expectEqual(@as(?u8, 0), sim.world.exited_with);
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
    var state: lifecycle.State = undefined;
    var ref: lifecycle.Ref = undefined;
    try lifecycle.adopt(sim.interface(), "web-1", &ref, &state);
    try testing.expectEqual(lifecycle.State.stopped, state);
}

test "run -d as the caller, when the fork fails or the supervisor never reports, is E0405" {
    var sim: HostSim = undefined;
    sim_run.init(&sim, 11);
    sim.world.fork_errno = 11;
    const args = [_][]const u8{ "run", "-d", "--rootfs", sim_run.rootfs_path, "--", "/bin/true" };
    try testing.expectEqual(@as(u8, 125), command_line(&sim, &args));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0405") != null);
    sim_run.init(&sim, 11);
    try testing.expectEqual(@as(u8, 125), command_line(&sim, &args));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0405") != null);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "stop takes a name from the command line as a name, never as a path" {
    // Goal: a name that is not a run name names no container (E0402); it is not made into a path.
    var sim: HostSim = undefined;
    try running_container(&sim, "web-1");
    const names = [_][]const u8{ repeat('x', 255), "../web-1", "a/b", "WEB", "-", "web-1.zon", "" };
    for (names) |name| {
        sim.stderr_len = 0;
        try testing.expectEqual(@as(u8, 1), command_line(&sim, &.{ "stop", name }));
        try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0402") != null);
    }
    _ = runtime.wait(&test_storage.handle);
}

test "a detached run stopped for its time reads as timed out in the record and in ps" {
    // Goal: the record keeps what `--timeout` did, so a later `ps` can say it. Method: the
    // supervisor's half with a time shorter than the command, then `ps --all` in text and JSON.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 13);
    sim.world.fork_role = .supervisor;
    sim.world.command_runs_ms = 3_600_000;
    const head = [_][]const u8{ "run", "-d", "--name", "web-1", "--rootfs", sim_run.rootfs_path };
    const args = head ++ [_][]const u8{ "--timeout", "2000", "--", "/bin/sh", "-c", "sleep 1000" };
    try testing.expectEqual(@as(u8, 0), command_line(&sim, &args));
    sim.world.fork_role = .parent;
    try testing.expectEqual(@as(u8, 0), command_line(&sim, &.{ "ps", "--all" }));
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "timed_out") != null);
    sim.stdout_len = 0;
    const listing = [_][]const u8{ "ps", "--all", "--output", "json" };
    try testing.expectEqual(@as(u8, 0), command_line(&sim, &listing));
    const parsed = try parse_json(sim.stdout());
    defer parsed.deinit();
    const one = parsed.value.object.get("containers").?.array.items[0].object;
    try testing.expect(one.get("timed_out").?.bool);
    try testing.expectEqualStrings("signal", one.get("reason").?.string);
}

test "parse: run takes a tree digest or --rootfs, one of them" {
    // Goal: `zbx run <digest> -- cmd` is the same command as `--rootfs`, with the tree as the
    // operand. Method: each form parses to the fields the dispatcher reads; neither and both
    // are refused with the codes that name the mistake; a second operand is refused.
    var invocation: Invocation = undefined;
    try testing.expect(
        try parse_case(&.{ "run", "b3:2f9c4a1d7e03", "--", "sh" }, &invocation) == null,
    );
    try testing.expectEqualStrings("b3:2f9c4a1d7e03", invocation.operand.?);
    try testing.expect(invocation.run.rootfs == null);
    try testing.expect(
        try parse_case(
            &.{ "run", "--read-only", "2f9c4a1d7e03", "--name", "a", "--", "sh" },
            &invocation,
        ) == null,
    );
    try testing.expect(invocation.run.read_only);
    try testing.expectEqualStrings("2f9c4a1d7e03", invocation.operand.?);
    try testing.expect(
        try parse_case(&.{ "run", "--rootfs", "alpine", "--", "sh" }, &invocation) == null,
    );
    try testing.expect(invocation.operand == null);
    try testing.expectEqual(
        @as(?codes.Code, .E0006),
        try parse_case(&.{ "run", "--", "sh" }, &invocation),
    );
    try testing.expectEqual(
        @as(?codes.Code, .E0003),
        try parse_case(&.{ "run", "2f9c4a1d7e03", "--rootfs", "alpine", "--", "sh" }, &invocation),
    );
    try testing.expectEqual(
        @as(?codes.Code, .E0003),
        try parse_case(&.{ "run", "2f9c4a1d7e03", "another", "--", "sh" }, &invocation),
    );
}

test "parse: --net takes none, host or user; --publish is repeatable and implies user" {
    // Goal: M5's flags. Method: each mode parses to the word the run reads; none given is null
    // (the default, none, and the hint's condition); --publish alone is user, and with an
    // explicit none or host is E0003; a bad word is E0005; a bad --publish is E0600.
    var invocation: Invocation = undefined;
    const base = [_][]const u8{ "run", "--rootfs", "alpine" };
    for ([_][]const u8{ "none", "host", "user" }) |word| {
        const args = base ++ [_][]const u8{ "--net", word, "--", "sh" };
        try testing.expect(try parse_case(&args, &invocation) == null);
        try testing.expectEqualStrings(word, invocation.run.net.?);
        try testing.expectEqualStrings(word, network_of(&invocation.run).word());
    }
    const inline_form = base ++ [_][]const u8{ "--net=host", "--", "sh" };
    try testing.expect(try parse_case(&inline_form, &invocation) == null);
    try testing.expectEqual(runtime_spec.Network.host, network_of(&invocation.run));
    const plain = base ++ [_][]const u8{ "--", "sh" };
    try testing.expect(try parse_case(&plain, &invocation) == null);
    try testing.expect(invocation.run.net == null);
    try testing.expectEqual(runtime_spec.Network.none, network_of(&invocation.run));
    const publish = base ++ [_][]const u8{
        "--publish", "8080:80", "--publish=8443:443", "--", "sh",
    };
    try testing.expect(try parse_case(&publish, &invocation) == null);
    try testing.expectEqual(runtime_spec.Network.user, network_of(&invocation.run));
    try testing.expectEqual(@as(usize, 2), invocation.run.publish_slice().len);
    try testing.expectEqual(@as(u16, 8443), invocation.run.publish_slice()[1].host);
    try testing.expectEqual(@as(u16, 443), invocation.run.publish_slice()[1].container);
    const with_user = base ++ [_][]const u8{ "--net", "user", "--publish", "8080:80", "--", "sh" };
    try testing.expect(try parse_case(&with_user, &invocation) == null);
    for ([_][]const u8{ "none", "host" }) |word| {
        const args = base ++ [_][]const u8{ "--publish", "8080:80", "--net", word, "--", "sh" };
        try testing.expectEqual(@as(?codes.Code, .E0003), try parse_case(&args, &invocation));
    }
    const bad_values = [_][]const []const u8{
        &.{"8080"}, &.{"0:80"}, &.{"80:x"}, &.{"65536:80"}, &.{ "8080:80", "8080:81" },
    };
    for (bad_values) |values| {
        var args: [16][]const u8 = undefined;
        @memcpy(args[0..base.len], &base);
        var count: usize = base.len;
        for (values) |value| {
            args[count] = "--publish";
            args[count + 1] = value;
            count += 2;
        }
        args[count] = "--";
        args[count + 1] = "sh";
        const code = try parse_case(args[0 .. count + 2], &invocation);
        try testing.expectEqual(@as(?codes.Code, .E0600), code);
    }
    const bad = base ++ [_][]const u8{ "--net", "bridge", "--", "sh" };
    try testing.expectEqual(@as(?codes.Code, .E0005), try parse_case(&bad, &invocation));
    const twice = base ++ [_][]const u8{ "--net", "none", "--net", "host", "--", "sh" };
    try testing.expectEqual(@as(?codes.Code, .E0003), try parse_case(&twice, &invocation));
    const last = [_][]const u8{ "run", "--rootfs", "alpine", "--net" };
    try testing.expectEqual(@as(?codes.Code, .E0005), try parse_case(&last, &invocation));
    const last_publish = [_][]const u8{ "run", "--rootfs", "alpine", "--publish" };
    try testing.expectEqual(@as(?codes.Code, .E0005), try parse_case(&last_publish, &invocation));
    // A word that is not an option of `run` is still refused for the other commands.
    const elsewhere = [_][]const u8{ "doctor", "--net", "host" };
    try testing.expectEqual(@as(?codes.Code, .E0004), try parse_case(&elsewhere, &invocation));
    const stop = [_][]const u8{ "stop", "web", "--publish", "8080:80" };
    try testing.expect(try parse_case(&stop, &invocation) != null);
}

test "parse: --publish at its bound of sixteen, and one past it" {
    // Goal: the bound of `publish_count_max`. Method: sixteen distinct forwards parse; a
    // seventeenth is E0600.
    var invocation: Invocation = undefined;
    var args: [3 + 2 * (constants.publish_count_max + 1) + 2][]const u8 = undefined;
    args[0] = "run";
    args[1] = "--rootfs";
    args[2] = "alpine";
    var texts: [constants.publish_count_max + 1][16]u8 = undefined;
    for (0..constants.publish_count_max + 1) |index| {
        args[3 + 2 * index] = "--publish";
        args[4 + 2 * index] = try std.fmt.bufPrint(&texts[index], "{d}:80", .{9000 + index});
    }
    const full = 3 + 2 * constants.publish_count_max;
    args[full] = "--";
    args[full + 1] = "sh";
    try testing.expect(try parse_case(args[0 .. full + 2], &invocation) == null);
    try testing.expectEqual(@as(u32, constants.publish_count_max), invocation.run.publish_count);
    args[full + 2] = "--";
    args[full + 3] = "sh";
    const over = full + 2;
    args[full] = "--publish";
    args[full + 1] = args[4 + 2 * constants.publish_count_max];
    args[over] = "--";
    args[over + 1] = "sh";
    const refused = try parse_case(args[0 .. over + 2], &invocation);
    try testing.expectEqual(@as(?codes.Code, .E0600), refused);
}
