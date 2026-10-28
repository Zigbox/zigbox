//! The assertions of M5's network namespace (slice 2) as pure functions over the text the guest
//! printed, each unit-tested with right and wrong input. The commands that print the text are in
//! net_m5.zig, which demo-m4 runs after its own steps.

const std = @import("std");
const checks = @import("checks.zig");

const Streams = checks.Streams;

pub const Error = error{
    ExitCodeWrong,
    /// The container sees interfaces it should not, or lacks `lo` or its UP flag.
    InterfacesWrong,
    /// The line that tells a failed run it had no network is missing, or in the wrong place.
    HintWrong,
    /// The fetched page is missing, or came from where it should not.
    PageWrong,
    /// A generated /etc file is not what the brief says.
    FileWrong,
    /// The commit's diff lists a generated file, or does not list what the container wrote.
    DiffWrong,
    JsonWrong,
    /// A published port is not listened on by pasta as the user, or still is when it should
    /// be free.
    ListenerWrong,
    /// The host's firewall rules changed.
    RulesChanged,
};

pub const hint = "zbx: network: none (grant with --net)";

fn contains(text: []const u8, part: []const u8) bool {
    return std.mem.indexOf(u8, text, part) != null;
}

/// The part of `text` before the first line that is exactly `---`, and the part after it.
fn cut(text: []const u8) struct { before: []const u8, after: []const u8 } {
    var at: usize = 0;
    while (at < text.len) {
        const end = std.mem.indexOfScalarPos(u8, text, at, '\n') orelse text.len;
        if (std.mem.eql(u8, std.mem.trimEnd(u8, text[at..end], "\r"), "---")) {
            return .{
                .before = text[0..at],
                .after = text[@min(end + 1, text.len)..],
            };
        }
        at = end + 1;
    }
    return .{ .before = text, .after = "" };
}

/// `ls /sys/class/net; echo ---; ip -o link` in a container with a network of its own: the list
/// is `lo` alone, and `ip` shows one interface, `lo`, up.
pub fn check_only_loopback(streams: Streams, status: u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    const parts = cut(streams.stdout);
    if (!std.mem.eql(u8, std.mem.trim(u8, parts.before, " \r\n\t"), "lo")) {
        return error.InterfacesWrong;
    }
    const link = std.mem.trim(u8, parts.after, " \r\n\t");
    if (std.mem.count(u8, link, "\n") != 0) return error.InterfacesWrong;
    if (!contains(link, ": lo:")) return error.InterfacesWrong;
    if (!contains(link, "LOOPBACK,UP")) return error.InterfacesWrong;
}

/// `ls /sys/class/net` on the host's network: `lo` and at least one other interface.
pub fn check_host_interfaces(streams: Streams, status: u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    var names: u32 = 0;
    var loopback = false;
    var lines = std.mem.tokenizeAny(u8, streams.stdout, " \r\n\t");
    while (lines.next()) |name| {
        names += 1;
        if (std.mem.eql(u8, name, "lo")) loopback = true;
    }
    if (!loopback or names < 2) return error.InterfacesWrong;
}

/// A run that failed to use the network without being given `--net`: it failed, the page was not
/// fetched, and the hint is the last line of stderr (after wget's own).
pub fn check_hint(streams: Streams, status: u8, page: []const u8) Error!void {
    if (status == 0) return error.ExitCodeWrong;
    if (contains(streams.stdout, page)) return error.PageWrong;
    const text = std.mem.trimEnd(u8, streams.stderr, " \r\n\t");
    const last = if (std.mem.lastIndexOfScalar(u8, text, '\n')) |at| text[at + 1 ..] else text;
    if (!std.mem.eql(u8, last, hint)) return error.HintWrong;
    if (std.mem.count(u8, text, hint) != 1) return error.HintWrong;
}

/// A run that failed with `--net none` given: no hint.
pub fn check_no_hint(streams: Streams, status: u8, page: []const u8) Error!void {
    if (status == 0) return error.ExitCodeWrong;
    if (contains(streams.stdout, page)) return error.PageWrong;
    if (contains(streams.stderr, "grant with --net")) return error.HintWrong;
}

/// A run on the host's network fetched the page, with no hint.
pub fn check_page(streams: Streams, status: u8, page: []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!contains(streams.stdout, page)) return error.PageWrong;
    if (contains(streams.stderr, "grant with --net")) return error.HintWrong;
}

/// `cat /etc/hosts; echo ---; cat /etc/resolv.conf; echo ---; (echo x >> /etc/hosts) 2>&1`:
/// the hosts file names localhost and the container; with `nameserver` false the resolv.conf has
/// none, else it has one; and the write is refused for want of a writable file system.
pub fn check_generated_files(
    streams: Streams,
    status: u8,
    name: []const u8,
    nameserver: bool,
) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    const first = cut(streams.stdout);
    const second = cut(first.after);
    if (!contains(first.before, "127.0.0.1\tlocalhost")) return error.FileWrong;
    if (!contains(first.before, "::1\tlocalhost")) return error.FileWrong;
    var needle: [96]u8 = undefined;
    const format = "localhost {s}\n";
    const named = std.fmt.bufPrint(&needle, format, .{name}) catch return error.FileWrong;
    if (!contains(first.before, named)) return error.FileWrong;
    if (contains(second.before, "nameserver ") != nameserver) return error.FileWrong;
    if (!contains(second.after, "Read-only file system")) return error.FileWrong;
}

/// A run in JSON mode ends with the container_exit line, which names the network.
pub fn check_json_network(streams: Streams, status: u8, network: []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    const text = std.mem.trimEnd(u8, streams.stderr, " \r\n\t");
    const last = if (std.mem.lastIndexOfScalar(u8, text, '\n')) |at| text[at + 1 ..] else text;
    if (!std.mem.startsWith(u8, last, "{\"container_exit\":{")) return error.JsonWrong;
    var needle: [48]u8 = undefined;
    const wanted = std.fmt.bufPrint(&needle, "\"network\":\"{s}\"", .{network}) catch {
        return error.JsonWrong;
    };
    if (!contains(last, wanted)) return error.JsonWrong;
}

/// `zbx store diff <parent> <commit>` after a container wrote `added` and nothing else: that path
/// is added, and neither generated file is anywhere in the list.
pub fn check_commit_diff(streams: Streams, status: u8, added: []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    var found = false;
    var lines = std.mem.splitScalar(u8, streams.stdout, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (line.len < 3 or line[1] != ' ') return error.DiffWrong;
        const rest = line[2..];
        const path = rest[0 .. std.mem.indexOf(u8, rest, "  ") orelse rest.len];
        if (std.mem.eql(u8, path, "/etc/hosts")) return error.DiffWrong;
        if (std.mem.eql(u8, path, "/etc/resolv.conf")) return error.DiffWrong;
        if (line[0] == 'A' and std.mem.eql(u8, path, added)) found = true;
    }
    if (!found) return error.DiffWrong;
}

// ---- Slice 3: --net user and --publish through pasta ----

pub const pasta_dns = "nameserver 169.254.1.1";

/// `cat /etc/resolv.conf; wget -qO- https://example.com` with `--net user`: the resolv.conf
/// names pasta's DNS address (and not the host's stub), and the page came, so DNS and the
/// connection both went through pasta.
pub fn check_user_fetch(streams: Streams, status: u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!contains(streams.stdout, pasta_dns)) return error.FileWrong;
    if (contains(streams.stdout, "127.0.0.53")) return error.FileWrong;
    if (!contains(streams.stdout, "Example Domain")) return error.PageWrong;
    if (contains(streams.stderr, "grant with --net")) return error.HintWrong;
}

/// `curl localhost:PORT` on the guest answered with nginx's welcome page.
pub fn check_nginx_page(text: []const u8, status: u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!contains(text, "Welcome to nginx!")) return error.PageWrong;
}

/// The lines of `ss -tlnpe` (as root) that listen on the host's `port`: `count` of them and,
/// when there are any, every one is pasta's, owned by uid 1000 (the demo user).
pub fn check_listener(text: []const u8, port: u16, want: bool) Error!void {
    var needle: [16]u8 = undefined;
    const local = std.fmt.bufPrint(&needle, ":{d} ", .{port}) catch return error.ListenerWrong;
    var found: u32 = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "LISTEN")) continue;
        // The local address is the fourth column; the peer's ("0.0.0.0:*") never ends ":PORT ".
        if (!contains(line, local)) continue;
        found += 1;
        if (!contains(line, "((\"pasta\"")) return error.ListenerWrong;
        if (!contains(line, " uid:1000 ")) return error.ListenerWrong;
    }
    if ((found > 0) != want) return error.ListenerWrong;
}

/// The host's rules (`iptables -S` and `ip6tables -S`, as root) are what they were.
pub fn check_rules_same(before: []const u8, after: []const u8) Error!void {
    if (before.len == 0) return error.RulesChanged; // Nothing was read: nothing is shown.
    const left = std.mem.trim(u8, before, " \r\n");
    const right = std.mem.trim(u8, after, " \r\n");
    if (!std.mem.eql(u8, left, right)) return error.RulesChanged;
}

/// The JSON line of a run with one `--publish HOST:CONTAINER`: network user and the forward.
pub fn check_json_published(streams: Streams, status: u8, host: u16, container: u16) Error!void {
    try check_json_network(streams, status, "user");
    var needle: [80]u8 = undefined;
    const format = "\"published\":[{{\"host\":{d},\"container\":{d}}}]";
    const wanted = std.fmt.bufPrint(&needle, format, .{ host, container }) catch {
        return error.JsonWrong;
    };
    if (!contains(streams.stderr, wanted)) return error.JsonWrong;
}

const testing = std.testing;

fn captured(stdout: []const u8, stderr: []const u8) Streams {
    return .{ .stdout = stdout, .stderr = stderr };
}

test "a container with a network of its own sees lo alone, and it is up" {
    // Goal: the isolation check cannot pass for a container that sees the host's interfaces.
    // Method: right output, then an extra interface, a down loopback and a failed run.
    const link = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN " ++
        "\\    link/loopback\n";
    try check_only_loopback(captured("lo\n---\n" ++ link, ""), 0);
    try testing.expectError(
        error.InterfacesWrong,
        check_only_loopback(captured("enp0s3\nlo\n---\n" ++ link, ""), 0),
    );
    const down = "1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN\\    link/loopback\n";
    try testing.expectError(
        error.InterfacesWrong,
        check_only_loopback(captured("lo\n---\n" ++ down, ""), 0),
    );
    try testing.expectError(error.ExitCodeWrong, check_only_loopback(captured("lo\n---\n", ""), 1));
    try testing.expectError(error.InterfacesWrong, check_only_loopback(captured("", ""), 0));
}

test "the host's network has lo and something else" {
    // Goal: `--net host` still reaches the host's interfaces. Method: right, then lo alone.
    try check_host_interfaces(captured("enp0s3\nlo\n", ""), 0);
    try testing.expectError(error.InterfacesWrong, check_host_interfaces(captured("lo\n", ""), 0));
    try testing.expectError(
        error.InterfacesWrong,
        check_host_interfaces(captured("enp0s3\n", ""), 0),
    );
}

test "the hint is the last line of a failed run's stderr, once, and never for an explicit none" {
    // Goal: the hint's placement. Method: right; no hint; hint first; twice; page fetched.
    const wget = "wget: can't connect to remote host (127.0.0.1): Connection refused\n";
    try check_hint(captured("", wget ++ hint ++ "\n"), 1, "zbx-net-ok");
    try testing.expectError(error.HintWrong, check_hint(captured("", wget), 1, "zbx-net-ok"));
    try testing.expectError(
        error.HintWrong,
        check_hint(captured("", hint ++ "\n" ++ wget), 1, "zbx-net-ok"),
    );
    try testing.expectError(
        error.HintWrong,
        check_hint(captured("", hint ++ "\n" ++ hint ++ "\n"), 1, "zbx-net-ok"),
    );
    try testing.expectError(
        error.PageWrong,
        check_hint(captured("zbx-net-ok\n", hint ++ "\n"), 1, "zbx-net-ok"),
    );
    try testing.expectError(error.ExitCodeWrong, check_hint(captured("", hint ++ "\n"), 0, "x"));
    try check_no_hint(captured("", wget), 1, "zbx-net-ok");
    try testing.expectError(
        error.HintWrong,
        check_no_hint(captured("", wget ++ hint ++ "\n"), 1, "zbx-net-ok"),
    );
}

test "the host's network fetches the page" {
    // Goal: `--net host` reaches the host. Method: right; no page; a hint where none belongs.
    try check_page(captured("zbx-net-ok\n", ""), 0, "zbx-net-ok");
    try testing.expectError(error.PageWrong, check_page(captured("", ""), 0, "zbx-net-ok"));
    try testing.expectError(error.ExitCodeWrong, check_page(captured("zbx-net-ok", ""), 1, "zbx"));
    try testing.expectError(
        error.HintWrong,
        check_page(captured("zbx-net-ok\n", hint ++ "\n"), 0, "zbx-net-ok"),
    );
}

test "the generated files name the container, and are read-only" {
    // Goal: /etc/hosts and /etc/resolv.conf. Method: right, then each way to be wrong.
    const hosts = "127.0.0.1\tlocalhost gen2\n::1\tlocalhost ip6-localhost ip6-loopback gen2\n";
    const write = "sh: can't create /etc/hosts: Read-only file system\n";
    const none = "# zbx: this container has no network (--net none).\n";
    const stub = "nameserver 127.0.0.53\n";
    const without = captured(hosts ++ "---\n" ++ none ++ "---\n" ++ write, "");
    const with = captured(hosts ++ "---\n" ++ stub ++ "---\n" ++ write, "");
    try check_generated_files(without, 0, "gen2", false);
    try check_generated_files(with, 0, "gen2", true);
    try testing.expectError(error.FileWrong, check_generated_files(with, 0, "gen2", false));
    try testing.expectError(error.FileWrong, check_generated_files(without, 0, "gen2", true));
    const writable = captured(hosts ++ "---\n" ++ none ++ "---\n", "");
    try testing.expectError(error.FileWrong, check_generated_files(writable, 0, "gen2", false));
    try testing.expectError(error.FileWrong, check_generated_files(without, 0, "other", false));
    try testing.expectError(error.ExitCodeWrong, check_generated_files(without, 1, "gen2", false));
}

test "the JSON line names the network" {
    // Goal: `run --output json` carries the mode. Method: right; the other mode; no line.
    const line = "{\"container_exit\":{\"reason\":\"exited\",\"code\":0,\"network\":\"none\"}}\n";
    try check_json_network(captured("", line), 0, "none");
    try testing.expectError(error.JsonWrong, check_json_network(captured("", line), 0, "host"));
    try testing.expectError(error.JsonWrong, check_json_network(captured("", ""), 0, "none"));
}

test "a commit's diff holds what the container wrote and neither generated file" {
    // Goal: the generated files never become part of a commit. Method: right; each file listed;
    // the container's file missing.
    try check_commit_diff(captured("A /root/note\nM /root  mode\n", ""), 0, "/root/note");
    try testing.expectError(
        error.DiffWrong,
        check_commit_diff(captured("A /root/note\nA /etc/resolv.conf\n", ""), 0, "/root/note"),
    );
    try testing.expectError(
        error.DiffWrong,
        check_commit_diff(captured("A /root/note\nM /etc/hosts  size\n", ""), 0, "/root/note"),
    );
    const other = captured("A /other\n", "");
    try testing.expectError(error.DiffWrong, check_commit_diff(other, 0, "/root/note"));
}

test "--net user fetched the page with pasta's DNS" {
    // Goal: the check fails unless DNS went to pasta and the page came. Method: right; the host's
    // stub; no page; a failed run.
    const page = "<title>Example Domain</title>\n";
    const right = "# zbx: DNS goes through pasta to the host's resolver (--net user).\n" ++
        pasta_dns ++ "\n" ++ page;
    try check_user_fetch(captured(right, ""), 0);
    const stub = captured("nameserver 127.0.0.53\n" ++ pasta_dns ++ "\n" ++ page, "");
    try testing.expectError(error.FileWrong, check_user_fetch(stub, 0));
    const no_page = captured(pasta_dns ++ "\n", "wget: bad address 'example.com'\n");
    try testing.expectError(error.PageWrong, check_user_fetch(no_page, 0));
    try testing.expectError(error.ExitCodeWrong, check_user_fetch(captured(right, ""), 1));
}

test "nginx answers through the published port" {
    // Goal: the page is nginx's. Method: right; another page; a failed curl.
    try check_nginx_page("<h1>Welcome to nginx!</h1>\n", 0);
    try testing.expectError(error.PageWrong, check_nginx_page("It works!\n", 0));
    try testing.expectError(error.ExitCodeWrong, check_nginx_page("", 7));
}

test "the listener is pasta's, as the user, and gone when it should be" {
    // Goal: the port check. Method: lines in the shape `ss -tlnpe` prints (docs/demos/m5.md has
    // the recorded ones); another program's listener; root's; the port free; a port that is a
    // prefix of another.
    const pasta = "LISTEN 0      128          0.0.0.0:8080      0.0.0.0:*    " ++
        "users:((\"pasta\",pid=1828,fd=7)) uid:1000 ino:21120 sk:1 cgroup:/user.slice <->\n";
    try check_listener(pasta, 8080, true);
    try testing.expectError(error.ListenerWrong, check_listener(pasta, 8080, false));
    try check_listener(pasta, 80, false);
    try check_listener("State Recv-Q Send-Q Local Address:Port\n", 8080, false);
    const other = "LISTEN 0 5 0.0.0.0:8080 0.0.0.0:* users:((\"python3\",pid=9,fd=3)) uid:1000 x\n";
    try testing.expectError(error.ListenerWrong, check_listener(other, 8080, true));
    const root = "LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:((\"pasta\",pid=9,fd=7)) ino:1 sk:2\n";
    try testing.expectError(error.ListenerWrong, check_listener(root, 8080, true));
    try check_listener(pasta, 808, false);
}

test "the host's rules are unchanged" {
    // Goal: no firewall change. Method: the same text; a rule added; nothing read.
    const rules = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n";
    try check_rules_same(rules, rules ++ "\n");
    const added = rules ++ "-A FORWARD -j ACCEPT\n";
    try testing.expectError(error.RulesChanged, check_rules_same(rules, added));
    try testing.expectError(error.RulesChanged, check_rules_same("", ""));
}

test "the JSON line lists the forward" {
    // Goal: `run --output json` says user and the port. Method: right; another port; mode none.
    const line = "{\"container_exit\":{\"reason\":\"exited\",\"code\":0,\"network\":\"user\"," ++
        "\"published\":[{\"host\":18081,\"container\":80}]},\"ran\":{\"kind\":\"image\"}}\n";
    try check_json_published(captured("", line), 0, 18081, 80);
    const other = check_json_published(captured("", line), 0, 18082, 80);
    try testing.expectError(error.JsonWrong, other);
    const none = "{\"container_exit\":{\"reason\":\"exited\",\"code\":0,\"network\":\"none\"," ++
        "\"published\":[]}}\n";
    const without = check_json_published(captured("", none), 0, 18081, 80);
    try testing.expectError(error.JsonWrong, without);
}
