//! Network detection: whether a `RUN`'s text fetches, by a checked-in table of commands
//! (docs/briefs/M9-dockerfile-import.md, "Network detection"; the survey's 46% of RUN lines).
//!
//! A phrase is a command and, for some, the subcommands that fetch (`apk add`, `go mod
//! download`). It matches when its command is a word of the text (a path's last part counts, so
//! `/usr/bin/curl` and `./gradlew` match) and its later words follow, in order, within the same
//! simple command (before `;`, `&`, `|`, a newline or a parenthesis), so `apk --no-cache add`
//! matches `apk add`. A miss is not silent: the build fails with E0805 and names the step.

const std = @import("std");
const assert = std.debug.assert;

pub const Phrase = struct {
    /// As the report shows it: `apk add`.
    text: []const u8,
    words: []const []const u8,
};

fn phrase(comptime text: []const u8) Phrase {
    comptime var words: []const []const u8 = &.{};
    comptime var parts = std.mem.tokenizeScalar(u8, text, ' ');
    inline while (comptime parts.next()) |part| words = words ++ .{part};
    return .{ .text = text, .words = words };
}

/// The table, in the order it is tried: the first phrase that matches is the one reported.
pub const table = table: {
    @setEvalBranchQuota(100_000);
    break :table [_]Phrase{
        phrase("apk add"),                phrase("apk update"),    phrase("apk upgrade"),
        phrase("apk fetch"),              phrase("apt-get"),       phrase("apt"),
        phrase("aptitude"),               phrase("dnf"),           phrase("yum"),
        phrase("microdnf"),               phrase("tdnf"),          phrase("zypper"),
        phrase("pacman"),                 phrase("pip install"),   phrase("pip3 install"),
        phrase("pip download"),           phrase("pip3 download"), phrase("pipx install"),
        phrase("pipenv"),                 phrase("uv"),            phrase("poetry"),
        phrase("conda install"),          phrase("mamba install"), phrase("micromamba install"),
        phrase("npm"),                    phrase("npx"),           phrase("yarn"),
        phrase("pnpm"),                   phrase("bun"),           phrase("corepack"),
        phrase("go mod download"),        phrase("go get"),        phrase("go install"),
        phrase("cargo build"),            phrase("cargo fetch"),   phrase("cargo install"),
        phrase("rustup"),                 phrase("bundle"),        phrase("gem install"),
        phrase("composer"),               phrase("mvn"),           phrase("mvnw"),
        phrase("gradle"),                 phrase("gradlew"),       phrase("sbt"),
        phrase("dotnet restore"),         phrase("nuget"),         phrase("cpanm"),
        phrase("luarocks install"),       phrase("opam install"),  phrase("stack"),
        phrase("cabal"),                  phrase("curl"),          phrase("wget"),
        phrase("aria2c"),                 phrase("git clone"),     phrase("git fetch"),
        phrase("git pull"),               phrase("git submodule"), phrase("add-apt-repository"),
        phrase("install-php-extensions"),
    };
};

const separators = ";&|\n()";
const blanks = " \t\r";
const quotes = "\"'`";

/// The first phrase of the table that `text` holds, or null.
pub fn detect(text: []const u8) ?[]const u8 {
    for (table) |entry| {
        assert(entry.words.len > 0);
        if (holds(text, entry.words)) return entry.text;
    }
    return null;
}

/// A word of `text`: a run of bytes between blanks and separators, with quotes trimmed.
const Word = struct {
    text: []const u8,
    /// Whether a separator came between the previous word and this one.
    after_separator: bool,
};

const Words = struct {
    text: []const u8,
    at: u32 = 0,

    fn next(words: *Words) ?Word {
        var after_separator = false;
        while (words.at < words.text.len) : (words.at += 1) {
            const byte = words.text[words.at];
            if (std.mem.indexOfScalar(u8, separators, byte) != null) {
                after_separator = true;
            } else if (std.mem.indexOfScalar(u8, blanks, byte) == null) break;
        }
        if (words.at == words.text.len) return null;
        const start = words.at;
        while (words.at < words.text.len) : (words.at += 1) {
            const byte = words.text[words.at];
            if (std.mem.indexOfScalar(u8, separators ++ blanks, byte) != null) break;
        }
        assert(words.at > start);
        const word = std.mem.trim(u8, words.text[start..words.at], quotes);
        return .{ .text = word, .after_separator = after_separator };
    }
};

fn command_name(word: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, word, '/') orelse return word;
    return word[slash + 1 ..];
}

fn holds(text: []const u8, phrase_words: []const []const u8) bool {
    var words: Words = .{ .text = text };
    while (words.next()) |word| {
        if (!std.mem.eql(u8, command_name(word.text), phrase_words[0])) continue;
        if (follows(words, phrase_words[1..])) return true;
    }
    return false;
}

/// Whether `rest` appear in order after the command, before the simple command ends.
fn follows(start: Words, rest: []const []const u8) bool {
    var words = start;
    var matched: usize = 0;
    while (matched < rest.len) {
        const word = words.next() orelse return false;
        if (word.after_separator) return false;
        if (std.mem.eql(u8, word.text, rest[matched])) matched += 1;
    }
    assert(matched == rest.len);
    return true;
}

const testing = std.testing;

test "the table's phrases match in real RUN lines" {
    // Goal: the forms the survey found. Method: lines and the phrase each should report.
    const cases = [_][2][]const u8{
        .{ "apk add --no-cache curl", "apk add" },
        .{ "apk --no-cache add curl", "apk add" },
        .{ "set -eux; apt-get update && apt-get install -y x", "apt-get" },
        .{ "python -m pip install -r r.txt", "pip install" },
        .{ "cd /src && go mod download", "go mod download" },
        .{ "/usr/bin/curl -fsSL https://x | sh", "curl" },
        .{ "./gradlew build", "gradlew" },
        .{ "sh -c \"wget -q x\"", "wget" },
    };
    for (cases) |case| {
        const found = detect(case[0]) orelse {
            std.debug.print("no match: {s}\n", .{case[0]});
            return error.TestUnexpectedResult;
        };
        try testing.expectEqualStrings(case[1], found);
    }
}

test "words inside other words and across commands do not match" {
    // Goal: the negative space: no match on part of a word, nor when the subcommand belongs
    // to another command. Method: near misses.
    const misses = [_][]const u8{
        "go build -o /x .",
        "echo apk; echo add",
        "curly-braces --apt",
        "mkdir -p /etc/apt/x",
        "cp npmrc /root/",
        "pip freeze",
        "",
    };
    for (misses) |text| {
        if (detect(text)) |found| {
            std.debug.print("matched {s} in: {s}\n", .{ found, text });
            return error.TestUnexpectedResult;
        }
    }
}
