# The user guide lives in docs/guide, labelled by the version it was run with

*Decided 2026-11-11, by the beta-docs session (for the owner to confirm in review).*

**Where.** The guide for users is plain Markdown in `docs/guide/`: an index, one "Try" page per
path (Mac, Linux, Claude Code), a tour of the core commands, and known limits. It is linked from
the top of `README.md` and from the "Try it" section of the site. It sits in this repository, not
on the site, so a change to a command and to its documentation can land in one pull request, and
GitHub renders it with no build step.

**Users, not process.** Guide pages say nothing about milestones, slices, briefs or how the work
is run. Error codes link to `https://zigbox.org/errors/box/<code>`. A feature that is on `main`
but not in a release is either left out or marked "from <version>".

**Honest output.** Every command and output in the guide was run for the guide (the page says
with which version and on what host) or is quoted from a recorded CI run that the page links.
Nothing is written from memory or invented. Where a step could not be run, an HTML comment
addressed to the owner says so (`<!-- owner: ... -->`, or `<!-- verify on a Mac before
<version> -->` for Mac steps), so the gaps are visible in the source and absent from the
rendered page.

**Versions.** Each page that shows output says, near the top, the version that produced it. Before a
release is announced, the examples are run again with that release and the comments are resolved;
the guide does not keep pages per version.

Links: [docs/guide/index.md](../guide/index.md),
[the parity scope](2026-11-11-docker-parity-scope.md) (the source of the known limits).
