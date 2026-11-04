# M7 · Slice 2: how a step's inputs are imported (for review)

*Decided 2026-11-02 by the slice 2 implementer, for review.* The brief was silent on these; each is the smaller option.

- **Follow rules.** Every open goes through `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)` from the project directory's handle. A declared input is opened following links (beneath), so an input that is a link to a file or directory inside the project still works. Entries found inside a directory input are opened without following: a link there is recorded as a link, its text in the key. The open that reads a file or lists a directory follows links beneath and then compares its inode with the entry's handle, so a swap between the two opens is caught.
- **New refusals, still E0803.** A path that leaves the project at import time (an absolute link, `..` past the project, a file that vanished or became a link or a directory) is the new problem kind `changed` ("changed while the build read it"), not `outside`: the check before the build said it was inside. A device, FIFO or socket inside a directory input is the new kind `holds_bad_kind`, naming the entry and its kind.
- **Store limits and failures reuse the store's diagnostics:** E0415 (`too_big`) for a tree, path or depth limit, and `write_failed` for a store write.
- **Modes in the tree.** Files are 0644, or 0755 when the owner's execute bit is set (what a checkout keeps). Directories are 0755 and links 0777. Every owner is 0 and no xattrs are kept. Times are not in the tree.
- **Roots.** The importer does not root the tree it writes; the caller roots what it keeps (the cache entry, slice 2b/3). Until then gc may remove an import tree that nothing references.
