# The ldconfig helper has one deadline over its whole run

Date: 2026-11-13. Supersedes the waiter paragraph of
`2026-11-13-cdi-ldconfig-and-spec-bounds.md` (that file is not edited).

`HostReal.run_helper` put its deadline on the read of the output pipe only. A helper
that closed or redirected its own output and ignored SIGALRM reached EOF at once, and
one that wrote past the read bound ended the loop early; both then sat in a blocking
`wait4` for ever. Now the reads and the reap share one deadline. At expiry the helper's
process group and the helper are sent SIGKILL, the pipe is closed and the helper reaped.
Running out of reads counts as the deadline.

`HelperResult.timed_out` says a kill happened. `run_ldconfig` counts it as a failed
`ldconfig` (W0208 and the `LD_LIBRARY_PATH` fallback) even when the helper had exited 0,
for instance with a grandchild still holding the pipe. The helper's stdin is `/dev/null`.

Still not run: a hanging `ldconfig` inside the VM guest; a holder that moved to its own
session survives the kill but no longer holds the waiter.
